"""Electron apps from Windows and macOS, rebuilt on the Linux build of Electron.

An Electron app is mostly JavaScript in resources/app.asar. The Windows or
Mac part is Electron itself, which the same Electron release also ships for
Linux. So the conversion keeps the app's resources folder and puts it next
to the Linux electron binary of the same version, inside a Flatpak on the
org.electronjs.Electron2.BaseApp base (zypak provides Chromium's sandbox).

What can stop it is native code. Node modules (.node files) compiled for
Windows or macOS can't load on Linux. Modules that only exist for one
platform, such as fsevents, are skipped by the app on Linux anyway, and so
are modules the app only loads where it catches the failure (caught_native).
Others need a Linux build of the same module, which --native-dir supplies.
Electron methods that only exist on Windows or macOS get stand-ins when the
app calls them (platform_api_shim).

The Electron version comes from, in order: --electron-version, the Mac
framework's Info.plist, a version string in the Electron binary, Chromium's
version in the binary matched against Electron's release list, and the
electron entry in the app's package.json.
"""
from __future__ import annotations

import hashlib
import json
import mmap
import os
import re
import shlex
import shutil
import urllib.request
from pathlib import Path

from .asar import Asar, AsarError
from .foreign import Plan, _need_replay, copy_tree, extra_source, icns_png, one_line, write_integration
from .packages import Package
from .permissions import infer
from .runtime import parse_ref, sdk_for
from .unpack import APPLY_EXTRA, install_helper
from . import net

RELEASES = "https://github.com/electron/electron/releases/download"
RELEASE_LIST = "https://releases.electronjs.org/releases.json"
ELECTRON_BASE = "org.electronjs.Electron2.BaseApp"
# The Electron base app follows org.freedesktop.Platform's branches; each GNOME runtime is built on one
GNOME_ON_FREEDESKTOP = {"46": "23.08", "47": "24.08", "48": "24.08", "49": "25.08", "50": "25.08",
                        "51": "26.08"}
GNOME_FOR_FREEDESKTOP = {"24.08": "47", "25.08": "49", "26.08": "51"}
DEFAULT_RUNTIME = "org.freedesktop.Platform//25.08"
ARCHES = {"x86_64": "x64", "aarch64": "arm64"}
# a module published once per platform (sharp-win32-x64, esbuild-darwin-arm64): on Linux the app
# looks for the -linux- sibling, which the Windows or Mac build doesn't include
PER_PLATFORM = re.compile(r"(^|/)(@[^/]+/)?([^/]+)-(win32|darwin)-(x64|ia32|arm64|universal)(/|$)", re.I)
# packages that only exist for one platform (fsevents, win-ca, macos-alias); apps load them only there.
# Matched against the package's name, not the whole path: node-pre-gyp and prebuildify put
# platform names in folder names (lib/binding/...-win32-x64, prebuilds/win32-x64) of modules
# that are needed everywhere.
PLATFORM_ONLY = re.compile(r"^(@[^/]+/)?(fsevents|.*(darwin|macos|mac-|osx|win32|win-|windows).*)$", re.I)
VERSION_RE = re.compile(rb"Electron/(\d+\.\d+\.\d+(?:-(?:alpha|beta|nightly)\.\d+)?)")
CHROME_RE = re.compile(rb"(?<![\d.])(\d{2,3}\.0\.\d{4}\.\d{1,3})(?![\d.])")


def fetch(url: str) -> bytes:
    """Download a URL (the tests replace this)."""
    with net.urlopen(url, timeout=60) as r:       # noqa: S310 - fixed https URLs
        return r.read()


_RELEASES: list | None = None


def release_list() -> list[dict]:
    """Return Electron's release list (fetched at most once per conversion; plan() resets it).

    Raises:
        OSError, ValueError: It can't be downloaded or parsed.
    """
    global _RELEASES
    if _RELEASES is None:
        _RELEASES = json.loads(fetch(RELEASE_LIST))
    return _RELEASES


def package_json(res: Path) -> dict:
    """Return the app's package.json, from app.asar or an unpacked app folder ({} if unreadable)."""
    try:
        if (res / "app.asar").is_file():
            return json.loads(Asar(res / "app.asar").read("package.json"))
        return json.loads((res / "app/package.json").read_text("utf-8"))
    except (AsarError, KeyError, OSError, ValueError):
        return {}


def _scan_binary(path: Path) -> tuple[str | None, str | None]:
    """Return (Electron version, Chromium version) found as text in a binary, either possibly None."""
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            ev = VERSION_RE.search(m)
            if ev:
                return ev.group(1).decode(), None
            i = m.find(b"Chrome/")
            if i != -1:
                cv = CHROME_RE.match(m, i + 7)
                if cv:
                    return None, cv.group(1).decode()
            cv = CHROME_RE.search(m)
            return None, cv.group(1).decode() if cv else None
    except (OSError, ValueError):
        return None, None


def _electron_binary(pkg: Package) -> Path | None:
    """Return the file that holds Electron's code: the Mac framework binary, or the Windows app's .exe."""
    if pkg.extra["platform"] == "mac":
        fw = pkg.extra["bundle"] / "Contents/Frameworks/Electron Framework.framework"
        hits = sorted(p for p in fw.glob("Versions/*/Electron Framework") if p.is_file() and not p.is_symlink())
        return hits[0] if hits else None
    app_dir = pkg.extra["app_dir"]
    exes = [p for p in app_dir.glob("*.exe") if p.is_file()]
    return max(exes, key=lambda p: p.stat().st_size) if exes else None


def detect_version(pkg: Package, pj: dict, override: str | None = None) -> tuple[str | None, str]:
    """Return (Electron version, where it came from); the version is None when nothing says."""
    if override:
        return override.lstrip("v"), "--electron-version"
    if pkg.extra["platform"] == "mac":
        fw = pkg.extra["bundle"] / "Contents/Frameworks/Electron Framework.framework"
        import plistlib
        for plist in sorted(fw.glob("Versions/*/Resources/Info.plist")):
            try:
                v = plistlib.loads(plist.read_bytes()).get("CFBundleVersion")
            except Exception:  # noqa: BLE001
                continue
            if v and re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", v):
                return v, "the Electron framework's Info.plist"
    else:
        vf = pkg.extra["app_dir"] / "version"
        if vf.is_file():
            v = vf.read_text(errors="replace").strip().lstrip("v")
            if re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", v):
                return v, "the version file next to the program"
    binary = _electron_binary(pkg)
    chrome = None
    if binary:
        ev, chrome = _scan_binary(binary)
        if ev:
            return ev, f"a version string in {binary.name}"
    if chrome:
        try:
            for rel in release_list():
                if rel.get("chrome") == chrome and not re.search(r"-(alpha|beta|nightly)", rel.get("version", "")):
                    return rel["version"], f"Chromium {chrome} in {binary.name}, matched against Electron's releases"
        except (OSError, ValueError, KeyError):
            pass
    spec = (pj.get("devDependencies") or {}).get("electron") or (pj.get("dependencies") or {}).get("electron")
    if spec:
        m = re.search(r"\d+\.\d+\.\d+", spec)
        if m:
            return m.group(0), f"package.json (\"electron\": \"{spec}\"; may not be the exact build)"
    return None, "nothing in the app states it"


def _magic_kind(head: bytes) -> str:
    """Return linux, windows, mac or other from a file's first bytes."""
    if head[:4] == b"\x7fELF":
        return "linux"
    if head[:2] == b"MZ":
        return "windows"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"):
        return "mac"
    return "other"


def native_modules(res: Path) -> list[tuple[str, str, bool]]:
    """List the app's native files: (path relative to resources, platform, packed in app.asar).

    Covers .node modules inside app.asar, in app.asar.unpacked and in an
    unpacked app folder, plus any Windows or Mac executables elsewhere in
    resources (helper programs the app may start).
    """
    out: list[tuple[str, str, bool]] = []
    asar_file = res / "app.asar"
    seen = set()
    if asar_file.is_file():
        try:
            a = Asar(asar_file)
            for p, e in a.walk():
                if p.endswith(".node"):
                    rel = f"app.asar/{p}"
                    seen.add(f"app.asar.unpacked/{p}")
                    out.append((rel, _magic_kind(a.head(p, 4)), not e.get("unpacked")))
        except AsarError:
            pass
    for dirpath, _dirs, files in os.walk(res):
        for f in files:
            p = Path(dirpath) / f
            rel = p.relative_to(res).as_posix()
            if rel in seen or rel == "app.asar" or p.is_symlink():
                continue
            try:
                with open(p, "rb") as fh:
                    kind = _magic_kind(fh.read(4))
            except OSError:
                continue
            if f.endswith(".node") or kind in ("windows", "mac"):
                out.append((rel, kind, False))
    return sorted(out)


SCRIPT_EXT = (".js", ".cjs", ".mjs")
SCRIPT_MAX = 64 << 20


def app_scripts(res: Path) -> list[tuple[str, str]]:
    """Return the app's JavaScript as (path relative to resources, text), from app.asar or resources/app."""
    out = []
    asar_file = res / "app.asar"
    if asar_file.is_file():
        try:
            a = Asar(asar_file)
            for p, e in a.walk():
                if p.endswith(SCRIPT_EXT) and "files" not in e and "link" not in e \
                        and int(e.get("size", 0)) <= SCRIPT_MAX:
                    try:
                        data = (res / "app.asar.unpacked" / p).read_bytes() if e.get("unpacked") else a.read(p)
                    except (OSError, KeyError, ValueError, AsarError):
                        continue
                    out.append((f"app.asar/{p}", data.decode("utf-8", "replace")))
        except AsarError:
            pass
    elif (res / "app").is_dir():
        for dirpath, _dirs, files in os.walk(res / "app"):
            for f in files:
                p = Path(dirpath) / f
                if f.endswith(SCRIPT_EXT) and not p.is_symlink() and p.stat().st_size <= SCRIPT_MAX:
                    out.append((p.relative_to(res).as_posix(), p.read_text("utf-8", "replace")))
    return out


# the start of a try block, with no other braces between it and what follows
_IN_TRY = re.compile(r"try\s*\{[^{}]*$")
# a function that does nothing but load the module: function f(){return require("x")} or f=()=>require("x")
_WRAPPER = re.compile(r"(?:function\s+([\w$]+)\s*\(\s*\)\s*\{\s*return\s*|([\w$]+)\s*=\s*\(\s*\)\s*=>\s*\(?\s*)$")


def caught_native(rel: str, package: tuple[str, str] | None, scripts: list[tuple[str, str]]) -> str | None:
    """Return where the app catches a failure to load a native module, if it never needs it to load; else None.

    rel is the module's path relative to resources, and package its
    (name, folder) when it's inside node_modules (natives.package_of). A
    package is found by its require("name"); a loose file by a string
    ending in its file name, which the app passes to require or
    createRequire.

    Every place the app's code (outside the package's own folder) loads the
    module must either sit at the start of a try block or, for a package, be
    the whole body of a small loader function; and at least one of those
    must catch the error: a try block around the require or around a call
    of the loader. An app written like that expects the module to be
    missing at times (left out of a build, or failing to load) and goes on
    without it. Bundled Electron apps often load optional modules that
    way, then use the result only when it isn't null. A load anywhere else,
    such as at the top of a file, means the app needs the module, and the
    rule doesn't apply.

    The check reads the text around each load, so unusual code can fool it;
    the compat suite's launch test is what confirms an app starts without
    the module.
    """
    if package:
        name, own_dir = package
        load = re.compile(r"""require\(\s*(["'])""" + re.escape(name) + r"""(?:/[^"'\n]*)?\1\s*\)""")
    else:
        own_dir = None
        base = re.escape(rel.rsplit("/", 1)[-1])
        load = re.compile(r"""(["'`])(?:[^"'`\n]*/)?""" + base + r"\1")
    caught = None
    seen = False
    for path, text in scripts:
        if own_dir and path.startswith(own_dir + "/"):
            continue
        for m in load.finditer(text):
            seen = True
            before = text[max(0, m.start() - 300):m.start()]
            if _IN_TRY.search(before):
                caught = caught or path
                continue
            w = _WRAPPER.search(before) if package else None
            if not w:
                return None
            fn = w.group(1) or w.group(2)
            call = re.compile(r"(?<![\w$.])" + re.escape(fn) + r"\(\s*\)")
            for c in call.finditer(text):
                if _IN_TRY.search(text[max(0, c.start() - 300):c.start()]):
                    caught = caught or path
                    break
    return caught if seen else None


# Electron methods that exist only on Windows or macOS: Linux Electron leaves them undefined, so an
# app built only for those systems may call them without checking the platform. Each gets a stand-in
# that does nothing and returns what the method returns when there's nothing to report.
# (object, method, stand-in)
PLATFORM_APIS = [
    ("win", "hookWindowMessage", "function () {}"),
    ("win", "unhookWindowMessage", "function () {}"),
    ("win", "unhookAllWindowMessages", "function () {}"),
    ("win", "isWindowMessageHooked", "function () { return false; }"),
    ("win", "setThumbnailClip", "function () { return false; }"),
    ("win", "setThumbnailToolTip", "function () {}"),
    ("win", "setAppDetails", "function () {}"),
    ("win", "setWindowButtonVisibility", "function () {}"),
    ("win", "invalidateShadow", "function () {}"),
    ("app", "setUserTasks", "function () { return false; }"),
    ("app", "setJumpList", "function () {}"),
    ("app", "getJumpListSettings", "function () { return { minItems: 0, removedItems: [] }; }"),
    ("app", "moveToApplicationsFolder", "function () { return false; }"),
    # true, so an app doesn't offer to move itself into /Applications
    ("app", "isInApplicationsFolder", "function () { return true; }"),
    ("systemPreferences", "isAeroGlassEnabled", "function () { return false; }"),
    ("systemPreferences", "getEffectiveAppearance",
     "function () { return electron.nativeTheme.shouldUseDarkColors ? 'dark' : 'light'; }"),
]


def platform_api_shim(scripts: list[tuple[str, str]]) -> tuple[list[str], str] | None:
    """Return (methods, JavaScript) defining stand-ins for the PLATFORM_APIS the app calls, or None if it calls none."""
    found = []
    for obj, method, body in PLATFORM_APIS:
        rx = re.compile(r"\." + method + r"\s*\(")
        if any(method in text and rx.search(text) for _p, text in scripts):
            found.append((obj, method, body))
    if not found:
        return None
    lines = [
        "// Added by debpak. The app was built for Windows or macOS and calls Electron methods that",
        "// only exist there; on Linux they're undefined and each call would throw. These stand-ins",
        "// do nothing, and are only added where Electron has no method of that name.",
        "'use strict';",
        "const electron = require('electron');",
        "const win = (electron.BaseWindow || electron.BrowserWindow).prototype;",
        "const app = electron.app;",
        "const systemPreferences = electron.systemPreferences;",
    ]
    for obj, method, body in found:
        lines.append(f"if (typeof {obj}.{method} !== 'function') {obj}.{method} = {body};")
    return [f"{'BrowserWindow' if o == 'win' else o}.{m}" for o, m, _b in found], "\n".join(lines) + "\n"


def _read_pj(res: Path, pkg_dir: str) -> dict:
    """Read a package.json given its folder relative to resources (inside app.asar or on disk)."""
    try:
        if pkg_dir.startswith("app.asar/"):
            inner = pkg_dir[len("app.asar/"):] + "/package.json"
            a = Asar(res / "app.asar")
            if a.entry(inner) and not a.entry(inner).get("unpacked"):
                return json.loads(a.read(inner))
            return json.loads((res / "app.asar.unpacked" / inner).read_text("utf-8"))
        return json.loads((res / pkg_dir / "package.json").read_text("utf-8"))
    except (AsarError, KeyError, OSError, ValueError):
        return {}


def _entry_script(res: Path, pj: dict) -> tuple[str, bytes] | None:
    """Return (path, contents) of the script package.json's "main" names, resolved the way Node does."""
    main = pj.get("main") if isinstance(pj.get("main"), str) else "index.js"
    main = main.strip()
    while main.startswith("./"):
        main = main[2:]
    main = main.rstrip("/") or "index.js"
    if any(part in ("", ".", "..") for part in main.split("/")):
        return None
    for cand in (main, f"{main}.js", f"{main}/index.js"):
        try:
            if (res / "app.asar").is_file():
                a = Asar(res / "app.asar")
                e = a.entry(cand)
                if not e or "files" in e:
                    continue
                if e.get("unpacked"):
                    return cand, (res / "app.asar.unpacked" / cand).read_bytes()
                return cand, a.read(cand)
            if (res / "app" / cand).is_file():
                return cand, (res / "app" / cand).read_bytes()
        except (AsarError, KeyError, OSError):
            continue
    return None


PLATFORM_NAMES = {"win": ("win32", "Windows"), "mac": ("darwin", "macOS")}
# the smallest main-process bundle judged by built_for_platform: a bundle this size carries npm
# code (graceful-fs, supports-color, electron-log) that asks process.platform unless it was compiled out
BUNDLE_MIN = 64 * 1024


def built_for_platform(res: Path, pj: dict, platform: str) -> str | None:
    """Return the evidence that the app's JavaScript only runs on the platform it was built for, or None.

    Bundlers can replace process.platform with a constant (webpack's
    DefinePlugin, as GitHub Desktop does) and then drop the code for other
    platforms. Such a bundle takes the Windows or Mac code path on Linux
    whatever native modules it gets: it loads registry.node at startup, starts
    bundled .exe programs, reads .lnk shortcuts. The sign is a large
    main-process script that never reads a platform property and names only
    its own platform, where process.platform used to be.
    """
    if platform not in PLATFORM_NAMES:
        return None
    found = _entry_script(res, pj)
    if not found or len(found[1]) < BUNDLE_MIN:
        return None
    path, data = found
    if re.search(rb"\.platform\b|\[\s*[\"']platform[\"']\s*\]", data):
        return None
    named = {p for p in ("win32", "darwin", "linux") if re.search(rb"[\"'`]" + p.encode() + rb"[\"'`]", data)}
    own, where = PLATFORM_NAMES[platform]
    if named != {own}:
        return None
    return (f"its JavaScript was built for {where} only: {path} ({len(data) // 1024} KB) never reads "
            f"process.platform and names only \"{own}\", so the bundler replaced process.platform with "
            f"\"{own}\" and left out the code for other platforms. On Linux it would still take the {where} "
            f"code paths, with {where} native modules and programs. A Linux build of the app is needed")


def _plan_natives(pl: Plan, res: Path, version: str | None, args) -> None:
    """Classify the app's native files; find Linux builds for blocked modules (natives.py) or block."""
    from . import natives as nat
    native_dir = Path(args.native_dir) if getattr(args, "native_dir", None) else None
    fetch_ok = not getattr(args, "no_fetch_natives", False)
    abi = None
    if fetch_ok and version:
        try:
            abi = nat.electron_abi(version, release_list())
        except (OSError, ValueError):
            pass
    resolver = nat.Resolver(lambda d: _read_pj(res, d), version or "0.0.0", abi,
                            pl.data.get("runtime_id") or "org.freedesktop.Platform")
    files: list = []
    scripts = None                  # the app's JavaScript, read only if a module would block
    for rel, kind, _packed in native_modules(res):
        if kind == "linux":
            continue
        where = "Mac" if kind == "mac" else "Windows" if kind == "windows" else "unknown-format"
        if not rel.endswith(".node"):
            pl.notes.append(f"resources/{rel} is a {where} program; features of the app that start it won't work")
            continue
        local = nat.from_native_dir(native_dir, rel) if native_dir else None
        if local:
            files.append(local)
            pl.notes.append(f"native module {rel}: using the Linux build from --native-dir")
            continue
        per = PER_PLATFORM.search(rel)
        found = nat.package_of(rel)
        if found and PLATFORM_ONLY.search(found[0]) and not per:
            pl.notes.append(f"native module {rel} is {where}-only; the app shouldn't load it on Linux")
            continue
        # evidence beyond the package name (see natives.windows_only): the package.json "os" field, or
        # a file named for Windows or a Windows-only API
        evidence = None
        if kind == "windows" and not per:
            evidence = nat.windows_only(rel, _read_pj(res, found[1]) if found else {})
        if evidence:
            pl.notes.append(f"native module {rel} is Windows-only ({evidence}); the app shouldn't load it on Linux")
            continue
        if fetch_ok and resolver.resolve(rel):
            continue
        tried = resolver.res.unresolved.get(rel, "looking online is turned off (--no-fetch-natives)")
        # checked only once nothing was found, so a guess about the app's code never stops a
        # Linux build from being added
        if not per:
            if scripts is None:
                scripts = app_scripts(res)
            evidence = nat.skipped_on_linux(rel, scripts)
            if evidence:
                pl.notes.append(f"native module {rel} is built for {where} and has no Linux build, but the app "
                                f"doesn't load it on Linux ({evidence})")
                continue
            where_caught = caught_native(rel, found, scripts)
            if where_caught:
                pl.notes.append(f"native module {rel} is built for {where}, and no Linux build was found "
                                f"({tried}); the app loads it only where it catches the failure "
                                f"({where_caught}), so it starts without it, but whatever needs it won't work")
                continue
        if per:
            pl.notes.append(f"native module {rel} is the {where} build of {per.group(2) or ''}{per.group(3)}; "
                            f"the app will look for {per.group(2) or ''}{per.group(3)}-linux-x64, which "
                            f"couldn't be added ({tried}), so whatever uses it will fail")
        else:
            pl.blockers.append(f"native module {rel} is built for {where}, and no Linux build was found "
                               f"({tried}): pass --native-dir with one (same module version, built for "
                               "this Electron version)")
    files += resolver.res.files
    pl.notes += resolver.res.notes
    pl.data["natives"] = files
    pl.data["native_sources"] = resolver.res.sources
    pl.data["native_builds"] = resolver.res.builds
    if any(f.asar_entry for f in files):
        pl.notes.append("app.asar's header is rewritten so the Linux builds load from app.asar.unpacked")


def plan(pkg: Package, args) -> Plan:
    """Work out an Electron conversion: versions, native code, permissions, notes and blockers."""
    global _RELEASES
    _RELEASES = None
    pl = Plan(pkg, "electron")
    res = pkg.extra["resources"]
    pj = package_json(res)
    display = pkg.extra.get("display_name") or pj.get("productName") or pj.get("name") or pkg.name
    pkg.extra["display_name"] = display
    if pkg.version in ("", "0") and pj.get("version"):
        pkg.version = str(pj["version"])
    pkg.summary = pkg.summary or pj.get("description", "")
    build = pj.get("build") if isinstance(pj.get("build"), dict) else {}
    linux = build.get("linux") if isinstance(build.get("linux"), dict) else {}
    if linux.get("category") and not pkg.extra.get("category"):
        pkg.extra["category"] = str(linux["category"])
    pkg.homepage = pkg.homepage or pj.get("homepage", "")
    lic = pj.get("license")
    pkg.license = pkg.license or (lic if isinstance(lic, str) else "")
    version, source = detect_version(pkg, pj, getattr(args, "electron_version", None))
    rref = getattr(args, "runtime", None) or DEFAULT_RUNTIME
    rid, _arch, branch = parse_ref(rref, "x86_64")
    pl.details += [("from", f"{'macOS' if pkg.extra['platform'] == 'mac' else 'Windows'} "
                            f"({pkg.extra.get('unpacked_by')})"),
                   ("Electron", f"{version or '??'} (from {source})"),
                   ("runtime", f"{rid}//{branch} with {ELECTRON_BASE}//{branch}"),
                   ("app code", "app.asar" if (res / "app.asar").is_file() else "resources/app (not packed)")]
    pl.data.update(electron=version, runtime_id=rid, branch=branch, wm_class=display, pj_name=pj.get("name"))
    if not version:
        pl.blockers.append("can't tell which Electron version the app was built with: pass --electron-version "
                           "(the app's About window or its release notes usually say)")
    base = branch
    if rid == "org.gnome.Platform" and branch in GNOME_ON_FREEDESKTOP:
        base = GNOME_ON_FREEDESKTOP[branch]
    elif rid != "org.freedesktop.Platform":
        pl.notes.append(f"{ELECTRON_BASE} expects org.freedesktop.Platform; runtime is {rid}")
    pl.data["base_branch"] = base
    folded = built_for_platform(res, pj, pkg.extra.get("platform", ""))
    if folded:
        pl.blockers.append(folded)

    before = (list(pl.notes), list(pl.blockers))
    _plan_natives(pl, res, version, args)
    # a Linux build of a native module that needs GNOME libraries (libadwaita): the GNOME
    # runtime on the same freedesktop base has them, so use it unless --runtime chose otherwise
    gnome = GNOME_FOR_FREEDESKTOP.get(branch)
    if rid == "org.freedesktop.Platform" and not getattr(args, "runtime", None) and gnome \
            and any("(org.gnome.Platform does)" in b for b in pl.blockers):
        pl.notes, pl.blockers = list(before[0]), list(before[1])
        pl.data.update(runtime_id="org.gnome.Platform", branch=gnome, base_branch=branch)
        pl.details = [d for d in pl.details if d[0] != "runtime"] + [
            ("runtime", f"org.gnome.Platform//{gnome} with {ELECTRON_BASE}//{branch}")]
        pl.notes.append(f"a native module's Linux build needs GNOME libraries, so the app runs on "
                        f"org.gnome.Platform//{gnome}, which is built on org.freedesktop.Platform//{branch}")
        _plan_natives(pl, res, version, args)
    shim = platform_api_shim(app_scripts(res))
    if shim:
        pl.data["main_shim"] = shim[1]
        pl.notes.append(f"the app calls Electron methods that only exist on Windows or macOS "
                        f"({', '.join(shim[0])}); a script run before the app's own defines them "
                        "as stand-ins that do nothing")
    pl.permissions = infer(set(), set(), "electron", permissive=getattr(args, "permissive", False))
    pl.notes.append("the app's own auto-updater won't work in a Flatpak; `debpak update` reconverts new "
                    "versions instead")
    return pl


def _icon(pkg: Package) -> bytes | None:
    """Return the app's icon as PNG bytes: from the .icns of a Mac app, the .exe of a Windows one."""
    if pkg.extra["platform"] == "mac":
        res = pkg.extra["resources"]
        name = pkg.extra.get("icon_file") or ""
        cands = [res / name, res / f"{name}.icns"] if name else []
        cands += sorted(res.glob("*.icns"))
        for c in cands:
            if c.is_file():
                png = icns_png(c)
                if png:
                    return png
        return None
    from .winres import extract_png
    exe = _electron_binary(pkg)
    return extract_png(exe) if exe else None


def _shasums(version: str) -> dict[str, str]:
    """Return file name -> SHA-256 from the release's SHASUMS256.txt."""
    text = fetch(f"{RELEASES}/v{version}/SHASUMS256.txt").decode("utf-8", "replace")
    out = {}
    for line in text.splitlines():
        m = re.match(r"([0-9a-f]{64}) [ *](\S+)$", line.strip())
        if m:
            out[m.group(2)] = m.group(1)
    return out


def electron_sources(version: str, local_zip: str | None = None) -> list[dict]:
    """Return flatpak-builder sources for the Linux Electron zip: one per architecture, or the local file.

    Raises:
        ValueError: The release's checksums can't be fetched, or don't list a Linux build.
    """
    if local_zip:
        data = Path(local_zip).read_bytes()
        return [{"type": "archive", "path": str(Path(local_zip).resolve()), "strip-components": 0,
                 "sha256": hashlib.sha256(data).hexdigest()}]
    try:
        sums = _shasums(version)
    except OSError as e:
        raise ValueError(f"couldn't download Electron {version}'s checksums ({e}); "
                         "pass --electron-zip with electron-v{version}-linux-x64.zip") from e
    sources = []
    for farch, earch in ARCHES.items():
        fname = f"electron-v{version}-linux-{earch}.zip"
        if fname in sums:
            sources.append({"type": "archive", "url": f"{RELEASES}/v{version}/{fname}", "sha256": sums[fname],
                            "strip-components": 0, "only-arches": [farch]})
    if not sources:
        raise ValueError(f"Electron {version} has no Linux build listed in its SHASUMS256.txt")
    return sources


# what Electron's Linux zip holds beside its program, which the program's new name mustn't replace
ELECTRON_ZIP_NAMES = {"electron", "resources", "locales", "chrome-sandbox", "chrome_crashpad_handler",
                      "LICENSE", "LICENSES.chromium.html", "version"}


def electron_exe_name(slug: str) -> str:
    """Return the name Electron's program gets in the Flatpak: the app's, as electron-builder names it.

    Electron's app.isPackaged is false when the program is called electron, and
    apps then act as in development: Notion skipped its login-item setup ("App
    is not packaged"), read package.json from the working folder and opened no
    window.
    """
    return slug if slug not in ELECTRON_ZIP_NAMES and not slug.startswith(("lib", ".")) else f"{slug}-app"


def write(pl: Plan, out: Path, app_id: str, args) -> Path:
    """Write out/app (launcher, desktop integration, and the resources or their unpack plan) and the manifest.

    In bundle mode the app's resources are copied into out/app. In
    extra-data mode Flatpak downloads the original file at install time and
    apply_extra unpacks the resources into /app/extra, which the Electron
    folder links to.

    Returns:
        The manifest path.

    Raises:
        ValueError: Electron's Linux download can't be described (see
            electron_sources), or extra-data mode can't be used for this input.
    """
    pkg = pl.pkg
    slug = pkg.name
    version = pl.data["electron"]
    extra_data = getattr(args, "mode", "bundle") == "extra-data"
    sources = electron_sources(version, getattr(args, "electron_zip", None))
    app = out / "app"
    if app.exists():
        shutil.rmtree(app)
    res = pkg.extra["resources"]
    natives = pl.data.get("natives", [])
    native_sources = pl.data.get("native_sources", [])
    native_builds = pl.data.get("native_builds", [])
    drop = sorted(n for n in os.listdir(res) if n in ("default_app.asar", "electron.asar")
                  or n.endswith((".lproj", ".icns")))
    build = ["cp -a bin share ${FLATPAK_DEST}/", f"chmod +x ${{FLATPAK_DEST}}/bin/{slug}"]
    modules = []
    app_sources: list[dict] = [{"type": "dir", "path": "app"}]

    if extra_data:
        replay = _need_replay(pkg, args)
        extra_name, extra_src = extra_source(pkg, args.url)
        app_sources.append(extra_src)
        plan = {"source": extra_name, "steps": replay["steps"], "take": replay["take"], "target": "resources",
                "drop": sorted(set(replay["drop"]) | set(drop)), "natives": []}
        for i, nf in enumerate(natives):
            if nf.built is not None:        # built by flatpak-builder (natives.build_module)
                origin = f"/app/share/debpak/natives-built/{nf.built}/{nf.to.rsplit('/', 1)[-1]}"
            elif nf.source is None:         # from --native-dir: carried in the Flatpak
                dest = app / "share/debpak/natives" / str(i)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(nf.data)
                origin = f"/app/share/debpak/natives/{i}"
            else:                           # downloaded by flatpak-builder from where debpak found it
                origin = f"/app/share/debpak/natives-src/{nf.source}/{nf.member}"
            entry = {"from": origin, "to": nf.to}
            if nf.asar_entry:
                entry["asar_add" if nf.new else "asar_unpack"] = nf.asar_entry
            plan["natives"].append(entry)
        for k, src in enumerate(native_sources):
            app_sources.append({"type": "archive", "url": src.url, "sha256": src.sha256,
                                "dest": f"natives-src/{k}", "strip-components": 0})
        if native_sources:
            build.append("install -d ${FLATPAK_DEST}/share/debpak && cp -a natives-src ${FLATPAK_DEST}/share/debpak/")
        if pl.data.get("main_shim"):
            plan["main_shim"] = pl.data["main_shim"]
        install_helper(app, plan)
        (app / "bin" / "apply_extra").write_text(APPLY_EXTRA)
        (app / "bin" / "apply_extra").chmod(0o755)
        build += [f"rm -rf ${{FLATPAK_DEST}}/lib/{slug}/resources",
                  f"ln -s /app/extra/resources ${{FLATPAK_DEST}}/lib/{slug}/resources"]
        if any(st["kind"] == "7z" for st in replay["steps"]):
            modules.append(seven_zip_module(pl.data["branch"]))
    else:
        res_out = app / "resources"
        copy_tree(res, res_out, ignore=lambda d, names: [n for n in names if (Path(d) == res and n in drop)])
        to_unpack, to_add = [], []
        for nf in natives:
            target = res_out / nf.to
            if not str(target.resolve()).startswith(str(res_out.resolve()) + os.sep):
                raise ValueError(f"native module path {nf.to!r} leaves the resources folder")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.unlink(missing_ok=True)      # may be a hard link to the original: never write through it
            target.write_bytes(nf.data)         # empty for a built module: the build puts it in place
            if nf.asar_entry:
                (to_add if nf.new else to_unpack).append(nf.asar_entry)
            if nf.built is not None:
                build.append(f"install -Dm755 /app/share/debpak/natives-built/{nf.built}/"
                             f"{shlex.quote(nf.to.rsplit('/', 1)[-1])} "
                             f"${{FLATPAK_DEST}}/lib/{slug}/resources/{shlex.quote(nf.to)}")
        if to_unpack or to_add:
            from .unpack import asar_edit
            asar_edit(res_out / "app.asar", unpack=to_unpack, add=to_add)
        if pl.data.get("main_shim"):
            from .unpack import install_main_shim
            install_main_shim(res_out, pl.data["main_shim"])
        build.insert(0, f"cp -a resources/. ${{FLATPAK_DEST}}/lib/{slug}/resources/")

    (app / "bin").mkdir(parents=True, exist_ok=True)
    exe = electron_exe_name(slug)
    launcher = app / "bin" / slug
    launcher.write_text(
        "#!/bin/sh\n"
        f"# Generated by debpak: runs {one_line(pkg.extra.get('display_name', slug))} on the Linux build of Electron "
        f"{version}.\n"
        "# Chromium keeps its single-instance lock in TMPDIR, so give every instance the same one.\n"
        'export TMPDIR="$XDG_RUNTIME_DIR/app/$FLATPAK_ID"\n'
        "export ELECTRON_TRASH=gio\n"
        + launch_line(f"/app/lib/{slug}/{exe}", version, bool(getattr(args, "no_chromium_sandbox", False))))
    launcher.chmod(0o755)
    pl.notes += write_integration(app, app_id, pkg, slug, _icon(pkg), wm_class=pl.data.get("wm_class"))

    rid, branch = pl.data["runtime_id"], pl.data["branch"]
    from .natives import NODE_SDK, build_module
    modules += [build_module(b, k) for k, b in enumerate(native_builds)]
    modules += [
        {
            "name": "electron",
            "buildsystem": "simple",
            "build-commands": [
                f"install -d ${{FLATPAK_DEST}}/lib/{slug}",
                f"cp -a . ${{FLATPAK_DEST}}/lib/{slug}/",
                f"rm -f ${{FLATPAK_DEST}}/lib/{slug}/resources/default_app.asar",
                # Electron's app.isPackaged is false for a program named electron
                f"mv ${{FLATPAK_DEST}}/lib/{slug}/electron ${{FLATPAK_DEST}}/lib/{slug}/{exe}",
            ],
            "sources": sources,
        },
        {"name": slug, "buildsystem": "simple", "build-commands": build, "sources": app_sources},
    ]
    manifest = {
        "id": app_id,
        "runtime": rid,
        "runtime-version": branch,
        "sdk": sdk_for(rid),
        # the files are the vendor's own builds: no stripping, no debuginfo split
        "build-options": {"no-debuginfo": True},
        "base": ELECTRON_BASE,
        "base-version": pl.data.get("base_branch", branch),
        "command": slug,
        "separate-locales": False,
        "finish-args": [p.arg for p in pl.permissions],
        "modules": modules,
        # kind: convert's check (selfcheck.diagnose) treats it as the Chromium app it is
        "x-debpak": _x_debpak(pl, {"kind": "electron", "mode": "extra-data" if extra_data else "bundle",
                                   "electron": version,
                                   "native-files": sorted(nf.to for nf in natives),
                                   "native-sources": [{"url": x.url, "sha256": x.sha256, "checked": x.checked}
                                                      for x in native_sources]}),
    }
    if native_builds:
        manifest["sdk-extensions"] = [NODE_SDK]
        manifest["x-debpak"]["native-builds"] = [f"{b.name}@{b.version}" for b in native_builds]
    path = out / f"{app_id}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path


def launch_line(program: str, version: str, no_sandbox: bool) -> str:
    """Return the launcher's last line, which starts the Linux Electron under zypak or with --no-sandbox.

    zypak only works with the sandbox of Electron 5 and later (stage.ZYPAK_MIN_ELECTRON);
    an older Electron crashes under it at once, as React Proto's Electron 2 does on
    the Linux route. Such an Electron, or any for which --no-chromium-sandbox was
    passed (convert's check passes it when the app crashed at start), runs directly
    with Chromium's sandbox off.
    """
    from .stage import ELECTRON_DISABLE_SANDBOX_MIN, ZYPAK_MIN_ELECTRON
    m = re.match(r"(\d+)\.", version)
    if no_sandbox or (m and int(m.group(1)) < ZYPAK_MIN_ELECTRON):
        why = "--no-chromium-sandbox" if no_sandbox else f"Electron {version} is older than zypak supports"
        if m and int(m.group(1)) >= ELECTRON_DISABLE_SANDBOX_MIN:
            # not on the command line, where the app's own option parser sees it (see stage.sandbox_off_by_env)
            return f'# no Chromium sandbox: {why}\nexport ELECTRON_DISABLE_SANDBOX=1\nexec {program} "$@"\n'
        return f'# no Chromium sandbox: {why}\nexec {program} --no-sandbox "$@"\n'
    return f'exec zypak-wrapper {program} "$@"\n'


def seven_zip_module(branch: str) -> dict:
    """Return a module that builds 7-Zip into /app/bin, for unpacking .dmg and NSIS files at install time.

    The source pin and build steps are those of Flathub's org.winehq.Wine
    manifest. GCC 16 (the 26.08 SDK) flags a false array-bounds warning in
    7-Zip, and 7-Zip builds with -Werror, so later branches drop -Werror.
    """
    make = "make -j $FLATPAK_BUILDER_N_JOBS -f makefile.gcc"
    if branch not in ("24.08", "25.08"):
        make += ' CFLAGS_WARN_WALL="-Wall -Wextra"'
    return {
        "name": "7zip",
        "buildsystem": "simple",
        "subdir": "CPP/7zip/Bundles/Alone2",
        "build-commands": [make, "install -Dm755 ./_o/7zz -t /app/bin", "ln -s /app/bin/7zz /app/bin/7z"],
        "sources": [{"type": "git", "url": "https://github.com/ip7z/7zip.git", "tag": "26.06",
                     "commit": "d3296e39e1f1f92c7b41c0c3848e65640428d42d"}],
    }


def _x_debpak(pl: Plan, extra: dict) -> dict:
    """Return the manifest's x-debpak block, which records where the conversion came from."""
    from . import __version__
    p = pl.pkg
    return {"generator": f"debpak {__version__}", "source-package": p.path.name, "format": p.format,
            "route": pl.route, "package": f"{p.name} {p.version}", "unpacked-by": p.extra.get("unpacked_by"),
            "permission-reasons": {pm.arg: pm.reason for pm in pl.permissions}, **extra}
