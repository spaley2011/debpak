"""Electron apps from Windows and macOS, rebuilt on the Linux build of Electron.

An Electron app is mostly JavaScript in resources/app.asar. The Windows or
Mac part is Electron itself, which the same Electron release also ships for
Linux. So the conversion keeps the app's resources folder and puts it next
to the Linux electron binary of the same version, inside a Flatpak on the
org.electronjs.Electron2.BaseApp base (zypak provides Chromium's sandbox).

What can stop it is native code. Node modules (.node files) compiled for
Windows or macOS can't load on Linux. Modules that only exist for one
platform, such as fsevents, are skipped by the app on Linux anyway. Others
need a Linux build of the same module, which --native-dir supplies.

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
GNOME_ON_FREEDESKTOP = {"46": "23.08", "47": "24.08", "48": "24.08", "49": "25.08", "50": "25.08"}
GNOME_FOR_FREEDESKTOP = {"24.08": "47", "25.08": "49"}
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
        build.insert(0, f"cp -a resources/. ${{FLATPAK_DEST}}/lib/{slug}/resources/")

    (app / "bin").mkdir(parents=True, exist_ok=True)
    launcher = app / "bin" / slug
    launcher.write_text(
        "#!/bin/sh\n"
        f"# Generated by debpak: runs {one_line(pkg.extra.get('display_name', slug))} on the Linux build of Electron "
        f"{version}.\n"
        "# Chromium keeps its single-instance lock in TMPDIR, so give every instance the same one.\n"
        'export TMPDIR="$XDG_RUNTIME_DIR/app/$FLATPAK_ID"\n'
        "export ELECTRON_TRASH=gio\n"
        f'exec zypak-wrapper /app/lib/{slug}/electron "$@"\n')
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
        "base": ELECTRON_BASE,
        "base-version": pl.data.get("base_branch", branch),
        "command": slug,
        "separate-locales": False,
        "finish-args": [p.arg for p in pl.permissions],
        "modules": modules,
        "x-debpak": _x_debpak(pl, {"mode": "extra-data" if extra_data else "bundle", "electron": version,
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
