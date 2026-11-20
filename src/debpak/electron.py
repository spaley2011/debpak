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
import shutil
import urllib.request
from pathlib import Path

from .asar import Asar, AsarError
from .foreign import Plan, copy_tree, icns_png, write_integration
from .packages import Package
from .permissions import infer
from .runtime import parse_ref, sdk_for

RELEASES = "https://github.com/electron/electron/releases/download"
RELEASE_LIST = "https://releases.electronjs.org/releases.json"
ELECTRON_BASE = "org.electronjs.Electron2.BaseApp"
DEFAULT_RUNTIME = "org.freedesktop.Platform//25.08"
ARCHES = {"x86_64": "x64", "aarch64": "arm64"}
# a module published once per platform (sharp-win32-x64, esbuild-darwin-arm64): on Linux the app
# looks for the -linux- sibling, which the Windows or Mac build doesn't include
PER_PLATFORM = re.compile(r"(^|/)(@[^/]+/)?([^/]+)-(win32|darwin)-(x64|ia32|arm64|universal)(/|$)", re.I)
# native modules that only exist for one platform; apps load them only there
PLATFORM_ONLY = re.compile(r"(^|/)(fsevents|[^/]*(darwin|macos|mac-|osx|win32|win-|windows)[^/]*)(/|$)", re.I)
VERSION_RE = re.compile(rb"Electron/(\d+\.\d+\.\d+(?:-(?:alpha|beta|nightly)\.\d+)?)")
CHROME_RE = re.compile(rb"(?<![\d.])(\d{2,3}\.0\.\d{4}\.\d{1,3})(?![\d.])")


def fetch(url: str) -> bytes:
    """Download a URL (the tests replace this)."""
    with urllib.request.urlopen(url, timeout=60) as r:       # noqa: S310 - fixed https URLs
        return r.read()


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
            for rel in json.loads(fetch(RELEASE_LIST)):
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


def _replacement(native_dir: Path, rel: str) -> Path | None:
    """Find a Linux build for a native module: same path under --native-dir, else a unique file of the same name."""
    inner = re.sub(r"^app\.asar(\.unpacked)?/", "", rel)
    for cand in (native_dir / inner, native_dir / rel):
        if cand.is_file():
            return cand
    hits = [p for p in native_dir.rglob(Path(inner).name) if p.is_file()]
    return hits[0] if len(hits) == 1 else None


def plan(pkg: Package, args) -> Plan:
    """Work out an Electron conversion: versions, native code, permissions, notes and blockers."""
    pl = Plan(pkg, "electron")
    res = pkg.extra["resources"]
    pj = package_json(res)
    display = pkg.extra.get("display_name") or pj.get("productName") or pj.get("name") or pkg.name
    pkg.extra["display_name"] = display
    if pkg.version in ("", "0") and pj.get("version"):
        pkg.version = str(pj["version"])
    pkg.summary = pkg.summary or pj.get("description", "")
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
    if rid != "org.freedesktop.Platform":
        pl.notes.append(f"{ELECTRON_BASE} expects org.freedesktop.Platform; runtime is {rid}")

    native_dir = Path(args.native_dir) if getattr(args, "native_dir", None) else None
    replace: dict[str, Path] = {}
    natives = native_modules(res)
    for rel, kind, _packed in natives:
        if kind == "linux":
            continue
        where = "Mac" if kind == "mac" else "Windows" if kind == "windows" else "unknown-format"
        repl = _replacement(native_dir, rel) if native_dir else None
        if rel.endswith(".node"):
            per = PER_PLATFORM.search(rel)
            if repl:
                replace[rel] = repl
                pl.notes.append(f"native module {rel}: using the Linux build {repl}")
            elif per:
                pl.notes.append(f"native module {rel} is the {where} build of {per.group(2) or ''}{per.group(3)}; "
                                f"the app will look for {per.group(2) or ''}{per.group(3)}-linux-x64 instead, which isn't included, "
                                "so whatever uses it will fail")
            elif PLATFORM_ONLY.search(rel):
                pl.notes.append(f"native module {rel} is {where}-only; the app shouldn't load it on Linux")
            else:
                pl.blockers.append(f"native module {rel} is built for {where}: pass --native-dir with a Linux "
                                   "build of it (same module version, built for this Electron version)")
        else:
            pl.notes.append(f"resources/{rel} is a {where} program; features of the app that start it won't work")
    pl.data["replace"] = replace
    if any(packed for rel, _k, packed in natives if rel in replace):
        pl.notes.append("app.asar is rewritten so the replaced modules load from app.asar.unpacked")
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


def _repack(src: Path, dest: Path, unpack: set[str]) -> None:
    """Copy an asar archive, marking the given paths as unpacked (their data stays in the blob, unused)."""
    import struct
    a = Asar(src)
    header = json.loads(json.dumps(a.header))
    for p in unpack:
        node = header
        for part in p.split("/"):
            node = node["files"][part]
        node.pop("offset", None)
        node["unpacked"] = True
    js = json.dumps(header, separators=(",", ":")).encode()
    padded = js + b"\0" * (-len(js) % 4)
    pickle = struct.pack("<II", 4 + len(padded), len(js)) + padded
    with open(src, "rb") as f, open(dest, "wb") as out:
        out.write(struct.pack("<II", 4, len(pickle)) + pickle)
        f.seek(a.data_offset)
        shutil.copyfileobj(f, out)


def write(pl: Plan, out: Path, app_id: str, args) -> Path:
    """Write out/app (resources, launcher, desktop integration) and the manifest; return the manifest path.

    Raises:
        ValueError: Electron's Linux download can't be described (see electron_sources).
    """
    pkg = pl.pkg
    slug = pkg.name
    version = pl.data["electron"]
    sources = electron_sources(version, getattr(args, "electron_zip", None))
    app = out / "app"
    if app.exists():
        shutil.rmtree(app)
    res_out = app / "resources"
    res = pkg.extra["resources"]
    skip = {"default_app.asar", "electron.asar"}
    copy_tree(res, res_out, ignore=lambda d, names: [n for n in names if (Path(d) == res and n in skip)
                                                     or n.endswith((".lproj", ".icns"))])
    replace: dict[str, Path] = pl.data.get("replace", {})
    to_unpack = set()
    for rel, repl in replace.items():
        inner = re.sub(r"^app\.asar(\.unpacked)?/", "", rel)
        if rel.startswith("app.asar"):
            target = res_out / "app.asar.unpacked" / inner
            if rel.startswith("app.asar/"):
                to_unpack.add(inner)
        else:
            target = res_out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.unlink(missing_ok=True)      # may be a hard link to the original: never write through it
        shutil.copy2(repl, target)
    if to_unpack:
        packed = res_out / "app.asar"
        tmp = res_out / "app.asar.new"
        _repack(packed, tmp, to_unpack)
        tmp.replace(packed)

    (app / "bin").mkdir(parents=True)
    launcher = app / "bin" / slug
    launcher.write_text(
        "#!/bin/sh\n"
        f"# Generated by debpak: runs {pkg.extra.get('display_name', slug)} on the Linux build of Electron "
        f"{version}.\n"
        "# Chromium keeps its single-instance lock in TMPDIR, so give every instance the same one.\n"
        'export TMPDIR="$XDG_RUNTIME_DIR/app/$FLATPAK_ID"\n'
        "export ELECTRON_TRASH=gio\n"
        f'exec zypak-wrapper /app/lib/{slug}/electron "$@"\n')
    launcher.chmod(0o755)
    pl.notes += write_integration(app, app_id, pkg, slug, _icon(pkg), wm_class=pl.data.get("wm_class"))

    rid, branch = pl.data["runtime_id"], pl.data["branch"]
    manifest = {
        "id": app_id,
        "runtime": rid,
        "runtime-version": branch,
        "sdk": sdk_for(rid),
        "base": ELECTRON_BASE,
        "base-version": branch,
        "command": slug,
        "separate-locales": False,
        "finish-args": [p.arg for p in pl.permissions],
        "modules": [
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
            {
                "name": slug,
                "buildsystem": "simple",
                "build-commands": [
                    f"cp -a resources/. ${{FLATPAK_DEST}}/lib/{slug}/resources/",
                    "cp -a bin share ${FLATPAK_DEST}/",
                    f"chmod +x ${{FLATPAK_DEST}}/bin/{slug}",
                ],
                "sources": [{"type": "dir", "path": "app"}],
            },
        ],
        "x-debpak": _x_debpak(pl, {"electron": version, "native-replacements": sorted(replace)}),
    }
    path = out / f"{app_id}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path


def _x_debpak(pl: Plan, extra: dict) -> dict:
    """Return the manifest's x-debpak block, which records where the conversion came from."""
    from . import __version__
    p = pl.pkg
    return {"generator": f"debpak {__version__}", "source-package": p.path.name, "format": p.format,
            "route": pl.route, "package": f"{p.name} {p.version}", "unpacked-by": p.extra.get("unpacked_by"),
            "permission-reasons": {pm.arg: pm.reason for pm in pl.permissions}, **extra}
