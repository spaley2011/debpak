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


