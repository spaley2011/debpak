"""Programs built for Windows and macOS.

This module unpacks them and decides which route each can take:

  An Electron app from either system keeps its JavaScript (app.asar) and gets
  the Linux build of the same Electron version in place of the Windows or Mac
  one. See electron.py.

  Any other Windows program runs under Wine, from the org.winehq.Wine base
  app. See winapp.py.

  A native Mac app has no route yet. Darling can't run graphical Mac apps,
  so these are refused with a pointer to `machgap scan`.

Inputs and what unpacks them:

  .dmg                  7z (7-Zip 23 or newer also reads APFS images)
  .app folder, .zip     nothing extra
  Inno Setup .exe       innoextract
  NSIS .exe             7z (electron-builder's app-64.7z is unpacked as well)
  Squirrel Setup.exe    the .nupkg inside its resources, read here
  .msi                  msiextract (msitools)
  .msix, .appx, .nupkg  zip files, read here
  installed folder      nothing: point debpak at the program's folder

An installer that none of these can open is refused with the suggestion to
install it in Wine and convert the installed folder.
"""
from __future__ import annotations

import mmap
import os
import plistlib
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from .packages import Package, PackageError, _slug, _version_from_filename, safe_unzip

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
TOOLS = {
    "7z": "7-Zip (the 7zip package; p7zip-full on older systems)",
    "innoextract": "innoextract",
    "msiextract": "msitools",
}
# executables that come with a program but aren't the program
HELPER_EXE = re.compile(r"(^unins\d*|uninstall|^update$|updater|crashpad|crash_?handler|crashreporter|"
                        r"^setup$|installer|vc_?redist|dxsetup|dotnet|elevate|notification_helper|"
                        r"squirrel|createdump|^7z|^wow_helper|^chrome_proxy)", re.I)
INSTALL_HINT = ("Install it in Wine instead (wine \"{name}\"), then convert the installed folder, for "
                "example: debpak convert ~/.wine/drive_c/Program\\ Files/APP")


def detect(path: str | Path) -> str | None:
    """Return "dmg", "macapp" or "windows" for a Mac or Windows input, else None."""
    p = Path(path)
    if p.is_dir():
        if p.suffix.lower() == ".app" or (p / "Contents/Info.plist").is_file():
            return "macapp"
        if _find_exes(p, depth=3):
            return "windows"
        return None
    name = p.name.lower()
    try:
        with open(p, "rb") as f:
            head = f.read(8)
            f.seek(max(0, p.stat().st_size - 512))
            tail = f.read(4)
    except OSError:
        return None
    if name.endswith(".dmg") or tail == b"koly":
        return "dmg"
    if name.endswith((".exe", ".msi", ".msix", ".appx", ".nupkg")) or head[:2] == b"MZ" or head == OLE_MAGIC:
        return "windows"
    if head[:2] == b"PK" and zipfile.is_zipfile(p):
        try:
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
        except zipfile.BadZipFile:
            return None
        if any(re.search(r"\.app/Contents/Info\.plist$", n) for n in names):
            return "macapp"
        if "AppxManifest.xml" in names or any(n.lower().endswith(".nuspec") for n in names):
            return "windows"
        # a zip with Linux pieces is a Linux app even if a stray .exe comes along
        linux = any(re.search(r"(\.so(\.\d+)*|\.desktop|\.appimage|\.sh)$", n.lower()) for n in names)
        if not linux and any(n.lower().endswith(".exe") for n in names):
            return "windows"
    return None


def _tool(name: str) -> str:
    """Return the path of an extraction tool, or raise PackageError naming the package that has it."""
    found = shutil.which(name) or (name == "7z" and (shutil.which("7zz") or shutil.which("7za")))
    if not found:
        raise PackageError(f"unpacking this needs {name}: install {TOOLS.get(name, name)}")
    return found


def _run(cmd: list[str]) -> None:
    """Run an extraction tool, raising PackageError with the end of its output if it fails."""
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()[-3:]
        raise PackageError(f"{Path(cmd[0]).name} failed: {' / '.join(msg) or f'exit status {r.returncode}'}")


def _7z(path: Path, dest: Path) -> None:
    """Extract an archive or disk image with 7z, then drop symlinks that leave dest."""
    dest.mkdir(parents=True, exist_ok=True)
    _run([_tool("7z"), "x", "-y", f"-o{dest}", str(path)])
    _drop_escaping_links(dest)


def _drop_escaping_links(root: Path) -> None:
    """Delete symbolic links under root that point outside it, so nothing reads host files through them."""
    base = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            p = Path(dirpath) / n
            if p.is_symlink():
                target = (p.parent / os.readlink(p)).resolve()
                if not (target == base or str(target).startswith(str(base) + os.sep)):
                    p.unlink()


def _find_exes(root: Path, depth: int = 6) -> list[Path]:
    """Return the .exe files under root, down to depth levels, skipping NSIS's $-folders."""
    out = []
    base = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        if len(Path(dirpath).parts) - base >= depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if not d.startswith("$")]
        out += [Path(dirpath) / f for f in filenames if f.lower().endswith(".exe")]
    return sorted(out)


def _strip_single_dir(d: Path) -> Path:
    """Return the only folder in d when it holds nothing else, else d."""
    entries = [e for e in d.iterdir() if not e.name.startswith(".")]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else d


# --------------------------------------------------------------------------- Mac

def _find_app_bundle(root: Path) -> Path | None:
    """Return the shallowest *.app bundle under root (a .dmg usually has one next to an Applications link)."""
    for depth in range(4):
        hits = sorted(p for p in root.glob("/".join(["*"] * depth + ["*.app"]))
                      if p.is_dir() and not p.is_symlink() and (p / "Contents").is_dir())
        if hits:
            return hits[0]
    return None


def unpack_mac(path: Path, dest: Path) -> Path:
    """Return the .app bundle of a .dmg, a zip or an .app folder, unpacking into dest as needed.

    Raises:
        PackageError: There's no .app inside, or 7z is missing or fails.
    """
    if path.is_dir():
        return path
    out = dest / "mac"
    if zipfile.is_zipfile(path):
        safe_unzip(path, out)
    else:
        _7z(path, out)
        if not _find_app_bundle(out):
            # older 7-Zip unpacks a .dmg into partition images: open the HFS+/APFS one
            for img in sorted(out.glob("*")):
                if img.is_file() and (img.suffix.lower() in (".hfs", ".hfsx", ".apfs", ".img")
                                      or re.match(r"\d+\.(hfs|apfs)", img.name, re.I)):
                    _7z(img, out / (img.name + ".d"))
    app = _find_app_bundle(out)
    if not app:
        if any(p.suffix == ".pkg" for p in out.rglob("*.pkg")):
            raise PackageError(f"{path.name} holds a macOS .pkg installer, not an .app; debpak can't open those")
        raise PackageError(f"no .app bundle found in {path.name}")
    return app


