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


def mac_info(app: Path) -> dict:
    """Return the bundle's Info.plist as a dict ({} when it's missing or unreadable)."""
    try:
        return plistlib.loads((app / "Contents/Info.plist").read_bytes())
    except Exception:  # noqa: BLE001 - malformed plists are common enough
        return {}


# --------------------------------------------------------------------------- Windows

def _msix_info(root: Path) -> dict:
    """Read name, version, architecture and executable from an AppxManifest.xml."""
    try:
        tree = ET.parse(root / "AppxManifest.xml")
    except (ET.ParseError, OSError):
        return {}
    info: dict = {}
    for el in tree.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "Identity":
            info.setdefault("version", el.get("Version"))
            info.setdefault("arch", el.get("ProcessorArchitecture"))
            info.setdefault("id", el.get("Name"))
        elif tag == "DisplayName" and el.text and "name" not in info:
            info["name"] = el.text.strip()
        elif tag == "Description" and el.text:
            info.setdefault("description", el.text.strip())
        elif tag == "Application" and el.get("Executable"):
            info.setdefault("exe", el.get("Executable").replace("\\", "/"))
    if info.get("name", "").startswith("ms-resource:"):
        info["name"] = info.get("id") or info["name"]
    return {k: v for k, v in info.items() if v}


def _nuspec_info(root: Path) -> dict:
    """Read id, version, title and description from the .nuspec of an unzipped .nupkg."""
    spec = next(iter(sorted(root.glob("*.nuspec"))), None)
    if not spec:
        return {}
    try:
        tree = ET.parse(spec)
    except ET.ParseError:
        return {}
    info = {}
    for el in tree.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in ("id", "version", "title", "description", "projectUrl") and el.text and tag not in info:
            info[tag] = el.text.strip()
    return info


def _squirrel_nupkg(exe: Path) -> bytes | None:
    """Return the .nupkg a Squirrel Setup.exe carries in its resources, or None."""
    from .pe import PeError
    from .winres import _resources
    try:
        data = exe.read_bytes()
        img, leaves = _resources(data)
        for _path, rva, size in leaves:
            o = img.off(rva)
            blob = data[o:o + size]
            if blob[:2] == b"PK" and b".nuspec" in blob[-65536:] + blob[:4096]:
                return bytes(blob)
    except (PeError, OSError, ValueError, IndexError):
        pass
    return None


def _contains(path: Path, *needles: bytes) -> bytes | None:
    """Return the first of needles found in the file, or None."""
    with open(path, "rb") as f:
        try:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:      # empty file
            return None
        with m:
            for n in needles:
                if m.find(n) != -1:
                    return n
    return None


def unpack_windows(path: Path, dest: Path) -> tuple[Path, str, dict]:
    """Unpack a Windows installer, package or archive.

    Args:
        path: The .exe, .msi, .msix/.appx, .nupkg or .zip, or an installed
            program's folder.
        dest: An empty working folder.

    Returns:
        (program folder, how it was unpacked, metadata the package itself
        states: name, version, description, exe, homepage).

    Raises:
        PackageError: The installer type is unknown or a tool it needs is missing.
    """
    if path.is_dir():
        return path, "folder", {}
    out = dest / "win"
    out.mkdir(parents=True, exist_ok=True)
    with open(path, "rb") as f:
        head = f.read(8)
    if head == OLE_MAGIC:
        _run([_tool("msiextract"), "-C", str(out), str(path)])
        _drop_escaping_links(out)
        return out, "msi", {}
    if head[:2] != b"MZ":
        if zipfile.is_zipfile(path):
            return _unpack_zip(path, out)
        raise PackageError(f"{path.name}: not a Windows program or installer")

    marker = _contains(path, b"Inno Setup Setup Data", b"NullsoftInst", b"Nullsoft Install System",
                       b".wixburn", b"InstallShield")
    if marker == b"Inno Setup Setup Data":
        _run([_tool("innoextract"), "--silent", "--extract", "--output-dir", str(out), str(path)])
        _drop_escaping_links(out)
        app = out / "app"
        if not app.is_dir():
            raise PackageError(f"{path.name}: innoextract found no program files ({{app}} folder)")
        return app, "inno", {}
    if marker in (b"NullsoftInst", b"Nullsoft Install System"):
        _7z(path, out)
        plugins = out / "$PLUGINSDIR"
        inner = next((p for n in ("app-64.7z", "app-arm64.7z", "app-32.7z") for p in [plugins / n] if p.is_file()),
                     None)
        if inner:               # electron-builder: the real program is a 7z inside the installer
            prog = dest / "win-app"
            _7z(inner, prog)
            return prog, "nsis", {}
        for d in out.iterdir():
            if d.name.startswith("$") and d.is_dir():
                shutil.rmtree(d)
        return out, "nsis", {}
    nupkg = _squirrel_nupkg(path)
    if nupkg:
        pkgfile = dest / "setup.nupkg"
        pkgfile.write_bytes(nupkg)
        safe_unzip(pkgfile, out)
        return _squirrel_root(out), "squirrel", _nuspec_info(out)
    if zipfile.is_zipfile(path):          # a self-extracting zip
        return _unpack_zip(path, out)
    if marker == b".wixburn":
        raise PackageError(f"{path.name} is a WiX bundle, which debpak can't unpack. "
                           + INSTALL_HINT.format(name=path.name))
    if marker == b"InstallShield" or _looks_like_installer(path):
        raise PackageError(f"{path.name} looks like an installer debpak can't unpack. "
                           + INSTALL_HINT.format(name=path.name))
    shutil.copy2(path, out / path.name)       # a portable program: the .exe is the whole app
    return out, "portable", {}


def _unpack_zip(path: Path, out: Path) -> tuple[Path, str, dict]:
    """Unpack a zip-based input: an .msix/.appx, a Squirrel .nupkg, or a plain archive of a program."""
    safe_unzip(path, out)
    if (out / "AppxManifest.xml").is_file():
        return out, "msix", _msix_info(out)
    if list(out.glob("*.nuspec")):
        return _squirrel_root(out), "squirrel", _nuspec_info(out)
    return _strip_single_dir(out), "zip", {}


def _squirrel_root(out: Path) -> Path:
    """Return lib/net45 (where Squirrel packages keep the program) or the folder itself."""
    lib = out / "lib"
    if lib.is_dir():
        subs = [d for d in lib.iterdir() if d.is_dir()]
        if subs:
            return sorted(subs)[0]
    return out


