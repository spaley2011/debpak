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
  7-Zip self-extractor  7z, on the archive after the .exe's program (7-Zip's installer)
  RAR self-extractor    bsdtar, on the archive after the .exe's program (WinRAR's, EditPlus's installer)
  Squirrel Setup.exe    the .nupkg inside its resources, read here
  .msi                  msiextract (msitools)
  WiX bundle            7z for its two cabinets, msiextract for the .msi files in them
  .msix, .appx, .nupkg  zip files, read here
  zip holding a .cab    7z for the cabinet (Total Commander's installer)
  .exe holding a .cab   7z for a cabinet with the program in it (NCH Software's installers)
  installed folder      nothing: point debpak at the program's folder

An installer that none of these can open, or that opens with no program in
it, is run silently under Wine, sandboxed, and the folder it installs is
taken (wineinstall.py). Only if that fails too is it refused, with the
suggestion to install it in Wine by hand and convert the installed folder.
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

from . import unpack
from .packages import Package, PackageError, _slug, _version_from_filename

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
TOOLS = {
    "7z": "7-Zip (the 7zip package; p7zip-full on older systems)",
    "bsdtar": "libarchive-tools (bsdtar)",
    "innoextract": "innoextract",
    "msiextract": "msitools",
}
# executables that come with a program but aren't the program (7z.exe, 7za.exe and 7zG.exe come
# with many; 7-Zip's own 7zFM.exe isn't one of them; a Squirrel app's NAME_ExecutionStub.exe
# only starts the newest installed version of it). The page processes of a browser engine a program
# embeds are helpers too: Tableau Public's QtWebEngineProcess.exe was taken for the program, and
# started alone it waits for a parent that never comes.
HELPER_EXE = re.compile(r"(^unins\d*|uninstall|^update$|updater|crashpad|crash_?handler|crashreporter|"
                        r"^setup$|installer|vc_?redist|dxsetup|^dotnet|elevate|notification_helper|"
                        r"squirrel|createdump|^7z[arg]?$|^wow_helper|^chrome_proxy|executionstub$|"
                        r"qtwebengineprocess|browser_?subprocess)", re.I)
# the newest Inno Setup each innoextract release reads (its web page's compatibility table); 1.9,
# from 2020, is still the latest release; 1.10-dev is its git master (which the debpak Flatpak
# bundles), whose version table ends at 6.4.0.1
INNOEXTRACT_READS = {"1.7": "5.6.1", "1.8": "6.0.5", "1.9": "6.2.2", "1.10": "6.4.0.1"}
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
                return _zip_kind(z)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return None
    return None


def _zip_kind(z: zipfile.ZipFile) -> str | None:
    """Return "macapp" or "windows" for a zip of a Mac or Windows program, else None.

    Near its top (in it, or in its single top folder and one below), a Linux
    program file decides for Linux and a .exe or .msi for Windows: Mission Planner
    and other .NET programs carry Linux libraries (libSkiaSharp.so) and a
    script or two beside their .exe, and Cmder has scripts deep in its vendor
    folder. Otherwise any Linux piece (a library, a menu entry, an AppImage,
    a script near the top) makes it Linux even if a stray .exe comes along.
    """
    names = z.namelist()
    if any(re.search(r"\.app/Contents/Info\.plist$", n) for n in names):
        # SunVox's zip has a build for each system: macos/SunVox.app beside linux_x86_64/sunvox
        others = [n for n in names if ".app/" not in n and not n.endswith("/") and n.count("/") <= 4]
        if any(_zip_elf_program(z, n) for n in others[:2000]):
            return None
        return "macapp"
    if "AppxManifest.xml" in names or any(n.lower().endswith(".nuspec") for n in names):
        return "windows"
    top = {n.split("/", 1)[0] for n in names}
    depth = 2 if len(top) == 1 else 1
    near = [n for n in names if n.count("/") <= depth and not n.endswith("/")]
    if any(re.search(r"\.(desktop|appimage)$", n.lower()) for n in names):
        return None
    if any(_zip_elf_program(z, n) for n in near[:500]):
        return None
    if any(n.lower().endswith(".exe") for n in near):
        return "windows"
    if any(n.lower().endswith((".msi", ".msix", ".appx")) for n in near):
        # a zip of the Windows installer alone (ScrambleID's holds its .msi and a README, Ableton
        # Live's its Setup.msi): taken for a Linux tarball, it had no main executable
        return "windows"
    linux = any(re.search(r"\.so(\.\d+)*$", n.lower()) or (n.lower().endswith(".sh") and n.count("/") <= depth)
                for n in names)
    if not linux and any(n.lower().endswith(".exe") for n in names):
        return "windows"
    return None


def _zip_elf_program(z: zipfile.ZipFile, name: str) -> bool:
    """Return whether a zip entry is an ELF file that isn't a shared library by its name."""
    if re.search(r"\.so(\.\d+)*$", name.lower()):
        return False
    with z.open(name) as f:
        return f.read(4) == b"\x7fELF"


class Unpacked:
    """An unpacked Windows or Mac input.

    Attributes:
        root: The program folder (Windows) or the .app bundle (Mac).
        how: How it was unpacked: folder, zip, cab, cab-sfx, msix, squirrel, nsis, 7z-sfx,
            rar-sfx, inno, msi, wix, wine-install, portable, dmg or macapp.
        meta: What the package itself states (name, version, description, exe,
            projectUrl).
        steps: The unpack.py steps that rebuild the files from the original
            download, or None when install-time unpacking isn't possible
            (innoextract and msiextract aren't in the Flatpak runtime, and a
            folder has nothing to download).
        tree: The folder the steps produced; root lies inside it.
        drop: Paths under root that conversion deleted (NSIS's $-folders).
    """
    def __init__(self, root: Path, how: str, meta: dict | None = None, steps: list | None = None,
                 tree: Path | None = None, drop: list | None = None):
        self.root, self.how, self.meta = root, how, meta or {}
        self.steps, self.tree, self.drop = steps, tree, drop or []

    def take(self, inner: Path | None = None) -> str:
        """Return the path of inner (default: root) relative to the unpacked tree, for an extra-data plan."""
        return (inner or self.root).relative_to(self.tree).as_posix().removeprefix(".")


def _tool(name: str) -> str:
    """Return the path of an extraction tool, or raise PackageError naming the package that has it."""
    found = unpack.seven_zip() if name == "7z" else shutil.which(name)
    if not found:
        raise PackageError(f"unpacking this needs {name}: install {TOOLS.get(name, name)}")
    return found


def _run(cmd: list[str]) -> None:
    """Run an extraction tool, raising PackageError with the end of its output if it fails."""
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()[-3:]
        raise PackageError(f"{Path(cmd[0]).name} failed: {' / '.join(msg) or f'exit status {r.returncode}'}")


def _unpack(path: Path, steps: list[dict], work: Path) -> Path:
    """Run unpack.py steps, turning their errors into PackageError (and a missing 7z into an install hint)."""
    for tool in ("7z", "bsdtar"):
        if any(s["kind"] == tool for s in steps):
            _tool(tool)
    try:
        return unpack.unpack(path, steps, work)
    except unpack.UnpackError as e:
        raise PackageError(f"{path.name}: {e}") from e


def _find_exes(root: Path, depth: int = 6) -> list[Path]:
    """Return the .exe files under root, down to depth levels, skipping NSIS's $-folders."""
    return _find_files(root, ".exe", depth)


def _find_files(root: Path, suffix: str, depth: int = 6) -> list[Path]:
    """Return the files under root whose names end in suffix (any case), down to depth levels."""
    out = []
    base = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        if len(Path(dirpath).parts) - base >= depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if not d.startswith("$")]
        out += [Path(dirpath) / f for f in filenames if f.lower().endswith(suffix)]
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


def unpack_mac(path: Path, dest: Path) -> Unpacked:
    """Find the .app bundle of a .dmg, a zip or an .app folder, unpacking into dest as needed.

    Raises:
        PackageError: There's no .app inside, or 7z is missing or fails.
    """
    if path.is_dir():
        return Unpacked(path, "macapp")
    work = dest / "mac"
    if zipfile.is_zipfile(path):
        steps = [{"kind": "zip"}]
    else:
        steps = [{"kind": "7z"}]
    tree = _unpack(path, steps, work)
    if steps[0]["kind"] == "7z" and not _find_app_bundle(tree):
        # older 7-Zip unpacks a .dmg into partition images: open the HFS+/APFS one
        for img in sorted(tree.glob("*")):
            if img.is_file() and (img.suffix.lower() in (".hfs", ".hfsx", ".apfs", ".img")
                                  or re.match(r"\d+\.(hfs|apfs)", img.name, re.I)):
                steps = [{"kind": "7z", "inner": img.name}, {"kind": "7z"}]
                tree = _unpack(img, steps[1:], dest / "mac-image")
                break
    app = _find_app_bundle(tree)
    if not app:
        if any(tree.rglob("*.pkg")):
            raise PackageError(f"{path.name} holds a macOS .pkg installer, not an .app; debpak can't open those")
        raise PackageError(f"no .app bundle found in {path.name}")
    return Unpacked(app, "dmg" if steps[0]["kind"] == "7z" else "zip", steps=steps, tree=tree)


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


def unpack_windows(path: Path, dest: Path, wine_branch: str | None = None) -> Unpacked:
    """Unpack a Windows installer, package or archive.

    An installer nothing here reads is run silently under Wine instead
    (wineinstall.py).

    Args:
        path: The .exe, .msi, .msix/.appx, .nupkg or .zip, or an installed
            program's folder.
        dest: An empty working folder.
        wine_branch: The org.winehq.Wine branch to run an installer with
            (default: the one winapp.py builds on).

    Raises:
        PackageError: The installer type is unknown or a tool it needs is missing.
    """
    if path.is_dir():
        return Unpacked(path, "folder")
    out = dest / "win"
    with open(path, "rb") as f:
        head = f.read(8)
    if head == OLE_MAGIC:
        _msiextract(path, out)
        services = msi_services(path)
        meta = {"services": services} if services else {}
        # the program its one Start-menu shortcut starts is the main one
        found = [[e for e in _find_exes(out) if e.name.lower() == n.lower()] for n in msi_shortcut_programs(path)]
        if len(found) == 1 and found[0]:
            meta["exe"] = min(found[0], key=lambda e: len(e.parts)).relative_to(out).as_posix()
        return Unpacked(out, "msi", meta)
    if head[:2] != b"MZ":
        if zipfile.is_zipfile(path):
            u = _unpack_zip(path, out)
            # a zip of an installer (Xenu's Link Sleuth's XENU.ZIP holds Setup.exe): unpack that
            if u.how == "zip" and (inner := _only_installer(u.root, path.stem)) and dest.name != "win-inner":
                return _inner(unpack_windows(inner, dest / "win-inner", wine_branch), inner)
            return u
        raise PackageError(f"{path.name}: not a Windows program or installer")

    marker = _contains(path, b"Inno Setup Setup Data", b"NullsoftInst", b"Nullsoft Install System",
                       b".wixburn", b"InstallShield")
    # a bundle inside it (the Visual C++ runtimes Rockstar Games Launcher's setup carries) doesn't
    # make it one, as it takes switches of its own, but it does make it an installer
    carries_bundle = marker == b".wixburn" and not unpack.is_burn_bundle(path)
    if carries_bundle:
        marker = _contains(path, b"InstallShield")
    if marker == b"Inno Setup Setup Data":
        out.mkdir(parents=True, exist_ok=True)
        exe = _tool("innoextract")
        lang = _inno_language(exe, path)
        try:
            _run([exe, "--silent", "--extract", *(["--language", lang] if lang else []),
                  "--output-dir", str(out), str(path)])
        except PackageError as e:
            return wine_install(path, dest, marker, wine_branch, _inno_failure(path, exe, str(e)))
        unpack.drop_escaping_links(out)
        app = out / "app"
        if not app.is_dir():
            # it installs elsewhere ({pf}\..., {userappdata}\...), as Advanced IP Scanner does
            return wine_install(path, dest, marker, wine_branch,
                                f"{path.name}: innoextract found no program files ({{app}} folder)")
        if not _find_exes(app):
            # its files are encrypted, and innoextract skips them, leaving {app} empty: Winaero
            # Tweaker's setup keeps the password in its own code, so it installs silently under Wine
            return wine_install(path, dest, marker, wine_branch,
                                f"{path.name}: innoextract unpacked no program into its {{app}} folder "
                                "(its files may be encrypted)")
        return Unpacked(app, "inno")
    if marker in (b"NullsoftInst", b"Nullsoft Install System"):
        tree = _unpack(path, [{"kind": "7z"}], out)
        inner = next((f"$PLUGINSDIR/{n}" for n in ("app-64.7z", "app-arm64.7z", "app-32.7z")
                      if (tree / "$PLUGINSDIR" / n).is_file()), None)
        if inner:               # electron-builder: the real program is a 7z inside the installer
            prog = _unpack(tree / inner, [{"kind": "7z"}], dest / "win-app")
            return Unpacked(prog, "nsis", steps=[{"kind": "7z", "inner": inner}, {"kind": "7z"}], tree=prog)
        drop = sorted(d.name for d in tree.iterdir() if d.name.startswith("$") and d.is_dir())
        if (var := _nsis_variable_dir(tree, drop)):
            # the installer works out where to install at run time, so 7z names the folder after
            # the variable that holds it ($_16_): Wrye Bash's installs Mopy into each game it finds,
            # one variable a game, and with no game installed its /S run under Wine quit at once
            return Unpacked(tree / var, "nsis", steps=[{"kind": "7z"}], tree=tree)
        for d in drop:
            shutil.rmtree(tree / d)
        return Unpacked(tree, "nsis", steps=[{"kind": "7z"}], tree=tree, drop=drop)
    if unpack.squirrel_nupkg(path.read_bytes()):
        tree = _unpack(path, [{"kind": "squirrel"}], out)
        return Unpacked(_squirrel_root(tree), "squirrel", _nuspec_info(tree), [{"kind": "squirrel"}], tree)
    if zipfile.is_zipfile(path):          # a self-extracting zip
        u = _unpack_zip(path, out)
        if u.how != "zip" or _find_exes(u.root) or _looks_like_installer(path):
            return u
        # a program that keeps a zip of resources inside it, with no program in the zip, is the
        # program itself (JetBrains' dotPeek64.exe, the portable dotPeek)
        shutil.rmtree(out)
    offset = unpack.sfx_7z_offset(path)
    if offset is not None:              # 7-Zip's installer, or one made with 7zS.sfx
        steps = [{"kind": "7z", "offset": offset}]
        tree = _unpack(path, steps, out)
        root = _strip_single_dir(tree)
        # a self-extractor of installers (Hex Editor Neo's): open the one for this machine
        if dest.name != "win-inner" and (inner := _only_installer(root, path.stem)):
            return _inner(unpack_windows(inner, dest / "win-inner", wine_branch), inner)
        return Unpacked(root, "7z-sfx", steps=steps, tree=tree)
    if (offset := unpack.sfx_rar_offset(path)) is not None:     # WinRAR's installer, EditPlus's
        # 7z lists it, but Debian's and Ubuntu's 7z can't decode RAR ("Unsupported Method")
        steps = [{"kind": "bsdtar", "offset": offset}]
        try:
            tree = _unpack(path, steps, out)
        except PackageError as e:
            return wine_install(path, dest, marker, wine_branch, str(e))
        return Unpacked(_strip_single_dir(tree), "rar-sfx", steps=steps, tree=tree)
    if marker == b".wixburn":
        return _unpack_burn(path, out) or wine_install(path, dest, marker, wine_branch,
                                                       f"{path.name} is a WiX bundle with no .msi inside")
    if marker == b"InstallShield" or carries_bundle or _looks_like_installer(path):
        if marker is None and (u := _unpack_cab_sfx(path, out)):
            # Apple's AirPortSetup.exe keeps AirPort.msi, Bonjour.msi and the like in its cabinet, with
            # SetupAdmin.exe, which installs them, as the only program
            if dest.name != "win-inner" and (inner := _only_installer(u.root, path.stem)):
                return _inner(unpack_windows(inner, dest / "win-inner", wine_branch), inner)
            return u
        if marker == b"InstallShield" and dest.name != "win-inner" and \
                (u := _unpack_issetup(path, dest, wine_branch)):
            return u
        return wine_install(path, dest, marker, wine_branch,
                            f"{path.name} looks like an installer debpak can't unpack")
    steps = [{"kind": "copy", "name": path.name}]       # a portable program: the .exe is the whole app
    tree = _unpack(path, steps, out)
    return Unpacked(tree, "portable", steps=steps, tree=tree)


# NSIS's own folders, as 7z names them, which hold no program to keep: the installer's plugins and
# temporary files, Windows' folders, shortcuts
NSIS_SYSTEM_DIR = re.compile(r"(?i)^\$(PLUGINSDIR|TEMP|SYSDIR|WINDIR|FONTS|DESKTOP|SMPROGRAMS|STARTMENU|SMSTARTUP|"
                             r"QUICKLAUNCH|SENDTO|RESOURCES|CDBURN_AREA|COMMONFILES(32|64)?|EXEDIR|R?\d)$")


def _nsis_variable_dir(tree: Path, dirs: list[str]) -> str | None:
    """Return the $-folder that holds an NSIS installer's program when nothing else does, or None.

    Only when no program lies outside the $-folders: then the program
    goes where a variable says ($_16_, $LOCALAPPDATA, $PROGRAMFILES), and
    of those with one, the one with the most files is taken (Wrye Bash's
    copies, one per game, are all alike, so the first).
    """
    if _find_exes(tree):        # it skips the $-folders
        return None
    best, most = None, 0
    for d in dirs:
        if NSIS_SYSTEM_DIR.match(d) or not _find_exes(tree / d):
            continue
        n = sum(1 for _ in (tree / d).rglob("*"))
        if n > most:
            best, most = d, n
    return best


def _unpack_burn(path: Path, out: Path) -> Unpacked | None:
    """Unpack the .msi packages a WiX bundle carries or names, or return None when it has none.

    BurnManifest.xml, in the bundle's first container, names each payload of
    the second (a0, a1, ...); the .msi files among them are unpacked like a
    plain .msi into one folder. A bundle that downloads its packages has no
    second container: EA app's names its .msi with the URL, size and hash
    Burn itself would fetch and check it with (DownloadUrl, FileSize, Hash),
    so debpak fetches it the same way (BURN_DOWNLOAD_LIMIT).
    """
    containers = unpack.burn_containers(path)
    if not containers:
        return None
    work = out.with_name("win-burn")
    work.mkdir(parents=True, exist_ok=True)
    found = []
    for (offset, size), name in zip(containers[:2], ("ux", "attached")):
        try:
            unpack.cut(path, offset, size, work / f"{name}.cab")
            found.append(_unpack(work / f"{name}.cab", [{"kind": "7z"}], work / name))
        except (unpack.UnpackError, PackageError):
            return None
    ux, attached = found[0], (found[1] if len(found) > 1 else None)
    try:
        manifest = ET.parse(ux / "0")
    except (OSError, ET.ParseError):
        return None
    # each payload under its own name, as the bundle installs it: an .msi finds the cabinets it
    # names beside it (Garmin BaseCamp's Disk_64.cab)
    payloads, msis, remote = work / "payloads", [], []
    for el in manifest.iter():
        name = (el.get("FilePath") or "").replace("\\", "/")
        if el.tag.rsplit("}", 1)[-1] != "Payload" or not name or not unpack._inside(payloads, payloads / name):
            continue
        dst = payloads / name
        if el.get("Container"):
            src = attached / (el.get("SourcePath") or "") if attached else None
            if src is None or not src.is_file() or src.parent != attached:
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(src, dst)
            if name.lower().endswith(".msi"):
                msis.append(dst)
        elif (el.get("DownloadUrl") or "").startswith("https://") and name.lower().endswith((".msi", ".cab")):
            remote.append(el)
    if not msis and any((el.get("FilePath") or "").lower().endswith(".msi") for el in remote):
        msis = _burn_download(path, remote, payloads)
    if not msis:
        return None
    services = []
    for msi in msis:
        _msiextract(msi, out)
        services += msi_services(msi)
    return Unpacked(out, "wix", {"services": services} if services else None)


# the most a WiX bundle's packages may come to for debpak to download them itself (EA app's .msi
# is 270 MB); a bigger one is left to its installer, under Wine
BURN_DOWNLOAD_LIMIT = 2 << 30


def _burn_download(path: Path, remote: list, payloads: Path) -> list[Path]:
    """Download the payloads a WiX bundle names (_unpack_burn), check each, and return the .msi files.

    Each must have the size and hash the manifest gives (SHA-1 in WiX 3,
    SHA-512 in WiX 4 and later). Returns [] when one can't be had.
    """
    import hashlib
    from . import net
    sizes = [int(el.get("FileSize") or 0) for el in remote]
    if not all(sizes) or sum(sizes) > BURN_DOWNLOAD_LIMIT:
        return []
    print(f"({path.name} downloads its packages: fetching "
          + ", ".join(el.get("FilePath") for el in remote) + f", {sum(sizes) >> 20} MB)")
    msis = []
    for el, size in zip(remote, sizes):
        dst = payloads / el.get("FilePath").replace("\\", "/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        want = (el.get("Hash") or "").lower()
        algo = {40: "sha1", 64: "sha256", 128: "sha512"}.get(len(want))
        try:
            net.download(el.get("DownloadUrl"), dst, timeout=300)
        except OSError as e:
            print(f"({el.get('FilePath')} couldn't be downloaded: {e})")
            return []
        h = hashlib.new(algo or "sha1")
        with open(dst, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        if dst.stat().st_size != size or not algo or h.hexdigest() != want:
            print(f"({el.get('FilePath')} came down unlike the one the bundle names: not the same size or hash)")
            return []
        if dst.name.lower().endswith(".msi"):
            msis.append(dst)
    return msis


# a service that's only an updater's, a browser's elevation helper or the like: the program runs
# without it (Firefox's MozillaMaintenance, Chrome's elevation_service)
HELPER_SERVICE = re.compile(r"(?i)updat|maintenance|elevat|crash|telemetry|install|repair")


def _msi_table(msi: Path, name: str) -> list[list[str]]:
    """Return the rows of one of an .msi's tables, read with msiinfo; [] when it can't be read."""
    exe = shutil.which("msiinfo")
    if not exe:
        return []
    try:
        r = subprocess.run([exe, "export", str(msi), name], capture_output=True, text=True, errors="replace",
                           timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    return [ln.split("\t") for ln in r.stdout.splitlines()[3:]] if r.returncode == 0 else []


def msi_shortcut_programs(msi: Path) -> list[str]:
    """Return the file names of the programs an .msi puts in the Start menu or on the desktop (its Shortcut table).

    An advertised shortcut targets a feature and starts its component's key
    file; any other names the file ([#FileKey]) or a path. Uninstallers and
    other helpers (HELPER_EXE) are left out. [] when msiinfo isn't there or the
    table can't be read. AirPort Utility's AirPort.msi has one shortcut, to
    APUtil.exe, beside APAgent.exe and APDiskPrefs.exe, and APDiskPrefs.exe was
    taken for the program.
    """
    rows = [r for r in _msi_table(msi, "Shortcut") if len(r) >= 5]
    if not rows:
        return []
    keys = {r[0]: r[5] for r in _msi_table(msi, "Component") if len(r) >= 6}
    files = {r[0]: r[2].split("|")[-1] for r in _msi_table(msi, "File") if len(r) >= 3}
    out = []
    for r in rows:
        component, target = r[3], r[4]
        if (m := re.fullmatch(r"\[[#!]([^\]]+)\]", target)):
            name = files.get(m.group(1), "")
        elif target.lower().endswith(".exe"):
            name = re.split(r"[\\/\]]", target)[-1]
        else:
            name = files.get(keys.get(component, ""), "")
        if name.lower().endswith(".exe") and not HELPER_EXE.search(Path(name).stem) and name not in out:
            out.append(name)
    return out


def msi_services(msi: Path) -> list[dict]:
    """Return the Windows services an .msi installs (its ServiceInstall table) that aren't HELPER_SERVICE.

    Each is {"name", "exe"}: the service's name and the file name of its
    program (the key file of its component). [] when msiinfo isn't there or
    the table can't be read. msiextract only writes the files, so a program
    that relies on one of its services (EA app's EADesktop.exe on
    EABackgroundService) finds it neither installed nor running.
    """
    def table(name: str) -> list[list[str]]:
        return _msi_table(msi, name)
    rows = [r for r in table("ServiceInstall") if len(r) >= 12]
    if not rows:
        return []
    keys = {r[0]: r[5] for r in table("Component") if len(r) >= 6}
    files = {r[0]: r[2].split("|")[-1] for r in table("File") if len(r) >= 3}
    out = []
    for r in rows:
        name, display, start, component = r[1], r[2], r[4], r[11]
        prog = files.get(keys.get(component, ""), "")
        if start == "4" or HELPER_SERVICE.search(" ".join((name, display, prog))):     # 4: disabled
            continue
        out.append({"name": name, "exe": prog})
    return out


def _msiextract(msi: Path, out: Path) -> None:
    """Unpack an .msi into out with msiextract.

    msiextract can name a folder after both halves of an MSI DefaultDir
    ("APPDIR:." for LTspice and PhraseExpress), and Wine can't open a
    program under it; the part before the colon, the folder's name on the
    target system, is kept.
    """
    out.mkdir(parents=True, exist_ok=True)
    _run([_tool("msiextract"), "-C", str(out), str(msi)])
    unpack.drop_escaping_links(out)
    for d in sorted((d for d in out.rglob("*") if d.is_dir() and ":" in d.name), key=lambda d: -len(d.parts)):
        name = d.name.split(":", 1)[0] or "_"
        # "." is the folder above it (Quark Update.msi's ".:System64"), where its files go
        target = d.parent if name == "." else d.with_name(name)
        if target.exists():
            copy_tree(d, target, dirs_exist_ok=True)
            shutil.rmtree(d)
        else:
            d.rename(target)


def _inner(u: Unpacked, installer: Path) -> Unpacked:
    """Return what an installer inside the download unpacked to, with no install-time steps.

    Its steps start from the inner installer, not from the download, so
    extra-data mode can't replay them. The installer is kept in the meta, to be
    run under Wine if what it unpacked to holds no program (see open_foreign).
    """
    u.steps = None
    u.meta.setdefault("inner_installer", str(installer))
    return u


def wine_install(path: Path, dest: Path, marker: bytes | None, wine_branch: str | None, why: str) -> Unpacked:
    """Install path silently under Wine and return the folder it installed (wineinstall.py).

    why says what stopped debpak from unpacking it; it begins the error when
    the installer doesn't install anything under Wine either.

    Raises:
        PackageError: Running it didn't install a program.
    """
    from . import wineinstall
    if wine_branch is None:
        from types import SimpleNamespace
        from .winapp import wine_branch as default_branch
        wine_branch = default_branch(SimpleNamespace())[0]
    why = why.rstrip(". ")
    st = path.stat()
    key = (str(path.resolve()), st.st_size, st.st_mtime_ns, wine_branch)
    kept = _INSTALLED.get(key)
    if kept and kept[0].is_dir():
        # converting again after the check (selfcheck) needn't install it again
        print(f"({why}; taking what it installed under Wine before)")
        root = dest / "wine-install/kept" / kept[0].name
        copy_tree(kept[0], root)
        _, exe, switches, network = kept
    else:
        print(f"({why}; running it silently under Wine instead)")
        try:
            root, exe, switches, network = wineinstall.install(path, dest / "wine-install",
                                                               wineinstall.kind_of(path, marker), wine_branch)
        except wineinstall.InstallError as e:
            raise PackageError(f"{why}, and running it under Wine didn't work either: {e}. "
                               + INSTALL_HINT.format(name=path.name)) from e
        _keep_installed(key, root, exe, switches, network)
    meta = {"switches": switches, "network": network, **({"exe": exe} if exe else {})}
    return Unpacked(root, "wine-install", meta, tree=root)


# what wine_install installed, by installer, for converting again in the same run: (a hard-linked
# copy of the program's folder, its main .exe, the switches, whether it needed the network)
_INSTALLED: dict[tuple, tuple[Path, str | None, str, bool]] = {}


def forget_installed() -> None:
    """Start a new conversion with nothing kept from an installer (_INSTALLED)."""
    for kept, *_ in _INSTALLED.values():
        shutil.rmtree(kept.parent, ignore_errors=True)
    _INSTALLED.clear()


def _keep_installed(key: tuple, root: Path, exe: str | None, switches: str, network: bool) -> None:
    """Keep a copy of what an installer installed until debpak exits (_INSTALLED).

    convert checks the app it built and may convert again with a remedy; each
    time OpenIV's installer was run again, taking up to a quarter of an hour.
    """
    import atexit
    import tempfile
    try:
        keep = Path(tempfile.mkdtemp(prefix="debpak-installed-"))
        atexit.register(shutil.rmtree, keep, True)
        copy_tree(root, keep / root.name)
    except OSError:
        return
    _INSTALLED[key] = (keep / root.name, exe, switches, network)


def _unpack_cab_sfx(path: Path, out: Path) -> Unpacked | None:
    """Unpack the cabinet an installer keeps its program in (NCH Software's), or return None.

    Only a cabinet with a program in it counts: an installer's cabinet of
    other files (an .msi's, a runtime's, the setup's own resource.dat in
    Doxillion's doxpsetup.exe, larger than the one with Doxillion.exe) is
    passed over for the next one, largest first.
    """
    work = out.with_name("win-cab-sfx")
    for n, found in enumerate(unpack.sfx_cabs(path)[:8]):
        sub = work / str(n)
        sub.mkdir(parents=True, exist_ok=True)
        try:
            unpack.cut(path, *found, sub / "program.cab")
            tree = _unpack(sub / "program.cab", [{"kind": "7z"}], sub / "files")
        except (unpack.UnpackError, PackageError):
            continue
        if _find_exes(tree):
            return Unpacked(_strip_single_dir(tree), "cab-sfx", tree=tree)
    return None


# the runtimes an installer brings along for its program, never the program's own installer: the
# Visual C++ and .NET redistributables (SMART Notebook's ndp481-x86-x64-allos-enu.exe), DirectX, WebView2
REDIST = re.compile(r"(?i)redist|^ndp\d|dotnetfx|\.net (framework|desktop runtime|runtime)|windowsdesktop-runtime|"
                    r"aspnetcore-runtime|directx|^dxsetup|^dxwebsetup|webview2|^vcrun")


def _redistributable(exe: Path) -> bool:
    from .winres import version_strings
    v = version_strings(exe)
    return any(REDIST.search(t) for t in (exe.stem, v.get("FileDescription", ""), v.get("ProductName", "")))


def _unpack_issetup(path: Path, dest: Path, wine_branch: str | None) -> Unpacked | None:
    """Open the .msi an InstallShield Suite setup carries (unpack.issetup_stream), or return None.

    SketchUp 2023's setup carries SketchUp 2023.msi beside the runtimes and
    Windows updates it installs first; under Wine the setup stopped while
    staging those ("Invalid handle") and installed nothing, silent or
    clicked through. The largest .msi that isn't a runtime's is opened as a
    downloaded one would be. None when the setup isn't a Suite one, carries
    no such .msi, or the .msi holds no program: the setup is run instead.
    """
    work = dest / "win-issetup"
    try:
        if not unpack.issetup_stream(path):
            return None
        unpack.issetup_stream(path, work)
    except (unpack.UnpackError, OSError):
        return None
    msis = sorted((m for m in _find_files(work, ".msi", depth=3) if not REDIST.search(m.stem)),
                  key=lambda m: (-m.stat().st_size, m.name))
    if not msis:
        return None
    try:
        u = unpack_windows(msis[0], dest / "win-inner", wine_branch)
    except PackageError:
        return None
    if not _find_exes(u.root):
        return None
    shutil.rmtree(work, ignore_errors=True)     # SketchUp's parts take 342 MB, its .msi's files more
    return _inner(u, path)


def _only_installer(root: Path, product: str = "") -> Path | None:
    """Return the installer to open in an unpacked archive that holds installers and no program, or None.

    There can be one for each architecture: Hex Editor Neo's 7-Zip
    self-extractor holds setup_x64.exe beside 32-bit ones, and setup_x64.exe
    was taken for the program, which installed nothing and exited. The x86-64
    one is taken, then the 32-bit one, then the largest. The runtimes an
    installer brings (REDIST) are no program, and no installer to open either:
    SMART Notebook's zip holds SMARTEducationSoftware.msi, with the .NET
    Framework's installer in its Support folder, and that was opened instead.

    An .msi is opened before an .exe installer, which on install media only
    starts the .msi: the one named like the product (product is the download's
    name), then the one nearest the top, then the largest. Apple's AirPortSetup.exe
    holds AirPort.msi beside Bonjour.msi and AppleSoftwareUpdate.msi. An .exe
    that is neither an installer nor a runtime makes the archive a program's,
    unless a setup.exe sits beside the .msi, as install media lay it out:
    Quark Update's zip holds setup.exe, Quark Update.msi and its Data1.cab, and
    SelfUpdater.exe, and "no program found" was all it got.
    """
    from .pe import PeError, read_pe
    exes = _find_exes(root, depth=2)
    msis = sorted(p for p in root.glob("*.msi") if p.is_file()) + \
        sorted(p for p in root.glob("*/*.msi") if p.is_file() and not p.parent.name.startswith("$"))
    runtimes = [e for e in exes if _redistributable(e)]
    setups = [e for e in exes if e not in runtimes and (re.match(r"(?i)(install|setup)", e.stem)
                                                        or _looks_like_installer(e))]
    others = [e for e in exes if e not in runtimes and e not in setups]
    if msis:
        keys = _name_keys(GLUED_SETUP.sub("", NAME_TAIL.sub("", product) or product) or product) if product else set()

        def msi_rank(m: Path):
            return not (_name_keys(m.stem) & keys), len(m.relative_to(root).parts), -m.stat().st_size, m.name
        msi = min(msis, key=msi_rank)
        if not others or any(e.parent == msi.parent and re.match(r"(?i)setup$", e.stem) for e in setups):
            return msi
        return None
    if not setups or others:
        return None

    def rank(e: Path):
        try:
            machine = read_pe(e).machine
        except (PeError, OSError, ValueError):
            machine = None
        return ARCH_RANK.get(machine, 2), -e.stat().st_size, e.name
    return min(setups, key=rank)


def _unpack_zip(path: Path, out: Path) -> Unpacked:
    """Unpack a zip-based input: an .msix/.appx, a Squirrel .nupkg, or a plain archive of a program.

    A zip with no program in it but a cabinet (.cab) is an installer that
    keeps the program in the cabinet (Total Commander's tcmd*.exe is a
    self-extracting zip of INSTALL.CAB and INSTALL.INF); 7z opens the cabinet.
    """
    steps = [{"kind": "zip"}]
    tree = _unpack(path, steps, out)
    if (tree / "AppxManifest.xml").is_file():
        return Unpacked(tree, "msix", _msix_info(tree), steps, tree)
    if list(tree.glob("*.nuspec")):
        return Unpacked(_squirrel_root(tree), "squirrel", _nuspec_info(tree), steps, tree)
    base = _strip_single_dir(tree)
    programs = [e for e in _find_exes(base) if not re.match(r"(?i)(install|setup)", e.stem)]
    cabs = [] if programs else sorted((p for p in base.iterdir() if p.suffix.lower() == ".cab" and p.is_file()
                                       and not p.is_symlink()), key=lambda p: (-p.stat().st_size, p.name))
    if cabs:
        inner = cabs[0].relative_to(tree).as_posix()
        prog = _unpack(cabs[0], [{"kind": "7z"}], out.with_name("win-cab"))
        return Unpacked(_strip_single_dir(prog), "cab", {}, [{"kind": "zip", "inner": inner}, {"kind": "7z"}], prog)
    return Unpacked(base, "zip", {}, steps, tree)


def _inno_language(exe: str, path: Path) -> str | None:
    """Return the installer language to extract, or None to extract the files of every language.

    Setup installs only the files of the language the user picks. innoextract
    without --language writes them all, so a later language's file replaces
    the earlier one of the same name, and a translation that's only installed
    for its own language is there too: TreeSize Free 3.4.5 found its
    TreeSizeFree.DE beside the .exe and started in German. English is taken
    when the installer has it, else the installer's first (default) language.
    """
    try:
        r = subprocess.run([exe, "--list-languages", str(path)], capture_output=True, text=True,
                           errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    langs = re.findall(r"^ - ([^\s:]+): (.*)$", r.stdout, re.M) if r.returncode == 0 else []
    if len(langs) < 2:
        return None
    for name, desc in langs:
        if name.lower() in ("en", "eng", "enu", "english", "en_us", "en-us") or desc.lower().startswith("english"):
            return name
    return langs[0][0]


def _inno_failure(path: Path, exe: str, error: str) -> str:
    """Explain an innoextract failure, saying so when the installer is newer than innoextract reads."""
    made = None
    with open(path, "rb") as f:
        try:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                found = re.search(rb"Inno Setup Setup Data \((\d+(?:\.\d+)+)\)", m)
                made = found.group(1).decode() if found else None
        except ValueError:
            pass
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
        found = re.search(r"innoextract (\d+\.\d+)", r.stdout + r.stderr)
        have = found.group(1) if found else None
    except (OSError, subprocess.SubprocessError):
        have = None
    newest = INNOEXTRACT_READS.get(have)
    if made and newest and [int(x) for x in made.split(".")] > [int(x) for x in newest.split(".")]:
        return (f"{path.name} was made with Inno Setup {made}, which is newer than innoextract {have} can read "
                f"(it reads installers up to Inno Setup {newest})")
    return error.rstrip(".") + (f" ({path.name} was made with Inno Setup {made})" if made else "")


def _squirrel_root(out: Path) -> Path:
    """Return lib/net45 (where Squirrel packages keep the program) or the folder itself."""
    lib = out / "lib"
    if lib.is_dir():
        subs = [d for d in lib.iterdir() if d.is_dir()]
        if subs:
            return sorted(subs)[0]
    return out


def _is_exe(path: Path) -> bool:
    """Return whether path is a Windows program file (an MZ header), as opposed to a zip or a folder."""
    if not path.is_file():
        return False
    with open(path, "rb") as f:
        return f.read(2) == b"MZ"


def _looks_like_installer(exe: Path) -> bool:
    """Guess from the file name and version strings whether an .exe installs something rather than being the program."""
    from .winres import version_strings
    v = version_strings(exe)
    text = " ".join([exe.stem, v.get("FileDescription", ""), v.get("OriginalFilename", "")]).lower()
    return bool(re.search(r"setup|install|self-?extract|redist|sfx|bootstrap", text))


# programs that ship next to the real one: .NET developer tools, test and sample apps
DEV_EXE = re.compile(r"(?i)^(ildasm|ilasm|ilspy|corflags|resgen|xsd|sn|al|crossgen\d*)$|test|demo|sample|benchmark")
# second modes of the same app, worse as the menu entry than the main one
ALT_MODE_EXE = re.compile(r"(?i)fullscreen|console|service|\bcli\b|\bhost\b|worker|broker|agent|daemon")
# the end of a command-line twin's name: Foo.Cli.exe, foo-cli.exe, FooConsole.exe next to Foo.exe
# what a helper's FileDescription says it is ("XYplorer 64-bit File Contents Extraction Helper")
HELPER_DESC = re.compile(r"(?i)\bhelper\b|\bplug-?in\b|shell extension|\bextraction\b")
TWIN_SUFFIX = re.compile(r"(?i)[ ._-]?(cli|console|cmd|headless|nogui)$")
ARCH_RANK = {"x86_64": 0, "i386": 1}


# what follows the name in a product or download name: a version or year, an architecture
# ("MediaMonkey 2024", "TableauPublicDesktop-64bit-2026-3-2")
NAME_TAIL = re.compile(r"(?i)([-_ .]+(v?\d[\d.]*|x64|x86|amd64|win(64|32)|(64|32)-?bits?))+$")
# an installer's name glued to the product's, with its architecture: PotPlayerSetup64,
# UbisoftConnectInstaller (a capital starts the word, so "Pinstall" isn't cut)
GLUED_SETUP = re.compile(r"(?<=[a-z0-9])(Setup|Installer|Install)[-_]?(x?64|x86|32)?$")


def _key(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _name_keys(name: str) -> set[str]:
    """Return the keys a product name matches programs by: as it is, and without a version or installer tail."""
    bare = NAME_TAIL.sub("", name) or name
    return {k for k in (_key(name), _key(bare), _key(GLUED_SETUP.sub("", bare) or bare)) if len(k) >= 3}


def pick_main_exe(root: Path, wanted: str | None = None, product: str | list[str] | None = None) -> Path | None:
    """Choose the program's main .exe under root.

    wanted (a path relative to root, from --exec or the package's own
    manifest) wins. Otherwise, after dropping uninstallers, updaters and
    other helpers, the candidates are ranked by: named like the product
    (file name, or its ProductName/FileDescription, against the product's
    names with and without a version or "Setup" tail), a file name that
    begins the product's or begins with it, a GUI program, x86-64
    before 32-bit before other architectures, not a developer tool or test
    app, not a second mode (fullscreen, console, service), nearest the
    top, largest. Two things come before all of that: a program Wine can't
    run (arm64) loses to any it can, and a command-line twin of another
    program (Foo.Cli.exe or FooConsole.exe next to Foo.exe) loses to it, even
    when the product name matches the twin better (DiscordChatExporter.Cli's
    download is named like the twin). Among programs named like the product,
    one whose description calls it a helper or plug-in loses to the rest, and
    one whose file name is the product's (or that and 64) wins over the others,
    whatever their architecture (XYplorer.exe is 32-bit, and the 64-bit XY64.exe
    and XY64contents.exe beside it don't run on their own).

    Args:
        product: Names the app goes by (package metadata, the download's
            file name), used to recognise the main program.
    """
    if wanted:
        p = root / wanted.replace("\\", "/")
        if p.is_file():
            return p
        hits = [e for e in _find_exes(root) if e.name.lower() == Path(wanted.replace("\\", "/")).name.lower()]
        return hits[0] if hits else None
    keys = {k for p in ([product] if isinstance(product, str) else product or []) if p for k in _name_keys(p)}
    # a program named like the product stays even if it looks like a helper (BCUninstaller is one)
    exes = [e for e in _find_exes(root) if not HELPER_EXE.search(e.stem) or _key(e.stem) in keys]
    if not exes:
        return None
    from .pe import PeError, read_pe
    from .winres import version_strings

    stems = {_key(e.stem) for e in exes}

    def twin(e: Path) -> bool:
        m = TWIN_SUFFIX.search(e.stem)
        return bool(m and m.start() > 0 and _key(e.stem[:m.start()]) in stems - {_key(e.stem)})

    def score(e: Path):
        try:
            info = read_pe(e)
            gui, arch = info.subsystem == "gui", ARCH_RANK.get(info.machine, 2)
            runs = info.machine in ARCH_RANK
        except (PeError, OSError, ValueError):
            gui, arch, runs = False, 2, False
        try:
            v = version_strings(e)
        except Exception:                       # noqa: BLE001 - a broken resource section isn't fatal
            v = {}
        names = {_key(e.stem)}
        if keys:
            names |= {_key(v.get("ProductName", "")), _key(v.get("FileDescription", ""))}
        # a file named exactly like the product (or that and 64) beats one only described as it:
        # XYplorer.exe is 32-bit, and its 64-bit XY64.exe "cannot be run standalone"
        stem = _key(e.stem)
        exact = stem in keys or (stem.endswith("64") and stem[:-2] in keys)
        named = exact or bool(keys & names)
        # a file whose name begins the product's, or the product's begins it, is likelier the program
        # than one named otherwise: PotPlayerMini64.exe for PotPlayer, beside KakaoUtil64.exe
        prefixed = any(len(k) >= 5 and len(stem) >= 5 and (stem.startswith(k) or k.startswith(stem))
                       for k in keys)
        helper = bool(HELPER_DESC.search(v.get("FileDescription", "")))
        # a GUI program before a console one, whatever their architecture: LaserGRBL.exe is a 32-bit
        # .NET program, and the 64-bit Autotrace/autotrace.exe beside it is a command-line tool it runs
        return (not runs, twin(e), not named, helper, not exact, not prefixed, not gui, arch,
                bool(DEV_EXE.search(e.stem)),
                bool(ALT_MODE_EXE.search(e.stem)),
                len(e.relative_to(root).parts), -e.stat().st_size)
    return min(exes, key=score)


def find_electron(root: Path) -> Path | None:
    """Return the resources folder of an Electron app under root (Windows layout), or None."""
    for depth in range(3):
        for res in sorted(root.glob("/".join(["*"] * depth + ["resources"]))):
            if res.is_dir() and ((res / "app.asar").is_file() or (res / "app/package.json").is_file()):
                return res
    return None


# --------------------------------------------------------------------------- entry point

def open_foreign(path: str | Path, dest: str | Path, kind: str, wine_branch: str | None = None) -> Package:
    """Unpack a Mac or Windows input and return a Package for the route it can take.

    The Package's format is "electron" or "wine"; extra holds what electron.py
    or winapp.py needs. wine_branch is the org.winehq.Wine branch an installer
    nothing can unpack is run with (see unpack_windows).

    Raises:
        PackageError: It can't be unpacked, or it's a native Mac app.
    """
    path, dest = Path(path), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest / "root"
    root.mkdir(exist_ok=True)
    if kind in ("dmg", "macapp"):
        u = unpack_mac(path, dest)
        app = u.root
        info = mac_info(app)
        res = app / "Contents/Resources"
        electron = (app / "Contents/Frameworks/Electron Framework.framework").exists() and \
            ((res / "app.asar").is_file() or (res / "app/package.json").is_file())
        name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or app.stem
        if not electron:
            raise PackageError(
                f"{name} is a native macOS app, not an Electron one, and there's no way to run those on "
                "Linux yet: Darling only runs command-line Mac programs so far. `machgap scan` shows what "
                "it would need.")
        pkg = Package("electron", path, root, _slug(name), info.get("CFBundleShortVersionString") or "0",
                      "", extra={"platform": "mac", "resources": res, "bundle": app, "display_name": name,
                                 "unpacked_by": u.how, "icon_file": info.get("CFBundleIconFile"),
                                 "category": info.get("LSApplicationCategoryType", ""),
                                 **_replay(u, res)})
        pkg.notes.append(f"macOS Electron app ({app.name}); its JavaScript runs on the Linux build of Electron")
        return pkg

    u = unpack_windows(path, dest, wine_branch)
    prog, how, meta = u.root, u.how, u.meta
    res = find_electron(prog)
    stem_name, stem_version = _version_from_filename(re.sub(r"\.(exe|msi|msix|appx|nupkg|zip)$", "", path.name,
                                                            flags=re.I))
    # xyplorer_full_noinstall.zip, BRU_NoInstall.zip
    stem_name = re.sub(r"([-_ .](setup|installer|install|no-?install|full|portable|bin|x64|win64|win32|windows))+$",
                       "", stem_name,
                       flags=re.I) or stem_name
    stem_name = re.sub(r"(?<=[A-Za-z])\d{3,}$", "", stem_name)     # Playnite1065: a version glued on
    stem_name = GLUED_SETUP.sub("", stem_name) or stem_name          # PotPlayerSetup64
    if res is not None:
        return _electron_package(path, root, u, res, stem_name, stem_version)

    from .winres import version_strings
    main = pick_main_exe(prog, meta.get("exe"), [meta.get("name"), meta.get("title"), stem_name])
    # any Windows program that unpacked to no program is an installer to run, whatever read it: FAF
    # Client's install4j installer opened as an archive of its own resources. So is an installer
    # inside the download (a zip's, a self-extractor's) that did
    installer = path if _is_exe(path) else Path(meta.get("inner_installer") or path)
    if main is None and how != "wine-install" and _is_exe(installer):
        # unpacked, but the program is in a part of the installer debpak can't read (Bandizip, Fiddler)
        # with its own kind's switches: an Inno setup's /VERYSILENT, not /S first
        u = wine_install(installer, dest, _contains(installer, b"Inno Setup Setup Data", b"NullsoftInst",
                                                    b"Nullsoft Install System"),
                         wine_branch, f"no program (.exe) found in {path.name}")
        prog, how, meta = u.root, u.how, u.meta
        res = find_electron(prog)
        if res is not None:
            return _electron_package(path, root, u, res, stem_name, stem_version)
        main = pick_main_exe(prog, meta.get("exe"), [meta.get("name"), meta.get("title"), stem_name])
    if main is None and not _find_exes(prog) and (dlls := _find_files(prog, ".dll")):
        # SDL3Installer.msi installs SDL3.dll, a licence and a readme into Program Files\SDL3, and
        # adds the folder to PATH for programs built with it: a library, with no app to convert
        names = ", ".join(sorted({d.name for d in dlls})[:3]) + (", ..." if len(dlls) > 3 else "")
        raise PackageError(f"{path.name} installs no program, only libraries ({names}): it's a library or "
                           "runtime for other programs, with no app to convert")
    if main is None:
        raise PackageError(f"no program (.exe) found in {path.name}"
                           + ("" if how == "folder" else ". " + INSTALL_HINT.format(name=path.name)))
    v = version_strings(main)
    name = meta.get("title") or meta.get("name") or v.get("ProductName") or v.get("FileDescription") or stem_name
    # "2, 7, 2, 0", or "2,7,2,0" as Quark Update's CheckUpdate.exe gives it
    version = meta.get("version") or re.sub(r"(?<=\d)\s*,\s*(?=\d)", ".",
                                            v.get("ProductVersion") or v.get("FileVersion") or "") \
        or stem_version
    summary = meta.get("description") or v.get("FileDescription", "")
    if summary.strip().lower() == name.strip().lower():
        summary = ""                # FileDescription often just repeats the name
    pkg = Package("wine", path, root, _slug(name), _clean_version(version), "x86_64", summary=summary,
                  homepage=meta.get("projectUrl", ""),
                  extra={"program_dir": prog, "main_exe": main.relative_to(prog).as_posix(),
                         "display_name": name, "company": v.get("CompanyName", ""), "unpacked_by": how,
                         **({"services": meta["services"]} if meta.get("services") else {}),
                         **_replay(u, prog)})
    pkg.notes.append(f"Windows program (unpacked as {how}); main executable {pkg.extra['main_exe']} "
                     "(guessed; override with --exec)")
    if how in ("inno", "nsis", "msi", "wix", "cab", "7z-sfx"):
        pkg.notes.append("the installer's own steps (registry entries, shortcuts, bundled runtimes) were not run; "
                         "if the program misses them, install it in Wine and convert the installed folder")
    _note_wine_install(pkg, u)
    return pkg


def _electron_package(path: Path, root: Path, u: Unpacked, res: Path, stem_name: str, stem_version: str) -> Package:
    """Return the Package for a Windows Electron app whose resources folder is res."""
    from .electron import package_json
    pj, meta = package_json(res), u.meta
    name = meta.get("title") or meta.get("name") or pj.get("productName") or pj.get("name") or stem_name
    version = meta.get("version") or (str(pj["version"]) if pj.get("version") else stem_version)
    pkg = Package("electron", path, root, _slug(name), version, "",
                  summary=meta.get("description", ""), homepage=meta.get("projectUrl", ""),
                  extra={"platform": "win", "resources": res, "app_dir": res.parent, "display_name": name,
                         "unpacked_by": u.how, **_replay(u, res)})
    pkg.notes.append(f"Windows Electron app (unpacked as {u.how}); its JavaScript runs on the Linux build "
                     "of Electron, so Wine isn't needed")
    _note_wine_install(pkg, u)
    # what the Wine route needs if the Electron one can't take the app (see wine_package)
    pkg.extra["wine"] = {"names": [meta.get("name"), meta.get("title"), pj.get("productName"), stem_name],
                         "exe": meta.get("exe"), "replay": _replay(u, res.parent)}
    return pkg


def wine_package(pkg: Package) -> Package | None:
    """Return the Wine route's Package for a Windows Electron app, or None when it has no program to run.

    Some Windows Electron apps can't be moved onto Linux Electron: Descript's
    beamcoder.node has no Linux build anywhere, and GitHub Desktop's JavaScript
    was compiled for Windows only. Their Windows build still runs under Wine,
    from the folder that holds the app's .exe and its resources folder.
    """
    if pkg.format != "electron" or pkg.extra.get("platform") != "win" or "wine" not in pkg.extra:
        return None
    from .winres import version_strings
    fb = pkg.extra["wine"]
    prog = pkg.extra["app_dir"]
    main = pick_main_exe(prog, fb.get("exe"), [n for n in fb.get("names", []) if n])
    if main is None:
        return None
    v = version_strings(main)
    extra = {k: pkg.extra[k] for k in ("display_name", "unpacked_by") if k in pkg.extra}
    extra.update(program_dir=prog, main_exe=main.relative_to(prog).as_posix(), company=v.get("CompanyName", ""),
                 electron=True, **fb.get("replay", {}))
    wpkg = Package("wine", pkg.path, pkg.root, pkg.name, _clean_version(pkg.version), "x86_64",
                   summary=pkg.summary, homepage=pkg.homepage, extra=extra)
    wpkg.license = pkg.license
    wpkg.notes = [n for n in pkg.notes if not n.startswith("Windows Electron app (unpacked as")]
    wpkg.notes.insert(0, f"Windows Electron app (unpacked as {pkg.extra.get('unpacked_by')}); main executable "
                         f"{extra['main_exe']} (guessed; override with --exec)")
    return wpkg


def _note_wine_install(pkg: Package, u: Unpacked) -> None:
    """Say so when the program comes from running its installer under Wine."""
    if u.how == "wine-install":
        net = ("with the network, as it downloads the program itself" if u.meta.get("network")
               else "with no network")
        sw = u.meta.get("switches")
        how = ("clicked through its installer under Wine (the keys a person would press on each page)"
               if sw == "(clicked through)" else f"ran its installer silently under Wine ({sw})")
        pkg.notes.append(f"{how}, sandboxed {net}, "
                         "and took the folder it installed; registry entries and files it put elsewhere "
                         "aren't kept")


def _replay(u: Unpacked, keep: Path) -> dict:
    """Return the extra-data replay for an unpacked input: steps, the folder to keep, paths to drop.

    Empty when the input can't be unpacked at install time; replay_problem
    then says why.
    """
    if u.steps is None:
        why = {"folder": "a folder has nothing to download",
               "macapp": "a folder has nothing to download",
               "inno": "innoextract isn't available inside the Flatpak",
               "msi": "msiextract isn't available inside the Flatpak",
               "wix": "msiextract isn't available inside the Flatpak"}.get(u.how, "it can't be unpacked there")
        return {"replay_problem": why}
    drop = list(u.drop) if keep == u.root else []
    return {"replay": {"steps": u.steps, "take": u.take(keep), "drop": drop}}


def _clean_version(v: str) -> str:
    """Return the leading version number of a version string ('v2.3.1 beta' -> '2.3.1'), or '0'."""
    m = re.match(r"v?(\d+(?:\.\d+)*[\w.+~-]*)", v.strip())
    return m.group(1) if m else "0"


# --------------------------------------------------------------------------- shared by electron.py and winapp.py

class Plan:
    """What converting a Windows or Mac app involves, before anything is written.

    Attributes:
        pkg: The Package from open_foreign.
        route: "electron" or "wine".
        details: (label, value) lines for the Application section of the report.
        permissions: finish-args, as permissions.Permission objects.
        blockers: Problems that stop the conversion unless --force is given.
        notes: Everything else the report should mention.
        data: Values the writer needs (versions, checksums, file lists).
    """
    def __init__(self, pkg: Package, route: str):
        self.pkg = pkg
        self.route = route
        self.details: list[tuple[str, str]] = []
        self.permissions: list = []
        self.blockers: list[str] = []
        self.notes: list[str] = list(pkg.notes)
        self.data: dict = {}

    def render(self) -> str:
        """Return the text report, laid out like report.render's."""
        from .report import _section
        p = self.pkg
        kind = {"electron": "Electron app", "wine": "Windows program, runs under Wine"}[self.route]
        out = [f"{p.extra.get('display_name', p.name)} {p.version} ({kind})"]
        if p.summary:
            out.append(f"  {p.summary}")
        out.append(_section("Application"))
        out += [f"  {label + ':':<14}{value}" for label, value in self.details]
        if self.permissions:
            out.append(_section("Suggested permissions"))
            out += [f"  {pm.arg:<45} # {pm.reason}" for pm in self.permissions]
        if self.notes:
            out.append(_section("Notes"))
            out += [f"  - {n}" for n in self.notes]
        out.append(_section("Verdict"))
        if self.blockers:
            out.append("  NOT CONVERTIBLE as-is:")
            out += [f"    x {b}" for b in self.blockers]
        else:
            out.append("  looks convertible")
        return "\n".join(out) + "\n"

    def to_json(self) -> dict:
        """Return the report as a dict for report.json."""
        p = self.pkg
        return {"name": p.name, "display_name": p.extra.get("display_name", p.name), "version": p.version,
                "format": p.format, "route": self.route, "source": str(p.path),
                "details": dict(self.details),
                "permissions": [{"arg": pm.arg, "reason": pm.reason} for pm in self.permissions],
                "notes": self.notes, "blockers": self.blockers}


def one_line(text: str, limit: int = 200) -> str:
    """Return text with control characters (newlines included) turned into spaces, for desktop keys and comments.

    Names and descriptions come from the vendor's files; a newline in one could
    add a key to a desktop file or a command to a launcher script.
    """
    return " ".join("".join(c if c.isprintable() else " " for c in str(text)).split())[:limit]


# the smallest icon appstreamcli compose (which flatpak-builder runs) will use
MIN_APPSTREAM_ICON = 64


def write_integration(app: Path, app_id: str, pkg: Package, command: str, icon_png: bytes | None,
                      wm_class: str | None = None, exec_codes: str = "%U") -> list[str]:
    """Write the desktop file, icon and AppStream metainfo under app/share.

    Returns notes for the report (such as a missing icon).
    """
    from .desktop import metainfo
    from .packages import _png_size
    notes = []
    share = app / "share"
    name = one_line(pkg.extra.get("display_name", pkg.name)) or pkg.name
    lines = ["[Desktop Entry]", "Type=Application", f"Name={name}"]
    if pkg.summary:
        lines.append(f"Comment={one_line(pkg.summary)}")
    lines += [f"Exec={command} {exec_codes}".rstrip(), f"Icon={app_id}", "Terminal=false",
              f"Categories={categories(pkg)}"]
    if wm_class and one_line(wm_class):
        lines.append(f"StartupWMClass={one_line(wm_class)}")
    (share / "applications").mkdir(parents=True, exist_ok=True)
    (share / "applications" / f"{app_id}.desktop").write_text("\n".join(lines) + "\n")
    if not icon_png:
        from .desktop import placeholder_icon
        icon_png = placeholder_icon(app_id)
        notes.append("no icon found; made a plain placeholder icon (AppStream won't accept an app without one)")
    tmp = app / ".icon.png"
    tmp.write_bytes(icon_png)
    size = _png_size(tmp) or 256
    tmp.unlink()
    icons = {size: icon_png}
    if size > 512:
        # Flatpak refuses an icon over 512x512 (Xenia's is 1024x1024): the build failed at export
        from .winres import shrink_png
        try:
            icons = {512: shrink_png(icon_png, 512)}
            notes.append(f"the program's icon is {size}x{size}; scaled it down to 512x512, the largest Flatpak takes")
        except ValueError:
            icons = {128: __import__("debpak.desktop", fromlist=["placeholder_icon"]).placeholder_icon(app_id)}
            notes.append(f"the program's icon is {size}x{size} and couldn't be scaled down; "
                         "added a plain placeholder icon")
    elif size < MIN_APPSTREAM_ICON:
        # appstreamcli compose finds no icon under 64x64 ("icon-not-found"), and many
        # Windows programs carry nothing bigger than 32x32 (NirSoft's tools, SharpKeys)
        from .winres import scale_png
        try:
            icons[128] = scale_png(icon_png, 128)
            notes.append(f"the program's icon is only {size}x{size}; added a 128x128 copy scaled up from it "
                         f"(AppStream needs one of {MIN_APPSTREAM_ICON}x{MIN_APPSTREAM_ICON} or more)")
        except ValueError as e:
            from .desktop import placeholder_icon
            icons[128] = placeholder_icon(app_id)
            notes.append(f"the program's icon is only {size}x{size} and couldn't be scaled up ({e}); "
                         "added a plain 128x128 placeholder icon for AppStream")
    for px, data in icons.items():
        d = share / f"icons/hicolor/{px}x{px}/apps"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{app_id}.png").write_bytes(data)
    md = share / "metainfo" / f"{app_id}.metainfo.xml"
    md.parent.mkdir(parents=True, exist_ok=True)
    md.write_text(metainfo(pkg, app_id, name, True))
    return notes


# Apple's LSApplicationCategoryType values -> freedesktop menu categories
MAC_CATEGORIES = {
    "business": "Office;", "developer-tools": "Development;", "education": "Education;",
    "entertainment": "AudioVideo;Video;", "finance": "Office;Finance;", "games": "Game;",
    "graphics-design": "Graphics;", "healthcare-fitness": "Utility;", "lifestyle": "Utility;",
    "medical": "Science;MedicalSoftware;", "music": "AudioVideo;Audio;Music;", "news": "Network;News;",
    "photography": "Graphics;Photography;", "productivity": "Office;", "reference": "Education;",
    "social-networking": "Network;Chat;", "sports": "Utility;", "travel": "Utility;",
    "utilities": "Utility;", "video": "AudioVideo;Video;", "weather": "Utility;",
}
# words in an app's name or description -> menu categories, when the app states none
KEYWORD_CATEGORIES = [
    (r"\b(game|games|gaming|play)\b", "Game;"),
    (r"\b(chat|messenger|messaging|mail|email|e-mail|slack|discord|meet|meeting|call)\b", "Network;Chat;"),
    (r"\b(browser|ftp|vpn|torrent|download manager)\b", "Network;"),
    (r"\b(music|audio|mp3|sound|podcast|tag editor|tagger)\b", "AudioVideo;Audio;"),
    (r"\b(video|movie|player|stream|recorder)\b", "AudioVideo;Video;"),
    (r"\b(photo|image|paint|draw|drawing|design|svg|3d|cad)\b", "Graphics;"),
    (r"\b(code|coding|ide|editor|terminal|developer|git|sql|database|api)\b", "Development;"),
    (r"\b(notes?|notebook|office|document|spreadsheet|calendar|todo|tasks?|wiki|pdf|writing)\b", "Office;"),
]


def categories(pkg: Package) -> str:
    """Return the desktop file's Categories value: what the app states, else a guess from its name, else Utility."""
    stated = str(pkg.extra.get("category") or "")
    m = re.search(r"app-category\.([a-z-]+)", stated)
    if m and m.group(1) in MAC_CATEGORIES:
        return MAC_CATEGORIES[m.group(1)]
    if re.fullmatch(r"([A-Za-z]+;)+", stated):           # already a freedesktop list (electron-builder's linux.category)
        return stated
    if re.fullmatch(r"[A-Za-z]+", stated):
        return stated + ";"
    text = f"{pkg.extra.get('display_name', pkg.name)} {pkg.summary}".lower()
    for pattern, cats in KEYWORD_CATEGORIES:
        if re.search(pattern, text):
            return cats
    return "Utility;"


def icns_png(path: Path, limit: int = 512) -> bytes | None:
    """Return the largest PNG image in a macOS .icns file that is at most limit pixels wide.

    When every PNG is larger than limit, the smallest of them is returned.
    JPEG 2000 and raw bitmap entries are skipped. None if there's no PNG.
    """
    import struct
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if data[:4] != b"icns":
        return None
    pngs = []
    off = 8
    while off + 8 <= len(data):
        _typ, length = struct.unpack_from(">4sI", data, off)
        if length < 8:
            break
        body = data[off + 8:off + length]
        if body[:8] == b"\x89PNG\r\n\x1a\n" and len(body) >= 24:
            pngs.append((struct.unpack_from(">I", body, 16)[0], body))
        off += length
    if not pngs:
        return None
    small = [p for p in pngs if p[0] <= limit]
    return max(small)[1] if small else min(pngs)[1]


def copy_tree(src: Path, dst: Path, ignore=None, dirs_exist_ok: bool = False) -> None:
    """Copy a folder, hard-linking files where src and dst share a filesystem (program folders can be large)."""
    def link_or_copy(s, d):
        try:
            os.link(s, d)
        except OSError:
            shutil.copy2(s, d)
    shutil.copytree(src, dst, symlinks=True, ignore=ignore, copy_function=link_or_copy, dirs_exist_ok=dirs_exist_ok)


def extra_source(pkg: Package, url: str | None) -> tuple[str, dict]:
    """Return (file name in /app/extra, extra-data source) for the package's original download.

    Raises:
        ValueError: There's no --url, or the input is a folder.
    """
    import hashlib
    if not url:
        raise ValueError("extra-data mode needs --url: the vendor's download URL for this exact file")
    if pkg.path.is_dir():
        raise ValueError("extra-data mode needs a downloaded file, not a folder")
    h = hashlib.sha256()
    with open(pkg.path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    suffix = pkg.path.suffix.lower() if re.fullmatch(r"\.[a-z0-9]{1,6}", pkg.path.suffix.lower()) else ""
    name = f"{pkg.name}{suffix or '.download'}"
    from .net import quote_url
    return name, {"type": "extra-data", "filename": name, "url": quote_url(url), "sha256": h.hexdigest(),
                  "size": pkg.path.stat().st_size}


def _need_replay(pkg: Package, args) -> dict:
    """Return the package's install-time unpack steps, or raise ValueError saying why extra-data can't work."""
    if "replay" not in pkg.extra:
        raise ValueError("--mode extra-data can't be used here: "
                         + pkg.extra.get("replay_problem", "the input can't be unpacked at install time")
                         + "; use the default bundle mode")
    return pkg.extra["replay"]
