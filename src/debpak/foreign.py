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

from . import unpack
from .packages import Package, PackageError, _slug, _version_from_filename

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


class Unpacked:
    """An unpacked Windows or Mac input.

    Attributes:
        root: The program folder (Windows) or the .app bundle (Mac).
        how: How it was unpacked: folder, zip, msix, squirrel, nsis, inno, msi,
            portable, dmg or macapp.
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
    if any(s["kind"] == "7z" for s in steps):
        _tool("7z")
    try:
        return unpack.unpack(path, steps, work)
    except unpack.UnpackError as e:
        raise PackageError(f"{path.name}: {e}") from e


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


def unpack_windows(path: Path, dest: Path) -> Unpacked:
    """Unpack a Windows installer, package or archive.

    Args:
        path: The .exe, .msi, .msix/.appx, .nupkg or .zip, or an installed
            program's folder.
        dest: An empty working folder.

    Raises:
        PackageError: The installer type is unknown or a tool it needs is missing.
    """
    if path.is_dir():
        return Unpacked(path, "folder")
    out = dest / "win"
    with open(path, "rb") as f:
        head = f.read(8)
    if head == OLE_MAGIC:
        out.mkdir(parents=True, exist_ok=True)
        _run([_tool("msiextract"), "-C", str(out), str(path)])
        unpack.drop_escaping_links(out)
        return Unpacked(out, "msi")
    if head[:2] != b"MZ":
        if zipfile.is_zipfile(path):
            return _unpack_zip(path, out)
        raise PackageError(f"{path.name}: not a Windows program or installer")

    marker = _contains(path, b"Inno Setup Setup Data", b"NullsoftInst", b"Nullsoft Install System",
                       b".wixburn", b"InstallShield")
    if marker == b"Inno Setup Setup Data":
        out.mkdir(parents=True, exist_ok=True)
        _run([_tool("innoextract"), "--silent", "--extract", "--output-dir", str(out), str(path)])
        unpack.drop_escaping_links(out)
        app = out / "app"
        if not app.is_dir():
            raise PackageError(f"{path.name}: innoextract found no program files ({{app}} folder)")
        return Unpacked(app, "inno")
    if marker in (b"NullsoftInst", b"Nullsoft Install System"):
        tree = _unpack(path, [{"kind": "7z"}], out)
        inner = next((f"$PLUGINSDIR/{n}" for n in ("app-64.7z", "app-arm64.7z", "app-32.7z")
                      if (tree / "$PLUGINSDIR" / n).is_file()), None)
        if inner:               # electron-builder: the real program is a 7z inside the installer
            prog = _unpack(tree / inner, [{"kind": "7z"}], dest / "win-app")
            return Unpacked(prog, "nsis", steps=[{"kind": "7z", "inner": inner}, {"kind": "7z"}], tree=prog)
        drop = sorted(d.name for d in tree.iterdir() if d.name.startswith("$") and d.is_dir())
        for d in drop:
            shutil.rmtree(tree / d)
        return Unpacked(tree, "nsis", steps=[{"kind": "7z"}], tree=tree, drop=drop)
    if unpack.squirrel_nupkg(path.read_bytes()):
        tree = _unpack(path, [{"kind": "squirrel"}], out)
        return Unpacked(_squirrel_root(tree), "squirrel", _nuspec_info(tree), [{"kind": "squirrel"}], tree)
    if zipfile.is_zipfile(path):          # a self-extracting zip
        return _unpack_zip(path, out)
    if marker == b".wixburn":
        raise PackageError(f"{path.name} is a WiX bundle, which debpak can't unpack. "
                           + INSTALL_HINT.format(name=path.name))
    if marker == b"InstallShield" or _looks_like_installer(path):
        raise PackageError(f"{path.name} looks like an installer debpak can't unpack. "
                           + INSTALL_HINT.format(name=path.name))
    steps = [{"kind": "copy", "name": path.name}]       # a portable program: the .exe is the whole app
    tree = _unpack(path, steps, out)
    return Unpacked(tree, "portable", steps=steps, tree=tree)


def _unpack_zip(path: Path, out: Path) -> Unpacked:
    """Unpack a zip-based input: an .msix/.appx, a Squirrel .nupkg, or a plain archive of a program."""
    steps = [{"kind": "zip"}]
    tree = _unpack(path, steps, out)
    if (tree / "AppxManifest.xml").is_file():
        return Unpacked(tree, "msix", _msix_info(tree), steps, tree)
    if list(tree.glob("*.nuspec")):
        return Unpacked(_squirrel_root(tree), "squirrel", _nuspec_info(tree), steps, tree)
    return Unpacked(_strip_single_dir(tree), "zip", {}, steps, tree)


def _squirrel_root(out: Path) -> Path:
    """Return lib/net45 (where Squirrel packages keep the program) or the folder itself."""
    lib = out / "lib"
    if lib.is_dir():
        subs = [d for d in lib.iterdir() if d.is_dir()]
        if subs:
            return sorted(subs)[0]
    return out


def _looks_like_installer(exe: Path) -> bool:
    """Guess from the file name and version strings whether an .exe installs something rather than being the program."""
    from .winres import version_strings
    v = version_strings(exe)
    text = " ".join([exe.stem, v.get("FileDescription", ""), v.get("OriginalFilename", "")]).lower()
    return bool(re.search(r"setup|install|self-?extract|redist|sfx|bootstrap", text))


def pick_main_exe(root: Path, wanted: str | None = None, product: str | None = None) -> Path | None:
    """Choose the program's main .exe under root.

    wanted (a path relative to root, from --exec or the package's own
    manifest) wins. Otherwise, after dropping uninstallers, updaters and
    other helpers: an .exe named like the product, else a GUI program near
    the top, the largest first.
    """
    if wanted:
        p = root / wanted.replace("\\", "/")
        if p.is_file():
            return p
        hits = [e for e in _find_exes(root) if e.name.lower() == Path(wanted.replace("\\", "/")).name.lower()]
        return hits[0] if hits else None
    exes = [e for e in _find_exes(root) if not HELPER_EXE.search(e.stem)]
    if not exes:
        return None
    if product:
        key = re.sub(r"[^a-z0-9]", "", product.lower())
        named = [e for e in exes if re.sub(r"[^a-z0-9]", "", e.stem.lower()) == key]
        if named:
            return min(named, key=lambda e: len(e.parts))
    from .pe import PeError, read_pe

    def score(e: Path):
        try:
            gui = read_pe(e).subsystem == "gui"
        except (PeError, OSError, ValueError):
            gui = False
        return (not gui, len(e.relative_to(root).parts), -e.stat().st_size)
    return min(exes, key=score)


def find_electron(root: Path) -> Path | None:
    """Return the resources folder of an Electron app under root (Windows layout), or None."""
    for depth in range(3):
        for res in sorted(root.glob("/".join(["*"] * depth + ["resources"]))):
            if res.is_dir() and ((res / "app.asar").is_file() or (res / "app/package.json").is_file()):
                return res
    return None


# --------------------------------------------------------------------------- entry point

def open_foreign(path: str | Path, dest: str | Path, kind: str) -> Package:
    """Unpack a Mac or Windows input and return a Package for the route it can take.

    The Package's format is "electron" or "wine"; extra holds what electron.py
    or winapp.py needs.

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

    u = unpack_windows(path, dest)
    prog, how, meta = u.root, u.how, u.meta
    res = find_electron(prog)
    stem_name, stem_version = _version_from_filename(re.sub(r"\.(exe|msi|msix|appx|nupkg|zip)$", "", path.name,
                                                            flags=re.I))
    stem_name = re.sub(r"[-_ ]?(setup|installer|install|x64|win64|win32|windows)$", "", stem_name, flags=re.I) \
        or stem_name
    if res is not None:
        from .electron import package_json
        pj = package_json(res)
        app_dir = res.parent
        name = meta.get("title") or meta.get("name") or pj.get("productName") or pj.get("name") or stem_name
        version = meta.get("version") or (str(pj["version"]) if pj.get("version") else stem_version)
        pkg = Package("electron", path, root, _slug(name), version, "",
                      summary=meta.get("description", ""), homepage=meta.get("projectUrl", ""),
                      extra={"platform": "win", "resources": res, "app_dir": app_dir, "display_name": name,
                             "unpacked_by": how, **_replay(u, res)})
        pkg.notes.append(f"Windows Electron app (unpacked as {how}); its JavaScript runs on the Linux build "
                         "of Electron, so Wine isn't needed")
        return pkg

    from .winres import version_strings
    main = pick_main_exe(prog, meta.get("exe"), meta.get("name") or meta.get("title"))
    if main is None:
        raise PackageError(f"no program (.exe) found in {path.name}"
                           + ("" if how == "folder" else ". " + INSTALL_HINT.format(name=path.name)))
    v = version_strings(main)
    name = meta.get("title") or meta.get("name") or v.get("ProductName") or v.get("FileDescription") or stem_name
    version = meta.get("version") or (v.get("ProductVersion") or v.get("FileVersion") or "").replace(", ", ".") \
        or stem_version
    summary = meta.get("description") or v.get("FileDescription", "")
    if summary.strip().lower() == name.strip().lower():
        summary = ""                # FileDescription often just repeats the name
    pkg = Package("wine", path, root, _slug(name), _clean_version(version), "x86_64", summary=summary,
                  homepage=meta.get("projectUrl", ""),
                  extra={"program_dir": prog, "main_exe": main.relative_to(prog).as_posix(),
                         "display_name": name, "company": v.get("CompanyName", ""), "unpacked_by": how,
                         **_replay(u, prog)})
    pkg.notes.append(f"Windows program (unpacked as {how}); main executable {pkg.extra['main_exe']} "
                     "(guessed; override with --exec)")
    if how in ("inno", "nsis", "msi"):
        pkg.notes.append("the installer's own steps (registry entries, shortcuts, bundled runtimes) were not run; "
                         "if the program misses them, install it in Wine and convert the installed folder")
    return pkg


def _replay(u: Unpacked, keep: Path) -> dict:
    """Return the extra-data replay for an unpacked input: steps, the folder to keep, paths to drop.

    Empty when the input can't be unpacked at install time; replay_problem
    then says why.
    """
    if u.steps is None:
        why = {"folder": "a folder has nothing to download",
               "macapp": "a folder has nothing to download",
               "inno": "innoextract isn't available inside the Flatpak",
               "msi": "msiextract isn't available inside the Flatpak"}.get(u.how, "it can't be unpacked there")
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
    d = share / f"icons/hicolor/{size}x{size}/apps"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{app_id}.png").write_bytes(icon_png)
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


def copy_tree(src: Path, dst: Path, ignore=None) -> None:
    """Copy a folder, hard-linking files where src and dst share a filesystem (program folders can be large)."""
    def link_or_copy(s, d):
        try:
            os.link(s, d)
        except OSError:
            shutil.copy2(s, d)
    shutil.copytree(src, dst, symlinks=True, ignore=ignore, copy_function=link_or_copy)


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
    return name, {"type": "extra-data", "filename": name, "url": url, "sha256": h.hexdigest(),
                  "size": pkg.path.stat().st_size}


def _need_replay(pkg: Package, args) -> dict:
    """Return the package's install-time unpack steps, or raise ValueError saying why extra-data can't work."""
    if "replay" not in pkg.extra:
        raise ValueError("--mode extra-data can't be used here: "
                         + pkg.extra.get("replay_problem", "the input can't be unpacked at install time")
                         + "; use the default bundle mode")
    return pkg.extra["replay"]
