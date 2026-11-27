"""Python modules a distribution package's Python app depends on.

A .deb of a Python app (dupeGuru, Ulauncher) holds only the app's own code: its
Depends name the modules it imports (python3-pyqt5, python3-mutagen), which
the distribution installs into /usr/lib/python3/dist-packages. The runtime's
Python has none of them, and dupeGuru stopped at "No module named 'PyQt5'".

They come from the Debian release whose Python is the runtime's (trixie and
the 25.08 runtimes both have 3.13), since compiled modules are built for one
Python version (sip.cpython-313-x86_64-linux-gnu.so). Their python3-*
dependencies come along; the libraries their compiled parts link come the
usual way (see resolve.fill_gaps), and a toolkit binding picks the runtime
that has the toolkit (PyQt5: KDE 5.15, PyGObject: GNOME).
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .elf import ElfError, is_elf, read_elf

# Debian release with the runtime's Python (3.13), and the dist-packages folder its modules go in
DEBIAN_SUITE = "trixie"
SITE = "usr/lib/python3/dist-packages"
APP_SITE = "lib/debpak-python"           # under /app

# parts of Python itself, which the runtime has
PYTHON_ITSELF = {"python3", "python3-minimal", "python3-distutils", "python3-lib2to3", "python3-venv",
                 "python3-dev", "python3-all", "python3-pip", "python3-tk", "python3-setuptools",
                 "python3-pkg-resources", "python3-wheel"}
# bindings the runtime a toolkit picks already has
IN_RUNTIME = {"gnome": {"python3-gi", "python3-gi-cairo", "python3-cairo"}}
TOOLKIT_RUNTIME = (
    (("python3-pyqt5", "python3-pyside2"), "kde5"),
    (("python3-pyqt6", "python3-pyside6"), "kde6"),
    (("python3-gi",), "gnome"),
)


def is_python_script(path: Path) -> bool:
    """Return True for a script whose #! line runs Python."""
    try:
        with open(path, "rb") as f:
            first = f.readline(200)
    except OSError:
        return False
    return first.startswith(b"#!") and b"python" in first


RUNTIME_PYTHON = "3.13"
CPYTHON_ABI = re.compile(r"\.cpython-3(\d+)[a-z]*-")


def abis(root: Path) -> dict[str, str]:
    """Return the Python versions the package's compiled Python modules are built for: version -> a module."""
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*.so")):
        if (m := CPYTHON_ABI.search(p.name)):
            out.setdefault(f"3.{m.group(1)}", p.relative_to(root).as_posix())
    return out


def foreign_abi(root: Path) -> tuple[str, str] | None:
    """Return (a module, its Python version) when the package's compiled Python modules are built for
    a Python other than the runtime's, and none for the runtime's, or None."""
    found = abis(root)
    if not found or RUNTIME_PYTHON in found:
        return None
    version = sorted(found, key=lambda v: int(v.split(".")[1]))[0]
    return found[version], version


# The distribution release whose own Python is each version, for an app whose compiled modules
# are built for a Python other than the runtime's. dupeGuru 4.3.1's .deb has its core.pe._block for
# 3.7 to 3.10 and none for 3.13, and stopped at "No module named 'core.pe._block'"; it gets Python
# 3.10 and its python3-* modules from Ubuntu jammy. (kind, suite, mirror); "" is the usual mirror.
PYTHON_RELEASES = {
    "3.12": ("ubuntu", "noble", ""),
    "3.11": ("debian", "bookworm", ""),
    "3.10": ("ubuntu", "jammy", ""),
    "3.9": ("debian", "bullseye", ""),
    "3.8": ("ubuntu", "focal", ""),
    "3.7": ("debian", "buster", "http://archive.debian.org/debian"),
}
APP_PYTHON = "lib/debpak-python{v}"     # under /app: the interpreter's usr/ folder goes here


def other_python(root: Path) -> str:
    """Return the Python version to bring for the package's compiled modules, or "".

    "" when they are built for the runtime's Python, or there are none, or no
    release in PYTHON_RELEASES has one of their versions. The newest of their
    versions that one has is taken.
    """
    found = abis(root)
    if not found or RUNTIME_PYTHON in found:
        return ""
    fits = sorted((v for v in found if v in PYTHON_RELEASES), key=lambda v: int(v.split(".")[1]))
    return fits[-1] if fits else ""


def interpreter_packages(version: str) -> list[str]:
    """Return the Debian/Ubuntu packages that make up Python version: the program and its standard library."""
    return [f"python{version}-minimal", f"libpython{version}-minimal", f"libpython{version}-stdlib"]


def interpreter_command(version: str) -> str:
    """Return the path in the Flatpak of the Python fetch_interpreter put there."""
    return f"/app/{APP_PYTHON.format(v=version)}/usr/bin/python{version}"


def fetch_interpreter(version: str, source, dest: Path) -> tuple[list[str], set[str]]:
    """Copy Python version's program and standard library from source into dest (its usr/ folder and all).

    The program finds its standard library beside it, in ../lib/python3.N, so
    the folder can go anywhere.

    Returns:
        (the packages that weren't found, the libraries the program and its
        compiled modules link).
    """
    missing, needed = [], set()
    for name in interpreter_packages(version):
        try:
            pkg = source._package(name)
        except RuntimeError:
            pkg = None
        if pkg is None:
            missing.append(name)
            continue
        if (pkg.root / "usr").is_dir():
            shutil.copytree(pkg.root / "usr", dest / "usr", symlinks=True, dirs_exist_ok=True)
    for f in (dest / "usr").rglob("*") if (dest / "usr").is_dir() else []:
        if f.is_file() and not f.is_symlink() and (".so" in f.name or f.parent.name == "bin") and is_elf(f):
            try:
                needed |= set(read_elf(f).needed)
            except ElfError:
                pass
    shutil.rmtree(dest / "usr/share", ignore_errors=True)       # documentation and manual pages
    # python3 beside it, for a launcher script that runs python3 from PATH (see stage.python_entry)
    if (dest / f"usr/bin/python{version}").exists() and not os.path.lexists(dest / "usr/bin/python3"):
        (dest / "usr/bin/python3").symlink_to(f"python{version}")
    return missing, needed


# Fedora's names for Python module packages whose Debian name differs, which an rpm's Requires name
# (see debian_names)
FEDORA_NAMES = {
    "python3-gobject": "python3-gi", "python3-gobject-base": "python3-gi", "python3-pyusb": "python3-usb",
    "python3-pyserial": "python3-serial", "python3-pyyaml": "python3-yaml", "python3-pillow": "python3-pil",
    "python3-pillow-tk": "python3-pil.imagetk", "python3-qt5": "python3-pyqt5", "python3-qt5-base": "python3-pyqt5",
    "python3-qt5-webengine": "python3-pyqt5.qtwebengine", "python3-pyxdg": "python3-xdg",
    "python3-beautifulsoup4": "python3-bs4", "python3-pyOpenSSL": "python3-openssl", "python3-hidapi": "python3-hid",
    "python3-libusb1": "python3-usb1", "python3-tkinter": "python3-tk", "python3-pyaudio": "python3-pyaudio",
}


def debian_names(name: str) -> list[str]:
    """Return the Debian packages that may hold the Python module package name, the likeliest first.

    pulsar-mouse-linux's rpm Requires python3-gobject and python3-pyusb, Fedora's
    names for what Debian calls python3-gi and python3-usb; neither was found in
    trixie, and the app stopped at "No module named 'usb'". Fedora names most
    such packages after the project on PyPI and Debian after the module it
    imports, so a name that isn't Debian's is looked for by Fedora's name for it
    (FEDORA_NAMES), and python3-pyX as python3-X.
    """
    out = [name]
    if (deb := FEDORA_NAMES.get(name)):
        out.append(deb)
    if name.startswith("python3-py") and len(name) > len("python3-py") + 1:
        out.append("python3-" + name[len("python3-py"):])
    return list(dict.fromkeys(out))


def wanted(depends: set[str]) -> list[str]:
    """Return the Python module packages, and the GObject introspection data, among a package's dependencies."""
    return sorted(d for d in depends if d.startswith(("python3-", "gir1.2-")) and d not in PYTHON_ITSELF)


def toolkit_runtime(modules: list[str]) -> str | None:
    """Return the runtime kind (kde5, kde6, gnome) the toolkit binding among modules needs, or None."""
    for names, kind in TOOLKIT_RUNTIME:
        if any(n in names for m in modules for n in debian_names(m)):     # by Fedora's name too
            return kind
    return None


@dataclass
class Fetched:
    """The Python modules fetched: package -> "version from suite", the libraries their compiled parts
    link, and what couldn't be found."""
    packages: dict[str, str] = field(default_factory=dict)
    needed: set[str] = field(default_factory=set)
    missing: list[str] = field(default_factory=list)
    typelibs: list[str] = field(default_factory=list)


TYPELIB_DIR = "girepository-1.0"       # beside SITE in dest's parent, and under /app/lib/debpak-gi
APP_TYPELIBS = "lib/debpak-gi"
TYPELIB_LIBRARY = re.compile(rb"lib[\w+.-]+?\.so(?:\.\d+)*")


def _deps_of(meta: dict[str, str]) -> list[str]:
    out = []
    for key in ("Pre-Depends", "Depends"):
        for group in meta.get(key, "").split(","):
            first = group.split("|")[0].strip()
            if (name := re.sub(r"[\s(\[<:].*$", "", first)):
                out.append(name)
    return out


def fetch(modules: list[str], source, dest: Path, runtime_kind: str = "", provides=lambda so: False) -> Fetched:
    """Copy the modules (and the python3-* packages they depend on) from source into dest/SITE.

    Args:
        modules: Package names, such as python3-pyqt5.
        source: A resolve.MirrorSource for DEBIAN_SUITE.
        dest: The folder that becomes /app/APP_SITE; typelibs go in dest.parent/TYPELIB_DIR.
        runtime_kind: The runtime's kind, whose own bindings (IN_RUNTIME) are skipped.
        provides: Whether the runtime has a library. A gir1.2-* package's typelibs are taken
            only when the runtime lacks the library they describe (Ulauncher's Keybinder): the
            runtime's own typelibs (Gtk, GLib) match its libraries, Debian's needn't.
    """
    res = Fetched()
    skip = PYTHON_ITSELF | IN_RUNTIME.get(runtime_kind, set())
    queue, seen = list(modules), set()
    while queue:
        name = queue.pop(0)
        if name in seen or name in skip:
            continue
        seen.add(name)
        pkg = None
        for cand in debian_names(name):
            if cand in skip:
                break           # the runtime has it under Debian's name (python3-gobject: python3-gi)
            if cand != name and (cand in seen or cand in res.packages):
                break
            try:
                pkg = source._package(cand)
            except RuntimeError:
                pkg = None
            if pkg is not None:
                seen.add(cand)
                name = cand
                break
        else:
            res.missing.append(name)
            continue
        if pkg is None:
            continue
        if name.startswith("gir1.2-"):
            typelibs = sorted(pkg.root.glob(f"usr/lib/*/{TYPELIB_DIR}/*.typelib")) + sorted(
                pkg.root.glob(f"usr/lib/{TYPELIB_DIR}/*.typelib"))
            libs = {m.group(0).decode() for t in typelibs for m in TYPELIB_LIBRARY.finditer(t.read_bytes())}
            if not typelibs or (libs and all(provides(so) for so in libs)):
                continue
            (dest.parent / TYPELIB_DIR).mkdir(parents=True, exist_ok=True)
            for t in typelibs:
                shutil.copy2(t, dest.parent / TYPELIB_DIR / t.name)
                res.typelibs.append(t.name)
            res.packages[name] = f"{pkg.version} from {source.suite}"
            res.needed |= libs
            queue += [d for d in _deps_of(source._packages.get(name, {})) if d.startswith("gir1.2-")]
            continue
        res.packages[name] = f"{pkg.version} from {source.suite}"
        site = pkg.root / SITE
        if site.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copytree(site, dest, symlinks=True, dirs_exist_ok=True)
            for f in site.rglob("*.so*"):
                if f.is_file() and not f.is_symlink() and is_elf(f):
                    try:
                        res.needed |= set(read_elf(f).needed)
                    except ElfError:
                        pass
        queue += [d for d in _deps_of(source._packages.get(name, {})) if d.startswith(("python3-", "gir1.2-"))]
    return res
