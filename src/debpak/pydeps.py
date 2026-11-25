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


def foreign_abi(root: Path) -> tuple[str, str] | None:
    """Return (a module, its Python version) when the package's compiled Python modules are built for
    a Python other than the runtime's, or None."""
    want = RUNTIME_PYTHON.split(".")[1]
    for p in sorted(root.rglob("*.so")):
        m = CPYTHON_ABI.search(p.name)
        if m and m.group(1) != want:
            return p.relative_to(root).as_posix(), f"3.{m.group(1)}"
    return None


def wanted(depends: set[str]) -> list[str]:
    """Return the Python module packages, and the GObject introspection data, among a package's dependencies."""
    return sorted(d for d in depends if d.startswith(("python3-", "gir1.2-")) and d not in PYTHON_ITSELF)


def toolkit_runtime(modules: list[str]) -> str | None:
    """Return the runtime kind (kde5, kde6, gnome) the toolkit binding among modules needs, or None."""
    for names, kind in TOOLKIT_RUNTIME:
        if any(m in names for m in modules):
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


def _package(source, name: str):
    """Return source's package name, or None if it hasn't got it or it fails its checksum."""
    try:
        return source._package(name)
    except RuntimeError:
        return None


def _fetch_typelibs(name: str, pkg, source, dest: Path, provides, res: Fetched) -> list[str]:
    """Copy a gir1.2-* package's typelibs unless the runtime has all their libraries; return its gir1.2-* deps."""
    typelibs = sorted(pkg.root.glob(f"usr/lib/*/{TYPELIB_DIR}/*.typelib")) + sorted(
        pkg.root.glob(f"usr/lib/{TYPELIB_DIR}/*.typelib"))
    libs = {m.group(0).decode() for t in typelibs for m in TYPELIB_LIBRARY.finditer(t.read_bytes())}
    if not typelibs or (libs and all(provides(so) for so in libs)):
        return []
    (dest.parent / TYPELIB_DIR).mkdir(parents=True, exist_ok=True)
    for t in typelibs:
        shutil.copy2(t, dest.parent / TYPELIB_DIR / t.name)
        res.typelibs.append(t.name)
    res.packages[name] = f"{pkg.version} from {source.suite}"
    res.needed |= libs
    return [d for d in _deps_of(source._packages.get(name, {})) if d.startswith("gir1.2-")]


def _linked(site: Path) -> set[str]:
    """Return the libraries the compiled modules under site link (those that can be read)."""
    needed: set[str] = set()
    for f in site.rglob("*.so*"):
        if not (f.is_file() and not f.is_symlink() and is_elf(f)):
            continue
        try:
            needed |= set(read_elf(f).needed)
        except ElfError:
            pass
    return needed


def _fetch_module(name: str, pkg, source, dest: Path, res: Fetched) -> list[str]:
    """Copy a Python module package's dist-packages into dest, noting what its compiled parts link; return the
    python3-* and gir1.2-* packages it needs."""
    res.packages[name] = f"{pkg.version} from {source.suite}"
    site = pkg.root / SITE
    if site.is_dir():
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copytree(site, dest, symlinks=True, dirs_exist_ok=True)
        res.needed |= _linked(site)
    return [d for d in _deps_of(source._packages.get(name, {})) if d.startswith(("python3-", "gir1.2-"))]


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
        pkg = _package(source, name)
        if pkg is None:
            res.missing.append(name)
        elif name.startswith("gir1.2-"):
            queue += _fetch_typelibs(name, pkg, source, dest, provides, res)
        else:
            queue += _fetch_module(name, pkg, source, dest, res)
    return res
