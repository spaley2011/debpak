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
                 "python3-dev", "python3-all", "python3-pip", "python3-setuptools",
                 "python3-pkg-resources", "python3-wheel"}
# Tkinter is a part of Python the runtimes leave out (see add_tkinter)
TKINTER = "python3-tk"
TCLTK = "_tcltk"                         # in the site folder: Tcl and Tk's libraries and their scripts
TCLTK_PACKAGES = ("libtcl8.6", "libtk8.6")
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


# a shell command that runs Python on a module or a script: "exec python3 -m prazycron.main", "python3
# /usr/share/foo/foo.py", at the start of a line or after ; & | ( or exec/env/nohup, and not quoted
_RUNS_PYTHON = re.compile(
    r"(?:^|[;&|(])[ \t]*(?:(?:exec|command|nohup|env)[ \t]+(?:\w+=\S*[ \t]+)*)*"
    r"(?:/usr(?:/local)?/bin/)?python3?(?:\.\d+)?[ \t]+(?:-\w+[ \t]+)*(?:-m[ \t]+[\w.]+|\S+\.py\b)", re.M)


def runs_python(path: Path, limit: int = 64 << 10) -> bool:
    """Return True for a shell script that starts the package's program with Python.

    PrazyCron's /usr/bin/prazycron is "exec python3 -m prazycron.main": its modules are in
    /usr/lib/python3/dist-packages, which the runtime's Python doesn't search, and it stopped at
    "No module named 'prazycron'". Such a launcher is treated as a Python program's: its
    modules go on PYTHONPATH and the python3-* packages it depends on are fetched.
    """
    try:
        if path.stat().st_size > limit:
            return False
        text = path.read_text("utf-8", "replace")
    except OSError:
        return False
    if not re.match(r"#!\s*\S*(?:/|\s)(?:ba|da|k|z)?sh\b", text):
        return False
    lines = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return bool(_RUNS_PYTHON.search(lines))


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


def foreign_gi_overrides(root: Path) -> list[str]:
    """Return the package's compiled PyGObject override modules built for a Python other than the runtime's.

    Rundfunk's snap carries Ubuntu noble's python3-gst-1.0 in its own
    dist-packages: gi/overrides/Gst.py and _gi_gst.cpython-312-x86_64-linux-gnu.so.
    Its launcher runs python3, which outside snapd is the runtime's 3.13, and
    PyGObject looks for overrides in every gi/overrides folder on the path, so
    importing Gst found the snap's Gst.py, which stopped at "cannot import name
    '_gi_gst' from 'gi.overrides'". They are listed only when they are the
    package's only compiled modules for another Python, and the package has no
    interpreter of that Python: one with more of those, or with that Python,
    runs on it (see other_python), and the modules fit it.

    Returns:
        Their paths relative to root.
    """
    def version(name: str) -> str:
        m = CPYTHON_ABI.search(name)
        return f"3.{m.group(1)}" if m else ""

    found, other = [], False
    for p in sorted(root.rglob("*.so")):
        if version(p.name) in ("", RUNTIME_PYTHON):
            continue
        if p.parent.name == "overrides" and p.parent.parent.name == "gi" and p.name.startswith("_gi_"):
            stem = p.name.split(".", 1)[0]
            if not any(version(s.name) == RUNTIME_PYTHON for s in p.parent.glob(f"{stem}.cpython-*.so")):
                found.append(p.relative_to(root).as_posix())
        else:
            other = True
    if other or any(next(root.rglob(f"bin/python{version(Path(rel).name)}"), None) for rel in found):
        return []           # nor when the package has the Python they are built for, which runs them
    return found


def replace_gi_overrides(root: Path, overrides: list[str], source, triplet: str) -> list[str]:
    """Put the Debian builds of the overrides (see foreign_gi_overrides) for the runtime's Python in their place.

    The package that has _gi_gst.cpython-313-<triplet>.so in the release whose
    Python is the runtime's (python3-gst-1.0 in trixie) is looked up in the
    mirror's file list; its gi/overrides files replace the package's, in the
    package's folder, so they are found where the old ones were whatever the
    app's launcher puts on the Python path. The old compiled module is removed.
    An override no package has is left as it was.

    Args:
        source: A resolve.MirrorSource for DEBIAN_SUITE.

    Returns:
        The packages used, as "name version".
    """
    tag = "cpython-" + RUNTIME_PYTHON.replace(".", "")
    used = []
    for rel in overrides:
        old = root / rel
        want = f"{old.name.split('.', 1)[0]}.{tag}-{triplet}.so"
        try:
            if source._contents is None:
                source._load_contents()
            names = [n for _path, n in source._contents.get(want, []) if not n.endswith(("-dbg", "-dbgsym"))]
            pkg = source._package(names[0]) if names else None
        except (OSError, RuntimeError):
            pkg = None
        overrides_dir = pkg.root / SITE / "gi/overrides" if pkg else None
        if not overrides_dir or not (overrides_dir / want).is_file():
            continue
        for f in overrides_dir.iterdir():
            if f.is_file() and not f.name.startswith("__init__"):
                dest = old.parent / f.name
                if dest.is_symlink() or dest.exists():
                    dest.unlink()
                shutil.copy2(f, dest)
        old.unlink()
        if (note := f"{pkg.name} {pkg.version}") not in used:
            used.append(note)
    return used


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


# a GObject introspection namespace a Python program asks for: gi.require_version("Gtk", "3.0"), or a
# helper of its own with the same first two arguments (Rundfunk's require_namespace("AyatanaAppIndicator3",
# "0.1", ...)), or gi.require_versions({"Gtk": "3.0", ...})
# (libadwaita's version is "1": gi.require_version('Adw', '1'))
GI_REQUIRE = re.compile(rb"require_\w*\(\s*['\"]([A-Z][A-Za-z0-9]*)['\"]\s*,\s*['\"](\d+(?:\.\d+)?)['\"]")
GI_REQUIRE_MANY = re.compile(rb"require_versions\(\s*\{([^}]*)\}")
GI_PAIR = re.compile(rb"['\"]([A-Z][A-Za-z0-9]*)['\"]\s*:\s*['\"](\d+(?:\.\d+)?)['\"]")
# namespaces of GLib and GObject introspection itself, which come with PyGObject wherever it is
GI_CORE = {"GLib", "GObject", "Gio", "GModule", "GIRepository"}


def gi_requirements(root: Path, limit: int = 20000) -> list[tuple[str, str]]:
    """Return the GObject introspection namespaces (name, version) the Python code under root asks for,
    other than GI_CORE and those whose typelib is under root."""
    found: dict[tuple[str, str], None] = {}
    have: set[str] = set()
    seen = 0
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            if f.endswith(".typelib"):
                have.add(f[:-len(".typelib")])
            if not f.endswith(".py") or seen >= limit:
                continue
            seen += 1
            p = Path(d) / f
            try:
                if p.is_symlink() or p.stat().st_size > (1 << 20):
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if b"require_" not in data:
                continue
            pairs = GI_REQUIRE.findall(data)
            for m in GI_REQUIRE_MANY.finditer(data):
                pairs += GI_PAIR.findall(m.group(1))
            for ns, ver in pairs:
                found[(ns.decode(), ver.decode())] = None
    return [(ns, ver) for ns, ver in found if ns not in GI_CORE and f"{ns}-{ver}" not in have]


def gir_package(namespace: str, version: str) -> str:
    """Return the name Debian and Ubuntu give the package of a namespace's typelib, by their convention:
    gir1.2-ayatanaappindicator3-0.1 for AyatanaAppIndicator3 0.1."""
    return f"gir1.2-{namespace.lower()}-{version}"


def gir_alternatives(name: str, index) -> list[str]:
    """Return the packages in a release's index that may hold the typelib a name made by gir_package is
    for, when the release has no package by that name: Debian names the package of Dbusmenu 0.4's
    typelib gir1.2-dbusmenu-glib-0.4, after its library, not gir1.2-dbusmenu-0.4. Those whose name
    begins with the namespace's and ends with its version, the shortest first."""
    m = re.fullmatch(r"gir1\.2-(.+)-(\d+(?:\.\d+)?)", name)
    if not m or not index:
        return []
    head, tail = f"gir1.2-{m.group(1)}-", f"-{m.group(2)}"
    return sorted((n for n in index if n != name and n.startswith(head) and n.endswith(tail)),
                  key=lambda n: (len(n), n))


def _typelibs(root: Path) -> list[Path]:
    return sorted(root.glob(f"usr/lib/*/{TYPELIB_DIR}/*.typelib")) + sorted(root.glob(f"usr/lib/{TYPELIB_DIR}/*.typelib"))


def wanted(depends: set[str]) -> list[str]:
    """Return the Python module packages, and the GObject introspection data, among a package's dependencies."""
    return sorted(d for d in depends if d.startswith(("python3-", "gir1.2-")) and d not in PYTHON_ITSELF)


def toolkit_runtime(modules: list[str]) -> str | None:
    """Return the runtime kind (kde5, kde6, gnome) the toolkit binding among modules needs, or None.

    Debian splits PySide6 into a package per Qt module (python3-pyside6.qtwidgets), and AdGuard VPN
    GUI's .deb depends on those alone: it got the freedesktop runtime, Qt 6.4 from Ubuntu under
    PySide6 6.8, and stopped at "undefined symbol: _ZN7QObject13doSetProperty...". Such a part
    picks the runtime its binding does.
    """
    for names, kind in TOOLKIT_RUNTIME:
        if any(n.split(".")[0] in names for m in modules for n in debian_names(m)):     # by Fedora's name too
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


def add_tkinter(pkg, source, dest: Path, res: Fetched) -> None:
    """Copy Tkinter from Debian's python3-tk into dest, with the Tcl and Tk it is built against.

    PrazyCron's .deb depends on python3-tk, which debpak took for a part of Python the runtime has;
    the runtimes' Python has no tkinter, and the app stopped at "Unable to start GUI: No module named
    'tkinter'". Debian keeps it, in python3.13-tk (trixie's python3-tk only depends on that), in the
    standard library's folder (usr/lib/python3.13/tkinter and
    lib-dynload/_tkinter.cpython-313-x86_64-linux-gnu.so), not in dist-packages; both go in the site
    folder, which is on PYTHONPATH. Tcl's init.tcl insists on the exact release of the library that
    reads it, so libtcl8.6 and libtk8.6 come from the same release as their scripts, into dest/TCLTK
    (lib/ for the libraries, the launcher puts it on LD_LIBRARY_PATH and points TCL_LIBRARY and
    TK_LIBRARY at the scripts), and only what they link in turn is left to the library gap.
    """
    dest.mkdir(parents=True, exist_ok=True)
    # trixie's python3-tk holds nothing but its dependency on python3.13-tk, which has the files
    roots = [pkg.root]
    for dep in _deps_of((getattr(source, "_packages", None) or {}).get(TKINTER, {})):
        if re.fullmatch(r"python3\.\d+-tk", dep):
            try:
                versioned = source._package(dep)
            except RuntimeError:
                versioned = None
            if versioned is not None:
                res.packages[dep] = f"{versioned.version} from {source.suite}"
                roots.append(versioned.root)
    for root in roots:
        for d in sorted(root.glob("usr/lib/python3*/tkinter")):
            if d.is_dir():
                shutil.copytree(d, dest / "tkinter", symlinks=True, dirs_exist_ok=True)
    mods = [f for root in roots for f in sorted(root.glob("usr/lib/python3*/lib-dynload/_tkinter*.so"))
            if f.is_file()]
    for f in mods:
        shutil.copy2(f, dest / f.name)
    own: set[str] = set()
    needed: set[str] = set()
    for f in mods:
        try:
            needed |= set(read_elf(f).needed)
        except ElfError:
            pass
    for name in TCLTK_PACKAGES:
        try:
            lib = source._package(name)
        except RuntimeError:
            lib = None
        if lib is None:
            continue
        res.packages[name] = f"{lib.version} from {source.suite}"
        for f in sorted(lib.root.glob("usr/lib/*/lib*.so*")) + sorted(lib.root.glob("usr/lib/lib*.so*")):
            if f.is_file() and not f.is_symlink() and is_elf(f):
                (dest / TCLTK / "lib").mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest / TCLTK / "lib" / f.name)
                try:
                    info = read_elf(f)
                except ElfError:
                    continue
                own |= {f.name} | ({info.soname} if info.soname else set())
                needed |= set(info.needed)
        for d in sorted(lib.root.glob("usr/share/tcltk/*")):
            if d.is_dir() and not d.is_symlink():
                shutil.copytree(d, dest / TCLTK / d.name, symlinks=True, dirs_exist_ok=True)
    res.needed |= {so for so in needed if so not in own}


def fetch(modules: list[str], source, dest: Path, runtime_kind: str = "", provides=lambda so: False,
          optional: frozenset[str] | set[str] = frozenset()) -> Fetched:
    """Copy the modules (and the python3-* packages they depend on) from source into dest/SITE.

    Args:
        modules: Package names, such as python3-pyqt5.
        source: A resolve.MirrorSource for DEBIAN_SUITE.
        dest: The folder that becomes /app/APP_SITE; typelibs go in dest.parent/TYPELIB_DIR.
        runtime_kind: The runtime's kind, whose own bindings (IN_RUNTIME) are skipped.
        provides: Whether the runtime has a library. A gir1.2-* package's typelibs are taken
            only when the runtime lacks the library they describe (Ulauncher's Keybinder): the
            runtime's own typelibs (Gtk, GLib) match its libraries, Debian's needn't.
        optional: Packages whose names were made from a namespace (gir_package), which aren't
            reported missing when the release has no package by that name.
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
            if name in optional:
                # a namespace's typelib in a package Debian names otherwise (see gir_alternatives): the
                # one that holds it, as gir_package spells it in lower case
                want = name[len("gir1.2-"):].lower() + ".typelib"
                for alt in gir_alternatives(name, getattr(source, "_packages", None) or {}):
                    if alt in seen or alt in res.packages:
                        break
                    try:
                        cand = source._package(alt)
                    except RuntimeError:
                        cand = None
                    if cand is not None and any(t.name.lower() == want for t in _typelibs(cand.root)):
                        pkg, name = cand, alt
                        seen.add(alt)
                        break
            if pkg is None:
                if name not in optional:
                    res.missing.append(name)
                continue
        if pkg is None:
            continue
        if pkg is None:
            continue
        if name.startswith("gir1.2-"):
            typelibs = _typelibs(pkg.root)
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
        if name == TKINTER:
            add_tkinter(pkg, source, dest, res)
            continue
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
