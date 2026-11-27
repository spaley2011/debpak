"""Fill soname gaps by pulling individual libraries out of distribution packages:
.debs/.rpms/pacman packages you downloaded, a Debian/Ubuntu mirror, or an RPM
repository (Fedora, openSUSE, RHEL/EPEL).

Sources are tried in order. Each resolved library is copied into a staging
lib dir under its soname, then its own DT_NEEDED entries are fed back into
the queue until each one is provided by the runtime, the app or the bundle,
or is reported as unresolved.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .analyze import is_never_bundle
from .deb import DebError, DebPackage, extract, resolve_in_root
from .elf import ElfError, ElfInfo, is_elf, read_elf
from .runtime import TRIPLETS, RuntimeIndex, cache_dir
from . import net


@dataclass
class Provided:
    """A library file a source found: the soname, the file to copy, and where it came from."""
    soname: str
    file: Path            # real file on disk to copy
    origin: str           # "package-name (version)" or deb path


class Source:
    """Somewhere to look for missing libraries. Subclasses implement find()."""
    name = "source"

    def find(self, soname: str) -> Provided | None:  # pragma: no cover - interface
        """Return the library file for soname, or None if this source doesn't have it."""
        raise NotImplementedError


def _lib_dirs_rel(arch: str) -> list[str]:
    """Return the library folders to look in, relative to a package root, most specific first."""
    t = TRIPLETS.get(arch, f"{arch}-linux-gnu")
    return [f"usr/lib/{t}", f"lib/{t}", "usr/lib", "lib", "usr/lib64", "lib64"]


class LocalDebSource(Source):
    """A directory of packages you downloaded yourself (`apt download`, `dnf download`,
    pacman's cache ...): .deb, .rpm and .pkg.tar.* files."""

    name = "local"

    def __init__(self, directory: str | Path, arch: str, workdir: Path):
        self.directory = Path(directory)
        self.arch = arch
        self.workdir = workdir
        self._index: dict[str, tuple[DebPackage, Path]] | None = None

    def _build(self) -> None:
        """Unpack every package in the folder once and index the .so files in their library folders."""
        from .packages import PackageError, is_package_file, open_package
        self._index = {}
        for i, deb in enumerate(sorted(p for p in self.directory.iterdir() if is_package_file(p))):
            try:
                pkg = open_package(deb, self.workdir / f"local-{i}")
            except (PackageError, DebError):
                continue
            for d in _lib_dirs_rel(self.arch):
                base = pkg.root / d
                if not base.is_dir():
                    continue
                for entry in base.iterdir():
                    if ".so" not in entry.name or entry.name in self._index:
                        continue
                    real = resolve_in_root(pkg.root, f"{d}/{entry.name}")
                    if real and real.is_file() and is_elf(real):
                        self._index[entry.name] = (pkg, real)

    def find(self, soname: str) -> Provided | None:
        """Return the library from the first package (in name order) that ships it."""
        if self._index is None:
            self._build()
        hit = self._index.get(soname)
        if not hit:
            return None
        pkg, real = hit
        return Provided(soname, real, f"{pkg.name} ({pkg.version}) from {pkg.path.name}")


# The fields of a mirror's Packages index that debpak reads: where the .deb is, its checksum and what it
# depends on (pydeps follows that)
PACKAGES_FIELDS = frozenset({"Package", "Version", "Filename", "SHA256", "Depends", "Pre-Depends"})


def _stanzas(lines, keep: frozenset[str]):
    """Yield the stanzas of a deb822 file read line by line, each with only the fields in keep.

    Ubuntu noble's universe Packages index is some 90 MB of text: read whole and
    split, with every field of every package kept, it took over a gigabyte, and
    a conversion on a machine short of memory was killed while loading it.
    """
    fields: dict[str, str] = {}
    key = None
    for line in lines:
        if not line.strip():
            if fields:
                yield fields
            fields, key = {}, None
            continue
        if line[0] in " \t":
            if key in fields:
                cont = line[1:].rstrip("\n")
                fields[key] += "\n" + ("" if cont.strip() == "." else cont)
            continue
        k, sep, val = line.partition(":")
        key = k.strip() if sep else None
        if key in keep:
            fields[key] = val.strip()
    if fields:
        yield fields


class MirrorSource(Source):
    """Debian/Ubuntu archive mirror, using Contents-<arch> to map files to
    packages and Packages to locate and verify the .deb."""

    name = "mirror"

    def __init__(self, mirror: str, suite: str, components: list[str], arch: str, deb_arch: str, workdir: Path):
        self.mirror = mirror.rstrip("/")
        self.suite = suite
        self.components = components
        self.arch = arch
        self.deb_arch = deb_arch
        self.workdir = workdir
        self.cache = cache_dir() / "mirror" / re.sub(r"[^A-Za-z0-9.]+", "_", f"{self.mirror}_{suite}_{deb_arch}")
        self._contents: dict[str, list[tuple[str, str]]] | None = None  # soname -> [(path, pkg)]
        self._packages: dict[str, dict[str, str]] | None = None
        self._extracted: dict[str, DebPackage] = {}

    # -- index download/caching
    def _fetch(self, url: str, dest: Path) -> bool:
        """Download url to dest unless it's already cached; return False if the download fails."""
        if dest.is_file():
            return True
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            net.download(url, Path(str(dest) + ".part"), timeout=60)
        except OSError:
            return False
        os.replace(str(dest) + ".part", dest)
        return True

    def _load_contents(self) -> None:
        """Load (and cache as sonames.json) the soname -> [(path, package)] map from the mirror's Contents-<arch> files."""
        cached = self.cache / "sonames.json"
        if cached.is_file():
            self._contents = json.loads(cached.read_text())
            return
        per_component = [f"{self.mirror}/dists/{self.suite}/{c}/Contents-{self.deb_arch}.gz"
                         for c in self.components]
        top_level = [f"{self.mirror}/dists/{self.suite}/Contents-{self.deb_arch}.gz"]  # Ubuntu / older Debian
        contents: dict[str, list[tuple[str, str]]] = {}
        lib_dirs = tuple(d + "/" for d in _lib_dirs_rel(self.arch))
        got_any = False
        for group_no, group in enumerate((per_component, top_level)):
            if got_any:
                break
            for i, url in enumerate(group):
                local = self.cache / f"Contents-{group_no}-{i}.gz"
                if not self._fetch(url, local):
                    continue
                got_any = True
                with gzip.open(local, "rt", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = line.rstrip("\n").rsplit(None, 1)
                        if len(parts) != 2:
                            continue
                        path, locs = parts
                        if not path.startswith(lib_dirs) or ".so" not in path:
                            continue
                        base = path.rsplit("/", 1)[-1]
                        for loc in locs.split(","):
                            contents.setdefault(base, []).append((path, loc.rsplit("/", 1)[-1]))
        if not got_any:
            raise RuntimeError(f"could not download a Contents index from {self.mirror} ({self.suite})")
        self._contents = contents
        cached.write_text(json.dumps(contents))

    def _load_packages(self) -> None:
        """Load the Packages index, which gives each package's .deb path and checksum."""
        self._packages = {}
        for c in self.components:
            for ext, opener in ((".xz", lzma.open), (".gz", gzip.open)):
                url = f"{self.mirror}/dists/{self.suite}/{c}/binary-{self.deb_arch}/Packages{ext}"
                local = self.cache / f"Packages-{c}{ext}"
                if not self._fetch(url, local):
                    continue
                with opener(local, "rt", encoding="utf-8", errors="replace") as f:
                    for fields in _stanzas(f, PACKAGES_FIELDS):
                        if "Package" in fields and "Filename" in fields:
                            self._packages.setdefault(fields["Package"], fields)
                break

    def _package(self, name: str) -> DebPackage | None:
        """Download, verify and unpack one package from the mirror.

        Returns None if the package isn't listed or the download fails.

        Raises:
            RuntimeError: The .deb's SHA-256 doesn't match the Packages index.
        """
        if name in self._extracted:
            return self._extracted[name]
        if self._packages is None:
            self._load_packages()
        meta = self._packages.get(name)
        if not meta:
            return None
        deb = self.cache / "debs" / Path(meta["Filename"]).name
        if not self._fetch(f"{self.mirror}/{meta['Filename']}", deb):
            return None
        want = meta.get("SHA256")
        if want and hashlib.sha256(deb.read_bytes()).hexdigest() != want:
            deb.unlink()
            raise RuntimeError(f"checksum mismatch for {deb.name}")
        pkg = extract(deb, self.workdir / f"mirror-{name}")
        self._extracted[name] = pkg
        return pkg

    def find(self, soname: str) -> Provided | None:
        """Return the library from the first runtime package that ships it; -dev and debug packages are skipped."""
        if self._contents is None:
            self._load_contents()
        for path, pkgname in self._contents.get(soname, []):
            # skip -dbg / -dev packages; they don't carry runtime libs
            if pkgname.endswith(("-dbg", "-dbgsym", "-dev")):
                continue
            pkg = self._package(pkgname)
            if not pkg:
                continue
            real = resolve_in_root(pkg.root, path)
            if real and real.is_file() and is_elf(real):
                return Provided(soname, real, f"{pkg.name} ({pkg.version}) from {self.suite}")
        return None


_RPM_NS = {"c": "http://linux.duke.edu/metadata/common", "rpm": "http://linux.duke.edu/metadata/rpm",
           "repo": "http://linux.duke.edu/metadata/repo"}
_RPM_ARCH = {"x86_64": "x86_64", "aarch64": "aarch64", "i386": "i686", "arm": "armv7hl"}
_PROVIDE_SO = re.compile(r"^(?P<so>[^()\s]+\.so(?:\.[0-9][0-9.]*)?)\(\)(?P<b64>\(64bit\))?$")


class RpmRepoSource(Source):
    """An RPM repository (Fedora, openSUSE, RHEL/EPEL, ...), given its base URL, the
    folder that holds repodata/. repodata's primary.xml lists what each package
    provides, including library sonames ("libfoo.so.1()(64bit)"), so a missing
    library maps straight to the package that ships it."""

    name = "rpm-repo"

    def __init__(self, baseurl: str, arch: str, workdir: Path):
        self.base = baseurl.rstrip("/")
        self.arch = arch
        self.rpm_arch = _RPM_ARCH.get(arch, arch)
        self.workdir = workdir
        self.cache = cache_dir() / "rpm-repo" / re.sub(r"[^A-Za-z0-9.]+", "_", f"{self.base}_{arch}")
        self._index: dict[str, dict] | None = None
        self._extracted: dict[str, object] = {}

    def _fetch(self, url: str, dest: Path) -> bool:
        return _fetch(url, dest)

    def _load(self) -> None:
        """Load (and cache) the soname -> package map from the repository's primary.xml."""
        cached = self.cache / "sonames.json"
        if cached.is_file():
            self._index = json.loads(cached.read_text())
            return
        import xml.etree.ElementTree as ET
        repomd = self.cache / "repomd.xml"
        if not self._fetch(f"{self.base}/repodata/repomd.xml", repomd):
            raise RuntimeError(f"no repodata/repomd.xml under {self.base}")
        href = None
        for data in ET.parse(repomd).getroot().findall("repo:data", _RPM_NS):
            if data.get("type") == "primary":
                loc = data.find("repo:location", _RPM_NS)
                href = loc.get("href") if loc is not None else None
        if not href:
            raise RuntimeError(f"{self.base}: repomd.xml has no primary metadata")
        primary = self.cache / Path(href).name
        if not self._fetch(f"{self.base}/{href}", primary):
            raise RuntimeError(f"couldn't download {href}")
        from .packages import _decompressed
        want_64 = self.arch in ("x86_64", "aarch64")
        index: dict[str, dict] = {}
        with _decompressed(primary) as f:
            for _ev, el in ET.iterparse(f):
                if el.tag != f"{{{_RPM_NS['c']}}}package":
                    continue
                name = el.findtext("c:name", "", _RPM_NS)
                arch = el.findtext("c:arch", "", _RPM_NS)
                if arch not in (self.rpm_arch, "noarch") or name.endswith(("-debuginfo", "-debugsource",
                                                                           "-devel")):
                    el.clear()
                    continue
                loc = el.find("c:location", _RPM_NS)
                chk = el.find("c:checksum", _RPM_NS)
                ver = el.find("c:version", _RPM_NS)
                entry = {"name": name, "href": loc.get("href") if loc is not None else "",
                         "sha256": chk.text if chk is not None and chk.get("type") == "sha256" else "",
                         "version": f"{ver.get('ver')}-{ver.get('rel')}" if ver is not None else ""}
                for p in el.findall("c:format/rpm:provides/rpm:entry", _RPM_NS):
                    m = _PROVIDE_SO.match(p.get("name", ""))
                    if m and bool(m.group("b64")) == want_64:
                        index.setdefault(m.group("so"), entry)
                el.clear()
        self._index = index
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps(index))

    def find(self, soname: str) -> Provided | None:
        """Download, verify and unpack the package that provides soname, and return the library.

        Raises:
            RuntimeError: The downloaded package's SHA-256 doesn't match primary.xml.
        """
        if self._index is None:
            self._load()
        meta = self._index.get(soname)
        if not meta or not meta["href"]:
            return None
        pkg = self._extracted.get(meta["href"])
        if pkg is None:
            from .rpm import extract_rpm
            rpm = self.cache / "rpms" / Path(meta["href"]).name
            if not self._fetch(f"{self.base}/{meta['href']}", rpm):
                return None
            if meta["sha256"] and hashlib.sha256(rpm.read_bytes()).hexdigest() != meta["sha256"]:
                rpm.unlink()
                raise RuntimeError(f"checksum mismatch for {rpm.name}")
            pkg = extract_rpm(rpm, self.workdir / f"rpm-{len(self._extracted)}")
            self._extracted[meta["href"]] = pkg
        for d in _lib_dirs_rel(self.arch):
            real = resolve_in_root(pkg.root, f"{d}/{soname}")
            if real and real.is_file() and is_elf(real):
                return Provided(soname, real, f"{pkg.name} ({pkg.version}) from {self.base}")
        return None


def _fetch(url: str, dest: Path) -> bool:
    """Download url to dest unless it's already cached; return False if the download fails."""
    if dest.is_file():
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        net.download(url, Path(str(dest) + ".part"), timeout=60)
    except OSError:
        return False
    os.replace(str(dest) + ".part", dest)
    return True


# Packages a package depends on that are never brought in as programs: they need root or the host's
# services, or the runtime has what they're for under another name
NOT_BUNDLED_PROGRAMS = frozenset({
    "sudo", "pkexec", "policykit-1", "polkitd", "systemd", "udev", "dbus", "dbus-x11", "pulseaudio",
    "pipewire", "adduser", "passwd", "login", "cron", "anacron", "kmod", "mount", "fuse", "fuse3",
    "util-linux", "procps", "coreutils", "bash", "dash", "debconf", "dpkg", "rpm", "apt", "dnf",
})


def _executables(root: Path):
    """Yield the package's programs: executable ELF files and scripts."""
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = Path(dirpath) / fn
            try:
                if p.is_symlink() or not p.is_file() or not os.access(p, os.X_OK):
                    continue
                with open(p, "rb") as f:
                    head = f.read(4)
            except OSError:
                continue
            if head == b"\x7fELF" or head[:2] == b"#!":
                yield p


def wanted_programs(pkg, runtime_programs: set[str]) -> list[str]:
    """Return the programs the package depends on and runs by name, which the runtime lacks.

    gorsync's RPM requires rsync, and its program runs rsync, which the
    Freedesktop runtime doesn't have: it stopped at start, showing an error
    dialog (rsync not found) before GTK was set up, and crashed. A package
    named in Depends or Requires counts when a program of the package names it
    as a word of its own, and neither the runtime nor the package has a
    program by that name; libraries, -dev and data packages, privileged tools
    and the daemon an app is the front end of (see analyze.privileged_parts)
    don't.
    """
    from .analyze import BIN_DIRS, package_depends
    from .maintscripts import fronts_daemon
    root = pkg.root
    ships = {p.name for d in BIN_DIRS if (root / d).is_dir() for p in (root / d).iterdir()}
    names = {pkg.name, *ships}
    cands = {d for d in package_depends(pkg)
             if re.fullmatch(r"[a-z][a-z0-9+.-]*[a-z0-9]", d) and not d.startswith("lib")
             and not d.endswith(("-dev", "-devel", "-common", "-data", "-doc"))
             and d not in runtime_programs and d not in ships and d not in NOT_BUNDLED_PROGRAMS
             and not any(fronts_daemon(n, d) for n in names)}
    if not cands:
        return []
    pats = {d: re.compile(rb"(?<![A-Za-z0-9_-])" + re.escape(d.encode()) + rb"(?![A-Za-z0-9_-])")
            for d in cands}
    found: set[str] = set()
    import mmap
    for prog in _executables(root):
        try:
            with open(prog, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                found |= {d for d in cands - found if pats[d].search(m)}
        except (OSError, ValueError):
            continue
        if found == cands:
            break
    return sorted(found)


def _needs_own_folders(prog: Path, root: Path) -> bool:
    """Return True if prog names a folder or file of its own package under /usr/lib, /usr/libexec or
    /usr/share: git runs its commands from /usr/lib/git-core, and alone it wouldn't work."""
    data = prog.read_bytes()
    for m in re.finditer(rb"/usr/(?:lib|libexec|share)/[\w.+-]+", data):
        rel = m.group(0).decode()[1:]
        if rel.startswith(("usr/share/doc", "usr/share/man", "usr/share/locale")):
            continue
        if (root / rel).exists():
            return True
    return False


def add_programs(names: list[str], sources: list[Source], root: Path) -> dict[str, str]:
    """Copy the program each named package carries (usr/bin/<name>) into the package's usr/bin.

    The first source that has the package and a program by its name there
    gives it; one that needs folders of its own package is left out. The
    libraries the program needs are found later, with the app's.

    Returns:
        Program name -> where it came from.
    """
    out: dict[str, str] = {}
    for name in names:
        for src in sources:
            if not hasattr(src, "_package"):
                continue
            try:
                dep = src._package(name)
            except (RuntimeError, DebError, OSError):
                dep = None
            if dep is None:
                continue
            prog = next((r for d in ("usr/bin", "bin") if (r := resolve_in_root(dep.root, f"{d}/{name}"))
                         and r.is_file() and is_elf(r)), None)
            if prog is None or _needs_own_folders(prog, dep.root):
                break
            dest = root / "usr/bin" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(prog, dest)
            os.chmod(dest, 0o755)
            out[name] = f"{dep.name} ({dep.version}) from {getattr(src, 'suite', src.name)}"
            break
    return out


# Libraries whose helper programs sit in a folder beside them, which goes along (by soname: the
# folder). WebKitGTK starts WebKitNetworkProcess and WebKitWebProcess from the path it was built
# with (/usr/lib/x86_64-linux-gnu/webkit2gtk-4.0); Tauri 1 apps such as Pot need 4.0, which only
# Ubuntu has, and stopped with "Failed to spawn child process"
HELPER_DIRS = {"libwebkit2gtk-4.0.so.37": "webkit2gtk-4.0", "libwebkit2gtk-4.1.so.0": "webkit2gtk-4.1"}


# Qt WebEngine (Chromium) starts QtWebEngineProcess from its Qt's libexec folder and reads its .pak
# resources and locales from where its distribution put them; a copy from Ubuntu takes them along
# (the resources from the -data package beside it). MindForger's RPM, on the KDE 5.15 runtime, which
# has no WebEngine: "Could not find QtWebEngineProcess", then an abort. soname -> (Qt folder, data
# package, resources folder, locales folder)
QT_WEBENGINE = {
    "libQt5WebEngineCore.so.5": ("qt5", "libqt5webengine-data", "usr/share/qt5/resources",
                                 "usr/share/qt5/translations/qtwebengine_locales"),
    "libQt6WebEngineCore.so.6": ("qt6", "libqt6webengine6-data", "usr/share/qt6/resources",
                                 "usr/share/qt6/translations/qtwebengine_locales"),
}
WEBENGINE_DIR = "qtwebengine"       # in the bundle's library folder: libexec/, resources/, locales/


def _webengine_companions(soname: str, found: Provided, src: Source, staging_libdir: Path) -> list[str]:
    """Copy Qt WebEngine's helper program, resources and locales beside a bundled copy of it.

    Returns the libraries the helper program needs.
    """
    qt, data_pkg, resources, locales = QT_WEBENGINE[soname]
    dest = staging_libdir / WEBENGINE_DIR
    needed: list[str] = []
    proc = found.file.parent / qt / "libexec/QtWebEngineProcess"
    if proc.is_file():
        (dest / "libexec").mkdir(parents=True, exist_ok=True)
        shutil.copy2(proc, dest / "libexec/QtWebEngineProcess")
        os.chmod(dest / "libexec/QtWebEngineProcess", 0o755)
        try:
            needed = read_elf(proc).needed
        except ElfError:
            pass
    data = None
    if hasattr(src, "_package"):
        try:
            data = src._package(data_pkg)
        except RuntimeError:
            data = None
    for folder, name in ((resources, "resources"), (locales, "locales")):
        if data is not None and (data.root / folder).is_dir():
            shutil.copytree(data.root / folder, dest / name, symlinks=True, dirs_exist_ok=True)
    return needed


@dataclass
class ResolveResult:
    """The outcome of filling library gaps.

    Attributes:
        bundled: Soname -> where the copy came from, for each library added.
        bundled_info: The ELF details of each added library.
        unresolved: Sonames no source had.
        refused: Core glibc libraries, which debpak never bundles.
        wrong_arch: Sonames a source had only for another architecture.
    """
    bundled: dict[str, str] = field(default_factory=dict)       # soname -> origin
    bundled_info: dict[str, ElfInfo] = field(default_factory=dict)
    unresolved: set[str] = field(default_factory=set)
    refused: set[str] = field(default_factory=set)              # never-bundle libs
    wrong_arch: set[str] = field(default_factory=set)


def _needs_glibc_private(info) -> bool:
    """True if a library needs a glibc's GLIBC_PRIVATE, which only the glibc it was built with defines."""
    return any("GLIBC_PRIVATE" in vs for vs in info.verneed.values())


def fill_gaps(missing: set[str], runtime: RuntimeIndex, package_sonames: set[str],
              sources: list[Source], staging_libdir: Path) -> ResolveResult:
    """Copy missing libraries into staging_libdir, then the libraries those need, and so on.

    Each soname is tried against the sources in order. Libraries the runtime or
    the package already provides are skipped, and core glibc libraries are
    refused. A source that raises RuntimeError (a bad checksum) counts as not
    having the library.

    Args:
        missing: Sonames the app needs that the runtime lacks.
        runtime: The target runtime's index.
        package_sonames: Sonames the package provides itself.
        sources: Where to look, in order; see make_sources.
        staging_libdir: Where the copies go (the bundle's lib/debpak).
    """
    res = ResolveResult()
    staging_libdir.mkdir(parents=True, exist_ok=True)
    queue = sorted(missing)
    done: set[str] = set()
    while queue:
        soname = queue.pop(0)
        if soname in done:
            continue
        done.add(soname)
        if runtime.provides(soname) or soname in package_sonames:
            continue
        if is_never_bundle(soname):
            res.refused.add(soname)
            continue
        found = info = None
        for src in sources:
            try:
                found = src.find(soname)
            except RuntimeError:
                found = None
            if not found:
                continue
            try:
                info = read_elf(found.file)
            except ElfError:
                found = info = None
                continue
            if _needs_glibc_private(info):
                # Ubuntu 18.04's libcrypt.so.1 is glibc 2.27's own, in libc6, and needs that glibc's
                # GLIBC_PRIVATE, which the runtime's doesn't define; Tizonia's snap (core18) got it.
                # Later releases' libcrypt1 is libxcrypt's, which needs nothing private
                found = info = None
                continue
            break
        if not found or info is None:
            res.unresolved.add(soname)
            continue
        if info.machine != runtime.arch:
            res.wrong_arch.add(soname)
            continue
        dest = staging_libdir / soname
        shutil.copy2(found.file, dest)
        os.chmod(dest, 0o755)
        helpers = found.file.parent / HELPER_DIRS.get(soname, "")
        if soname in HELPER_DIRS and helpers.is_dir() and not (staging_libdir / helpers.name).exists():
            shutil.copytree(helpers, staging_libdir / helpers.name, symlinks=True)
            for f in (staging_libdir / helpers.name).rglob("*"):
                if f.is_file() and not f.is_symlink() and is_elf(f):
                    for n in read_elf(f).needed:
                        if n not in done:
                            queue.append(n)
        if soname in QT_WEBENGINE:
            queue += [n for n in _webengine_companions(soname, found, src, staging_libdir) if n not in done]
        res.bundled[soname] = found.origin
        res.bundled_info[soname] = info
        for n in info.needed:
            if n not in done:
                queue.append(n)
    return res


# The Ubuntu release that fills the gaps of a package when no library source is
# named (a snap uses the release its base snap comes from instead). An LTS keeps
# its archive for years, and its glibc (2.39) is older than the default runtimes'.
UBUNTU_LTS = "noble"
# the LTSes before it, newest first, for libraries noble no longer has: webkit2gtk-4.0, which
# Wails apps such as Tiny RDM link against, went in favour of 4.1 after jammy, and OpenSSL 1.1
# (klogg, Boosteroid) after focal
UBUNTU_PREVIOUS_LTS = ("jammy", "focal")


def _scratch() -> Path:
    """Return a new folder for downloaded packages, removed when debpak exits."""
    import atexit
    import shutil
    d = Path(tempfile.mkdtemp(prefix="debpak-deps-"))
    atexit.register(shutil.rmtree, d, True)
    return d


def ubuntu_source(arch: str, deb_arch: str, suite: str = UBUNTU_LTS) -> MirrorSource:
    """Return the Ubuntu archive for suite (main and universe) as a library source."""
    from .snap import ubuntu_mirror
    return MirrorSource(ubuntu_mirror(arch), suite, ["main", "universe"], arch, deb_arch, _scratch())


# After Ubuntu's LTSes, Debian's last two releases, for sonames no Ubuntu LTS ships: Snapmaker Luban's
# bundled Python wants libpython3.11.so.1.0 (bookworm's; Ubuntu went from 3.10 to 3.12), TrueConf's
# RPM libgsl.so.25 (bullseye's)
DEBIAN_MIRROR = "http://deb.debian.org/debian"
DEBIAN_RELEASES = ("bookworm", "bullseye")
# and last Fedora, whose sonames an RPM's programs were linked against where Debian's differ
# (Sniffnet's RPM: libpcap.so.1, which Debian still calls libpcap.so.0.8). A release whose glibc
# is no newer than the default runtime's, from the archive, which keeps it after its end of life
FEDORA_RELEASE = "42"
FEDORA_ARCHIVE = "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases"
# and after everything else, Debian's newest release, for sonames none of the older releases has yet:
# Besprited's tarball, built on a newer system, links libtinyxml2.so.11, which only trixie of these
# ships. Its glibc (2.41) is still older than the default runtimes', but it comes last, so a library
# the others have keeps coming from them, as before
DEBIAN_NEWEST = "trixie"
# and at the very end an older Fedora, for the versioned sonames of the releases between the LTSes
# that no other source keeps: GSequencer's AppImage, built in 2023, carries a libxml2 linked against
# ICU 73's libicui18n.so.73 and gettext 0.22's helpers, and was refused for both; Ubuntu and Debian
# went from ICU 72 to 74 and 76, and only Fedora 39 shipped ICU 73 and gettext 0.22
FEDORA_OLDER = "39"


def debian_source(arch: str, deb_arch: str, suite: str, mirror: str = "") -> MirrorSource:
    """Return Debian's archive for suite (main) as a library source; mirror for one that moved to
    archive.debian.org."""
    return MirrorSource(mirror or DEBIAN_MIRROR, suite, ["main"], arch, deb_arch, _scratch())


def fedora_source(arch: str, release: str = FEDORA_RELEASE) -> RpmRepoSource | None:
    """Return a Fedora release's Everything repository as a library source, or None for an architecture
    it lacks."""
    if arch not in ("x86_64", "aarch64"):
        return None
    return RpmRepoSource(f"{FEDORA_ARCHIVE}/{release}/Everything/{arch}/os", arch, _scratch())


def default_sources(arch: str, deb_arch: str) -> list[Source]:
    """Return where missing libraries come from when no source is named: Ubuntu's LTSes, newest first,
    then Debian's releases, then Fedora, then Debian's newest release, then an older Fedora."""
    out: list[Source] = [ubuntu_source(arch, deb_arch)]
    out += [ubuntu_source(arch, deb_arch, suite) for suite in UBUNTU_PREVIOUS_LTS]
    out += [debian_source(arch, deb_arch, suite) for suite in DEBIAN_RELEASES]
    if (fedora := fedora_source(arch)):
        out.append(fedora)
    out.append(debian_source(arch, deb_arch, DEBIAN_NEWEST))
    if (older := fedora_source(arch, FEDORA_OLDER)):
        out.append(older)
    return out


def fallback_sources(arch: str, deb_arch: str, suite: str) -> list[Source]:
    """Return the default sources other than Ubuntu suite, for libraries a snap's base doesn't have."""
    return [s for s in default_sources(arch, deb_arch) if getattr(s, "suite", None) != suite]


def fill_gaps_after(res: ResolveResult, needed: set[str], runtime: RuntimeIndex, package_sonames: set[str],
                    sources: list[Source], staging_libdir: Path) -> ResolveResult:
    """Look for the libraries in needed that res left unresolved in sources, and add what they find to res.

    Kubrick's snap links libKDEGames6.so.6, which its kf6-core24 content snap carries and which
    Ubuntu noble, the snap's base, doesn't have yet; Debian trixie does. A snap's missing libraries
    come from its base's Ubuntu first, as before, and only the ones the base has no package for
    are looked for in the other sources, so a library the base has still comes from the base.
    """
    todo = res.unresolved & needed
    if not todo or not sources:
        return res
    more = fill_gaps(todo, runtime, package_sonames | set(res.bundled), sources, staging_libdir)
    res.bundled.update(more.bundled)
    res.bundled_info.update(more.bundled_info)
    res.unresolved = (res.unresolved - set(more.bundled) - todo) | more.unresolved
    res.refused |= more.refused
    res.wrong_arch |= more.wrong_arch
    return res


def make_sources(args, arch: str, deb_arch: str) -> list[Source]:
    """Build the library sources the command line asked for: --deps-dir, then --rpm-repo, then --mirror."""
    workdir = _scratch()
    sources: list[Source] = []
    for d in getattr(args, "deps_dir", None) or []:
        sources.append(LocalDebSource(d, arch, workdir))
    for repo in getattr(args, "rpm_repo", None) or []:
        sources.append(RpmRepoSource(repo, arch, workdir))
    if getattr(args, "mirror", None):
        comps = [c.strip() for c in (args.components or "main").split(",") if c.strip()]
        sources.append(MirrorSource(args.mirror, args.suite, comps, arch, deb_arch, workdir))
    return sources
