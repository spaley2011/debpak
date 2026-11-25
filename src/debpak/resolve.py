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
from .deb import DebError, DebPackage, extract, parse_control, resolve_in_root
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
                    for stanza in f.read().split("\n\n"):
                        fields = parse_control(stanza)
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


# Libraries whose helper programs sit in a folder beside them, which goes along (by soname: the
# folder). WebKitGTK starts WebKitNetworkProcess and WebKitWebProcess from the path it was built
# with (/usr/lib/x86_64-linux-gnu/webkit2gtk-4.0); Tauri 1 apps such as Pot need 4.0, which only
# Ubuntu has, and stopped with "Failed to spawn child process"
HELPER_DIRS = {"libwebkit2gtk-4.0.so.37": "webkit2gtk-4.0", "libwebkit2gtk-4.1.so.0": "webkit2gtk-4.1"}


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
        found = None
        for src in sources:
            try:
                found = src.find(soname)
            except RuntimeError:
                found = None
            if found:
                break
        if not found:
            res.unresolved.add(soname)
            continue
        try:
            info = read_elf(found.file)
        except ElfError:
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
