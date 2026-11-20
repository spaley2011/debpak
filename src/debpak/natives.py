"""Find Linux builds of an Electron app's Windows or Mac native modules.

A native Node module (.node file) compiled for Windows or macOS can't load
on Linux. Most popular modules publish Linux builds, though, in one of four
places, tried in this order:

  1. A per-platform npm package. Modules like sharp and esbuild publish
     PKG-win32-x64, PKG-darwin-arm64 and PKG-linux-x64 separately, and the
     app only shipped its own platform's. debpak fetches PKG-linux-x64 at the
     same version and adds it next to the others.
  2. The module's own npm tarball. Modules built with prebuildify keep every
     platform's build in prebuilds/PLATFORM-ARCH/, and the packager often
     dropped the Linux one. The tarball still has it.
  3. A prebuild release asset on GitHub, named
     NAME-vVERSION-electron-vABI-linux-x64.tar.gz (or napi-vN for N-API
     builds), under the repository's vVERSION release.
  4. A node-pre-gyp download, from the package.json "binary" section.

npm tarballs are checked against the registry's SHA-512 integrity. GitHub
and node-pre-gyp downloads have no published checksum, so the report says
so; the SHA-256 debpak saw is pinned in the manifest, and the file has to be
an x86-64 ELF library.

Every network call goes through fetch(), which the tests replace.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tarfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

NPM = "https://registry.npmjs.org"
ELF_X86_64 = 62


def fetch(url: str) -> bytes:
    """Download a URL (the tests replace this)."""
    req = urllib.request.Request(url, headers={"User-Agent": "debpak"})
    with urllib.request.urlopen(req, timeout=60) as r:      # noqa: S310 - https URLs built here
        return r.read()


@dataclass
class Source:
    """A download that holds Linux builds: its URL, SHA-256, kind (tgz or file) and how it was checked."""
    url: str
    sha256: str
    kind: str
    checked: str


@dataclass
class NativeFile:
    """One file to put in place of, or next to, a blocked module.

    Attributes:
        to: Path under the app's resources folder, e.g.
            app.asar.unpacked/node_modules/x/build/Release/x.node.
        asar_entry: The path inside app.asar to mark unpacked (or add), or None
            for files outside the archive.
        new: True when app.asar has no entry for it yet (a sibling package or
            a prebuilds folder the packager dropped).
        data: The file's contents.
        source: Index into Resolution.sources, or None for --native-dir files.
        member: Its path inside that source.
    """
    to: str
    asar_entry: str | None
    new: bool
    data: bytes
    source: int | None = None
    member: str | None = None


@dataclass
class Resolution:
    """What resolve() found: files to install, their sources, notes, and modules still blocked."""
    files: list[NativeFile] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unresolved: dict[str, str] = field(default_factory=dict)     # blocked path -> what was tried


def is_linux_x64(data: bytes) -> bool:
    """True for a 64-bit little-endian x86-64 ELF file."""
    return len(data) > 20 and data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1 \
        and int.from_bytes(data[18:20], "little") == ELF_X86_64


def _tgz_members(blob: bytes) -> dict[str, bytes]:
    """Return the regular files of a .tar.gz as {path: contents}, skipping unsafe paths and links."""
    out = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for m in tf:
            name = m.name
            while name.startswith("./"):
                name = name[2:]
            if not m.isfile() or name.startswith("/") or ".." in name.split("/") or not name:
                continue
            f = tf.extractfile(m)
            if f is not None:
                out[name] = f.read()
    return out


NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
SAFE_VERSION = re.compile(r"^[0-9A-Za-z.+_-]{1,64}$")


def _check_name(name: str, version: str) -> None:
    """Refuse package names and versions that aren't plain npm ones (they become URLs and paths)."""
    if not NPM_NAME.match(name) or not SAFE_VERSION.match(version):
        raise ValueError(f"not a valid npm package: {name!r}@{version!r}")


def _npm_version(name: str, version: str) -> dict:
    _check_name(name, version)
    return json.loads(fetch(f"{NPM}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}"))


def _npm_tarball(name: str, version: str) -> tuple[bytes, Source]:
    """Download an npm package's tarball and check it against the registry's integrity hash.

    Raises:
        ValueError: The hash doesn't match or the registry gives none.
    """
    meta = _npm_version(name, version)
    dist = meta.get("dist", {})
    url, integrity = dist.get("tarball"), dist.get("integrity", "")
    if not url:
        raise ValueError(f"{name}@{version} has no tarball")
    blob = fetch(url)
    if integrity.startswith("sha512-"):
        if base64.b64encode(hashlib.sha512(blob).digest()).decode() != integrity[7:]:
            raise ValueError(f"{name}@{version}: tarball doesn't match the registry's SHA-512")
        checked = "npm registry SHA-512"
    elif dist.get("shasum"):
        if hashlib.sha1(blob).hexdigest() != dist["shasum"]:       # noqa: S324 - npm's legacy shasum
            raise ValueError(f"{name}@{version}: tarball doesn't match the registry's SHA-1")
        checked = "npm registry SHA-1"
    else:
        raise ValueError(f"{name}@{version}: the registry gives no checksum")
    return blob, Source(url, hashlib.sha256(blob).hexdigest(), "tgz", checked)


def package_of(rel: str) -> tuple[str, str] | None:
    """Return (package name, path of its folder) for a module path like app.asar/node_modules/@a/b/x.node."""
    matches = list(re.finditer(r"node_modules/((?:@[^/]+/)?[^/]+)", rel))
    if not matches:
        return None
    m = matches[-1]                 # the innermost package
    return m.group(1), rel[:m.end()]


def _repo_url(pj: dict) -> str | None:
    repo = pj.get("repository")
    url = repo.get("url") if isinstance(repo, dict) else repo
    if not isinstance(url, str):
        return None
    if re.fullmatch(r"[\w.-]+/[\w.-]+", url):            # npm shorthand: owner/name
        return f"https://github.com/{url}"
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url)
    return f"https://github.com/{m.group(1)}/{m.group(2)}" if m else None


def _relpath(p: str) -> str:
    """'./a/b/' -> 'a/b' (node-pre-gyp paths are written relative, with ./ and trailing slashes)."""
    p = p.strip()
    while p.startswith("./"):
        p = p[2:]
    return p.strip("/")


def _expand(template: str, values: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), m.group(0))), template)


class Resolver:
    """Looks for Linux builds of blocked modules (see the module docstring).

    Args:
        read_package_json: Callable taking a package folder path (relative to
            resources, e.g. app.asar/node_modules/x) and returning its
            package.json as a dict, or {}.
        electron_version: The app's Electron version.
        abi: Electron's NODE_MODULE_VERSION, if known.
    """
    def __init__(self, read_package_json, electron_version: str, abi: str | None):
        self.read_pj = read_package_json
        self.electron = electron_version
        self.abi = abi
        self.res = Resolution()
        self._cache: dict[str, int] = {}
        self._done: set[str] = set()

    def _add_source(self, src: Source) -> int:
        if src.url not in self._cache:
            self.res.sources.append(src)
            self._cache[src.url] = len(self.res.sources) - 1
        return self._cache[src.url]

    def _place(self, pkg_dir: str, members: dict[str, bytes], src: int, prefix: str, dest_dir: str,
               new: bool) -> int:
        """Add every member under prefix to dest_dir (relative to pkg_dir); return how many."""
        n = 0
        for name, data in sorted(members.items()):
            if not name.startswith(prefix):
                continue
            inner = name[len(prefix):]
            to_in_pkg = f"{dest_dir}/{inner}" if dest_dir else inner
            self.res.files.append(self._file(f"{pkg_dir}/{to_in_pkg}", data, src, name, new))
            n += 1
        return n

    @staticmethod
    def _file(path: str, data: bytes, src: int, member: str, new: bool) -> NativeFile:
        """Turn a path under resources (app.asar/... or other) into a NativeFile.

        Raises:
            ValueError: The path has empty, "." or ".." parts.
        """
        if any(part in ("", ".", "..") for part in path.split("/")):
            raise ValueError(f"unsafe path {path!r}")
        if path.startswith(("app.asar/", "app.asar.unpacked/")):
            inner = re.sub(r"^app\.asar(\.unpacked)?/", "", path)
            return NativeFile(f"app.asar.unpacked/{inner}", inner, new, data, src, member)
        return NativeFile(path, None, new, data, src, member)

    def sibling(self, rel: str, name: str, pkg_dir: str, m: re.Match) -> bool:
        """Strategy 1: fetch PKG-linux-x64 next to PKG-win32-x64 / PKG-darwin-ARCH."""
        version = self.read_pj(pkg_dir).get("version")
        if not version:
            return False
        linux = re.sub(r"-(win32|darwin)-(x64|ia32|arm64|universal)$", "-linux-x64", name)
        blob, src = _npm_tarball(linux, version)
        members = _tgz_members(blob)
        if not any(is_linux_x64(d) for n, d in members.items() if n.endswith(".node") or ".so" in n):
            raise ValueError(f"{linux}@{version} has no x86-64 Linux library")
        parent = pkg_dir[: -len(name)]
        k = self._add_source(src)
        count = self._place(f"{parent}{linux}".rstrip("/"), members, k, "package/", "", new=True)
        self.res.notes.append(f"{name}: added {linux}@{version} from npm ({count} files, {src.checked})")
        # its own Linux-only dependencies (sharp-linux-x64 needs sharp-libvips-linux-x64)
        try:
            spj = json.loads(members.get("package/package.json", b"{}"))
        except ValueError:
            spj = {}
        deps = {**(spj.get("optionalDependencies") or {}), **(spj.get("dependencies") or {})}
        for dep, spec in sorted(deps.items()):
            if not re.search(r"-linux-x64$", dep):
                continue
            dep_version = re.sub(r"^[\^~=v]+", "", str(spec))
            dblob, dsrc = _npm_tarball(dep, dep_version)
            dk = self._add_source(dsrc)
            n = self._place(f"{parent}{dep}".rstrip("/"), _tgz_members(dblob), dk, "package/", "", new=True)
            self.res.notes.append(f"{name}: added {dep}@{dep_version}, which {linux} needs ({n} files, "
                                  f"{dsrc.checked})")
        return True

    def prebuilds(self, rel: str, name: str, pkg_dir: str) -> bool:
        """Strategy 2: take prebuilds/linux-x64 from the package's own npm tarball."""
        version = self.read_pj(pkg_dir).get("version")
        if not version:
            return False
        blob, src = _npm_tarball(name, version)
        members = _tgz_members(blob)
        linux = {n: d for n, d in members.items() if n.startswith("package/prebuilds/linux-x64/")}
        if not any(is_linux_x64(d) for n, d in linux.items() if n.endswith(".node")):
            raise ValueError(f"{name}@{version} has no prebuilds/linux-x64 in its npm tarball")
        k = self._add_source(src)
        count = self._place(pkg_dir, linux, k, "package/prebuilds/linux-x64/", "prebuilds/linux-x64", new=True)
        self.res.notes.append(f"{name}: added prebuilds/linux-x64 from its npm tarball ({count} files, "
                              f"{src.checked})")
        return True

    def _replace_from(self, rel: str, blob: bytes, src: Source, what: str, dest: str | None = None) -> bool:
        """Put the member named like the blocked file at dest (default: in the blocked file's place)."""
        members = _tgz_members(blob)
        base = rel.rsplit("/", 1)[-1]
        hits = [n for n, d in members.items() if n.rsplit("/", 1)[-1] == base and is_linux_x64(d)]
        if not hits:
            raise ValueError(f"{what} has no x86-64 Linux {base}")
        k = self._add_source(src)
        target = dest or rel
        self.res.files.append(self._file(target, members[hits[0]], k, hits[0], new=target != rel))
        self.res.notes.append(f"{target}: Linux build from {what} ({src.checked})")
        return True

    def prebuild_asset(self, rel: str, name: str, pkg_dir: str) -> bool:
        """Strategy 3: a prebuild-style GitHub release asset for this Electron ABI, then for N-API."""
        pj = self.read_pj(pkg_dir)
        version, repo = pj.get("version"), _repo_url(pj)
        if not (version and repo):
            return False
        short = name.split("/")[-1]
        runtimes = [f"electron-v{self.abi}"] if self.abi else []
        napi = (pj.get("binary") or {}).get("napi_versions") or []
        runtimes += [f"napi-v{n}" for n in sorted(napi, reverse=True)]
        errors = []
        for rt in runtimes:
            asset = f"{short}-v{version}-{rt}-linux-x64.tar.gz"
            url = f"{repo}/releases/download/v{version}/{asset}"
            try:
                blob = fetch(url)
            except OSError as e:
                errors.append(f"{asset}: {e}")
                continue
            return self._replace_from(rel, blob, Source(url, hashlib.sha256(blob).hexdigest(), "tgz",
                                                        "no published checksum (GitHub release asset)"), asset)
        raise ValueError("; ".join(errors) or "no Electron ABI or N-API version to look for")

    def node_pre_gyp(self, rel: str, name: str, pkg_dir: str) -> bool:
        """Strategy 4: node-pre-gyp's host + remote_path + package_name, expanded for Electron on Linux."""
        pj = self.read_pj(pkg_dir)
        b = pj.get("binary") or {}
        if not (b.get("host") and b.get("module_name") and pj.get("version")):
            return False
        major, minor, patch = (self.electron.split("-")[0].split(".") + ["0", "0"])[:3]
        v = pj["version"].split("-")[0].split(".") + ["0", "0"]
        values = {"name": name, "version": pj["version"], "module_name": b["module_name"],
                  "node_abi": f"electron-v{major}.{minor}", "platform": "linux", "arch": "x64", "libc": "glibc",
                  "configuration": "Release", "toolset": "", "major": v[0], "minor": v[1], "patch": v[2],
                  "napi_build_version": max((b.get("napi_versions") or [""]), key=str)}
        host = b["host"] if isinstance(b["host"], str) else (b["host"].get("endpoint") or "")
        package_name = b.get("package_name") or "{module_name}-v{version}-{node_abi}-{platform}-{arch}.tar.gz"
        url = "/".join(p for p in (host.rstrip("/"), _relpath(_expand(b.get("remote_path", ""), values)),
                                   _expand(package_name, values)) if p)
        blob = fetch(url)
        # node-pre-gyp loads from module_path expanded for the running platform, not from where
        # the Windows build sat
        module_path = _relpath(_expand(b.get("module_path", "./lib/binding"), values))
        if ".." in module_path.split("/"):
            raise ValueError(f"module_path {b.get('module_path')!r} leaves the package")
        dest = f"{pkg_dir}/{module_path}/{b['module_name']}.node" if module_path else \
            f"{pkg_dir}/{b['module_name']}.node"
        return self._replace_from(rel, blob, Source(url, hashlib.sha256(blob).hexdigest(), "tgz",
                                                    "no published checksum (node-pre-gyp download)"),
                                  url.rsplit("/", 1)[-1], dest=dest)

    def resolve(self, rel: str) -> bool:
        """Try every strategy for one blocked module; record what was tried when none works."""
        found = package_of(rel)
        if not found:
            self.res.unresolved[rel] = "not inside node_modules, so there's no package to look up"
            return False
        name, pkg_dir = found
        if pkg_dir in self._done:      # another file of a package already handled as a whole
            return True
        tried = []
        plans = []
        m = re.search(r"-(win32|darwin)-(x64|ia32|arm64|universal)$", name)
        if m:
            plans.append(("npm package " + re.sub(r"-(win32|darwin)-\w+$", "-linux-x64", name),
                          lambda: self.sibling(rel, name, pkg_dir, m)))
        if re.search(r"/prebuilds/(win32|darwin)-[^/]+/[^/]+\.node$", rel):
            plans.append(("prebuilds/linux-x64 in the npm tarball", lambda: self.prebuilds(rel, name, pkg_dir)))
        plans += [("prebuild release asset", lambda: self.prebuild_asset(rel, name, pkg_dir)),
                  ("node-pre-gyp download", lambda: self.node_pre_gyp(rel, name, pkg_dir))]
        for what, attempt in plans:
            try:
                if attempt():
                    if what.startswith(("npm package", "prebuilds/")):
                        self._done.add(pkg_dir)
                    return True
                tried.append(f"{what}: not applicable")
            except (OSError, ValueError, KeyError, tarfile.TarError, json.JSONDecodeError) as e:
                tried.append(f"{what}: {e}")
        self.res.unresolved[rel] = "; ".join(tried)
        return False


def electron_abi(version: str, releases: list[dict]) -> str | None:
    """Return Electron's NODE_MODULE_VERSION ("modules" in Electron's release list), or None."""
    for rel in releases:
        if rel.get("version") == version and rel.get("modules"):
            return str(rel["modules"])
    return None


def from_native_dir(native_dir: Path, rel: str) -> NativeFile | None:
    """Find a --native-dir replacement for a blocked module: same path under the folder, else a unique same-named file."""
    inner = re.sub(r"^app\.asar(\.unpacked)?/", "", rel)
    hits = [c for c in (native_dir / inner, native_dir / rel) if c.is_file()]
    if not hits:
        hits = [p for p in native_dir.rglob(Path(inner).name) if p.is_file()]
        if len(hits) != 1:
            return None
    return Resolver._file(rel, hits[0].read_bytes(), None, None, new=False)   # type: ignore[arg-type]
