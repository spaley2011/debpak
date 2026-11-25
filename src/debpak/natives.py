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
  5. An N-API Linux build in the module's own npm tarball, put where the
     app's copy was (build/Release/X.node). better-sqlite3 13 ships
     prebuilds/linux-x64.node this way and no per-Electron release assets.
     N-API builds don't depend on Electron's ABI, so any Electron loads them.
  6. A build from source. flatpak-builder runs node-gyp (from the Node SDK
     extension) on the module's npm tarball against Electron's headers, for
     modules written against V8 (better-sqlite3 12 and older) when no build
     for this Electron's ABI was published.

npm tarballs are checked against the registry's SHA-512 integrity. GitHub
and node-pre-gyp downloads have no published checksum, so the report says
so; the SHA-256 debpak saw is pinned in the manifest, and the file has to be
an x86-64 ELF library. Electron's headers are pinned to the SHA-256 in the
release's SHASUMS256.txt.

Some modules are only for Windows; windows_only() says when there's enough
evidence that the app won't load one on Linux, so it's a note, not a blocker.
skipped_on_linux() does the same, for a module nothing was found for, when
the app's own JavaScript checks for Linux before loading it.

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
from . import net
from .elf import ElfError, read_elf_bytes

NPM = "https://registry.npmjs.org"
ELF_X86_64 = 62
HEADERS = "https://artifacts.electronjs.org/headers/dist"
# Node and npm (with node-gyp) for building modules; published for SDK 24.08, 25.08 and 26.08
NODE_SDK = "org.freedesktop.Sdk.Extension.node24"
NODE_SDK_DIR = "/usr/lib/sdk/node24"
NODE_GYP = f"{NODE_SDK_DIR}/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js"
# libraries Linux builds may link that org.freedesktop.Platform doesn't have, and a runtime that does
NOT_IN_FREEDESKTOP = {"libadwaita-1.so.0": "org.gnome.Platform"}
# what every runtime has; other libraries a Linux build needs are listed in the report
CORE_LIBS = {"libc.so.6", "libm.so.6", "libstdc++.so.6", "libgcc_s.so.1", "libdl.so.2", "libpthread.so.0",
             "librt.so.1", "ld-linux-x86-64.so.2"}


def fetch(url: str) -> bytes:
    """Download a URL (the tests replace this)."""
    with net.urlopen(url, timeout=60) as r:      # noqa: S310 - https URLs built here
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
        built: Index into Resolution.builds when flatpak-builder makes the
            file; data is then empty (a placeholder until the build).
    """
    to: str
    asar_entry: str | None
    new: bool
    data: bytes
    source: int | None = None
    member: str | None = None
    built: int | None = None


@dataclass
class Build:
    """A module flatpak-builder builds from source against Electron's headers.

    Attributes:
        name, version: The npm package.
        target: node-gyp writes build/Release/TARGET.node.
        sources: flatpak-builder sources: the package's npm tarball in
            package/, Electron's headers in electron-headers/, and packages
            binding.gyp requires in package/node_modules/.
    """
    name: str
    version: str
    target: str
    sources: list[dict]


def build_module(b: Build, k: int) -> dict:
    """Return the flatpak-builder module that builds b into /app/share/debpak/natives-built/K/TARGET.node."""
    return {
        "name": f"native-{k}-{re.sub(r'[^A-Za-z0-9._-]+', '-', b.name).strip('-')}",
        "buildsystem": "simple",
        "subdir": "package",
        "build-options": {"append-path": f"{NODE_SDK_DIR}/bin"},
        "build-commands": [
            f'HOME="$PWD/.home" node {NODE_GYP} rebuild --release -j "$FLATPAK_BUILDER_N_JOBS" '
            '--nodedir="$PWD/../electron-headers"',
            f"install -Dm755 build/Release/{b.target}.node "
            f"${{FLATPAK_DEST}}/share/debpak/natives-built/{k}/{b.target}.node",
        ],
        "sources": b.sources,
    }


@dataclass
class Resolution:
    """What resolve() found: files to install, their sources, notes, and modules still blocked."""
    files: list[NativeFile] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    builds: list[Build] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unresolved: dict[str, str] = field(default_factory=dict)     # blocked path -> what was tried


def is_linux_x64(data: bytes) -> bool:
    """True for a 64-bit little-endian x86-64 ELF file."""
    return len(data) > 20 and data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1 \
        and int.from_bytes(data[18:20], "little") == ELF_X86_64


def abi_kind(data: bytes) -> str:
    """Return napi, v8 or unknown for a Linux .node file, from the symbols it imports.

    N-API modules call only napi_* functions, which every Electron provides.
    Others call into V8 and Node directly (_ZN2v8..., node_module_register)
    and load only in the Electron ABI they were built for.
    """
    try:
        syms = read_elf_bytes(data).undefined_symbols
    except ElfError:
        return "unknown"
    if any(s.startswith(("_ZN2v8", "_ZN4node", "node_module_register")) for s in syms):
        return "v8"
    return "napi" if any(s.startswith("napi_") for s in syms) else "unknown"


def needed_libs(data: bytes) -> list[str]:
    """Return the libraries an ELF file links, other than the C and C++ runtime's ([] if unreadable)."""
    try:
        return [n for n in read_elf_bytes(data, want_symbols=False).needed if n not in CORE_LIBS]
    except ElfError:
        return []


# Windows-only APIs and words in a module's file name. Split on - _ . + so that
# win_utils, windows-argv-parser and dpapi match, but bindings or winston don't.
WINDOWS_WORDS = {"win", "win32", "win64", "windows", "dpapi", "winreg", "winregistry", "winrt", "uwp"}
ARCH_WORDS = {"x64", "x86", "ia32", "arm64", "amd64", "arm"}


def windows_only(rel: str, pj: dict) -> str | None:
    """Return the evidence that the app won't load a Windows .node file on Linux, or None.

    Two kinds count:

      - The package's package.json "os" field leaves out both Linux and
        macOS. npm installs it only on Windows, so code that also runs on a
        Mac must check the platform before loading it.
      - The file's own name says Windows (win_utils.node, windows-argv-parser.node)
        or names a Windows-only API (dpapi.node). No Linux build of such a
        file can exist, and a loader that picks files by platform would never
        pick it on Linux.

    A Windows platform folder alone (prebuilds/win32-x64/, lib/binding/...-win32-x64/)
    is not evidence: prebuildify and node-pre-gyp loaders look in the
    linux-x64 folder on Linux, so those modules are needed everywhere. Nor
    is a name that only marks a per-platform build (sharp-win32-x64.node,
    prebuilds/win32-x64.node).
    """
    os_field = pj.get("os")
    if isinstance(os_field, str):
        os_field = [os_field]
    if isinstance(os_field, list) and os_field and all(isinstance(x, str) for x in os_field):
        allowed = [x for x in os_field if not x.startswith("!")]
        def excluded(plat):
            return f"!{plat}" in os_field or bool(allowed and plat not in allowed)
        # Linux and macOS both left out: the app's Mac build can't have it either, so its code
        # must already check for Windows. ["darwin", "win32"] isn't enough: an app that ships
        # only for those two may load the module unconditionally.
        if excluded("linux") and excluded("darwin"):
            return f'its package.json says "os": {json.dumps(os_field)}, so npm installs it only on Windows'
    stem = rel.rsplit("/", 1)[-1]
    stem = stem[:-5] if stem.endswith(".node") else stem
    words = [w for w in re.split(r"[-_.+]", stem.lower()) if w]
    if any(w in ARCH_WORDS for w in words):
        return None
    hits = [w for w in words if w in WINDOWS_WORDS]
    if not hits:
        return None
    if hits[0] in ("win", "win32", "win64", "windows"):
        return f"its file name, {stem}, says it's for Windows"
    return f"{hits[0]} is a Windows-only API"


# process.platform compared with "linux", either way round
LINUX_TEST = r"""(?:process\.platform\s*[!=]==?\s*["'`]linux["'`]|["'`]linux["'`]\s*[!=]==?\s*process\.platform)"""
# how far before a reference to the file the check may be: enough for a short if or ternary
# (Figma's `TC?stub():isPackaged?require("./bindings.node")`), not for unrelated code
GUARD_WINDOW = 300


def skipped_on_linux(rel: str, scripts) -> str | None:
    """Return the evidence that the app's code checks for Linux before every load of a .node file, or None.

    Figma's main.js loads its Windows bindings.node with
    `TC?stubs():require("./bindings.node")`, where TC is
    process.platform==="linux", so Linux never loads it. That counts when
    every string in the app's JavaScript that names the file (a path
    ending in its file name) has, shortly before it, a test of
    process.platform against "linux" or a variable assigned one. A file no
    script names is no evidence: loaders like bindings() build the path at
    run time.

    Args:
        rel: The module's path relative to resources.
        scripts: (path, text) for each of the app's JavaScript files.
    """
    base = rel.rsplit("/", 1)[-1]
    ref = re.compile(r"""["'`](?:[^"'`\n]*/)?""" + re.escape(base) + r"""["'`]""")
    sites: list[str] = []
    for path, text in scripts:
        if base not in text:
            continue
        hits = list(ref.finditer(text))
        if not hits:
            continue
        # minified code keeps the test in a variable: var TC=process.platform==="linux"||...
        flags = {m.group(1) for m in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*" + LINUX_TEST, text)}
        for m in hits:
            before = text[max(0, m.start() - GUARD_WINDOW):m.start()]
            if not (re.search(LINUX_TEST, before)
                    or any(re.search(rf"(?<![\w$.]){re.escape(f)}(?![\w$])", before) for f in flags)):
                return None
        sites.append(path)
    if not sites:
        return None
    return f"{' and '.join(sites)} {'checks' if len(sites) == 1 else 'check'} for Linux before loading it"


def gyp_targets(text: str) -> list[str]:
    """Return the target names in a binding.gyp."""
    return re.findall(r"""['"]target_name['"]\s*:\s*['"]([^'"]+)['"]""", text)


def gyp_commands(text: str) -> list[str] | None:
    """Return the shell commands a binding.gyp runs (<!(...) and <!@(...)), or None if they can't be read."""
    found = [m.group(2) for m in re.finditer(r"""(['"])<!@?\((.*?)\)\1""", text)]
    return found if len(found) == text.count("<!") else None


def _norm(name: str) -> str:
    return re.sub(r"[-_.]", "", name.split("/")[-1].lower())


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


def _missing(e: OSError) -> bool:
    """True if e means the URL doesn't exist (HTTP 404), as opposed to a network failure."""
    return getattr(e, "code", None) == 404 or str(e).startswith("404")


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


def _dep_dirs(pkg_dir: str, dep: str) -> list[str]:
    """Return the folders Node would look in for dep, required from pkg_dir: its own node_modules, then each parent's."""
    out = [f"{pkg_dir}/node_modules/{dep}"]
    d = pkg_dir
    while "/node_modules/" in d:
        d = d[:d.rfind("/node_modules/")]
        out.append(f"{d}/node_modules/{dep}")
    return out


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
        runtime: The Flatpak runtime's ID, to check the libraries a Linux
            build links.
    """
    def __init__(self, read_package_json, electron_version: str, abi: str | None,
                 runtime: str = "org.freedesktop.Platform"):
        self.read_pj = read_package_json
        self.electron = electron_version
        self.abi = abi
        self.runtime = runtime
        self.res = Resolution()
        self._cache: dict[str, int] = {}
        self._done: set[str] = set()
        self._tarballs: dict[tuple[str, str], tuple[dict[str, bytes], Source]] = {}

    def _tarball(self, name: str, version: str) -> tuple[dict[str, bytes], Source]:
        """Return a package's npm tarball as {path: contents} and its Source, downloading it once."""
        if (name, version) not in self._tarballs:
            blob, src = _npm_tarball(name, version)
            self._tarballs[(name, version)] = (_tgz_members(blob), src)
        return self._tarballs[(name, version)]

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
        base = re.sub(r"-(win32|darwin)-(x64|ia32|arm64|universal)$", "", name)
        # most publish PKG-linux-x64; napi-rs projects (rollup, swc, lightningcss) add -gnu and
        # @parcel/watcher adds -glibc, next to a -musl build
        tried = []
        for linux in (f"{base}-linux-x64", f"{base}-linux-x64-gnu", f"{base}-linux-x64-glibc"):
            try:
                blob, src = _npm_tarball(linux, version)
                break
            except OSError as e:
                if not _missing(e):
                    raise
                tried.append(linux)
        else:
            raise ValueError(f"no Linux package on npm (tried {', '.join(tried)} at {version})")
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
            if not re.search(r"-linux-x64(-gnu|-glibc)?$", dep):
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
        members, src = self._tarball(name, version)
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
                  "napi_build_version": max((b.get("napi_versions") or [""]),
                                            key=lambda x: int(x) if str(x).isdigit() else -1)}
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

    @staticmethod
    def _target_of(rel: str, name: str, members: dict[str, bytes]) -> tuple[str, list[str]]:
        """Return (the blocked file's addon name, binding.gyp's targets), checking the package builds it."""
        stem = rel.rsplit("/", 1)[-1].removesuffix(".node")
        gyp = members.get("package/binding.gyp")
        if gyp is None:
            raise ValueError(f"its npm tarball has no binding.gyp to tell which addon {stem}.node is")
        targets = gyp_targets(gyp.decode("utf-8", "replace"))
        if stem not in targets:
            raise ValueError(f"its binding.gyp doesn't build {stem}.node (only {', '.join(targets) or 'nothing'})")
        return stem, targets

    def npm_prebuild(self, rel: str, name: str, pkg_dir: str) -> bool:
        """Strategy 5: the N-API Linux build in the package's own npm tarball, put where the app loads it.

        better-sqlite3 13 ships prebuilds/linux-x64.node and loads it before
        build/Release/better_sqlite3.node; modules loaded with bindings() only
        look in build/Release. Putting the build in the blocked file's place
        works for both. A build for this Electron's ABI (electron.abiN in its
        name) counts too.
        """
        version = self.read_pj(pkg_dir).get("version")
        if not version:
            return False
        members, src = self._tarball(name, version)
        flat = re.search(r"/prebuilds/(win32|darwin)-[^/.]+\.node$", rel)     # prebuilds/PLATFORM-ARCH.node
        builds = {n: d for n, d in members.items()
                  if re.fullmatch(r"package/prebuilds/linux-x64(\.node|/[^/]+\.node)", n)
                  and "musl" not in n.rsplit("/", 1)[-1] and is_linux_x64(d)}
        if flat:
            builds = {n: d for n, d in builds.items() if n == "package/prebuilds/linux-x64.node"}
        else:
            stem, targets = self._target_of(rel, name, members)
        if not builds:
            raise ValueError(f"{name}@{version}'s npm tarball has no x86-64 Linux build")
        usable = {n: d for n, d in builds.items() if abi_kind(d) == "napi"
                  or {"electron", f"abi{self.abi}"} <= set(n.rsplit("/", 1)[-1].split("."))}
        if len(usable) > 1:
            glibc = {n: d for n, d in usable.items() if "glibc" in n.rsplit("/", 1)[-1].split(".")}
            usable = glibc if len(glibc) == 1 else usable
        if not usable:
            raise ValueError(f"the Linux build in {name}@{version}'s npm tarball is neither N-API nor for "
                             f"Electron ABI {self.abi}")
        if len(usable) > 1:
            raise ValueError(f"{name}@{version}'s npm tarball has several Linux builds "
                             f"({', '.join(sorted(usable))}); can't tell which to use")
        member, data = next(iter(usable.items()))
        base = member.rsplit("/", 1)[-1].split(".")[0]
        if not flat and len(targets) > 1 and _norm(stem) not in (_norm(name), _norm(base)):
            raise ValueError(f"its binding.gyp builds {', '.join(targets)}; can't tell that {member} is {stem}.node")
        libs = needed_libs(data)
        missing = [lib for lib in libs if lib in NOT_IN_FREEDESKTOP] if self.runtime == "org.freedesktop.Platform" \
            else []
        if missing:
            raise ValueError(f"its Linux build ({member.removeprefix('package/')}) needs {', '.join(missing)}, "
                             f"which {self.runtime} doesn't have ({NOT_IN_FREEDESKTOP[missing[0]]} does)")
        dest = f"{pkg_dir}/{member.removeprefix('package/')}" if flat else rel
        k = self._add_source(src)
        self.res.files.append(self._file(dest, data, k, member, new=dest != rel))
        kind = "N-API" if abi_kind(data) == "napi" else f"Electron ABI {self.abi}"
        uses = f"; it links {', '.join(libs)}" if libs else ""
        self.res.notes.append(f"{dest}: Linux build from {name}@{version}'s npm tarball "
                              f"({member.removeprefix('package/')}, {kind}, {src.checked}){uses}")
        return True

    def _headers(self) -> tuple[str, str]:
        """Return the URL and SHA-256 (from the release's SHASUMS256.txt) of Electron's headers tarball."""
        v = self.electron
        _check_name("electron", v)
        name = f"node-v{v}-headers.tar.gz"
        text = fetch(f"{HEADERS}/v{v}/SHASUMS256.txt").decode("utf-8", "replace")
        for line in text.splitlines():
            m = re.match(r"([0-9a-f]{64}) [ *](\S+)$", line.strip())
            if m and m.group(2) == name:
                return f"{HEADERS}/v{v}/{name}", m.group(1)
        raise ValueError(f"Electron {v}'s SHASUMS256.txt doesn't list {name}")

    def source_build(self, rel: str, name: str, pkg_dir: str) -> bool:
        """Strategy 6: flatpak-builder builds the module from its npm tarball against Electron's headers.

        Only for modules whose .gyp files run nothing at configure time but
        node (with packages the app itself ships, such as nan or
        node-addon-api): anything else, such as pkg-config for system
        libraries, may need more than the SDK has.
        """
        version = self.read_pj(pkg_dir).get("version")
        if not version or not re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", self.electron) or self.electron == "0.0.0":
            return False
        members, src = self._tarball(name, version)
        stem, _targets = self._target_of(rel, name, members)
        # a prebuilds/PLATFORM-ARCH/NAME.node module (node-pty) loads prebuilds/linux-x64/NAME.node on
        # Linux, so the build goes there; build/Release is where it would load a build of its own
        # anywhere else in the package, it goes where the app's copy was (@ronomon/opened keeps
        # binding.node at its top); node-gyp's build/Release/NAME.node is only copied there
        dest = rel
        if re.fullmatch(re.escape(pkg_dir) + r"/prebuilds/(win32|darwin)-[^/]+/" + re.escape(stem) + r"\.node", rel):
            dest = f"{pkg_dir}/prebuilds/linux-x64/{stem}.node"
        elif not rel.startswith(pkg_dir + "/") or "/node_modules/" in rel.removeprefix(pkg_dir):
            raise ValueError(f"{rel} isn't {name}'s own file")
        deps: list[str] = []
        for path, data in sorted(members.items()):
            if not path.endswith((".gyp", ".gypi")):
                continue
            text = data.decode("utf-8", "replace")
            commands = gyp_commands(text)
            if commands is None:
                raise ValueError(f"can't read the commands {path.removeprefix('package/')} runs")
            for c in commands:
                if not re.match(r"node\s", c.strip()):
                    raise ValueError(f"{path.removeprefix('package/')} runs {c.strip()!r} at build time; debpak "
                                     "only builds modules that need nothing but node and a compiler")
                for dep in re.findall(r"""require\(\\?['"]([^'"\\]+)\\?['"]\)""", c):
                    if dep not in deps:
                        deps.append(dep)
        sources = [{"type": "archive", "url": src.url, "sha256": src.sha256, "dest": "package"}]
        for dep in deps:
            dpj = next((p for p in map(self.read_pj, _dep_dirs(pkg_dir, dep)) if p.get("version")), None)
            if not dpj:
                raise ValueError(f"its binding.gyp needs {dep} to build, which the app doesn't include")
            _m, dsrc = self._tarball(dep, str(dpj["version"]))
            sources.append({"type": "archive", "url": dsrc.url, "sha256": dsrc.sha256,
                            "dest": f"package/node_modules/{dep}"})
        url, sha = self._headers()
        sources.append({"type": "archive", "url": url, "sha256": sha, "dest": "electron-headers"})
        k = len(self.res.builds)
        self.res.builds.append(Build(name, version, stem, sources))
        nf = self._file(dest, b"", None, None, new=dest != rel)      # type: ignore[arg-type]
        nf.built = k
        self.res.files.append(nf)
        if dest != rel:
            self._done.add(pkg_dir)         # the package's other platforms' builds don't matter on Linux
        self.res.notes.append(f"{rel}: no Linux build for Electron {self.electron} was published, so flatpak-builder "
                              f"builds {name}@{version} from its npm tarball ({src.checked}) against Electron's "
                              f"headers (pinned to its SHASUMS256.txt), with node-gyp from {NODE_SDK}")
        return True

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
                  ("node-pre-gyp download", lambda: self.node_pre_gyp(rel, name, pkg_dir)),
                  ("Linux build in the npm tarball", lambda: self.npm_prebuild(rel, name, pkg_dir)),
                  ("build from source", lambda: self.source_build(rel, name, pkg_dir))]
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
