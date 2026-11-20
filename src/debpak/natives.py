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


