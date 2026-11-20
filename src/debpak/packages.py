"""Input packages of every format debpak converts.

Each format is unpacked into the same shape the rest of the pipeline expects:
a `root` directory laid out like an installed system (usr/..., opt/...), plus
name, version, architecture, description, homepage, license and the
package's install scripts under Debian's names (preinst, postinst, prerm,
postrm), so the host-integration checks read them the same way.

  .deb                    deb.py
  .rpm                    rpm.py (pure Python: headers + cpio payload)
  .pkg.tar.{zst,xz,gz}    Arch Linux / pacman: tar with .PKGINFO and .INSTALL
  .AppImage               squashfs after an ELF runtime; placed under opt/NAME
  .tar.gz/.tar.xz/.zip    a vendor's "unpack and run" archive; placed under opt/NAME
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import re
import shutil
import struct
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ARCH_TO_FLATPAK = {
    # Debian
    "amd64": "x86_64", "arm64": "aarch64", "i386": "i386", "armhf": "arm",
    # RPM / pacman / uname
    "x86_64": "x86_64", "aarch64": "aarch64", "i686": "i386", "i586": "i386", "armv7hl": "arm",
    "armv7h": "arm",
}
FLATPAK_TO_DEB = {"x86_64": "amd64", "aarch64": "arm64", "i386": "i386", "arm": "armhf"}
ELF_MACHINES = {0x3E: "x86_64", 0xB7: "aarch64", 0x03: "i386", 0x28: "arm"}
FORMATS = ("deb", "rpm", "pacman", "appimage", "tarball")


class PackageError(Exception):
    pass


@dataclass
class Package:
    format: str
    path: Path
    root: Path
    name: str
    version: str = "0"
    pkg_arch: str = ""            # the format's own architecture name (amd64, x86_64, any, noarch ...)
    summary: str = ""
    long_description: str = ""
    homepage: str = ""
    license: str = ""
    scripts: dict[str, str] = field(default_factory=dict)   # preinst/postinst/prerm/postrm
    default_exec: str | None = None   # entry point when the package has no .desktop file
    notes: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)                # format-specific (extra-data unpacking)

    @property
    def flatpak_arch(self) -> str | None:
        if self.pkg_arch in ("noarch", "any", "all", ""):
            return None
        return ARCH_TO_FLATPAK.get(self.pkg_arch)

    @property
    def deb_arch(self) -> str:      # older callers
        return self.pkg_arch

    @property
    def control(self) -> dict[str, str]:   # older callers
        return {"Package": self.name, "Version": self.version, "Homepage": self.homepage}

    def maintainer_script(self, name: str) -> str | None:
        return self.scripts.get(name)


# --------------------------------------------------------------------------- detection

def detect_format(path: str | Path) -> str:
    p = Path(path)
    with open(p, "rb") as f:
        head = f.read(512)
    if head.startswith(b"!<arch>\n"):
        return "deb"
    if head[:4] == b"\xed\xab\xee\xdb":
        return "rpm"
    if head[:4] == b"\x7fELF":
        if head[8:11] in (b"AI\x02", b"AI\x01"):
            return "appimage"
        raise PackageError(f"{p}: an ELF program, not a package (to check one binary use `debpak smoke --exec`)")
    name = p.name.lower()
    if re.search(r"\.pkg\.tar(\.(zst|xz|gz|bz2))?$", name):
        return "pacman"
    if name.endswith(".appimage"):
        return "appimage"
    if re.search(r"\.(tar\.(gz|xz|bz2|zst)|tgz|txz|tbz2?|tar|zip)$", name) or head[:2] == b"PK" or \
            head[:2] == b"\x1f\x8b" or head[:6] == b"\xfd7zXZ\x00" or head[:4] == b"\x28\xb5\x2f\xfd":
        return "tarball"
    raise PackageError(f"{p}: unknown package format (supported: {', '.join(FORMATS)})")


def open_package(path: str | Path, dest: str | Path, allow_run: bool = False):
    """Unpack any supported package into dest; returns a Package (or DebPackage)."""
    path, dest = Path(path), Path(dest)
    fmt = detect_format(path)
    if fmt == "deb":
        from .deb import extract
        return extract(path, dest)
    if fmt == "rpm":
        from .rpm import extract_rpm
        return extract_rpm(path, dest)
    if fmt == "pacman":
        return extract_pacman(path, dest)
    if fmt == "appimage":
        return extract_appimage(path, dest, allow_run=allow_run)
    return extract_tarball(path, dest)


def is_package_file(p: Path) -> bool:
    n = p.name.lower()
    return n.endswith((".deb", ".rpm")) or bool(re.search(r"\.pkg\.tar(\.(zst|xz|gz|bz2))?$", n))


# --------------------------------------------------------------------------- shared helpers

def _decompressed(path: Path):
    """A file object for a (possibly compressed) archive, by its magic bytes."""
    with open(path, "rb") as f:
        head = f.read(6)
    if head[:2] == b"\x1f\x8b":
        return gzip.open(path, "rb")
    if head[:6] == b"\xfd7zXZ\x00":
        return lzma.open(path, "rb")
    if head[:3] == b"BZh":
        return bz2.open(path, "rb")
    if head[:4] == b"\x28\xb5\x2f\xfd":
        from .deb import _zstd_stream
        raw = open(path, "rb")
        s = _zstd_stream(raw)
        if s is not None:
            return s
        raw.close()
        if shutil.which("zstd"):
            out = subprocess.run(["zstd", "-dc", str(path)], capture_output=True, check=True).stdout
            return io.BytesIO(out)
        raise PackageError(f"{path.name} is zstd-compressed; install the 'zstandard' Python module "
                           "(pip install debpak[zstd]) or the zstd command-line tool")
    return open(path, "rb")


def _safe_tar_extract(fileobj, dest: Path, take=None) -> list[str]:
    """Stream-extract a tar, refusing paths that escape dest. `take(name, member, tar)` may
    claim a member (return True) so it isn't extracted. Returns the extracted names."""
    names = []
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=fileobj, mode="r|*") as tf:
        for m in tf:
            n = m.name.removeprefix("./")
            if not n or n == ".":
                continue
            if take and take(n, m, tf):
                continue
            names.append(n)
            if hasattr(tarfile, "tar_filter"):
                tf.extract(m, dest, filter="tar")     # blocks traversal, strips setuid
            else:  # pragma: no cover
                tf.extract(m, dest)
    return names


