""".deb reading and extraction.

A .deb is an `ar` archive holding `debian-binary`, `control.tar.*` and
`data.tar.*`. The ar container is parsed in pure Python; the inner tarballs
are streamed through the right decompressor. zstd (the default on Ubuntu
since 21.10) is handled via the `zstandard` module, Python 3.14's
`compression.zstd`, the `zstd` binary, or `dpkg-deb`, whichever exists.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

DEB_ARCH_TO_FLATPAK = {"amd64": "x86_64", "arm64": "aarch64", "i386": "i386", "armhf": "arm"}


class DebError(Exception):
    pass


@dataclass
class ArMember:
    name: str
    offset: int
    size: int


def read_ar(path: str | Path) -> list[ArMember]:
    members = []
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise DebError(f"{path}: not an ar archive (is this a .deb?)")
        while True:
            hdr = f.read(60)
            if len(hdr) < 60:
                break
            name = hdr[0:16].decode("ascii", "replace").strip().rstrip("/")
            try:
                size = int(hdr[48:58].decode("ascii").strip())
            except ValueError as e:
                raise DebError(f"{path}: corrupt ar header") from e
            members.append(ArMember(name, f.tell(), size))
            f.seek(size + (size & 1), os.SEEK_CUR)
    return members


class _Slice(io.RawIOBase):
    """Read-only view of [offset, offset+size) of a file."""

    def __init__(self, path, offset: int, size: int):
        self._f = open(path, "rb")
        self._f.seek(offset)
        self._left = size

    def readable(self):
        return True

    def readinto(self, b):
        n = min(len(b), self._left)
        if n <= 0:
            return 0
        data = self._f.read(n)
        b[: len(data)] = data
        self._left -= len(data)
        return len(data)

    def close(self):
        self._f.close()
        super().close()


def _zstd_stream(raw):
    try:
        import zstandard  # type: ignore

        return zstandard.ZstdDecompressor().stream_reader(raw)
    except ImportError:
        pass
    try:
        from compression import zstd  # type: ignore  # Python 3.14+

        return zstd.ZstdFile(raw)
    except ImportError:
        return None


def _extract_tar_stream(fileobj, dest: Path) -> None:
    with tarfile.open(fileobj=fileobj, mode="r|") as tf:
        if hasattr(tarfile, "tar_filter"):
            # 'tar' filter: blocks path traversal and strips setuid bits but,
            # unlike 'data', keeps absolute symlinks, which debs rely on.
            tf.extractall(dest, filter="tar")
        else:  # pragma: no cover - very old Python
            tf.extractall(dest)


def _extract_member(deb: Path, member: ArMember, dest: Path, dpkg_flag: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    name = member.name
    raw = _Slice(deb, member.offset, member.size)
    try:
        if name.endswith(".tar"):
            _extract_tar_stream(io.BufferedReader(raw), dest)
        elif name.endswith(".gz"):
            _extract_tar_stream(gzip.GzipFile(fileobj=io.BufferedReader(raw)), dest)
        elif name.endswith(".xz") or name.endswith(".lzma"):
            _extract_tar_stream(lzma.LZMAFile(io.BufferedReader(raw)), dest)
        elif name.endswith(".bz2"):
            _extract_tar_stream(bz2.BZ2File(io.BufferedReader(raw)), dest)
        elif name.endswith(".zst"):
            stream = _zstd_stream(io.BufferedReader(raw))
            if stream is not None:
                _extract_tar_stream(stream, dest)
            else:
                raw.close()
                _extract_zstd_external(deb, member, dest, dpkg_flag)
        else:
            raise DebError(f"unsupported compression for {name}")
    finally:
        if not raw.closed:
            raw.close()


def _extract_zstd_external(deb: Path, member: ArMember, dest: Path, dpkg_flag: str) -> None:
    if shutil.which("zstd"):
        with tempfile.NamedTemporaryFile(suffix=".zst") as tmp:
            with open(deb, "rb") as f:
                f.seek(member.offset)
                remaining = member.size
                while remaining:
                    chunk = f.read(min(remaining, 1 << 20))
                    tmp.write(chunk)
                    remaining -= len(chunk)
            tmp.flush()
            proc = subprocess.Popen(["zstd", "-dc", tmp.name], stdout=subprocess.PIPE)
            try:
                _extract_tar_stream(proc.stdout, dest)
            finally:
                proc.stdout.close()
                if proc.wait() != 0:
                    raise DebError(f"zstd failed on {member.name}")
        return
    if shutil.which("dpkg-deb"):
        proc = subprocess.Popen(["dpkg-deb", dpkg_flag, str(deb)], stdout=subprocess.PIPE)
        try:
            _extract_tar_stream(proc.stdout, dest)
        finally:
            proc.stdout.close()
            if proc.wait() != 0:
                raise DebError(f"dpkg-deb {dpkg_flag} failed")
        return
    raise DebError(
        f"{member.name} is zstd-compressed; install the 'zstandard' Python module "
        "(pip install debpak[zstd]) or the zstd command-line tool"
    )


def parse_control(text: str) -> dict[str, str]:
    """Parse a deb822 control stanza. Continuation lines are joined with '\\n'."""
    fields: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if not line.strip():
            if fields:
                break
            continue
        if line[0] in " \t" and key:
            cont = line[1:]
            fields[key] += "\n" + ("" if cont.strip() == "." else cont)
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            fields[key] = val.strip()
    return fields


