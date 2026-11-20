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
from dataclasses import dataclass, field
from pathlib import Path

DEB_ARCH_TO_FLATPAK = {"amd64": "x86_64", "arm64": "aarch64", "i386": "i386", "armhf": "arm"}


class DebError(Exception):
    """A .deb that can't be read or extracted."""
    pass


@dataclass
class ArMember:
    """One member of an ar archive: its name and where its data sits in the file."""
    name: str
    offset: int
    size: int


def read_ar(path: str | Path) -> list[ArMember]:
    """List the members of an ar archive (the container format of a .deb)."""
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
        """Read from the slice into b, stopping at its end; return the byte count."""
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
    """Wrap raw in a zstd decompressor from Python, or return None if none is installed."""
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
    """Extract one tarball member of a .deb into dest.

    dpkg_flag (--ctrl-tarfile or --fsys-tarfile) tells dpkg-deb which member to
    stream if dpkg-deb has to do the zstd decompression.

    Raises:
        DebError: The member uses a compression debpak can't read.
    """
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
    """Extract a zstd member with the zstd command, or failing that dpkg-deb.

    Raises:
        DebError: Neither tool is installed, or the one that ran failed.
    """
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


@dataclass
class DebPackage:
    """An extracted .deb.

    Attributes:
        path: The .deb file.
        root: The extracted data.tar, laid out like an installed system.
        control_dir: The extracted control.tar (control file, maintainer scripts).
        control: The fields of the control file.
        notes: Messages for the report about how the package was unpacked.
        default_exec: The entry point the format implies, if any (None for .deb;
            the other formats in packages.py set it).
    """
    path: Path
    root: Path
    control_dir: Path
    control: dict[str, str]
    notes: list[str] = field(default_factory=list)
    default_exec: str | None = None
    format = "deb"

    @property
    def pkg_arch(self) -> str:
        return self.deb_arch

    @property
    def homepage(self) -> str:
        return self.control.get("Homepage", "")

    @property
    def license(self) -> str:
        return ""     # debs keep it in usr/share/doc/*/copyright, rarely as SPDX

    @property
    def name(self) -> str:
        return self.control.get("Package", self.path.stem)

    @property
    def version(self) -> str:
        return self.control.get("Version", "0")

    @property
    def deb_arch(self) -> str:
        return self.control.get("Architecture", "amd64")

    @property
    def flatpak_arch(self) -> str | None:
        return DEB_ARCH_TO_FLATPAK.get(self.deb_arch)

    @property
    def summary(self) -> str:
        return self.control.get("Description", "").split("\n", 1)[0].strip()

    @property
    def long_description(self) -> str:
        """Return the Description field without its first (summary) line."""
        parts = self.control.get("Description", "").split("\n", 1)
        return parts[1].strip() if len(parts) > 1 else ""

    def maintainer_script(self, name: str) -> str | None:
        """Return the text of a maintainer script (preinst, postinst, ...) or None."""
        p = self.control_dir / name
        if p.is_file():
            return p.read_text("utf-8", "replace")
        return None


def extract(deb: str | Path, dest: str | Path) -> DebPackage:
    """Extract a .deb into dest/root (the files) and dest/control (the metadata).

    Raises:
        DebError: The file isn't a .deb, lacks control.tar or data.tar, or uses a
            compression debpak can't read.
    """
    deb = Path(deb)
    dest = Path(dest).resolve()
    members = {m.name: m for m in read_ar(deb)}
    ctrl = next((m for n, m in members.items() if n.startswith("control.tar")), None)
    data = next((m for n, m in members.items() if n.startswith("data.tar")), None)
    if ctrl is None or data is None:
        raise DebError(f"{deb}: missing control.tar or data.tar member")
    control_dir, root = dest / "control", dest / "root"
    _extract_member(deb, ctrl, control_dir, "--ctrl-tarfile")
    _extract_member(deb, data, root, "--fsys-tarfile")
    control_file = control_dir / "control"
    if not control_file.is_file():
        raise DebError(f"{deb}: control file missing")
    control = parse_control(control_file.read_text("utf-8", "replace"))
    return DebPackage(path=deb, root=root, control_dir=control_dir, control=control)


def resolve_in_root(root: Path, rel: str, max_hops: int = 40) -> Path | None:
    """Resolve a path inside an extracted tree, treating absolute symlink
    targets as relative to `root` (like a chroot). Returns None if the path
    doesn't exist or escapes the root."""
    root = root.resolve()
    parts = [p for p in rel.strip("/").split("/") if p]
    current = root
    hops = 0
    while parts:
        part = parts.pop(0)
        if part == ".":
            continue
        if part == "..":
            if current != root:
                current = current.parent
            continue
        candidate = current / part
        if candidate.is_symlink():
            hops += 1
            if hops > max_hops:
                return None
            target = os.readlink(candidate)
            if target.startswith("/"):
                current = root
            parts = [p for p in target.strip("/").split("/") if p] + parts
            continue
        if not candidate.exists():
            return None
        current = candidate
    try:
        current.relative_to(root)
    except ValueError:
        return None
    return current
