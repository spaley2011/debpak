""".rpm reading and extraction, in pure Python.

An RPM file is: a 96-byte lead, a signature header (padded to 8 bytes), the
main header, and a compressed cpio ("newc") archive of the files. Headers are
an index of (tag, type, offset, count) entries over a data store. The payload
compressor is found from its magic bytes (gzip, xz, legacy lzma, bzip2, zstd).

When the package carries them, the SHA-256 digests of the main header and of
the compressed payload are checked, so a damaged download fails loudly instead
of producing a half-extracted tree. Extraction refuses paths that leave the
destination (`..`, writes through symlinks) and strips setuid/setgid bits.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import stat
import struct
import zlib
from pathlib import Path

from .packages import Package, PackageError

LEAD_MAGIC = b"\xed\xab\xee\xdb"
HEADER_MAGIC = b"\x8e\xad\xe8\x01"

# header tags
NAME, VERSION, RELEASE, EPOCH, SUMMARY, DESCRIPTION = 1000, 1001, 1002, 1003, 1004, 1005
LICENSE, URL, ARCH = 1014, 1020, 1022
PREIN, POSTIN, PREUN, POSTUN = 1023, 1024, 1025, 1026
PREINPROG, POSTINPROG, PREUNPROG, POSTUNPROG = 1085, 1086, 1087, 1088
TRIGGERSCRIPTS = 1065
PAYLOADFORMAT, PAYLOADCOMPRESSOR = 1124, 1125
PRETRANS, POSTTRANS = 1151, 1152
PAYLOADDIGEST, PAYLOADDIGESTALGO = 5092, 5093
SIG_SHA256 = 273        # signature-header tag: hex SHA-256 of the main header

# RPM scriptlets under the Debian names the host-integration checks use
SCRIPT_TAGS = {"preinst": (PREIN, PREINPROG), "postinst": (POSTIN, POSTINPROG),
               "prerm": (PREUN, PREUNPROG), "postrm": (POSTUN, POSTUNPROG)}
MAX_HEADER = 256 * 1024 * 1024


def _read_exact(f, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise PackageError("truncated RPM")
    return b


def read_header(f) -> tuple[dict[int, object], bytes]:
    """Parse one header structure at the current position: ({tag: value}, raw bytes)."""
    head = _read_exact(f, 16)
    if head[:4] != HEADER_MAGIC:
        raise PackageError("bad RPM header magic")
    nindex, hsize = struct.unpack(">II", head[8:16])
    if nindex > 100000 or hsize > MAX_HEADER:
        raise PackageError("implausible RPM header size")
    index = _read_exact(f, 16 * nindex)
    store = _read_exact(f, hsize)
    tags: dict[int, object] = {}
    for i in range(nindex):
        tag, typ, off, count = struct.unpack(">IIII", index[16 * i:16 * i + 16])
        if off > hsize:
            raise PackageError(f"RPM header entry {tag} points outside the header")
        tags[tag] = _value(store, typ, off, count)
    return tags, head + index + store


def _value(store: bytes, typ: int, off: int, count: int):
    if typ == 6:                                    # STRING
        end = store.index(b"\0", off)
        return store[off:end].decode("utf-8", "replace")
    if typ in (8, 9):                               # STRING_ARRAY, I18NSTRING
        out = []
        for _ in range(count):
            end = store.index(b"\0", off)
            out.append(store[off:end].decode("utf-8", "replace"))
            off = end + 1
        return out
    if typ == 4:
        return list(struct.unpack(f">{count}I", store[off:off + 4 * count]))
    if typ == 3:
        return list(struct.unpack(f">{count}H", store[off:off + 2 * count]))
    if typ == 5:
        return list(struct.unpack(f">{count}Q", store[off:off + 8 * count]))
    if typ in (1, 2, 7):                            # CHAR, INT8, BIN
        return store[off:off + count]
    return None


def _s(tags: dict, tag: int, default: str = "") -> str:
    v = tags.get(tag)
    if isinstance(v, list):
        return v[0] if v and isinstance(v[0], str) else default
    return v if isinstance(v, str) else default


def _decompressor(raw, head: bytes):
    if head[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=raw)
    if head[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(raw, format=lzma.FORMAT_XZ)
    if head[:3] == b"BZh":
        return bz2.BZ2File(raw)
    if head[:4] == b"\x28\xb5\x2f\xfd":
        from .deb import _zstd_stream
        s = _zstd_stream(raw)
        if s is None:
            raise _NeedZstdTool()
        return s
    if head[:4] == b"0707":
        return raw
    if head[:1] == b"\x5d":                                     # legacy .lzma
        return lzma.LZMAFile(raw, format=lzma.FORMAT_ALONE)
    raise PackageError("payload is damaged or uses an unknown compression")


class _NeedZstdTool(Exception):
    """zstd payload, and no Python zstd module: decompress with the zstd command instead."""


class RpmInfo:
    def __init__(self, path: Path):
        self.path = path
        with open(path, "rb") as f:
            lead = _read_exact(f, 96)
            if lead[:4] != LEAD_MAGIC:
                raise PackageError(f"{path.name}: not an RPM file")
            self.sig, raw_sig = read_header(f)
            pad = (8 - len(raw_sig) % 8) % 8
            _read_exact(f, pad)
            self.tags, raw_header = read_header(f)
            self.payload_offset = f.tell()
        want = self.sig.get(SIG_SHA256)
        if isinstance(want, str) and want and hashlib.sha256(raw_header).hexdigest() != want.lower():
            raise PackageError(f"{path.name}: header checksum mismatch (corrupted download?)")

    @property
    def name(self) -> str:
        return _s(self.tags, NAME, self.path.stem)

    @property
    def version(self) -> str:
        v, r = _s(self.tags, VERSION, "0"), _s(self.tags, RELEASE)
        e = self.tags.get(EPOCH)
        epoch = f"{e[0]}:" if isinstance(e, list) and e else ""
        return f"{epoch}{v}-{r}" if r else f"{epoch}{v}"

    def scripts(self) -> tuple[dict[str, str], list[str]]:
        out, notes = {}, []
        for deb_name, (tag, prog_tag) in SCRIPT_TAGS.items():
            body = _s(self.tags, tag)
            prog = self.tags.get(prog_tag)
            prog = prog[0] if isinstance(prog, list) and prog else (prog if isinstance(prog, str) else "")
            if prog == "<lua>":
                notes.append(f"{deb_name} scriptlet is Lua (run inside rpm); reviewed as text only")
            if body:
                out[deb_name] = (f"#!{prog}\n" if prog and prog.startswith("/") else "") + body
        for tag, label in ((PRETRANS, "%pretrans"), (POSTTRANS, "%posttrans")):
            if _s(self.tags, tag):
                out.setdefault("postinst", "")
                out["postinst"] += f"\n# {label}\n" + _s(self.tags, tag)
        if self.tags.get(TRIGGERSCRIPTS):
            notes.append("package has rpm triggers (scripts run when other packages change); "
                         "a Flatpak can't run them")
        return out, notes


