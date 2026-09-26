"""Minimal, dependency-free Mach-O reader (thin and universal/fat binaries).

Extracts linked dylibs (with weak/re-export flags), the install name,
rpaths, platform/minimum OS, the entry point kind, undefined symbols with
the library ordinal they bind to (two-level namespace), and exported symbols
from the export trie (falling back to the symbol table).
"""
from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass, field
from pathlib import Path

MH_MAGIC, MH_CIGAM = 0xFEEDFACE, 0xCEFAEDFE
MH_MAGIC_64, MH_CIGAM_64 = 0xFEEDFACF, 0xCFFAEDFE
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF

CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 18: "ppc", 0x01000012: "ppc64"}
FILETYPES = {1: "object", 2: "execute", 6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib_stub"}
PLATFORMS = {1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos", 6: "maccatalyst",
             7: "iossimulator", 8: "tvossimulator", 9: "watchossimulator", 10: "driverkit",
             11: "visionos", 12: "visionossimulator"}

LC_REQ_DYLD = 0x80000000
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x20
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x24
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_BUILD_VERSION = 0x32
LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD

DYLIB_CMDS = {LC_LOAD_DYLIB: "load", LC_LOAD_WEAK_DYLIB: "weak", LC_REEXPORT_DYLIB: "reexport",
              LC_LAZY_LOAD_DYLIB: "lazy", LC_LOAD_UPWARD_DYLIB: "upward"}

N_EXT, N_TYPE, N_UNDF, N_SECT, N_STAB = 0x01, 0x0E, 0x0, 0xE, 0xE0
N_WEAK_REF = 0x40
MH_TWOLEVEL = 0x80
SELF_ORDINAL, DYNAMIC_LOOKUP_ORDINAL, EXECUTABLE_ORDINAL = 0, 0xFE, 0xFF
EXPORT_REEXPORT = 0x08
EXPORT_STUB_AND_RESOLVER = 0x10


class MachOError(Exception):
    pass


@dataclass
class Dylib:
    name: str
    kind: str          # load | weak | reexport | lazy | upward

    @property
    def weak(self) -> bool:
        return self.kind in ("weak", "lazy")


@dataclass
class UndefSym:
    name: str
    ordinal: int       # 1-based index into dylibs, or special ordinal
    weak: bool


@dataclass
class MachOSlice:
    path: str
    arch: str
    filetype: str
    offset: int
    twolevel: bool = True
    install_name: str | None = None
    dylibs: list[Dylib] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    platform: str | None = None
    min_os: str | None = None
    has_main: bool = False
    undefined: list[UndefSym] = field(default_factory=list)
    exports: set[str] = field(default_factory=set)
    reexported_names: set[str] = field(default_factory=set)   # exported via EXPORT_REEXPORT entries

    def library_for(self, sym: UndefSym) -> Dylib | None:
        if 1 <= sym.ordinal <= len(self.dylibs):
            return self.dylibs[sym.ordinal - 1]
        return None


@dataclass
class MachOFile:
    path: str
    slices: list[MachOSlice]

    @property
    def archs(self) -> list[str]:
        return [s.arch for s in self.slices]

    def slice(self, arch: str) -> MachOSlice | None:
        return next((s for s in self.slices if s.arch == arch), None)


def is_macho(path: str | Path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return False
    if len(head) < 8:
        return False
    magic = struct.unpack(">I", head[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        # Java class files share 0xCAFEBABE; fat headers have a small arch count
        return 0 < struct.unpack(">I", head[4:8])[0] < 32
    return magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64) or \
        struct.unpack("<I", head[:4])[0] in (MH_MAGIC, MH_MAGIC_64)


def read_macho(path: str | Path) -> MachOFile:
    path = str(path)
    with open(path, "rb") as f:
        try:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError as e:
            raise MachOError(f"{path}: {e}") from e
        try:
            magic = struct.unpack_from(">I", m, 0)[0]
            if magic in (FAT_MAGIC, FAT_MAGIC_64):
                n = struct.unpack_from(">I", m, 4)[0]
                slices = []
                for i in range(n):
                    if magic == FAT_MAGIC:
                        _cpu, _sub, off, size, _al = struct.unpack_from(">iiIII", m, 8 + 20 * i)
                    else:
                        _cpu, _sub, off, size, _al, _r = struct.unpack_from(">iiQQII", m, 8 + 32 * i)
                    slices.append(_parse_slice(path, m, off))
                return MachOFile(path, slices)
            return MachOFile(path, [_parse_slice(path, m, 0)])
        except (struct.error, IndexError) as e:
            raise MachOError(f"{path}: malformed Mach-O ({e})") from e
        finally:
            m.close()


def _cstr(m, off: int) -> str:
    end = m.find(b"\0", off)
    return bytes(m[off:end if end >= 0 else len(m)]).decode("utf-8", "replace")


def _uleb(m, off: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = m[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def _version(v: int) -> str:
    major, minor, patch = v >> 16, (v >> 8) & 0xFF, v & 0xFF
    return f"{major}.{minor}" + (f".{patch}" if patch else "")


