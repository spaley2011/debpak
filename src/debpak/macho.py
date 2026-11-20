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
    """A file that isn't a readable Mach-O object."""
    pass


@dataclass
class Dylib:
    """A library a Mach-O file links, with its load command kind: load, weak, reexport, lazy or upward."""
    name: str
    kind: str          # load | weak | reexport | lazy | upward

    @property
    def weak(self) -> bool:
        """True if the app still starts without the library (weak or lazy load)."""
        return self.kind in ("weak", "lazy")


@dataclass
class UndefSym:
    """An imported symbol, with the ordinal of the library it binds to (two-level namespace) and whether it's weak."""
    name: str
    ordinal: int       # 1-based index into dylibs, or special ordinal
    weak: bool


@dataclass
class MachOSlice:
    """One architecture of a Mach-O file.

    Attributes:
        filetype: execute, dylib, bundle, dylib_stub and so on.
        twolevel: True if symbols bind to a specific library; False for flat
            namespace, where dyld searches every loaded library.
        install_name: The name other binaries link this dylib by.
        platform, min_os: From LC_BUILD_VERSION or the older version-min commands.
        has_main: True if it has LC_MAIN, so it's a program.
        exports: Symbols in the export trie (or the symbol table if it has none).
    """
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
        """Return the library an undefined symbol binds to, or None for special ordinals (self, flat lookup)."""
        if 1 <= sym.ordinal <= len(self.dylibs):
            return self.dylibs[sym.ordinal - 1]
        return None


@dataclass
class MachOFile:
    """A thin or universal (fat) Mach-O file as a list of slices."""
    path: str
    slices: list[MachOSlice]

    @property
    def archs(self) -> list[str]:
        return [s.arch for s in self.slices]

    def slice(self, arch: str) -> MachOSlice | None:
        """Return the slice for arch (x86_64, arm64, ...), or None."""
        return next((s for s in self.slices if s.arch == arch), None)


def is_macho(path: str | Path) -> bool:
    """Return True for a thin or fat Mach-O file.

    Java class files start with the same 0xCAFEBABE magic as fat binaries, so a
    fat header also needs a plausible architecture count.
    """
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
    """Read every slice of a Mach-O file.

    Raises:
        MachOError: The file is empty, truncated or malformed.
    """
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
    """Decode an unsigned LEB128 number at off; return (value, offset after it)."""
    result = shift = 0
    while True:
        b = m[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def _version(v: int) -> str:
    """Format a packed xxxx.yy.zz version number, such as 0x000D0000 -> '13.0'."""
    major, minor, patch = v >> 16, (v >> 8) & 0xFF, v & 0xFF
    return f"{major}.{minor}" + (f".{patch}" if patch else "")


def _parse_slice(path: str, m, base: int) -> MachOSlice:
    """Parse the load commands of the slice at base."""
    magic_le = struct.unpack_from("<I", m, base)[0]
    if magic_le in (MH_MAGIC, MH_MAGIC_64):
        e = "<"
    elif magic_le in (MH_CIGAM, MH_CIGAM_64):
        e = ">"
    else:
        raise MachOError(f"{path}: bad Mach-O magic at {base:#x}")
    magic = struct.unpack_from(e + "I", m, base)[0]
    is64 = magic == MH_MAGIC_64
    _magic, cputype, _sub, filetype, ncmds, _size, flags = struct.unpack_from(e + "IiiIIII", m, base)
    s = MachOSlice(path=path, arch=CPU.get(cputype, f"cpu-{cputype:#x}"),
                   filetype=FILETYPES.get(filetype, str(filetype)), offset=base,
                   twolevel=bool(flags & MH_TWOLEVEL))
    off = base + (32 if is64 else 28)
    symtab = None
    export_trie = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(e + "II", m, off)
        if cmdsize < 8:
            raise MachOError(f"{path}: bad load command size")
        if cmd in DYLIB_CMDS or cmd == LC_ID_DYLIB:
            name_off = struct.unpack_from(e + "I", m, off + 8)[0]
            name = _cstr(m, off + name_off)
            if cmd == LC_ID_DYLIB:
                s.install_name = name
            else:
                s.dylibs.append(Dylib(name, DYLIB_CMDS[cmd]))
        elif cmd == LC_RPATH:
            s.rpaths.append(_cstr(m, off + struct.unpack_from(e + "I", m, off + 8)[0]))
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack_from(e + "IIII", m, off + 8)
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            exp_off, exp_size = struct.unpack_from(e + "II", m, off + 40)
            if exp_size:
                export_trie = (exp_off, exp_size)
        elif cmd == LC_DYLD_EXPORTS_TRIE:
            export_trie = struct.unpack_from(e + "II", m, off + 8)
        elif cmd == LC_BUILD_VERSION:
            platform, minos = struct.unpack_from(e + "II", m, off + 8)
            s.platform, s.min_os = PLATFORMS.get(platform, str(platform)), _version(minos)
        elif cmd == LC_VERSION_MIN_MACOSX:
            s.platform, s.min_os = "macos", _version(struct.unpack_from(e + "I", m, off + 8)[0])
        elif cmd == LC_MAIN:
            s.has_main = True
        off += cmdsize

    if symtab:
        symoff, nsyms, stroff, _strsize = symtab
        entry = struct.Struct(e + ("IBBHQ" if is64 else "IBBHI"))
        have_trie_exports = False
        if export_trie:
            _parse_trie(m, base + export_trie[0], export_trie[1], s)
            have_trie_exports = bool(s.exports)
        for i in range(min(nsyms, 5_000_000)):
            n_strx, n_type, _n_sect, n_desc, n_value = entry.unpack_from(m, base + symoff + i * entry.size)
            if n_type & N_STAB or not n_type & N_EXT:
                continue
            name = _cstr(m, base + stroff + n_strx)
            t = n_type & N_TYPE
            if t == N_UNDF and n_value == 0:
                s.undefined.append(UndefSym(name, (n_desc >> 8) & 0xFF, bool(n_desc & N_WEAK_REF)))
            elif t == N_SECT and not have_trie_exports:
                s.exports.add(name)
    elif export_trie:
        _parse_trie(m, base + export_trie[0], export_trie[1], s)
    return s


def _parse_trie(m, start: int, size: int, s: MachOSlice) -> None:
    """Walk the export trie and add every exported name to s.exports (re-exports also to s.reexported_names)."""
    end = start + size
    seen: set[int] = set()
    stack = [(0, "")]
    while stack:
        node_off, prefix = stack.pop()
        if node_off in seen or start + node_off >= end:
            continue
        seen.add(node_off)
        p = start + node_off
        term_size, p = _uleb(m, p)
        if term_size:
            flags, q = _uleb(m, p)
            s.exports.add(prefix)
            if flags & EXPORT_REEXPORT:
                s.reexported_names.add(prefix)
        p += term_size
        nchildren = m[p]
        p += 1
        for _ in range(nchildren):
            edge = _cstr(m, p)
            p += len(edge.encode()) + 1
            child, p = _uleb(m, p)
            stack.append((child, prefix + edge))
