"""Minimal, dependency-free PE (Windows executable) reader.

Reads imports (static and delay-load, by name or ordinal), exports
(including forwarders), machine, subsystem, whether the file is a
.NET assembly, and the outside types a .NET assembly uses.
"""
from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass, field
from pathlib import Path

MACHINES = {0x14C: "i386", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C4: "arm"}
SUBSYSTEMS = {1: "native", 2: "gui", 3: "console", 9: "wince", 10: "efi"}
IMAGE_FILE_DLL = 0x2000

DIR_EXPORT, DIR_IMPORT, DIR_CLR, DIR_DELAY_IMPORT = 0, 1, 14, 13


class PeError(Exception):
    """A file that isn't a readable PE image."""
    pass


@dataclass
class PeImport:
    """One imported function: by name, or by ordinal when name is None; delay is True for delay-load imports."""
    dll: str
    name: str | None       # None when imported by ordinal
    ordinal: int | None
    delay: bool

    @property
    def label(self) -> str:
        """Return the name, or '#<ordinal>' for an import by ordinal."""
        return self.name if self.name is not None else f"#{self.ordinal}"


@dataclass
class PeInfo:
    """The parts of a PE file (.exe or .dll) that gap analysis needs.

    Attributes:
        machine: x86_64, i386, aarch64 and so on.
        is_dotnet: True if it has a CLR header (a .NET assembly).
        dll_name: The name in the export directory, for a DLL.
        exports: Exported name -> ordinal.
        ordinals: Every exported ordinal, including ordinal-only exports.
        forwarders: Exports that forward elsewhere: name -> "dll.func".
        problems: Tables that couldn't be read completely (the rest was kept).
    """
    path: str
    machine: str
    is_dll: bool
    subsystem: str
    is_dotnet: bool = False
    dll_name: str | None = None
    imports: list[PeImport] = field(default_factory=list)
    exports: dict[str, int] = field(default_factory=dict)
    ordinals: set[int] = field(default_factory=set)
    forwarders: dict[str, str] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def imported_dlls(self) -> set[str]:
        """Return the lower-cased names of every DLL it imports from."""
        return {i.dll.lower() for i in self.imports}


def is_pe(path: str | Path) -> bool:
    """Return True if path has an MZ header pointing at a PE signature."""
    try:
        with open(path, "rb") as f:
            head = f.read(64)
            if len(head) < 64 or head[:2] != b"MZ":
                return False
            off = struct.unpack_from("<I", head, 0x3C)[0]
            f.seek(off)
            return f.read(4) == b"PE\0\0"
    except OSError:
        return False


def _cstr(m, off: int, limit: int = 4096) -> str:
    """Read a NUL-terminated ASCII string at off.

    Raises:
        PeError: No NUL within limit bytes.
    """
    end = m.find(b"\0", off, off + limit)
    if end < 0:
        raise PeError("unterminated string")
    return bytes(m[off:end]).decode("ascii", "replace")


class _Image:
    """A PE file's headers and section table, for turning RVAs into file offsets."""
    def __init__(self, m):
        self.m = m
        pe = struct.unpack_from("<I", m, 0x3C)[0]
        if m[pe:pe + 4] != b"PE\0\0":
            raise PeError("missing PE signature")
        (self.machine, nsec, _ts, _st, _ns, opt_size, self.characteristics) = struct.unpack_from("<HHIIIHH", m, pe + 4)
        opt = pe + 24
        self.magic = struct.unpack_from("<H", m, opt)[0]
        if self.magic == 0x20B:
            self.image_base = struct.unpack_from("<Q", m, opt + 24)[0]
            self.subsystem = struct.unpack_from("<H", m, opt + 68)[0]
            ndirs = struct.unpack_from("<I", m, opt + 108)[0]
            dirs_off = opt + 112
            self.ptr_size = 8
        elif self.magic == 0x10B:
            self.image_base = struct.unpack_from("<I", m, opt + 28)[0]
            self.subsystem = struct.unpack_from("<H", m, opt + 68)[0]
            ndirs = struct.unpack_from("<I", m, opt + 92)[0]
            dirs_off = opt + 96
            self.ptr_size = 4
        else:
            raise PeError(f"unknown optional header magic {self.magic:#x}")
        self.dirs = [struct.unpack_from("<II", m, dirs_off + 8 * i) for i in range(min(ndirs, 16))]
        self.dirs += [(0, 0)] * (16 - len(self.dirs))
        self.sections = []
        sec = opt + opt_size
        for i in range(nsec):
            _name, vsize, va, rawsize, rawptr = struct.unpack_from("<8sIIII", m, sec + 40 * i)
            self.sections.append((va, max(vsize, rawsize), rawptr, rawsize))

    def off(self, rva: int) -> int:
        """Return the file offset of an RVA.

        Raises:
            PeError: The RVA is outside every section, or in uninitialized data.
        """
        for va, size, rawptr, rawsize in self.sections:
            if va <= rva < va + size:
                delta = rva - va
                if delta >= rawsize:
                    raise PeError(f"RVA {rva:#x} is in uninitialized data")
                return rawptr + delta
        # headers are mapped at RVA 0 == file offset 0
        if rva < (self.sections[0][2] if self.sections else len(self.m)):
            return rva
        raise PeError(f"RVA {rva:#x} not in any section")


def read_pe(path: str | Path) -> PeInfo:
    """Read the imports, exports and headers of a PE file.

    Raises:
        PeError: The file is empty, not a PE file, or malformed.
    """
    path = str(path)
    with open(path, "rb") as f:
        try:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError as e:
            raise PeError(f"{path}: {e}") from e
        try:
            return _parse(path, m)
        except (struct.error, IndexError) as e:
            raise PeError(f"{path}: malformed PE ({e})") from e
        finally:
            m.close()


def _parse(path: str, m) -> PeInfo:
    """Parse the headers, imports, delay imports and exports of a mapped PE file.

    Raises:
        PeError: The file has no MZ header.
    """
    if m[:2] != b"MZ":
        raise PeError(f"{path}: not a PE file")
    img = _Image(m)
    info = PeInfo(path=path, machine=MACHINES.get(img.machine, f"machine-{img.machine:#x}"),
                  is_dll=bool(img.characteristics & IMAGE_FILE_DLL),
                  subsystem=SUBSYSTEMS.get(img.subsystem, str(img.subsystem)))
    info.is_dotnet = img.dirs[DIR_CLR][0] != 0
    # A table pointing somewhere odd (Rufus has an RVA in uninitialized data, which the Windows
    # loader reads as zeros) shouldn't make the whole program unreadable: keep what reads cleanly.
    for what, parse in (("imports", _parse_imports), ("delay-load imports", _parse_delay_imports),
                        ("exports", _parse_exports)):
        try:
            parse(img, info)
        except (PeError, struct.error, IndexError) as e:
            info.problems.append(f"{what}: {e}")
    return info


def _read_thunks(img: _Image, rva: int):
    """Yield (name or None, ordinal or None) for each entry of a null-terminated import lookup table."""
    fmt, flag = ("<Q", 1 << 63) if img.ptr_size == 8 else ("<I", 1 << 31)
    off = img.off(rva)
    for _ in range(65536):
        val = struct.unpack_from(fmt, img.m, off)[0]
        if val == 0:
            return
        if val & flag:
            yield None, val & 0xFFFF
        else:
            hint_name = img.off(val & 0x7FFFFFFF)
            yield _cstr(img.m, hint_name + 2), None
        off += img.ptr_size


def _parse_imports(img: _Image, info: PeInfo) -> None:
    """Add the import directory's entries to info.imports."""
    rva, size = img.dirs[DIR_IMPORT]
    if not rva:
        return
    off = img.off(rva)
    for _ in range(4096):
        ilt, _ts, _fwd, name_rva, iat = struct.unpack_from("<IIIII", img.m, off)
        if not (ilt or name_rva or iat):
            break
        dll = _cstr(img.m, img.off(name_rva))
        for name, ordinal in _read_thunks(img, ilt or iat):
            info.imports.append(PeImport(dll, name, ordinal, delay=False))
        off += 20


def _parse_delay_imports(img: _Image, info: PeInfo) -> None:
    """Add the delay-load import directory's entries to info.imports, marked delay=True."""
    rva, _size = img.dirs[DIR_DELAY_IMPORT]
    if not rva:
        return
    off = img.off(rva)
    for _ in range(4096):
        attrs, name, _hmod, _iat, int_rva, _b, _u, _ts = struct.unpack_from("<IIIIIIII", img.m, off)
        if not (name or int_rva):
            break
        # attribute bit 0 set: fields are RVAs; otherwise (old VC6 style) they are VAs
        fix = (lambda x: x) if attrs & 1 else (lambda x: x - img.image_base if x else 0)
        dll = _cstr(img.m, img.off(fix(name)))
        if int_rva:
            if attrs & 1:
                thunks = _read_thunks(img, int_rva)
            else:
                thunks = _read_va_thunks(img, fix(int_rva))
            for fname, ordinal in thunks:
                info.imports.append(PeImport(dll, fname, ordinal, delay=True))
        off += 32


def _read_va_thunks(img: _Image, rva: int):
    """Like _read_thunks, for old delay-load tables that hold virtual addresses instead of RVAs."""
    fmt, flag = ("<Q", 1 << 63) if img.ptr_size == 8 else ("<I", 1 << 31)
    off = img.off(rva)
    for _ in range(65536):
        val = struct.unpack_from(fmt, img.m, off)[0]
        if val == 0:
            return
        if val & flag:
            yield None, val & 0xFFFF
        else:
            yield _cstr(img.m, img.off(val - img.image_base) + 2), None
        off += img.ptr_size


def _parse_exports(img: _Image, info: PeInfo) -> None:
    """Fill info.dll_name, exports, ordinals and forwarders from the export directory."""
    rva, size = img.dirs[DIR_EXPORT]
    if not rva:
        return
    off = img.off(rva)
    (_ch, _ts, _maj, _min, name_rva, base, nfuncs, nnames,
     funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", img.m, off)
    if name_rva:
        info.dll_name = _cstr(img.m, img.off(name_rva))
    funcs = [struct.unpack_from("<I", img.m, img.off(funcs_rva) + 4 * i)[0] for i in range(min(nfuncs, 65536))]
    for i, f in enumerate(funcs):
        if f:
            info.ordinals.add(base + i)
    for i in range(min(nnames, 65536)):
        name = _cstr(img.m, img.off(struct.unpack_from("<I", img.m, img.off(names_rva) + 4 * i)[0]))
        idx = struct.unpack_from("<H", img.m, img.off(ords_rva) + 2 * i)[0]
        info.exports[name] = base + idx
        if idx < len(funcs) and rva <= funcs[idx] < rva + size:
            info.forwarders[name] = _cstr(img.m, img.off(funcs[idx]))


# ECMA-335 metadata tables: Module, TypeRef, ModuleRef and AssemblyRef, the tables a TypeRef's
# ResolutionScope can point into, which decide how wide that column is
TBL_MODULE, TBL_TYPEREF, TBL_MODULEREF, TBL_ASSEMBLYREF = 0x00, 0x01, 0x1A, 0x23


def dotnet_type_refs(path: str | Path) -> set[tuple[str, str]]:
    """Return the (namespace, name) of every type a .NET assembly uses from other assemblies.

    These are the rows of its metadata's TypeRef table. Searching the file
    for a class name isn't enough: compilers store a name that ends another
    one (PropertyGrid in FilteredPropertyGrid) only once, so the name may not
    appear on its own. Returns an empty set for anything that isn't a
    readable .NET assembly.
    """
    try:
        with open(path, "rb") as f:
            try:
                m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:
                return set()
            try:
                return _type_refs(m) if m[:2] == b"MZ" else set()
            finally:
                m.close()
    except (OSError, PeError, struct.error, IndexError, ValueError):
        return set()


def _type_refs(m) -> set[tuple[str, str]]:
    img = _Image(m)
    clr_rva = img.dirs[DIR_CLR][0]
    if not clr_rva:
        return set()
    md_rva = struct.unpack_from("<I", m, img.off(clr_rva) + 8)[0]
    root = img.off(md_rva)
    if m[root:root + 4] != b"BSJB":
        return set()
    vlen = struct.unpack_from("<I", m, root + 12)[0]
    off = root + 16 + vlen + 2
    nstreams = struct.unpack_from("<H", m, off)[0]
    off += 2
    streams = {}
    for _ in range(nstreams):
        s_off, s_size = struct.unpack_from("<II", m, off)
        name = _cstr(m, off + 8, 32)
        streams[name] = (root + s_off, s_size)
        off += 8 + (len(name) + 4) // 4 * 4
    tables = streams.get("#~") or streams.get("#-")
    strings = streams.get("#Strings")
    if not tables or not strings:
        return set()
    t = tables[0]
    heap_sizes = m[t + 6]
    valid = struct.unpack_from("<Q", m, t + 8)[0]
    rows, off = {}, t + 24
    for i in range(64):
        if valid >> i & 1:
            rows[i] = struct.unpack_from("<I", m, off)[0]
            off += 4
    if heap_sizes & 0x40:       # an edit-and-continue (#-) stream may carry 4 extra bytes here
        off += 4
    str_w = 4 if heap_sizes & 0x01 else 2
    guid_w = 4 if heap_sizes & 0x02 else 2
    scope_w = 4 if max(rows.get(x, 0) for x in (TBL_MODULE, TBL_MODULEREF, TBL_ASSEMBLYREF,
                                                TBL_TYPEREF)) >= 1 << 14 else 2
    off += rows.get(TBL_MODULE, 0) * (2 + str_w + 3 * guid_w)
    idx = "<I" if str_w == 4 else "<H"

    def string(i: int) -> str:
        if i >= strings[1]:
            raise PeError("string index outside the #Strings heap")
        end = m.find(b"\0", strings[0] + i, strings[0] + strings[1])
        if end < 0:
            raise PeError("unterminated string in the #Strings heap")
        return bytes(m[strings[0] + i:end]).decode("utf-8", "replace")
    found = set()
    for _ in range(min(rows.get(TBL_TYPEREF, 0), 1 << 20)):
        name = struct.unpack_from(idx, m, off + scope_w)[0]
        ns = struct.unpack_from(idx, m, off + scope_w + str_w)[0]
        found.add((string(ns), string(name)))
        off += scope_w + 2 * str_w
    return found
