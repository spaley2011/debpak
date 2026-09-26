"""Minimal, dependency-free PE (Windows executable) reader.

Reads imports (static and delay-load, by name or ordinal), exports
(including forwarders), machine, subsystem, and whether the file is a
.NET assembly.
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
    pass


@dataclass
class PeImport:
    dll: str
    name: str | None       # None when imported by ordinal
    ordinal: int | None
    delay: bool

    @property
    def label(self) -> str:
        return self.name if self.name is not None else f"#{self.ordinal}"


@dataclass
class PeInfo:
    path: str
    machine: str
    is_dll: bool
    subsystem: str
    is_dotnet: bool = False
    dll_name: str | None = None                         # from the export directory
    imports: list[PeImport] = field(default_factory=list)
    exports: dict[str, int] = field(default_factory=dict)     # name -> ordinal
    ordinals: set[int] = field(default_factory=set)
    forwarders: dict[str, str] = field(default_factory=dict)  # name -> "dll.func"

    @property
    def imported_dlls(self) -> set[str]:
        return {i.dll.lower() for i in self.imports}


def is_pe(path: str | Path) -> bool:
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
    end = m.find(b"\0", off, off + limit)
    if end < 0:
        raise PeError("unterminated string")
    return bytes(m[off:end]).decode("ascii", "replace")


class _Image:
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
    if m[:2] != b"MZ":
        raise PeError(f"{path}: not a PE file")
    img = _Image(m)
    info = PeInfo(path=path, machine=MACHINES.get(img.machine, f"machine-{img.machine:#x}"),
                  is_dll=bool(img.characteristics & IMAGE_FILE_DLL),
                  subsystem=SUBSYSTEMS.get(img.subsystem, str(img.subsystem)))
    info.is_dotnet = img.dirs[DIR_CLR][0] != 0
    _parse_imports(img, info)
    _parse_delay_imports(img, info)
    _parse_exports(img, info)
    return info


def _read_thunks(img: _Image, rva: int):
    """Yield (name|None, ordinal|None) for a null-terminated import lookup table."""
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
