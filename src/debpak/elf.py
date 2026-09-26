"""Minimal, dependency-free ELF reader.

Extracts exactly what debpak needs from a binary or shared library:
DT_NEEDED / DT_SONAME / RPATH / RUNPATH, the program interpreter,
symbol-version requirements (verneed), symbol-version definitions (verdef)
and the set of undefined dynamic symbols (used for permission heuristics).
"""
from __future__ import annotations

import mmap
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHT_GNU_VERDEF = 0x6FFFFFFD
SHT_GNU_VERNEED = 0x6FFFFFFE

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29

ET_EXEC = 2
ET_DYN = 3

VER_FLG_BASE = 0x1

MACHINES = {3: "i386", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv64"}


class ElfError(Exception):
    pass


@dataclass
class ElfInfo:
    path: str
    machine: str
    elf_type: int
    bits: int
    interp: str | None = None
    soname: str | None = None
    needed: list[str] = field(default_factory=list)
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    # library file name (as in DT_NEEDED) -> set of version names required
    verneed: dict[str, set[str]] = field(default_factory=dict)
    # version names this object defines (e.g. GLIBC_2.34 for libc.so.6)
    verdef: set[str] = field(default_factory=set)
    undefined_symbols: set[str] = field(default_factory=set)

    @property
    def is_executable(self) -> bool:
        return self.interp is not None or self.elf_type == ET_EXEC

    @property
    def is_shared_library(self) -> bool:
        return self.elf_type == ET_DYN and self.interp is None


def is_elf(path: str | Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except (OSError, IsADirectoryError):
        return False


def _cstr(buf, off: int) -> str:
    end = buf.find(b"\0", off)
    if end < 0:
        end = len(buf)
    return bytes(buf[off:end]).decode("utf-8", "replace")


def read_elf(path: str | Path, want_symbols: bool = True) -> ElfInfo:
    path = str(path)
    with open(path, "rb") as f:
        try:
            buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError as e:  # empty file
            raise ElfError(f"{path}: {e}") from e
        try:
            return _parse(path, buf, want_symbols)
        except struct.error as e:
            raise ElfError(f"{path}: truncated or malformed ELF ({e})") from e
        finally:
            buf.close()


def _parse(path: str, m, want_symbols: bool) -> ElfInfo:
    if m[:4] != ELF_MAGIC:
        raise ElfError(f"{path}: not an ELF file")
    ei_class, ei_data = m[4], m[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ElfError(f"{path}: unsupported ELF class/encoding")
    bits = 64 if ei_class == 2 else 32
    e = "<" if ei_data == 1 else ">"

    if bits == 64:
        (e_type, e_machine, _ver, _entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", m, 16)
    else:
        (e_type, e_machine, _ver, _entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", m, 16)

    info = ElfInfo(path=path, machine=MACHINES.get(e_machine, f"machine-{e_machine}"),
                   elf_type=e_type, bits=bits)

    # --- program headers: interpreter, PT_LOAD map, PT_DYNAMIC fallback
    loads: list[tuple[int, int, int]] = []  # (vaddr, offset, filesz)
    pt_dynamic: tuple[int, int] | None = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if bits == 64:
            p_type, _pf, p_offset, p_vaddr, _pa, p_filesz, _pm, _al = struct.unpack_from(e + "IIQQQQQQ", m, off)
        else:
            p_type, p_offset, p_vaddr, _pa, p_filesz, _pm, _pf, _al = struct.unpack_from(e + "IIIIIIII", m, off)
        if p_type == PT_INTERP:
            info.interp = _cstr(m, p_offset)
        elif p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC:
            pt_dynamic = (p_offset, p_filesz)

    # --- section headers
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if bits == 64:
            fields = struct.unpack_from(e + "IIQQQQIIQQ", m, off)
        else:
            fields = struct.unpack_from(e + "IIIIIIIIII", m, off)
        # name, type, flags, addr, offset, size, link, info, align, entsize
        sections.append(fields)

    def strtab_of(sec_index: int):
        s = sections[sec_index]
        return s[4]  # offset of linked string table

    dyn_entry = struct.Struct(e + ("qQ" if bits == 64 else "iI"))

    def parse_dynamic(dyn_off: int, dyn_size: int, strtab_off: int | None):
        entries = []
        for j in range(dyn_size // dyn_entry.size):
            tag, val = dyn_entry.unpack_from(m, dyn_off + j * dyn_entry.size)
            if tag == DT_NULL:
                break
            entries.append((tag, val))
        if strtab_off is None:
            # No section headers: locate DT_STRTAB via its virtual address.
            vaddr = next((v for t, v in entries if t == DT_STRTAB), None)
            if vaddr is None:
                return
            strtab_off = _vaddr_to_offset(loads, vaddr)
            if strtab_off is None:
                return
        for tag, val in entries:
            if tag == DT_NEEDED:
                info.needed.append(_cstr(m, strtab_off + val))
            elif tag == DT_SONAME:
                info.soname = _cstr(m, strtab_off + val)
            elif tag == DT_RPATH:
                info.rpath.extend(p for p in _cstr(m, strtab_off + val).split(":") if p)
            elif tag == DT_RUNPATH:
                info.runpath.extend(p for p in _cstr(m, strtab_off + val).split(":") if p)

    have_dynamic_section = False
    for s in sections:
        _name, s_type, _fl, _addr, s_off, s_size, s_link, s_info, _al, _es = s
        if s_type == SHT_DYNAMIC:
            have_dynamic_section = True
            parse_dynamic(s_off, s_size, strtab_of(s_link) if s_link < len(sections) else None)
        elif s_type == SHT_GNU_VERNEED and s_link < len(sections):
            _parse_verneed(m, e, s_off, s_info, strtab_of(s_link), info)
        elif s_type == SHT_GNU_VERDEF and s_link < len(sections):
            _parse_verdef(m, e, s_off, s_info, strtab_of(s_link), info)
        elif s_type == SHT_DYNSYM and want_symbols and s_link < len(sections):
            _parse_undefined(m, e, bits, s_off, s_size, strtab_of(s_link), info)

    if not have_dynamic_section and pt_dynamic is not None:
        parse_dynamic(pt_dynamic[0], pt_dynamic[1], None)

    return info


