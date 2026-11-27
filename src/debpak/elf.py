"""Minimal, dependency-free ELF reader.

Reads what debpak needs from a binary or shared library:
DT_NEEDED / DT_SONAME / RPATH / RUNPATH, the program interpreter,
symbol-version requirements (verneed), symbol-version definitions (verdef)
and the set of undefined dynamic symbols (used for permission heuristics).
"""
from __future__ import annotations

import mmap
import os
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
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_NODEFLIB = 0x800
DF_1_PIE = 0x08000000

ET_EXEC = 2
ET_DYN = 3

VER_FLG_BASE = 0x1

MACHINES = {3: "i386", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv64"}


class ElfError(Exception):
    """A file that isn't a readable ELF object."""


@dataclass
class ElfInfo:
    """The parts of an ELF file that gap analysis needs.

    Attributes:
        machine: The Flatpak architecture name, such as x86_64.
        interp: The program interpreter (ld-linux), set for executables.
        needed: DT_NEEDED sonames, in file order.
        verneed: Library file name (as in DT_NEEDED) -> version names required
            from it, such as {"libc.so.6": {"GLIBC_2.34"}}.
        verdef: Version names this object defines (GLIBC_2.34 for libc.so.6).
        undefined_symbols: Dynamic symbols it imports; filled only when
            read_elf() is called with want_symbols=True.
        defines_xlib: It defines XOpenDisplay itself, holding a copy of Xlib
            linked in statically (see XLIB_ENTRY); also only with want_symbols.
        copies_qt_app: It defines QCoreApplication::self, Qt's pointer to the
            application object, as a copy of its own (see QT_APP_SELF); also only
            with want_symbols.
        defines_harfbuzz: It exports HarfBuzz's functions (HARFBUZZ_ENTRY), holding
            a copy of HarfBuzz linked in statically; also only with want_symbols.
        nodeflib: Its DT_FLAGS_1 has DF_1_NODEFLIB: the loader looks for its
            libraries nowhere but in its own paths (see clear_nodeflib).
        pie: Its DT_FLAGS_1 has DF_1_PIE, which the linker sets only on a
            position-independent program, never on a library.
        defined_symbols: The dynamic symbols it defines (exports); filled only when
            read_elf() is called with want_defined=True, else None.
    """
    path: str
    machine: str
    elf_type: int
    bits: int
    interp: str | None = None
    soname: str | None = None
    needed: list[str] = field(default_factory=list)
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    verneed: dict[str, set[str]] = field(default_factory=dict)
    verdef: set[str] = field(default_factory=set)
    undefined_symbols: set[str] = field(default_factory=set)
    defined_symbols: set[str] | None = None
    defines_xlib: bool = False
    copies_qt_app: bool = False
    defines_harfbuzz: bool = False
    nodeflib: bool = False
    pie: bool = False

    @property
    def is_executable(self) -> bool:
        """True for programs: they have an interpreter, or are ET_EXEC, or are marked as PIE programs.

        A static-pie program has no interpreter and is ET_DYN like a library:
        soar's tarball holds one such Rust program and nothing else, and
        convert found no program in it to start.
        """
        return self.interp is not None or self.elf_type == ET_EXEC or self.pie

    @property
    def is_shared_library(self) -> bool:
        """True for shared libraries. PIE executables are also ET_DYN, so the interpreter (or DF_1_PIE) decides."""
        return self.elf_type == ET_DYN and self.interp is None and not self.pie


def is_elf(path: str | Path) -> bool:
    """Return True if path starts with the ELF magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except (OSError, IsADirectoryError):
        return False


# Settings only sharun reads. Its static launcher is copied (or hard-linked) in place of
# every program of a sharun AppDir, as AppRun too, and finds the real program in
# shared/bin by the name it was started as.
SHARUN_MARKERS = (b"SHARUN_EXTRA_LIBRARY_PATH", b"SHARUN_LDNAME")
SHARUN_MAX_SIZE = 16 << 20


def is_sharun(path: str | Path) -> bool:
    """Return True if path is sharun's launcher (or a copy of it), not a real program."""
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > SHARUN_MAX_SIZE:
            return False
        with open(p, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return m[:4] == ELF_MAGIC and all(m.find(k) != -1 for k in SHARUN_MARKERS)
    except (OSError, ValueError):
        return False


def _cstr(buf, off: int) -> str:
    """Read a NUL-terminated string at off."""
    end = buf.find(b"\0", off)
    if end < 0:
        end = len(buf)
    return bytes(buf[off:end]).decode("utf-8", "replace")


def read_elf(path: str | Path, want_symbols: bool = True, want_defined: bool = False) -> ElfInfo:
    """Read the dynamic-linking information of an ELF file.

    Args:
        path: The file.
        want_symbols: Also collect undefined dynamic symbols, which costs a
            pass over the symbol table.
        want_defined: Also collect the dynamic symbols it defines (defined_symbols).

    Raises:
        ElfError: The file is empty, truncated or malformed.
    """
    path = str(path)
    with open(path, "rb") as f:
        try:
            buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError as e:  # empty file
            raise ElfError(f"{path}: {e}") from e
        try:
            return _parse(path, buf, want_symbols or want_defined, want_defined)
        except (struct.error, IndexError, ValueError, OverflowError) as e:
            raise ElfError(f"{path}: truncated or malformed ELF ({e})") from e
        finally:
            buf.close()


def read_elf_bytes(data: bytes, name: str = "<data>", want_symbols: bool = True) -> ElfInfo:
    """Like read_elf, for a file already in memory.

    Raises:
        ElfError: The data is empty, truncated or malformed.
    """
    try:
        return _parse(name, data, want_symbols)
    except (struct.error, IndexError, ValueError, OverflowError) as e:
        raise ElfError(f"{name}: truncated or malformed ELF ({e})") from e


def _parse(path: str, m, want_symbols: bool, want_defined: bool = False) -> ElfInfo:
    """Parse a mapped ELF file: interpreter, dynamic entries, version tables and dynamic symbols.

    The dynamic section is found through the section headers, or through the
    PT_DYNAMIC segment when a file has none (stripped section headers are
    common in vendor binaries).

    Raises:
        ElfError: Not an ELF file, or an ELF class or byte order debpak doesn't know.
    """
    if m[:4] != ELF_MAGIC:
        raise ElfError(f"{path}: not an ELF file")
    ei_class, ei_data = m[4], m[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ElfError(f"{path}: unsupported ELF class/encoding")
    bits = 64 if ei_class == 2 else 32
    e = "<" if ei_data == 1 else ">"

    if bits == 64:
        (e_type, e_machine, _ver, _entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", m, 16)
    else:
        (e_type, e_machine, _ver, _entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", m, 16)

    info = ElfInfo(path=path, machine=MACHINES.get(e_machine, f"machine-{e_machine}"),
                   elf_type=e_type, bits=bits)
    if want_defined:
        info.defined_symbols = set()

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
        if any(t == DT_FLAGS_1 and v & DF_1_NODEFLIB for t, v in entries):
            info.nodeflib = True
        if any(t == DT_FLAGS_1 and v & DF_1_PIE for t, v in entries):
            info.pie = True
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


def _vaddr_to_offset(loads, vaddr: int) -> int | None:
    """Map a virtual address to a file offset using the PT_LOAD segments."""
    for p_vaddr, p_offset, p_filesz in loads:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


def _parse_verneed(m, e: str, off: int, count: int, strtab: int, info: ElfInfo) -> None:
    """Add the SHT_GNU_verneed entries (versions required per library) to info.verneed."""
    for _ in range(count):
        _vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(e + "HHIII", m, off)
        lib = _cstr(m, strtab + vn_file)
        versions = info.verneed.setdefault(lib, set())
        aoff = off + vn_aux
        for _ in range(vn_cnt):
            _hash, _flags, _other, vna_name, vna_next = struct.unpack_from(e + "IHHII", m, aoff)
            versions.add(_cstr(m, strtab + vna_name))
            if not vna_next:
                break
            aoff += vna_next
        if not vn_next:
            break
        off += vn_next


def _parse_verdef(m, e: str, off: int, count: int, strtab: int, info: ElfInfo) -> None:
    """Add the SHT_GNU_verdef entries (versions this object defines) to info.verdef, skipping the base version."""
    for _ in range(count):
        _ver, vd_flags, _ndx, vd_cnt, _hash, vd_aux, vd_next = struct.unpack_from(e + "HHHHIII", m, off)
        if vd_cnt and not vd_flags & VER_FLG_BASE:
            vda_name, _vda_next = struct.unpack_from(e + "II", m, off + vd_aux)
            info.verdef.add(_cstr(m, strtab + vda_name))
        if not vd_next:
            break
        off += vd_next


# Xlib's first function. A library other than libX11 that defines it has Xlib linked in: the
# libpython3.8 of python-appimage's builds (Mu Editor's AppImage) carries Tk with an old static Xlib
XLIB_ENTRY = b"XOpenDisplay\0"
# QCoreApplication::self, which a program built without -fPIC against a Qt whose headers read it
# inline (qApp) holds a copy of (a copy relocation)
QT_APP_SELF = b"_ZN16QCoreApplication4selfE\0"
# HarfBuzz's first function, which every build of it has. A program other than libharfbuzz that
# exports it carries its own HarfBuzz (old Electron and Chromium do; see hide_harfbuzz)
HARFBUZZ_ENTRY = b"hb_buffer_create\0"


def _parse_undefined(m, e: str, bits: int, off: int, size: int, strtab: int, info: ElfInfo) -> None:
    """Add the undefined symbols (st_shndx == SHN_UNDEF) of a dynamic symbol table to info, and note
    whether it defines XLIB_ENTRY, QT_APP_SELF or HARFBUZZ_ENTRY."""
    if bits == 64:
        sym = struct.Struct(e + "IBBHQQ")
        fields = ((st_name, st_shndx) for st_name, _i, _o, st_shndx, _v, _s
                  in (sym.unpack_from(m, off + j * sym.size) for j in range(size // sym.size)))
    else:
        sym = struct.Struct(e + "IIIBBH")
        fields = ((st_name, st_shndx) for st_name, _v, _s, _i, _o, st_shndx
                  in (sym.unpack_from(m, off + j * sym.size) for j in range(size // sym.size)))
    for st_name, st_shndx in fields:
        if not st_name:
            continue
        if st_shndx == 0:
            info.undefined_symbols.add(_cstr(m, strtab + st_name))
            continue
        if info.defined_symbols is not None and st_shndx != 0xfff1:     # not SHN_ABS (version names)
            info.defined_symbols.add(_cstr(m, strtab + st_name))
        if m[strtab + st_name:strtab + st_name + len(XLIB_ENTRY)] == XLIB_ENTRY:
            info.defines_xlib = True
        elif m[strtab + st_name:strtab + st_name + len(QT_APP_SELF)] == QT_APP_SELF:
            info.copies_qt_app = True
        elif m[strtab + st_name:strtab + st_name + len(HARFBUZZ_ENTRY)] == HARFBUZZ_ENTRY:
            info.defines_harfbuzz = True


_VERSION_RE = re.compile(r"^([A-Z]+)_(\d+(?:\.\d+)*)$")


def version_key(name: str) -> tuple[str, tuple[int, ...]] | None:
    """Split a symbol version name for sorting: 'GLIBC_2.34' -> ('GLIBC', (2, 34)); None if not numeric."""
    mt = _VERSION_RE.match(name)
    if not mt:
        return None
    return mt.group(1), tuple(int(x) for x in mt.group(2).split("."))


def max_version(names, family: str) -> str | None:
    """Return the highest version name of one family in names, such as GLIBC_2.38, or None."""
    best = None
    for n in names:
        k = version_key(n)
        if k and k[0] == family and (best is None or k[1] > best[1]):
            best = (n, k[1])
    return best[0] if best else None


# the loaders the runtime has, by machine
STANDARD_INTERP = {"x86_64": "/lib64/ld-linux-x86-64.so.2", "aarch64": "/lib/ld-linux-aarch64.so.1",
                   "i386": "/lib/ld-linux.so.2"}


def set_interpreter(path, new: str) -> bool:
    """Point an ELF program's PT_INTERP at new, in place; False if it has none or new doesn't fit.

    The interpreter string can only be replaced by one no longer than it (the
    rest is filled with NULs): enough to turn a classic snap's
    /snap/core22/current/lib64/ld-linux-x86-64.so.2 into /lib64/ld-linux-x86-64.so.2.
    """
    with open(path, "r+b") as f:
        head = f.read(64)
        if head[:4] != ELF_MAGIC:
            return False
        bits = 64 if head[4] == 2 else 32
        e = "<" if head[5] == 1 else ">"
        if bits == 64:
            e_phoff, = struct.unpack_from(e + "Q", head, 32)
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", head, 54)
        else:
            e_phoff, = struct.unpack_from(e + "I", head, 28)
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", head, 42)
        for i in range(e_phnum):
            f.seek(e_phoff + i * e_phentsize)
            ph = f.read(e_phentsize)
            if bits == 64:
                p_type, _pf, p_offset, _va, _pa, p_filesz = struct.unpack_from(e + "IIQQQQ", ph)
            else:
                p_type, p_offset, _va, _pa, p_filesz = struct.unpack_from(e + "IIIII", ph)
            if p_type != PT_INTERP:
                continue
            return _write_interpreter(f, p_offset, p_filesz, new)
    return False


def _write_interpreter(f, p_offset: int, p_filesz: int, new: str) -> bool:
    """Write new, NUL-padded, over the loader path at p_offset; False if it doesn't fit.

    Only the old path and the NULs after it inside the segment are overwritten. The
    header's p_filesz isn't trusted on its own: a damaged one far larger than the path
    had the padding zero the rest of the program, or grow the file by gigabytes.
    """
    f.seek(0, os.SEEK_END)
    room = _interpreter_room(f, p_offset, min(p_filesz, max(f.tell() - p_offset, 0), 4096))
    data = new.encode() + b"\0"
    if len(data) > room:
        return False
    f.seek(p_offset)
    f.write(data.ljust(room, b"\0"))
    return True


def _interpreter_room(f, p_offset: int, size: int) -> int:
    """Return how many bytes from p_offset hold the loader path and the NULs that follow it (0 if unterminated)."""
    f.seek(p_offset)
    seg = f.read(size)
    end = seg.find(b"\0")
    if end < 0:
        return 0
    return len(seg) - len(seg[end:].lstrip(b"\0"))


def clear_nodeflib(path) -> bool:
    """Take DF_1_NODEFLIB out of an ELF file's DT_FLAGS_1, in place; False if it wasn't set.

    snapcraft links a classic snap's programs with -z nodefaultlib, so that they
    find their libraries in the base snap (RUNPATH /snap/core24/current/lib/...)
    and never in the host's. With the flag the loader passes over the runtime's
    /usr/lib, its ld.so.cache entries included, and MiniZinc's IDE stopped at
    "libpthread.so.0: cannot open shared object file", though the runtime has it.
    """
    with open(path, "r+b") as f:
        head = f.read(64)
        if len(head) < 52 or head[:4] != ELF_MAGIC:
            return False
        bits = 64 if head[4] == 2 else 32
        e = "<" if head[5] == 1 else ">"
        if bits == 64:
            e_phoff, = struct.unpack_from(e + "Q", head, 32)
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", head, 54)
        else:
            e_phoff, = struct.unpack_from(e + "I", head, 28)
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", head, 42)
        entry = struct.Struct(e + ("qQ" if bits == 64 else "iI"))
        changed = False
        for i in range(e_phnum):
            f.seek(e_phoff + i * e_phentsize)
            ph = f.read(e_phentsize)
            if bits == 64:
                p_type, _pf, p_offset, _va, _pa, p_filesz = struct.unpack_from(e + "IIQQQQ", ph)
            else:
                p_type, p_offset, _va, _pa, p_filesz = struct.unpack_from(e + "IIIII", ph)
            if p_type != PT_DYNAMIC:
                continue
            f.seek(p_offset)
            dyn = f.read(p_filesz)
            for j in range(len(dyn) // entry.size):
                tag, val = entry.unpack_from(dyn, j * entry.size)
                if tag == DT_NULL:
                    break
                if tag == DT_FLAGS_1 and val & DF_1_NODEFLIB:
                    f.seek(p_offset + j * entry.size)
                    f.write(entry.pack(tag, val & ~DF_1_NODEFLIB))
                    changed = True
        return changed


SHN_ABS = 0xFFF1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
STT_OBJECT, STT_FUNC = 1, 2


def fix_absolute_symbols(path) -> int:
    """Give a shared library's functions marked absolute back their section, in place; return how many.

    LLD 5, which built Electron 2's libnode.so and libffmpeg.so, wrote some
    exported functions with the section index SHN_ABS (1361 in libnode.so).
    glibc before 2.28 added the library's load address to such a symbol all
    the same, but later ones take an absolute symbol at its word (glibc bug
    19818), so a call to nghttp2_session_callbacks_set_on_frame_recv_callback
    jumped to 0xe6e0c0 itself: PlayMe, Bodhi and React Proto crashed at start
    in libnode.so's constructors. A function (or object) whose value lies in
    one of the library's own code (or data) sections is the library's, so it
    gets that section's index, and the loader relocates it again.
    """
    with open(path, "r+b") as f:
        head = f.read(64)
        if len(head) < 52 or head[:4] != ELF_MAGIC:
            return 0
        bits = 64 if head[4] == 2 else 32
        e = "<" if head[5] == 1 else ">"
        e_type, = struct.unpack_from(e + "H", head, 16)
        if e_type != ET_DYN:
            return 0
        if bits == 64:
            e_shoff, = struct.unpack_from(e + "Q", head, 40)
            e_shentsize, e_shnum = struct.unpack_from(e + "HH", head, 58)
            sh_fmt, sym_fmt, sym_size = e + "IIQQQQIIQQ", e + "IBBHQQ", 24
        else:
            e_shoff, = struct.unpack_from(e + "I", head, 32)
            e_shentsize, e_shnum = struct.unpack_from(e + "HH", head, 46)
            sh_fmt, sym_fmt, sym_size = e + "IIIIIIIIII", e + "IIIBBH", 16
        if not e_shoff or not e_shnum:
            return 0                # no section headers: nothing to point at
        f.seek(e_shoff)
        raw = f.read(e_shentsize * e_shnum)
        if len(raw) < e_shentsize * e_shnum:
            return 0
        sections = []
        for i in range(e_shnum):
            _n, sh_type, sh_flags, sh_addr, sh_offset, sh_size, *_ = struct.unpack_from(sh_fmt, raw, i * e_shentsize)
            sections.append((sh_type, sh_flags, sh_addr, sh_offset, sh_size))
        fixed = 0
        for sh_type, _fl, _ad, sh_offset, sh_size in sections:
            if sh_type != SHT_DYNSYM:
                continue
            f.seek(sh_offset)
            table = bytearray(f.read(sh_size))
            for off in range(0, len(table) - sym_size + 1, sym_size):
                if bits == 64:
                    _name, st_info, _other, shndx, value, _size = struct.unpack_from(sym_fmt, table, off)
                    ndx_at = off + 6
                else:
                    _name, value, _size, st_info, _other, shndx = struct.unpack_from(sym_fmt, table, off)
                    ndx_at = off + 14
                kind = st_info & 0xF
                if shndx != SHN_ABS or not value or kind not in (STT_OBJECT, STT_FUNC):
                    continue
                want = SHF_ALLOC | (SHF_EXECINSTR if kind == STT_FUNC else 0)
                home = next((i for i, (_t, fl, addr, _o, size) in enumerate(sections)
                             if fl & want == want and addr <= value < addr + size), None)
                if home is None:
                    continue
                struct.pack_into(e + "H", table, ndx_at, home)
                fixed += 1
            if fixed:
                f.seek(sh_offset)
                f.write(table)
        return fixed


STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2


def hide_harfbuzz(path) -> int:
    """Make the HarfBuzz functions a program exports its own, in place; return how many it exported.

    SEO Manager's AppImage runs Electron 1.7, whose program has HarfBuzz linked in
    and exports its 299 hb_ functions. A program's exports come first for every
    library, so the runtime's libharfbuzz, which Pango loads for GTK, found its own
    calls to hb_face_reference_table bound to Electron's older HarfBuzz, and the
    app crashed as GTK measured its first text (Pango 1.44 and later reach
    HarfBuzz this way; the Ubuntu 18.04 the app was built for had an older Pango).
    Each hb_ entry of the dynamic symbol table is made local: the loader then
    passes over it when it binds another file's calls, and binds the program's own
    references to it to the program itself, as before.
    """
    with open(path, "r+b") as f:
        head = f.read(64)
        if len(head) < 52 or head[:4] != ELF_MAGIC:
            return 0
        bits = 64 if head[4] == 2 else 32
        e = "<" if head[5] == 1 else ">"
        if bits == 64:
            e_shoff, = struct.unpack_from(e + "Q", head, 40)
            e_shentsize, e_shnum = struct.unpack_from(e + "HH", head, 58)
            sh_fmt, sym_fmt, sym_size, info_at = e + "IIQQQQIIQQ", e + "IBBHQQ", 24, 4
        else:
            e_shoff, = struct.unpack_from(e + "I", head, 32)
            e_shentsize, e_shnum = struct.unpack_from(e + "HH", head, 46)
            sh_fmt, sym_fmt, sym_size, info_at = e + "IIIIIIIIII", e + "IIIBBH", 16, 12
        if not e_shoff or not e_shnum:
            return 0
        f.seek(e_shoff)
        raw = f.read(e_shentsize * e_shnum)
        if len(raw) < e_shentsize * e_shnum:
            return 0
        sections = [struct.unpack_from(sh_fmt, raw, i * e_shentsize) for i in range(e_shnum)]
        hidden = 0
        for s in sections:
            if s[1] != SHT_DYNSYM or s[6] >= len(sections):
                continue
            strtab = sections[s[6]]
            f.seek(strtab[4])
            names = f.read(strtab[5])
            f.seek(s[4])
            table = bytearray(f.read(s[5]))
            for off in range(0, len(table) - sym_size + 1, sym_size):
                if bits == 64:
                    st_name, st_info, _o, shndx, _v, _s = struct.unpack_from(sym_fmt, table, off)
                else:
                    st_name, _v, _s, st_info, _o, shndx = struct.unpack_from(sym_fmt, table, off)
                if not shndx or st_info >> 4 not in (STB_GLOBAL, STB_WEAK) or not names.startswith(b"hb_", st_name):
                    continue
                table[off + info_at] = STB_LOCAL << 4 | st_info & 0xF
                hidden += 1
            if hidden:
                f.seek(s[4])
                f.write(table)
        return hidden


SHT_GNU_VERSYM = 0x6FFFFFFF

# libm functions that glibc 2.43 and 2.44 gave a new symbol version only to move the SVID error
# handling (a matherr the program defines, the _LIB_VERSION switch) out of the way of the fast
# path: "The SVID handling for acosf, ... was moved to compat symbols, allowing improvements in
# performance" (glibc 2.43 NEWS). A program linked against glibc 2.27 or later can't turn SVID
# handling on, so the older versions of these functions give it the same results and the same
# errno. fromfp and its kin are left out: at 2.43 they changed their return type.
SVID_ONLY_LIBM = {
    "GLIBC_2.43": frozenset({"acosf", "acoshf", "asinf", "atan2f", "atanhf", "coshf", "j0f", "j1f", "jnf",
                             "lgammaf", "lgammaf_r", "log10f", "remainder", "remainderf", "sinhf", "sqrtf",
                             "y0f", "y1f", "ynf", "tgammaf"}),
    "GLIBC_2.44": frozenset({"cosh", "sinh"}),
}
# the version every function above has had since libm's first release for the machine
LIBM_BASE_VERSION = {"x86_64": "GLIBC_2.2.5", "aarch64": "GLIBC_2.17", "i386": "GLIBC_2.0"}


def _elf_hash(name: bytes) -> int:
    h = 0
    for c in name:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


def _libm_version_plan(data, versions: set[str]):
    """Return how to lower the libm versions named in versions, or None when it can't be done soundly.

    The plan is (endian, base name offset in .dynstr, base hash, [file offset of each
    Vernaux entry to rewrite]). Every dynamic symbol bound to one of the versions
    must be one SVID_ONLY_LIBM lists for it, and the base version's name must be in
    .dynstr already (it nearly always is: the program needs libc at it too).
    """
    if data[:4] != ELF_MAGIC or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    bits = 64 if data[4] == 2 else 32
    e = "<" if data[5] == 1 else ">"
    if bits == 64:
        e_machine, = struct.unpack_from(e + "H", data, 18)
        e_shoff, = struct.unpack_from(e + "Q", data, 40)
        e_shentsize, e_shnum = struct.unpack_from(e + "HH", data, 58)
        sh_fmt, sym_fmt, sym_size = e + "IIQQQQIIQQ", e + "IBBHQQ", 24
    else:
        e_machine, = struct.unpack_from(e + "H", data, 18)
        e_shoff, = struct.unpack_from(e + "I", data, 32)
        e_shentsize, e_shnum = struct.unpack_from(e + "HH", data, 46)
        sh_fmt, sym_fmt, sym_size = e + "IIIIIIIIII", e + "IIIBBH", 16
    base = LIBM_BASE_VERSION.get(MACHINES.get(e_machine, ""))
    if not base or not e_shoff or not e_shnum or e_shoff + e_shnum * e_shentsize > len(data):
        return None
    secs = [struct.unpack_from(sh_fmt, data, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    by_type: dict[int, tuple] = {}
    for s in secs:
        by_type.setdefault(s[1], s)
    dynsym, versym, verneed = by_type.get(SHT_DYNSYM), by_type.get(SHT_GNU_VERSYM), by_type.get(SHT_GNU_VERNEED)
    if not dynsym or not versym or not verneed or dynsym[6] >= len(secs) or verneed[6] != dynsym[6]:
        return None
    strtab = secs[dynsym[6]][4]
    strsize = secs[dynsym[6]][5]
    # the Vernaux entries of libm.so.6 for the versions, by version index
    targets: dict[int, tuple[str, int]] = {}
    off, count = verneed[4], verneed[7]
    for _ in range(count):
        _v, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(e + "HHIII", data, off)
        lib = _cstr(data, strtab + vn_file)
        aoff = off + vn_aux
        for _ in range(vn_cnt):
            _h, _fl, other, vna_name, vna_next = struct.unpack_from(e + "IHHII", data, aoff)
            name = _cstr(data, strtab + vna_name)
            if lib == "libm.so.6" and name in versions:
                targets[other & 0x7FFF] = (name, aoff)
            if not vna_next:
                break
            aoff += vna_next
        if not vn_next:
            break
        off += vn_next
    if {n for n, _ in targets.values()} != set(versions):
        return None
    nsyms = dynsym[5] // sym_size
    for i in range(1, nsyms):
        ndx, = struct.unpack_from(e + "H", data, versym[4] + 2 * i)
        if (ndx & 0x7FFF) not in targets:
            continue
        st_name = struct.unpack_from(sym_fmt, data, dynsym[4] + i * sym_size)[0]
        if _cstr(data, strtab + st_name) not in SVID_ONLY_LIBM.get(targets[ndx & 0x7FFF][0], ()):
            return None
    want = base.encode() + b"\0"
    table = bytes(data[strtab:strtab + strsize])
    at = table.find(b"\0" + want)
    if at < 0:
        return None
    return e, at + 1, _elf_hash(base.encode()), [aoff for _n, aoff in targets.values()]


def libm_versions_lowerable(path, versions: set[str]) -> bool:
    """Whether lower_libm_versions() can take the versions in versions off a file's libm needs."""
    if not versions or not set(versions) <= set(SVID_ONLY_LIBM):
        return False
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return _libm_version_plan(m, set(versions)) is not None
    except (OSError, ValueError, struct.error, IndexError):
        return False


def lower_libm_versions(path, versions: set[str]) -> bool:
    """Bind a program's calls to libm functions at versions (GLIBC_2.43, ...) to their older versions, in place.

    ModelViewer-Qt, built on a glibc 2.43 system, needs libm.so.6 at GLIBC_2.43 for
    nothing but sqrtf, atan2f and the like (see SVID_ONLY_LIBM), and the KDE runtime's
    glibc is 2.42. The requirement's Vernaux entry is renamed to the base version of
    libm, so the loader binds those calls to the functions' older versions, which
    behave the same for such a program. Returns False, changing nothing, when
    another function is bound to one of the versions.
    """
    with open(path, "r+b") as f:
        data = f.read()
        try:
            plan = _libm_version_plan(data, set(versions))
        except (struct.error, IndexError):
            plan = None
        if plan is None:
            return False
        e, name_off, h, entries = plan
        for aoff in entries:
            f.seek(aoff)
            f.write(struct.pack(e + "I", h))
            f.seek(aoff + 8)
            f.write(struct.pack(e + "I", name_off))
    return True


# the start of a 64-bit little-endian Go function table (runtime.pcHeader): the magic of Go 1.18-1.19
# (0xfffffff0) or of Go 1.20 and later (0xfffffff1), two zero pad bytes, minLC 1 and ptrSize 8
GO_PCLNTAB_HEAD = re.compile(rb"[\xf0\xf1]\xff\xff\xff\x00\x00\x01\x08", re.S)


def _go_loads(data) -> list[tuple[int, int, int]]:
    """Return the (vaddr, offset, filesz) of a 64-bit little-endian ELF file's PT_LOAD segments."""
    if data[:4] != ELF_MAGIC or data[4] != 2 or data[5] != 1:
        return []
    e_phoff, = struct.unpack_from("<Q", data, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    loads = []
    for i in range(e_phnum):
        p_type, _pf, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from("<IIQQQQ", data, e_phoff + i * e_phentsize)
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
    return loads


def go_functions(data, wanted: set[str]) -> dict[str, int]:
    """Return the file offset of the code of each function named in wanted that a Go program has.

    Go 1.18 and later keep a table of every function, its name and where its code
    starts (runtime.pclntab), even in a program stripped of its symbols, as Wails
    builds its apps (ProKZee). data is the program's bytes; a name is the function's
    full name, e.g. github.com/wailsapp/wails/v2/internal/frontend/desktop/linux.processMenu.
    Only 64-bit little-endian programs (x86-64, aarch64) are read.
    """
    loads = _go_loads(data)
    if not loads or not wanted:
        return {}
    want = {n.encode(): n for n in wanted}
    found: dict[str, int] = {}
    for m in GO_PCLNTAB_HEAD.finditer(data):
        base = m.start()
        try:
            nfunc, _nfiles, text, nameoff, _cu, _filetab, _pctab, funcoff = struct.unpack_from("<QQQQQQQQ", data,
                                                                                                base + 8)
            if not 0 < nfunc < 10_000_000 or funcoff > len(data) - base or nameoff > len(data) - base:
                continue
            names = base + nameoff
            tab = base + funcoff
            for i in range(nfunc):
                entry, fo = struct.unpack_from("<II", data, tab + 8 * i)
                f_entry, f_name = struct.unpack_from("<Ii", data, tab + fo)
                if f_entry != entry or f_name < 0:
                    break           # not a function table after all
                start = names + f_name
                name = bytes(data[start:data.index(b"\0", start)])
                if name in want and want[name] not in found:
                    off = _vaddr_to_offset(loads, text + entry)
                    if off is not None:
                        found[want[name]] = off
                        if len(found) == len(want):
                            return found
        except (struct.error, ValueError, IndexError):
            continue
        if found:
            return found
    return found


def stub_go_functions(path, names: set[str]) -> list[str]:
    """Make the Go functions named return as soon as they're called, in place; return those changed.

    The function's first instruction becomes a return (x86-64's ret): for a
    function with no results that crashes the app over something it can do
    without. Wails 2.9 builds the menu bar of a Linux window in processMenu, which
    dies on a menu item of a role (an Edit or App menu, which only macOS fills in)
    that has no submenu: ProKZee panicked with a nil pointer as it started, and with
    processMenu returning at once it opens with no menu bar. Only x86-64 programs
    are changed.
    """
    with open(path, "r+b") as f:
        data = f.read()
        if len(data) < 64 or data[:4] != ELF_MAGIC or struct.unpack_from("<H", data, 18)[0] != 62:
            return []
        done = []
        for name, off in sorted(go_functions(data, set(names)).items()):
            f.seek(off)
            f.write(b"\xc3")
            done.append(name)
    return done
