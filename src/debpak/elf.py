"""Minimal, dependency-free ELF reader.

Reads what debpak needs from a binary or shared library:
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
    """A file that isn't a readable ELF object."""
    pass


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

    @property
    def is_executable(self) -> bool:
        """True for programs: they have an interpreter, or are ET_EXEC."""
        return self.interp is not None or self.elf_type == ET_EXEC

    @property
    def is_shared_library(self) -> bool:
        """True for shared libraries. PIE executables are also ET_DYN, so the interpreter decides."""
        return self.elf_type == ET_DYN and self.interp is None


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


def read_elf(path: str | Path, want_symbols: bool = True) -> ElfInfo:
    """Read the dynamic-linking information of an ELF file.

    Args:
        path: The file.
        want_symbols: Also collect undefined dynamic symbols, which costs a
            pass over the symbol table.

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
            return _parse(path, buf, want_symbols)
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


def _parse(path: str, m, want_symbols: bool) -> ElfInfo:
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


def _parse_undefined(m, e: str, bits: int, off: int, size: int, strtab: int, info: ElfInfo) -> None:
    """Add the undefined symbols (st_shndx == SHN_UNDEF) of a dynamic symbol table to info."""
    if bits == 64:
        sym = struct.Struct(e + "IBBHQQ")
        for j in range(size // sym.size):
            st_name, _info, _other, st_shndx, _v, _s = sym.unpack_from(m, off + j * sym.size)
            if st_shndx == 0 and st_name:
                info.undefined_symbols.add(_cstr(m, strtab + st_name))
    else:
        sym = struct.Struct(e + "IIIBBH")
        for j in range(size // sym.size):
            st_name, _v, _s, _info, _other, st_shndx = sym.unpack_from(m, off + j * sym.size)
            if st_shndx == 0 and st_name:
                info.undefined_symbols.add(_cstr(m, strtab + st_name))


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
            data = new.encode() + b"\0"
            if len(data) > p_filesz:
                return False
            f.seek(p_offset)
            f.write(data + b"\0" * (p_filesz - len(data)))
            return True
    return False


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
