"""Minimal ELF files for tests: a header, PT_INTERP, one PT_LOAD over the file and a PT_DYNAMIC."""
import struct

MACHINE_CODES = {"x86_64": 62, "i386": 3, "aarch64": 183}
DT_NEEDED, DT_STRTAB, DT_SONAME = 1, 5, 14


def elf(machine: str = "x86_64", interp: str = "", needed=(), soname: str = "", etype: int = 0) -> bytes:
    """Return an ELF file for machine that names interp, links needed and is called soname.

    etype defaults to an executable (2) with an interpreter and a shared object (3) without.
    """
    bits = 32 if machine == "i386" else 64
    etype = etype or (2 if interp else 3)
    ehsize, phsize = (52, 32) if bits == 32 else (64, 56)
    phnum = 3 if interp else 2
    strtab = b"\0"
    offsets = {}
    for name in [*needed, soname]:
        if name and name not in offsets:
            offsets[name] = len(strtab)
            strtab += name.encode() + b"\0"
    interp_bytes = interp.encode() + b"\0" if interp else b""
    interp_off = ehsize + phnum * phsize
    strtab_off = interp_off + len(interp_bytes)
    dyn_off = (strtab_off + len(strtab) + 7) & ~7
    entries = [(DT_NEEDED, offsets[n]) for n in needed] + ([(DT_SONAME, offsets[soname])] if soname else [])
    entries += [(DT_STRTAB, strtab_off), (0, 0)]
    dyn = b"".join(struct.pack("<iI" if bits == 32 else "<qQ", t, v) for t, v in entries)
    total = dyn_off + len(dyn)
    if bits == 64:
        ehdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + struct.pack(
            "<HHIQQQIHHHHHH", etype, MACHINE_CODES[machine], 1, 0, ehsize, 0, 0, ehsize, phsize, phnum, 64, 0, 0)

        def ph(t, off, size):
            return struct.pack("<IIQQQQQQ", t, 4, off, off, off, size, size, 1)
    else:
        ehdr = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9) + struct.pack(
            "<HHIIIIIHHHHHH", etype, MACHINE_CODES[machine], 1, 0, ehsize, 0, 0, ehsize, phsize, phnum, 40, 0, 0)

        def ph(t, off, size):
            return struct.pack("<IIIIIIII", t, off, off, off, size, size, 4, 1)
    phdrs = (ph(3, interp_off, len(interp_bytes)) if interp else b"") + ph(1, 0, total) + ph(2, dyn_off, len(dyn))
    body = ehdr + phdrs + interp_bytes + strtab
    return body + bytes(dyn_off - len(body)) + dyn
