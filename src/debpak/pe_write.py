"""Minimal PE image writer.

Used to generate stub DLLs: a DLL that exports the requested names so the
Windows/Wine loader can resolve an app's static imports. Each stub either
returns 0 ("zero") or executes a trap instruction ("trap") so an unexpected
call fails loudly instead of silently corrupting state.

32-bit x86 stubs are always "trap": stdcall functions pop their own
arguments, and the argument size isn't knowable from an import table, so a
returning stub would corrupt the stack.

The same writer can also emit import tables (used by the test-suite to
produce realistic executables without a Windows toolchain).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

MACHINE_CODES = {"x86_64": 0x8664, "i386": 0x14C, "arm64": 0xAA64}

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

# per-arch machine code snippets (little endian)
DLLMAIN = {
    "x86_64": bytes.fromhex("b801000000c3"),          # mov eax,1 ; ret
    "i386": bytes.fromhex("b801000000c20c00"),        # mov eax,1 ; ret 12 (stdcall, 3 args)
    "arm64": struct.pack("<II", 0x52800020, 0xD65F03C0),  # mov w0,#1 ; ret
}
STUB_ZERO = {
    "x86_64": bytes.fromhex("31c0c3"),                # xor eax,eax ; ret
    "arm64": struct.pack("<II", 0x52800000, 0xD65F03C0),  # mov w0,#0 ; ret
}
STUB_TRAP = {
    "x86_64": bytes.fromhex("0f0b"),                  # ud2
    "i386": bytes.fromhex("0f0b"),                    # ud2
    "arm64": struct.pack("<I", 0xD4200000),           # brk #0
}


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


@dataclass
class _Section:
    name: bytes
    data: bytearray
    characteristics: int
    rva: int = 0


@dataclass
class PeSpec:
    arch: str = "x86_64"
    is_dll: bool = True
    dll_name: str | None = None
    exports: list[str] = field(default_factory=list)          # exported names
    export_ordinals: list[int] = field(default_factory=list)  # ordinal-only exports
    imports: dict[str, list[str | int]] = field(default_factory=dict)        # dll -> names / ordinals
    delay_imports: dict[str, list[str | int]] = field(default_factory=dict)
    stub_mode: str = "zero"
    dotnet: bool = False
    subsystem: int = 2


def build_pe(spec: PeSpec) -> bytes:
    if spec.arch not in MACHINE_CODES:
        raise ValueError(f"unsupported arch {spec.arch}")
    pe64 = spec.arch != "i386"
    ptr = 8 if pe64 else 4
    image_base = 0x180000000 if pe64 else 0x10000000

    # ---- .text: DllMain/entry + one stub per export
    text = bytearray(DLLMAIN[spec.arch])
    mode = "trap" if spec.arch == "i386" else spec.stub_mode
    stub = (STUB_TRAP if mode == "trap" else STUB_ZERO)[spec.arch]
    export_names = sorted(set(spec.exports))        # name table must be sorted for binary search
    ordinal_only = sorted(set(spec.export_ordinals))
    stub_offsets: list[int] = []
    for _ in range(len(export_names) + len(ordinal_only)):
        while len(text) % 16:
            text.append(0xCC if spec.arch != "arm64" else 0)
        stub_offsets.append(len(text))
        text += stub
    sections = [_Section(b".text", text, 0x60000020)]

    # ---- layout RVAs
    rva = SECT_ALIGN
    sections[0].rva = rva
    rva += _align(len(text), SECT_ALIGN)

    edata_rva = idata_rva = didata_rva = clr_rva = 0
    edata = idata = None
    if export_names or ordinal_only:
        edata_rva = rva
        edata = _build_exports(spec, export_names, ordinal_only, stub_offsets, sections[0].rva, edata_rva)
        sections.append(_Section(b".edata", edata, 0x40000040, edata_rva))
        rva += _align(len(edata), SECT_ALIGN)
    import_dir = delay_dir = (0, 0)
    if spec.imports or spec.delay_imports or spec.dotnet:
        idata_rva = rva
        idata, import_dir, delay_dir, clr_dir = _build_imports(spec, ptr, idata_rva)
        sections.append(_Section(b".idata", idata, 0xC0000040, idata_rva))
        rva += _align(len(idata), SECT_ALIGN)
    else:
        clr_dir = (0, 0)
    size_of_image = rva

    # ---- headers
    nsec = len(sections)
    opt_size = 240 if pe64 else 224
    pe_off = 0x80
    headers_size = _align(pe_off + 24 + opt_size + 40 * nsec, FILE_ALIGN)

    dirs = [(0, 0)] * 16
    if edata is not None:
        dirs[0] = (edata_rva, len(edata))
    dirs[1] = import_dir
    dirs[13] = delay_dir
    dirs[14] = clr_dir

    characteristics = 0x0002 | (0x2000 if spec.is_dll else 0) | (0x0020 if pe64 else 0x0100)
    coff = struct.pack("<HHIIIHH", MACHINE_CODES[spec.arch], nsec, 0, 0, 0, opt_size, characteristics)
    size_code = _align(len(text), FILE_ALIGN)
    size_idata = sum(_align(len(s.data), FILE_ALIGN) for s in sections[1:])
    entry = sections[0].rva
    dllchar = 0x0140 | (0x0020 if pe64 else 0)  # DYNAMIC_BASE | NX_COMPAT (| HIGH_ENTROPY_VA)
    if pe64:
        opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, size_code, size_idata, 0, entry, sections[0].rva)
        opt += struct.pack("<QIIHHHHHHIIIIHHQQQQII", image_base, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
                           size_of_image, headers_size, 0, spec.subsystem, dllchar,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        opt = struct.pack("<HBBIIIIII", 0x10B, 14, 0, size_code, size_idata, 0, entry, sections[0].rva, 0)
        opt += struct.pack("<IIIHHHHHHIIIIHHIIIIII", image_base, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
                           size_of_image, headers_size, 0, spec.subsystem, dllchar,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    assert len(opt) == opt_size

    out = bytearray(headers_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, pe_off)
    out[pe_off:pe_off + 4] = b"PE\0\0"
    out[pe_off + 4:pe_off + 24] = coff
    out[pe_off + 24:pe_off + 24 + opt_size] = opt
    sh = pe_off + 24 + opt_size
    raw = headers_size
    for s in sections:
        rawsize = _align(len(s.data), FILE_ALIGN)
        out[sh:sh + 40] = struct.pack("<8sIIIIIIHHI", s.name, len(s.data), s.rva, rawsize, raw, 0, 0, 0, 0,
                                      s.characteristics)
        sh += 40
        raw += rawsize
    for s in sections:
        out += s.data + bytes(_align(len(s.data), FILE_ALIGN) - len(s.data))
    return bytes(out)


def _build_exports(spec: PeSpec, names: list[str], ordinal_only: list[int], stub_offsets: list[int],
                   text_rva: int, base_rva: int) -> bytearray:
    n_named = len(names)
    # ordinals: named exports get 1..n unless that collides with requested ordinal-only exports
    taken = set(ordinal_only)
    named_ordinals = []
    nxt = 1
    for _ in names:
        while nxt in taken:
            nxt += 1
        named_ordinals.append(nxt)
        taken.add(nxt)
        nxt += 1
    all_ordinals = named_ordinals + ordinal_only
    base = min(all_ordinals) if all_ordinals else 1
    nfuncs = (max(all_ordinals) - base + 1) if all_ordinals else 0

    dll_name = (spec.dll_name or "stub.dll").encode() + b"\0"
    header = 40
    eat = header
    npt = eat + 4 * nfuncs
    ot = npt + 4 * n_named
    strings = ot + 2 * n_named
    blob = bytearray()
    name_rva = base_rva + strings
    blob += dll_name
    name_rvas = []
    for nm in names:
        name_rvas.append(base_rva + strings + len(blob))
        blob += nm.encode() + b"\0"

    out = bytearray(strings) + blob
    struct.pack_into("<IIHHIIIIIII", out, 0, 0, 0, 0, 0, name_rva, base, nfuncs, n_named,
                     base_rva + eat, base_rva + npt, base_rva + ot)
    for i, ordinal in enumerate(all_ordinals):
        struct.pack_into("<I", out, eat + 4 * (ordinal - base), text_rva + stub_offsets[i])
    for i, nm_rva in enumerate(name_rvas):
        struct.pack_into("<I", out, npt + 4 * i, nm_rva)
        struct.pack_into("<H", out, ot + 2 * i, named_ordinals[i] - base)
    return out


