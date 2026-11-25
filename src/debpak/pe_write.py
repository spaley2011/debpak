"""Minimal PE image writer.

Used to generate stub DLLs: a DLL that exports the requested names so the
Windows/Wine loader can resolve an app's static imports. Each stub either
returns 0 ("zero") or executes a trap instruction ("trap"), which stops the
process at the stub before an unexpected call can corrupt anything.

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
    """Round n up to a multiple of a."""
    return (n + a - 1) // a * a


@dataclass
class _Section:
    """A section being built: name, contents, flags, and its RVA once laid out."""
    name: bytes
    data: bytearray
    characteristics: int
    rva: int = 0


@dataclass
class PeSpec:
    """What build_pe should produce.

    Attributes:
        exports: Names to export, each pointing at a stub.
        export_ordinals: Extra exports by ordinal only.
        imports, delay_imports: DLL name -> names or ordinals to import (the
            tests use these to build realistic executables).
        stub_mode: "zero" (return 0) or "trap" (stop the process). 32-bit x86
            always traps.
        dotnet: Add a CLR directory entry, so the file looks like a .NET assembly.
        type_refs: (namespace, name) of outside types the .NET assembly uses,
            written as metadata with a TypeRef table (needs dotnet).
        subsystem: 2 for a GUI program, 3 for a console program.
        resources: (type, id, data) resources for a .rsrc section, such as
            the output of version_info() and icon_resources().
    """
    arch: str = "x86_64"
    is_dll: bool = True
    dll_name: str | None = None
    exports: list[str] = field(default_factory=list)          # exported names
    export_ordinals: list[int] = field(default_factory=list)  # ordinal-only exports
    imports: dict[str, list[str | int]] = field(default_factory=dict)        # dll -> names / ordinals
    delay_imports: dict[str, list[str | int]] = field(default_factory=dict)
    stub_mode: str = "zero"
    dotnet: bool = False
    clr_flags: int = 1                      # COMIMAGE_FLAGS_ILONLY: a pure .NET assembly
    type_refs: list[tuple[str, str]] = field(default_factory=list)
    subsystem: int = 2
    resources: list[tuple[int, int, bytes]] = field(default_factory=list)   # (type, id, data)


def build_pe(spec: PeSpec) -> bytes:
    """Build a minimal, valid PE image from a PeSpec.

    Raises:
        ValueError: The architecture isn't in MACHINE_CODES.
    """
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
    rsrc_dir = (0, 0)
    if spec.resources:
        rsrc = _build_resources(spec.resources, rva)
        sections.append(_Section(b".rsrc", rsrc, 0x40000040, rva))
        rsrc_dir = (rva, len(rsrc))
        rva += _align(len(rsrc), SECT_ALIGN)
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
    dirs[2] = rsrc_dir
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
    """Build the export directory: one stub per export.

    Named exports get ordinals 1, 2, ... skipping any ordinal requested for an
    ordinal-only export, so both kinds can coexist.
    """
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


def _build_imports(spec: PeSpec, ptr: int, base_rva: int):
    """Build the import and delay-import tables; return (section bytes, import dir, delay import dir, clr dir)."""
    fmt = "<Q" if ptr == 8 else "<I"
    ordflag = (1 << 63) if ptr == 8 else (1 << 31)
    imports = dict(spec.imports)
    if spec.dotnet and "mscoree.dll" not in {k.lower() for k in imports}:
        imports["mscoree.dll"] = ["_CorExeMain" if not spec.is_dll else "_CorDllMain"]

    # plan: [import descriptors][delay descriptors][clr header][thunk tables][names]
    n_imp, n_delay = len(imports), len(spec.delay_imports)
    desc_size = 20 * (n_imp + 1) if imports else 0
    ddesc_size = 32 * (n_delay + 1) if spec.delay_imports else 0
    clr_size = 72 if spec.dotnet else 0
    cursor = desc_size + ddesc_size + clr_size
    buf = bytearray(cursor)
    strings = bytearray()
    thunk_blobs = []

    def table(entries) -> int:
        nonlocal cursor
        start = cursor
        thunk_blobs.append((start, entries))
        cursor += ptr * (len(entries) + 1)
        return start

    plan = []
    for dll, entries in imports.items():
        plan.append(("imp", dll, entries, table(entries), table(entries)))
    for dll, entries in spec.delay_imports.items():
        plan.append(("delay", dll, entries, table(entries), table(entries), cursor))
        cursor += ptr  # module handle slot
    str_base = cursor
    buf += bytearray(cursor - len(buf))

    def add_str(b: bytes) -> int:
        off = str_base + len(strings)
        strings.extend(b)
        if len(strings) % 2:
            strings.append(0)
        return off

    name_offsets: dict[tuple[str, str], int] = {}
    for item in plan:
        dll, entries = item[1], item[2]
        name_offsets[(dll, "")] = add_str(dll.encode() + b"\0")
        for e in entries:
            if isinstance(e, str) and (dll, e) not in name_offsets:
                name_offsets[(dll, e)] = add_str(b"\0\0" + e.encode() + b"\0")
    buf += strings

    i_imp = i_delay = 0
    for item in plan:
        kind, dll, entries, t1, t2 = item[:5]
        for tstart in (t1, t2):
            for j, e in enumerate(entries):
                val = (ordflag | e) if isinstance(e, int) else base_rva + name_offsets[(dll, e)]
                struct.pack_into(fmt, buf, tstart + ptr * j, val)
        if kind == "imp":
            struct.pack_into("<IIIII", buf, 20 * i_imp, base_rva + t1, 0, 0, base_rva + name_offsets[(dll, "")],
                             base_rva + t2)
            i_imp += 1
        else:
            hmod = item[5]
            struct.pack_into("<IIIIIIII", buf, desc_size + 32 * i_delay, 1, base_rva + name_offsets[(dll, "")],
                             base_rva + hmod, base_rva + t2, base_rva + t1, 0, 0, 0)
            i_delay += 1
    import_dir = (base_rva, desc_size) if imports else (0, 0)
    delay_dir = (base_rva + desc_size, ddesc_size) if spec.delay_imports else (0, 0)
    clr_dir = (base_rva + desc_size + ddesc_size, 72) if spec.dotnet else (0, 0)
    if spec.dotnet:
        struct.pack_into("<IHH", buf, desc_size + ddesc_size, 72, 2, 5)
        struct.pack_into("<I", buf, desc_size + ddesc_size + 16, spec.clr_flags)
        if spec.type_refs:
            buf += bytes(-len(buf) % 4)
            md = _metadata(spec.type_refs)
            struct.pack_into("<II", buf, desc_size + ddesc_size + 8, base_rva + len(buf), len(md))
            buf += md
    return buf, import_dir, delay_dir, clr_dir


def _metadata(type_refs: list[tuple[str, str]]) -> bytes:
    """Build ECMA-335 metadata holding a Module row and one TypeRef row per (namespace, name).

    Each name is stored only as the end of a longer string where it can be
    (FilteredPropertyGrid holds PropertyGrid), as compilers do.
    """
    heap = bytearray(b"\0")
    where: dict[str, int] = {}

    def add(text: str) -> int:
        if text not in where:
            where[text] = len(heap)
            heap.extend(text.encode() + b"\0")
        return where[text]
    module = add("App.exe")
    refs = []
    for ns, name in type_refs:
        longer = add("Filtered" + name) if name else add(name)
        refs.append((add(ns), longer + (len("Filtered") if name else 0)))
    heap += bytes(-len(heap) % 4)
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, (1 << 0) | (1 << 1), 0)
    tables += struct.pack("<II", 1, len(refs))
    tables += struct.pack("<HHHHH", 0, module, 1, 0, 0)
    for ns, name in refs:
        tables += struct.pack("<HHH", 0, name, ns)
    tables += bytes(-len(tables) % 4)
    guid = bytes(16)
    version = b"v4.0.30319\0\0"
    names = [(b"#~\0\0", tables), (b"#Strings\0\0\0\0", bytes(heap)), (b"#GUID\0\0\0", guid)]
    head_len = 16 + len(version) + 4 + sum(8 + len(n) for n, _ in names)
    root = bytearray(b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, len(names)))
    body, pos = bytearray(), head_len
    for n, data in names:
        root += struct.pack("<II", pos, len(data)) + n
        body += data
        pos += len(data)
    return bytes(root + body)


def stub_dll(dll_name: str, arch: str, names: list[str], ordinals: list[int] | None = None,
             mode: str = "zero") -> bytes:
    """Build a DLL that exports the given names and ordinals, each as a stub.

    Args:
        dll_name: The DLL's name, recorded in its export directory.
        arch: x86_64, i386 or arm64.
        names: Function names to export.
        ordinals: Ordinal-only exports.
        mode: "zero" or "trap" (see PeSpec.stub_mode).
    """
    return build_pe(PeSpec(arch=arch, is_dll=True, dll_name=dll_name, exports=names,
                           export_ordinals=ordinals or [], stub_mode=mode))


def _build_resources(entries: list[tuple[int, int, bytes]], rsrc_rva: int) -> bytes:
    """Build a .rsrc section: a type / id / language (0x409) directory tree, then the data."""
    tree: dict[int, dict[int, bytes]] = {}
    for typ, rid, data in entries:
        tree.setdefault(typ, {})[rid] = data

    def table(n: int) -> int:
        return 16 + 8 * n
    # directory tables first (root, one per type, one per id), then data entries, then data
    size = table(len(tree))
    type_off, id_off = {}, {}
    for typ in sorted(tree):
        type_off[typ] = size
        size += table(len(tree[typ]))
    for typ in sorted(tree):
        for rid in sorted(tree[typ]):
            id_off[(typ, rid)] = size
            size += table(1)
    entry_off = {}
    for typ in sorted(tree):
        for rid in sorted(tree[typ]):
            entry_off[(typ, rid)] = size
            size += 16
    data_off = {}
    for typ in sorted(tree):
        for rid in sorted(tree[typ]):
            size = _align(size, 4)
            data_off[(typ, rid)] = size
            size += len(tree[typ][rid])
    out = bytearray(_align(size, 4))

    def put_table(at: int, items: list[tuple[int, int]]) -> None:
        struct.pack_into("<IIHHHH", out, at, 0, 0, 0, 0, 0, len(items))
        for i, (ident, target) in enumerate(items):
            struct.pack_into("<II", out, at + 16 + 8 * i, ident, target)
    put_table(0, [(t, 0x80000000 | type_off[t]) for t in sorted(tree)])
    for typ in sorted(tree):
        put_table(type_off[typ], [(r, 0x80000000 | id_off[(typ, r)]) for r in sorted(tree[typ])])
        for rid in sorted(tree[typ]):
            put_table(id_off[(typ, rid)], [(0x409, entry_off[(typ, rid)])])
            data = tree[typ][rid]
            struct.pack_into("<IIII", out, entry_off[(typ, rid)], rsrc_rva + data_off[(typ, rid)], len(data), 0, 0)
            out[data_off[(typ, rid)]:data_off[(typ, rid)] + len(data)] = data
    return bytes(out)


def version_info(strings: dict[str, str], version: tuple[int, int, int, int] = (1, 0, 0, 0)) -> tuple[int, int, bytes]:
    """Build an RT_VERSION resource holding strings such as ProductName and ProductVersion."""
    def block(key: str, value: bytes, children: list[bytes], text: bool, value_len: int) -> bytes:
        body = bytearray(6) + (key + "\0").encode("utf-16-le")
        while len(body) % 4:
            body.append(0)
        body += value
        while len(body) % 4:
            body.append(0)
        for c in children:
            body += c
            while len(body) % 4:
                body.append(0)
        struct.pack_into("<HHH", body, 0, len(body), value_len, 1 if text else 0)
        return bytes(body)
    strs = [block(k, (v + "\0").encode("utf-16-le"), [], True, len(v) + 1) for k, v in strings.items()]
    table = block("040904b0", b"", strs, True, 0)
    sfi = block("StringFileInfo", b"", [table], True, 0)
    ms, ls = (version[0] << 16) | version[1], (version[2] << 16) | version[3]
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x10000, ms, ls, ms, ls, 0x3F, 0, 4, 1, 0, 0, 0)
    return (16, 1, block("VS_VERSION_INFO", fixed, [sfi], False, len(fixed)))


def icon_resources(png: bytes, size: int) -> list[tuple[int, int, bytes]]:
    """Build an RT_GROUP_ICON with one PNG image (RT_ICON 1), as modern .exe files carry them."""
    group = struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHIH", size % 256, size % 256, 0, 0, 1, 32,
                                                       len(png), 1)
    return [(3, 1, png), (14, 1, group)]
