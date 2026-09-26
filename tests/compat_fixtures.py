"""Fixtures for the Wine and Darling backends, built without any Windows or
Apple toolchain: PE files via debpak.pe_write, Mach-O files via the small
writer below (checked against the Mach-O ABI layouts in <mach-o/loader.h>)."""
from __future__ import annotations

import plistlib
import struct
from pathlib import Path

from debpak.pe_write import PeSpec, build_pe

# ------------------------------------------------------------------ Wine source tree

WINE_SPECS = {
    "kernel32": """
@ stdcall CreateFileW(wstr long long ptr long long long) kernelbase.CreateFileW
@ stdcall ExitProcess(long)
@ stub SetCurrentConsoleFontEx
@ stdcall GetConsoleFontEx(ptr) kernelbase.GetConsoleFontEx
17 stdcall -noname KernelOrdinal17()
""",
    "kernelbase": """
@ stdcall CreateFileW(wstr long long ptr long long long)
@ stub GetConsoleFontEx
""",
    "user32": """
@ stdcall MessageBoxW(long wstr wstr long)
@ stdcall -arch=win32 Only32()
""",
    "mfplat": """
@ stdcall MFStartup(long long)
""",
}


def make_wine_source(root: Path) -> Path:
    (root / "VERSION").parent.mkdir(parents=True, exist_ok=True)
    (root / "VERSION").write_text("Wine version 11.8\n")
    for name, body in WINE_SPECS.items():
        d = root / "dlls" / name
        d.mkdir(parents=True)
        (d / f"{name}.spec").write_text(body)
    return root


def make_windows_app(root: Path) -> Path:
    """An installed app dir resembling the Lightroom case."""
    root.mkdir(parents=True)
    (root / "App.exe").write_bytes(build_pe(PeSpec(
        arch="x86_64", is_dll=False,
        imports={"KERNEL32.dll": ["CreateFileW", "ExitProcess", "SetCurrentConsoleFontEx", "GetConsoleFontEx", 17,
                                  "NotInWineAtAll"],
                 "NDFAPI.DLL": ["NdfCreateWebIncident", "NdfCloseIncident"],
                 "mfplat.dll": ["MFCreateSampleCopierMFT"],   # served by the app's own mfplat.dll
                 "helper.dll": ["HelperInit"]},
        delay_imports={"wkscli.dll": ["NetWkstaGetInfo"]})))
    # app-local DLLs: the bundled mfplat overrides Wine's builtin; helper needs a missing API set
    (root / "mfplat.dll").write_bytes(build_pe(PeSpec(arch="x86_64", dll_name="mfplat.dll",
                                                      exports=["MFStartup", "MFCreateSampleCopierMFT"])))
    (root / "helper.dll").write_bytes(build_pe(PeSpec(
        arch="x86_64", dll_name="helper.dll", exports=["HelperInit"],
        imports={"ext-ms-win-uiacore-l1-1-2.dll": ["UiaRaiseEvent"]})))
    # a plugin nobody links statically
    (root / "plugins").mkdir()
    (root / "plugins" / "fx.dll").write_bytes(build_pe(PeSpec(
        arch="x86_64", dll_name="fx.dll", exports=["FxInit"], imports={"d3dcompiler_99.dll": ["D3DCompile"]})))
    # a 32-bit updater
    (root / "Updater.exe").write_bytes(build_pe(PeSpec(arch="i386", is_dll=False,
                                                       imports={"user32.dll": ["MessageBoxW", "Only32"]})))
    return root


# ------------------------------------------------------------------ Mach-O writer

CPU_TYPES = {"x86_64": (0x01000007, 3), "arm64": (0x0100000C, 0)}
FILETYPE = {"execute": 2, "dylib": 6, "bundle": 8}
LC = {"load": 0xC, "weak": 0x80000018, "reexport": 0x8000001F, "id": 0xD, "rpath": 0x8000001C,
      "symtab": 0x2, "build": 0x32, "main": 0x80000028, "trie": 0x80000033}


def _a8(n: int) -> int:
    return (n + 7) & ~7


def _uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _trie(names: list[str]) -> bytes:
    """Radix-tree export trie, as ld64 emits it (shared prefixes, <=255 children per node)."""
    root: dict = {"t": None, "c": {}}
    for i, name in enumerate(sorted(names)):
        node = root
        for ch in name:
            node = node["c"].setdefault(ch, {"t": None, "c": {}})
        node["t"] = 0x1000 + i

    def compress(node):
        for edge in list(node["c"]):
            child = node["c"].pop(edge)
            while child["t"] is None and len(child["c"]) == 1:
                (e2, c2), = child["c"].items()
                edge, child = edge + e2, c2
            compress(child)
            node["c"][edge] = child
    compress(root)

    order = []
    stack = [root]
    while stack:
        n = stack.pop(0)
        order.append(n)
        stack.extend(n["c"][e] for e in sorted(n["c"]))
    offsets = {id(n): 0 for n in order}
    for _ in range(20):
        blobs, pos, new = [], 0, {}
        for n in order:
            new[id(n)] = pos
            term = (_uleb(0) + _uleb(n["t"])) if n["t"] is not None else b""
            b = _uleb(len(term)) + term + bytes([len(n["c"])])
            for e in sorted(n["c"]):
                b += e.encode() + b"\0" + _uleb(offsets[id(n["c"][e])])
            blobs.append(b)
            pos += len(b)
        if new == offsets:
            return b"".join(blobs)
        offsets = new
    raise RuntimeError("trie layout did not converge")


def _dylib_cmd(kind: str, name: str) -> bytes:
    size = _a8(24 + len(name) + 1)
    body = struct.pack("<IIIIII", LC[kind], size, 24, 2, 0x10000, 0x10000) + name.encode() + b"\0"
    return body + bytes(size - len(body))


def build_macho(arch: str = "x86_64", filetype: str = "execute", install_name: str | None = None,
                dylibs: list[tuple[str, str]] = (), undefined: list[tuple[str, int, bool]] = (),
                exports: list[str] = (), rpaths: list[str] = (), platform: int = 1, minos=(11, 0),
                strings: list[bytes] = ()) -> bytes:
    cmds = []
    if install_name:
        cmds.append(_dylib_cmd("id", install_name))
    for name, kind in dylibs:
        cmds.append(_dylib_cmd(kind, name))
    for rp in rpaths:
        size = _a8(12 + len(rp) + 1)
        c = struct.pack("<III", LC["rpath"], size, 12) + rp.encode() + b"\0"
        cmds.append(c + bytes(size - len(c)))
    cmds.append(struct.pack("<IIIIII", LC["build"], 24, platform, (minos[0] << 16) | (minos[1] << 8), 0, 0))
    if filetype == "execute":
        cmds.append(struct.pack("<IIQQ", LC["main"], 24, 0x1000, 0))
    symtab_index = len(cmds)
    cmds.append(b"")  # placeholder
    trie_index = None
    if exports:
        trie_index = len(cmds)
        cmds.append(b"")
    sizeofcmds = 24 + (16 if exports else 0) + sum(len(c) for c in cmds)
    data_start = _a8(32 + sizeofcmds)

    strtab = bytearray(b"\0")
    syms = bytearray()
    for name in sorted(exports):
        off = len(strtab)
        strtab += name.encode() + b"\0"
        syms += struct.pack("<IBBHQ", off, 0x0F, 1, 0, 0x1000)
    for name, ordinal, weak in undefined:
        off = len(strtab)
        strtab += name.encode() + b"\0"
        syms += struct.pack("<IBBHQ", off, 0x01, 0, (ordinal << 8) | (0x40 if weak else 0), 0)
    trie = _trie(list(exports)) if exports else b""
    extra = b"".join(s + b"\0" for s in strings)

    symoff = data_start
    stroff = symoff + len(syms)
    trieoff = _a8(stroff + len(strtab))
    extraoff = trieoff + len(trie)
    cmds[symtab_index] = struct.pack("<IIIIII", LC["symtab"], 24, symoff, len(syms) // 16, stroff, len(strtab))
    if trie_index is not None:
        cmds[trie_index] = struct.pack("<IIII", LC["trie"], 16, trieoff, len(trie))
    cpu, sub = CPU_TYPES[arch]
    flags = 0x80 | 0x4 | (0x200000 if filetype == "execute" else 0)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, sub, FILETYPE[filetype], len(cmds), sizeofcmds, flags, 0)
    out = bytearray(header + b"".join(cmds))
    out += bytes(data_start - len(out))
    out += syms + strtab
    out += bytes(trieoff - len(out))
    out += trie
    assert len(out) == extraoff
    out += extra
    return bytes(out)


def fat(slices: dict[str, bytes]) -> bytes:
    n = len(slices)
    offset = 4096
    header = struct.pack(">II", 0xCAFEBABE, n)
    body = bytearray()
    entries = b""
    for arch, data in slices.items():
        cpu, sub = CPU_TYPES[arch]
        entries += struct.pack(">iiIII", cpu, sub, offset, len(data), 12)
        pad = offset - (4096 + len(body))
        body += bytes(pad) + data
        offset = (4096 + len(body) + 4095) // 4096 * 4096
    out = header + entries
    return out + bytes(4096 - len(out)) + bytes(body)


# ------------------------------------------------------------------ Darling prefix + apps

APPKIT = "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"
FOUNDATION = "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"
LIBSYSTEM = "/usr/lib/libSystem.B.dylib"
METAL = "/System/Library/Frameworks/Metal.framework/Versions/A/Metal"


def _put(root: Path, rel: str, data: bytes) -> None:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def make_darling_root(root: Path) -> Path:
    _put(root, "/usr/lib/system/libsystem_c.dylib",
         build_macho(filetype="dylib", install_name="/usr/lib/system/libsystem_c.dylib",
                     exports=["_printf", "_malloc"]))
    _put(root, LIBSYSTEM, build_macho(filetype="dylib", install_name=LIBSYSTEM,
                                      dylibs=[("/usr/lib/system/libsystem_c.dylib", "reexport")]))
    _put(root, FOUNDATION, build_macho(filetype="dylib", install_name=FOUNDATION,
                                       exports=["_OBJC_CLASS_$_NSString", "_NSLog"]))
    _put(root, APPKIT, build_macho(filetype="dylib", install_name=APPKIT,
                                   exports=["_OBJC_CLASS_$_NSWindow", "_NSApplicationMain", "_NSBeep"],
                                   strings=[b"STUB: NSBeep called"]))
    return root


def make_mac_app(root: Path, archs=("x86_64", "arm64")) -> Path:
    app = root / "Zap.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleExecutable": "Zap", "CFBundleName": "Zap", "CFBundleIdentifier": "com.example.zap",
        "LSMinimumSystemVersion": "11.0"}))
    helper_id = "@rpath/Helper.framework/Versions/A/Helper"
    deps = [(LIBSYSTEM, "load"), (APPKIT, "load"), (FOUNDATION, "load"), (helper_id, "load"), (METAL, "weak")]
    undefined = [("_printf", 1, False), ("_NSApplicationMain", 2, False), ("_NSBeep", 2, False),
                 ("_OBJC_CLASS_$_NSToolbarItemGroup", 2, False), ("_OBJC_CLASS_$_NSString", 3, False),
                 ("_NSLog", 3, False), ("_helper_fn", 4, False), ("_MTLCreateSystemDefaultDevice", 5, True)]
    main = {a: build_macho(a, "execute", dylibs=deps, undefined=undefined,
                           rpaths=["@executable_path/../Frameworks"]) for a in archs}
    (app / "Contents/MacOS/Zap").write_bytes(fat(main) if len(main) > 1 else next(iter(main.values())))
    _put(app, "Contents/Frameworks/Helper.framework/Versions/A/Helper",
         fat({a: build_macho(a, "dylib", install_name=helper_id, dylibs=[(LIBSYSTEM, "load")],
                             undefined=[("_malloc", 1, False)], exports=["_helper_fn"]) for a in archs}))
    _put(app, "Contents/PlugIns/Fx.bundle/Contents/MacOS/Fx",
         fat({a: build_macho(a, "bundle", dylibs=[(METAL, "load")],
                             undefined=[("_MTLCreateSystemDefaultDevice", 1, False)]) for a in archs}))
    return app
