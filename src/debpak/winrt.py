"""The Windows runtimes a program gets, decided up front from its files.

A Windows program assumes things every Windows PC has or that its installer
put there: the Visual C++ runtime its compiler links against, the DirectX
helper DLLs, Microsoft's core fonts, an East Asian font for its Chinese or
Japanese text. Wine has its own versions of most of these, and they are often
enough, so debpak used to only suggest the real ones in the report and leave
the program to fail first. Programs kept failing that way: GPT4All showed
"Program Error" after a null-pointer read in Wine's own msvcp140, and
TouchOSC and instigator, which import msvcp140.dll and vcruntime140.dll
without shipping them, never came up. Now the plan is made from the program
before it's built:

  - the Visual C++ runtime each import of msvcp*/vcruntime*/msvcr*/concrt*
    names, d3dx9 for d3dx9_*.dll, d3dcompiler_47 for d3dcompiler_47.dll:
    installed by the Wine base app's winetricks on first start, unless the
    program ships the DLL itself;
  - gdiplus only suggested: winetricks takes it out of Windows 7 SP1, a
    download of most of a gigabyte, and Wine's own GDI+ draws most programs;
  - Arial, Times New Roman, Courier New, Calibri and Cambria always, as the
    runtime's metric-compatible Liberation, Carlito and Caladea fonts (Wine's
    font replacements, set once on first start: no download, no wait);
  - for a program whose own text is Chinese, Japanese or Korean, Wine's
    Windows CJK font names and the fonts its dialogs link to point at a CJK
    font the sandbox has (the runtime has none, the host's are shared in);
  - the .NET runtime as winapp.dotnet_needs decides it (runtimeconfig.json,
    WPF, mixed-mode assemblies and the rest).

What can't be given is said plainly. A program built on Microsoft's
WebView2 (Tauri and Wails apps, WinForms and WPF apps with the WebView2
control) draws its whole window with it: Wails apps showed "Missing
Requirements", Tauri apps an "Error" box. The runtime's own installer
(MicrosoftEdgeWebView2RuntimeInstallerX64.exe /silent /install) exits with
status 1 under the Wine 11 base app without installing anything, so it
isn't installed, and the report says why the window won't come.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# imports whose runtime is installed up front, by import name: the Visual C++ runtimes (their
# MFC too) and DirectX's helper DLLs
INSTALL_FOR = [
    (r"^(msvcp140(_\d|_atomic_wait|_codecvt_ids)?|vcruntime140(_1)?|concrt140|vccorlib140|vcomp140|"
     r"mfc140u?)\.dll$", "vcrun2022"),
    (r"^(msvcp120|msvcr120|vcomp120|mfc120u?)\.dll$", "vcrun2013"),
    (r"^(msvcp110|msvcr110|vcomp110|mfc110u?)\.dll$", "vcrun2012"),
    (r"^(msvcp100|msvcr100|vcomp100|mfc100u?)\.dll$", "vcrun2010"),
    (r"^(msvcp90|msvcr90|mfc90u?)\.dll$", "vcrun2008"),
    (r"^(msvcp80|msvcr80|mfc80u?)\.dll$", "vcrun2005"),
    (r"^d3dx9_\d+\.dll$", "d3dx9"),
    (r"^d3dcompiler_47\.dll$", "d3dcompiler_47"),
]
# what each verb costs the first start, for the report
COST = {"vcrun2022": "about 40 MB", "vcrun2013": "about 13 MB", "vcrun2012": "about 13 MB",
        "vcrun2010": "about 10 MB", "vcrun2008": "about 7 MB", "vcrun2005": "about 6 MB",
        "d3dx9": "about 100 MB (DirectX's June 2010 redistributable)", "d3dcompiler_47": "about 8 MB"}


def install_verb(dll: str) -> str | None:
    """Return the winetricks verb installed up front for an imported DLL (lower case), or None."""
    return next((verb for pat, verb in INSTALL_FOR if re.match(pat, dll)), None)


# Windows core fonts and the runtime's metric-compatible stand-ins (same widths, so text fits
# where the program's layout expects it to)
CORE_FONTS = {"Arial": "Liberation Sans", "Arial Narrow": "Liberation Sans Narrow",
              "Times New Roman": "Liberation Serif", "Courier New": "Liberation Mono",
              "Calibri": "Carlito", "Cambria": "Caladea"}

# Windows' CJK fonts by the language fc-list knows them by, and the faces Wine draws dialogs and
# controls with, which get a CJK font linked for the characters they lack
CJK_FONTS = {"zh-cn": ("SimSun", "NSimSun", "SimHei", "Microsoft YaHei", "Microsoft YaHei UI", "DengXian"),
             "zh-tw": ("MingLiU", "PMingLiU", "Microsoft JhengHei", "Microsoft JhengHei UI"),
             "ja": ("MS Gothic", "MS PGothic", "MS UI Gothic", "MS Mincho", "Meiryo", "Meiryo UI", "Yu Gothic",
                    "Yu Gothic UI"),
             "ko": ("Gulim", "Dotum", "Batang", "Malgun Gothic")}
CJK_LINKED_FACES = ("Tahoma", "Tahoma Bold", "MS Shell Dlg", "MS Shell Dlg 2", "Microsoft Sans Serif", "Segoe UI",
                    "Arial", "Liberation Sans")

# Hiragana, Katakana, CJK ideographs (and extension A), Hangul syllables
_CJK = "぀-ヿ㐀-䶿一-鿿가-힯"
CJK_TEXT = re.compile(f"[{_CJK}]{{2,}}")
# the same in UTF-8, as Go, Rust and Qt programs keep their strings: four or more in a row
CJK_UTF8 = re.compile(rb"(?:[\xe3-\xed][\x80-\xbf]{2}){4,}")
# resource languages: Chinese, Japanese, Korean (the primary language in the low 10 bits)
CJK_LANGS = {0x04, 0x11, 0x12}
# resources that hold a program's UI text: menus, dialogs, string tables, version strings
RT_TEXT = {4, 5, 6, 16}

# what shows a program uses WebView2: the loader DLL (imported or shipped), its entry point
# (programs that load it themselves, like Wails' go-webview2), the runtime's client GUID the
# loader looks up in the registry (Tauri's wry links the loader in statically), and the .NET
# control's assembly
WEBVIEW2_MARKS = (b"WebView2Loader.dll", b"CreateCoreWebView2Environment", b"F3017226-FE2A-4295-8BDF-00C3A9A7E4C5",
                  b"Microsoft.Web.WebView2")


@dataclass
class RuntimePlan:
    """What a Windows program gets besides itself."""
    verbs: list[str] = field(default_factory=list)          # winetricks verbs installed on first start
    why: dict[str, str] = field(default_factory=dict)       # verb -> the import that calls for it
    suggest: dict[str, str] = field(default_factory=dict)   # verb -> import, only suggested
    core_fonts: bool = True
    cjk: str = ""                                           # what shows its text is CJK, or ""
    webview2: str = ""                                      # what shows it uses WebView2, or ""


def _read(f: Path, limit: int = 256 << 20) -> bytes:
    try:
        if f.stat().st_size > limit:
            return b""
        return f.read_bytes()
    except OSError:
        return b""


def cjk_text(exe: Path, data: bytes | None = None) -> str:
    """Say what shows a program's own UI text is Chinese, Japanese or Korean; "" if nothing does.

    That is a menu, dialog, string table or version resource in one of those
    languages or with such text in it, or, for programs that keep their
    strings in UTF-8 (Go, Rust, Qt), runs of CJK characters in the file.
    AcFun's virtual-avatar tool is a Chinese Qt program.
    """
    import struct
    from .pe import PeError
    from .winres import _resources
    data = _read(exe) if data is None else data
    if not data:
        return ""
    try:
        img, leaves = _resources(data)
    except (PeError, ValueError, struct.error, IndexError):
        leaves, img = [], None
    for path, rva, size in leaves:
        if path[0] not in RT_TEXT or len(path) < 3:
            continue
        lang = path[2] if isinstance(path[2], int) else 0
        if lang & 0x3FF in CJK_LANGS:
            return f"its resources are in {({0x04: 'Chinese', 0x11: 'Japanese', 0x12: 'Korean'})[lang & 0x3FF]}"
        try:
            o = img.off(rva)
        except (PeError, ValueError, IndexError):
            continue
        raw = data[o:o + min(size, 1 << 20)]
        if (m := CJK_TEXT.search(raw[:len(raw) & ~1].decode("utf-16-le", "replace"))):
            return f"its resources hold text such as {m.group(0)[:12]!r}"
    if len(CJK_UTF8.findall(data, 0, 64 << 20)) >= 3:
        return "it holds strings in Chinese, Japanese or Korean"
    return ""


def webview2_use(main: Path, files: list[Path], imports: set[str]) -> str:
    """Say what shows the program draws with Microsoft's WebView2; "" if nothing does.

    A program that brings its own copy of the runtime (msedgewebview2.exe in
    its folder, the "fixed version" way) needs nothing, and gets "".
    """
    names = {f.name.lower() for f in files}
    try:
        names |= {p.name.lower() for p in main.parent.rglob("msedgewebview2.exe")}
    except OSError:
        pass
    if "msedgewebview2.exe" in names:
        return ""
    if "webview2loader.dll" in imports:
        return "it imports WebView2Loader.dll"
    if "webview2loader.dll" in names:
        return "it ships WebView2Loader.dll"
    try:
        beside = [main] + sorted(p for p in main.parent.iterdir() if p.suffix.lower() == ".dll" and p.is_file())[:200]
    except OSError:
        beside = [main]
    for f in beside:
        data = _read(f)
        for mark in WEBVIEW2_MARKS:
            if mark in data or mark.decode().encode("utf-16-le") in data:
                return f"{f.name} holds {mark.decode()!r}"
    return ""


def survey(main: Path, files: list[Path], imports: set[str]) -> RuntimePlan:
    """Work out the runtimes a Windows program gets from its files.

    main is the program, files the .exe and .dll files of its folder, and
    imports the lower-case names of the DLLs any of them imports. A DLL the
    program ships needs no runtime.
    """
    from .winapp import RUNTIME_FOR
    plan = RuntimePlan()
    shipped = {f.name.lower() for f in files}
    for dll in sorted(imports - shipped):
        if (verb := install_verb(dll)):
            if verb not in plan.verbs:
                plan.verbs.append(verb)
                plan.why[verb] = dll
        elif (verb := next((v for pat, v in RUNTIME_FOR if re.match(pat, dll)), None)):
            plan.suggest.setdefault(verb, dll)
    plan.cjk = cjk_text(main)
    plan.webview2 = webview2_use(main, files, imports)
    return plan


# the file the launcher keeps in the Wine prefix while it installs runtimes on first start, and
# removes when it's done (or gave up): a check that starts the app waits while it's there
INSTALLING = ".debpak-installing"


def font_lines(cjk: bool) -> list[str]:
    """Return the launcher lines that point Windows' font names at the sandbox's fonts, once per prefix.

    The core fonts become the runtime's metric-compatible ones. With cjk,
    Windows' CJK fonts become the sandbox's own (fc-match's choice for each
    language, if it covers the language), and the faces Wine draws dialogs and
    controls with get them linked for the characters they lack. A real font
    of the name, if one is ever installed (winetricks' corefonts), wins over a
    replacement. The marker says what was set, so a launcher that sets more
    sets it again.
    """
    import shlex
    q = shlex.quote
    mark = "core 1" + (" cjk" if cjk else "")
    lines = [
        "# Windows' fonts by name: the core ones as the runtime's fonts of the same widths"
        + (", and the CJK ones as a CJK font the sandbox has" if cjk else ""),
        f'if [ "$(cat "$WINEPREFIX/.debpak-fontsubs" 2>/dev/null)" != {q(mark)} ]; then',
        '    reg="$WINEPREFIX/debpak-fonts.reg"',
        "    links=",
        "    {",
        "        printf 'REGEDIT4\\r\\n\\r\\n[HKEY_CURRENT_USER\\\\Software\\\\Wine\\\\Fonts\\\\Replacements]\\r\\n'",
    ]
    lines += [f"        printf '\"%s\"=\"%s\"\\r\\n' {q(win)} {q(ours)}" for win, ours in CORE_FONTS.items()]
    if cjk:
        lines += ["        for lang in " + " ".join(CJK_FONTS) + "; do",
                  "            # fc-match always answers; only a font that covers the language will do",
                  "            file=$(fc-match -f '%{file}' \"sans-serif:lang=$lang\" 2>/dev/null)",
                  '            fc-list ":lang=$lang" file 2>/dev/null | grep -qF "$file" || continue',
                  "            fam=$(fc-match -f '%{family[0]}' \"sans-serif:lang=$lang\" | tr -d '\"\\\\')",
                  '            case $lang in']
        for lang, faces in CJK_FONTS.items():
            lines.append(f"                {lang}) faces={q(chr(10).join(faces))} ;;")
        lines += ["            esac",
                  "            printf '%s\\n' \"$faces\" | while IFS= read -r face; do",
                  "                printf '\"%s\"=\"%s\"\\r\\n' \"$face\" \"$fam\"",
                  "            done",
                  '            case "$links" in *"${file##*/},$fam"*) ;; '
                  '*) links="${links:+$links\\0}${file##*/},$fam" ;; esac',
                  "        done"]
    lines += [
        '    } > "$reg"',
        '    ok=1',
        '    wine regedit /S "$reg" >/dev/null 2>&1 || ok=',
    ]
    if cjk:
        lines += ['    if [ -n "$links" ]; then',
                  "        for face in " + " ".join(q(f) for f in CJK_LINKED_FACES) + "; do",
                  "            wine reg add 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontLink\\SystemLink' "
                  '/v "$face" /t REG_MULTI_SZ /d "$links" /f >/dev/null 2>&1 || ok=',
                  "        done",
                  "    fi"]
    lines += [
        '    rm -f "$reg"',
        f'    [ -z "$ok" ] || echo {q(mark)} > "$WINEPREFIX/.debpak-fontsubs"',
        "fi",
    ]
    return lines
