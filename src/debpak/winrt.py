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

A program built on Microsoft's WebView2 (Tauri and Wails apps, WinForms and
WPF apps with the WebView2 control) draws its whole window with it: Wails
apps showed "Missing Requirements" (QShell, Swiss Knife Graph), Tauri apps
an "Error" box (Netstat Cat, MDViewer+, Racemo, Whisperi). The runtime's own
installer (MicrosoftEdgeWebView2RuntimeInstallerX64.exe /silent /install)
exits with status 1 under the Wine 11 base app, and winetricks' webview2
verb (which the base app's winetricks doesn't have) runs the online
bootstrapper of the same installer. So the first start takes Microsoft's
Fixed Version runtime instead, a .cab of the browser's folder that needs no
installer, puts it where the installer would, and writes the registry value
WebView2's loader finds an installed runtime by (Wails' own loader in Go
reads the same one, and ignores WEBVIEW2_BROWSER_EXECUTABLE_FOLDER). See
webview2_lines.
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


# GPUI, the Zed editor's UI framework, draws a window on Windows into a DXGI swap chain made for
# DirectComposition (CreateSwapChainForComposition), which Wine's dxgi doesn't implement: Sonora, a GPUI
# music player, panicked as it started with "failed to open window: Creating DirectX renderer ...
# Creating DirectX resources ... Not implemented. (0x80004001)". GPUI has a switch in the environment for
# systems without DirectComposition, which has it make a swap chain for the window itself; the program
# holds the switch's name, and the launcher sets it
COMPOSITION_SWITCH = re.compile(rb"[A-Z][A-Z0-9]*_DISABLE_DIRECT_COMPOSITION")


def direct_composition_switch(main: Path, data: bytes | None = None) -> str:
    """Return the name of the environment switch that keeps the program off DirectComposition, or "".

    See COMPOSITION_SWITCH: GPUI's, in a Rust program, is a run of ASCII.
    """
    data = _read(main) if data is None else data
    m = COMPOSITION_SWITCH.search(data)
    return m.group(0).decode() if m else ""


@dataclass
class RuntimePlan:
    """What a Windows program gets besides itself."""
    verbs: list[str] = field(default_factory=list)          # winetricks verbs installed on first start
    why: dict[str, str] = field(default_factory=dict)       # verb -> the import that calls for it
    suggest: dict[str, str] = field(default_factory=dict)   # verb -> import, only suggested
    core_fonts: bool = True
    cjk: str = ""                                           # what shows its text is CJK, or ""
    webview2: str = ""                                      # what shows it uses WebView2, or ""
    composition_switch: str = ""                            # see COMPOSITION_SWITCH


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
        assert img is not None     # leaves is empty without it
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
    plan.composition_switch = direct_composition_switch(main)
    return plan


# the file the launcher keeps in the Wine prefix while it installs runtimes on first start, and
# removes when it's done (or gave up): a check that starts the app waits while it's there
INSTALLING = ".debpak-installing"

# the file the launcher writes in the Wine prefix once wineboot has set it up whole. Wine writes its
# .update-timestamp as its setup begins, and wineboot --init does nothing in a prefix whose timestamp
# is current, so a setup cut short after that (by a check, or a user closing the first start) is never
# finished: Racemo and MDViewer+ panicked in RegisterDragDrop, the classes and services wine.inf
# registers missing ("Failed to open RpcSs service"), and QuarkUpdate's winetricks found no
# syswow64\regedit.exe (status 53). A prefix without this file is one the launcher can't vouch for.
PREFIX_DONE = ".debpak-prefix"
# what a prefix wine.inf was applied to has in system.reg, for one set up before PREFIX_DONE was written
PREFIX_SET_UP = "Services\\\\RpcSs]"


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


# Microsoft's WebView2 Fixed Version runtime, x64 (it serves 32-bit programs too: it holds
# EBWebView\x86 beside EBWebView\x64). Microsoft lets it be shipped with an app; debpak doesn't ship
# it, the launcher downloads it from Microsoft on first start, as winetricks does its runtimes. This
# version ran Netstat Cat (Tauri) and QShell (Wails) under the Wine 11 base app; if its link ever
# dies, the launcher takes the newest one Microsoft's download page links to.
WEBVIEW2_VERSION = "158.0.4370.45"
WEBVIEW2_CAB = ("https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/"
                "4fe269a2-de5a-488b-b6a0-9d9a42d641b8/Microsoft.WebView2.FixedVersionRuntime.158.0.4370.45.x64.cab")
WEBVIEW2_SHA256 = "a7d41bc8b51f5594130113c8e218742a2762fbc74c4ee4c2a4e59b9ec172aff5"
WEBVIEW2_PAGE = "https://developer.microsoft.com/en-us/microsoft-edge/webview2/"
# the page keeps its links in a JSON blob, with "/" written as \u002F
WEBVIEW2_LINK = (r"https://msedge\.sf\.dl\.delivery\.mp\.microsoft\.com/filestreamingservice/files/[0-9a-f-]*/"
                 r"Microsoft\.WebView2\.FixedVersionRuntime\.[0-9.]*\.x64\.cab")
WEBVIEW2_COST = "a download of about 440 MB, about 810 MB in the Wine prefix"
# the runtime's client GUID: the loader finds an installed runtime by the EBWebView value of
# HKLM\Software\Microsoft\EdgeUpdate\ClientState\{this}, in the 32-bit view
WEBVIEW2_CLIENT = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
# Chromium's sandbox doesn't start under Wine, and with its GPU process drawing into the program's
# window Netstat Cat crashed on most starts (Wine's RevokeDragDrop releases the browser process's drop
# target from wry's process); with these it came up on six starts out of seven
WEBVIEW2_ARGS = ("--no-sandbox", "--disable-gpu")
# where the runtime's installer puts it, as Windows paths go
WEBVIEW2_HOME = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application"


def webview2_lines() -> list[str]:
    """Return the launcher lines that put WebView2's runtime in the Wine prefix, once, and start it right.

    The Fixed Version cab is checked against its SHA-256 (a newer one from
    Microsoft's page, the fallback, can't be), unpacked with the base app's
    cabextract into Program Files (x86)\\Microsoft\\EdgeWebView\\Application
    \\<version>, with the locales other than en-US and the user's language
    left out (137 MB of them), and registered as an installed runtime. Like
    winetricks' webview2 verb, the browser is told it runs on Windows 7
    (Wine bug 58921). The marker holds the version, and a runtime folder
    that has gone is fetched again. Chromium's switches go in
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, which the loader passes on; a
    value the user set (even empty) is kept. Wine's crash dialog is turned
    off in the prefix, so that a start that crashes in Wine's drag and drop
    (see winapp.launcher) ends, and the launcher starts the program again.
    """
    import shlex
    q = shlex.quote
    home = WEBVIEW2_HOME.replace("\\", "/").replace("C:/", "$WINEPREFIX/drive_c/", 1)
    client_key = "HKLM\\Software\\Microsoft\\EdgeUpdate\\ClientState\\" + WEBVIEW2_CLIENT
    return [
        "# Microsoft's WebView2 runtime, which the program draws its window with: its installer fails under",
        "# Wine, so its Fixed Version (a cab of the browser's folder) goes where the installer would put it",
        f'WV2="{home}"',
        'wv2=$(cat "$WINEPREFIX/.debpak-webview2" 2>/dev/null)',
        'if [ -z "$wv2" ] || [ ! -e "$WV2/$wv2/msedgewebview2.exe" ]; then',
        f'    echo "Installing Microsoft\'s WebView2 runtime into the Wine prefix (first run only, {WEBVIEW2_COST})..." >&2',
        "    # while this is here a check that started the app waits (see selfcheck.OBSERVER)",
        f'    echo webview2 > "$WINEPREFIX/{INSTALLING}"',
        '    tmp="$WINEPREFIX/debpak-webview2"',
        '    rm -rf "$tmp"; mkdir -p "$tmp"',
        "    # the version debpak was tried with, if it is still there and unchanged; else the newest on Microsoft's page",
        f'    if curl -fsSL --retry 3 -o "$tmp/runtime.cab" {q(WEBVIEW2_CAB)} \\',
        f'            && echo {q(WEBVIEW2_SHA256)}"  $tmp/runtime.cab" | sha256sum -c --status; then',
        "        got=1",
        "    else",
        f"        url=$(curl -fsSL --retry 3 {q(WEBVIEW2_PAGE)} | sed 's#\\\\u002F#/#g' | grep -o {q(WEBVIEW2_LINK)} | head -n 1)",
        '        got=; [ -z "$url" ] || ! curl -fsSL --retry 3 -o "$tmp/runtime.cab" "$url" || got=1',
        "    fi",
        "    wv2=",
        '    if [ -n "$got" ] && cabextract -q -d "$tmp" "$tmp/runtime.cab" >/dev/null 2>&1; then',
        '        rm -f "$tmp/runtime.cab"',
        '        for d in "$tmp"/Microsoft.WebView2.FixedVersionRuntime.*; do',
        '            [ -e "$d/msedgewebview2.exe" ] || continue',
        '            wv2=${d##*/Microsoft.WebView2.FixedVersionRuntime.}; wv2=${wv2%.x64}',
        "        done",
        "    fi",
        '    if [ -n "$wv2" ]; then',
        '        src="$tmp/Microsoft.WebView2.FixedVersionRuntime.$wv2.x64"',
        "        # its 168 locale files make 137 MB; Chromium falls back to en-US for a language it lacks",
        "        lang=${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}; lang=${lang%%.*}; lang=${lang%%@*}",
        "        region=$(printf %s \"$lang\" | tr _ -)",
        '        for f in "$src/Locales"/*.pak; do',
        '            n=${f##*/}; n=${n%.pak}; n=${n#copilot_overlay_strings_}',
        '            case $n in en-US|"${lang%%_*}"|"$region") ;; *) rm -f "$f" ;; esac',
        "        done",
        '        mkdir -p "$WV2" && rm -rf "${WV2:?}/$wv2" && mv "$src" "$WV2/$wv2" || wv2=',
        "    fi",
        '    if [ -n "$wv2" ]; then',
        "        # where WebView2's loader (and Wails' loader in Go) finds an installed runtime; Windows 7 for the",
        "        # browser, as winetricks' webview2 sets (Wine bug 58921); and no crash dialog, so a start that",
        "        # crashes ends and the launcher can start it again",
        f"        wine reg add {q(client_key)} /v EBWebView /t REG_SZ /d {q(WEBVIEW2_HOME + chr(92))}\"$wv2\" /reg:32 /f \\",
        "                >/dev/null 2>&1 \\",
        "            && wine reg add 'HKCU\\Software\\Wine\\AppDefaults\\msedgewebview2.exe' /v Version /t REG_SZ /d win7 /f \\",
        "                >/dev/null 2>&1 \\",
        "            && wine reg add 'HKCU\\Software\\Wine\\WineDbg' /v ShowCrashDialog /t REG_DWORD /d 0 /f >/dev/null 2>&1 \\",
        '            && echo "$wv2" > "$WINEPREFIX/.debpak-webview2"',
        "    else",
        "        echo \"WebView2's runtime didn't install; the program's window may not come. It retries next start.\" >&2",
        "    fi",
        '    rm -rf "$tmp"',
        f'    rm -f "$WINEPREFIX/{INSTALLING}"',
        "fi",
        "# Chromium's sandbox doesn't start under Wine, and its GPU process crashes the program now and then",
        f'export WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="${{WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS-{" ".join(WEBVIEW2_ARGS)}}}"',
    ]
