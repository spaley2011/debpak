"""Windows programs packaged as Flatpaks that run them under Wine.

The Flatpak is built on the org.winehq.Wine base app, which brings Wine,
wine-mono (for .NET programs) and wine-gecko. The program's files go in
/app/opt/NAME, and a launcher in /app/bin starts them:

  - The Wine prefix lives in the app's own data folder
    (~/.var/app/APP_ID/data/wine) and is created on first run.
  - Arguments that name existing files are turned into Windows paths with
    winepath, so "open with" works.
  - /app is read-only. A program that writes next to its own .exe needs
    --writable, which copies it into the prefix's C: drive on first run.
    On an update, files the user changed since the last copy are kept.
  - Windows runtimes given with --wine-runtime (vcrun2022, dotnet48,
    corefonts ...) are installed into the prefix on first run by the
    winetricks the Wine base app includes. The report suggests them from the
    DLLs the program imports but doesn't ship.

When a Wine index is cached (see `winegap index`), the program's imports are
checked against it, and a DLL or function Wine lacks entirely stops the
conversion unless --force is given.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
from pathlib import Path

from .foreign import Plan, _need_replay, copy_tree, extra_source, one_line, write_integration
from .packages import Package
from .permissions import Permission
from .runtime import parse_ref, sdk_for
from .unpack import APPLY_EXTRA, install_helper
from .winrt import INSTALLING, PREFIX_DONE, PREFIX_SET_UP, font_lines, webview2_lines

WINE_BASE = "org.winehq.Wine"
DEFAULT_RUNTIME = "org.freedesktop.Platform//25.08"
NETWORK_DLLS = {"ws2_32.dll", "wsock32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "iphlpapi.dll",
                "dnsapi.dll", "mswsock.dll"}
# DLLs whose runtime winetricks installs, by import name. Wine has its own versions of many of
# these, so they're suggestions: programs often run without them, and some need the real ones.
RUNTIME_FOR = [
    (r"^(msvcp140|vcruntime140|vcruntime140_1|concrt140|vccorlib140|mfc140u?)\.dll$", "vcrun2022"),
    (r"^(msvcp120|msvcr120|mfc120u?)\.dll$", "vcrun2013"),
    (r"^(msvcp110|msvcr110|mfc110u?)\.dll$", "vcrun2012"),
    (r"^(msvcp100|msvcr100|mfc100u?)\.dll$", "vcrun2010"),
    (r"^(msvcp90|msvcr90|mfc90u?)\.dll$", "vcrun2008"),
    (r"^(msvcp80|msvcr80|mfc80u?)\.dll$", "vcrun2005"),
    (r"^d3dx9_\d+\.dll$", "d3dx9"),
    (r"^d3dcompiler_47\.dll$", "d3dcompiler_47"),
    (r"^(gdiplus)\.dll$", "gdiplus"),
]
# DLLs Wine has no version of at all, so a program that imports them can't start without the
# runtime: XYplorer is a Visual Basic 6 program ("Library MSVBVM60.DLL ... not found"), and
# TrafficMonitor and MusicPlayer2 are MFC programs (mfc140u.dll; Dependency Walker's MFC42.DLL),
# which exit with status 53, Wine's "DLL not found"
WINE_LACKS = {"msvbvm60.dll": "vb6run", "msvbvm50.dll": "vb5run", "mfc42.dll": "mfc42", "mfc42u.dll": "mfc42",
              "mfc40.dll": "mfc40", "mfc40u.dll": "mfc40", "mfc71.dll": "vcrun2003", "mfc71u.dll": "vcrun2003"}


# the verbs above that install only the 32-bit DLL: Microsoft never made a 64-bit Visual Basic
# runtime, and winetricks' mfc42 takes the 32-bit MFC42.DLL out of the Visual C++ 6 redistributable.
# Dependency Walker's x64 build imports MFC42.DLL and exited with status 53 after mfc42 was installed
ONLY_32BIT_VERBS = {"vb6run", "vb5run", "mfc42", "mfc40", "vcrun2003"}


def wine_lacks(dll: str) -> str | None:
    """Return the winetricks verb that installs a DLL Wine has no version of, or None."""
    if dll in WINE_LACKS:
        return WINE_LACKS[dll]
    if re.fullmatch(r"mfc\d+u?\.dll", dll):        # the Visual C++ runtimes carry MFC too
        return next((verb for pat, verb in RUNTIME_FOR if re.match(pat, dll)), None)
    return None
VERB_RE = re.compile(r"^[a-z0-9_.-]{2,40}$")

# DLLs the Wine base app is built without, whose every function reports failure through what it
# returns, and the failure each stand-in returns. Flathub's org.winehq.Wine is built without
# pcsc-lite, so it has no winscard.dll at all, and Belfius Connector, which imports it, exited
# with status 53 (Wine's "DLL not found") before it could do anything. A stand-in whose SCard
# functions say the smart-card service isn't running (SCARD_E_NO_SERVICE, what Windows says
# when that service is stopped) lets the program start; it can't use a card reader, which the
# sandbox doesn't reach anyway. The few functions that return a handle or nothing return 0.
STANDINS = {"winscard.dll": (0x8010001D, {"SCardAccessStartedEvent": 0, "SCardReleaseStartedEvent": 0},
                             "smart cards (the Wine base app is built without them)",
                             "the smart-card service isn't running")}


# DLLs Windows split out of another, whose functions Wine still has in the one they came from: each
# function the program imports is passed on to it, under the same name. Windows 10 moved Media
# Foundation's pipeline (MFCreateMediaSession, MFCreateTopology and the rest) from mf.dll into
# MFCORE.dll, which Qt 6's multimedia imports, and Wine has them in mf.dll only: QField's qfield.exe
# was refused for lacking MFCORE.dll, though every function it imports from it is in Wine's mf.dll.
SPLIT_FROM = {"mfcore.dll": ("mf", "Media Foundation's core, which Windows 10 split out of mf.dll")}


def wine_base_dlls(base_version: str, machine: str) -> set[str] | None:
    """Return the lower-case names of the DLLs the installed Wine base app has for machine, or None.

    None when the base app isn't installed (or its files can't be seen), so
    nothing can be said about what it lacks.
    """
    import subprocess
    from . import host
    sub = {"x86_64": "x86_64-windows", "i386": "i386-windows"}.get(machine)
    if not sub or not host.which("flatpak"):
        return None
    try:
        r = subprocess.run(host.command(["flatpak", "info", "--show-location", f"{WINE_BASE}//{base_version}"]),
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    d = Path(r.stdout.strip() or "/nonexistent") / "files/lib/wine" / sub
    if r.returncode != 0 or not d.is_dir():
        return None
    try:
        names = {p.name.lower() for p in d.iterdir()}
    except OSError:
        return None
    return names if "kernel32.dll" in names else None


def startup_imports(main: Path, files: list[Path]) -> dict[str, dict]:
    """Return the DLLs that must load for the program to start, and what it imports from each.

    That is the DLLs the program imports (not delay-loads), and those that the
    DLLs it ships and loads that way import, and so on. A DLL it ships is left
    out. Keys are lower-case names; each value has "dll" (the name as
    imported), "names" (the functions imported by name) and "by" (the file
    names that import it).
    """
    from .pe import PeError, read_pe
    shipped: dict[str, Path] = {}
    for f in files:
        # the copy beside the program is the one Windows loads first
        if f.name.lower() not in shipped or f.parent == main.parent:
            shipped[f.name.lower()] = f
    out: dict[str, dict] = {}
    todo, seen = [main], set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        try:
            imports = read_pe(f).imports
        except (PeError, OSError, ValueError):
            continue
        for i in imports:
            if i.delay:
                continue
            low = i.dll.lower()
            if low in shipped:
                todo.append(shipped[low])
                continue
            e = out.setdefault(low, {"dll": i.dll, "names": set(), "by": []})
            if i.name:
                e["names"].add(i.name)
            if f.name not in e["by"]:
                e["by"].append(f.name)
    return out
# --wine-runtime value that installs no .NET runtime: the program stays on wine-mono
MONO = "wine-mono"
# Microsoft's ucrtbase.dll, from winetricks. Wine's own has one in system32 already, so winetricks
# takes the verb as done and skips it unless forced; the launcher forces the verbs named here
UCRTBASE = "ucrtbase2019"
FORCED_VERBS = {UCRTBASE}
# Python 3.15's calendar module asks strftime for "%OB" when it's imported; Windows' C runtime
# ignores the O, Wine's rejects the format, and the import fails
PYTHON_DLL = re.compile(rb"(?i)python3(\d{2})t?\.dll")
UCRT_PYTHON = 15
# winetricks verbs that set the Windows version Wine reports
WINVER_VERBS = {"win31", "win95", "win98", "winme", "win2k", "winxp", "win2k3", "vista", "win2k8", "win2k8r2",
                "win7", "win8", "win81", "win10", "win11", "nt351", "nt40"}
# names the launcher must not take, because the Wine base already has them in /app/bin
RESERVED = {"wine", "wine64", "wineboot", "winecfg", "wineserver", "winepath", "msiexec", "regedit", "notepad",
            "winetricks"}
# Windows symbol fonts Wine doesn't have, and the Freedesktop runtime font that stands in for each.
# GDI+ draws nothing at all with a font family it can't find, so WinDirStat's toolbar icons, which
# are Segoe UI Symbol characters drawn as paths, came out as blank (greyed: flat grey) squares.
# These fonts use standard Unicode code points, so another font's glyphs fit; Segoe MDL2 Assets
# and Segoe Fluent Icons use private-use code points and have no such stand-in.
SYMBOL_FONT_STANDINS = {"Segoe UI Symbol": "DejaVu Sans"}

# Programs that index NTFS volumes by reading their file table, which Wine doesn't have, but can
# index ordinary folders named in the settings file beside them: the .exe's name, lower case, and
# that file. The launcher writes it on first start with the user's Documents and Downloads, the
# folders the sandbox grants, so a search shows something instead of an empty window
FOLDER_INDEXERS = {"everything.exe": "Everything.ini"}
# Runtime fonts Wine falls back to for characters DejaVu Sans lacks (font linking, which Wine
# applies to text and to GetGlyphOutline, so GDI+ paths too): DejaVu Sans Mono has U+2315 (the
# search glyph), FreeSerif the squared symbols around U+29C8, DejaVu Serif the arrows around U+2913.
# Wine looks links up by the face's full name, so the bold face needs its own entry.
SYMBOL_FONT_LINKS = ("DejaVuSansMono.ttf,DejaVu Sans Mono", "FreeSerif.ttf,FreeSerif", "DejaVuSerif.ttf,DejaVu Serif")
SYMBOL_FONT_LINKED_FACES = ("DejaVu Sans", "DejaVu Sans Bold")


def wine_branch(args) -> tuple[str, str]:
    """Return (base-version of org.winehq.Wine, runtime branch).

    --wine-branch wins and sets the runtime branch to match. Otherwise the
    runtime branch picks it: wow64-25.08 for 25.08 (a 64-bit Wine that also
    runs 32-bit programs, with no i386 runtime needed), stable-BRANCH for
    26.08 and later, where the stable build is WoW64 too.
    """
    wb = getattr(args, "wine_branch", None)
    if wb:
        return wb, wb.rsplit("-", 1)[-1]
    _rid, _arch, branch = parse_ref(getattr(args, "runtime", None) or DEFAULT_RUNTIME, "x86_64")
    return ({"24.08": "wow64-24.08", "25.08": "wow64-25.08"}.get(branch, f"stable-{branch}"), branch)


def _pe_files(root: Path, limit: int = 2000) -> list[Path]:
    """Return up to limit .exe and .dll files under root, for the import scan."""
    out = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".exe", ".dll") and p.is_file() and not p.is_symlink():
            out.append(p)
            if len(out) >= limit:
                break
    return out


def _cached_indexes() -> dict:
    """Load the newest cached Wine index for each architecture ({} when none is cached)."""
    from .wine import WineIndex, default_cache
    found: dict = {}
    d = default_cache()
    if not d.is_dir():
        return found
    for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            idx = WineIndex.load(f)
        except (OSError, ValueError, KeyError):
            continue
        found.setdefault(idx.arch, idx)
    return found


# .NET majors debpak installs: winetricks' dotnetN and dotnetdesktopN verbs, or, where the Wine base
# app's winetricks doesn't have the verb yet, Microsoft's zips of the runtime (see launcher). There
# is no upper end: OpenDirectoryDownloader 5.1, built for .NET 11 the month it came out, was given
# no runtime at all ("needs Microsoft.NETCore.App 11.0.0, which winetricks has no verb for") and
# stopped at "You must install .NET to run this application", though aka.ms/dotnet/11.0 had the zip
DOTNET_MAJORS = range(6, 100)
# winetricks' verbs for the .NET Framework that a 64-bit prefix takes and whose names look like a
# modern .NET's dotnetN. Its dotnet11 and dotnet30 (Framework 1.1 and 3.0) refuse 64-bit prefixes,
# and debpak's are all 64-bit, so there dotnet11 can only mean .NET 11: OpenDirectoryDownloader 5.1
# asked for .NET 11 and the launcher handed winetricks its dotnet11, which said "This package
# (dotnet11) does not work on a 64-bit installation", so nothing was installed
FRAMEWORK_VERBS = frozenset({"dotnet20", "dotnet35", "dotnet40", "dotnet45", "dotnet46", "dotnet48"})


def modern_dotnet(verb: str) -> bool:
    """Whether a runtime verb names a modern .NET (dotnet8, dotnetdesktop10, dotnet11), not the .NET Framework."""
    m = re.fullmatch(r"dotnet(desktop)?(\d+)", verb)
    return bool(m) and int(m.group(2)) in DOTNET_MAJORS and verb not in FRAMEWORK_VERBS


def embedded_runtimeconfig(exe: Path) -> dict | None:
    """Return runtimeOptions from a single-file .NET program, which carries its runtimeconfig.json inside.

    dotnet publish -p:PublishSingleFile=true appends the app's files to the
    apphost uncompressed (a framework-dependent bundle can't compress them),
    so the JSON is there as text. ScreenToGif's portable .exe is one.
    """
    try:
        data = exe.read_bytes()
    except OSError:
        return None
    if b"runtimeOptions" not in data:
        return None
    dec = json.JSONDecoder()
    for m in re.finditer(rb'"runtimeOptions"', data):
        start = data.rfind(b"{", max(0, m.start() - 64), m.start())
        if start < 0:
            continue
        try:
            obj, _end = dec.raw_decode(data[start:start + 16384].decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("runtimeOptions"), dict):
            return obj["runtimeOptions"]
    return None


def dotnet_needs(main: Path, is_dotnet: bool) -> tuple[list[str], bool, str]:
    """Work out which .NET runtime a program needs.

    A modern .NET program's NAME.runtimeconfig.json names its framework:
    Microsoft.WindowsDesktop.App 9.0 needs dotnetdesktop9 and
    Microsoft.NETCore.App 8.0 needs dotnet8; a self-contained one
    (includedFrameworks) needs nothing. A single-file program carries the
    file inside its .exe. A .NET Framework program that uses
    WPF needs dotnet48, since wine-mono's WPF is incomplete, and so does a
    WinForms one with a PropertyGrid, which wine-mono draws with black boxes
    over its category rows and labels (mRemoteNG's Config panel); the rest
    run on wine-mono.

    Returns:
        (winetricks verbs, uses WPF, a sentence for the report or "").
    """
    from .pe import dotnet_type_refs
    def uses_wpf(*files: Path) -> bool:
        for f in files:
            try:
                if b"PresentationFramework" in f.read_bytes():
                    return True
            except OSError:
                continue
        return False

    rc = main.with_name(main.stem + ".runtimeconfig.json")
    opts, source = None, rc.name
    if rc.is_file():
        try:
            opts = json.loads(rc.read_text("utf-8-sig")).get("runtimeOptions") or {}
        except (OSError, ValueError, AttributeError):
            return [], False, ""
    else:
        opts, source = embedded_runtimeconfig(main), f"the runtimeconfig inside {main.name}"
    if opts is not None:
        wpf = uses_wpf(main.with_suffix(".dll"), main)
        if "includedFrameworks" in opts:
            return [], wpf, ""
        fws = opts.get("frameworks") or ([opts["framework"]] if isinstance(opts.get("framework"), dict) else [])
        names = {str(f.get("name", "")): str(f.get("version", "")) for f in fws if isinstance(f, dict)}
        for fw, prefix in (("Microsoft.WindowsDesktop.App", "dotnetdesktop"), ("Microsoft.NETCore.App", "dotnet")):
            if fw in names:
                major = int(m.group(1)) if (m := re.match(r"(\d+)", names[fw])) else 0
                if major not in DOTNET_MAJORS:
                    return [], wpf, f"needs {fw} {names[fw]}, which is older than any .NET debpak can install"
                verb = f"{prefix}{major}"
                why = f"needs {fw} {names[fw]} (from {source}), so the first start installs {verb}"
                if (wmi := uses_wmi(main)):
                    return [verb, "dotnet48"], wpf, why + f", and dotnet48 too: {wmi}"
                return [verb], wpf, why
        return [], wpf, ""
    if is_dotnet and uses_wpf(main):
        return (["dotnet48"], True, "is a WPF program for .NET Framework, whose WPF wine-mono only partly "
                "implements, so the first start installs dotnet48")
    if is_dotnet and ("System.Windows.Forms", "PropertyGrid") in dotnet_type_refs(main):
        return (["dotnet48"], False, "is a WinForms program with a PropertyGrid, which wine-mono draws with "
                "black boxes over its labels, so the first start installs dotnet48")
    if is_dotnet and (tool := obfuscator(main)):
        return (["dotnet48"], False, f"is obfuscated with {tool}, whose code wine-mono rejects (\"Invalid IL "
                "code\"), so the first start installs dotnet48")
    if is_dotnet and (mixed := mixed_mode_assembly(main)):
        return (["dotnet48"], False, f"loads {mixed.name}, a mixed-mode C++/CLI assembly, which wine-mono can't "
                "run, so the first start installs dotnet48")
    if not is_dotnet and (where := carries_pythonnet(main)):
        return (["dotnet48"], False, f"is a Python program that {where}, which runs .NET Framework code (pywebview's "
                "Windows Forms window) and fails on wine-mono's assemblies, so the first start installs dotnet48")
    return [], False, ""


# pythonnet's own assembly, which a frozen Python program carries to reach .NET
PYTHONNET = b"Python.Runtime.dll"


def carries_pythonnet(main: Path, limit: int = 4000) -> str:
    """Say where a Python program carries pythonnet, which runs on the .NET Framework; "" if it doesn't.

    Creallo Atlas, frozen by PyInstaller, opens its window with pywebview,
    whose Windows backend loads System.Windows.Forms through pythonnet. On
    wine-mono that stopped at "System.BadImageFormatException: Invalid Image:
    ...\\wine-mono-10.4.1\\lib\\mono\\4.5\\System.Windows.Forms.dll", an "Unhandled
    exception in script" box; pythonnet picks the .NET Framework (netfx) on
    Windows unless told otherwise. A onedir build has Python.Runtime.dll in its
    folder (pythonnet/runtime/), a onefile build names it in the archive at
    the end of the .exe.
    """
    n = 0
    for _dir, _subdirs, names in os.walk(main.parent):
        if any(f.lower() == PYTHONNET.decode().lower() for f in names):
            return f"carries pythonnet ({PYTHONNET.decode()})"
        n += len(names)
        if n > limit:
            break
    try:
        with open(main, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - (4 << 20)))
            tail = fh.read()
    except OSError:
        return ""
    if PYTHONNET in tail and re.search(rb"(?i)python3\d+t?\.dll", tail):
        return f"carries pythonnet ({PYTHONNET.decode()} in its archive)"
    return ""


# the .NET Framework's own DLL that System.Management loads, on modern .NET too, to reach WMI
WMI_NATIVE = "wminet_utils.dll"


def uses_wmi(main: Path, limit: int = 400) -> str:
    """Say what shows a modern .NET program reaches WMI through System.Management; "" if nothing does.

    System.Management loads wminet_utils.dll from the .NET Framework's folder
    (C:\\windows\\Microsoft.NET\\Framework64\\v4.0.30319) even on .NET 8, and only
    the real Framework has it: AuthenticatorChooser, a .NET 8 single-file
    program, asked WMI for the Windows version at start and stopped at "The
    type initializer for 'System.Management.WmiNetUtilsHelper' threw an
    exception" (Failed to load required native library ... wminet_utils.dll).
    The name is in System.Management.dll's strings, beside the program or inside
    a single-file program's .exe.
    """
    try:
        beside = sorted(p for p in main.parent.iterdir() if p.suffix.lower() == ".dll" and p.is_file())[:limit]
    except OSError:
        beside = []
    marks = (WMI_NATIVE.encode(), WMI_NATIVE.encode("utf-16-le"))
    for f in [main] + [p for p in beside if p.name.lower() == "system.management.dll"]:
        try:
            if f.stat().st_size > 512 << 20:
                continue
            data = f.read_bytes()
        except OSError:
            continue
        if any(m in data for m in marks):
            return (f"{f.name} " + ("carries" if f == main else "is") + " System.Management, which loads the .NET "
                    f"Framework's {WMI_NATIVE} to reach WMI")
    return ""


def mixed_mode_assembly(main: Path, limit: int = 400) -> Path | None:
    """Return the program or a DLL beside it that is a mixed-mode (C++/CLI) .NET assembly, or None.

    Such an assembly holds native code next to its .NET code, and its CLR header
    lacks the IL-only flag. wine-mono can't load one ("field __ImageBase in
    <Module> should have RVA data, but hasn't"), which left Snagit's editor
    without a window; the real .NET Framework can.
    """
    from .pe import PeError, read_pe
    try:
        files = [main] + sorted(p for p in main.parent.iterdir() if p.suffix.lower() == ".dll" and p.is_file())
    except OSError:
        return None
    for f in files[:limit]:
        try:
            info = read_pe(f)
        except (PeError, OSError, ValueError):
            continue
        if info.is_dotnet and not info.clr_flags & 1:
            return f
    return None


# what obfuscators leave in a .NET program, as names (ASCII) or strings (UTF-16): Fiddler Classic
# carries SmartAssembly's attributes, S3 Browser Babel's virtual machine ("babelvm"), and wine-mono
# fails on both ("Invalid IL code", "babel e3 ... NotImplementedException")
OBFUSCATORS = {"SmartAssembly": (b"SmartAssembly.Attributes", b"SmartAssembly.HouseOfCards"),
               "Babel": (b"BabelObfuscatorAttribute", b"babelvm"),
               "ConfuserEx": (b"ConfusedByAttribute",),
               "Dotfuscator": (b"DotfuscatorAttribute",),
               "Crypto Obfuscator": (b"CryptoObfuscator",),
               "Agile.NET": (b"AgileDotNetRT",),
               "Xenocode": (b"XenocodeRT",)}


def obfuscator(exe: Path) -> str | None:
    """Return the obfuscator a .NET program was run through, by what it leaves behind, or None."""
    try:
        data = exe.read_bytes()
    except OSError:
        return None
    for tool, marks in OBFUSCATORS.items():
        if any(m in data or m.decode().encode("utf-16-le") in data for m in marks):
            return tool
    return None


def python_needs_ucrt(main: Path, files: list[Path]) -> int | None:
    """Return the minor version of the Python the program runs on, when Wine's C runtime breaks it; else None.

    GAM, frozen by PyInstaller on Python 3.15, ended at once with "ValueError:
    Invalid format string" from calendar.py, which arrow imports: Python 3.15's
    calendar module asks strftime for "%OB" (the standalone month name) as it is
    imported, and catches the error only where it asks, not where it uses the
    names. Windows' ucrtbase.dll ignores the O, Wine's rejects the format, and
    with Microsoft's ucrtbase.dll GAM runs. The Python is told by its DLL
    (python315.dll, in a onedir build or beside the program), or, in a onefile
    build, by the name of that DLL in the archive at the end of the .exe.
    """
    found = [int(m.group(1)) for f in files if (m := PYTHON_DLL.fullmatch(f.name.encode()))]
    if not found:
        try:
            with open(main, "rb") as fh:
                fh.seek(0, 2)
                fh.seek(max(0, fh.tell() - (256 << 10)))
                tail = fh.read()
        except OSError:
            tail = b""
        found = [int(m.group(1)) for m in PYTHON_DLL.finditer(tail)]
    py = max(found, default=0)
    return py if py >= UCRT_PYTHON else None


def uses_mfc_toolbars(exe: Path) -> bool:
    """Return True if the program is built on MFC's control bars (CToolBar, CReBar, CStatusBar).

    MFC registers their window class as AfxControlBar plus its version, so the
    name is in every program that has them, as UTF-16 in Unicode builds and as
    ASCII in the others, whether MFC is linked in or comes from mfc140u.dll.
    """
    try:
        data = exe.read_bytes()
    except OSError:
        return False
    return b"AfxControlBar" in data or "AfxControlBar".encode("utf-16-le") in data


def symbol_fonts_named(files: list[Path]) -> list[str]:
    """Return the Windows-only symbol fonts (SYMBOL_FONT_STANDINS) that any of these files names.

    Programs pass the family name to GDI or GDI+ as a string, which is in the
    .exe or .dll as UTF-16 (or ASCII in ANSI builds and some resources).
    """
    found = []
    for name in SYMBOL_FONT_STANDINS:
        forms = (name.encode("utf-16-le"), name.encode("ascii"))
        for f in files:
            try:
                data = f.read_bytes()
            except OSError:
                continue
            if any(form in data for form in forms):
                found.append(name)
                break
    return found


def keeps_settings_beside(exe: Path) -> str | None:
    """Return the file that shows a program saves its settings next to its .exe, or None.

    Portable programs ship a settings file named like the program (Notepad3.ini
    beside Notepad3.exe) or a marker such as portable.ini or portable.txt, and
    fail with "access denied" when that folder is read-only.
    """
    try:
        names = sorted(p.name for p in exe.parent.iterdir() if p.is_file())
    except OSError:
        return None
    for n in names:
        low = n.lower()
        if low == exe.stem.lower() + ".ini" or re.match(r"(?i)^(portable|_portable)(\.[a-z]+)?$", n) \
                or low.endswith(".portable"):
            return n
    return None


# what Chromium needs to start under Wine. Its sandbox is built on Windows job objects and
# restricted tokens that Wine doesn't enforce, and the sandboxed renderers die at start; its GPU
# process often crashes on Wine's Direct3D and Chromium then quits ("GPU process isn't usable"),
# so it draws in software in the main process instead
CHROMIUM_WINE_ARGS = ("--no-sandbox", "--disable-gpu", "--disable-gpu-sandbox", "--in-process-gpu")
ELECTRON_RESOURCES = ("resources/app.asar", "resources/electron.asar", "resources/default_app.asar",
                      "resources/app/package.json")


def chromium_program(exe: Path) -> str | None:
    """Return what shows the program is Electron (or another Chromium shell taking its switches), or None.

    An Electron app keeps resources/app.asar beside its .exe; a Chromium build
    has chrome_100_percent.pak there. A CEF app (libcef.dll) has the .pak too,
    but its own .exe decides which switches reach Chromium, and one that takes
    arguments as file names would be handed --no-sandbox as a file to open, so
    CEF apps are left alone.
    """
    here = exe.parent
    for rel in ELECTRON_RESOURCES:
        if (here / rel).is_file():
            return f"{rel} beside {exe.name}"
    from .winres import version_strings
    try:
        v = version_strings(exe)
    except (OSError, ValueError):
        v = {}
    for key in ("ProductName", "FileDescription", "InternalName", "OriginalFilename"):
        if re.search(r"\bElectron\b", str(v.get(key, ""))):
            return f"its {key} is {str(v[key])!r}"
    if (here / "chrome_100_percent.pak").is_file() and not (here / "libcef.dll").is_file():
        return f"chrome_100_percent.pak beside {exe.name}"
    return None


def plan(pkg: Package, args) -> Plan:
    """Work out a Wine conversion: entry point, architecture, Wine check, permissions, notes and blockers."""
    from .foreign import pick_main_exe
    from .pe import PeError, read_pe
    pl = Plan(pkg, "wine")
    prog = pkg.extra["program_dir"]
    if getattr(args, "exec", None):
        main = pick_main_exe(prog, args.exec)
        if main is None:
            pl.blockers.append(f"--exec {args.exec}: no such program in the package")
        else:
            pkg.extra["main_exe"] = main.relative_to(prog).as_posix()
            pl.notes = [n for n in pl.notes if "(guessed; override with --exec)" not in n]
    main_rel = pkg.extra["main_exe"]
    base_version, branch = wine_branch(args)
    pl.data.update(base_version=base_version, branch=branch)
    try:
        info = read_pe(prog / main_rel)
    except (PeError, OSError, ValueError) as e:
        info = None
        pl.blockers.append(f"{main_rel} can't be read as a Windows program ({e})")
    pl.details += [("from", f"Windows ({pkg.extra.get('unpacked_by')})"),
                   ("program", main_rel + (f" ({info.machine}, {info.subsystem})" if info else "")),
                   ("runs on", f"{WINE_BASE}//{base_version} (org.freedesktop.Platform//{branch})")]
    if pkg.extra.get("company"):
        pl.details.insert(1, ("publisher", pkg.extra["company"]))
    if info:
        if info.problems:
            pl.notes.append(f"parts of {main_rel}'s tables couldn't be read ({'; '.join(info.problems)[:200]}), "
                            "so its imports were only partly checked")
        if info.subsystem == "console":
            pl.data["console"] = True
            pl.notes.append(f"{Path(main_rel).name} is a console program: started from a terminal it runs there, "
                            "otherwise in a console window of Wine's own (wineconsole)")
        if info.machine == "i386":
            pl.notes.append("32-bit program; Wine's WoW64 mode runs it in the 64-bit Wine")
        elif info.machine == "x86_64" and uses_mfc_toolbars(prog / main_rel):
            # Wine's TB_GETBUTTON fills in only 2 of a 64-bit TBBUTTON's 6 reserved bytes, so when MFC's
            # CToolBar compares a button with what it read back, leftover bytes make it look changed.
            # MFC then deletes the button and adds it again with the text pointer it read, which the
            # delete just freed: WinMerge's menu bar lost every label but one. 32-bit TBBUTTONs have
            # only the 2 bytes Wine fills in.
            pl.notes.append(f"{Path(main_rel).name} is a 64-bit MFC program with toolbars. Under Wine, the "
                            "labels on its toolbar buttons (and on a menu bar built as a toolbar) can come out "
                            "blank; the program's 32-bit build doesn't have this problem")
        elif info.machine not in ("x86_64", "i386"):
            pl.blockers.append(f"{main_rel} is built for {info.machine}; the Wine base app is x86_64 only")
        if info.is_dotnet:
            pl.notes.append(".NET program: it runs on wine-mono, which the Wine base app includes. Programs "
                            "that need the real .NET runtime may not work")

    # a Windows service the installer would set up, whose program is one of the program's own: under
    # Wine nothing installs or starts it, and a Flatpak can't run one for the system (EA app's
    # EADesktop.exe waits on EABackgroundService)
    own = {f.name.lower() for f in prog.rglob("*.exe")} if pkg.extra.get("services") else set()
    for svc in pkg.extra.get("services", []):
        if svc.get("exe", "").lower() in own:
            pl.blockers.append(f"{pkg.extra.get('display_name') or Path(main_rel).stem} relies on {svc['name']}, a "
                               f"Windows system service its installer sets up ({svc['exe']}), which can't be "
                               "installed or run in a Flatpak")
            break
    if (drivers := pkg.extra.get("printer_drivers")):
        # pdfFactory's installer, taken for a portable program, ran on with no window
        pl.blockers.append(f"{Path(pkg.path).name} installs a printer driver ({drivers[0]}, of Windows' Printer "
                           "class): what it sets up is a virtual printer that Windows' print spooler loads, which "
                           "can't be installed in a Flatpak or run under Wine")
    files = _pe_files(prog)
    dlls: set[str] = set()
    for f in files:
        try:
            dlls |= {i.dll.lower() for i in read_pe(f).imports}
        except (PeError, OSError, ValueError):
            continue
    perms = [Permission("--share=ipc", "X11 shared memory"),
             Permission("--socket=x11", "Wine draws windows through X11"),
             Permission("--device=dri", "OpenGL, Vulkan and Direct3D through the GPU"),
             Permission("--socket=pulseaudio", "Wine's sound output"),
             # without it Flatpak refuses modify_ldt, which Wine needs for 32-bit code, so 32-bit
             # programs (and the x86 runtime installers winetricks runs) fail with "ShellExecuteEx failed"
             Permission("--allow=multiarch", "32-bit Windows code (the Wine base app sets this too)")]
    net = sorted(dlls & NETWORK_DLLS)
    runtimes = list(dict.fromkeys(getattr(args, "wine_runtime", None) or []))
    bad = [v for v in runtimes if not VERB_RE.match(v)]
    if bad:
        pl.blockers.append(f"--wine-runtime {bad[0]!r} isn't a winetricks verb name (like vcrun2022 or corefonts)")
    runtimes = [v for v in runtimes if v not in bad]
    # "wine-mono" isn't a winetricks verb: it keeps the program on the base app's wine-mono, for
    # programs that the real .NET Framework breaks under Wine (WinCompose's culture lookups do)
    mono = MONO in runtimes
    runtimes = [v for v in runtimes if v != MONO]
    auto, wpf, why = dotnet_needs(prog / main_rel, bool(info and info.is_dotnet))
    if mono:
        if auto:
            pl.notes.append(f"{Path(main_rel).name} runs on wine-mono (--wine-runtime {MONO}), so "
                            f"{', '.join(auto)} isn't installed")
    else:
        if not any(v.startswith("dotnet") for v in runtimes):
            runtimes += [v for v in auto if v not in runtimes]
        if why:
            pl.notes.append(f"{Path(main_rel).name} {why}")
    if wpf:
        if "corefonts" not in runtimes:
            runtimes.append("corefonts")
        pl.notes.append("WPF program: the launcher turns off WPF's hardware acceleration (Wine draws WPF's "
                        "Direct3D 9 badly), and corefonts is installed, since WPF fails on missing fonts")
    # what the program and the DLLs it ships import, less the DLLs it ships
    shipped = {f.name.lower() for f in files}
    if info and info.machine == "x86_64":
        for dll in sorted({i.dll.lower() for i in info.imports} - shipped):
            if (verb := wine_lacks(dll)) in ONLY_32BIT_VERBS:
                pl.blockers.append(f"{Path(main_rel).name} is a 64-bit program that imports {dll}, which Wine "
                                   f"doesn't have and winetricks' {verb} installs only for 32-bit programs, so it "
                                   "can't start (Wine exits with status 53); convert the program's 32-bit build")
                break
    for dll in sorted(dlls - shipped):
        verb = wine_lacks(dll)
        if verb and verb not in runtimes:
            runtimes.append(verb)
            pl.notes.append(f"the program imports {dll}, which Wine doesn't have, so {verb} is installed")
    from .winrt import survey
    rt = survey(prog / main_rel, files, dlls)
    for verb in rt.verbs:
        if verb not in runtimes:
            runtimes.append(verb)
            pl.notes.append(f"the program imports {rt.why[verb]} without shipping it, so the first start installs "
                            f"{verb}, the runtime it was built for, in place of Wine's own version")
    if (py := python_needs_ucrt(prog / main_rel, files)) and UCRTBASE not in runtimes:
        runtimes.append(UCRTBASE)
        pl.notes.append(f"the program runs on Python 3.{py}, whose calendar module asks the C runtime for a format "
                        f"Wine's ucrtbase.dll rejects, so Microsoft's ucrtbase.dll is installed ({UCRTBASE})")
    extra_data = getattr(args, "mode", "bundle") == "extra-data"
    if info and info.machine == "x86_64" and not extra_data and (icu := icu_imports(files)):
        from . import icunames
        pl.data["icu"] = icu
        who = sorted(icu)
        pl.notes.append(f"the program imports {', '.join(who)}, Windows' own ICU, which Wine doesn't have, so ICU "
                        f"{icunames.VERSION} (the Unicode Consortium's Windows build, about 30 MB) is put beside it, "
                        f"with {', '.join(who)} passing its functions on to it")
    if info and info.machine in ("x86_64", "i386"):
        _missing_dlls(pl, prog / main_rel, files, info.machine, base_version, runtimes,
                      bool(getattr(args, "wine_runtime", None)), getattr(args, "mode", "bundle") == "extra-data",
                      pkg.extra.get("companions") or [])
    pl.data["runtimes"] = runtimes
    pl.data["wpf"] = wpf
    pl.data["core_fonts"] = rt.core_fonts
    pl.data["cjk_fonts"] = bool(rt.cjk)
    if rt.cjk:
        pl.notes.append(f"{Path(main_rel).name} shows Chinese, Japanese or Korean text ({rt.cjk}), so the launcher has "
                        "Wine's CJK fonts and dialog fonts use a CJK font the sandbox has")
    pl.data["webview2"] = bool(rt.webview2)
    if rt.webview2:
        from .winrt import WEBVIEW2_COST
        pl.notes.append(f"{Path(main_rel).name} draws with Microsoft's WebView2 ({rt.webview2}), whose installer fails "
                        "under the Wine base app, so the first start downloads Microsoft's Fixed Version runtime "
                        f"({WEBVIEW2_COST}) into the Wine prefix and registers it there")
    if (quick := next((f for f in files if f.name.lower() == "qt6quick.dll"), None)):
        pl.data["qt_quick"] = True
        pl.notes.append(f"the program draws with Qt 6's Qt Quick ({quick.name}), which the launcher has draw with "
                        "OpenGL rather than through Wine's Direct3D 11 (QSG_RHI_BACKEND=opengl)")
    if (sqm := names_sqm_key(prog)):
        pl.data["machine_id"] = True
        pl.notes.append(f"{sqm} reads the machine ID Windows keeps in HKLM\\{SQM_KEY}, which Wine's prefix lacks, "
                        "so the first start makes one there")
    fonts = symbol_fonts_named(files)
    pl.data["symbol_fonts"] = fonts
    for font in fonts:
        pl.notes.append(f"the program draws with the {font} font, which only Windows has, so the launcher has Wine "
                        f"use {SYMBOL_FONT_STANDINS[font]} for it (GDI+ draws nothing with a missing font)")
    if net:
        perms.append(Permission("--share=network", f"imports {net[0]}"))
    elif runtimes:
        perms.append(Permission("--share=network", "winetricks downloads the Windows runtimes on first run"))
    elif rt.webview2:
        perms.append(Permission("--share=network", "the first run downloads WebView2's runtime"))
    if runtimes:
        pl.details.append(("runtimes", " ".join(runtimes) + " (installed by winetricks on first run)"))
        pl.notes.append("the first start installs " + ", ".join(runtimes) + " into the Wine prefix, which needs "
                        "the network and can take several minutes")
    # what's left of RUNTIME_FOR once the plan's verbs are in: gdiplus, which is a download of most of a gigabyte
    wanted = {verb: dll for verb, dll in rt.suggest.items() if verb not in runtimes}
    if info and info.is_dotnet and not mono and not any(v.startswith("dotnet") for v in runtimes) \
            and not (prog / main_rel).with_name(Path(main_rel).stem + ".runtimeconfig.json").is_file():
        wanted.setdefault("dotnet48", "the .NET runtime (if wine-mono isn't enough)")
    for verb, why in wanted.items():
        pl.notes.append(f"imports {why} without shipping it: if the program won't start, convert with "
                        f"--wine-runtime {verb}")
    if getattr(args, "permissive", False):
        perms.append(Permission("--filesystem=home", "--permissive"))
    else:
        perms += [Permission("--filesystem=xdg-documents", "Wine's file dialogs can't use portals, so the "
                                                          "program only sees folders it's given"),
                  Permission("--filesystem=xdg-download", "same: Downloads")]
    pl.permissions = perms

    indexes = _cached_indexes()
    if indexes:
        from .wine import scan
        result = scan(prog, indexes, pkg.extra.get("display_name"))
        rep = result.report
        pl.details.append(("Wine check", f"{rep.verdict} (against {rep.provider})"))
        if rep.worst == "fatal":
            fatal = [g.key for g in rep.by_tier("fatal")][:8]
            pl.blockers.append("Wine lacks what the program needs to start: " + ", ".join(fatal)
                               + (" ..." if len(rep.by_tier("fatal")) > 8 else "")
                               + " (`winegap scan` gives the full report)")
        elif rep.worst in ("crash", "degraded"):
            pl.notes.append(f"Wine check: {rep.verdict}; `winegap scan` lists them")
    else:
        pl.notes.append("no Wine index is cached, so the program's imports weren't checked against Wine "
                        "(`winegap index` makes one)")
    if (ini := FOLDER_INDEXERS.get(Path(main_rel).name.lower())):
        pl.data["writable"] = True
        pl.data["folder_index"] = ini
        pl.notes.append(f"{Path(main_rel).name} indexes NTFS volumes, which Wine doesn't have; on first start "
                        f"the launcher writes {ini} so it indexes Documents and Downloads instead, and it runs "
                        "from a copy in the Wine prefix so it can keep that file")
    chromium = chromium_program(prog / main_rel)
    if chromium:
        pl.data["chromium_args"] = list(CHROMIUM_WINE_ARGS)
        pl.notes.append(f"{Path(main_rel).name} is an Electron or Chromium program ({chromium}); under Wine "
                        f"Chromium's sandbox and GPU process don't start, so it's started with "
                        f"{' '.join(CHROMIUM_WINE_ARGS)}")
    marker = None if getattr(args, "writable", False) else keeps_settings_beside(prog / main_rel)
    if marker:
        pl.data["writable"] = True
        pl.notes.append(f"{marker} beside the program shows it saves settings next to its .exe, so it runs "
                        "from a copy in the Wine prefix, as with --writable")
    elif not getattr(args, "writable", False):
        pl.notes.append("the program runs from read-only /app; if it saves files next to its .exe, convert "
                        "with --writable")
    return pl


def _missing_dlls(pl: Plan, main: Path, files: list[Path], machine: str, base_version: str,
                  runtimes: list[str], runtimes_given: bool, extra_data: bool = False,
                  companions: list[str] | None = None) -> None:
    """Deal with the DLLs the program needs to start that neither it nor the Wine base app has.

    One that another package of its installer installs (foreign.companion_dll:
    AirPort Utility's dnssd.dll, from Bonjour.msi beside AirPort.msi) is put
    beside the program, as installing both would have made it reachable. One
    Windows split out of another that Wine has (SPLIT_FROM: MFCORE.dll, from
    mf.dll) gets a DLL that passes its functions on to that one. One
    with a stand-in (STANDINS) gets it, beside the program. Any other
    stops the conversion: Wine exits with status 53 before the program runs.
    QField imports icu.dll, the ICU that Windows 10 carries, and MFCORE.dll, a
    part of Media Foundation, neither of which Wine has or winetricks installs,
    and was built, installed and started for a minute and a half to find that
    out. That's only said when the installed base app's own DLLs show what it
    lacks, and as a note when Windows runtimes were asked for, since one of
    them may bring the DLL. In extra-data mode the program's folder is made at
    install time, so there's nowhere to put a stand-in.
    """
    from .foreign import companion_dll
    base = wine_base_dlls(base_version, machine)
    lacking, standins, taken, split = [], {}, {}, {}
    for low, e in sorted(startup_imports(main, files).items()):
        if (base is not None and low in base) or low.startswith(("api-ms-", "ext-ms-")) or wine_lacks(low) \
                or any(re.match(pat, low) for pat, _verb in RUNTIME_FOR) \
                or low in {d.lower() for d in pl.data.get("icu") or {}}:
            continue
        if low in SPLIT_FROM and not extra_data and (base is None or f"{SPLIT_FROM[low][0]}.dll" in base):
            target, what = SPLIT_FROM[low]
            split[e["dll"]] = sorted(e["names"])
            pl.notes.append(f"{', '.join(e['by'])} imports {e['dll']}, {what}, and Wine has its functions in "
                            f"{target}.dll only, so a {e['dll']} that passes them on to {target}.dll is put beside "
                            "the program")
        elif base is not None and companions and not extra_data \
                and (found := companion_dll(companions, e["dll"], machine)):
            dll, msi = found
            taken[dll.name] = str(dll)
            pl.notes.append(f"{', '.join(e['by'])} imports {e['dll']}, which {msi}, another package its installer "
                            f"installs, has, so that {dll.name} is put beside the program")
        elif low in STANDINS and machine == "x86_64" and not extra_data:
            standins[e["dll"]] = sorted(e["names"])
            _value, _special, what, says = STANDINS[low]
            pl.notes.append(f"{', '.join(e['by'])} imports {e['dll']}, which Wine lacks for {what}, so a stand-in "
                            f"is put beside the program whose functions say {says}: it starts, without them")
        elif base is not None:
            lacking.append(e)
    pl.data["standins"] = standins
    pl.data["companion_dlls"] = taken
    pl.data["split_dlls"] = {"machine": machine, "dlls": split} if split else {}
    if lacking:
        names = ", ".join(e["dll"] for e in lacking[:6]) + (" ..." if len(lacking) > 6 else "")
        who = ", ".join(dict.fromkeys(b for e in lacking for b in e["by"]))[:120]
        msg = (f"{who} needs {names} to start, which neither the program nor Wine has, so Wine stops it before "
               "it runs (status 53, \"DLL not found\")")
        if runtimes_given:
            pl.notes.append(msg + f"; one of the runtimes asked for ({' '.join(runtimes)}) may bring it")
        else:
            pl.blockers.append(msg)


# Windows' own ICU, which Wine doesn't have: icu.dll since Windows 10 1903, icuuc.dll and icuin.dll before
ICU_DLLS = ("icu.dll", "icuuc.dll", "icuin.dll")


def icu_imports(files: list[Path]) -> dict[str, list[str]]:
    """Return what the program's files import from Windows' ICU (ICU_DLLS), by DLL as imported, unless they ship it.

    Premiere Companion's PyQt6 holds Qt6Core.dll, which imports icuuc.dll and
    which Python loads, so no import of the program's own leads to it.
    """
    from .pe import PeError, read_pe
    shipped = {f.name.lower() for f in files}
    out: dict[str, set[str]] = {}
    for f in files:
        try:
            imports = read_pe(f).imports
        except (PeError, OSError, ValueError):
            continue
        for i in imports:
            if i.dll.lower() in ICU_DLLS and i.dll.lower() not in shipped and i.name:
                out.setdefault(next((k for k in out if k.lower() == i.dll.lower()), i.dll), set()).add(i.name)
    return {k: sorted(v) for k, v in out.items()}


def icu_forwarders(imports: dict[str, list[str]]) -> dict[str, bytes]:
    """Return DLLs named as Windows' ICU (file name -> contents) that forward to ICU's own build (icunames).

    Each function the program imports goes to the one of icuuc78.dll and
    icuin78.dll that has it, under its versioned name (u_strlen to
    icuuc78.u_strlen_78); one neither has (a function Windows' ICU has that
    ICU 78 dropped) is a stub that returns 0.
    """
    from . import icunames
    from .pe_write import PeSpec, build_pe
    v = icunames.VERSION
    out = {}
    for dll, names in imports.items():
        forwards = {n: f"icuuc{v}.{n}_{v}" if n in icunames.UC else f"icuin{v}.{n}_{v}"
                    for n in names if n in icunames.UC or n in icunames.IN}
        out[dll] = build_pe(PeSpec(dll_name=dll, exports=[n for n in names if n not in forwards], forwards=forwards))
    return out


def split_forwarders(split: dict) -> dict[str, bytes]:
    """Return DLLs named as ones Windows split out of another (SPLIT_FROM) that pass their functions on to it.

    split is what _missing_dlls kept: {"machine", "dlls": {name as imported: functions}}.
    """
    from .pe_write import PeSpec, build_pe
    out = {}
    for dll, names in (split.get("dlls") or {}).items():
        target = SPLIT_FROM[dll.lower()][0]
        out[dll] = build_pe(PeSpec(arch=split.get("machine", "x86_64"), dll_name=dll,
                                   forwards={n: f"{target}.{n}" for n in names}))
    return out


def standin_dlls(standins: dict[str, list[str]]) -> dict[str, bytes]:
    """Return the stand-in DLLs (file name -> contents) for STANDINS entries the program imports."""
    from .pe_write import stub_dll
    out = {}
    for dll, names in standins.items():
        value, special, _what, _says = STANDINS[dll.lower()]
        out[dll] = stub_dll(dll, "x86_64", names, mode="value", value=value, values=special)
    return out


# A prefix whose first setup was cut short (by a check, or a user closing the first start) has Wine's
# start of it, and maybe its registry, but no kernel32.dll in system32, and Wine can neither run a
# program in it nor set it up again: Intel's BCT, like MediaMonkey and DYMO ID before it, said only
# "could not load kernel32.dll, status c0000135" on every start after, and wineboot itself ended with
# status 53. Cut short a little later, it has kernel32.dll and Wine's .update-timestamp but not what
# wine.inf registers, and wineboot --init, finding the timestamp current, leaves it so (see
# winrt.PREFIX_DONE): Racemo, MDViewer+, Whisperi and Netstat Cat panicked in RegisterDragDrop
# ("Failed to open RpcSs service"). Such a prefix holds nothing of the user's (no program ever ran in
# it whole), so the launcher removes it and sets it up from nothing; only its own prefix, never one
# WINEPREFIX names. One set up before the launcher wrote PREFIX_DONE is known by wine.inf's services.
PREFIX_REPAIR = (
    "# a prefix whose first setup was cut short (no kernel32.dll, or wine.inf never applied) can't be",
    "# used, and wineboot won't finish it",
    'if [ -n "${OWN_PREFIX-}" ] && { [ -d "$WINEPREFIX/drive_c" ] || [ -e "$WINEPREFIX/.update-timestamp" ]; } \\',
    '        && { [ ! -e "$WINEPREFIX/drive_c/windows/system32/kernel32.dll" ] \\',
    f'             || {{ [ ! -e "$WINEPREFIX/{PREFIX_DONE}" ] '
    f'&& ! grep -qsF \'{PREFIX_SET_UP}\' "$WINEPREFIX/system.reg"; }}; }}; then',
    '    echo "Wine\'s setup was cut short last time; setting it up again..." >&2',
    '    rm -rf "$WINEPREFIX"',
    "fi",
)


# The registry key Windows keeps a machine's telemetry ID in, which Wine's prefix lacks. Flutter's
# device_info_plus reads its MachineId for every program that asks what device it runs on, and throws
# when the key isn't there: Media Remote, a Flutter app, stopped at "Unhandled Exception:
# WindowsException HRESULT(0x80070002): File not found" with no window. A program whose files name
# the key gets it, with a MachineId made up once for the prefix, as Windows makes one at setup
SQM_KEY = "SOFTWARE\\Microsoft\\SQMClient"
SQM_LINES = (
    "# the machine ID Windows keeps for telemetry, which the program reads and Wine has none of (see",
    "# winapp.SQM_KEY)",
    'if [ ! -f "$WINEPREFIX/.debpak-machine-id" ]; then',
    '    id=$(tr "[:lower:]" "[:upper:]" < /proc/sys/kernel/random/uuid)',
    "    # in the 64-bit registry, and in the one 32-bit programs see",
    f"    if wine reg add 'HKLM\\{SQM_KEY}' /v MachineId /t REG_SZ /d \"{{$id}}\" /f >/dev/null 2>&1; then",
    f"        wine reg add 'HKLM\\{SQM_KEY}' /v MachineId /t REG_SZ /d \"{{$id}}\" /reg:32 /f >/dev/null 2>&1",
    '        touch "$WINEPREFIX/.debpak-machine-id"',
    "    fi",
    "fi",
)


def names_sqm_key(root: Path, limit: int = 400 << 20) -> str | None:
    """Return the name of a program file under root that names SQM_KEY, or None.

    The program's .exe and .dll files are looked in, and its .so files too:
    a Flutter app's Dart code is data/app.so, which holds the name in one
    byte to a letter; a Windows program holds it in two (UTF-16) or one.
    """
    import mmap
    tail = SQM_KEY.split("\\", 1)[1]           # "Software" or "SOFTWARE", as the program spells it
    needles = [tail.encode(), tail.encode("utf-16-le")]
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in (".exe", ".dll", ".so") or p.is_symlink() or not p.is_file():
            continue
        try:
            size = p.stat().st_size
            if not 0 < size <= limit:
                continue
            with open(p, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                if any(m.find(n) >= 0 for n in needles):
                    return p.name
        except (OSError, ValueError):
            continue
    return None


# Qt 6's Qt Quick draws through Direct3D 11 on Windows, which Wine turns into OpenGL calls itself; OmaWrite,
# a Qt 6 Quick editor, crashed as it started with a NULL read inside one of Wine's own DLLs ("Unhandled page
# fault on read access to 0000000000000000 at address 00006FFFFB07D096"), the first thing it does being to
# set up its window's Direct3D. Asked for OpenGL, Qt Quick draws with Wine's opengl32, straight onto the
# host's OpenGL, with no Direct3D in between. A user's own choice is kept
QT_QUICK_LINES = (
    "# Qt Quick draws with OpenGL here, not through Wine's Direct3D 11 (see winapp.QT_QUICK_LINES)",
    'export QSG_RHI_BACKEND="${QSG_RHI_BACKEND:-opengl}"',
)


def launcher(pkg: Package, slug: str, main_rel: str, writable: bool, stamp: str,
             runtimes: list[str] | None = None, wpf: bool = False, symbol_fonts: list[str] | None = None,
             folder_index: str | None = None, console: bool = False,
             chromium_args: list[str] | None = None, core_fonts: bool = False, cjk_fonts: bool = False,
             webview2: bool = False, qt_quick: bool = False, machine_id: bool = False) -> str:
    """Return the /app/bin launcher script.

    Paths and names come from the vendor's files, so they're shell-quoted, and
    names in comments are kept to one line.
    """
    name = one_line(pkg.extra.get("display_name", slug)) or slug
    sub = str(Path(main_rel).parent)
    q = shlex.quote
    lines = [
        "#!/bin/sh",
        f"# Generated by debpak: runs {name} under Wine.",
        '[ -n "${WINEPREFIX-}" ] || OWN_PREFIX=1',
        'export WINEPREFIX="${WINEPREFIX:-$XDG_DATA_HOME/wine}"',
        'export WINEDEBUG="${WINEDEBUG:--all}"',
        "# don't let Wine add its own menu entries; the Flatpak has one",
        'export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-winemenubuilder.exe=d}"',
        *(QT_QUICK_LINES if qt_quick else ()),
        *PREFIX_REPAIR,
        'mkdir -p "$WINEPREFIX"',
        'if [ ! -f "$WINEPREFIX/system.reg" ]; then',
        '    echo "Setting up Wine (first run only)..." >&2',
        "    # while this is here a check that started the app waits (see selfcheck.OBSERVER)",
        f'    echo wineboot > "$WINEPREFIX/{INSTALLING}"',
        "    # a registry never saved, its setup done or not: Wine's timestamp alone would have wineboot skip it",
        '    rm -f "$WINEPREFIX/.update-timestamp"',
        f'    wineboot --init >/dev/null 2>&1 && : > "$WINEPREFIX/{PREFIX_DONE}"',
        f'    rm -f "$WINEPREFIX/{INSTALLING}"',
        f'elif [ ! -e "$WINEPREFIX/{PREFIX_DONE}" ]; then',
        "    # set up whole before the launcher marked it so (PREFIX_REPAIR let it be)",
        f'    : > "$WINEPREFIX/{PREFIX_DONE}"',
        "fi",
        f"PROGRAM=/app/opt/{slug}",
    ]
    if runtimes:
        want = " ".join(runtimes)
        # winetricks' .NET Framework verbs set Windows 7 and leave it set, and programs that need
        # Windows 10 refuse to start on it (Playnite: "Windows 7 and Windows 8 are no longer
        # supported"), so the verbs end by setting Windows 10 back, Wine's own default
        winver = "" if WINVER_VERBS & set(runtimes) else " win10"
        modern = [v for v in runtimes if modern_dotnet(v)]
        lines += [
            "# Windows runtimes the program needs, installed once by the Wine base app's winetricks",
            f'RUNTIMES="{want}"',
            f'VERBS="$RUNTIMES{winver}"',
            'if [ "$(cat "$WINEPREFIX/.debpak-runtimes" 2>/dev/null)" != "$VERBS" ]; then',
            '    echo "Installing $RUNTIMES into the Wine prefix (first run only, this can take a while)..." >&2',
            "    # while this is here a check that started the app waits (see selfcheck.OBSERVER)",
            f'    echo "$VERBS" > "$WINEPREFIX/{INSTALLING}"',
            "    # a .NET newer than this winetricks knows (its 20260125 has no dotnetdesktop10) comes from",
            "    # Microsoft's own zips: the .NET runtime, and the desktop one on top for dotnetdesktopN",
            "    known=$(winetricks list-all 2>/dev/null) ok=1 tricks= forced=",
            "    for v in $VERBS; do",
            "        # Wine has a DLL of its own where this verb installs Microsoft's, so winetricks would skip it",
            f'        case $v in {"|".join(sorted(FORCED_VERBS))}) forced="$forced $v"; continue;; esac',
            # the modern .NET verbs only (dotnet48 is the .NET Framework, winetricks' own)
            f"        case $v in {'|'.join(modern) or 'dotnet-none'})",
            "            # winetricks' verb only if it is that .NET's runtime (\"MS .NET Runtime 9.0\"): its dotnet11",
            "            # is the .NET Framework 1.1, which a 64-bit prefix can't take",
            "            # grep reads it all (no -q): quitting early made printf complain of a broken pipe",
            '            if ! printf "%s\\n" "$known" | grep "^$v .*Runtime" >/dev/null; then',
            '                major=$(printf %s "$v" | tr -dc 0-9) dir="$WINEPREFIX/drive_c/Program Files/dotnet"',
            '                parts=dotnet-runtime; [ "${v#dotnetdesktop}" = "$v" ] || parts="$parts windowsdesktop-runtime"',
            '                mkdir -p "$dir"',
            "                for part in $parts; do",
            '                    curl -fsSL -o "$WINEPREFIX/debpak-dotnet.zip" '
            '"https://aka.ms/dotnet/$major.0/$part-win-x64.zip" \\',
            '                        && unzip -oq "$WINEPREFIX/debpak-dotnet.zip" -d "$dir" || ok=',
            "                done",
            '                rm -f "$WINEPREFIX/debpak-dotnet.zip"',
            "                continue",
            "            fi",
            "        esac",
            '        tricks="$tricks $v"',
            "    done",
            "    # shellcheck disable=SC2086  # one argument per verb",
            '    if [ -n "$ok" ] && { [ -z "$tricks" ] || winetricks -q --unattended $tricks >&2; } \\',
            '            && { [ -z "$forced" ] || winetricks -q --unattended --force $forced >&2; }; then',
            '        echo "$VERBS" > "$WINEPREFIX/.debpak-runtimes"',
            "    else",
            "        echo \"Not everything installed; the program may not work. It retries next start.\" >&2",
            "    fi",
            f'    rm -f "$WINEPREFIX/{INSTALLING}"',
            "fi",
        ]
    if wpf:
        lines += [
            "# WPF draws through Direct3D 9, which Wine renders badly; software rendering is slower but works",
            'if [ ! -f "$WINEPREFIX/.debpak-wpf" ]; then',
            "    wine reg add 'HKCU\\Software\\Microsoft\\Avalon.Graphics' /v DisableHWAcceleration "
            "/t REG_DWORD /d 1 /f >/dev/null 2>&1 && touch \"$WINEPREFIX/.debpak-wpf\"",
            "fi",
        ]
    if symbol_fonts:
        q_links = q("\\0".join(SYMBOL_FONT_LINKS))
        regs = [f"wine reg add 'HKCU\\Software\\Wine\\Fonts\\Replacements' /v {q(font)} /t REG_SZ "
                f"/d {q(SYMBOL_FONT_STANDINS[font])} /f" for font in symbol_fonts]
        regs += [f"wine reg add 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\FontLink\\SystemLink' "
                 f"/v {q(face)} /t REG_MULTI_SZ /d {q_links} /f" for face in SYMBOL_FONT_LINKED_FACES]
        # the marker holds what was set, so a launcher that sets something else sets it again
        mark = q(" ".join(symbol_fonts) + " 1")
        lines += [
            "# Windows-only symbol fonts the program draws with: Wine uses runtime fonts in their place",
            f'if [ "$(cat "$WINEPREFIX/.debpak-fonts" 2>/dev/null)" != {mark} ]; then',
            "    if " + " >/dev/null 2>&1 &&\n       ".join(regs) + " >/dev/null 2>&1; then",
            f'        echo {mark} > "$WINEPREFIX/.debpak-fonts"',
            "    fi",
            "fi",
        ]
    if core_fonts or cjk_fonts:
        lines += font_lines(cjk_fonts)
    if webview2:
        lines += webview2_lines()
    if machine_id:
        lines += SQM_LINES
    if writable:
        lines += [
            "# The program writes next to its .exe, so it runs from a copy in the prefix.",
            "# Files changed since the last copy (settings, saves) are never overwritten.",
            f'DEST="$WINEPREFIX/drive_c/Program Files/{slug}"',
            f'if [ "$(cat "$DEST/.debpak-version" 2>/dev/null)" != {q(stamp)} ]; then',
            f'    echo {q("Copying " + name + " into the Wine prefix...")} >&2',
            '    mkdir -p "$DEST"',
            "    # empty folders too: a program may count on one its installer leaves empty (vimacc's log\\)",
            '    (cd "$PROGRAM" && find . -type d) | while IFS= read -r d; do mkdir -p "$DEST/$d"; done',
            '    (cd "$PROGRAM" && find . -type f) | while IFS= read -r f; do',
            '        if [ -e "$DEST/$f" ]; then',
            '            sum=$(cd "$DEST" && md5sum "$f")',
            '            grep -qxF "$sum" "$DEST/.debpak-sums" 2>/dev/null || continue',
            "        fi",
            '        mkdir -p "$(dirname "$DEST/$f")"',
            '        cp -p "$PROGRAM/$f" "$DEST/$f"',
            "    done",
            '    (cd "$PROGRAM" && find . -type f -exec md5sum {} +) > "$DEST/.debpak-sums"',
            f'    echo {q(stamp)} > "$DEST/.debpak-version"',
            "fi",
            'PROGRAM="$DEST"',
        ]
    if folder_index:
        ini = q(folder_index)
        lines += [
            "# It can't index NTFS volumes under Wine, so it indexes the folders the sandbox grants;",
            "# the file is only written when it's missing, so folders the user sets later stay",
            f'if [ ! -f "$PROGRAM"/{ini} ]; then',
            '    folders=""',
            '    for d in "$(xdg-user-dir DOCUMENTS 2>/dev/null || echo "$HOME/Documents")" \\',
            '             "$(xdg-user-dir DOWNLOAD 2>/dev/null || echo "$HOME/Downloads")"; do',
            '        [ -d "$d" ] || continue',
            "        # in the file's quoted lists a backslash and a quote are escaped with a backslash",
            '        w=$(winepath -w "$d" 2>/dev/null | sed \'s/\\\\/\\\\\\\\/g; s/"/\\\\"/g\') || continue',
            '        folders="${folders:+$folders,}\\"$w\\""',
            "    done",
            '    if [ -n "$folders" ]; then',
            f'        printf \'[Everything]\\r\\nfolders=%s\\r\\n\' "$folders" > "$PROGRAM"/{ini}',
            "    fi",
            "fi",
        ]
    lines += [
        "# Windows programs expect Windows paths: convert arguments that name existing files.",
        'for a; do',
        "    shift",
        '    if [ -e "$a" ]; then a=$(winepath -w "$a" 2>/dev/null || printf "%s" "$a"); fi',
        '    set -- "$@" "$a"',
        "done",
        "# many programs look for their files in the current folder",
        f'cd "$PROGRAM"/{q(sub)} || exit 1' if sub != "." else 'cd "$PROGRAM" || exit 1',
    ]
    if console:
        # Far Manager is a console program: started from the menu, Wine gave it no window at all
        lines += [
            "# a console program: in the terminal it was started from, or else in a console window of Wine's own",
            "WINE=wine",
            "# DEBPAK_WINECONSOLE=0 keeps it out of the console window, so debpak's check can read what it prints",
            '[ -t 0 ] || [ -t 1 ] || [ "${DEBPAK_WINECONSOLE-}" = 0 ] || WINE=wineconsole',
            f'"$WINE" "$PROGRAM"/{q(main_rel)} "$@"',
        ]
    elif chromium_args:
        # DEBPAK_CHROMIUM_ARGS set (even empty) replaces them, to try the GPU or the sandbox again
        lines += [
            "# an Electron or Chromium program: Chromium's sandbox and GPU process don't start under Wine",
            f'CHROMIUM_ARGS="${{DEBPAK_CHROMIUM_ARGS-{" ".join(chromium_args)}}}"',
            "# shellcheck disable=SC2086  # one argument per switch",
            f'wine "$PROGRAM"/{q(main_rel)} $CHROMIUM_ARGS "$@"',
        ]
    elif webview2:
        # Wine's RevokeDragDrop releases a drop target that WebView2's browser process registered on
        # its own window as if it were the caller's, and a Tauri program (wry revokes them all to put
        # its own in) crashed with an access violation on some starts and not others, by which
        # process got there first: Netstat Cat did on about one start in four
        lines += [
            "# a crash as it starts (status 5, an access violation) is Wine's drag and drop racing WebView2's",
            "# browser: it gets three more tries",
            "tries=0",
            "while :; do",
            "    began=$(date +%s)",
            f'    wine "$PROGRAM"/{q(main_rel)} "$@"',
            "    status=$?",
            '    [ "$status" = 5 ] && [ $(($(date +%s) - began)) -lt 60 ] && [ "$tries" -lt 3 ] || break',
            "    tries=$((tries + 1))",
            '    echo "The program crashed as it started; starting it again..." >&2',
            "done",
        ]
    else:
        lines.append(f'wine "$PROGRAM"/{q(main_rel)} "$@"')
    if not webview2 or console or chromium_args:
        lines.append("status=$?")
    lines += [
        "# a program that starts another and exits (a launcher, a single-instance stub, one that restarts",
        "# itself) leaves that one running in the prefix, and the sandbox ends with this script: wait for it",
        "wineserver -w",
        'exit "$status"',
    ]
    return "\n".join(lines) + "\n"


def write(pl: Plan, out: Path, app_id: str, args) -> Path:
    """Write out/app (program files, launcher, desktop integration) and the manifest; return the manifest path."""
    from .winres import extract_png
    pkg = pl.pkg
    slug = pkg.name if pkg.name not in RESERVED else f"{pkg.name}-app"
    prog = pkg.extra["program_dir"]
    main_rel = pkg.extra["main_exe"]
    app = out / "app"
    if app.exists():
        shutil.rmtree(app)
    extra_data = getattr(args, "mode", "bundle") == "extra-data"
    build = ["cp -a bin share ${FLATPAK_DEST}/", f"chmod +x ${{FLATPAK_DEST}}/bin/{slug}"]
    sources: list[dict] = [{"type": "dir", "path": "app"}]
    if extra_data:
        # Flatpak downloads the original at install time; apply_extra unpacks the program
        # into /app/extra/program, and /app/opt/NAME points there.
        replay = _need_replay(pkg, args)
        extra_name, extra_src = extra_source(pkg, args.url)
        sources.append(extra_src)
        install_helper(app, {"source": extra_name, "steps": replay["steps"], "take": replay["take"],
                             "target": "program", "drop": replay["drop"]})
        (app / "bin" / "apply_extra").write_text(APPLY_EXTRA)
        (app / "bin" / "apply_extra").chmod(0o755)
        build.append(f"install -d ${{FLATPAK_DEST}}/opt && ln -s /app/extra/program ${{FLATPAK_DEST}}/opt/{slug}")
    else:
        copy_tree(prog, app / "opt" / slug)
        build[0] = "cp -a opt bin share ${FLATPAK_DEST}/"
        for name, data in standin_dlls(pl.data.get("standins") or {}).items():
            (app / "opt" / slug / Path(main_rel).parent / name).write_bytes(data)
        for name, data in split_forwarders(pl.data.get("split_dlls") or {}).items():
            (app / "opt" / slug / Path(main_rel).parent / name).write_bytes(data)
        for name, src in (pl.data.get("companion_dlls") or {}).items():
            shutil.copy2(src, app / "opt" / slug / Path(main_rel).parent / name)
        if pl.data.get("icu"):
            # ICU's own build comes from the Unicode Consortium; the DLLs named as Windows' forward to it
            from . import icunames
            for name, data in icu_forwarders(pl.data["icu"]).items():
                (app / "opt" / slug / Path(main_rel).parent / name).write_bytes(data)
            sources.append({"type": "archive", "url": icunames.URL, "sha256": icunames.SHA256,
                            "strip-components": 0, "dest": "icu"})
            where = shlex.quote(f"{slug}/{Path(main_rel).parent.as_posix()}")
            build.append(" ".join(["cp -n", *(f"icu/bin64/{d}" for d in icunames.DLLS),
                                   f"${{FLATPAK_DEST}}/opt/{where}"]))
    writable = bool(getattr(args, "writable", False) or pl.data.get("writable"))
    h = hashlib.sha256()
    with open(prog / main_rel, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    stamp = f"{pkg.version}-{h.hexdigest()[:12]}"
    (app / "bin").mkdir(parents=True, exist_ok=True)
    script = app / "bin" / slug
    script.write_text(launcher(pkg, slug, main_rel, writable, stamp, pl.data.get("runtimes"),
                               wpf=bool(pl.data.get("wpf")), symbol_fonts=pl.data.get("symbol_fonts"),
                               folder_index=pl.data.get("folder_index"), console=bool(pl.data.get("console")),
                               chromium_args=pl.data.get("chromium_args"),
                               core_fonts=bool(pl.data.get("core_fonts")), cjk_fonts=bool(pl.data.get("cjk_fonts")),
                               webview2=bool(pl.data.get("webview2")), qt_quick=bool(pl.data.get("qt_quick")),
                               machine_id=bool(pl.data.get("machine_id"))))
    script.chmod(0o755)
    pl.notes += write_integration(app, app_id, pkg, slug, extract_png(prog / main_rel),
                                  wm_class=Path(main_rel).name.lower(), exec_codes="%F")

    base_version, branch = pl.data["base_version"], pl.data["branch"]
    ext = ["org.winehq.Wine.gecko", "org.winehq.Wine.mono"]
    if base_version.startswith("wow64-"):
        ext = [e + "-wow64" for e in ext]
    from . import __version__
    manifest = {
        "id": app_id,
        "runtime": "org.freedesktop.Platform",
        "runtime-version": branch,
        "sdk": sdk_for("org.freedesktop.Platform"),
        # the files are the vendor's own builds: no stripping, no debuginfo split
        "build-options": {"no-debuginfo": True},
        "base": WINE_BASE,
        "base-version": base_version,
        "inherit-extensions": ext,
        "command": slug,
        "separate-locales": False,
        "finish-args": [p.arg for p in pl.permissions],
        "modules": [{
            "name": slug,
            "buildsystem": "simple",
            "build-commands": build,
            "sources": sources,
        }],
        "x-debpak": {"generator": f"debpak {__version__}", "source-package": pkg.path.name, "format": pkg.format,
                     "route": "wine", "mode": "extra-data" if extra_data else "bundle",
                     "package": f"{pkg.name} {pkg.version}",
                     "unpacked-by": pkg.extra.get("unpacked_by"), "entry-point": f"/app/opt/{slug}/{main_rel}",
                     "writable": writable, "runtimes": pl.data.get("runtimes", []),
                     "console": bool(pl.data.get("console")), "webview2": bool(pl.data.get("webview2")),
                     "permission-reasons": {p.arg: p.reason for p in pl.permissions}},
    }
    path = out / f"{app_id}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path
