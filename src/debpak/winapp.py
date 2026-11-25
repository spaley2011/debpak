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
import re
import shlex
import shutil
from pathlib import Path

from .foreign import Plan, _need_replay, copy_tree, extra_source, one_line, write_integration
from .packages import Package
from .permissions import Permission
from .runtime import parse_ref, sdk_for
from .unpack import APPLY_EXTRA, install_helper

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
# --wine-runtime value that installs no .NET runtime: the program stays on wine-mono
MONO = "wine-mono"
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
# app's winetricks doesn't have the verb yet, Microsoft's zips of the runtime (see launcher)
DOTNET_MAJORS = range(6, 11)


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
                    return [], wpf, f"needs {fw} {names[fw]}, which winetricks has no verb for"
                verb = f"{prefix}{major}"
                return [verb], wpf, f"needs {fw} {names[fw]} (from {source}), so the first start installs {verb}"
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
    return [], False, ""


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
    pl.data["runtimes"] = runtimes
    pl.data["wpf"] = wpf
    fonts = symbol_fonts_named(files)
    pl.data["symbol_fonts"] = fonts
    for font in fonts:
        pl.notes.append(f"the program draws with the {font} font, which only Windows has, so the launcher has Wine "
                        f"use {SYMBOL_FONT_STANDINS[font]} for it (GDI+ draws nothing with a missing font)")
    if net:
        perms.append(Permission("--share=network", f"imports {net[0]}"))
    elif runtimes:
        perms.append(Permission("--share=network", "winetricks downloads the Windows runtimes on first run"))
    if runtimes:
        pl.details.append(("runtimes", " ".join(runtimes) + " (installed by winetricks on first run)"))
        pl.notes.append("the first start installs " + ", ".join(runtimes) + " into the Wine prefix, which needs "
                        "the network and can take several minutes")
    shipped = {f.name.lower() for f in files}
    wanted: dict[str, str] = {}
    for dll in sorted(dlls - shipped):
        for pattern, verb in RUNTIME_FOR:
            if re.match(pattern, dll) and verb not in runtimes:
                wanted.setdefault(verb, dll)
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
    marker = None if getattr(args, "writable", False) else keeps_settings_beside(prog / main_rel)
    if marker:
        pl.data["writable"] = True
        pl.notes.append(f"{marker} beside the program shows it saves settings next to its .exe, so it runs "
                        "from a copy in the Wine prefix, as with --writable")
    elif not getattr(args, "writable", False):
        pl.notes.append("the program runs from read-only /app; if it saves files next to its .exe, convert "
                        "with --writable")
    return pl


def launcher(pkg: Package, slug: str, main_rel: str, writable: bool, stamp: str,
             runtimes: list[str] | None = None, wpf: bool = False, symbol_fonts: list[str] | None = None,
             folder_index: str | None = None, console: bool = False) -> str:
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
        'export WINEPREFIX="${WINEPREFIX:-$XDG_DATA_HOME/wine}"',
        'export WINEDEBUG="${WINEDEBUG:--all}"',
        "# don't let Wine add its own menu entries; the Flatpak has one",
        'export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-winemenubuilder.exe=d}"',
        'mkdir -p "$WINEPREFIX"',
        'if [ ! -f "$WINEPREFIX/system.reg" ]; then',
        '    echo "Setting up Wine (first run only)..." >&2',
        "    wineboot --init >/dev/null 2>&1",
        "fi",
        f"PROGRAM=/app/opt/{slug}",
    ]
    if runtimes:
        want = " ".join(runtimes)
        # winetricks' .NET Framework verbs set Windows 7 and leave it set, and programs that need
        # Windows 10 refuse to start on it (Playnite: "Windows 7 and Windows 8 are no longer
        # supported"), so the verbs end by setting Windows 10 back, Wine's own default
        winver = "" if WINVER_VERBS & set(runtimes) else " win10"
        lines += [
            "# Windows runtimes the program needs, installed once by the Wine base app's winetricks",
            f'RUNTIMES="{want}"',
            f'VERBS="$RUNTIMES{winver}"',
            'if [ "$(cat "$WINEPREFIX/.debpak-runtimes" 2>/dev/null)" != "$VERBS" ]; then',
            '    echo "Installing $RUNTIMES into the Wine prefix (first run only, this can take a while)..." >&2',
            "    # a .NET newer than this winetricks knows (its 20260125 has no dotnetdesktop10) comes from",
            "    # Microsoft's own zips: the .NET runtime, and the desktop one on top for dotnetdesktopN",
            "    known=$(winetricks list-all 2>/dev/null) ok=1 tricks=",
            "    for v in $VERBS; do",
            '        case $v in dotnet[0-9]*|dotnetdesktop[0-9]*)',
            '            if ! printf "%s\\n" "$known" | grep -q "^$v "; then',
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
            '    if [ -n "$ok" ] && { [ -z "$tricks" ] || winetricks -q --unattended $tricks >&2; }; then',
            '        echo "$VERBS" > "$WINEPREFIX/.debpak-runtimes"',
            "    else",
            "        echo \"Not everything installed; the program may not work. It retries next start.\" >&2",
            "    fi",
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
    if writable:
        lines += [
            "# The program writes next to its .exe, so it runs from a copy in the prefix.",
            "# Files changed since the last copy (settings, saves) are never overwritten.",
            f'DEST="$WINEPREFIX/drive_c/Program Files/{slug}"',
            f'if [ "$(cat "$DEST/.debpak-version" 2>/dev/null)" != {q(stamp)} ]; then',
            f'    echo {q("Copying " + name + " into the Wine prefix...")} >&2',
            '    mkdir -p "$DEST"',
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
            'if [ -t 0 ] || [ -t 1 ]; then',
            f'    exec wine "$PROGRAM"/{q(main_rel)} "$@"',
            "fi",
            f'exec wineconsole "$PROGRAM"/{q(main_rel)} "$@"',
        ]
    else:
        lines.append(f'exec wine "$PROGRAM"/{q(main_rel)} "$@"')
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
                               folder_index=pl.data.get("folder_index"), console=bool(pl.data.get("console"))))
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
                     "permission-reasons": {p.arg: p.reason for p in pl.permissions}},
    }
    path = out / f"{app_id}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return path
