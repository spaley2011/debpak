"""debpak command-line interface.

PACKAGE is a .deb, .rpm, Arch .pkg.tar.*, .AppImage, .snap (or /snap/NAME/current),
a vendor's .tar.gz/.tar.xz/.zip or .run installer, a Windows .exe/.msi/.msix or
program folder (Electron apps natively, others through Wine), or a macOS
Electron app (.dmg, .app, zipped .app).

  debpak inspect  PACKAGE [--runtime REF]
  debpak convert  PACKAGE --app-id ID [--runtime REF] [--deps-dir DIR | --mirror URL | --rpm-repo URL]
                  [-o OUT] [--no-build] [--anyway]
  debpak desnap   [--yes] [--copy-data] [--remove-snaps] [--block-snapd]   replace snaps with Flatpaks
  debpak install NAME [--recipes URL|DIR]                       install from a recipe
  debpak recipe make OUT --to DIR | index DIR | list [TERM] | check DIR [--apply] | publish DIR --repo R --url U
  debpak list | update [APP_ID ...] [--check] | uninstall APP_ID [--delete-data]
  debpak runtime-index REF | --root DIR --ref REF
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__, host
from .analyze import CHROMIUM_KINDS, analyze, check_versions, helper_only_needs, home_seed, is_never_bundle
from .deb import DebError
from .packages import FLATPAK_TO_DEB, PackageError, open_package
from .permissions import Permission, infer
from .report import render, to_json
from .resolve import (DEBIAN_NEWEST, DEBIAN_RELEASES, FEDORA_OLDER, FEDORA_RELEASE, UBUNTU_NEWEST_LTS,
                      UBUNTU_PREVIOUS_LTS, ResolveResult,
                      default_sources, fill_gaps, make_sources)
from .runtime import RuntimeIndex, get_index, host_arch, index_root, parse_ref
from .stage import stage

EXIT_ON_FLATHUB = 4
FOREIGN = ("electron", "wine")
APP_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*){2,}$")


def _err(msg: str) -> int:
    """Print an error message to stderr and return exit status 1."""
    print(f"debpak: error: {msg}", file=sys.stderr)
    return 1


def _no_runtime_for(arch: str) -> str:
    """Say why a package built for arch can't be converted on this machine; "" if it can.

    HexoEditor's HexoEditor_1.5.30_linux_x32.tar.gz is a 32-bit x86 build, and convert
    asked for org.freedesktop.Platform/i386/25.08, which Flathub doesn't have ("Nothing
    matches"): its current runtimes are 64-bit, with only the Compat.i386 libraries that
    64-bit apps such as Steam add for the 32-bit programs they start. No install command can help,
    so it says so instead of printing one.
    """
    if arch == "i386" and host_arch() == "x86_64":
        return ("built for 32-bit x86 (i386) only: Flathub has no i386 runtime to build it on (only the "
                "Compat.i386 libraries that 64-bit apps add for 32-bit helpers). Convert the release's x86-64 "
                "build instead")
    return ""


def default_app_id(pkg_name: str) -> str:
    """Return the Flatpak app ID used when --app-id isn't given: local.debpak.<package>.

    A part of an app ID can't start with a digit, so 7-zip becomes _7_zip.
    """
    part = re.sub(r"[^A-Za-z0-9_]", "_", pkg_name)
    return "local.debpak." + ("_" + part if part[:1].isdigit() else part)


def _load_runtime(args, fallback_ref: str | None, arch: str) -> RuntimeIndex | None:
    """Load the runtime index that --runtime-index or --runtime names.

    fallback_ref is used when neither option was given, and None comes back when
    there is no fallback either.
    """
    if getattr(args, "runtime_index", None):
        return RuntimeIndex.load(Path(args.runtime_index))
    ref = getattr(args, "runtime", None) or fallback_ref
    if not ref:
        return None
    return get_index(ref, arch, rebuild=getattr(args, "reindex", False))


# the next branch of a default runtime, for a package built against a newer glibc than the
# default has: OpenWhispr's helpers and RSS Guard's Qt need GLIBC_2.43, which 25.08 (2.42) lacks.
# GNOME 51 is built on 26.08 (GNOME 49 and 50 on 25.08). No KDE runtime on Flathub is built on 26.08
# yet (as of November 2026 only 6.12-beta, on flathub-beta), so a Qt 6 app keeps the default and
# has its libm needs lowered where that's sound (see analyze.lower_libm_needs)
NEWER_RUNTIME = {("org.freedesktop.Platform", "25.08"): "org.freedesktop.Platform//26.08",
                 ("org.gnome.Platform", "49"): "org.gnome.Platform//51",
                 ("org.gnome.Platform", "50"): "org.gnome.Platform//51"}


def _glibc_key(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def _newer_runtime(args, runtime: RuntimeIndex | None, a, arch: str) -> RuntimeIndex | None:
    """Return the next branch of the runtime when the package needs a newer glibc and that branch has it.

    Only when no runtime was named: --runtime and --runtime-index are kept as given.
    """
    if not runtime or getattr(args, "runtime", None) or getattr(args, "runtime_index", None):
        return None
    newer = NEWER_RUNTIME.get((runtime.id, runtime.branch))
    if not newer or not a.max_glibc or _glibc_key(a.max_glibc) <= _glibc_key(runtime.glibc):
        return None
    try:
        index = get_index(newer, arch)
    except RuntimeError:
        if args.no_build or not host.which("flatpak-builder") or not _install_runtime(newer, arch):
            return None
        try:
            index = get_index(newer, arch)
        except RuntimeError:
            return None
    return index if _glibc_key(a.max_glibc) <= _glibc_key(index.glibc) else None


def _install_runtime(ref: str, arch: str) -> bool:
    """Install a runtime from Flathub for the user (the build needs it); return whether that worked."""
    from .manage import flathub_install_cmd
    from .runtime import parse_ref
    rid, _, branch = parse_ref(ref, arch)
    full = f"{rid}/{arch}/{branch}"
    print(f"Installing the runtime {full} from Flathub, which the build needs...", flush=True)
    add, install = flathub_install_cmd(full)
    try:
        subprocess.run(host.command(add), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return subprocess.call(host.command([*install[:-1], "--noninteractive", install[-1]])) == 0
    except OSError:
        return False


def _open(args, dest):
    from .winapp import wine_branch
    return open_package(args.deb, dest, allow_run=getattr(args, "allow_run", False),
                        wine_branch=wine_branch(args)[0])


def _exec_for(args, pkg) -> str | None:
    """Return the entry point: --exec if given, else the one the package format chose (AppImage, snap)."""
    return args.exec or getattr(pkg, "default_exec", None)


def _add_depended_programs(args, pkg, runtime, arch: str) -> dict[str, str]:
    """Add the programs the package depends on and runs, which the runtime lacks (resolve.wanted_programs),
    from the mirror named on the command line, or else from Ubuntu's LTS; return name -> origin."""
    from .resolve import add_programs, asked_programs, wanted_programs
    from .runtime import runtime_programs
    asked = getattr(args, "add_program", None) or []
    if not (getattr(pkg, "control", None) or getattr(pkg, "extra", {}).get("requires") or asked):
        return {}
    have = runtime_programs(runtime.ref, runtime.arch)
    if have is None:
        return {}
    # and the ones the check found it looking for (--add-program), which no Depends named: rkdeveloptool-gui's
    # rpm declares no dependencies at all, and its dialog said "Error: rkdeveloptool not found"
    names = sorted(set(wanted_programs(pkg, have) if (getattr(pkg, "control", None)
                                                      or getattr(pkg, "extra", {}).get("requires")) else [])
                   | set(asked_programs(pkg, asked, have)))
    if not names:
        return {}
    deb_arch = FLATPAK_TO_DEB.get(arch, arch)
    if getattr(args, "deps_dir", None) or getattr(args, "mirror", None) or getattr(args, "rpm_repo", None):
        srcs = [s for s in make_sources(args, arch, deb_arch) if hasattr(s, "_package")]
    elif getattr(args, "no_auto_mirror", False):
        return {}
    else:
        srcs = default_sources(arch, deb_arch)[:2]
    try:
        return add_programs(names, srcs, pkg.root)
    except OSError as e:
        print(f"(couldn't add {', '.join(names)}, which the package depends on: {e})")
        return {}


def _home_permissions(a) -> list[Permission]:
    """Return --persist for the home folder a program keeps its files in (Analysis.home_skel,
    Analysis.home_folder): without it ~/.parsec would be lost when the app exits. And
    --allow=multiarch for a package that runs 32-bit x86 code (Analysis.multiarch)."""
    perms = []
    if a.multiarch:
        perms.append(Permission("--allow=multiarch", a.multiarch))
    if a.home_skel:
        skel, home_dir = a.home_skel
        perms.append(Permission(f"--persist={home_dir}",
                                f"the app keeps its files in ~/{home_dir} (first copied from /{skel})"))
    if a.home_folder and all(p.arg != f"--persist={a.home_folder}" for p in perms):
        perms.append(Permission(f"--persist={a.home_folder}",
                                f"the app keeps itself, its updates and the user's data in ~/{a.home_folder}"))
    for folder, rel in sorted(a.tool_settings.items()):
        perms.append(Permission(f"--filesystem=~/{folder}:ro", f"{rel} reads the settings in ~/{folder}"))
    return perms


def cmd_inspect(args) -> int:
    """Print what converting the package would involve. Exit status 0, or 1 on error."""
    with tempfile.TemporaryDirectory(prefix="debpak-") as tmp:
        try:
            pkg = _open(args, tmp)
        except (PackageError, DebError, OSError) as e:
            return _err(str(e))
        if pkg.format in FOREIGN:
            pkg, _mod, pl = _plan_foreign(args, pkg, announce=not args.json)
            print(json.dumps(pl.to_json(), indent=2) if args.json else pl.render(), end="\n" if args.json else "")
            return 2 if pl.blockers else 0
        arch = pkg.flatpak_arch or host_arch()
        runtime = None
        if args.runtime or args.runtime_index:
            try:
                runtime = _load_runtime(args, None, arch)
            except (RuntimeError, ValueError) as e:
                return _err(str(e))
        try:
            a = analyze(pkg, runtime, exec_override=_exec_for(args, pkg))
        except ValueError as e:
            return _err(str(e))
        perms = infer(set().union(*(set(i.needed) for i in a.elfs.values())) if a.elfs else set(),
                      a.all_symbols(), a.kind, dlopened=a.dlopened, gui=a.gui_reason(),
                      bus_names=a.bus_names, host_spawner=a.host_spawner,
                      bus_clients=a.bus_clients, bus_access=a.bus_access) + _home_permissions(a)
        hit = None if args.no_flathub_check else _flathub_hit(pkg, a)
        if hit:
            pkg.notes.insert(0, f"already on Flathub as {hit.app_id} ({hit.name}): "
                                f"flatpak install flathub {hit.app_id}")
        if args.json:
            print(json.dumps(to_json(a, perms), indent=2))
        else:
            print(render(a, perms, extra_notes=list(getattr(pkg, "notes", []))), end="")
        return 2 if a.blockers else 0


def cmd_convert(args) -> int:
    """Convert a package into a Flatpak manifest and staged /app tree, then build it.

    With --verify (the default when the host has xvfb-run), the installed app is
    started on a virtual display, and when it doesn't come up, converted again
    with the changes its output points to (see selfcheck), a few times at most.

    Exit status: as _convert_once.
    """
    from .foreign import forget_installed
    forget_installed()          # what an installer installed is kept for this conversion's rounds only
    rc = _convert_once(args)
    if rc != 0 or not getattr(args, "verify", False) or args.no_build or not _app_id_of(args):
        return rc
    from . import selfcheck
    if not selfcheck.available():
        return rc
    app_id = _app_id_of(args)
    wine = (Path(args.output) / "wine").is_dir() or _manifest_base(args) == "org.winehq.Wine"
    kind = _manifest_kind(args)
    seconds = selfcheck.SECONDS.get("wine" if wine else kind, selfcheck.DEFAULT_SECONDS)
    fresh = wine and not selfcheck.wine_prefix_exists(app_id)
    # (a Windows program's prefix, which its first start takes long to set up, is judged above instead)
    untouched = not wine and selfcheck.app_data_empty(app_id)
    try:
        return _check_rounds(args, app_id, wine, kind, seconds, rc)
    finally:
        if fresh and selfcheck.drop_unfinished_wine_prefix(app_id):
            print("(the check stopped the app before its first-start setup was done; removed the Wine prefix it "
                  "had begun, so the first real start sets it up whole)")
        if untouched and selfcheck.clear_check_data(app_id):
            print("(removed what the app kept in its folder during the check, so its first real start begins "
                  "from nothing: a lock it left naming its PID would name it again)")


def _check_rounds(args, app_id: str, wine: bool, kind: str, seconds: int, rc: int) -> int:
    """Start the app, and convert again with what its failure points to, a few rounds at most (see cmd_convert)."""
    from . import selfcheck
    tried: set[str] = set()
    for round_ in range(1, selfcheck.ROUNDS + 1):
        # the runtimes the plan already installs are no remedy: converting again with one changes nothing
        tried |= {f"wine:{v}" for v in (_manifest(args).get("x-debpak") or {}).get("runtimes") or []}
        print(f"\nChecking the app: starting it on a virtual display for {seconds} seconds...", flush=True)
        obs = selfcheck.observe(app_id, seconds, wine=wine)
        if kind in CHROMIUM_KINDS:
            # an Electron or CEF app draws its pages in a window of its own; a page it serves on this machine
            # (as some serve their own interface to that window) is no window of its own
            obs.served = None
        if obs.ok:
            print(f"Check: {obs.describe()}.")
            return 0
        print(f"Check: {obs.describe()}.")
        d = selfcheck.diagnose(obs, kind, wine, tried)
        _drop_unseedable(args, d)
        logged = None
        terminal = _menu_terminal(args)
        # it can open windows, but no menu entry starts it (MolvAI's molva): only what it said when
        # started bare counts, and only commands of its own (see selfcheck.command_line)
        graphical = _manifest_graphical(args) and not terminal
        # an AppImage must have a menu entry, so its own says nothing of a window: bisonc++'s AppImage, a
        # parser generator, has one with Terminal=false and printed "Usage: bisonc++ [OPTIONS] file" and
        # its options, and counted as a crashed app
        unlisted = graphical and (not _menu_entries(args) or _manifest_format(args) == "appimage")
        # a program with no display in its sandbox that runs on is looked at too: a server's is, and so is
        # one whose menu entries all run it in a terminal (Amfora's snap, a text interface)
        windowless = _manifest_windowless(args) or (terminal and not _manifest_graphical(args))
        if not d.remedies and not wine \
                and (not obs.running or windowless or selfcheck.NEEDS_TERMINAL.search(obs.output)) \
                and (not graphical or unlisted or selfcheck.NEEDS_TERMINAL.search(obs.output)):
            # (a program that says it needs a terminal is one whatever its menu entry says: Cryptnox's snap,
            # an interactive prompt, has a menu entry with Terminal=false)
            # no menu entry for a graphical app and no window: a command-line program that wants
            # arguments exits at once too (Arkloop's ark, appimagetool), and that's no failure
            helped = None if graphical or obs.running or selfcheck.USAGE.search(obs.output) \
                or selfcheck.NEEDS_TERMINAL.search(obs.output) \
                else selfcheck.observe(app_id, selfcheck.QUICK_SECONDS * 3, args=["--help"])
            if (why := selfcheck.command_line(obs, helped, terminal, windowless, graphical)):
                tail = "" if graphical and not unlisted else \
                    ", and its menu entry is only the one every AppImage must have" if graphical and _menu_entries(args) \
                    else ", and it has no menu entry for a graphical app"
                print(f"Check: {selfcheck.COMMAND_LINE}: {why}{tail}. "
                      f"Run it in a terminal: flatpak run {app_id} --help")
                return 0
            if terminal and (windowless or not obs.running) and selfcheck.can_give_terminal():
                # a terminal program that broke with no terminal (LE, an ncurses editor, crashed on a
                # signal) is started in one, as its menu entry would (see selfcheck.in_terminal); so is
                # one with a display in its sandbox that ended with no window: musikcube's snap carries
                # libraries that link libX11, so it got X11, and it was never started in a terminal
                print("Starting it again in a terminal, as its menu entry does...", flush=True)
                if (why := selfcheck.in_terminal(selfcheck.observe(app_id, selfcheck.QUICK_SECONDS * 3,
                                                                   terminal=True))):
                    print(f"Check: {selfcheck.COMMAND_LINE}: {why}. Run it in a terminal: flatpak run {app_id}")
                    return 0
        if not d.remedies and wine and not obs.running and _manifest_console(args):
            # a Windows console program that ended: fio and TrId2Console print their options or what they
            # miss and exit at once, into a console window the check can't read, so it starts the
            # program again outside one
            bare = selfcheck.observe(app_id, selfcheck.QUICK_SECONDS * 3, selfcheck.CONSOLE_ENV, wine=True)
            why = selfcheck.command_line(bare, None, console=True)
            if not why and not bare.running and bare.code is not None:
                why = selfcheck.command_line(bare, selfcheck.observe(app_id, selfcheck.QUICK_SECONDS * 3,
                                                                     selfcheck.CONSOLE_ENV, args=["--help"], wine=True),
                                             console=True)
            if why:
                print(f"Check: {selfcheck.COMMAND_LINE}: {why}. Run it in a terminal: flatpak run {app_id} --help")
                return 0
        if not d.remedies:
            print("Starting it again with the loader's logging on, to see why...", flush=True)
            logged = selfcheck.observe(app_id, seconds, selfcheck.diagnostic_env(wine), wine=wine)
            d = selfcheck.diagnose(logged, kind, wine, tried)
            _drop_unseedable(args, d)
            if not wine:
                for so in selfcheck.failed_loads(logged.output, kind):
                    d.add(selfcheck.Remedy(f"lib:{so}", f"it tried to load {so}, which wasn't there",
                                           "add_library", so), tried)
            # only a portable app (an archive's folder) keeps its files beside itself
            if not d.remedies and not wine and not obs.running and obs.code == 0 and _manifest_graphical(args) \
                    and (_manifest(args).get("x-debpak") or {}).get("format") in ("tarball", "run"):
                d.add(selfcheck.QUIT_AT_ONCE, tried)
        if not d.remedies:
            print("Check: nothing in what it printed points to a change debpak can make"
                  + (f" ({'; '.join(d.evidence)})" if d.evidence else "") + ".")
            tail = selfcheck.output_tail(logged.output if logged else obs.output)
            if tail:
                print("The end of what it printed:")
                print("\n".join("  | " + ln for ln in tail))
            return 0
        for r in d.remedies:
            print(f"  - {r.why}: {_remedy_flag(r)}")
            tried.add(r.key)
        before = {r.option: copy.copy(getattr(args, r.option, None)) for r in d.remedies}
        written = _manifest_stamp(args)
        selfcheck.apply(args, d.remedies)
        print(f"\nConverting again with {'that change' if len(d.remedies) == 1 else 'those changes'} "
              f"(round {round_} of {selfcheck.ROUNDS})...", flush=True)
        rc = _convert_once(args)
        if rc == 2:
            # the change made the conversion refuse (nothing was written), so the build from the round
            # before is still the installed one, and it stays
            for option, value in before.items():
                setattr(args, option, value)
            print("Check: converting with that change was refused, so the app stays as it was built before.")
            return 0
        if rc != 0:
            # The changes made it worse: Tusk's loader log named libnss_myhostname.so.2, which debpak
            # won't bundle, and the conversion stopped, though the app it had built was running.
            # The build from before is what the user gets.
            for option, value in before.items():
                setattr(args, option, value)
            print("Converting with those changes failed; keeping the app as it was built before them.",
                  flush=True)
            if _manifest_stamp(args) == written:
                return 0                # nothing was written: the earlier build is still installed
            return _convert_once(args)
        kind = _manifest_kind(args)
    return rc


def _manifest_stamp(args) -> tuple:
    """Return the names and modification times of the output folder's manifests, to tell whether one was written."""
    out = Path(args.output)
    return tuple(sorted((m.name, m.stat().st_mtime_ns) for m in out.glob("*.json"))) if out.is_dir() else ()


def _remedy_flag(r) -> str:
    flag = "--" + r.option.replace("_", "-")
    return flag if r.value is True else f"{flag} {r.value}"


def _manifest(args) -> dict:
    """The manifest the last conversion wrote, or {}."""
    out = Path(args.output)
    for m in sorted(out.glob("*.json")):
        try:
            data = json.loads(m.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get("id") and "modules" in data:
            return data
    return {}


def _app_id_of(args) -> str | None:
    return _manifest(args).get("id")


def _manifest_base(args) -> str:
    return _manifest(args).get("base", "")


def _manifest_kind(args) -> str:
    return (_manifest(args).get("x-debpak") or {}).get("kind", "")


def _drop_unseedable(args, d) -> None:
    """Leave out a remedy that copies a file into the home folder when the app the last conversion wrote has no copy.

    The staged /app tree is the package's files (usr/share is share), so the
    share/NAME/FILE that analyze.home_seed looks for is there too.
    """
    app = Path(args.output) / "app"
    d.remedies = [r for r in d.remedies if r.option != "seed_home" or home_seed(app, r.value)]


def _manifest_graphical(args) -> bool:
    """True if the app the last conversion wrote can open windows, or has a menu entry for a graphical app."""
    if any(a in ("--socket=x11", "--socket=fallback-x11", "--socket=wayland")
           for a in _manifest(args).get("finish-args", [])):
        return True
    for d in sorted((Path(args.output) / "app/share/applications").glob("*.desktop")):
        try:
            text = d.read_text("utf-8", "replace")
        except OSError:
            continue
        if not re.search(r"(?m)^Terminal\s*=\s*true\s*$", text):
            return True
    return False


def _manifest_windowless(args) -> bool:
    """True if the app the last conversion wrote has no display in its sandbox and no menu entry at all."""
    return not _manifest_graphical(args) and not any((Path(args.output) / "app/share/applications").glob("*.desktop"))


def _manifest_format(args) -> str:
    """The format of the package the last conversion wrote (deb, rpm, appimage, ...), or ""."""
    return str((_manifest(args).get("x-debpak") or {}).get("format") or "")


def _menu_entries(args) -> bool:
    """True if the app the last conversion wrote has a menu entry."""
    return any((Path(args.output) / "app/share/applications").glob("*.desktop"))


def _manifest_console(args) -> bool:
    """True if the Windows program the last conversion wrote is a console program (see winapp's launcher)."""
    return bool((_manifest(args).get("x-debpak") or {}).get("console"))


def _menu_terminal(args) -> bool:
    """True if the app the last conversion wrote has menu entries, and each runs it in a terminal (Terminal=true)."""
    texts = []
    for d in sorted((Path(args.output) / "app/share/applications").glob("*.desktop")):
        try:
            texts.append(d.read_text("utf-8", "replace"))
        except OSError:
            continue
    return bool(texts) and all(re.search(r"(?m)^Terminal\s*=\s*true\s*$", t) for t in texts)


def _convert_once(args) -> int:
    """Convert a package into a Flatpak manifest and staged /app tree, then build it.

    Exit status:
        0: converted (and built and installed, when flatpak-builder exists).
        1: an error, such as an unreadable package or a missing runtime.
        2: blockers or unresolved libraries, so nothing was written (see --force).
        4: Flathub already has the app (see --anyway).
        Anything else is flatpak-builder's own exit status.
    """
    if args.mode == "extra-data" and not args.url:
        return _err("--mode extra-data requires --url (the vendor's download URL for this exact file)")
    out = Path(args.output)
    work = Path(tempfile.mkdtemp(prefix="debpak-"))
    try:
        pkg = _open(args, work / "src")
        if pkg.format in FOREIGN:
            return _convert_foreign(args, pkg, out)
        arch = pkg.flatpak_arch
        if not arch and pkg.pkg_arch in ("noarch", "any", "all", ""):
            arch = host_arch()       # architecture-independent package (scripts, Java, ...)
        if not arch:
            return _err(f"unsupported package architecture {pkg.pkg_arch!r}")
        if (why := _no_runtime_for(arch)):
            print(f"{pkg.name} {pkg.version} ({arch}, .{pkg.format})\n\n== Verdict ==\n  NOT CONVERTIBLE as-is:\n"
                  f"    x {why}\n\nNot writing a manifest.")
            return 2
        app_id = args.app_id or default_app_id(pkg.name)
        if not APP_ID_RE.match(app_id):
            return _err(f"invalid app id {app_id!r} (needs 3+ dot-separated components)")

        # first pass without a runtime to learn which runtime fits
        probe = analyze(pkg, None, exec_override=_exec_for(args, pkg))
        if not (args.anyway or args.no_flathub_check):
            hit = _flathub_hit(pkg, probe)
            if hit:
                print(f"{hit.name} is already on Flathub as {hit.app_id}; the official Flatpak will work better "
                      f"than a conversion:\n  flatpak install flathub {hit.app_id}\n"
                      "(pass --anyway to convert this package regardless)")
                return EXIT_ON_FLATHUB
        if getattr(pkg, "format", "") == "snap" and not (args.deps_dir or args.mirror or args.rpm_repo) \
                and pkg.extra.get("ubuntu_suite") and not args.no_auto_mirror:
            from .snap import ubuntu_mirror
            args.mirror, args.suite = ubuntu_mirror(arch), pkg.extra["ubuntu_suite"]
            args.components = "main,universe"
            args.snap_base_mirror = True
            print(f"(snap base {pkg.extra['base']}: missing libraries come from Ubuntu {args.suite}, "
                  f"{args.mirror})")
        if getattr(pkg, "format", "") == "snap" and args.mirror and args.suite:
            from .resolve import MirrorSource, _scratch
            from .snap import add_base_python, base_venvs, point_venvs_at, python_without_stdlib
            opt = pkg.root / "opt" / pkg.extra["opt_name"]
            if (versions := python_without_stdlib(opt)):
                src = MirrorSource(args.mirror, args.suite, ["main", "universe"], arch,
                                   FLATPAK_TO_DEB.get(arch, arch), _scratch())
                try:
                    used = add_base_python(opt, versions, src._package, link_python3=not base_venvs(opt))
                    if used and (venvs := point_venvs_at(opt, f"/app/opt/{pkg.extra['opt_name']}")):
                        pkg.notes.append(f"the snap's Python venv ({', '.join(venvs)}) runs on the base's Python, "
                                         "added below")
                except (OSError, RuntimeError) as e:
                    used = []
                    print(f"(couldn't add the base's Python {', '.join(versions)}: {e})")
                if used:
                    print(f"(the snap's Python {', '.join(versions)} had its standard library in the base snap; "
                          f"added {', '.join(used)} from Ubuntu {args.suite})")
                    pkg.notes.append(f"Python {', '.join(versions)}'s standard library added from Ubuntu "
                                     f"{args.suite}, as the base snap had it")
            from .snap import point_scripts_at_python
            if scripts := point_scripts_at_python(opt, f"/app/opt/{pkg.extra['opt_name']}"):
                pkg.notes.append(f"the snap's scripts that run /usr/bin/python3 ({', '.join(scripts[:3])}) run the "
                                 "snap's own Python, which its compiled modules are built for")
        try:
            try:
                runtime = _load_runtime(args, probe.runtime_suggestion, arch)
            except RuntimeError as e:
                # the build would install the runtime anyway (--install-deps-from), so do it now
                if "is not installed" not in str(e) or args.no_build or not host.which("flatpak-builder") \
                        or not _install_runtime(args.runtime or probe.runtime_suggestion, arch):
                    raise
                runtime = _load_runtime(args, probe.runtime_suggestion, arch)
        except (RuntimeError, ValueError) as e:
            return _err(f"{e}\n(hint: run on a machine with flatpak + the runtime installed, "
                        "or pass --runtime-index FILE)")
        a = analyze(pkg, runtime, exec_override=_exec_for(args, pkg))
        if (newer := _newer_runtime(args, runtime, a, arch)):
            print(f"(it needs {a.max_glibc}, which {runtime.ref} doesn't have; using {newer.ref})")
            runtime = newer
            a = analyze(pkg, runtime, exec_override=_exec_for(args, pkg))
        if (added := _add_depended_programs(args, pkg, runtime, arch)):
            before, reason = a.main_exec, a.main_exec_reason
            a = analyze(pkg, runtime, exec_override=_exec_for(args, pkg))
            if before and a.main_exec != before:
                # a program added beside the package's own doesn't become its entry point
                a = analyze(pkg, runtime, exec_override="/" + before)
                a.main_exec_reason = reason
            pkg.notes.append("added " + "; ".join(f"{n}, from {o}" for n, o in added.items())
                             + ": the package depends on it and its program runs it, and the runtime "
                             "doesn't have it")

        # what --verify found (or the user asked for), see selfcheck
        if getattr(args, "java", False) and not a.java:
            from . import javart
            a.java = javart.setup(pkg.root)
        if getattr(args, "mono", False) and not a.mono:
            from . import monort
            a.mono = monort.setup(pkg.root)
            a.missing_loaded |= {so for so in a.mono["libraries"] if not runtime.provides(so)}
        for rel in getattr(args, "seed_home", None) or []:
            if not a.home_skel and (skel := home_seed(pkg.root, rel)):
                # (see analyze.home_seed) clrsync's config.toml, from its /usr/share/clrsync
                a.home_skel = (skel, str(Path(rel).parent))
        a.no_chromium_sandbox = bool(getattr(args, "no_chromium_sandbox", False))
        # analyze sets it for a program that makes files in the folder it starts in (relative_temp_template)
        a.writable = a.writable or bool(getattr(args, "writable", False))
        if getattr(args, "chdir", False) and not a.chdir:
            a.chdir = "asked for with --chdir"
        a.fd_limit = getattr(args, "fd_limit", None)
        if getattr(args, "signal_onstack", False) and not a.signal_onstack:
            a.signal_onstack = "asked for with --signal-onstack"
        a.missing_loaded |= {so for so in getattr(args, "add_library", None) or []
                             if so not in a.package_sonames and not runtime.provides(so)}
        from .analyze import QT_WEBENGINE_BASE, webengine_from_base
        if (webengine := webengine_from_base(a, runtime)):
            pkg.notes.append(f"{', '.join(webengine[:4])}{', ...' if len(webengine) > 4 else ''} come from "
                             f"{QT_WEBENGINE_BASE} {a.webengine_base}, built for the runtime's Qt")
        if (a.python_modules or a.python_version) and not getattr(args, "no_auto_mirror", False):
            _fetch_python_modules(a, pkg, runtime, arch, work / "python")

        res = ResolveResult()
        libstage = work / "bundled"
        missing = a.missing_hard | a.missing_soft | a.missing_loaded
        # what the package's files import from each library it lacks (see resolve.lacks_imports)
        imports: dict[str, set[str]] = {}
        for info in a.elfs.values():
            for n in set(info.needed) & missing:
                imports.setdefault(n, set()).update(info.undefined_symbols)
        if missing:
            sources = make_sources(args, arch, FLATPAK_TO_DEB.get(arch, arch))
            if sources:
                res = fill_gaps(missing, runtime, set(a.package_sonames), sources, libstage, set(a.over_runtime),
                                imports)
                if getattr(args, "snap_base_mirror", False) and res.unresolved & (a.missing_hard | a.missing_loaded):
                    from .resolve import fallback_sources, fill_gaps_after
                    print(f"(libraries Ubuntu {args.suite} doesn't have are looked for in the other Ubuntu LTSes, "
                          "then Debian and Fedora)")
                    res = fill_gaps_after(res, a.missing_hard | a.missing_loaded, runtime, set(a.package_sonames),
                                          fallback_sources(arch, FLATPAK_TO_DEB.get(arch, arch), args.suite),
                                          libstage, set(a.over_runtime), imports)
            elif (a.missing_hard or a.missing_loaded) and not getattr(args, "no_auto_mirror", False):
                # only what the programs and the app's own libraries need: libraries that only
                # plugins want are often parts of a toolkit the vendor bundles (Zoom's own Qt 6),
                # and a distribution's build of them needn't match it
                srcs = default_sources(arch, FLATPAK_TO_DEB.get(arch, arch))
                print(f"(missing libraries come from Ubuntu {srcs[0].suite}, or {' or '.join(UBUNTU_PREVIOUS_LTS)} "
                      f"for ones it no longer has, {srcs[0].mirror}; then Debian {' or '.join(DEBIAN_RELEASES)}, "
                      f"then Fedora {FEDORA_RELEASE}, then Debian {DEBIAN_NEWEST}, then Ubuntu {UBUNTU_NEWEST_LTS}, "
                      f"then Fedora {FEDORA_OLDER}; "
                      "--no-auto-mirror to turn this off)")
                res = fill_gaps(a.missing_hard | a.missing_loaded, runtime, set(a.package_sonames), srcs, libstage,
                                set(a.over_runtime), imports)
                res.unresolved |= a.missing_soft - set(res.bundled)
            else:
                res.unresolved = set(missing)

        # re-check symbol versions with bundled libraries in the picture
        def recheck():
            providers: dict[str, set[str] | None] = {}
            elfs = dict(a.elfs)
            for so, info in res.bundled_info.items():
                elfs[f"lib/debpak/{so}"] = info
            for info in elfs.values():
                for lib in info.verneed:
                    if is_never_bundle(lib) and runtime.provides(lib):
                        providers[lib] = runtime.versions_of(lib)
                    elif lib in res.bundled_info:
                        providers[lib] = res.bundled_info[lib].verdef
                    elif lib in a.package_sonames and a.package_sonames[lib] in a.elfs:
                        providers[lib] = a.elfs[a.package_sonames[lib]].verdef
                    elif runtime.provides(lib):
                        providers[lib] = runtime.versions_of(lib)
            return elfs, check_versions(elfs, providers)

        elfs, a.version_problems = recheck()
        # a library fetched only for what the app's other libraries need is optional: if the
        # copy needs a newer glibc than the runtime's, leave it out instead of refusing the app
        # (LocalSend's AppImage: a libjvm.so for a library beside its own)
        drop = {so for so in res.bundled_info if so not in a.missing_hard
                and any(p.startswith(f"lib/debpak/{so} needs libc.so") or p.startswith(f"lib/debpak/{so} needs libm.so")
                        for p in a.version_problems)}
        if drop:
            for so in drop:
                (libstage / so).unlink(missing_ok=True)
                res.bundled.pop(so, None)
                res.bundled_info.pop(so, None)
                res.unresolved.add(so)
            elfs, a.version_problems = recheck()

        all_needed = set().union(*(set(i.needed) for i in elfs.values())) if elfs else set()
        symbols = a.all_symbols()
        perms = infer(all_needed, symbols, a.kind, permissive=args.permissive, dlopened=a.dlopened,
                      gui=a.gui_reason(), bus_names=a.bus_names, host_spawner=a.host_spawner,
                      bus_clients=a.bus_clients, bus_access=a.bus_access) + _home_permissions(a)
        for arg in getattr(args, "add_permission", None) or []:
            if not any(p.arg == arg for p in perms):
                perms.append(Permission(arg, "the app needed it when checked (--add-permission)"))

        if (helpers := helper_only_needs(a, res.unresolved)):
            a.missing_hard -= set(helpers)
            a.missing_soft |= set(helpers)
            progs = sorted({p for ps in helpers.values() for p in ps})
            pkg.notes.append(f"{', '.join(progs[:3])}{', ...' if len(progs) > 3 else ''} need "
                             f"{', '.join(sorted(helpers))}, which no source has; {a.main_exec} doesn't, so "
                             f"the app is converted without {'it' if len(helpers) == 1 else 'them'}, and "
                             f"{'that program' if len(progs) == 1 else 'those programs'} won't start")
        hard_unresolved = res.unresolved & a.missing_hard
        blocked = bool(a.blockers) or bool(hard_unresolved) or bool(res.refused)
        if blocked and not args.force:
            print(render(a, perms, res), end="")
            print("\nNot writing a manifest. Fix the issues above or pass --force to write one anyway.")
            return 2

        out.mkdir(parents=True, exist_ok=True)
        result = stage(a, out, app_id, runtime.ref, args.mode, perms, res.bundled,
                       libstage if res.bundled else None, url=args.url)
        report = render(a, perms, res, list(getattr(pkg, "notes", [])) + result.notes)
        (out / "report.txt").write_text(report)
        (out / "report.json").write_text(json.dumps(to_json(a, perms, res), indent=2) + "\n")
        print(report, end="")
        _stamp_options(result.manifest_path, args, app_id)
        if not args.keep_work:
            # everything the build needs is in the output folder now; the unpacked package would
            # only take up space (often a RAM disk's) while flatpak-builder copies it once more
            shutil.rmtree(work, ignore_errors=True)
        return _build_install(args, pkg, app_id, out, result.manifest_path)
    except (DebError, PackageError) as e:
        return _err(str(e))
    except ValueError as e:
        return _err(str(e))
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"(work dir kept at {work})")


def _fetch_python_modules(a, pkg, runtime, arch: str, dest: Path) -> None:
    """Fetch the Python modules a Python app's package depends on, from Debian (see pydeps).

    When the app's own compiled modules are built for another Python (a.python_version),
    that Python and the modules come from the release whose Python it is.
    """
    from . import pydeps
    from .resolve import debian_source, ubuntu_source
    kind = runtime_kind = {"org.gnome.Platform": "gnome", "org.kde.Platform": "kde"}.get(runtime.id, "")
    deb_arch = FLATPAK_TO_DEB.get(arch, arch)
    if a.python_version:
        # the runtime's own bindings (PyGObject in GNOME's) are built for its Python, not this one: Dialect's
        # snap, with modules for Python 3.10, needs jammy's python3-gi beside jammy's Python
        kind = ""
        distro, suite, mirror = pydeps.PYTHON_RELEASES[a.python_version]
        src = ubuntu_source(arch, deb_arch, suite) if distro == "ubuntu" else \
            debian_source(arch, deb_arch, suite, mirror)
        print(f"(its compiled Python modules are built for Python {a.python_version}: it and the modules it "
              f"depends on come from {distro.title()} {suite}"
              + (f": {', '.join(a.python_modules)})" if a.python_modules else ")"), flush=True)
        home = dest / "home"
        missing, needed = pydeps.fetch_interpreter(a.python_version, src, home)
        if missing:
            pkg.notes.append(f"Python {a.python_version} not found in {distro.title()} {suite} "
                             f"({', '.join(missing)}); the runtime's Python runs the app")
            a.python_version = ""
            kind = runtime_kind
            src = debian_source(arch, deb_arch, pydeps.DEBIAN_SUITE)
        else:
            a.python_home = home
            pkg.notes.append(f"Python {a.python_version} added from {distro.title()} {suite}, for the app's "
                             "compiled modules")
            a.missing_loaded |= {so for so in needed if so not in a.package_sonames and not runtime.provides(so)}
    else:
        src = debian_source(arch, deb_arch, pydeps.DEBIAN_SUITE)
        print(f"(the Python modules it depends on come from Debian {pydeps.DEBIAN_SUITE}, whose Python is the "
              f"runtime's: {', '.join(a.python_modules)})", flush=True)
    if not a.python_modules:
        return
    got = pydeps.fetch(a.python_modules, src, dest / "site", kind, runtime.provides,
                       set((getattr(pkg, "extra", None) or {}).get("gir") or []))
    if got.packages:
        a.python_site = dest / "site"
    if got.typelibs:
        a.typelib_dir = dest / pydeps.TYPELIB_DIR
        pkg.notes.append("Python modules added from Debian: " + ", ".join(
            f"{n} {v}" for n, v in sorted(got.packages.items())))
    if got.missing:
        pkg.notes.append(f"Python modules not found in {src.suite}: " + ", ".join(got.missing))
    a.missing_loaded |= {so for so in got.needed if so not in a.package_sonames and not runtime.provides(so)}


COMPOSE_FAILED = "appstreamcli compose failed"


def _run_teed(cmd: list[str]) -> tuple[int, str]:
    """Run cmd, passing its output through; return (exit status, the output)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    seen = []
    assert proc.stdout is not None
    for raw in iter(proc.stdout.readline, b""):
        text = raw.decode("utf-8", "replace")
        sys.stdout.write(text)
        sys.stdout.flush()
        seen.append(text)
        del seen[:-400]
    return proc.wait(), "".join(seen)


def _skip_appstream_compose(manifest: Path) -> bool:
    """Turn off flatpak-builder's AppStream step in manifest; False if it was off already."""
    m = json.loads(manifest.read_text())
    if m.get("appstream-compose") is False:
        return False
    m["appstream-compose"] = False
    manifest.write_text(json.dumps(m, indent=2) + "\n")
    return True


# what flatpak says when another install or uninstall rewrote its configuration and dropped the
# temporary remote this install had just added
REMOTE_LOST = re.compile(r'Remote "[^"]+" not found')


def _install_built(repo: Path, app_id: str, attempts: int = 4) -> int:
    """Install app_id from the repository flatpak-builder exported it to; return flatpak's exit status.

    This is what flatpak-builder --install does, with other debpak runs kept out
    meanwhile (manage.flatpak_remotes_lock), and done again when the temporary
    remote was lost all the same, to a flatpak run debpak didn't start.
    """
    import time
    from .manage import flatpak_remotes_lock
    cmd = ["flatpak", "install", "--user", "-y", "--noninteractive", "--reinstall", str(repo), app_id]
    for attempt in range(attempts):
        with flatpak_remotes_lock():
            rc, output = _run_teed(host.command(cmd))
        if rc == 0 or not REMOTE_LOST.search(output) or attempt == attempts - 1:
            return rc
        print("(another flatpak install or uninstall running at the same time dropped this one's temporary "
              "remote; installing again)", flush=True)
        time.sleep(3 + 5 * attempt)
    return rc


def _build_install(args, pkg, app_id: str, out: Path, manifest: Path) -> int:
    """Print the build command and, unless --no-build, build and install the manifest.

    Returns flatpak-builder's exit status, 0 when nothing was built, or 1 when
    --build was given and flatpak-builder is missing.
    """
    print(f"\nWrote {manifest}")
    build_cmd = ["flatpak-builder", "--user", "--install", "--force-clean",
                 "--install-deps-from=flathub", str(out / "build-dir"), str(manifest)]
    print("Build & install with:\n  " + " ".join(build_cmd))
    builder = host.which("flatpak-builder")
    if args.build and not builder:
        return _err("flatpak-builder not found")
    if builder and not args.no_build:
        if not host.sees(out):
            return _err(f"{out} is outside your home folder, which flatpak-builder on the host sees differently "
                        "from the debpak Flatpak: give an output folder in your home folder (-o)")
        print("\nBuilding and installing (--no-build to stop after writing the manifest)...", flush=True)
        # built into a repository of its own, then installed from it with other debpak runs kept
        # out (see _install_built)
        repo = out / "repo"
        run_cmd = [c for c in build_cmd if c != "--install"]
        run_cmd.insert(-2, f"--repo={repo}")
        rc, output = _run_teed(host.command(run_cmd))
        if rc and COMPOSE_FAILED in output and _skip_appstream_compose(manifest):
            # what AppStream rejects (an icon it can't read, a .desktop field it doesn't like) only
            # costs the app its software-centre listing; it runs the same without it
            print("\nAppStream couldn't compose the app's metadata (see above); building again without it...",
                  flush=True)
            rc, output = _run_teed(host.command(run_cmd))
        if rc == 0:
            rc = _install_built(repo, app_id)
        shutil.rmtree(repo, ignore_errors=True)
        if rc == 0:
            from .manage import record
            record(app_id, args, pkg, out, installed=True)
            print(f"\nInstalled. Run with:\n  flatpak run {app_id}")
        return rc
    if not builder:
        print("(flatpak-builder isn't installed, so nothing was built: install it and run the command above)")
    print(f"Run with:\n  flatpak run {app_id}")
    return 0


LOCAL_OPTIONS = ("url", "runtime_index", "deps_dir", "native_dir")


def _stamp_options(manifest: Path, args, app_id: str) -> None:
    """Record in the manifest's x-debpak how to convert this app again: the options, minus local paths.

    `debpak recipe check --apply` reads them to convert a vendor's new
    version the same way. Options naming local files (and --url, which
    changes with each version) are listed separately, so the checker knows
    when it can't repeat the conversion.
    """
    from .manage import CONVERT_OPTIONS
    m = json.loads(manifest.read_text())
    set_opts = {k: getattr(args, k, None) for k in CONVERT_OPTIONS if getattr(args, k, None) not in (None, False, [])}
    x = m.setdefault("x-debpak", {})
    x["app-id"] = app_id
    x["convert-options"] = {k: v for k, v in set_opts.items() if k not in LOCAL_OPTIONS}
    local = sorted(k for k in set_opts if k in LOCAL_OPTIONS and k != "url")
    if local:
        x["convert-local-options"] = local
    manifest.write_text(json.dumps(m, indent=2) + "\n")


def _foreign_module(pkg):
    """Return the module that converts a Windows or Mac app: electron or winapp."""
    if pkg.format == "electron":
        from . import electron
        return electron
    from . import winapp
    return winapp


def _plan_foreign(args, pkg, announce: bool = True):
    """Return (pkg, module, plan) for a Windows or Mac app: the Electron route, or Wine when it can't.

    A Windows Electron app the Electron route refuses (a native module with
    no Linux build, as Descript's beamcoder.node; JavaScript compiled for
    Windows only, as GitHub Desktop's; an Electron version debpak can't tell,
    as with Amazon Games) still has its Windows build, and that runs under
    Wine. --no-wine-fallback keeps the refusal. A Mac app has no Windows build
    to fall back to, so its refusal stands.
    """
    mod = _foreign_module(pkg)
    pl = mod.plan(pkg, args)
    if not pl.blockers or pkg.format != "electron" or getattr(args, "no_wine_fallback", False):
        return pkg, mod, pl
    from .foreign import wine_package, one_line
    wpkg = wine_package(pkg)
    if wpkg is None:
        return pkg, mod, pl
    from . import winapp
    wpl = winapp.plan(wpkg, args)
    if wpl.blockers:
        pl.notes.append("the Windows build can't run under Wine either: " + "; ".join(wpl.blockers))
        return pkg, mod, pl
    why = "; ".join(one_line(b, 400) for b in pl.blockers)
    wpl.notes.insert(0, "this is the Windows build of the app, running under Wine: the Electron route, which "
                        f"runs the app's JavaScript on Linux Electron, can't take it ({why}). "
                        "--no-wine-fallback refuses instead")
    wpl.data["electron_blockers"] = list(pl.blockers)
    if announce:
        print(f"The Electron route can't convert {pkg.extra.get('display_name', pkg.name)}, so it's converted as "
              "its Windows build running under Wine. Why:\n" + "".join(f"  x {b}\n" for b in pl.blockers),
              flush=True)
    return wpkg, winapp, wpl


def _convert_foreign(args, pkg, out: Path) -> int:
    """Convert an Electron app from Windows or macOS, or a Windows program for Wine (see cmd_convert)."""
    if args.mode == "extra-data" and not args.url:
        return _err("--mode extra-data requires --url (the vendor's download URL for this exact file)")
    for opt in ("deps_dir", "mirror", "rpm_repo"):
        if getattr(args, opt, None):
            print(f"(--{opt.replace('_', '-')} is ignored: Windows and Mac apps don't use Linux libraries)")
    app_id = args.app_id or default_app_id(pkg.name)
    if not APP_ID_RE.match(app_id):
        return _err(f"invalid app id {app_id!r} (needs 3+ dot-separated components)")
    pkg, mod, pl = _plan_foreign(args, pkg)
    if args.mode == "extra-data" and "replay" not in pkg.extra:
        pl.blockers.append("--mode extra-data can't be used: " + pkg.extra.get("replay_problem", "unknown")
                           + "; use the default bundle mode")
    if not (args.anyway or args.no_flathub_check):
        from .manage import flathub_match
        try:
            hit = flathub_match([pkg.extra.get("display_name", pkg.name), pkg.name])
        except Exception:       # never let the check break a conversion
            hit = None
        if hit:
            print(f"{hit.name} is already on Flathub as {hit.app_id}; the official Flatpak will work better "
                  f"than a conversion:\n  flatpak install flathub {hit.app_id}\n"
                  "(pass --anyway to convert this package regardless)")
            return EXIT_ON_FLATHUB
    if pl.blockers and not args.force:
        print(pl.render(), end="")
        print("\nNot writing a manifest. Fix the issues above or pass --force to write one anyway.")
        return 2
    out.mkdir(parents=True, exist_ok=True)
    manifest = mod.write(pl, out, app_id, args)
    _stamp_options(manifest, args, app_id)
    report = pl.render()
    (out / "report.txt").write_text(report)
    (out / "report.json").write_text(json.dumps(pl.to_json(), indent=2) + "\n")
    print(report, end="")
    return _build_install(args, pkg, app_id, out, manifest)


def _flathub_hit(pkg, a):
    from .desktop import app_display_name
    from .manage import flathub_match
    from .manage import different_app
    names = [pkg.name]
    if a.desktop_file:
        names.append(app_display_name(pkg.root, a.desktop_file, pkg.name))
    try:
        hit = flathub_match(names)
        if hit and (why := different_app(hit, getattr(pkg, "homepage", "") or pkg.control.get("Homepage", ""),
                                         Path(a.desktop_file).stem if a.desktop_file else "")):
            pkg.notes.append(f"Flathub's {hit.name} ({hit.app_id}) looks like a different app ({why}), "
                             "so this is converted anyway")
            return None
        return hit
    except Exception:       # never let the check break a conversion
        return None


def cmd_list(args) -> int:
    """Print the apps debpak installed, from the registry."""
    from .manage import load_registry, registry_path
    reg = load_registry()
    if not reg:
        print(f"no apps installed by debpak ({registry_path()})")
        return 0
    for app_id, e in sorted(reg.items()):
        src = e.get("snap") and f"snap {e['snap']} r{e.get('snap_revision', '?')}" or \
            (e.get("options") or {}).get("url") or e.get("source")
        print(f"{app_id:<40} {e.get('format', '?'):<9} {e.get('version', ''):<16} {src}")
    return 0


def cmd_update(args) -> int:
    """Check converted apps for new versions, and convert and reinstall the changed ones.

    Returns 0 when every app is up to date or was updated. Otherwise it returns
    1 for an app that can't be checked or isn't in the registry, or the exit
    status of a conversion that failed.
    """
    from .manage import check_update, load_registry, options_to_argv, update_workdir
    reg = load_registry()
    ids = args.app_ids or sorted(reg)
    if not ids:
        print("no apps installed by debpak")
        return 0
    rc = 0
    work = update_workdir()
    try:
        for app_id in ids:
            entry = reg.get(app_id)
            if not entry:
                rc = _err(f"{app_id} wasn't installed by debpak (see `debpak list`)")
                continue
            chk = check_update(app_id, entry, download=not args.check, workdir=work)
            print(f"{app_id}: {chk.status} ({chk.detail})")
            if entry.get("recipe") and chk.status == "update available" and not args.check:
                code = main(["install", entry["recipe"], "--recipes", entry["recipe_source"], "--yes"])
                if code != 0:
                    rc = code
            elif chk.new_file and not args.check:
                argv = ["convert", str(chk.new_file), "--app-id", app_id, "-o", entry["output"], "--anyway",
                        *options_to_argv(entry.get("options") or {})]
                code = main(argv)
                if code != 0:
                    rc = code
            elif chk.status == "can't check":
                rc = rc or 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return rc


def cmd_install(args) -> int:
    """Install an app from a recipe.

    Exit status:
        0: installed (or, with --no-build, downloaded).
        1: no such recipe, several match, a download or hash check failed, or
           the user said no.
        Anything else is flatpak-builder's own exit status.
    """
    from . import recipes
    source = args.recipes or recipes.default_source()
    try:
        index = recipes.load_index(source)
        hits = recipes.find(index, args.name)
        if not hits:
            near = recipes.search(index, args.name)
            return _err(f"no recipe for {args.name!r} in {source}"
                        + (": did you mean " + ", ".join(r["id"] for r in near[:5]) + "?" if near else
                           " (`debpak recipe list` shows what's there; `debpak convert` works without one)"))
        if len(hits) > 1:
            return _err(f"{args.name!r} matches several recipes: " + ", ".join(r["id"] for r in hits)
                        + "; give the app ID")
        entry = hits[0]
        dest = recipes.recipes_dir() / entry["id"]
        recipe = recipes.download(source, entry, dest)
    except recipes.RecipeError as e:
        return _err(str(e))
    print(recipes.describe(recipe), end="")
    manifest = dest / f"{entry['id']}.json"
    build_cmd = ["flatpak-builder", "--user", "--install", "--force-clean", "--install-deps-from=flathub",
                 str(dest / "build-dir"), str(manifest)]
    if args.no_build:
        print(f"Recipe in {dest}. Build and install with:\n  " + " ".join(build_cmd))
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            return _err("not asking without a terminal: pass --yes to install")
        if input("Install it? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Not installed.")
            return 1
    if not host.which("flatpak-builder"):
        return _err("flatpak-builder isn't installed (it's in your distribution's flatpak-builder package)")
    rc = subprocess.call(host.command(build_cmd))
    if rc == 0:
        recipes.record(recipe, source, dest, entry["recipe_sha256"])
        shutil.rmtree(dest / "build-dir", ignore_errors=True)
        shutil.rmtree(dest / ".flatpak-builder", ignore_errors=True)
        print(f"\nInstalled. Run with:\n  flatpak run {entry['id']}")
    return rc


def cmd_recipe(args) -> int:
    """Make, index or list recipes (see recipes.py)."""
    from . import recipes
    try:
        if args.recipe_cmd == "make":
            check = None
            if args.check:
                text = Path(args.check[1:]).read_text() if args.check.startswith("@") else args.check
                try:
                    check = json.loads(text)
                except ValueError as e:
                    return _err(f"--check isn't valid JSON ({e})")
            dest = recipes.make(Path(args.output_dir), Path(args.to), allow_binaries=args.allow_binaries,
                                note=args.note or "", check=check)
            print(f"Wrote {dest} and updated {Path(args.to) / 'index.json'}")
            print(recipes.describe(json.loads((dest / "recipe.json").read_text())), end="")
            return 0
        if args.recipe_cmd == "index":
            print(f"Wrote {recipes.reindex(Path(args.dir))}")
            return 0
        if args.recipe_cmd == "check":
            results = recipes.check_updates(Path(args.dir), args.ids or None, apply=args.apply)
            for r in results:
                change = f"{r['old']} -> {r['new']}" if r["new"] and r["new"] != r["old"] else r["old"]
                print(f"{r['id']:<40} {r['status']:<13} {change}" + (f"  {r['detail']}" if r["detail"] else ""))
            if args.summary:
                lines = [f"- {r['id']}: {r['old']} → {r['new']} ({r['status']})" + (f": {r['detail']}" if
                         r["status"] in ("error", "can't update") else "")
                         for r in results if r["status"] in ("updated", "update", "error", "can't update")]
                Path(args.summary).write_text("\n".join(lines) + "\n" if lines else "")
            return 1 if any(r["status"] == "error" for r in results) else 0
        if args.recipe_cmd == "publish":
            built = recipes.publish(Path(args.dir), Path(args.repo), args.url, gpg_key=args.gpg_key,
                                    gpg_homedir=args.gpg_homedir, title=args.title, ids=args.only or None)
            print(f"Built {len(built)} apps into {args.repo}. Users add it with:\n"
                  f"  flatpak remote-add --user --if-not-exists debpak {args.url.rstrip('/')}/debpak.flatpakrepo")
            return 0
        source = args.recipes or recipes.default_source()
        found = recipes.search(recipes.load_index(source), args.term)
        for r in found:
            print(f"{r['id']:<40} {r['version']:<14} {r['name']}" + (f" - {r['summary']}" if r.get("summary") else ""))
        if not found:
            print(f"no recipes{' matching ' + repr(args.term) if args.term else ''} in {source}")
        return 0
    except recipes.RecipeError as e:
        return _err(str(e))


def cmd_uninstall(args) -> int:
    """Uninstall a Flatpak debpak installed and drop it from the registry."""
    from .manage import load_registry, update_registry
    entry = load_registry().get(args.app_id)
    if not entry and not args.force:
        return _err(f"{args.app_id} wasn't installed by debpak (see `debpak list`); --force to uninstall anyway")
    cmd = ["flatpak", "uninstall", "--user", "-y", *(["--delete-data"] if args.delete_data else []), args.app_id]
    print("$ " + " ".join(cmd))
    from .manage import flatpak_remotes_lock
    try:
        with flatpak_remotes_lock():        # it takes the app's temporary remote away
            code = subprocess.call(host.command(cmd))
    except OSError as e:
        return _err(f"flatpak: {e}")
    if code != 0:
        return code
    if entry:
        if args.delete_build and Path(entry.get("output", "")).is_dir():
            shutil.rmtree(entry["output"])
            print(f"removed {entry['output']}")
        update_registry(lambda reg: reg.pop(args.app_id, None))
    return 0


def cmd_desnap(args) -> int:
    """Replace installed snaps with Flatpaks; see desnap.run."""
    from .desnap import run
    return run(args)


def cmd_runtime_index(args) -> int:
    """Index an installed runtime, or a usr tree with --root, and print a summary."""
    try:
        if args.root:
            if not args.ref:
                return _err("--root needs --ref ID/ARCH/BRANCH to label the index")
            rid, arch, branch = parse_ref(args.ref, args.arch)
            idx = index_root(args.root, f"{rid}/{arch}/{branch}", arch)
        else:
            if not args.ref:
                return _err("give a runtime ref, e.g. org.freedesktop.Platform//25.08")
            idx = get_index(args.ref, args.arch or host_arch(), rebuild=True)
    except (RuntimeError, ValueError) as e:
        return _err(str(e))
    if args.output:
        idx.save(Path(args.output))
        print(f"wrote {args.output}")
    print(f"{idx.ref}: {len(idx.sonames)} libraries, glibc {idx.glibc or '?'}")
    return 0


def cmd_smoke(args) -> int:
    """Run an app with LD_DEBUG=libs,files (or read such a log) and report failed loads.

    Exit status 2 if a library the app needs at startup is missing, else 0.
    """
    import json
    import shlex
    from pathlib import Path

    from .smoke import flatpak_argv, parse_ld_debug, run_logged, to_report
    if args.log:
        log = Path(args.log)
        name = args.app_id or log.stem
    else:
        if args.exec_cmd:
            argv = shlex.split(args.exec_cmd) + [a for a in args.args if a != "--"]
            name = args.app_id or Path(argv[0]).name
        elif args.app_id:
            argv = flatpak_argv(args.app_id, args.command, [a for a in args.args if a != "--"])
            name = args.app_id
        else:
            return _err("give a Flatpak app ID, --exec COMMAND or --log FILE")
        wait = args.timeout or None
        print(f"running {name} with LD_DEBUG=libs,files" + (f" for up to {wait:g}s" if wait else ""),
              file=sys.stderr)
        try:
            log, code = run_logged(argv, wait, log=Path(args.save_log) if args.save_log else None)
        except OSError as e:
            return _err(f"{argv[0]}: {e}")
        if code is None and args.app_id and not args.exec_cmd:
            subprocess.run(host.command(["flatpak", "kill", args.app_id]), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        print(f"log: {log}", file=sys.stderr)
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            report = to_report(parse_ld_debug(f), name)
    except OSError as e:
        return _err(str(e))
    if args.output:
        Path(args.output).write_text(json.dumps(report.to_json(), indent=2) + "\n")
    print(json.dumps(report.to_json(), indent=2) if args.json else report.render(), end="" if not args.json else "\n")
    return 2 if report.worst == "fatal" else 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every debpak subcommand."""
    ap = argparse.ArgumentParser(prog="debpak", description="Turn Linux app packages (.deb, .rpm, Arch "
                                 ".pkg.tar.*, AppImage, snap, .tar.gz/.zip, .run) into Flatpaks, "
                                 "along with Windows programs (through Wine) and Electron apps from "
                                 "Windows or macOS, and replace installed snaps with Flatpaks.")
    ap.add_argument("--version", action="version", version=f"debpak {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def runtime_opts(p):
        p.add_argument("--runtime", help="target runtime ref, e.g. org.freedesktop.Platform//25.08")
        p.add_argument("--runtime-index", help="use a saved runtime index JSON instead of an installed runtime")
        p.add_argument("--reindex", action="store_true", help="rebuild the cached runtime index")
        p.add_argument("--exec", help="override the main executable (path inside the package or command name)")
        p.add_argument("--allow-run", action="store_true",
                       help="AppImage without unsquashfs (or dwarfsextract): let the AppImage unpack itself "
                            "(this runs it)")

    def foreign_opts(p):
        g = p.add_argument_group("Windows and Mac apps")
        g.add_argument("--electron-version", metavar="VERSION", help="Electron version the app was built with, when debpak can't tell")
        g.add_argument("--electron-zip", metavar="FILE", help="use this Linux Electron zip instead of downloading it")
        g.add_argument("--no-wine-fallback", action="store_true",
                       help="refuse a Windows Electron app the Electron route can't convert, instead of "
                            "converting its Windows build to run under Wine")
        g.add_argument("--native-dir", metavar="DIR", help="folder of Linux builds of the app's native .node modules")
        g.add_argument("--no-fetch-natives", action="store_true",
                       help="don't look for Linux builds of native modules on npm and GitHub")
        g.add_argument("--wine-branch", metavar="BRANCH", help="org.winehq.Wine branch, e.g. stable-26.08 (default: wow64-25.08, "
                                             "or stable-BRANCH for the runtime's branch)")
        g.add_argument("--wine-runtime", action="append", metavar="VERB",
                       help="Wine: install this runtime with winetricks on first run, e.g. vcrun2022, dotnet48, "
                            "corefonts (repeatable); wine-mono installs no .NET runtime and keeps a .NET program "
                            "on wine-mono")
        g.add_argument("--fd-limit", type=int, metavar="N",
                       help="start the app with at most N open files (ulimit -Sn): a program that select()s on "
                            "every file it may open aborts past 1024 (\"bit out of range 0 - FD_SETSIZE\")")
        g.add_argument("--writable", action="store_true",
                       help="run the program from a copy of its folder in the app's data: Wine programs, and "
                            "Linux ones under /opt, that write next to themselves")

    pkg_help = (".deb, .rpm, .pkg.tar.*, .AppImage, .snap or /snap/NAME/current, .tar.gz/.tar.xz/.zip, .run, "
                "Windows .exe/.msi/.msix or program folder, macOS .dmg/.app")
    p = sub.add_parser("inspect", help="analyze a package and report what conversion would need")
    p.add_argument("deb", metavar="PACKAGE", help=pkg_help)
    runtime_opts(p)
    foreign_opts(p)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-flathub-check", action="store_true", help="don't look the app up on Flathub")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("convert", help="turn a package into a Flatpak and install it (--no-build: manifest only)")
    p.add_argument("deb", metavar="PACKAGE", help=pkg_help)
    p.add_argument("--app-id", help="Flatpak app id (default local.debpak.<package>)")
    runtime_opts(p)
    foreign_opts(p)
    p.add_argument("-o", "--output", default="out", help="output directory (default: ./out)")
    p.add_argument("--mode", choices=["bundle", "extra-data"], default="bundle",
                   help="bundle (default): copy the vendor's files into the Flatpak; extra-data: download "
                        "them when the Flatpak is installed (needs --url)")
    p.add_argument("--url", help="vendor download URL of this exact file (extra-data mode)")
    p.add_argument("--deps-dir", action="append",
                   help="directory of .deb/.rpm/.pkg.tar.* files to take missing libraries from")
    p.add_argument("--rpm-repo", action="append", metavar="URL",
                   help="RPM repository to fetch missing libraries from (the folder with repodata/), e.g. "
                        "https://dl.fedoraproject.org/pub/fedora/linux/releases/41/Everything/x86_64/os")
    p.add_argument("--mirror", help="Debian/Ubuntu mirror to fetch missing libraries from, "
                                    "e.g. https://deb.debian.org/debian")
    p.add_argument("--suite", default="stable", help="mirror suite (default: stable)")
    p.add_argument("--components", default="main", help="comma-separated mirror components (default: main)")
    p.add_argument("--permissive", action="store_true", help="grant --filesystem=home")
    p.add_argument("--force", action="store_true", help="write a manifest even if blockers were found")
    p.add_argument("--build", action="store_true", help="fail if flatpak-builder isn't available "
                                                           "(building and installing is the default when it is)")
    p.add_argument("--no-build", action="store_true", help="only write the manifest; don't build or install")
    p.add_argument("--anyway", action="store_true", help="convert even if the app is already on Flathub")
    p.add_argument("--no-flathub-check", action="store_true", help="don't look the app up on Flathub")
    p.add_argument("--no-auto-mirror", action="store_true",
                   help="with no --deps-dir, --mirror or --rpm-repo, don't fill missing libraries from Ubuntu "
                        "(for a snap the release it was built on, for other packages the current LTS)")
    p.add_argument("--keep-work", action="store_true", help="keep the temporary extraction directory")
    g = p.add_argument_group("checking the app (see --no-verify)")
    g.add_argument("--no-verify", dest="verify", action="store_false",
                   help="don't start the built app on a virtual display to check it (the default when the host "
                        "has xvfb-run), nor rebuild it with the changes its failure points to")
    g.add_argument("--add-library", action="append", metavar="SONAME",
                   help="bundle this library too, though nothing shows the app needs it (repeatable)")
    g.add_argument("--add-permission", action="append", metavar="ARG",
                   help="add this finish-arg, e.g. --socket=x11 (repeatable)")
    g.add_argument("--java", action="store_true", help="add a JDK, for a Java app debpak didn't recognise")
    g.add_argument("--mono", action="store_true", help="add Mono, for a .NET app debpak didn't recognise")
    g.add_argument("--add-program", action="append", metavar="NAME",
                   help="bring the program NAME, which the app runs, from a distribution's package of that name "
                        "(repeatable)")
    g.add_argument("--seed-home", action="append", metavar="PATH",
                   help="a file the program wants under the home folder (.config/NAME/FILE) that the package "
                        "ships a copy of in share/NAME: the folder's files are copied there at first start "
                        "(repeatable)")
    g.add_argument("--chdir", action="store_true",
                   help="start the program in its own folder, for one that finds its files relative to it")
    g.add_argument("--no-chromium-sandbox", action="store_true",
                   help="Electron and CEF apps: start with --no-sandbox instead of under zypak")
    g.add_argument("--signal-onstack", action="store_true",
                   help="preload a library that has every signal handler run on the signal stack (SA_ONSTACK), "
                        "for a Go program that a C library's handlers kill (\"non-Go code set up signal handler "
                        "without SA_ONSTACK flag\"); automatic for Go programs that link WebKitGTK")
    p.set_defaults(func=cmd_convert, verify=True)

    p = sub.add_parser("smoke", help="run a converted app with the loader's logging on and report libraries "
                                     "it tries to load at runtime (dlopen) but can't find")
    p.add_argument("app_id", nargs="?", help="installed Flatpak app ID to run")
    p.add_argument("args", nargs="*", help="arguments for the app, after --")
    p.add_argument("--command", help="run this command inside the Flatpak instead of its default")
    p.add_argument("--exec", dest="exec_cmd", help="run this command line directly (no Flatpak), e.g. to "
                                                    "check an unpacked app")
    p.add_argument("--log", help="read an existing LD_DEBUG=libs,files log instead of running anything")
    p.add_argument("--timeout", type=float, default=20,
                   help="seconds before the app is closed (default 20; 0 = wait until you close it)")
    p.add_argument("--save-log", help="keep the raw log here")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-o", "--output", help="write the gap report JSON here (for gaprank)")
    p.set_defaults(func=cmd_smoke)

    p = sub.add_parser("list", help="apps debpak converted and installed")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("install", help="install an app from a recipe someone already converted and checked")
    p.add_argument("name", help="app name or ID, e.g. 'Vendor App' or com.vendor.App")
    p.add_argument("--recipes", metavar="URL|DIR", help="recipe collection (default: $DEBPAK_RECIPES, else the "
                                                         "recipes/ folder of the debpak repository)")
    p.add_argument("-y", "--yes", action="store_true", help="don't ask before building")
    p.add_argument("--no-build", action="store_true", help="download and check the recipe, but don't build it")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("recipe", help="make, index or list recipes")
    rsub = p.add_subparsers(dest="recipe_cmd", required=True)
    r = rsub.add_parser("make", help="turn a conversion (convert --mode extra-data --url ... -o OUT) into a recipe")
    r.add_argument("output_dir", metavar="OUT", help="the folder convert wrote")
    r.add_argument("--to", required=True, metavar="DIR", help="recipe collection to add it to, e.g. recipes/")
    r.add_argument("--note", help="what you tested, shown when someone installs it")
    r.add_argument("--allow-binaries", action="store_true",
                   help="accept binary files besides icons (only ones you may redistribute)")
    r.add_argument("--check", metavar="JSON|@FILE",
                   help='how to find new versions, e.g. \'{"type": "redirect", "url": "https://vendor.example/'
                        'latest.deb", "version": "_([0-9.]+)_amd64"}\' (kept from the old recipe when omitted)')
    r = rsub.add_parser("index", help="rewrite a collection's index.json")
    r.add_argument("dir", metavar="DIR")
    r = rsub.add_parser("check", help="look for new vendor versions; --apply converts them and updates the recipes")
    r.add_argument("dir", metavar="DIR")
    r.add_argument("ids", nargs="*", metavar="APP_ID", help="only these recipes")
    r.add_argument("--apply", action="store_true", help="download, convert and replace recipes that are out of date")
    r.add_argument("--summary", metavar="FILE", help="write a Markdown list of changes (for a pull request)")
    r = rsub.add_parser("publish", help="build a collection into a Flatpak repository for a static web host")
    r.add_argument("dir", metavar="DIR")
    r.add_argument("--repo", required=True, help="repository folder to create or update")
    r.add_argument("--url", required=True, help="the URL the repository will be served from")
    r.add_argument("--gpg-key", help="sign with this key (strongly recommended)")
    r.add_argument("--gpg-homedir", help="GnuPG home with that key")
    r.add_argument("--title", default="debpak recipes")
    r.add_argument("--only", action="append", metavar="APP_ID", help="build only this recipe (repeatable)")
    r = rsub.add_parser("list", help="list the recipes in a collection")
    r.add_argument("term", nargs="?", help="only recipes whose name, ID or summary contains this")
    r.add_argument("--recipes", metavar="URL|DIR", help="recipe collection (default as for install)")
    p.set_defaults(func=cmd_recipe)

    p = sub.add_parser("update", help="re-download converted apps (vendor URL or Snap Store) and rebuild changed ones")
    p.add_argument("app_ids", nargs="*", help="apps to update (default: all of them)")
    p.add_argument("--check", action="store_true", help="only report what's out of date")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("uninstall", help="uninstall an app debpak installed")
    p.add_argument("app_id", help="as shown by `debpak list`")
    p.add_argument("--delete-data", action="store_true", help="also delete the app's data in ~/.var/app")
    p.add_argument("--delete-build", action="store_true", help="also delete its conversion output folder")
    p.add_argument("--force", action="store_true", help="uninstall even if debpak didn't install it")
    p.set_defaults(func=cmd_uninstall)

    p = sub.add_parser("desnap", help="replace your snaps with Flatpaks: Flathub where it has the app, "
                                      "converted snaps otherwise")
    p.add_argument("--yes", "-y", action="store_true", help="answer yes to every question")
    p.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    p.add_argument("--only", nargs="+", metavar="SNAP", help="only these snaps")
    p.add_argument("--copy-data", action="store_true", help="copy each app's snap data (~/snap/NAME) into its "
                                                            "Flatpak data folder (~/.var/app/ID), never overwriting")
    p.add_argument("--remove-snaps", action="store_true", help="remove each snap once its Flatpak is installed")
    p.add_argument("--block-snapd", action="store_true", help="pin snapd out of apt, so debs that only install a "
                                                              "snap (firefox, chromium-browser, thunderbird) can't "
                                                              "bring it back; with --remove-snaps, also offer to "
                                                              "purge snapd once no app snaps are left")
    p.add_argument("--no-convert", action="store_true", help="only use Flathub; leave snaps it doesn't have")
    p.add_argument("-o", "--output", default=None, help="where conversions go (default ~/.local/share/debpak/desnap)")
    p.add_argument("--runtime-index", help=argparse.SUPPRESS)
    p.add_argument("--deps-dir", action="append", help=argparse.SUPPRESS)
    p.add_argument("--no-build", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_desnap)

    p = sub.add_parser("runtime-index", help="index an installed runtime (or a directory) for gap analysis")
    p.add_argument("ref", nargs="?", help="runtime ref, e.g. org.freedesktop.Platform//25.08")
    p.add_argument("--root", help="index this usr-tree directory instead of an installed runtime")
    p.add_argument("--ref", dest="ref_opt", help=argparse.SUPPRESS)
    p.add_argument("--arch", help="architecture (default: host)")
    p.add_argument("-o", "--output", help="also save the index to this file")
    p.set_defaults(func=cmd_runtime_index)
    return ap


def main(argv: list[str] | None = None) -> int:
    """Run the debpak command line with argv (default: sys.argv[1:]) and return the exit status."""
    args = build_parser().parse_args(argv)
    try:        # so flatpak-builder's output, written straight to the same file, lands after ours
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    if getattr(args, "ref_opt", None) and not args.ref:
        args.ref = args.ref_opt
    return args.func(args)
