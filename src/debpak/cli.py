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
from .analyze import analyze, check_versions, is_never_bundle
from .deb import DebError
from .packages import FLATPAK_TO_DEB, PackageError, open_package
from .permissions import Permission, infer
from .report import render, to_json
from .resolve import (DEBIAN_RELEASES, FEDORA_RELEASE, UBUNTU_PREVIOUS_LTS, MirrorSource, ResolveResult,
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
# default has: OpenWhispr's helpers and RSS Guard's Qt need GLIBC_2.43, which 25.08 (2.42) lacks
NEWER_RUNTIME = {("org.freedesktop.Platform", "25.08"): "org.freedesktop.Platform//26.08"}


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
        installed = _install_and_index(args, newer, arch)
        if installed is None:
            return None
        index = installed
    return index if _glibc_key(a.max_glibc) <= _glibc_key(index.glibc) else None


def _install_and_index(args, ref: str, arch: str) -> RuntimeIndex | None:
    """Install the runtime ref when the build would install it anyway, and return its index; None if that fails."""
    if args.no_build or not host.which("flatpak-builder") or not _install_runtime(ref, arch):
        return None
    try:
        return get_index(ref, arch)
    except RuntimeError:
        return None


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


def _home_permissions(a) -> list[Permission]:
    """Return --persist for the home folder a program keeps its files in (Analysis.home_skel,
    Analysis.home_folder): without it ~/.parsec would be lost when the app exits."""
    perms = []
    if a.home_skel:
        skel, home_dir = a.home_skel
        perms.append(Permission(f"--persist={home_dir}",
                                f"the app keeps its files in ~/{home_dir} (first copied from /{skel})"))
    if a.home_folder and all(p.arg != f"--persist={a.home_folder}" for p in perms):
        perms.append(Permission(f"--persist={a.home_folder}",
                                f"the app keeps itself, its updates and the user's data in ~/{a.home_folder}"))
    return perms


def cmd_inspect(args) -> int:
    """Print what converting the package would involve. Exit status 0, or 1 on error."""
    with tempfile.TemporaryDirectory(prefix="debpak-") as tmp:
        try:
            pkg = _open(args, tmp)
        except (PackageError, DebError, OSError) as e:
            return _err(str(e))
        if pkg.format in FOREIGN:
            return _inspect_foreign(args, pkg)
        return _inspect_package(args, pkg)


def _inspect_foreign(args, pkg) -> int:
    """Print the plan for a Windows or Mac app; see cmd_inspect."""
    pl = _foreign_module(pkg).plan(pkg, args)
    print(json.dumps(pl.to_json(), indent=2) if args.json else pl.render(), end="\n" if args.json else "")
    return 2 if pl.blockers else 0


def _inspect_package(args, pkg) -> int:
    """Analyze an unpacked Linux package against the runtime named, if any, and print the report; see cmd_inspect."""
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
    return _inspect_report(args, pkg, a)


def _inspect_report(args, pkg, a) -> int:
    """Print what the analysis found, with the permissions it implies and any Flathub match; see cmd_inspect."""
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
    app_id = _app_id_of(args)
    if not selfcheck.available() or not app_id:
        return rc
    wine = (Path(args.output) / "wine").is_dir() or _manifest_base(args) == "org.winehq.Wine"
    kind = _manifest_kind(args)
    seconds = selfcheck.SECONDS.get("wine" if wine else kind, selfcheck.DEFAULT_SECONDS)
    tried: set[str] = set()
    for round_ in range(1, selfcheck.ROUNDS + 1):
        done = _check_round(args, app_id, seconds, kind, wine, tried, round_)
        if done is not None:
            return done
        kind = _manifest_kind(args)
    return 0


def _check_round(args, app_id: str, seconds: int, kind: str, wine: bool, tried: set[str], round_: int) -> int | None:
    """Start the app once and convert it again with what its failure points to.

    Returns the exit status when the check is over, or None to check the new build.
    """
    from . import selfcheck
    print(f"\nChecking the app: starting it on a virtual display for {seconds} seconds...", flush=True)
    obs = selfcheck.observe(app_id, seconds)
    print(f"Check: {obs.describe()}.")
    if obs.ok:
        return 0
    d = _diagnose(args, obs, app_id, seconds, kind, wine, tried)
    if not d.remedies:
        print("Check: nothing in what it printed points to a change debpak can make"
              + (f" ({'; '.join(d.evidence)})" if d.evidence else "") + ".")
        return 0
    again = _convert_with_remedies(args, d.remedies, tried, round_)
    if again is None:
        return 0
    if again != 0:
        return again
    return None


def _diagnose(args, obs, app_id: str, seconds: int, kind: str, wine: bool, tried: set[str]):
    """Work out what to change from a failed start, starting it again with the loader's logging if need be."""
    from . import selfcheck
    d = selfcheck.diagnose(obs, kind, wine, tried)
    if d.remedies:
        return d
    print("Starting it again with the loader's logging on, to see why...", flush=True)
    logged = selfcheck.observe(app_id, seconds, selfcheck.diagnostic_env(wine))
    d = selfcheck.diagnose(logged, kind, wine, tried)
    if not wine:
        for so in selfcheck.failed_loads(logged.output, kind):
            d.add(selfcheck.Remedy(f"lib:{so}", f"it tried to load {so}, which wasn't there",
                                   "add_library", so), tried)
    # only a portable app (an archive's folder) keeps its files beside itself
    if not d.remedies and not wine and not obs.running and obs.code == 0 and _manifest_graphical(args) \
            and (_manifest(args).get("x-debpak") or {}).get("format") in ("tarball", "run"):
        d.add(selfcheck.QUIT_AT_ONCE, tried)
    return d


def _convert_with_remedies(args, remedies: list, tried: set[str], round_: int) -> int | None:
    """Convert again with the remedies applied.

    Returns the new conversion's exit status (0 to check the app again), or
    None when the earlier build stays and the check is over.
    """
    from . import selfcheck
    for r in remedies:
        print(f"  - {r.why}: {_remedy_flag(r)}")
        tried.add(r.key)
    before = {r.option: copy.copy(getattr(args, r.option, None)) for r in remedies}
    written = _manifest_stamp(args)
    selfcheck.apply(args, remedies)
    print(f"\nConverting again with {'that change' if len(remedies) == 1 else 'those changes'} "
          f"(round {round_} of {selfcheck.ROUNDS})...", flush=True)
    rc = _convert_once(args)
    if rc == 0:
        return 0
    for option, value in before.items():
        setattr(args, option, value)
    if rc == 2:
        # the change made the conversion refuse (nothing was written), so the build from the round
        # before is still the installed one, and it stays
        print("Check: converting with that change was refused, so the app stays as it was built before.")
        return None
    # The changes made it worse: Tusk's loader log named libnss_myhostname.so.2, which debpak
    # won't bundle, and the conversion stopped, though the app it had built was running.
    # The build from before is what the user gets.
    print("Converting with those changes failed; keeping the app as it was built before them.", flush=True)
    if _manifest_stamp(args) == written:
        return None                # nothing was written: the earlier build is still installed
    rc = _convert_once(args)
    return rc if rc != 0 else None


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
    work = Path(tempfile.mkdtemp(prefix="debpak-"))
    try:
        pkg = _open(args, work / "src")
        if pkg.format in FOREIGN:
            return _convert_foreign(args, pkg, Path(args.output))
        return _convert_package(args, pkg, work)
    except (DebError, PackageError, ValueError) as e:
        return _err(str(e))
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"(work dir kept at {work})")


def _convert_package(args, pkg, work: Path) -> int:
    """Convert an unpacked Linux package; see _convert_once for the exit status."""
    arch = _target_arch(pkg)
    if not arch:
        return _err(f"unsupported package architecture {pkg.pkg_arch!r}")
    app_id = _checked_app_id(args, pkg)
    if isinstance(app_id, int):
        return app_id

    # first pass without a runtime to learn which runtime fits
    probe = analyze(pkg, None, exec_override=_exec_for(args, pkg))
    if not (args.anyway or args.no_flathub_check) and (hit := _flathub_hit(pkg, probe)):
        return _say_on_flathub(hit)
    if getattr(pkg, "format", "") == "snap":
        _prepare_snap(args, pkg, arch)
    runtime = _runtime_for(args, probe, arch)
    if isinstance(runtime, int):
        return runtime
    a = analyze(pkg, runtime, exec_override=_exec_for(args, pkg))
    if (newer := _newer_runtime(args, runtime, a, arch)):
        print(f"(it needs {a.max_glibc}, which {runtime.ref} doesn't have; using {newer.ref})")
        runtime = newer
        a = analyze(pkg, runtime, exec_override=_exec_for(args, pkg))
    _apply_options(args, a, pkg, runtime, arch, work)
    return _bundle_stage_build(args, pkg, work, a, runtime, arch, app_id)


def _checked_app_id(args, pkg) -> str | int:
    """Return the app ID to convert to (--app-id, or the default), or an exit status when it isn't valid."""
    app_id = args.app_id or default_app_id(pkg.name)
    if not APP_ID_RE.match(app_id):
        return _err(f"invalid app id {app_id!r} (needs 3+ dot-separated components)")
    return app_id


def _say_on_flathub(hit) -> int:
    """Print that Flathub already has the app and how to install it; return EXIT_ON_FLATHUB."""
    print(f"{hit.name} is already on Flathub as {hit.app_id}; the official Flatpak will work better "
          f"than a conversion:\n  flatpak install flathub {hit.app_id}\n"
          "(pass --anyway to convert this package regardless)")
    return EXIT_ON_FLATHUB


def _refuse_to_write(report: str) -> int:
    """Print the report and that no manifest is written; return 2."""
    print(report, end="")
    print("\nNot writing a manifest. Fix the issues above or pass --force to write one anyway.")
    return 2


def _bundle_stage_build(args, pkg, work: Path, a, runtime: RuntimeIndex, arch: str, app_id: str) -> int:
    """Bundle the libraries the runtime lacks, write the manifest and /app tree, then build; see _convert_once."""
    libstage = work / "bundled"
    res = _fill_library_gaps(args, a, runtime, arch, libstage)
    elfs = _settle_bundled_versions(a, res, runtime, libstage)
    perms = _permissions(args, a, elfs)
    hard_unresolved = res.unresolved & a.missing_hard
    if (a.blockers or hard_unresolved or res.refused) and not args.force:
        return _refuse_to_write(render(a, perms, res))

    out = Path(args.output)
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


def _target_arch(pkg) -> str | None:
    """Return the Flatpak architecture to build for: the package's, or the host's for an architecture-free one."""
    if pkg.flatpak_arch:
        return pkg.flatpak_arch
    if pkg.pkg_arch in ("noarch", "any", "all", ""):
        return host_arch()       # architecture-independent package (scripts, Java, ...)
    return None


def _prepare_snap(args, pkg, arch: str) -> None:
    """Point a snap's missing libraries at its base's Ubuntu release, and add the base's Python if it relied on it."""
    if not (args.deps_dir or args.mirror or args.rpm_repo) and pkg.extra.get("ubuntu_suite") \
            and not args.no_auto_mirror:
        from .snap import ubuntu_mirror
        args.mirror, args.suite = ubuntu_mirror(arch), pkg.extra["ubuntu_suite"]
        args.components = "main,universe"
        print(f"(snap base {pkg.extra['base']}: missing libraries come from Ubuntu {args.suite}, "
              f"{args.mirror})")
    if not (args.mirror and args.suite):
        return
    from .resolve import _scratch
    from .snap import add_base_python, python_without_stdlib
    opt = pkg.root / "opt" / pkg.extra["opt_name"]
    if not (versions := python_without_stdlib(opt)):
        return
    src = MirrorSource(args.mirror, args.suite, ["main", "universe"], arch,
                       FLATPAK_TO_DEB.get(arch, arch), _scratch())
    try:
        used = add_base_python(opt, versions, src._package)
    except (OSError, RuntimeError) as e:
        used = []
        print(f"(couldn't add the base's Python {', '.join(versions)}: {e})")
    if used:
        print(f"(the snap's Python {', '.join(versions)} had its standard library in the base snap; "
              f"added {', '.join(used)} from Ubuntu {args.suite})")
        pkg.notes.append(f"Python {', '.join(versions)}'s standard library added from Ubuntu "
                         f"{args.suite}, as the base snap had it")


def _runtime_for(args, probe, arch: str) -> RuntimeIndex | int:
    """Load the runtime to convert against, installing it first when the build would anyway; or an exit status."""
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
    if runtime is None:
        return _err("no runtime to convert against; pass --runtime or --runtime-index")
    return runtime


def _apply_options(args, a, pkg, runtime: RuntimeIndex, arch: str, work: Path) -> None:
    """Apply what --verify found, or the user asked for (see selfcheck), to the analysis."""
    _add_java_mono(args, a, pkg, runtime)
    a.no_chromium_sandbox = bool(getattr(args, "no_chromium_sandbox", False))
    a.writable = bool(getattr(args, "writable", False))
    if getattr(args, "chdir", False) and not a.chdir:
        a.chdir = "asked for with --chdir"
    a.fd_limit = getattr(args, "fd_limit", None)
    a.missing_loaded |= {so for so in getattr(args, "add_library", None) or []
                         if so not in a.package_sonames and not runtime.provides(so)}
    if a.python_modules and not getattr(args, "no_auto_mirror", False):
        _fetch_python_modules(a, pkg, runtime, arch, work / "python")


def _add_java_mono(args, a, pkg, runtime: RuntimeIndex) -> None:
    """Add a JDK or Mono when --java or --mono asks for one the analysis didn't find."""
    if getattr(args, "java", False) and not a.java:
        from . import javart
        a.java = javart.setup(pkg.root)
    if getattr(args, "mono", False) and not a.mono:
        from . import monort
        a.mono = monort.setup(pkg.root)
        a.missing_loaded |= {so for so in a.mono["libraries"] if not runtime.provides(so)}


def _fill_library_gaps(args, a, runtime: RuntimeIndex, arch: str, libstage: Path) -> ResolveResult:
    """Fetch the libraries the runtime lacks from the sources the user named, or by default from Ubuntu and Debian."""
    missing = a.missing_hard | a.missing_soft | a.missing_loaded
    if not missing:
        return ResolveResult()
    sources = make_sources(args, arch, FLATPAK_TO_DEB.get(arch, arch))
    if sources:
        return fill_gaps(missing, runtime, set(a.package_sonames), sources, libstage)
    if not (a.missing_hard or a.missing_loaded) or getattr(args, "no_auto_mirror", False):
        res = ResolveResult()
        res.unresolved = set(missing)
        return res
    # only what the programs and the app's own libraries need: libraries that only
    # plugins want are often parts of a toolkit the vendor bundles (Zoom's own Qt 6),
    # and a distribution's build of them needn't match it
    srcs = default_sources(arch, FLATPAK_TO_DEB.get(arch, arch))
    ubuntu = srcs[0]
    assert isinstance(ubuntu, MirrorSource)
    print(f"(missing libraries come from Ubuntu {ubuntu.suite}, or {' or '.join(UBUNTU_PREVIOUS_LTS)} "
          f"for ones it no longer has, {ubuntu.mirror}; then Debian {' or '.join(DEBIAN_RELEASES)}, "
          f"then Fedora {FEDORA_RELEASE}; --no-auto-mirror to turn this off)")
    res = fill_gaps(a.missing_hard | a.missing_loaded, runtime, set(a.package_sonames), srcs, libstage)
    res.unresolved |= a.missing_soft - set(res.bundled)
    return res


def _recheck_versions(a, res: ResolveResult, runtime: RuntimeIndex) -> dict:
    """Check symbol versions again with the bundled libraries in the picture; return every ELF file checked."""
    providers: dict[str, set[str] | None] = {}
    elfs = dict(a.elfs)
    for so, info in res.bundled_info.items():
        elfs[f"lib/debpak/{so}"] = info
    for info in elfs.values():
        _note_providers(providers, info.verneed, a, res, runtime)
    a.version_problems = check_versions(elfs, providers)
    return elfs


def _note_providers(providers: dict[str, set[str] | None], verneed, a, res: ResolveResult,
                    runtime: RuntimeIndex) -> None:
    """Record in providers the symbol versions defined by whatever provides each library in verneed."""
    for lib in verneed:
        if is_never_bundle(lib) and runtime.provides(lib):
            providers[lib] = runtime.versions_of(lib)
        elif lib in res.bundled_info:
            providers[lib] = res.bundled_info[lib].verdef
        elif lib in a.package_sonames and a.package_sonames[lib] in a.elfs:
            providers[lib] = a.elfs[a.package_sonames[lib]].verdef
        elif runtime.provides(lib):
            providers[lib] = runtime.versions_of(lib)


def _settle_bundled_versions(a, res: ResolveResult, runtime: RuntimeIndex, libstage: Path) -> dict:
    """Recheck symbol versions, leaving out optional bundled libraries that need a newer glibc; return the ELF files."""
    elfs = _recheck_versions(a, res, runtime)
    # a library fetched only for what the app's other libraries need is optional: if the
    # copy needs a newer glibc than the runtime's, leave it out instead of refusing the app
    # (LocalSend's AppImage: a libjvm.so for a library beside its own)
    drop = {so for so in res.bundled_info if so not in a.missing_hard
            and any(p.startswith((f"lib/debpak/{so} needs libc.so", f"lib/debpak/{so} needs libm.so"))
                    for p in a.version_problems)}
    if not drop:
        return elfs
    for so in drop:
        (libstage / so).unlink(missing_ok=True)
        res.bundled.pop(so, None)
        res.bundled_info.pop(so, None)
        res.unresolved.add(so)
    return _recheck_versions(a, res, runtime)


def _permissions(args, a, elfs: dict) -> list[Permission]:
    """Infer the app's permissions, plus any --add-permission."""
    all_needed = set().union(*(set(i.needed) for i in elfs.values())) if elfs else set()
    perms = infer(all_needed, a.all_symbols(), a.kind, permissive=args.permissive, dlopened=a.dlopened,
                  gui=a.gui_reason(), bus_names=a.bus_names, host_spawner=a.host_spawner,
                  bus_clients=a.bus_clients, bus_access=a.bus_access) + _home_permissions(a)
    for arg in getattr(args, "add_permission", None) or []:
        if not any(p.arg == arg for p in perms):
            perms.append(Permission(arg, "the app needed it when checked (--add-permission)"))
    return perms


def _fetch_python_modules(a, pkg, runtime, arch: str, dest: Path) -> None:
    """Fetch the Python modules a Python app's package depends on, from Debian (see pydeps)."""
    from . import pydeps
    from .resolve import debian_source
    kind = {"org.gnome.Platform": "gnome", "org.kde.Platform": "kde"}.get(runtime.id, "")
    src = debian_source(arch, FLATPAK_TO_DEB.get(arch, arch), pydeps.DEBIAN_SUITE)
    print(f"(the Python modules it depends on come from Debian {pydeps.DEBIAN_SUITE}, whose Python is the "
          f"runtime's: {', '.join(a.python_modules)})", flush=True)
    got = pydeps.fetch(a.python_modules, src, dest / "site", kind, runtime.provides)
    if got.packages:
        a.python_site = dest / "site"
    if got.typelibs:
        a.typelib_dir = dest / pydeps.TYPELIB_DIR
        pkg.notes.append("Python modules added from Debian: " + ", ".join(
            f"{n} {v}" for n, v in sorted(got.packages.items())))
    if got.missing:
        pkg.notes.append("Python modules not found in Debian " + pydeps.DEBIAN_SUITE + ": " + ", ".join(got.missing))
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
        return _build_and_install(args, pkg, app_id, out, manifest, build_cmd)
    if not builder:
        print("(flatpak-builder isn't installed, so nothing was built: install it and run the command above)")
    print(f"Run with:\n  flatpak run {app_id}")
    return 0


def _build_and_install(args, pkg, app_id: str, out: Path, manifest: Path, build_cmd: list[str]) -> int:
    """Run flatpak-builder on the manifest and record the app once installed; return flatpak-builder's exit status."""
    if not host.sees(out):
        return _err(f"{out} is outside your home folder, which flatpak-builder on the host sees differently "
                    "from the debpak Flatpak: give an output folder in your home folder (-o)")
    print("\nBuilding and installing (--no-build to stop after writing the manifest)...", flush=True)
    rc, output = _run_teed(host.command(build_cmd))
    if rc and COMPOSE_FAILED in output and _skip_appstream_compose(manifest):
        # what AppStream rejects (an icon it can't read, a .desktop field it doesn't like) only
        # costs the app its software-centre listing; it runs the same without it
        print("\nAppStream couldn't compose the app's metadata (see above); building again without it...",
              flush=True)
        rc, output = _run_teed(host.command(build_cmd))
    if rc == 0:
        from .manage import record
        record(app_id, args, pkg, out, installed=True)
        print(f"\nInstalled. Run with:\n  flatpak run {app_id}")
    return rc


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


def _convert_foreign(args, pkg, out: Path) -> int:
    """Convert an Electron app from Windows or macOS, or a Windows program for Wine (see cmd_convert)."""
    if args.mode == "extra-data" and not args.url:
        return _err("--mode extra-data requires --url (the vendor's download URL for this exact file)")
    _warn_ignored_options(args)
    app_id = _checked_app_id(args, pkg)
    if isinstance(app_id, int):
        return app_id
    mod = _foreign_module(pkg)
    pl = mod.plan(pkg, args)
    if args.mode == "extra-data" and "replay" not in pkg.extra:
        pl.blockers.append("--mode extra-data can't be used: " + pkg.extra.get("replay_problem", "unknown")
                           + "; use the default bundle mode")
    if (hit := _foreign_flathub_hit(args, pkg)):
        return _say_on_flathub(hit)
    if pl.blockers and not args.force:
        return _refuse_to_write(pl.render())
    out.mkdir(parents=True, exist_ok=True)
    manifest = mod.write(pl, out, app_id, args)
    _stamp_options(manifest, args, app_id)
    report = pl.render()
    (out / "report.txt").write_text(report)
    (out / "report.json").write_text(json.dumps(pl.to_json(), indent=2) + "\n")
    print(report, end="")
    return _build_install(args, pkg, app_id, out, manifest)


def _warn_ignored_options(args) -> None:
    """Say which of the options for finding Linux libraries a Windows or Mac app ignores."""
    for opt in ("deps_dir", "mirror", "rpm_repo"):
        if getattr(args, opt, None):
            print(f"(--{opt.replace('_', '-')} is ignored: Windows and Mac apps don't use Linux libraries)")


def _foreign_flathub_hit(args, pkg):
    """Look a Windows or Mac app up on Flathub, unless --anyway or --no-flathub-check; None when it isn't there."""
    if args.anyway or args.no_flathub_check:
        return None
    from .manage import flathub_match
    try:
        return flathub_match([pkg.extra.get("display_name", pkg.name), pkg.name])
    except Exception:       # never let the check break a conversion
        return None


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
        src = (e.get("snap") and f"snap {e['snap']} r{e.get('snap_revision', '?')}") or \
            (e.get("options") or {}).get("url") or e.get("source")
        print(f"{app_id:<40} {e.get('format', '?'):<9} {e.get('version', ''):<16} {src}")
    return 0


def cmd_update(args) -> int:
    """Check converted apps for new versions, and convert and reinstall the changed ones.

    Returns 0 when every app is up to date or was updated. Otherwise it returns
    1 for an app that can't be checked or isn't in the registry, or the exit
    status of a conversion that failed.
    """
    from .manage import load_registry, update_workdir
    reg = load_registry()
    ids = args.app_ids or sorted(reg)
    if not ids:
        print("no apps installed by debpak")
        return 0
    rc = 0
    work = update_workdir()
    try:
        for app_id in ids:
            rc = _update_app(args, app_id, reg.get(app_id), work, rc)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return rc


def _update_app(args, app_id: str, entry: dict | None, work: Path, rc: int) -> int:
    """Check one app and convert or reinstall it when it changed; return rc, changed by anything that went wrong."""
    from .manage import check_update
    if not entry:
        return _err(f"{app_id} wasn't installed by debpak (see `debpak list`)")
    chk = check_update(app_id, entry, download=not args.check, workdir=work)
    print(f"{app_id}: {chk.status} ({chk.detail})")
    argv = _update_argv(args, app_id, entry, chk)
    if argv:
        code = main(argv)
        return code if code != 0 else rc
    if chk.status == "can't check":
        return rc or 1
    return rc


def _update_argv(args, app_id: str, entry: dict, chk) -> list[str] | None:
    """Return the debpak command line that installs the app's new version, or None when there is none to install."""
    from .manage import options_to_argv
    if args.check:
        return None
    if entry.get("recipe") and chk.status == "update available":
        return ["install", entry["recipe"], "--recipes", entry["recipe_source"], "--yes"]
    if chk.new_file:
        return ["convert", str(chk.new_file), "--app-id", app_id, "-o", entry["output"], "--anyway",
                *options_to_argv(entry.get("options") or {})]
    return None


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
    got = _download_recipe(args, source)
    if isinstance(got, int):
        return got
    entry, dest, recipe = got
    print(recipes.describe(recipe), end="")
    manifest = dest / f"{entry['id']}.json"
    build_cmd = ["flatpak-builder", "--user", "--install", "--force-clean", "--install-deps-from=flathub",
                 str(dest / "build-dir"), str(manifest)]
    if args.no_build:
        print(f"Recipe in {dest}. Build and install with:\n  " + " ".join(build_cmd))
        return 0
    if (refused := _confirm_install(args)) is not None:
        return refused
    if not host.which("flatpak-builder"):
        return _err("flatpak-builder isn't installed (it's in your distribution's flatpak-builder package)")
    rc = subprocess.call(host.command(build_cmd))
    if rc == 0:
        recipes.record(recipe, source, dest, entry["recipe_sha256"])
        shutil.rmtree(dest / "build-dir", ignore_errors=True)
        shutil.rmtree(dest / ".flatpak-builder", ignore_errors=True)
        print(f"\nInstalled. Run with:\n  flatpak run {entry['id']}")
    return rc


def _download_recipe(args, source: str) -> tuple[dict, Path, dict] | int:
    """Download the one recipe args.name names; return (its index entry, its folder, the recipe), or an exit status."""
    from . import recipes
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
    return entry, dest, recipe


def _confirm_install(args) -> int | None:
    """Ask before building, unless --yes; return the exit status when the answer is no, else None."""
    if args.yes:
        return None
    if not sys.stdin.isatty():
        return _err("not asking without a terminal: pass --yes to install")
    if input("Install it? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Not installed.")
        return 1
    return None


def cmd_recipe(args) -> int:
    """Make, index or list recipes (see recipes.py)."""
    from . import recipes
    steps = {"make": _recipe_make, "index": _recipe_index, "check": _recipe_check, "publish": _recipe_publish}
    try:
        return steps.get(args.recipe_cmd, _recipe_search)(args)
    except recipes.RecipeError as e:
        return _err(str(e))


def _recipe_make(args) -> int:
    from . import recipes
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


def _recipe_index(args) -> int:
    from . import recipes
    print(f"Wrote {recipes.reindex(Path(args.dir))}")
    return 0


def _recipe_check(args) -> int:
    from . import recipes
    results = recipes.check_updates(Path(args.dir), args.ids or None, apply=args.apply)
    for r in results:
        print(_check_line(r))
    if args.summary:
        lines = [_summary_line(r) for r in results if r["status"] in ("updated", "update", "error", "can't update")]
        Path(args.summary).write_text("\n".join(lines) + "\n" if lines else "")
    return 1 if any(r["status"] == "error" for r in results) else 0


def _check_line(r: dict) -> str:
    """Return the line `debpak recipe check` prints for one recipe: its ID, status and version change."""
    change = f"{r['old']} -> {r['new']}" if r["new"] and r["new"] != r["old"] else r["old"]
    return f"{r['id']:<40} {r['status']:<13} {change}" + (f"  {r['detail']}" if r["detail"] else "")


def _summary_line(r: dict) -> str:
    detail = f": {r['detail']}" if r["status"] in ("error", "can't update") else ""
    return f"- {r['id']}: {r['old']} → {r['new']} ({r['status']}){detail}"


def _recipe_publish(args) -> int:
    from . import recipes
    built = recipes.publish(Path(args.dir), Path(args.repo), args.url, gpg_key=args.gpg_key,
                            gpg_homedir=args.gpg_homedir, title=args.title, ids=args.only or None)
    print(f"Built {len(built)} apps into {args.repo}. Users add it with:\n"
          f"  flatpak remote-add --user --if-not-exists debpak {args.url.rstrip('/')}/debpak.flatpakrepo")
    return 0


def _recipe_search(args) -> int:
    from . import recipes
    source = args.recipes or recipes.default_source()
    found = recipes.search(recipes.load_index(source), args.term)
    for r in found:
        print(f"{r['id']:<40} {r['version']:<14} {r['name']}" + (f" - {r['summary']}" if r.get("summary") else ""))
    if not found:
        print(f"no recipes{' matching ' + repr(args.term) if args.term else ''} in {source}")
    return 0


def cmd_uninstall(args) -> int:
    """Uninstall a Flatpak debpak installed and drop it from the registry."""
    from .manage import load_registry, update_registry
    entry = load_registry().get(args.app_id)
    if not entry and not args.force:
        return _err(f"{args.app_id} wasn't installed by debpak (see `debpak list`); --force to uninstall anyway")
    cmd = ["flatpak", "uninstall", "--user", "-y", *(["--delete-data"] if args.delete_data else []), args.app_id]
    print("$ " + " ".join(cmd))
    try:
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
        idx = _runtime_index_for(args)
    except (RuntimeError, ValueError) as e:
        return _err(str(e))
    if isinstance(idx, int):
        return idx
    if args.output:
        idx.save(Path(args.output))
        print(f"wrote {args.output}")
    print(f"{idx.ref}: {len(idx.sonames)} libraries, glibc {idx.glibc or '?'}")
    return 0


def _runtime_index_for(args) -> RuntimeIndex | int:
    """Index the usr tree --root names, or the installed runtime args.ref names; or an exit status."""
    if args.root:
        if not args.ref:
            return _err("--root needs --ref ID/ARCH/BRANCH to label the index")
        rid, arch, branch = parse_ref(args.ref, args.arch)
        return index_root(args.root, f"{rid}/{arch}/{branch}", arch)
    if not args.ref:
        return _err("give a runtime ref, e.g. org.freedesktop.Platform//25.08")
    return get_index(args.ref, args.arch or host_arch(), rebuild=True)


def cmd_smoke(args) -> int:
    """Run an app with LD_DEBUG=libs,files (or read such a log) and report failed loads.

    Exit status 2 if a library the app needs at startup is missing, else 0.
    """
    from .smoke import parse_ld_debug, to_report
    ran = _smoke_log(args)
    if isinstance(ran, int):
        return ran
    log, name = ran
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            report = to_report(parse_ld_debug(f), name)
    except OSError as e:
        return _err(str(e))
    if args.output:
        Path(args.output).write_text(json.dumps(report.to_json(), indent=2) + "\n")
    if args.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        print(report.render(), end="")
    return 2 if report.worst == "fatal" else 0


def _smoke_log(args) -> tuple[Path, str] | int:
    """Return (log file, app name): --log's, or a new run's; or an exit status."""
    if args.log:
        return Path(args.log), args.app_id or Path(args.log).stem
    return _smoke_run(args)


def _smoke_argv(args) -> tuple[list[str], str] | None:
    """Return the command line to run and the app's name, for --exec or a Flatpak app ID; None for neither."""
    import shlex

    from .smoke import flatpak_argv
    extra = [a for a in args.args if a != "--"]
    if args.exec_cmd:
        argv = shlex.split(args.exec_cmd) + extra
        return argv, args.app_id or Path(argv[0]).name
    if args.app_id:
        return flatpak_argv(args.app_id, args.command, extra), args.app_id
    return None


def _smoke_run(args) -> tuple[Path, str] | int:
    """Start the app with the loader's logging on; return (log file, app name), or an exit status."""
    from .smoke import run_logged
    got = _smoke_argv(args)
    if got is None:
        return _err("give a Flatpak app ID, --exec COMMAND or --log FILE")
    argv, name = got
    wait = args.timeout or None
    print(f"running {name} with LD_DEBUG=libs,files" + (f" for up to {wait:g}s" if wait else ""), file=sys.stderr)
    try:
        log, code = run_logged(argv, wait, log=Path(args.save_log) if args.save_log else None)
    except OSError as e:
        return _err(f"{argv[0]}: {e}")
    if code is None and args.app_id and not args.exec_cmd:
        subprocess.run(host.command(["flatpak", "kill", args.app_id]), stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
    print(f"log: {log}", file=sys.stderr)
    return log, name


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for every debpak subcommand."""
    ap = argparse.ArgumentParser(prog="debpak", description="Turn Linux app packages (.deb, .rpm, Arch "
                                 ".pkg.tar.*, AppImage, snap, .tar.gz/.zip, .run) into Flatpaks, "
                                 "along with Windows programs (through Wine) and Electron apps from "
                                 "Windows or macOS, and replace installed snaps with Flatpaks.")
    ap.add_argument("--version", action="version", version=f"debpak {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    _add_inspect_parser(sub)
    _add_convert_parser(sub)
    _add_smoke_parser(sub)
    _add_list_parser(sub)
    _add_install_parser(sub)
    _add_recipe_parser(sub)
    _add_update_parser(sub)
    _add_uninstall_parser(sub)
    _add_desnap_parser(sub)
    _add_runtime_index_parser(sub)
    return ap


def _runtime_opts(p) -> None:
    """Add the options that pick the runtime and the program to run (inspect, convert)."""
    p.add_argument("--runtime", help="target runtime ref, e.g. org.freedesktop.Platform//25.08")
    p.add_argument("--runtime-index", help="use a saved runtime index JSON instead of an installed runtime")
    p.add_argument("--reindex", action="store_true", help="rebuild the cached runtime index")
    p.add_argument("--exec", help="override the main executable (path inside the package or command name)")
    p.add_argument("--allow-run", action="store_true",
                   help="AppImage without unsquashfs (or dwarfsextract): let the AppImage unpack itself "
                        "(this runs it)")


def _foreign_opts(p) -> None:
    """Add the options for Windows and Mac apps (inspect, convert)."""
    g = p.add_argument_group("Windows and Mac apps")
    g.add_argument("--electron-version", metavar="VERSION", help="Electron version the app was built with, when debpak can't tell")
    g.add_argument("--electron-zip", metavar="FILE", help="use this Linux Electron zip instead of downloading it")
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


PKG_HELP = (".deb, .rpm, .pkg.tar.*, .AppImage, .snap or /snap/NAME/current, .tar.gz/.tar.xz/.zip, .run, "
            "Windows .exe/.msi/.msix or program folder, macOS .dmg/.app")


def _add_inspect_parser(sub) -> None:
    """Add `debpak inspect` to the subcommands."""
    p = sub.add_parser("inspect", help="analyze a package and report what conversion would need")
    p.add_argument("deb", metavar="PACKAGE", help=PKG_HELP)
    _runtime_opts(p)
    _foreign_opts(p)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-flathub-check", action="store_true", help="don't look the app up on Flathub")
    p.set_defaults(func=cmd_inspect)


def _add_convert_parser(sub) -> None:
    """Add `debpak convert` to the subcommands."""
    p = sub.add_parser("convert", help="turn a package into a Flatpak and install it (--no-build: manifest only)")
    p.add_argument("deb", metavar="PACKAGE", help=PKG_HELP)
    p.add_argument("--app-id", help="Flatpak app id (default local.debpak.<package>)")
    _runtime_opts(p)
    _foreign_opts(p)
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
    g.add_argument("--chdir", action="store_true",
                   help="start the program in its own folder, for one that finds its files relative to it")
    g.add_argument("--no-chromium-sandbox", action="store_true",
                   help="Electron and CEF apps: start with --no-sandbox instead of under zypak")
    p.set_defaults(func=cmd_convert, verify=True)


def _add_smoke_parser(sub) -> None:
    """Add `debpak smoke` to the subcommands."""
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


def _add_list_parser(sub) -> None:
    """Add `debpak list` to the subcommands."""
    p = sub.add_parser("list", help="apps debpak converted and installed")
    p.set_defaults(func=cmd_list)


def _add_install_parser(sub) -> None:
    """Add `debpak install` to the subcommands."""
    p = sub.add_parser("install", help="install an app from a recipe someone already converted and checked")
    p.add_argument("name", help="app name or ID, e.g. 'Vendor App' or com.vendor.App")
    p.add_argument("--recipes", metavar="URL|DIR", help="recipe collection (default: $DEBPAK_RECIPES, else the "
                                                         "recipes/ folder of the debpak repository)")
    p.add_argument("-y", "--yes", action="store_true", help="don't ask before building")
    p.add_argument("--no-build", action="store_true", help="download and check the recipe, but don't build it")
    p.set_defaults(func=cmd_install)


def _add_recipe_parser(sub) -> None:
    """Add `debpak recipe` to the subcommands."""
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


def _add_update_parser(sub) -> None:
    """Add `debpak update` to the subcommands."""
    p = sub.add_parser("update", help="re-download converted apps (vendor URL or Snap Store) and rebuild changed ones")
    p.add_argument("app_ids", nargs="*", help="apps to update (default: all of them)")
    p.add_argument("--check", action="store_true", help="only report what's out of date")
    p.set_defaults(func=cmd_update)


def _add_uninstall_parser(sub) -> None:
    """Add `debpak uninstall` to the subcommands."""
    p = sub.add_parser("uninstall", help="uninstall an app debpak installed")
    p.add_argument("app_id", help="as shown by `debpak list`")
    p.add_argument("--delete-data", action="store_true", help="also delete the app's data in ~/.var/app")
    p.add_argument("--delete-build", action="store_true", help="also delete its conversion output folder")
    p.add_argument("--force", action="store_true", help="uninstall even if debpak didn't install it")
    p.set_defaults(func=cmd_uninstall)


def _add_desnap_parser(sub) -> None:
    """Add `debpak desnap` to the subcommands."""
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


def _add_runtime_index_parser(sub) -> None:
    """Add `debpak runtime-index` to the subcommands."""
    p = sub.add_parser("runtime-index", help="index an installed runtime (or a directory) for gap analysis")
    p.add_argument("ref", nargs="?", help="runtime ref, e.g. org.freedesktop.Platform//25.08")
    p.add_argument("--root", help="index this usr-tree directory instead of an installed runtime")
    p.add_argument("--ref", dest="ref_opt", help=argparse.SUPPRESS)
    p.add_argument("--arch", help="architecture (default: host)")
    p.add_argument("-o", "--output", help="also save the index to this file")
    p.set_defaults(func=cmd_runtime_index)


def main(argv: list[str] | None = None) -> int:
    """Run the debpak command line with argv (default: sys.argv[1:]) and return the exit status."""
    args = build_parser().parse_args(argv)
    try:        # so flatpak-builder's output, written straight to the same file, lands after ours
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    if getattr(args, "ref_opt", None) and not args.ref:
        args.ref = args.ref_opt
    return args.func(args)
