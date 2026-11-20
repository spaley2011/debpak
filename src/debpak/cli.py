"""debpak command-line interface.

PACKAGE is a .deb, .rpm, Arch .pkg.tar.*, .AppImage, .snap (or /snap/NAME/current),
or a vendor's .tar.gz/.tar.xz/.zip.

  debpak inspect  PACKAGE [--runtime REF]
  debpak convert  PACKAGE --app-id ID [--runtime REF] [--deps-dir DIR | --mirror URL | --rpm-repo URL]
                  [-o OUT] [--no-build] [--anyway]
  debpak desnap   [--yes] [--copy-data] [--remove-snaps] [--block-snapd]   replace snaps with Flatpaks
  debpak list | update [APP_ID ...] [--check] | uninstall APP_ID [--delete-data]
  debpak runtime-index REF | --root DIR --ref REF
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__
from .analyze import analyze, check_versions
from .deb import DebError
from .packages import FLATPAK_TO_DEB, PackageError, open_package
from .permissions import infer
from .report import render, to_json
from .resolve import ResolveResult, fill_gaps, make_sources
from .runtime import RuntimeIndex, get_index, host_arch, index_root, parse_ref
from .stage import stage

EXIT_ON_FLATHUB = 4
APP_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*){2,}$")


def _err(msg: str) -> int:
    print(f"debpak: error: {msg}", file=sys.stderr)
    return 1


def default_app_id(pkg_name: str) -> str:
    return "local.debpak." + re.sub(r"[^A-Za-z0-9_]", "_", pkg_name)


def _load_runtime(args, fallback_ref: str | None, arch: str) -> RuntimeIndex | None:
    if getattr(args, "runtime_index", None):
        return RuntimeIndex.load(Path(args.runtime_index))
    ref = getattr(args, "runtime", None) or fallback_ref
    if not ref:
        return None
    return get_index(ref, arch, rebuild=getattr(args, "reindex", False))


def _open(args, dest):
    return open_package(args.deb, dest, allow_run=getattr(args, "allow_run", False))


def _exec_for(args, pkg) -> str | None:
    return args.exec or getattr(pkg, "default_exec", None)


def cmd_inspect(args) -> int:
    with tempfile.TemporaryDirectory(prefix="debpak-") as tmp:
        try:
            pkg = _open(args, tmp)
        except (PackageError, DebError, OSError) as e:
            return _err(str(e))
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
                      a.all_symbols(), a.kind)
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
    if args.mode == "extra-data" and not args.url:
        return _err("--mode extra-data requires --url (the vendor's download URL for this exact file)")
    out = Path(args.output)
    work = Path(tempfile.mkdtemp(prefix="debpak-"))
    try:
        pkg = _open(args, work / "src")
        arch = pkg.flatpak_arch
        if not arch and pkg.pkg_arch in ("noarch", "any", "all", ""):
            arch = host_arch()       # architecture-independent package (scripts, Java, ...)
        if not arch:
            return _err(f"unsupported package architecture {pkg.pkg_arch!r}")
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
            print(f"(snap base {pkg.extra['base']}: missing libraries come from Ubuntu {args.suite}, "
                  f"{args.mirror})")
        try:
            runtime = _load_runtime(args, probe.runtime_suggestion, arch)
        except (RuntimeError, ValueError) as e:
            return _err(f"{e}\n(hint: run on a machine with flatpak + the runtime installed, "
                        "or pass --runtime-index FILE)")
        a = analyze(pkg, runtime, exec_override=_exec_for(args, pkg))

        res = ResolveResult()
        libstage = work / "bundled"
        missing = a.missing_hard | a.missing_soft
        if missing:
            sources = make_sources(args, arch, FLATPAK_TO_DEB.get(arch, arch))
            if sources:
                res = fill_gaps(missing, runtime, set(a.package_sonames), sources, libstage)
            else:
                res.unresolved = set(missing)

        # re-check symbol versions with bundled libraries in the picture
        providers: dict[str, set[str] | None] = {}
        elfs = dict(a.elfs)
        for so, info in res.bundled_info.items():
            elfs[f"lib/debpak/{so}"] = info
        for info in elfs.values():
            for lib in info.verneed:
                if lib in res.bundled_info:
                    providers[lib] = res.bundled_info[lib].verdef
                elif lib in a.package_sonames and a.package_sonames[lib] in a.elfs:
                    providers[lib] = a.elfs[a.package_sonames[lib]].verdef
                elif runtime.provides(lib):
                    providers[lib] = runtime.versions_of(lib)
        a.version_problems = check_versions(elfs, providers)

        all_needed = set().union(*(set(i.needed) for i in elfs.values())) if elfs else set()
        symbols = a.all_symbols()
        perms = infer(all_needed, symbols, a.kind, permissive=args.permissive)

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
        print(f"\nWrote {result.manifest_path}")
        build_cmd = ["flatpak-builder", "--user", "--install", "--force-clean",
                     "--install-deps-from=flathub", str(out / "build-dir"), str(result.manifest_path)]
        print("Build & install with:\n  " + " ".join(build_cmd))
        builder = shutil.which("flatpak-builder")
        if args.build and not builder:
            return _err("flatpak-builder not found")
        if builder and not args.no_build:
            print("\nBuilding and installing (--no-build to stop after writing the manifest)...")
            rc = subprocess.call(build_cmd)
            if rc == 0:
                from .manage import record
                record(app_id, args, pkg, out, installed=True)
                print(f"\nInstalled. Run with:\n  flatpak run {app_id}")
            return rc
        if not builder:
            print("(flatpak-builder isn't installed, so nothing was built: install it and run the command above)")
        print(f"Run with:\n  flatpak run {app_id}")
        return 0
    except (DebError, PackageError) as e:
        return _err(str(e))
    except ValueError as e:
        return _err(str(e))
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"(work dir kept at {work})")


def _flathub_hit(pkg, a):
    from .desktop import app_display_name
    from .manage import flathub_match
    names = [pkg.name]
    if a.desktop_file:
        names.append(app_display_name(pkg.root, a.desktop_file, pkg.name))
    try:
        return flathub_match(names)
    except Exception:       # never let the check break a conversion
        return None


def cmd_list(args) -> int:
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
            if chk.new_file and not args.check:
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


def cmd_uninstall(args) -> int:
    from .manage import load_registry, save_registry
    reg = load_registry()
    entry = reg.get(args.app_id)
    if not entry and not args.force:
        return _err(f"{args.app_id} wasn't installed by debpak (see `debpak list`); --force to uninstall anyway")
    cmd = ["flatpak", "uninstall", "--user", "-y", *(["--delete-data"] if args.delete_data else []), args.app_id]
    print("$ " + " ".join(cmd))
    try:
        code = subprocess.call(cmd)
    except OSError as e:
        return _err(f"flatpak: {e}")
    if code != 0:
        return code
    if entry:
        if args.delete_build and Path(entry.get("output", "")).is_dir():
            shutil.rmtree(entry["output"])
            print(f"removed {entry['output']}")
        reg.pop(args.app_id, None)
        save_registry(reg)
    return 0


def cmd_desnap(args) -> int:
    from .desnap import run
    return run(args)


def cmd_runtime_index(args) -> int:
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
            subprocess.run(["flatpak", "kill", args.app_id], stdout=subprocess.DEVNULL,
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
    ap = argparse.ArgumentParser(prog="debpak", description="Turn Linux app packages (.deb, .rpm, Arch "
                                 ".pkg.tar.*, AppImage, snap, .tar.gz/.zip) into Flatpaks, "
                                 "and replace installed snaps with Flatpaks.")
    ap.add_argument("--version", action="version", version=f"debpak {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def runtime_opts(p):
        p.add_argument("--runtime", help="target runtime ref, e.g. org.freedesktop.Platform//25.08")
        p.add_argument("--runtime-index", help="use a saved runtime index JSON instead of an installed runtime")
        p.add_argument("--reindex", action="store_true", help="rebuild the cached runtime index")
        p.add_argument("--exec", help="override the main executable (path inside the package or command name)")
        p.add_argument("--allow-run", action="store_true",
                       help="AppImage without unsquashfs: let the AppImage unpack itself (this runs it)")

    p = sub.add_parser("inspect", help="analyze a package and report what conversion would need")
    p.add_argument("deb", metavar="PACKAGE", help=".deb, .rpm, .pkg.tar.*, .AppImage, .snap or /snap/NAME/current, .tar.gz/.tar.xz/.zip")
    runtime_opts(p)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-flathub-check", action="store_true", help="don't look the app up on Flathub")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("convert", help="turn a package into a Flatpak and install it (--no-build: manifest only)")
    p.add_argument("deb", metavar="PACKAGE", help=".deb, .rpm, .pkg.tar.*, .AppImage, .snap or /snap/NAME/current, .tar.gz/.tar.xz/.zip")
    p.add_argument("--app-id", help="Flatpak app id (default local.debpak.<package>)")
    runtime_opts(p)
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
                   help="snaps: don't fill missing libraries from the Ubuntu release the snap was built on")
    p.add_argument("--keep-work", action="store_true", help="keep the temporary extraction directory")
    p.set_defaults(func=cmd_convert)

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
    args = build_parser().parse_args(argv)
    if getattr(args, "ref_opt", None) and not args.ref:
        args.ref = args.ref_opt
    return args.func(args)
