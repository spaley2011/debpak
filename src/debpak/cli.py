"""debpak command-line interface.

  debpak inspect  APP.deb [--runtime REF]
  debpak convert  APP.deb --app-id ID [--runtime REF] [--deps-dir DIR | --mirror URL] [-o OUT] [--build]
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
from .deb import DebError, extract
from .permissions import infer
from .report import render, to_json
from .resolve import ResolveResult, fill_gaps, make_sources
from .runtime import RuntimeIndex, get_index, host_arch, index_root, parse_ref
from .stage import stage

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


def cmd_inspect(args) -> int:
    with tempfile.TemporaryDirectory(prefix="debpak-") as tmp:
        pkg = extract(args.deb, tmp)
        arch = pkg.flatpak_arch or host_arch()
        runtime = None
        if args.runtime or args.runtime_index:
            try:
                runtime = _load_runtime(args, None, arch)
            except (RuntimeError, ValueError) as e:
                return _err(str(e))
        a = analyze(pkg, runtime, exec_override=args.exec)
        perms = infer(set().union(*(set(i.needed) for i in a.elfs.values())) if a.elfs else set(),
                      a.all_symbols(), a.kind)
        if args.json:
            print(json.dumps(to_json(a, perms), indent=2))
        else:
            print(render(a, perms), end="")
        return 2 if a.blockers else 0


def cmd_convert(args) -> int:
    if args.mode == "extra-data" and not args.url:
        return _err("--mode extra-data requires --url (the vendor's download URL for this exact .deb)")
    out = Path(args.output)
    work = Path(tempfile.mkdtemp(prefix="debpak-"))
    try:
        pkg = extract(args.deb, work / "src")
        arch = pkg.flatpak_arch
        if not arch:
            return _err(f"unsupported package architecture {pkg.deb_arch!r}")
        app_id = args.app_id or default_app_id(pkg.name)
        if not APP_ID_RE.match(app_id):
            return _err(f"invalid app id {app_id!r} (needs 3+ dot-separated components)")

        # first pass without a runtime to learn which runtime fits
        probe = analyze(pkg, None, exec_override=args.exec)
        try:
            runtime = _load_runtime(args, probe.runtime_suggestion, arch)
        except (RuntimeError, ValueError) as e:
            return _err(f"{e}\n(hint: run on a machine with flatpak + the runtime installed, "
                        "or pass --runtime-index FILE)")
        a = analyze(pkg, runtime, exec_override=args.exec)

        res = ResolveResult()
        libstage = work / "bundled"
        missing = a.missing_hard | a.missing_soft
        if missing:
            sources = make_sources(args, arch, pkg.deb_arch)
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
        report = render(a, perms, res, result.notes)
        (out / "report.txt").write_text(report)
        (out / "report.json").write_text(json.dumps(to_json(a, perms, res), indent=2) + "\n")
        print(report, end="")
        print(f"\nWrote {result.manifest_path}")
        build_cmd = ["flatpak-builder", "--user", "--install", "--force-clean",
                     "--install-deps-from=flathub", str(out / "build-dir"), str(result.manifest_path)]
        print("Build & install with:\n  " + " ".join(build_cmd))
        print(f"Run with:\n  flatpak run {app_id}")
        if args.build:
            if not shutil.which("flatpak-builder"):
                return _err("flatpak-builder not found")
            return subprocess.call(build_cmd)
        return 0
    except DebError as e:
        return _err(str(e))
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"(work dir kept at {work})")


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


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="debpak", description="Convert binary .deb packages into Flatpaks.")
    ap.add_argument("--version", action="version", version=f"debpak {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def runtime_opts(p):
        p.add_argument("--runtime", help="target runtime ref, e.g. org.freedesktop.Platform//25.08")
        p.add_argument("--runtime-index", help="use a saved runtime index JSON instead of an installed runtime")
        p.add_argument("--reindex", action="store_true", help="rebuild the cached runtime index")
        p.add_argument("--exec", help="override the main executable (path inside the package or command name)")

    p = sub.add_parser("inspect", help="analyze a .deb and report what conversion would need")
    p.add_argument("deb")
    runtime_opts(p)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("convert", help="generate a flatpak-builder manifest and staged tree")
    p.add_argument("deb")
    p.add_argument("--app-id", help="Flatpak app id (default local.debpak.<package>)")
    runtime_opts(p)
    p.add_argument("-o", "--output", default="out", help="output directory (default: ./out)")
    p.add_argument("--mode", choices=["bundle", "extra-data"], default="bundle")
    p.add_argument("--url", help="vendor download URL of this .deb (extra-data mode)")
    p.add_argument("--deps-dir", action="append", help="directory of .debs to take missing libraries from")
    p.add_argument("--mirror", help="Debian/Ubuntu mirror to fetch missing libraries from, "
                                    "e.g. https://deb.debian.org/debian")
    p.add_argument("--suite", default="stable", help="mirror suite (default: stable)")
    p.add_argument("--components", default="main", help="comma-separated mirror components (default: main)")
    p.add_argument("--permissive", action="store_true", help="grant --filesystem=home")
    p.add_argument("--force", action="store_true", help="write a manifest even if blockers were found")
    p.add_argument("--build", action="store_true", help="run flatpak-builder afterwards")
    p.add_argument("--keep-work", action="store_true", help="keep the temporary extraction directory")
    p.set_defaults(func=cmd_convert)

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
