"""Command-line front ends for the Wine and Darling backends and the
cross-backend ranking tool.

  winegap index  --wine-source DIR [--arch x86_64] [-o FILE]
  winegap scan   TARGET (--index FILE ... | --wine-source DIR) [--stubs DIR]
  winegap trace  [--prefix DIR] [--wine CMD] [--timeout S] (EXE [-- ARGS] | --log FILE)
                 [--index FILE ... | --wine-source DIR] [--static DIR]
  machgap index  --darling-root DIR [--arch x86_64] [-o FILE]
  machgap scan   TARGET.app --index FILE
  gaprank        REPORT.json|DIR ... [--tier fatal,crash] [--top N]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

from . import __version__
from .gap import TIERS, load_reports, rank


def _err(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


def _emit(report, args) -> int:
    if args.output:
        Path(args.output).write_text(json.dumps(report.to_json(), indent=2) + "\n")
    if args.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        print(report.render(), end="")
        if args.output:
            print(f"\nreport written to {args.output}")
    return 2 if report.worst == "fatal" else 0


# --------------------------------------------------------------------------- winegap

def winegap_main(argv: list[str] | None = None) -> int:
    from .wine import WineIndex, default_cache, index_wine_libdir, index_wine_source, scan, write_stub_dlls

    ap = argparse.ArgumentParser(prog="winegap", description="Predict Wine/Proton import gaps for Windows apps.")
    ap.add_argument("--version", action="version", version=f"winegap (debpak {__version__})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("index", help="build a Wine index from a source tree or an installed lib dir")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--wine-source", help="Wine or Proton-wine git checkout")
    g.add_argument("--wine-libdir", help="installed builtin DLL dir, e.g. /usr/lib/wine/x86_64-windows")
    p.add_argument("--arch", default="x86_64", choices=["x86_64", "i386", "arm64"])
    p.add_argument("--label", help="version label for --wine-libdir indexes")
    p.add_argument("-o", "--output", help="index file (default: cache)")

    p = sub.add_parser("scan", help="scan an installed app directory or a single .exe/.dll")
    p.add_argument("target")
    p.add_argument("--index", action="append", help="index file(s); give one per architecture")
    p.add_argument("--wine-source", help="index this source tree on the fly (all needed architectures)")
    p.add_argument("--name", help="app name for the report")
    p.add_argument("--json", action="store_true")
    p.add_argument("-o", "--output", help="write the gap report JSON here (for gaprank)")
    p.add_argument("--stubs", metavar="DIR", help="write loader-satisfying stub DLLs for missing DLLs here")
    p.add_argument("--stub-mode", choices=["zero", "trap"], default="zero",
                   help="stub body: return 0, or trap if called (32-bit x86 always traps)")
    p.add_argument("--no-guess", action="store_true",
                   help="don't report functions found only as text (probably looked up with GetProcAddress)")

    p = sub.add_parser("trace", help="run an app under Wine with debug logging (or read a log) and report what "
                                     "failed: unimplemented calls, stubs, COM, failed loads, crashes")
    p.add_argument("exe", nargs="?", help="the .exe to run (or give --log)")
    p.add_argument("exe_args", nargs="*", help="arguments for the app, after -- (winegap trace [options] EXE -- ARGS)")
    p.add_argument("--log", help="read this Wine/Proton log instead of running anything")
    p.add_argument("--prefix", help="WINEPREFIX to run in")
    p.add_argument("--wine", default="wine", help="wine command (default: wine); e.g. a project's own build")
    p.add_argument("--timeout", type=float, default=120,
                   help="seconds before the app is closed (default 120; 0 = wait until you close it)")
    p.add_argument("--channels", default=None,
                   help="WINEDEBUG channels (default: err+all,fixme+all,warn+module,+loaddll)")
    p.add_argument("--save-log", help="keep the raw log here")
    p.add_argument("--index", action="append", help="Wine index file(s): names the DLL behind fixme'd functions "
                                                   "and enables the merged static scan")
    p.add_argument("--wine-source", help="index this Wine source tree on the fly")
    p.add_argument("--static", metavar="DIR", help="also scan this installed app folder and merge "
                                                  "(default with an index: the .exe's folder)")
    p.add_argument("--name", help="app name for the report")
    p.add_argument("--json", action="store_true")
    p.add_argument("-o", "--output", help="write the gap report JSON here (for gaprank)")
    args = ap.parse_args(argv)

    if args.cmd == "trace":
        return _winegap_trace(args)

    if args.cmd == "index":
        try:
            idx = (index_wine_source(args.wine_source, args.arch) if args.wine_source
                   else index_wine_libdir(args.wine_libdir, args.arch, args.label or "installed"))
        except (OSError, ValueError) as e:
            return _err(str(e))
        out = Path(args.output) if args.output else default_cache() / f"{idx.version}_{idx.arch}.json"
        idx.save(out)
        stubs = sum(1 for d in idx.dlls.values() for s in d["e"].values() if s == "s")
        print(f"{idx.label}: {len(idx.dlls)} DLLs, {stubs} stubbed exports -> {out}")
        return 0

    indexes: dict[str, WineIndex] = {}
    try:
        for f in args.index or []:
            i = WineIndex.load(Path(f))
            indexes[i.arch] = i
        if args.wine_source:
            from .pe import is_pe, read_pe
            t = Path(args.target)
            files = [t] if t.is_file() else [p for p in t.rglob("*") if p.is_file()]
            archs = {read_pe(p).machine for p in files if is_pe(p)} & {"x86_64", "i386", "arm64"}
            for a in archs or {"x86_64"}:
                indexes.setdefault(a, index_wine_source(args.wine_source, a))
    except (OSError, ValueError) as e:
        return _err(str(e))
    if not indexes:
        return _err("give --index FILE or --wine-source DIR")
    result = scan(args.target, indexes, args.name, guess=not args.no_guess)
    if args.stubs and result.missing_dlls:
        written = write_stub_dlls(result.missing_dlls, Path(args.stubs), args.stub_mode)
        if written:
            result.report.notes.append(
                f"wrote {len(written)} stub DLL(s) to {args.stubs}: {', '.join(written)}. Copy them next to the "
                "app's .exe; they only satisfy the loader, so features that call them won't work")
    return _emit(result.report, args)


def _winegap_trace(args) -> int:
    from .pe import is_pe, read_pe
    from .wine import WineIndex, index_wine_source, scan
    from .winetrace import DEFAULT_CHANNELS, read_log, run_traced, to_report
    if not args.log and not args.exe:
        return _err("give the .exe to run, or --log FILE")
    indexes: dict[str, WineIndex] = {}
    try:
        for f in args.index or []:
            i = WineIndex.load(Path(f))
            indexes[i.arch] = i
        static_dir = Path(args.static) if args.static else (Path(args.exe).parent if args.exe and indexes
                                                             else None)
        if args.wine_source:
            t = static_dir or (Path(args.exe) if args.exe else None)
            files = ([t] if t and t.is_file() else [p for p in t.rglob("*") if p.is_file()]) if t else []
            archs = {read_pe(p).machine for p in files if is_pe(p)} & {"x86_64", "i386", "arm64"}
            for a in archs or {"x86_64"}:
                indexes.setdefault(a, index_wine_source(args.wine_source, a))
            static_dir = static_dir or (Path(args.exe).parent if args.exe else None)
    except (OSError, ValueError) as e:
        return _err(str(e))

    name = args.name or (Path(args.exe).stem if args.exe else Path(args.log).stem)
    if args.log:
        log = Path(args.log)
    else:
        log = Path(args.save_log) if args.save_log else Path(tempfile.mkdtemp(prefix="winegap-")) / "wine.log"
        env = dict(os.environ)
        if args.prefix:
            env["WINEPREFIX"] = os.path.abspath(args.prefix)
        argv = [args.wine, args.exe, *[a for a in args.exe_args if a != "--"]]
        wait = None if not args.timeout else args.timeout
        print(f"running {name} under Wine with WINEDEBUG={env.get('WINEDEBUG') or args.channels or DEFAULT_CHANNELS}"
              + (f" for up to {args.timeout:g}s" if wait else " until you close it"), file=sys.stderr)
        print("use the features you want checked: open documents, menus, export ...", file=sys.stderr)
        try:
            code = run_traced(argv, log, env, timeout=wait, channels=args.channels or DEFAULT_CHANNELS)
        except OSError as e:
            return _err(f"{args.wine}: {e}")
        print(f"log: {log}" + ("" if code is None else f" (exit status {code})"), file=sys.stderr)
    try:
        trace = read_log(log)
    except OSError as e:
        return _err(str(e))
    static = scan(static_dir, indexes, name).report if static_dir and indexes else None
    report = to_report(trace, name, list(indexes.values()), static)
    return _emit(report, args)


# --------------------------------------------------------------------------- machgap

def machgap_main(argv: list[str] | None = None) -> int:
    from .darling import DarlingIndex, default_cache, index_darling_root, scan

    ap = argparse.ArgumentParser(prog="machgap", description="Predict Darling import gaps for macOS apps.")
    ap.add_argument("--version", action="version", version=f"machgap (debpak {__version__})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("index", help="index an installed Darling prefix")
    p.add_argument("--darling-root", required=True, help="e.g. /usr/local/libexec/darling")
    p.add_argument("--arch", default="x86_64", choices=["x86_64", "arm64", "i386"])
    p.add_argument("--label", default="installed", help="version label")
    p.add_argument("--stub-pattern", action="append",
                   help="regex with one group capturing a stubbed function name (repeatable)")
    p.add_argument("-o", "--output", help="index file (default: cache)")

    p = sub.add_parser("scan", help="scan a .app bundle, a .zip containing one, or a single Mach-O file")
    p.add_argument("target")
    p.add_argument("--index", required=True, help="Darling index file")
    p.add_argument("--json", action="store_true")
    p.add_argument("-o", "--output", help="write the gap report JSON here (for gaprank)")
    args = ap.parse_args(argv)

    if args.cmd == "index":
        pats = [s.encode() for s in args.stub_pattern] if args.stub_pattern else None
        idx = index_darling_root(args.darling_root, args.arch, args.label, pats)
        if not idx.libs:
            return _err(f"no {args.arch} Mach-O dylibs found under {args.darling_root}")
        out = Path(args.output) if args.output else default_cache() / f"{idx.version}_{idx.arch}.json"
        idx.save(out)
        stubs = sum(len(v["s"]) for v in idx.libs.values())
        print(f"{idx.label}: {len(idx.libs)} libraries, {stubs} detected stubs -> {out}")
        return 0

    try:
        idx = DarlingIndex.load(Path(args.index))
    except (OSError, ValueError) as e:
        return _err(str(e))
    target = Path(args.target)
    if target.suffix.lower() == ".dmg":
        return _err("extract the .dmg first (e.g. `7z x App.dmg`) and scan the .app inside")
    if target.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(target) as z:
                z.extractall(tmp)
            apps = sorted(Path(tmp).rglob("*.app"))
            if not apps:
                return _err("no .app bundle inside the zip")
            return _emit(scan(apps[0], idx), args)
    return _emit(scan(target, idx), args)


# --------------------------------------------------------------------------- gaprank

def gaprank_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gaprank",
                                 description="Rank import gaps across many apps: what to implement first.")
    ap.add_argument("reports", nargs="+", help="gap report JSON files or directories of them")
    ap.add_argument("--tier", default="fatal,crash,degraded", help=f"tiers to include ({', '.join(TIERS)})")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    reports = load_reports(args.reports)
    if not reports:
        return _err("no gap reports found")
    tiers = tuple(t.strip() for t in args.tier.split(",") if t.strip())
    rows = rank(reports, tiers)[: args.top]
    if args.json:
        print(json.dumps([r.__dict__ for r in rows], indent=2))
        return 0
    starting = sum(1 for r in reports if r.worst != "fatal")
    print(f"{len(reports)} apps analysed; {starting} would start, {len(reports) - starting} would not.\n")
    print(f"{'tier':<9} {'apps':>5} {'sole':>5} {'seen':>5}  gap")
    for r in rows:
        print(f"{r.tier:<9} {r.apps:>5} {r.sole_blocker:>5} {r.seen:>5}  [{r.backend}] {r.key}")
    print("\n'sole' = apps for which this is the only fatal gap: fixing it alone makes them start.")
    print("'seen' = apps where it happened in a traced run (winegap trace, debpak smoke), "
          "as well as being predicted.")
    return 0
