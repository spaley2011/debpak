"""Command-line front ends for the Wine and Darling backends and the
cross-backend ranking tool.

  winegap index  --wine-source DIR [--arch x86_64] [-o FILE]
  winegap scan   TARGET (--index FILE ... | --wine-source DIR) [--stubs DIR]
  machgap index  --darling-root DIR [--arch x86_64] [-o FILE]
  machgap scan   TARGET.app --index FILE
  gaprank        REPORT.json|DIR ... [--tier fatal,crash] [--top N]
"""
from __future__ import annotations

import argparse
import json
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
    args = ap.parse_args(argv)

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
    result = scan(args.target, indexes, args.name)
    if args.stubs and result.missing_dlls:
        written = write_stub_dlls(result.missing_dlls, Path(args.stubs), args.stub_mode)
        if written:
            result.report.notes.append(
                f"wrote {len(written)} stub DLL(s) to {args.stubs}: {', '.join(written)}. Copy them next to the "
                "app's .exe; they only satisfy the loader, so features that call them won't work")
    return _emit(result.report, args)


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
    print(f"{'tier':<9} {'apps':>5} {'sole':>5}  gap")
    for r in rows:
        print(f"{r.tier:<9} {r.apps:>5} {r.sole_blocker:>5}  [{r.backend}] {r.key}")
    print("\n'sole' = apps for which this is the only fatal gap: fixing it alone makes them start.")
    return 0
