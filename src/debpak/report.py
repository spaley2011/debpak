"""Human-readable and JSON reports."""
from __future__ import annotations

from .analyze import Analysis
from .gap import Gap, GapReport
from .permissions import Permission
from .resolve import ResolveResult


def _section(title: str) -> str:
    """Return a section heading for the text report: '== Title ====...'."""
    return f"\n== {title} " + "=" * max(0, 60 - len(title))


def render(a: Analysis, perms: list[Permission] | None = None, res: ResolveResult | None = None,
           extra_notes: list[str] | None = None) -> str:
    """Format an analysis (and its permissions and gap filling, if given) as the text report."""
    p = a.pkg
    fmt = getattr(p, "format", "deb")
    out = [f"{p.name} {p.version} ({getattr(p, 'pkg_arch', '') or 'any arch'}, .{fmt})",
           f"  {p.summary}" if p.summary else ""]
    out += _application(a) + _runtime(a)
    if a.runtime:
        out += _library_gap(a, res)
    if a.findings:
        out.append(_section("Maintainer scripts & host integration"))
        out += [f"  {f}" for f in a.findings]
    out += _hardcoded(a)
    if perms:
        out.append(_section("Suggested permissions"))
        out += [f"  {pm.arg:<45} # {pm.reason}" for pm in perms]
    if extra_notes:
        out.append(_section("Notes"))
        out += [f"  - {n}" for n in extra_notes]
    out += _verdict(a, res)
    return "\n".join(out) + "\n"


def _application(a: Analysis) -> list[str]:
    out = [_section("Application"),
           f"  kind:         {a.kind} ({a.kind_evidence})",
           f"  entry point:  {a.main_exec or '??'}"
           + (f"  [{a.main_exec_reason}]" if a.main_exec else "")
           + ("  (shell script)" if a.main_exec_is_script else ""),
           f"  desktop file: {a.desktop_file or '(none)'}",
           f"  ELF files:    {len(a.elfs)}  (package provides {len(a.package_sonames)} library names)"]
    if a.max_glibc or a.max_glibcxx:
        out.append(f"  requires:     {a.max_glibc or '-'} / {a.max_glibcxx or '-'}")
    return out


def _runtime(a: Analysis) -> list[str]:
    out = [_section("Runtime")]
    if a.runtime:
        out.append(f"  target:       {a.runtime.ref} (glibc {a.runtime.glibc or '?'})")
        if a.runtime.ref.split("/")[0] != a.runtime_suggestion.split("/")[0]:
            out.append(f"  suggestion:   {a.runtime_suggestion} fits a {a.kind} app better")
        return out
    ext = sorted(a.hard_needed | a.soft_needed)
    return out + [f"  suggested:    {a.runtime_suggestion}",
                  "  (no runtime index: pass --runtime REF or --runtime-index FILE for gap analysis)",
                  f"  external libraries needed ({len(ext)}): " + ", ".join(ext)]


def _library_gap(a: Analysis, res: ResolveResult | None) -> list[str]:
    out = [_section("Library gap")]
    if not (a.missing_hard or a.missing_soft):
        out.append("  none - the runtime provides every external library")
    if a.missing_hard:
        out.append(f"  required by executables ({len(a.missing_hard)}): " + ", ".join(sorted(a.missing_hard)))
    if a.missing_soft:
        out.append(f"  only needed by plugins/extra libs ({len(a.missing_soft)}): "
                   + ", ".join(sorted(a.missing_soft)))
    if res:
        out += _gap_filling(res)
    for vp in a.version_problems:
        side = "GLIBC_" in vp and a.is_side_program(vp.split(" needs ")[0])
        out.append(f"  ! {vp}" + ("; a helper program, which won't run, but the app starts without it"
                                   if side else ""))
    return out


def _gap_filling(res: ResolveResult) -> list[str]:
    out = [f"  + bundled {so:<32} <- {origin}" for so, origin in sorted(res.bundled.items())]
    for label, names in (("unresolved", res.unresolved), ("refuses to bundle core libs", res.refused),
                         ("wrong architecture in source", res.wrong_arch)):
        if names:
            out.append(f"  ! {label}: " + ", ".join(sorted(names)))
    return out


def _hardcoded(a: Analysis) -> list[str]:
    if not a.hardcoded:
        return []
    out = [_section("Hardcoded install paths")]
    out += [f"  {'text  ' if h.is_text else 'binary'} {h.file}: {h.path}" for h in a.hardcoded[:15]]
    if len(a.hardcoded) > 15:
        out.append(f"  ... {len(a.hardcoded) - 15} more")
    if any(not h.is_text for h in a.hardcoded):
        out.append("  (binary paths can't be rewritten; the app may not find its data files)")
    return out


def _verdict(a: Analysis, res: ResolveResult | None) -> list[str]:
    out = [_section("Verdict")]
    if a.blockers:
        return out + ["  NOT CONVERTIBLE as-is:"] + [f"    x {b}" for b in a.blockers]
    if res and res.unresolved & a.missing_hard:
        return out + ["  INCOMPLETE: required libraries could not be found (add --deps-dir or --mirror)"]
    return out + ["  looks convertible"]


def gapreport(a: Analysis, res: ResolveResult | None = None) -> GapReport:
    """Express the ELF analysis in the backend-neutral gap format (for gaprank)."""
    r = GapReport(backend="elf-flatpak", target=a.pkg.name,
                  provider=a.runtime.ref if a.runtime else "(no runtime index)")
    bundled = set(res.bundled) if res else set()
    if a.runtime:
        for so in sorted(a.missing_hard - bundled):
            r.add(Gap("fatal", so, None, "library not in the runtime and not bundled", [], "app"))
        for so in sorted(a.missing_soft - bundled):
            r.add(Gap("optional", so, None, "library not in the runtime (plugins only)", [], "plugin"))
        for vp in a.version_problems:
            who, _, rest = vp.partition(" needs ")
            lib, _, versions = rest.partition(" ")
            r.add(Gap("fatal", lib, versions.replace(" (not provided)", ""), "symbol version not provided",
                      [who], "app"))
    r.blockers = [f.detail for f in a.findings if f.category == "blocker"]
    r.stats = {"elf_files": len(a.elfs), "bundled": len(bundled)}
    return r


def to_json(a: Analysis, perms: list[Permission] | None = None, res: ResolveResult | None = None) -> dict:
    """Return the analysis as the dict written to report.json, with the gap report embedded under 'gapreport'."""
    return {
        "gapreport": gapreport(a, res).to_json(),
        "package": {"name": a.pkg.name, "version": a.pkg.version, "arch": getattr(a.pkg, "pkg_arch", ""),
                    "format": getattr(a.pkg, "format", "deb"), "license": getattr(a.pkg, "license", ""),
                    "notes": list(getattr(a.pkg, "notes", []))},
        "kind": a.kind,
        "entry_point": a.main_exec,
        "desktop_file": a.desktop_file,
        "runtime": a.runtime.ref if a.runtime else None,
        "runtime_suggestion": a.runtime_suggestion,
        "requires": {"glibc": a.max_glibc, "glibcxx": a.max_glibcxx},
        "missing_required": sorted(a.missing_hard),
        "missing_optional": sorted(a.missing_soft),
        "bundled": res.bundled if res else {},
        "unresolved": sorted(res.unresolved) if res else [],
        "version_problems": a.version_problems,
        "findings": [{"category": f.category, "where": f.where, "detail": f.detail} for f in a.findings],
        "hardcoded_paths": [{"file": h.file, "path": h.path, "text": h.is_text} for h in a.hardcoded],
        "permissions": [{"arg": p.arg, "reason": p.reason} for p in (perms or [])],
        "blockers": a.blockers,
    }
