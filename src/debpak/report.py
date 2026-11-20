"""Human-readable and JSON reports."""
from __future__ import annotations

from .analyze import Analysis
from .gap import Gap, GapReport
from .permissions import Permission
from .resolve import ResolveResult


def _section(title: str) -> str:
    return f"\n== {title} " + "=" * max(0, 60 - len(title))


def render(a: Analysis, perms: list[Permission] | None = None, res: ResolveResult | None = None,
           extra_notes: list[str] | None = None) -> str:
    p = a.pkg
    fmt = getattr(p, "format", "deb")
    out = [f"{p.name} {p.version} ({getattr(p, 'pkg_arch', '') or 'any arch'}, .{fmt})",
           f"  {p.summary}" if p.summary else ""]

    out.append(_section("Application"))
    out.append(f"  kind:         {a.kind} ({a.kind_evidence})")
    out.append(f"  entry point:  {a.main_exec or '??'}"
               + (f"  [{a.main_exec_reason}]" if a.main_exec else "")
               + ("  (shell script)" if a.main_exec_is_script else ""))
    out.append(f"  desktop file: {a.desktop_file or '(none)'}")
    out.append(f"  ELF files:    {len(a.elfs)}  (package provides {len(a.package_sonames)} library names)")
    if a.max_glibc or a.max_glibcxx:
        out.append(f"  requires:     {a.max_glibc or '-'} / {a.max_glibcxx or '-'}")

    out.append(_section("Runtime"))
    if a.runtime:
        out.append(f"  target:       {a.runtime.ref} (glibc {a.runtime.glibc or '?'})")
        if a.runtime.ref.split("/")[0] != a.runtime_suggestion.split("/")[0]:
            out.append(f"  suggestion:   {a.runtime_suggestion} fits a {a.kind} app better")
    else:
        out.append(f"  suggested:    {a.runtime_suggestion}")
        out.append("  (no runtime index: pass --runtime REF or --runtime-index FILE for gap analysis)")
        ext = sorted(a.hard_needed | a.soft_needed)
        out.append(f"  external libraries needed ({len(ext)}): " + ", ".join(ext))

    if a.runtime:
        out.append(_section("Library gap"))
        if not (a.missing_hard or a.missing_soft):
            out.append("  none - the runtime provides every external library")
        if a.missing_hard:
            out.append(f"  required by executables ({len(a.missing_hard)}): " + ", ".join(sorted(a.missing_hard)))
        if a.missing_soft:
            out.append(f"  only needed by plugins/extra libs ({len(a.missing_soft)}): "
                       + ", ".join(sorted(a.missing_soft)))
        if res:
            for so, origin in sorted(res.bundled.items()):
                out.append(f"  + bundled {so:<32} <- {origin}")
            if res.unresolved:
                out.append("  ! unresolved: " + ", ".join(sorted(res.unresolved)))
            if res.refused:
                out.append("  ! refuses to bundle core libs: " + ", ".join(sorted(res.refused)))
            if res.wrong_arch:
                out.append("  ! wrong architecture in source: " + ", ".join(sorted(res.wrong_arch)))
        for vp in a.version_problems:
            out.append(f"  ! {vp}")

    if a.findings:
        out.append(_section("Maintainer scripts & host integration"))
        for f in a.findings:
            out.append(f"  {f}")

    if a.hardcoded:
        out.append(_section("Hardcoded install paths"))
        for h in a.hardcoded[:15]:
            out.append(f"  {'text  ' if h.is_text else 'binary'} {h.file}: {h.path}")
        if len(a.hardcoded) > 15:
            out.append(f"  ... {len(a.hardcoded) - 15} more")
        if any(not h.is_text for h in a.hardcoded):
            out.append("  (binary paths can't be rewritten; the app may not find its data files)")

    if perms:
        out.append(_section("Suggested permissions"))
        for pm in perms:
            out.append(f"  {pm.arg:<45} # {pm.reason}")

    notes = list(extra_notes or [])
    if notes:
        out.append(_section("Notes"))
        out += [f"  - {n}" for n in notes]

    blockers = a.blockers
    out.append(_section("Verdict"))
    if blockers:
        out.append("  NOT CONVERTIBLE as-is:")
        out += [f"    x {b}" for b in blockers]
    elif res and res.unresolved & a.missing_hard:
        out.append("  INCOMPLETE: required libraries could not be found (add --deps-dir or --mirror)")
    else:
        out.append("  looks convertible")
    return "\n".join(line for line in out if line is not None) + "\n"


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
