"""Backend-neutral gap reports.

Every backend (ELF->Flatpak runtime, PE->Wine, Mach-O->Darling) answers the
same question: which things does this binary import that the target
environment doesn't provide, and how bad is each gap? They all emit a
GapReport, so the same ranking tool can aggregate across many apps.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

FORMAT = "gapreport/1"

# Ordered from worst to least bad.
TIERS = {
    "fatal": "will not start (loader/dyld fails)",
    "crash": "starts, but aborts if this function is reached",
    "degraded": "starts, but a feature is missing: a stub that returns empty results, or a piece that "
                "failed to load at runtime",
    "optional": "only matters if an optional or delay-loaded feature is used",
}
TIER_ORDER = list(TIERS)

# How a gap was found. Older reports have no evidence field and count as "static".
EVIDENCE = {
    "static": "predicted from the binaries' imports",
    "runtime": "seen while the app ran",
    "both": "predicted, and seen while the app ran",
    "guess": "a function name found as text in the binary (probably looked up at runtime)",
}


@dataclass
class Gap:
    """One thing an app needs that the target environment lacks.

    Attributes:
        tier: fatal, crash, degraded or optional (see TIERS).
        module: The library, DLL or dylib involved.
        symbol: The missing function or symbol, or None when the whole module
            is missing.
        reason: Why it counts as a gap, for the report.
        importers: Files of the app that import it.
        scope: "app" if an executable reaches it, "plugin" if only plugins do.
        evidence: How it was found: static, runtime, both or guess (see EVIDENCE).
        count: How many times a traced run hit it.
    """
    tier: str
    module: str
    symbol: str | None
    reason: str
    importers: list[str] = field(default_factory=list)
    scope: str = "app"
    evidence: str = "static"
    count: int = 0

    @property
    def key(self) -> str:
        """Return 'module!symbol', or the module alone; reports merge gaps by this key."""
        return f"{self.module}!{self.symbol}" if self.symbol else self.module


@dataclass
class GapReport:
    """The gaps of one app against one target, in the format every backend shares.

    gaprank reads these, so a report from winegap, machgap or debpak can be
    ranked together with the others.

    Attributes:
        backend: elf-flatpak, pe-wine or macho-darling.
        target: The app's name.
        provider: What it was checked against, such as "wine 11.8 (x86_64)".
        blockers: Reasons the app can't work that aren't import gaps (a kernel
            driver, a systemd service). Any blocker makes the report fatal.
        stats: Counts for the report header, such as modules scanned.
    """
    backend: str
    target: str
    provider: str
    gaps: list[Gap] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def add(self, gap: Gap) -> None:
        """Add a gap, merging it into an existing one with the same key and tier.

        A merged gap keeps every importer, becomes app-scoped if either was, sums the
        run counts and combines the evidence (static + runtime = both).
        """
        for g in self.gaps:
            if g.key == gap.key and g.tier == gap.tier:
                _merge_gap(g, gap)
                return
        self.gaps.append(gap)

    def by_tier(self, tier: str) -> list[Gap]:
        """Return the gaps of one tier, sorted by key."""
        return sorted((g for g in self.gaps if g.tier == tier), key=lambda g: g.key.lower())

    @property
    def worst(self) -> str | None:
        """Return the most severe tier present (fatal if there's a blocker), or None."""
        if self.blockers:
            return "fatal"
        for t in TIER_ORDER:
            if any(g.tier == t for g in self.gaps):
                return t
        return None

    @property
    def verdict(self) -> str:
        """Return a one-line summary of what the worst gaps mean for the app."""
        if self.blockers:
            return "NOT SUPPORTED: " + "; ".join(self.blockers)
        n = Counter(g.tier for g in self.gaps)
        if n["fatal"]:
            return f"WILL NOT START: {n['fatal']} fatal gap(s)"
        if n["crash"]:
            return f"STARTS; may abort if it reaches any of {n['crash']} unimplemented function(s)"
        if n["degraded"]:
            return f"STARTS; {n['degraded']} stubbed or missing piece(s) may leave features non-functional"
        if n["optional"]:
            return "LOOKS OK; only optional/delay-loaded pieces are missing"
        return "LOOKS OK; no import gaps found"

    def to_json(self) -> dict:
        return {"format": FORMAT, "backend": self.backend, "target": self.target, "provider": self.provider,
                "verdict": self.verdict, "worst": self.worst, "blockers": self.blockers, "notes": self.notes,
                "stats": self.stats, "gaps": [asdict(g) for g in self.gaps]}

    @classmethod
    def from_json(cls, d: dict) -> GapReport:
        """Read a report saved by to_json().

        Also accepts a document with the report under "gapreport", as in debpak's
        report.json.

        Raises:
            ValueError: d isn't a gapreport/1 document.
        """
        if d.get("format") != FORMAT:
            if isinstance(d.get("gapreport"), dict):   # embedded, e.g. in debpak's report.json
                return cls.from_json(d["gapreport"])
            raise ValueError("not a gapreport/1 document")
        r = cls(backend=d["backend"], target=d["target"], provider=d["provider"],
                notes=d.get("notes", []), blockers=d.get("blockers", []), stats=d.get("stats", {}))
        r.gaps = [Gap(**g) for g in d.get("gaps", [])]
        return r

    def render(self, limit: int = 25) -> str:
        """Format the report for a terminal, listing at most limit gaps per tier."""
        out = [f"{self.target}  [{self.backend} -> {self.provider}]"]
        for k, v in self.stats.items():
            out.append(f"  {k}: {v}")
        for tier in TIER_ORDER:
            out += _render_tier(tier, self.by_tier(tier), limit)
        if self.notes:
            out.append("\n== NOTES")
            out += [f"  - {n}" for n in self.notes]
        out.append(f"\n== VERDICT\n  {self.verdict}")
        return "\n".join(out) + "\n"


def load_reports(paths: list[str | Path]) -> list[GapReport]:
    """Read every gap report in the given files and folders; skip files that aren't reports."""
    reports = []
    for p in paths:
        p = Path(p)
        files = sorted(p.rglob("*.json")) if p.is_dir() else [p]
        for f in files:
            try:
                reports.append(GapReport.from_json(json.loads(f.read_text())))
            except (ValueError, KeyError, json.JSONDecodeError):
                continue
    return reports


@dataclass
class RankRow:
    """One line of gaprank's table.

    Attributes:
        apps: Apps that have this gap in an executable's path.
        sole_blocker: Apps for which this is the only fatal gap, so fixing it
            alone makes them start.
        seen: Apps where a traced run hit it.
    """
    backend: str
    key: str
    tier: str
    apps: int
    sole_blocker: int
    seen: int = 0


def rank(reports: list[GapReport], tiers: tuple[str, ...] = ("fatal", "crash", "degraded")) -> list[RankRow]:
    """Rank gaps across many apps by how much fixing each one would help.

    Rows are ordered by tier, then sole_blocker, then seen, then apps. Gaps that
    only plugins hit are left out.
    """
    apps_by_gap: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    seen_by_gap: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    sole: Counter = Counter()
    for r in reports:
        _count_report(r, tiers, apps_by_gap, seen_by_gap, sole)
    rows = [RankRow(b, k, t, len(apps), sole[(b, k, t)], len(seen_by_gap[(b, k, t)]))
            for (b, k, t), apps in apps_by_gap.items()]
    # Within a tier, problems seen in real runs outrank ones only predicted from imports.
    rows.sort(key=lambda r: (TIER_ORDER.index(r.tier), -r.sole_blocker, -r.seen, -r.apps, r.key.lower()))
    return rows


def _count_report(r: GapReport, tiers: tuple[str, ...], apps_by_gap: dict[tuple[str, str, str], set[str]],
                  seen_by_gap: dict[tuple[str, str, str], set[str]], sole: Counter) -> None:
    """Add one report's app-scoped gaps, the runs that hit them and its sole fatal gap to rank()'s tallies."""
    fatal_keys = {g.key for g in r.gaps if g.tier == "fatal" and g.scope == "app"}
    for g in r.gaps:
        if g.tier not in tiers or g.scope != "app":
            continue
        apps_by_gap[(r.backend, g.key, g.tier)].add(r.target)
        if g.evidence in ("runtime", "both"):
            seen_by_gap[(r.backend, g.key, g.tier)].add(r.target)
    if len(fatal_keys) == 1 and not r.blockers:
        sole[(r.backend, next(iter(fatal_keys)), "fatal")] += 1


def _merge_gap(g: Gap, gap: Gap) -> None:
    """Merge gap into g, which has the same key and tier (see GapReport.add)."""
    for imp in gap.importers:
        if imp not in g.importers:
            g.importers.append(imp)
    if gap.scope == "app":
        g.scope = "app"
    g.evidence = _merge_evidence(g.evidence, gap.evidence)
    g.count += gap.count


def _render_tier(tier: str, gaps: list[Gap], limit: int) -> list[str]:
    """Return GapReport.render()'s lines for one tier's gaps, app-scoped ones first; none if it has no gaps."""
    if not gaps:
        return []
    app = [g for g in gaps if g.scope == "app"]
    plug = [g for g in gaps if g.scope != "app"]
    out = [f"\n== {tier.upper()} ({len(gaps)}): {TIERS[tier]}"]
    out += [_render_gap(g) for g in (app + plug)[:limit]]
    if len(gaps) > limit:
        out.append(f"  ... {len(gaps) - limit} more (see --json)")
    return out


def _render_gap(g: Gap) -> str:
    """Return the two lines GapReport.render() prints for one gap."""
    who = ", ".join(g.importers[:3]) + (" ..." if len(g.importers) > 3 else "")
    tag = " [plugin]" if g.scope != "app" else ""
    if g.evidence in ("runtime", "both"):
        tag += f" [seen running{f' x{g.count}' if g.count > 1 else ''}]"
    elif g.evidence == "guess":
        tag += " [guess]"
    return f"  {g.key}{tag}\n      {g.reason}; " + (f"used by {who}" if who else "no importer recorded")


def _merge_evidence(a: str, b: str) -> str:
    """Combine two evidence values: static and runtime make both; a guess loses to anything else."""
    if a == b:
        return a
    s = {a, b}
    if "both" in s or {"static", "runtime"} <= s:
        return "both"
    if "runtime" in s:
        return "runtime"
    if "static" in s:
        return "static"
    return "guess"
