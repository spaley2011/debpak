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
    "degraded": "exists as a stub; calls return empty/zero results",
    "optional": "only matters if an optional or delay-loaded feature is used",
}
TIER_ORDER = list(TIERS)


@dataclass
class Gap:
    tier: str
    module: str                 # library / DLL / dylib the import targets
    symbol: str | None          # None when the whole module is missing
    reason: str
    importers: list[str] = field(default_factory=list)
    scope: str = "app"          # "app" (reachable from an executable) or "plugin"

    @property
    def key(self) -> str:
        return f"{self.module}!{self.symbol}" if self.symbol else self.module


@dataclass
class GapReport:
    backend: str                # "elf-flatpak" | "pe-wine" | "macho-darling"
    target: str                 # app name
    provider: str               # e.g. "wine 11.8 (x86_64)"
    gaps: list[Gap] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)   # non-import reasons it can't work
    stats: dict = field(default_factory=dict)

    def add(self, gap: Gap) -> None:
        for g in self.gaps:
            if g.key == gap.key and g.tier == gap.tier:
                for imp in gap.importers:
                    if imp not in g.importers:
                        g.importers.append(imp)
                if gap.scope == "app":
                    g.scope = "app"
                return
        self.gaps.append(gap)

    def by_tier(self, tier: str) -> list[Gap]:
        return sorted((g for g in self.gaps if g.tier == tier), key=lambda g: g.key.lower())

    @property
    def worst(self) -> str | None:
        if self.blockers:
            return "fatal"
        for t in TIER_ORDER:
            if any(g.tier == t for g in self.gaps):
                return t
        return None

    @property
    def verdict(self) -> str:
        if self.blockers:
            return "NOT SUPPORTED: " + "; ".join(self.blockers)
        n = Counter(g.tier for g in self.gaps)
        if n["fatal"]:
            return f"WILL NOT START: {n['fatal']} fatal gap(s)"
        if n["crash"]:
            return f"STARTS; may abort if it reaches any of {n['crash']} unimplemented function(s)"
        if n["degraded"]:
            return f"STARTS; {n['degraded']} stubbed function(s) may leave features non-functional"
        if n["optional"]:
            return "LOOKS OK; only optional/delay-loaded pieces are missing"
        return "LOOKS OK; no import gaps found"

    def to_json(self) -> dict:
        return {"format": FORMAT, "backend": self.backend, "target": self.target, "provider": self.provider,
                "verdict": self.verdict, "worst": self.worst, "blockers": self.blockers, "notes": self.notes,
                "stats": self.stats, "gaps": [asdict(g) for g in self.gaps]}

    @classmethod
    def from_json(cls, d: dict) -> "GapReport":
        if d.get("format") != FORMAT:
            if isinstance(d.get("gapreport"), dict):   # embedded, e.g. in debpak's report.json
                return cls.from_json(d["gapreport"])
            raise ValueError("not a gapreport/1 document")
        r = cls(backend=d["backend"], target=d["target"], provider=d["provider"],
                notes=d.get("notes", []), blockers=d.get("blockers", []), stats=d.get("stats", {}))
        r.gaps = [Gap(**g) for g in d.get("gaps", [])]
        return r

    def render(self, limit: int = 25) -> str:
        out = [f"{self.target}  [{self.backend} -> {self.provider}]"]
        for k, v in self.stats.items():
            out.append(f"  {k}: {v}")
        for tier in TIER_ORDER:
            gaps = self.by_tier(tier)
            if not gaps:
                continue
            app = [g for g in gaps if g.scope == "app"]
            plug = [g for g in gaps if g.scope != "app"]
            out.append(f"\n== {tier.upper()} ({len(gaps)}): {TIERS[tier]}")
            for g in (app + plug)[:limit]:
                who = ", ".join(g.importers[:3]) + (" ..." if len(g.importers) > 3 else "")
                tag = " [plugin]" if g.scope != "app" else ""
                out.append(f"  {g.key}{tag}\n      {g.reason}; used by {who}")
            if len(gaps) > limit:
                out.append(f"  ... {len(gaps) - limit} more (see --json)")
        if self.notes:
            out.append("\n== NOTES")
            out += [f"  - {n}" for n in self.notes]
        out.append(f"\n== VERDICT\n  {self.verdict}")
        return "\n".join(out) + "\n"


def load_reports(paths: list[str | Path]) -> list[GapReport]:
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
    backend: str
    key: str
    tier: str
    apps: int
    sole_blocker: int   # apps for which fixing this alone clears every fatal gap


def rank(reports: list[GapReport], tiers: tuple[str, ...] = ("fatal", "crash", "degraded")) -> list[RankRow]:
    """Which gaps, if fixed, would help the most apps?"""
    apps_by_gap: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    sole: Counter = Counter()
    for r in reports:
        fatal_keys = {g.key for g in r.gaps if g.tier == "fatal" and g.scope == "app"}
        for g in r.gaps:
            if g.tier in tiers and g.scope == "app":
                apps_by_gap[(r.backend, g.key, g.tier)].add(r.target)
        if len(fatal_keys) == 1 and not r.blockers:
            sole[(r.backend, next(iter(fatal_keys)), "fatal")] += 1
    rows = [RankRow(b, k, t, len(apps), sole[(b, k, t)]) for (b, k, t), apps in apps_by_gap.items()]
    rows.sort(key=lambda r: (TIER_ORDER.index(r.tier), -r.sole_blocker, -r.apps, r.key.lower()))
    return rows
