"""Mach-O -> Darling gap analysis.

Provider index
  Built by scanning an installed Darling prefix (Mach-O dylibs and
  frameworks, e.g. /usr/local/libexec/darling). Each library contributes its
  install name, exported symbols (export trie / symbol table) and re-exported
  libraries (libSystem re-exports libsystem_c etc.). A function counts as
  a stub when Darling's generated stub log string ("STUB: Foo called")
  names it; --stub-pattern changes the pattern.

Loader behaviour this models (dyld)
  - A non-weak linked dylib that can't be found aborts launch ("fatal").
  - A non-weak symbol that no linked library exports aborts launch; modern
    binaries bind all symbols at launch ("fatal"). Weak refs are "optional".
  - A symbol that exists only as a Darling stub returns nil/0 ("degraded").
  - Objective-C method calls are dispatched at runtime by selector and are
    invisible here; a present class can still lack methods.
"""
from __future__ import annotations

import json
import mmap
import os
import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .gap import Gap, GapReport
from .macho import (DYNAMIC_LOOKUP_ORDINAL, EXECUTABLE_ORDINAL, SELF_ORDINAL, MachOError, MachOFile,
                    MachOSlice, is_macho, read_macho)

INDEX_FORMAT = 1
DEFAULT_STUB_PATTERNS = [rb"STUB: ([A-Za-z_$][\w$:]*) called"]
SCANNED_FILETYPES = ("execute", "dylib", "bundle")
_VERSIONS_RE = re.compile(r"\.framework/Versions/[^/]+/")


def normalize_install_name(name: str) -> str:
    """Drop the Versions/<v>/ part of a framework path, so every version maps to one key."""
    return _VERSIONS_RE.sub(".framework/", name)


def pretty_symbol(sym: str) -> str:
    """Return a Mach-O symbol as a reader would write it: no leading _, ObjC names labelled."""
    for prefix, kind in (("_OBJC_CLASS_$_", "ObjC class"), ("_OBJC_METACLASS_$_", "ObjC metaclass"),
                         ("_OBJC_IVAR_$_", "ObjC ivar"), ("_OBJC_EHTYPE_$_", "ObjC exception type")):
        if sym.startswith(prefix):
            return f"{sym[len(prefix):]} ({kind})"
    return sym[1:] if sym.startswith("_") else sym


# --------------------------------------------------------------------------- index

@dataclass
class DarlingIndex:
    """What an installed Darling provides, by library.

    Attributes:
        version: Darling's version, or "installed" when unknown.
        arch: The architecture the index covers, such as x86_64.
        libs: Normalized install name -> {"e": exported symbols, "r": install
            names it re-exports, "s": exports that are only stubs}.
    """
    version: str
    arch: str
    libs: dict[str, dict] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"darling {self.version} ({self.arch})"

    def find_lib(self, install_name: str) -> str | None:
        """Return the index key for an install name, or None if Darling lacks the library.

        Falls back to matching on the file name alone when exactly one library has
        it, since Darling doesn't always install a library at the path macOS uses.
        """
        key = normalize_install_name(install_name)
        if key in self.libs:
            return key
        leaf = key.rsplit("/", 1)[-1]
        matches = [k for k in self.libs if k.rsplit("/", 1)[-1] == leaf]
        return matches[0] if len(matches) == 1 else None

    def status(self, install_name: str, sym: str, _seen: set | None = None) -> str:
        """Look up a symbol the way dyld would, following re-exports.

        Returns:
            "i" if implemented, "s" if Darling only has a stub, "m" if the library
            exists but nothing exports the symbol, "M" if the library is missing.
        """
        key = self.find_lib(install_name)
        if key is None:
            return "M"
        seen = _seen or set()
        if key in seen:
            return "m"
        seen.add(key)
        lib = self.libs[key]
        if sym in lib["_e"]:
            return "s" if sym in lib["_s"] else "i"
        for r in lib["r"]:
            st = self.status(r, sym, seen)
            if st in ("i", "s"):
                return st
        return "m"

    def any_exports(self, sym: str) -> bool:
        """Return True if any library in the index exports sym (for flat-namespace lookups)."""
        return any(sym in lib["_e"] for lib in self.libs.values())

    def _prepare(self) -> None:
        for lib in self.libs.values():
            lib["_e"] = set(lib["e"])
            lib["_s"] = set(lib["s"])

    def to_json(self) -> dict:
        return {"format": INDEX_FORMAT, "version": self.version, "arch": self.arch,
                "libs": {k: {"e": v["e"], "r": v["r"], "s": v["s"]} for k, v in self.libs.items()}}

    @classmethod
    def from_json(cls, d: dict) -> "DarlingIndex":
        if d.get("format") != INDEX_FORMAT:
            raise ValueError("darling index format mismatch; rebuild it")
        idx = cls(version=d["version"], arch=d["arch"], libs=d["libs"])
        idx._prepare()
        return idx

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_json(), separators=(",", ":")))

    @classmethod
    def load(cls, path: Path) -> "DarlingIndex":
        return cls.from_json(json.loads(Path(path).read_text()))


def _stub_names(path: Path, patterns: list[bytes]) -> set[str]:
    names: set[str] = set()
    with open(path, "rb") as f:
        if not os.fstat(f.fileno()).st_size:
            return names
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            for pat in patterns:
                for mt in re.finditer(pat, m):
                    names.add(mt.group(1).decode("utf-8", "replace"))
    return names


def index_darling_root(root: str | Path, arch: str = "x86_64", version: str = "installed",
                       stub_patterns: list[bytes] | None = None) -> DarlingIndex:
    """Index every dylib and framework under an installed Darling prefix.

    Args:
        root: The prefix, such as /usr/local/libexec/darling.
        arch: The slice to index in universal binaries.
        version: A label for reports.
        stub_patterns: Regexes with one group, matching the log line a Darling
            stub prints and capturing its function name. Defaults to
            DEFAULT_STUB_PATTERNS ("STUB: <name> called").
    """
    root = Path(root)
    patterns = stub_patterns or DEFAULT_STUB_PATTERNS
    idx = DarlingIndex(version=version, arch=arch)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.endswith(".dSYM")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not is_macho(p):
                continue
            try:
                mf = read_macho(p)
            except MachOError:
                continue
            sl = mf.slice(arch)
            if not sl or sl.filetype not in ("dylib", "dylib_stub"):
                continue
            name = sl.install_name or "/" + p.relative_to(root).as_posix()
            stubs = _stub_names(p, patterns)
            stubbed = sorted(s for s in ({"_" + n for n in stubs} | stubs) if s in sl.exports)
            idx.libs[normalize_install_name(name)] = {
                "e": sorted(sl.exports),
                "r": [d.name for d in sl.dylibs if d.kind == "reexport"],
                "s": stubbed,
            }
    idx._prepare()
    return idx


# --------------------------------------------------------------------------- scan

@dataclass
class BundleInfo:
    """The parts of an .app bundle's Info.plist that a scan needs, plus its root and main executable."""
    root: Path
    name: str
    main: str | None            # rel path of the main executable
    bundle_id: str | None = None
    min_os: str | None = None


def read_bundle(target: Path) -> BundleInfo:
    """Read an .app bundle, or a bare Mach-O file, into a BundleInfo."""
    if target.is_file():
        return BundleInfo(target.parent, target.name, target.name)
    plist = target / "Contents/Info.plist"
    info = BundleInfo(target, target.name.removesuffix(".app"), None)
    if plist.is_file():
        try:
            data = plistlib.loads(plist.read_bytes())
        except Exception:  # noqa: BLE001 - malformed plists are common enough
            data = {}
        exe = data.get("CFBundleExecutable")
        if exe and (target / "Contents/MacOS" / exe).is_file():
            info.main = f"Contents/MacOS/{exe}"
        info.name = data.get("CFBundleName") or data.get("CFBundleDisplayName") or info.name
        info.bundle_id = data.get("CFBundleIdentifier")
        info.min_os = data.get("LSMinimumSystemVersion")
    return info


def _collect(target: Path) -> dict[str, MachOFile]:
    """Read every Mach-O file under target (or target itself), keyed by path relative to it."""
    files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file() and not p.is_symlink()]
    mods: dict[str, MachOFile] = {}
    for p in sorted(files):
        if ".dSYM/" in p.as_posix() or not is_macho(p):
            continue
        try:
            mods[p.name if target.is_file() else p.relative_to(target).as_posix()] = read_macho(p)
        except MachOError:
            continue
    return mods


def _expand(path: str, loader_rel: str, exe_rel: str | None) -> str | None:
    """Resolve an @loader_path or @executable_path install name to a path inside the bundle."""
    if path.startswith("@loader_path"):
        return os.path.normpath(os.path.join(os.path.dirname(loader_rel), path[len("@loader_path/"):]))
    if path.startswith("@executable_path"):
        base = os.path.dirname(exe_rel or loader_rel)
        return os.path.normpath(os.path.join(base, path[len("@executable_path/"):]))
    return None


def scan(target: str | Path, index: DarlingIndex) -> GapReport:
    """Check an .app bundle (or one Mach-O file) against a Darling index.

    Every module in the bundle is scanned: dylibs it ships itself are resolved
    inside the bundle, and the rest against the index. Missing libraries and
    non-weak symbols are fatal, because dyld binds everything at launch; stubs
    are degraded; weak references, and anything only a plugin needs, are
    optional.
    """
    target = Path(target)
    bundle = read_bundle(target)
    mods = _collect(target)
    report = GapReport(backend="macho-darling", target=bundle.name, provider=index.label)
    if not mods:
        report.blockers.append("no Mach-O binaries found (extract .dmg/.pkg first, e.g. with 7z)")
        return report

    slices: dict[str, MachOSlice] = {}
    for rel, mf in mods.items():
        sl = mf.slice(index.arch)
        if sl is None:
            if rel == bundle.main or (bundle.main is None and any(s.filetype == "execute" for s in mf.slices)):
                report.blockers.append(f"{rel} has no {index.arch} code (only {', '.join(mf.archs)})")
            else:
                report.notes.append(f"{rel}: no {index.arch} slice ({', '.join(mf.archs)}); skipped")
            continue
        if sl.filetype in SCANNED_FILETYPES:
            slices[rel] = sl
    main = bundle.main or next((r for r, s in slices.items() if s.filetype == "execute"), None)
    if main in slices and slices[main].platform not in (None, "macos"):
        report.blockers.append(f"built for {slices[main].platform}, not macOS")

    by_id = {normalize_install_name(s.install_name): r for r, s in slices.items() if s.install_name}
    by_leaf: dict[str, list[str]] = {}
    for r in slices:
        by_leaf.setdefault(r.rsplit("/", 1)[-1], []).append(r)

    def resolve_bundled(dep: str, loader_rel: str) -> str | None:
        candidates = []
        if dep.startswith("@rpath/"):
            rest = dep[len("@rpath/"):]
            for rp in slices[loader_rel].rpaths + (slices[main].rpaths if main in slices else []):
                base = _expand(rp, loader_rel, main) if rp.startswith("@") else rp.lstrip("/")
                if base is not None:
                    candidates.append(os.path.normpath(os.path.join(base, rest)))
        elif dep.startswith("@"):
            c = _expand(dep, loader_rel, main)
            if c:
                candidates.append(c)
        for c in candidates:
            if c in slices:
                return c
        hit = by_id.get(normalize_install_name(dep))
        if hit:
            return hit
        if dep.startswith("@"):
            leaf = dep.rsplit("/", 1)[-1]
            if len(by_leaf.get(leaf, [])) == 1:
                return by_leaf[leaf][0]
        return None

    # reachability from executables
    roots = [r for r, s in slices.items() if s.filetype == "execute"]
    reachable: set[str] = set()
    stack = list(roots)
    while stack:
        rel = stack.pop()
        if rel in reachable:
            continue
        reachable.add(rel)
        for d in slices[rel].dylibs:
            b = resolve_bundled(d.name, rel)
            if b:
                stack.append(b)

    stats = {"binaries": len(slices), "arch": index.arch, "undefined_symbols": 0}
    if main in slices and slices[main].min_os:
        stats["min_macos"] = slices[main].min_os
    objc_classes = 0
    for rel, sl in slices.items():
        scope = "app" if rel in reachable else "plugin"
        lib_state: list[str] = []   # per dylib ordinal: "bundled" | "system" | "missing"
        for d in sl.dylibs:
            if resolve_bundled(d.name, rel):
                lib_state.append("bundled")
            elif d.name.startswith("@"):
                lib_state.append("missing")
                tier = "optional" if d.weak or scope == "plugin" else "fatal"
                report.add(Gap(tier, d.name.rsplit("/", 1)[-1], None,
                               f"bundled library {d.name} referenced but not found in the app", [rel], scope))
            elif index.find_lib(d.name):
                lib_state.append("system")
            else:
                lib_state.append("missing")
                tier = "optional" if d.weak or scope == "plugin" else "fatal"
                what = "weak-linked library" if d.weak else "library"
                report.add(Gap(tier, normalize_install_name(d.name).rsplit("/", 1)[-1], None,
                               f"{what} {d.name} not provided by Darling", [rel], scope))
        for sym in sl.undefined:
            stats["undefined_symbols"] += 1
            if sym.name.startswith("_OBJC_CLASS_$_"):
                objc_classes += 1
            if sym.name.startswith("_OBJC_METACLASS_$_"):
                continue
            if not sl.twolevel or sym.ordinal == DYNAMIC_LOOKUP_ORDINAL:
                if not index.any_exports(sym.name):
                    report.add(Gap("crash", "(flat lookup)", pretty_symbol(sym.name),
                                   "dynamically looked-up symbol not exported by any Darling library", [rel], scope))
                continue
            if sym.ordinal in (SELF_ORDINAL, EXECUTABLE_ORDINAL):
                continue
            lib = sl.library_for(sym)
            if lib is None:
                continue
            state = lib_state[sym.ordinal - 1]
            if state != "system":
                continue
            st = index.status(lib.name, sym.name)
            if st == "i":
                continue
            short = normalize_install_name(lib.name).rsplit("/", 1)[-1]
            if st == "s":
                report.add(Gap("degraded", short, pretty_symbol(sym.name), "stub in Darling (returns nil/0)",
                               [rel], scope))
            else:
                tier = "optional" if sym.weak or scope == "plugin" else "fatal"
                report.add(Gap(tier, short, pretty_symbol(sym.name),
                               "weak symbol not exported by Darling" if sym.weak
                               else "symbol not exported by Darling (dyld aborts at launch)", [rel], scope))
    stats["objc_classes_referenced"] = objc_classes
    report.stats = stats
    if objc_classes:
        report.notes.append("Objective-C method calls are resolved at runtime by selector and aren't visible "
                            "to static analysis; a class that exists may still lack methods the app calls")
    return report


def default_cache() -> Path:
    """Return the folder where machgap caches Darling indexes (~/.cache/debpak/darling)."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "debpak" / "darling"
