"""PE -> Wine/Proton gap analysis.

Provider index
  Built from a Wine (or Proton-wine) source tree: every dlls/<name>/<name>.spec
  lists what a builtin DLL exports and marks unimplemented exports as `stub`.
  Forwarders (e.g. kernel32 -> kernelbase) are followed when classifying.
  Alternatively an installed Wine lib dir can be indexed from the builtin
  DLLs' export tables; that sees *which* functions exist but can't tell
  stubs from implementations.

Loader behaviour this models
  - A statically imported DLL that exists neither in Wine nor next to the
    app makes the process fail to start ("fatal").
  - A function missing from, or stubbed in, an existing DLL gets a thunk
    that aborts with "unimplemented function" only when called ("crash").
  - Delay-loaded DLLs are resolved on first use ("optional").
  - DLLs shipped in the app's directory are loaded instead of builtins.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .gap import Gap, GapReport
from .pe import PeError, PeInfo, is_pe, read_pe
from .pe_write import stub_dll

INDEX_FORMAT = 1
PE_EXTS = (".exe", ".dll", ".ocx", ".cpl", ".drv", ".ax", ".acm", ".tlb", ".sys", ".node", ".pyd")
ARCH_TAGS = {"x86_64": {"x86_64", "win64"}, "i386": {"i386", "win32"}, "arm64": {"arm64", "win64"},
             "arm": {"arm", "win32"}}


# --------------------------------------------------------------------------- index

@dataclass
class WineIndex:
    version: str
    arch: str
    source: str              # "spec" or "libdir"
    # dll (lowercase) -> {"e": {name: status}, "o": {ordinal: name}}
    # status: "i" implemented, "s" stub, "f:target.dll.Func" forwarder
    dlls: dict[str, dict] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"wine {self.version} ({self.arch})"

    def has_dll(self, dll: str) -> bool:
        return dll.lower() in self.dlls

    def status(self, dll: str, name: str | None, ordinal: int | None, _depth: int = 0) -> str:
        """'i' implemented, 's' stub, 'm' missing function, 'M' missing dll."""
        d = self.dlls.get(dll.lower())
        if d is None:
            return "M"
        if name is None:
            name = d["o"].get(str(ordinal))
            if name is None:
                return "m"
        st = d["e"].get(name)
        if st is None:
            return "m"
        if st.startswith("f:") and _depth < 8:
            target = st[2:]
            tdll, _, tfunc = target.rpartition(".")
            if not tdll.lower().endswith((".dll", ".drv", ".exe", ".sys", ".ocx")):
                tdll += ".dll"
            if tfunc.startswith("#") and tfunc[1:].isdigit():
                return self.status(tdll, None, int(tfunc[1:]), _depth + 1)
            return self.status(tdll, tfunc, None, _depth + 1)
        return "s" if st == "s" else "i"

    def to_json(self) -> dict:
        return {"format": INDEX_FORMAT, "version": self.version, "arch": self.arch, "source": self.source,
                "dlls": self.dlls}

    @classmethod
    def from_json(cls, d: dict) -> "WineIndex":
        if d.get("format") != INDEX_FORMAT:
            raise ValueError("wine index format mismatch; rebuild it")
        return cls(version=d["version"], arch=d["arch"], source=d["source"], dlls=d["dlls"])

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_json(), separators=(",", ":")))

    @classmethod
    def load(cls, path: Path) -> "WineIndex":
        return cls.from_json(json.loads(Path(path).read_text()))


def _arch_allows(flag_value: str, arch: str) -> bool:
    tags = ARCH_TAGS.get(arch, {arch})
    negate = flag_value.startswith("!")
    values = set(flag_value.lstrip("!").split(","))
    hit = bool(values & tags)
    return not hit if negate else hit


def parse_spec(text: str, arch: str) -> dict:
    """Parse a winebuild .spec file into {"e": {...}, "o": {...}} for one arch."""
    exports: dict[str, str] = {}
    ordinals: dict[str, str] = {}
    text = re.sub(r"\\\n", " ", text)
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        toks = line.split()
        if len(toks) < 3:
            continue
        ordinal, ftype = toks[0], toks[1]
        if ftype not in ("stdcall", "cdecl", "varargs", "thiscall", "fastcall", "extern", "stub", "equate",
                         "pascal", "variable"):
            continue
        i = 2
        noname = False
        allowed = True
        while i < len(toks) and toks[i].startswith("-"):
            flag = toks[i]
            if flag.startswith("-arch="):
                allowed = _arch_allows(flag[len("-arch="):], arch)
            elif flag == "-noname":
                noname = True
            i += 1
        if not allowed or i >= len(toks):
            continue
        rest = " ".join(toks[i:])
        mt = re.match(r"([^\s(]+)\s*(\([^)]*\))?\s*(\S+)?", rest)
        if not mt:
            continue
        name, args, target = mt.group(1), mt.group(2), mt.group(3)
        if ftype == "stub":
            status = "s"
        elif ftype in ("extern", "equate"):
            status = "i"
            target = None
        elif target and "." in target and args is not None:
            status = "f:" + target
        else:
            status = "i"
        if not noname:
            exports[name] = status
        if ordinal.isdigit():
            ordinals[ordinal] = name
            if noname:
                exports[name] = status
    return {"e": exports, "o": ordinals}


def _spec_dll_name(spec: Path) -> str | None:
    stem = spec.stem  # kernel32 / winspool.drv / ntoskrnl.exe / krnl386.exe16
    if stem.endswith("16"):
        return None
    return stem.lower() if "." in stem else f"{stem.lower()}.dll"


def index_wine_source(src: str | Path, arch: str) -> WineIndex:
    src = Path(src)
    dlls_dir = src / "dlls"
    if not dlls_dir.is_dir():
        raise ValueError(f"{src} doesn't look like a Wine source tree (no dlls/ directory)")
    version = "unknown"
    vf = src / "VERSION"
    if vf.is_file():
        version = vf.read_text().strip().replace("Wine version ", "")
    idx = WineIndex(version=version, arch=arch, source="spec")
    for d in sorted(dlls_dir.iterdir()):
        if not d.is_dir():
            continue
        for spec in d.glob("*.spec"):
            name = _spec_dll_name(spec)
            if name and spec.stem.lower() == d.name.lower():
                idx.dlls[name] = parse_spec(spec.read_text("utf-8", "replace"), arch)
    return idx


def index_wine_libdir(libdir: str | Path, arch: str, version: str = "installed") -> WineIndex:
    """Index installed builtin PE DLLs (e.g. /usr/lib/wine/x86_64-windows)."""
    idx = WineIndex(version=version, arch=arch, source="libdir")
    for p in sorted(Path(libdir).iterdir()):
        if p.suffix.lower() not in PE_EXTS or not is_pe(p):
            continue
        try:
            info = read_pe(p)
        except PeError:
            continue
        e = {n: ("f:" + info.forwarders[n] if n in info.forwarders else "i") for n in info.exports}
        o = {str(ordn): n for n, ordn in info.exports.items()}
        for ordn in info.ordinals:
            o.setdefault(str(ordn), f"#{ordn}")
            e.setdefault(f"#{ordn}", "i")
        idx.dlls[p.name.lower()] = {"e": e, "o": o}
    return idx


# --------------------------------------------------------------------------- scan

@dataclass
class ScanResult:
    report: GapReport
    modules: dict[str, PeInfo]
    missing_dlls: dict[str, dict]   # dll -> {"arch": str, "names": set, "ordinals": set}


def _collect(target: Path) -> dict[str, PeInfo]:
    files = [target] if target.is_file() else [p for p in target.rglob("*")
                                              if p.is_file() and p.suffix.lower() in PE_EXTS]
    mods: dict[str, PeInfo] = {}
    for p in sorted(files):
        if not is_pe(p):
            continue
        try:
            info = read_pe(p)
        except PeError:
            continue
        rel = p.name if target.is_file() else p.relative_to(target).as_posix()
        mods[rel] = info
    return mods


_ASCII_NAME = re.compile(rb"([A-Za-z_][A-Za-z0-9_]{3,79})\x00")
_ASCII_DLL = re.compile(rb"([A-Za-z0-9_.-]{1,60}\.[dD][lL][lL])\x00")
# UTF-16 (LoadLibraryW): must not start in the middle of other text
_WIDE_DLL = re.compile(rb"(?<![\x20-\x7e]\x00)((?:[A-Za-z0-9_.-]\x00){1,60}\.\x00[dD]\x00[lL]\x00[lL]\x00)\x00\x00")
GUESS_MAX_BYTES = 512 * 1024 * 1024


def text_lookups(path: str | Path) -> tuple[set[str], set[str]]:
    """(DLL names, identifier-like names) stored as NUL-terminated text in a binary:
    what LoadLibrary("x.dll") + GetProcAddress(h, "Func") look up at runtime."""
    p = Path(path)
    if p.stat().st_size > GUESS_MAX_BYTES:
        return set(), set()
    data = p.read_bytes()
    dlls = {m.group(1).decode("ascii").lower() for m in _ASCII_DLL.finditer(data)}
    dlls |= {m.group(1).decode("utf-16-le", "ignore").lower() for m in _WIDE_DLL.finditer(data)}
    names = {m.group(1).decode("ascii") for m in _ASCII_NAME.finditer(data)}
    return dlls, names


def _guess_gaps(rel: str, info: PeInfo, idx: WineIndex, bundled: dict[str, str], scope: str) -> list[Gap]:
    """Functions named as text next to their DLL's name that Wine has only as stubs.

    Only stubs are reported: a stub found with GetProcAddress aborts the app when
    called, while a function Wine lacks entirely makes GetProcAddress return NULL,
    which apps usually check for (and we can't tell a missing API from any string).
    """
    try:
        dlls, names = text_lookups(info.path)
    except OSError:
        return []
    static = {(i.dll.lower(), i.name) for i in info.imports if i.name}
    out = []
    for dll in sorted(dlls):
        if dll in bundled or not idx.has_dll(dll):
            continue
        for func in sorted(names & idx.dlls[dll]["e"].keys()):
            if (dll, func) in static or idx.status(dll, func, None) != "s":
                continue
            out.append(Gap("optional", dll, func, f"named as text next to \"{dll}\" (probably looked up with "
                           "GetProcAddress); Wine has it only as a stub, which aborts the app if it's called",
                           [rel], scope, "guess"))
    return out


def scan(target: str | Path, indexes: dict[str, WineIndex], name: str | None = None,
         guess: bool = True) -> ScanResult:
    target = Path(target)
    mods = _collect(target)
    first = next(iter(indexes.values()))
    report = GapReport(backend="pe-wine", target=name or target.name,
                       provider=", ".join(i.label for i in indexes.values()))
    if not mods:
        report.blockers.append("no PE executables found (installers must be installed/extracted first)")
        return ScanResult(report, mods, {})

    bundled: dict[str, str] = {}   # basename lower -> rel
    for rel, info in mods.items():
        if info.is_dll or rel.lower().endswith((".dll", ".ocx", ".drv", ".ax", ".cpl", ".node", ".pyd")):
            bundled.setdefault(Path(rel).name.lower(), rel)

    # reachability: executables are roots; follow static imports into bundled DLLs
    exes = [r for r, i in mods.items() if not i.is_dll and r.lower().endswith(".exe")]
    reachable: set[str] = set()
    stack = list(exes)
    while stack:
        rel = stack.pop()
        if rel in reachable:
            continue
        reachable.add(rel)
        for imp in mods[rel].imports:
            b = bundled.get(imp.dll.lower())
            if b and not imp.delay:
                stack.append(b)

    missing: dict[str, dict] = {}
    counts = {"modules": len(mods), "executables": len(exes), "imports": 0}
    for rel, info in mods.items():
        if info.machine not in indexes:
            if info.machine in ARCH_TAGS:
                report.notes.append(f"{rel}: {info.machine} module skipped (no {info.machine} index; "
                                    f"pass one with --arch)")
            continue
        if rel.lower().endswith(".sys"):
            report.notes.append(f"{rel}: kernel driver; Wine only emulates a tiny part of the NT kernel "
                                "(anti-cheat, DRM and hardware drivers generally don't work)")
            continue
        idx = indexes[info.machine]
        scope = "app" if rel in reachable else "plugin"
        if info.is_dotnet:
            report.notes.append(f"{rel}: .NET assembly; needs wine-mono or Microsoft .NET, and managed "
                                "P/Invoke calls are not visible to import analysis")
        for imp in info.imports:
            counts["imports"] += 1
            dll_l = imp.dll.lower()
            if dll_l in bundled:
                continue  # app-local DLL wins; its own imports are scanned separately
            st = idx.status(imp.dll, imp.name, imp.ordinal)
            if st == "i":
                continue
            if st == "M":
                tier = "optional" if imp.delay or scope == "plugin" else "fatal"
                reason = ("delay-loaded DLL missing from Wine; fails on first use" if imp.delay
                          else "DLL is not provided by Wine and not shipped with the app")
                report.add(Gap(tier, dll_l, None, reason, [rel], scope))
                entry = missing.setdefault(dll_l, {"dll": imp.dll, "arch": info.machine, "names": set(),
                                                    "ordinals": set(), "static": False})
                if imp.name:
                    entry["names"].add(imp.name)
                else:
                    entry["ordinals"].add(imp.ordinal)
                entry["static"] |= not imp.delay
            else:
                tier = "crash" if scope == "app" else "optional"
                reason = "stub in Wine" if st == "s" else "not exported by Wine's builtin"
                report.add(Gap(tier, dll_l, imp.label, reason, [rel], scope))
        if guess:
            for g in _guess_gaps(rel, info, idx, bundled, scope):
                report.add(g)
    report.stats = counts
    if first.source == "libdir":
        report.notes.append("index built from installed DLLs: stubbed functions look implemented; "
                            "index a Wine source tree for stub detection")
    return ScanResult(report, mods, missing)


def write_stub_dlls(missing: dict[str, dict], out: Path, mode: str = "zero",
                    static_only: bool = True) -> list[str]:
    """Generate loader-satisfying stub DLLs for DLLs Wine doesn't have."""
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for dll_l, e in sorted(missing.items()):
        if static_only and not e["static"]:
            continue
        data = stub_dll(e["dll"], e["arch"], sorted(e["names"]), sorted(e["ordinals"]), mode=mode)
        (out / e["dll"]).write_bytes(data)
        written.append(e["dll"])
    return written


def default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "debpak" / "wine"
