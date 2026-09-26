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


