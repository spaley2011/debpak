"""Runtime evidence for Wine: run an app with Wine's debug logging on (or read a
log you already have, e.g. Proton's steam-<id>.log) and turn what went wrong
into a gap report.

Import analysis (wine.scan) predicts problems from what a binary links against.
It can't see functions looked up with GetProcAddress, DLLs loaded with
LoadLibrary, COM classes, or Wine functions that exist but are only partly
implemented. Wine reports many of those itself when they happen:

  wine: Call from ... to unimplemented function NDFAPI.DLL.NdfCloseIncident, aborting
  0024:fixme:dwmapi:DwmSetWindowAttribute (...) stub
  0024:err:module:import_dll Library MSVCP140.dll (which is needed by L"C:\\...\\app.exe") not found
  0024:warn:module:load_dll Failed to load module L"nvcuda.dll"; status=c0000135
  0024:fixme:combase:CoCreateInstanceEx no instance created for interface {...} of class {...}, hr 0x80040154
  wine: Unhandled page fault on read access to 0000000000000000 at address ... (thread 0024)

Only code paths the run exercised show up, so merge a trace with the static
scan (evidence "both" means predicted and confirmed). Behaviour that is wrong
without Wine noticing, such as a function returning a slightly different result,
is still invisible; finding that needs a comparison against Windows.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .gap import Gap, GapReport, _merge_evidence

# err/fixme for everything, loader warnings (failed LoadLibrary), and the list of
# DLLs that loaded. Proton and the launch scripts pass WINEDEBUG through.
DEFAULT_CHANNELS = "err+all,fixme+all,warn+module,+loaddll"

_PREFIX = r"^(?:[0-9a-fA-F.]+:)*"   # optional timestamp / pid / tid fields
_LINE = re.compile(_PREFIX + r"(?P<cls>fixme|err|warn|trace):(?P<ch>[\w-]+):(?P<fn>[^\s:]+)[:\s]\s*(?P<msg>.*)$")
_UNIMPL = re.compile(r"Call from (?:0x)?[0-9a-fA-F]+ to unimplemented function (?P<dll>[^\s]+?)\.(?P<fn>[^.\s]+),")
_IMPORT_MISSING = re.compile(r'Library (?P<dll>\S+) \(which is needed by L?"(?P<by>[^"]+)"\) not found')
_IMPORT_FAILED = re.compile(r'Loading library (?P<dll>\S+) \(which is needed by L?"(?P<by>[^"]+)"\) failed '
                            r'\(error (?P<code>[0-9a-fA-Fx]+)\)')
_LOAD_FAILED = re.compile(r'Failed to load module L?"(?P<dll>[^"]+)"; status=(?P<code>[0-9a-fA-Fx]+)')
_IMPORT_ENTRY = re.compile(r'No implementation for (?P<dll>\S+?)\.(?P<fn>\S+) imported from L?"(?P<by>[^"]+)"')
_LOADED = re.compile(r'Loaded (?:module )?L?"(?P<path>[^"]+)"[^:]*: (?P<kind>builtin|native)')
_GUID = r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
_COM_NOINST = re.compile(r"no instance created for interface (?P<iid>" + _GUID + r") of class (?P<clsid>"
                         + _GUID + r"), hr (?P<hr>(?:0x)?[0-9a-fA-F]+)")
_COM_NOTREG = re.compile(r"class (?P<clsid>" + _GUID + r") not registered")
_UNHANDLED = re.compile(r"^(?:[0-9a-fA-F.]+:)*wine: (?P<what>Unhandled (?:page fault|exception|illegal instruction|"
                        r"stack overflow|privileged instruction)[^\n]*)")
_FRAME0 = re.compile(r"^=>\s*0\s+0x[0-9a-fA-F]+\s+(?:\S+\s+)?in\s+(?P<mod>[\w.+-]+)")
_STUB = re.compile(r"\bstub\b|\bnot implemented\b|\bunimplemented\b|\bsemi-stub\b", re.I)

COM_HRESULTS = {"0x80040154": "class not registered", "0x80004002": "interface not supported",
                "0x80070005": "access denied", "0x80004001": "not implemented"}


@dataclass
class Trace:
    """What one Wine run reported."""
    unimplemented: Counter = field(default_factory=Counter)          # (dll, func) -> n: aborted
    stubs: Counter = field(default_factory=Counter)                  # (channel, func) -> n: fixme ... stub
    partial: Counter = field(default_factory=Counter)                # (channel, func) -> n: other fixme
    missing_imports: dict = field(default_factory=lambda: defaultdict(set))   # dll -> {importer}
    failed_loads: Counter = field(default_factory=Counter)           # dll -> n (LoadLibrary / import failed)
    missing_entries: dict = field(default_factory=lambda: defaultdict(set))   # (dll, func) -> {importer}
    com: Counter = field(default_factory=Counter)                    # (clsid, hr) -> n
    crashes: list = field(default_factory=list)                      # (description, module or None)
    loaded: dict = field(default_factory=dict)                       # dll basename lower -> builtin/native
    lines: int = 0
    errors: Counter = field(default_factory=Counter)                 # (channel, func) -> n: other err lines

    @property
    def empty(self) -> bool:
        return not (self.unimplemented or self.stubs or self.missing_imports or self.failed_loads
                    or self.com or self.crashes or self.loaded or self.partial)


def _base(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def parse_log(lines) -> Trace:
    """Parse Wine/Proton debug output (any mix of channels, with or without timestamps)."""
    t = Trace()
    pending_crash: int | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        t.lines += 1
        if pending_crash is not None:
            m = _FRAME0.match(line.strip())
            if m:
                desc, _ = t.crashes[pending_crash]
                t.crashes[pending_crash] = (desc, m.group("mod").lower())
                pending_crash = None
                continue
        if "unimplemented function" in line and (m := _UNIMPL.search(line)):
            t.unimplemented[(m.group("dll").lower(), m.group("fn"))] += 1
            continue
        if m := _UNHANDLED.match(line):
            t.crashes.append((m.group("what").strip(), None))
            pending_crash = len(t.crashes) - 1
            continue
        m = _LINE.match(line)
        if not m:
            continue
        cls, ch, fn, msg = m.group("cls", "ch", "fn", "msg")
        if ch == "loaddll" and (mm := _LOADED.search(msg)):
            t.loaded[_base(mm.group("path")).lower()] = mm.group("kind")
            continue
        if ch == "module":
            if mm := _IMPORT_MISSING.search(msg):
                t.missing_imports[mm.group("dll").lower()].add(_base(mm.group("by")))
                continue
            if mm := _IMPORT_FAILED.search(msg):
                t.failed_loads[mm.group("dll").lower()] += 1
                continue
            if mm := _LOAD_FAILED.search(msg):
                t.failed_loads[_base(mm.group("dll")).lower()] += 1
                continue
            if mm := _IMPORT_ENTRY.search(msg):
                t.missing_entries[(mm.group("dll").lower(), mm.group("fn"))].add(_base(mm.group("by")))
                continue
        if mm := _COM_NOINST.search(msg):
            t.com[(mm.group("clsid").upper(), mm.group("hr").lower())] += 1
            continue
        if mm := _COM_NOTREG.search(msg):
            t.com[(mm.group("clsid").upper(), "0x80040154")] += 1
            continue
        if cls == "fixme":
            (t.stubs if _STUB.search(msg) else t.partial)[(ch, fn)] += 1
        elif cls == "err":
            t.errors[(ch, fn)] += 1
    return t


def _dll_for(func: str, channel: str, indexes) -> str:
    """Which DLL a fixme'd function belongs to: ask the Wine index, else guess from the channel."""
    for idx in indexes or ():
        hits = [d for d, e in idx.dlls.items() if func in e["e"] and not e["e"][func].startswith("f:")]
        if hits:
            return sorted(hits, key=lambda d: (not d.startswith(channel), len(d)))[0]
    return f"[{channel}]"


def to_report(trace: Trace, name: str, indexes=None, static: GapReport | None = None,
              provider: str = "wine (traced run)") -> GapReport:
    """A gap report of what the run showed, merged into the static scan if one is given."""
    r = static or GapReport(backend="pe-wine", target=name, provider=provider)
    runtime: list[Gap] = []
    for (dll, func), n in trace.unimplemented.items():
        runtime.append(Gap("crash", dll, func, "called while running: Wine has no implementation, so the app "
                           "aborted here", [], "app", "runtime", n))
    for dll, who in trace.missing_imports.items():
        main_exe = any(w.lower().endswith(".exe") for w in who)
        runtime.append(Gap("fatal" if main_exe else "degraded", dll, None,
                           "needed while running but not found" + ("" if main_exe else
                           " (a DLL loaded on demand couldn't load, so its feature is missing)"),
                           sorted(who), "app", "runtime", 1))
    for (dll, func), who in trace.missing_entries.items():
        runtime.append(Gap("crash", dll, func, "imported by a DLL loaded while running; Wine doesn't export it",
                           sorted(who), "app", "runtime", 1))
    for dll, n in trace.failed_loads.items():
        if dll in trace.missing_imports:
            continue
        runtime.append(Gap("degraded", dll, None, "the app tried to load it while running and it failed "
                           "(LoadLibrary returned NULL; the feature that needs it is off)", [], "app", "runtime", n))
    for (ch, func), n in trace.stubs.items():
        runtime.append(Gap("degraded", _dll_for(func, ch, indexes), func,
                           "called while running; Wine's implementation is a stub (fixme)", [], "app", "runtime", n))
    for (clsid, hr), n in trace.com.items():
        why = COM_HRESULTS.get(hr, f"hr {hr}")
        runtime.append(Gap("degraded", "com", clsid, f"COM object the app asked for couldn't be created ({why})",
                           [], "app", "runtime", n))
    for desc, mod in trace.crashes:
        runtime.append(Gap("crash", mod or "[crash]", None, f"the app crashed: {desc}" +
                           ("" if mod else " (no backtrace in the log)"), [], "app", "runtime", 1))

    by_key = {g.key: g for g in r.gaps}
    for g in runtime:
        if g.key in by_key:      # predicted by the scan, and now seen
            s = by_key[g.key]
            s.evidence = _merge_evidence(s.evidence, "runtime")
            s.count += g.count
            s.reason += f"; confirmed while running ({g.reason})"
            if _worse(g.tier, s.tier):
                s.tier = g.tier
        else:
            r.add(g)

    r.stats = dict(r.stats)
    r.stats.update({"log_lines": trace.lines, "dlls_loaded": len(trace.loaded),
                    "native_dlls": sum(1 for k in trace.loaded.values() if k == "native"),
                    "fixme_other": sum(trace.partial.values())})
    if trace.partial:
        top = ", ".join(f"{fn} ({ch}) x{n}" for (ch, fn), n in trace.partial.most_common(8))
        r.notes.append(f"partly implemented functions the app used (fixme, usually harmless): {top}")
    if trace.empty:
        r.notes.append("the log has no Wine debug output: was WINEDEBUG set, and did the launcher pass it "
                       f"through? (winegap trace sets WINEDEBUG={DEFAULT_CHANNELS})")
    elif not trace.loaded:
        r.notes.append("no +loaddll lines: DLLs loaded at runtime weren't recorded")
    r.notes.append("a trace only covers what this run did: open the documents and features you care about "
                   "while tracing")
    if static is not None and r.provider and "traced" not in r.provider:
        r.provider += " + traced run"
    return r


def _worse(a: str, b: str) -> bool:
    from .gap import TIER_ORDER
    return TIER_ORDER.index(a) < TIER_ORDER.index(b)


# --------------------------------------------------------------------------- running

def run_traced(argv: list[str], log: Path, env: dict | None = None, timeout: float | None = 120,
               channels: str = DEFAULT_CHANNELS, wineserver: str | None = "wineserver") -> int | None:
    """Run a command with WINEDEBUG set, its output going to `log`.

    Stops it after `timeout` seconds (None = wait for it to exit), then, if
    WINEPREFIX is set, shuts down that prefix's wineserver so helper processes
    don't linger. Returns the exit status, or None if it was stopped.
    """
    e = dict(os.environ if env is None else env)
    e.setdefault("WINEDEBUG", channels)   # Proton keeps a WINEDEBUG it's given
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "wb") as out:
        proc = subprocess.Popen(argv, env=e, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        finally:
            if proc.poll() is None:
                _stop(proc)
            # only with a known prefix: a bare `wineserver -k` would close the default prefix's apps
            if wineserver and e.get("WINEPREFIX") and (ws := _which(wineserver, e)):
                subprocess.run([ws, "-k"], env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=30, check=False)
    return None


def _stop(proc: subprocess.Popen) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        for _ in range(50):
            if proc.poll() is not None:
                return
            time.sleep(0.1)


def _which(name: str, env: dict) -> str | None:
    import shutil
    return shutil.which(name, path=env.get("PATH"))


def read_log(path: str | Path) -> Trace:
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse_log(f)
