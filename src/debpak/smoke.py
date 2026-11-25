"""Runtime check for converted apps: run one with the dynamic loader's own
logging on (LD_DEBUG=libs,files) and report the libraries it asked for but
couldn't load.

Static analysis sees DT_NEEDED, but plugins, codecs and GPU libraries are
loaded with dlopen() while the app runs. glibc logs every request and every
successful load:

  file=libfoo.so.3 [0];  dynamically loaded by ./app [0]     <- dlopen request
  file=libbar.so.1 [0];  needed by ./app [0]                 <- DT_NEEDED request
  file=libfoo.so.3 [0];  generating link map                 <- found and loaded

A request with no "generating link map" afterwards (in the same process) failed.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import host
from .gap import Gap, GapReport

_PID = r"^\s*(?P<pid>\d+):\s+"
_REQUEST = re.compile(_PID + r"file=(?P<name>\S+) \[\d+\];\s+(?P<how>dynamically loaded|needed) by (?P<by>\S+)")
_LOADED = re.compile(_PID + r"file=(?P<name>\S+) \[\d+\];\s+generating link map")
_UNDEF = re.compile(r"(?:symbol lookup error|undefined symbol)[^\n]*?undefined symbol: (?P<sym>[^\s,]+)"
                    r"(?:[^\n]*?\(?(?P<ver>[\w.]+)?\)?)?")
_STARTUP = re.compile(r"error while loading shared libraries: (?P<name>[^:]+): (?P<why>.+)")

# Libraries apps commonly probe for and run fine without (GPU vendors, optional
# accelerators). Their failures are reported but called out as usually harmless.
PROBES = re.compile(r"^lib(?:cuda|nvidia|nvcuvid|nvidia-encode|OpenCL|vdpau|va|va-drm|va-x11|amdocl|"
                    r"vulkan|GLX_nvidia|EGL_nvidia|unity|appindicator|ayatana|gtk-x11|canberra|"
                    r"secret|gnome-keyring|kwallet)", re.I)


@dataclass
class LoadLog:
    """What one LD_DEBUG=libs,files log shows: what loaded, what failed and how it was requested."""
    failed: dict = field(default_factory=lambda: defaultdict(set))   # name -> {requested by}
    failed_needed: dict = field(default_factory=lambda: defaultdict(set))
    loaded: set = field(default_factory=set)
    undefined: dict = field(default_factory=lambda: defaultdict(int))  # symbol -> n
    startup_errors: list = field(default_factory=list)
    lines: int = 0


def parse_ld_debug(lines) -> LoadLog:
    """Read an LD_DEBUG=libs,files log.

    A request with no "generating link map" line afterwards from the same
    process failed. A failed dlopen() goes in failed; a failed DT_NEEDED load,
    or a loader error at startup, goes in failed_needed.
    """
    out = LoadLog()
    pending: dict[tuple[str, str], tuple[str, str]] = {}   # (pid, name) -> (how, by)
    for raw in lines:
        line = raw.rstrip("\n")
        out.lines += 1
        _read_line(line, out, pending)
    for (_pid, name), (how, by) in pending.items():
        base = os.path.basename(name)
        if base in out.loaded and "/" not in name:
            continue      # another process loaded it; this request was a duplicate
        (out.failed if how == "dynamically loaded" else out.failed_needed)[base].add(by)
    return out


def _read_line(line: str, out: LoadLog, pending: dict[tuple[str, str], tuple[str, str]]) -> None:
    """Record what one log line shows: a load, a request, a loader error at startup or an undefined symbol."""
    if m := _LOADED.match(line):
        pending.pop((m.group("pid"), m.group("name")), None)
        out.loaded.add(os.path.basename(m.group("name")))
        return
    if m := _REQUEST.match(line):
        pending[(m.group("pid"), m.group("name"))] = (m.group("how"), os.path.basename(m.group("by")))
        return
    if m := _STARTUP.search(line):
        out.startup_errors.append(f"{m.group('name')}: {m.group('why').strip()}")
        out.failed_needed[os.path.basename(m.group("name"))].add("(startup)")
        return
    if "undefined symbol:" in line and (m := _UNDEF.search(line)):
        out.undefined[m.group("sym")] += 1


def to_report(log: LoadLog, name: str, provider: str = "flatpak runtime (smoke run)") -> GapReport:
    """Turn a load log into a gap report.

    Startup failures are fatal. dlopen() failures are degraded, except the GPU
    and desktop probes in PROBES, which are optional. Undefined symbols are crash.
    """
    r = GapReport(backend="elf-flatpak", target=name, provider=provider)
    for lib, who in sorted(log.failed_needed.items()):
        r.add(Gap("fatal", lib, None, "needed at startup but not found", sorted(who), "app", "runtime", 1))
    for lib, who in sorted(log.failed.items()):
        r.add(_dlopen_gap(lib, who))
    for sym, n in sorted(log.undefined.items()):
        r.add(Gap("crash", "[symbol]", sym, "undefined symbol at runtime (library version too old or wrong)",
                  [], "app", "runtime", n))
    r.stats = {"log_lines": log.lines, "libraries_loaded": len(log.loaded)}
    r.notes += [f"loader error at startup: {e}" for e in log.startup_errors]
    if not log.lines or (not log.loaded and not log.failed and not log.failed_needed):
        r.notes.append("no LD_DEBUG output: did the command run, and does it keep the environment?")
    r.notes.append("only libraries this run tried to load are covered: use the app's features while it runs")
    r.notes.append("to fix a missing library, add the package that has it with "
                   "`debpak convert --deps-dir` or pick a runtime that provides it")
    return r


def _dlopen_gap(lib: str, who: set) -> Gap:
    """Return the gap for a library dlopen() couldn't find: optional for a probe in PROBES, else degraded."""
    probe = bool(PROBES.match(lib))
    return Gap("optional" if probe else "degraded", lib, None,
               "loaded on demand (dlopen) and not found" + (": an optional GPU/desktop library apps usually "
                                                            "run fine without" if probe else
                                                            "; the feature that needs it won't work"),
               sorted(who), "app", "runtime", 1)


def run_logged(argv: list[str], timeout: float | None = 20, env: dict | None = None,
               log: Path | None = None) -> tuple[Path, int | None]:
    """Run argv with LD_DEBUG=libs,files and capture the log (stderr+stdout)."""
    from .winetrace import _stop
    e = dict(os.environ if env is None else env)
    e["LD_DEBUG"] = "libs,files"
    log = log or Path(tempfile.mkdtemp(prefix="debpak-smoke-")) / "ld-debug.log"
    with open(log, "wb") as out:
        proc = subprocess.Popen(host.command(argv), env=e, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            return log, proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _stop(proc)
            return log, None


def flatpak_argv(app_id: str, command: str | None, args: list[str]) -> list[str]:
    """Return the `flatpak run` command line that passes LD_DEBUG into the sandbox."""
    cmd = ["flatpak", "run", "--env=LD_DEBUG=libs,files"]
    if command:
        cmd.append(f"--command={command}")
    return cmd + [app_id, *args]
