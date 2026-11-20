"""appbridge: one launcher for Microsoft 365, Adobe and other Windows-only work apps on Linux.

  appbridge list [--ready] [--suite NAME] [--json]
  appbridge info APP [--json]
  appbridge launch [--backend B] [--dry-run] APP [FILE ...]
  appbridge stop APP
  appbridge install [--backend B] [--dry-run] [-y] APP
  appbridge run APP PROGRAM [ARG ...]          run any .exe (an installer, say) in the app's prefix
  appbridge prefer APP BACKEND|auto
  appbridge integrate [APP ...] [--remove] [--default-handlers] [--force] [--dry-run]
  appbridge add ID --exe PATH [--name ...] [--runner wine|umu] [--prefix DIR] [--mime TYPE ...]
  appbridge remove ID
  appbridge doctor
  appbridge gap APP (--index FILE ... | --wine-source DIR)   winegap scan of the installed app
  appbridge gui [--tray]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from .. import __version__
from .backends import BACKENDS, Command
from .catalog import SUITES, to_json
from .core import NO_BACKEND, NOT_INSTALLED, READY, Bridge, Resolved
from .host import Host
from .integrate import Integrator

EXIT_NOT_READY = 3


def _err(msg: str, code: int = 1) -> int:
    print(f"appbridge: {msg}", file=sys.stderr)
    return code


def _notify(host: Host, title: str, body: str) -> None:
    """Started from a menu there's no terminal, so say what went wrong in a notification."""
    if sys.stderr.isatty():
        return
    if ns := host.which("notify-send"):
        subprocess.run([ns, "-a", "AppBridge", "-i", "dialog-warning", title, body], check=False)


def _state_json(res: Resolved) -> dict:
    return {
        "id": res.app.id, "name": res.app.name, "suite": res.app.suite, "status": res.status,
        "backend": res.backend.name if res.backend else None, "summary": res.summary,
        "routes": [{"backend": s.backend.name, "label": s.backend.label, "target": s.route.target,
                    "ready": s.check.ok, "detail": s.check.detail, "installed": s.installed}
                   for s in res.routes],
    }


# --------------------------------------------------------------------------- commands

def cmd_list(b: Bridge, a) -> int:
    rows = []
    for app in b.apps:
        if a.suite and app.suite.lower() != a.suite.lower():
            continue
        res = b.resolve(app)
        if a.ready and res.status != READY:
            continue
        rows.append(res)
    if a.json:
        print(json.dumps([_state_json(r) for r in rows], indent=2))
        return 0
    mark = {READY: "●", NOT_INSTALLED: "◐", NO_BACKEND: "○"}
    for suite in SUITES:
        group = [r for r in rows if r.app.suite == suite]
        if not group:
            continue
        print(f"\n{suite}")
        for r in group:
            via = r.backend.label if r.backend else "-"
            print(f"  {mark[r.status]} {r.app.id:<17} {r.app.name:<30} {r.status:<14} {via}")
    print("\n● ready   ◐ set up, app not installed (appbridge install APP)   ○ nothing set up (appbridge info APP)")
    return 0


def cmd_info(b: Bridge, a) -> int:
    app = b.app(a.app)
    res = b.resolve(app)
    if a.json:
        d = _state_json(res)
        d["app"] = to_json(app)
        print(json.dumps(d, indent=2))
        return 0
    print(f"{app.name} ({app.id}) - {app.suite}")
    print(f"status: {res.status} - {res.summary}")
    pref = b.config.prefer.get(app.id)
    if pref:
        print(f"preferred backend: {pref}")
    print("routes (best first):")
    for s in res.routes:
        chosen = "→" if s is res.state else " "
        inst = {True: "installed", False: "not installed", None: "unknown"}[s.installed] if s.check.ok else "-"
        print(f"  {chosen} {s.backend.name:<10} {s.route.target:<40} ready={'yes' if s.check.ok else 'no'}  app={inst}")
        if not s.check.ok:
            print(f"      {s.check.detail}")
    if res.status != READY:
        hint = b.install_hint(res)
        cmds = b.install_commands(res)
        if cmds:
            print(f"next: appbridge install {app.id}")
        elif hint:
            print(f"next: {hint}")
    if app.mime:
        print("opens: " + ", ".join(app.mime))
    return 0


def _run_all(b: Bridge, cmds: list[Command], wait_last: bool) -> int:
    """Run commands one after another; stop at the first failure."""
    for c in cmds:
        if c.label:
            print(f"==> {c.label}")
        print(f"$ {c.shell()}")
        if c.interactive and not sys.stdin.isatty():
            c = b.terminal(c)
        rc = subprocess.call(c.argv, env=b.env_for(c))
        if rc != 0:
            return _err(f"command failed with exit status {rc}", rc)
    return 0


def cmd_launch(b: Bridge, a) -> int:
    app = b.app(a.app)
    try:
        res = b.resolve(app, a.backend)
    except KeyError as e:
        return _err(str(e).strip("'\""))
    if res.status != READY and not a.backend:
        hint = b.install_hint(res)
        msg = f"{app.name} isn't ready: {res.summary}"
        _notify(b.host, f"Can't open {app.name}", msg + (f"\n{hint}" if hint else ""))
        print(msg, file=sys.stderr)
        if res.status == NOT_INSTALLED and b.install_commands(res):
            print(f"run: appbridge install {app.id}", file=sys.stderr)
        elif hint:
            print(hint, file=sys.stderr)
        return EXIT_NOT_READY
    cmds = b.launch_commands(res, a.files)
    if a.dry_run:
        for c in cmds:
            print(c.shell())
        return 0
    log = b.log_path(app.id)
    for c in cmds[:-1]:
        b.spawn(c, log)
    last = cmds[-1]
    if a.detach:
        b.spawn(last, log)
        return 0
    try:
        os.execvpe(last.argv[0], last.argv, b.env_for(last))
    except OSError as e:
        _notify(b.host, f"Can't open {app.name}", str(e))
        return _err(f"{last.argv[0]}: {e}")


def cmd_stop(b: Bridge, a) -> int:
    app = b.app(a.app)
    res = b.resolve(app)
    c = b.stop_command(res)
    if not c:
        return _err(f"{app.name} has no stop command; close it from its window")
    return _run_all(b, [c], True)


