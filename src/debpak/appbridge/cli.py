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


def cmd_install(b: Bridge, a) -> int:
    app = b.app(a.app)
    try:
        res = b.resolve(app, a.backend)
    except KeyError as e:
        return _err(str(e).strip("'\""))
    if res.status == NO_BACKEND:
        print(f"{app.name}: nothing is set up to run it yet. Options, best first:")
        for s in res.routes:
            print(f"  - {s.backend.label}: {s.check.detail or b.install_hint(Resolved(app, NO_BACKEND, s, res.routes))}")
        return EXIT_NOT_READY
    cmds = b.install_commands(res)
    if not cmds:
        print(f"{app.name}: appbridge can't install this one for you. {b.install_hint(res)}")
        return EXIT_NOT_READY if res.status != READY else 0
    if res.status == READY:
        print(f"{app.name} is already installed ({res.summary}); these will refresh or repair it:")
    for c in cmds:
        print(f"  {c.label + ': ' if c.label else ''}{c.shell()}")
    if a.dry_run:
        return 0
    if not a.yes and sys.stdin.isatty():
        if input("Run these? [y/N] ").strip().lower() not in ("y", "yes"):
            return 1
    return _run_all(b, cmds, True)


def cmd_run(b: Bridge, a) -> int:
    app = b.app(a.app)
    res = b.resolve(app)
    c = res.backend.run_program(app, res.state.route, a.program, a.args, b.host) if res.state and res.state.check.ok else None
    if not c:
        return _err(f"{app.name}: its backend ({res.backend.name if res.backend else 'none'}) can't run other programs")
    print(f"$ {c.shell()}")
    return subprocess.call(c.argv, env=b.env_for(c))


def cmd_prefer(b: Bridge, a) -> int:
    app = b.app(a.app)
    if a.backend == "auto":
        b.config.prefer.pop(app.id, None)
    else:
        names = [r.backend for r in app.routes]
        if a.backend not in names:
            return _err(f"{app.name} can run through: {', '.join(names)}")
        b.config.prefer[app.id] = a.backend
    b.config.save()
    print(f"{app.name}: {b.resolve(app).summary}")
    return 0


def cmd_integrate(b: Bridge, a) -> int:
    integ = Integrator(b, dry_run=a.dry_run)
    try:
        if a.remove:
            r = integ.remove(a.apps or None, include_self=not a.apps)
            for p in r.removed:
                print(f"removed {p}")
            if not r.removed:
                print("nothing to remove")
        else:
            r = integ.add(a.apps or None, force=a.force, include_self=not a.no_self, set_default=a.default_handlers)
            for p in r.written:
                print(f"{'would write' if a.dry_run else 'wrote'} {p}")
            for app_id, why in r.skipped:
                print(f"skipped {app_id}: {why}")
            if r.defaults:
                print(f"default app for: {', '.join(r.defaults)}")
            if not a.apps and not [p for p in r.written if p.name.startswith("appbridge-")]:
                print("no apps are ready yet; `appbridge list` shows what's missing")
    except KeyError as e:
        return _err(str(e).strip("'\""))
    if r.refreshed:
        print(f"refreshed: {', '.join(r.refreshed)}")
    return 0


def cmd_add(b: Bridge, a) -> int:
    env = {}
    for kv in a.env or []:
        k, sep, v = kv.partition("=")
        if not sep:
            return _err(f"--env needs KEY=VALUE, got {kv!r}")
        env[k] = v
    app = b.add_custom(a.id, a.exe, name=a.name or "", runner=a.runner, prefix=a.prefix or "", mime=a.mime,
                       categories=a.category, env=env, proton=a.proton or "", installer=a.installer or "",
                       generic=a.generic or "")
    res = b.resolve(app)
    print(f"added {app.id}: {res.status} - {res.summary}")
    if res.status == NOT_INSTALLED:
        print(f"install it with: appbridge install {app.id}" if a.installer else
              f"install it with: appbridge run {app.id} /path/to/setup.exe")
    return 0


def cmd_remove(b: Bridge, a) -> int:
    b.remove_custom(a.id)
    Integrator(b).remove([a.id])
    print(f"removed {a.id} (its Wine prefix was left in place)")
    return 0


def doctor_lines(b: Bridge) -> list[tuple[bool | None, str, str]]:
    """(ok, item, detail) rows; ok=None for information."""
    h = b.host
    rows: list[tuple[bool | None, str, str]] = []
    rows.append((None, "desktop", f"{h.desktop or 'unknown'} ({h.env.get('XDG_SESSION_TYPE', '?')})"))
    for name, bk in BACKENDS.items():
        if name in ("native", "wine"):
            continue
        c = bk.ready(h)
        rows.append((c.ok, f"backend {name}", c.detail))
    for tool, why in [("wine", "custom apps"), ("umu-run", "custom apps on Proton"), ("nix", "Microsoft 365 flake"),
                      ("flatpak", "LinDobe, LinOffice, Teams"), ("podman", "WinApps/LinOffice VM"),
                      ("docker", "WinApps VM"), ("virsh", "WinApps on libvirt"),
                      ("xdg-mime", "file associations"), ("update-desktop-database", "MIME cache"),
                      ("notify-send", "error notifications from menu launches")]:
        p = h.which(tool)
        rows.append((bool(p), tool, p or f"not found ({why})"))
    rdp = next((p for t in ("xfreerdp3", "sdl-freerdp3", "xfreerdp", "sdl-freerdp") if (p := h.which(t))), None)
    if not rdp and h.flatpak_installed("com.freerdp.FreeRDP"):
        rdp = "flatpak com.freerdp.FreeRDP"
    rows.append((bool(rdp), "FreeRDP", rdp or "not found (WinApps/LinOffice)"))
    kvm = os.path.exists("/dev/kvm")
    rows.append((kvm, "/dev/kvm", "present" if kvm else "missing: VM backends will be very slow or fail"))
    if h.desktop in ("kde", "plasma"):
        k = h.which("kbuildsycoca6") or h.which("kbuildsycoca5")
        rows.append((bool(k), "kbuildsycoca", k or "not found: KDE won't see new menu entries until you log out"))
    if h.checkout:
        missing = [n for n in ("office365_flake", "winapps", "linoffice", "LinDobe") if not h.submodule_dir(n)]
        rows.append((None, "debpak checkout", f"{h.checkout}" + (f" (not checked out: {', '.join(missing)}; "
                     "git submodule update --init --depth 1 third_party/NAME)" if missing else "")))
    return rows


def cmd_doctor(b: Bridge, a) -> int:
    sym = {True: "ok ", False: "-- ", None: "   "}
    for ok, item, detail in doctor_lines(b):
        print(f"{sym[ok]} {item:<26} {detail}")
    ready = [x for x in b.apps if b.resolve(x).status == READY]
    print(f"\n{len(ready)} of {len(b.apps)} apps ready" + (f": {', '.join(x.id for x in ready)}" if ready else ""))
    return 0


def cmd_gap(b: Bridge, a) -> int:
    app = b.app(a.app)
    res = b.resolve(app)
    exe = res.backend.exe_path(app, res.state.route, b.host) if res.state else None
    if not exe or not exe.exists():
        return _err(f"can't find {app.name}'s installed files (status: {res.status})")
    from ..cli_compat import winegap_main
    return winegap_main(["scan", str(exe.parent), "--name", app.name, *a.winegap_args])


def cmd_gui(b: Bridge, a) -> int:
    from .gui import main as gui_main
    return gui_main(["--tray"] if a.tray else [])


# --------------------------------------------------------------------------- argparse

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="appbridge", description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"appbridge (debpak) {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    p = sub.add_parser("list", help="list apps and whether they can run")
    p.add_argument("--ready", action="store_true", help="only apps that can launch now")
    p.add_argument("--suite", help=f"one of: {', '.join(SUITES)}")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("info", help="how an app can run, and what's missing")
    p.add_argument("app")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_info)

    p = sub.add_parser("launch", help="open an app (optionally with files)")
    p.add_argument("app")
    p.add_argument("files", nargs="*")
    p.add_argument("--backend", help="use this backend instead of the automatic choice")
    p.add_argument("--dry-run", action="store_true", help="print the command instead of running it")
    p.add_argument("--detach", action="store_true", help="start it in the background and return")
    p.set_defaults(fn=cmd_launch)

    p = sub.add_parser("stop", help="close an app or stop a sync service")
    p.add_argument("app")
    p.set_defaults(fn=cmd_stop)

    p = sub.add_parser("install", help="install or set up an app through its backend")
    p.add_argument("app")
    p.add_argument("--backend")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("-y", "--yes", action="store_true", help="don't ask before running")
    p.set_defaults(fn=cmd_install)

    p = sub.add_parser("run", help="run another program (an installer, regedit, ...) in an app's Wine prefix")
    p.add_argument("app")
    p.add_argument("program")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("prefer", help="always use one backend for an app ('auto' to undo)")
    p.add_argument("app")
    p.add_argument("backend")
    p.set_defaults(fn=cmd_prefer)

    p = sub.add_parser("integrate", help="add ready apps to the app menu, KRunner and Open With")
    p.add_argument("apps", nargs="*", help="default: every ready app")
    p.add_argument("--remove", action="store_true", help="remove appbridge's menu entries instead")
    p.add_argument("--default-handlers", action="store_true", help="also make them the default app for their file types")
    p.add_argument("--force", action="store_true", help="add entries even if not ready or already present")
    p.add_argument("--no-self", action="store_true", help="don't add the AppBridge window itself")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_integrate)

    p = sub.add_parser("add", help="add your own Windows app, run with Wine or umu/Proton")
    p.add_argument("id")
    p.add_argument("--exe", required=True, help="the .exe: a Linux path, or C:\\... inside the prefix")
    p.add_argument("--name")
    p.add_argument("--generic", help="what it is, e.g. 'Expense Reports'")
    p.add_argument("--runner", choices=["wine", "umu"], default="wine")
    p.add_argument("--proton", help="PROTONPATH for umu (default GE-Proton, downloaded by umu)")
    p.add_argument("--prefix", help="Wine prefix (default ~/.local/share/appbridge/prefixes/ID)")
    p.add_argument("--installer", help="setup .exe for `appbridge install ID`")
    p.add_argument("--mime", action="append", help="a file type it opens (repeatable)")
    p.add_argument("--category", action="append", help="menu category (repeatable, default Office)")
    p.add_argument("--env", action="append", metavar="KEY=VALUE")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("remove", help="remove one of your custom apps")
    p.add_argument("id")
    p.set_defaults(fn=cmd_remove)

    p = sub.add_parser("doctor", help="check what's installed")
    p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("gap", help="winegap scan of an installed app: which Windows functions Wine is missing")
    p.add_argument("app")
    p.add_argument("winegap_args", nargs=argparse.REMAINDER, help="--index FILE ... or --wine-source DIR, -o, --json")
    p.set_defaults(fn=cmd_gap)

    p = sub.add_parser("gui", help="open the AppBridge window")
    p.add_argument("--tray", action="store_true")
    p.set_defaults(fn=cmd_gui)
    return ap


def main(argv: list[str] | None = None, host: Host | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        b = Bridge(host)
        return a.fn(b, a)
    except KeyError as e:
        return _err(str(e).strip("'\""))
    except (ValueError, RuntimeError) as e:
        return _err(str(e))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
