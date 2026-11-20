"""Choosing a route for an app and running commands. Shared by the CLI and the GUI."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .backends import BACKENDS, Backend, Check, Command
from .catalog import App, Config, Route, all_apps, find
from .host import Host

READY, NOT_INSTALLED, NO_BACKEND = "ready", "not installed", "not set up"


@dataclass
class RouteState:
    route: Route
    backend: Backend
    check: Check
    installed: bool | None

    @property
    def usable(self) -> bool:
        return self.check.ok and self.installed is not False


@dataclass
class Resolved:
    app: App
    status: str
    state: RouteState | None       # the route that will be used (or set up, if not installed)
    routes: list[RouteState]

    @property
    def backend(self) -> Backend | None:
        return self.state.backend if self.state else None

    @property
    def summary(self) -> str:
        if self.status == READY:
            return f"via {self.state.backend.label}"
        if self.status == NOT_INSTALLED:
            return f"{self.state.backend.label} is set up; {self.app.name} isn't installed there yet"
        first = self.routes[0]
        return f"{first.backend.label}: {first.check.detail}" if self.routes else "no way to run it"


class Bridge:
    """The catalog, your config and the machine, in one place."""

    def __init__(self, host: Host | None = None):
        self.host = host or Host()
        self.config = Config(self.host)
        self.apps = all_apps(self.config)

    def reload(self) -> None:
        self.config = Config(self.host)
        self.apps = all_apps(self.config)

    def app(self, app_id: str) -> App:
        a = find(self.apps, app_id)
        if not a:
            raise KeyError(f"unknown app '{app_id}' (see `appbridge list --all`)")
        return a

    def route_states(self, app: App) -> list[RouteState]:
        out = []
        for r in app.routes:
            b = BACKENDS[r.backend]
            chk = b.ready_app(app, self.host)
            out.append(RouteState(r, b, chk, b.installed(app, r, self.host) if chk.ok else None))
        return out

    def resolve(self, app: App, backend: str | None = None) -> Resolved:
        states = self.route_states(app)
        want = backend or self.config.prefer.get(app.id)
        if want:
            pick = next((s for s in states if s.backend.name == want), None)
            if backend and not pick:
                raise KeyError(f"{app.name} can't run through '{backend}' "
                               f"(choices: {', '.join(s.backend.name for s in states)})")
            # --backend is obeyed as asked; a saved preference only wins when it can launch the app
            if pick and (pick.usable or backend):
                status = READY if pick.usable else (NOT_INSTALLED if pick.check.ok else NO_BACKEND)
                return Resolved(app, status, pick, states)
        for s in states:
            if s.usable:
                return Resolved(app, READY, s, states)
        settable = [s for s in states if s.check.ok]
        for s in settable:   # prefer a route appbridge can install the app through
            if s.backend.install(app, s.route, self.host):
                return Resolved(app, NOT_INSTALLED, s, states)
        if settable:
            return Resolved(app, NOT_INSTALLED, settable[0], states)
        return Resolved(app, NO_BACKEND, None, states)

    # ------------------------------------------------------------------ custom apps
    def add_custom(self, app_id: str, exe: str, name: str = "", runner: str = "wine", prefix: str = "",
                   mime: list[str] | None = None, categories: list[str] | None = None,
                   env: dict[str, str] | None = None, proton: str = "", installer: str = "",
                   generic: str = "") -> App:
        """Add (or replace) one of your own Windows apps. Raises ValueError on bad input."""
        from .catalog import BUILTIN, valid_id
        if not valid_id(app_id):
            raise ValueError("ID must be lower-case letters, digits, '.', '_' or '-'")
        if any(x.id == app_id for x in BUILTIN):
            raise ValueError(f"'{app_id}' is a built-in app; pick another ID")
        if runner not in ("wine", "umu"):
            raise ValueError("runner must be wine or umu")
        if not exe:
            raise ValueError("give the program's .exe")
        d = {"id": app_id, "name": name or app_id, "exe": exe, "runner": runner,
             "prefix": prefix or str(self.config.default_prefix(app_id)), "mime": list(mime or []),
             "categories": list(categories or ["Office"]), "env": dict(env or {})}
        for k, v in (("proton", proton), ("installer", installer), ("generic", generic)):
            if v:
                d[k] = v
        self.config.custom = [x for x in self.config.custom if x["id"] != app_id] + [d]
        self.config.save()
        self.reload()
        return self.app(app_id)

    def remove_custom(self, app_id: str) -> None:
        if not any(x["id"] == app_id for x in self.config.custom):
            raise ValueError(f"'{app_id}' isn't one of your custom apps")
        self.config.custom = [x for x in self.config.custom if x["id"] != app_id]
        self.config.prefer.pop(app_id, None)
        self.config.save()
        self.reload()

    # ------------------------------------------------------------------ commands
    def launch_commands(self, res: Resolved, files: list[str]) -> list[Command]:
        files = [str(Path(f).expanduser().resolve()) if not _is_uri(f) else f for f in files]
        return res.backend.launch(res.app, res.state.route, files, self.host)

    def install_commands(self, res: Resolved) -> list[Command]:
        return res.backend.install(res.app, res.state.route, self.host) if res.state else []

    def stop_command(self, res: Resolved) -> Command | None:
        return res.backend.stop(res.app, res.state.route, self.host) if res.state else None

    def install_hint(self, res: Resolved) -> str:
        """What to do by hand when there's no command appbridge can run."""
        if not res.state:   # nothing set up: list every way to get it, best first
            return "; or ".join(f"{s.backend.label}: {s.check.detail}" for s in res.routes)
        s = res.state
        if not s.check.ok:
            return s.check.detail
        b = s.backend
        if b.name == "native":
            return f"install `{s.route.target}` from your distro or {b.release_url(s.route, self.host)}"
        if b.name == "flatpak" and not s.route.remote:
            return "download the .flatpak from the project's releases page and run `flatpak install --user FILE`"
        if b.name == "wine":
            return f"run its installer in the prefix: appbridge run {res.app.id} /path/to/setup.exe"
        return b.hint(self.host)

    def env_for(self, cmd: Command) -> dict[str, str]:
        env = dict(self.host.env)
        env.update(cmd.env)
        return env

    def log_path(self, app_id: str) -> Path:
        d = self.host.state_home / "appbridge/logs"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{app_id}.log"

    def spawn(self, cmd: Command, log: Path | None = None) -> subprocess.Popen:
        """Start a command detached from us (it keeps running if the GUI closes)."""
        out = open(log, "ab") if log else subprocess.DEVNULL
        try:
            return subprocess.Popen(cmd.argv, env=self.env_for(cmd), stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            if log:
                out.close()

    def terminal(self, cmd: Command) -> Command:
        """Wrap an interactive command in the desktop's terminal (Konsole on KDE)."""
        import shlex
        script = cmd.shell() + '; echo; read -r -p "Done (exit $?). Press Enter to close. " _'
        inner = ["bash", "-c", script]
        order = ["konsole", "gnome-terminal", "kgx", "xfce4-terminal", "x-terminal-emulator", "alacritty",
                 "kitty", "foot", "xterm"]
        if self.host.desktop in ("gnome", "ubuntu"):
            order.remove("gnome-terminal")
            order.insert(0, "gnome-terminal")
        for t in order:
            if p := self.host.which(t):
                # each terminal must stay in the foreground until the command ends,
                # so the next step (e.g. "start syncing") waits for this one
                if t == "gnome-terminal":
                    return Command([p, "--wait", "--", *inner], cmd.env, False, cmd.label)
                if t == "kgx":
                    return Command([p, "--", *inner], cmd.env, False, cmd.label)
                if t == "konsole":
                    return Command([p, "--nofork", "-e", *inner], cmd.env, False, cmd.label)
                if t in ("kitty", "foot"):
                    return Command([p, *inner], cmd.env, False, cmd.label)
                return Command([p, "-e", *inner] if t != "xfce4-terminal" else [p, "-x", *inner],
                               cmd.env, False, cmd.label)
        raise RuntimeError(f"no terminal emulator found to run: {shlex.join(cmd.argv)}")


def _is_uri(s: str) -> bool:
    return "://" in s or s.startswith(("msteams:", "mailto:"))
