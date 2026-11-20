"""One adapter per upstream project. Each knows how to tell whether it's set up,
whether a given app is installed under it, and the commands that launch,
install and stop that app."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .catalog import App, Route
from .host import Host


@dataclass
class Command:
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)   # added to the environment
    interactive: bool = False   # needs a terminal (asks questions)
    label: str = ""

    def shell(self) -> str:
        import shlex
        envs = " ".join(f"{k}={shlex.quote(v)}" for k, v in self.env.items())
        return (envs + " " if envs else "") + shlex.join(self.argv)


@dataclass
class Check:
    ok: bool
    detail: str


def to_windows_path(p: str) -> str:
    """A Linux path as a Windows app inside Wine sees it (Wine maps Z: to /)."""
    if p.startswith("/"):
        return "Z:" + p.replace("/", "\\")
    return p


class Backend:
    name = ""
    label = ""          # shown in the GUI and the menu actions
    project = ""        # submodule under third_party/
    single_file = False  # opens one file per launch

    def tool(self, host: Host) -> list[str] | None:
        return None

    def ready(self, host: Host) -> Check:
        t = self.tool(host)
        return Check(True, " ".join(t)) if t else Check(False, self.hint(host))

    def ready_app(self, app: App, host: Host) -> Check:
        """Whether this backend can run this particular app (most backends: same for every app)."""
        return self.ready(host)

    def installed(self, app: App, route: Route, host: Host) -> bool | None:
        """True/False if we can tell, None if we can't (for example, apps inside a VM)."""
        return None

    def launch(self, app: App, route: Route, files: list[str], host: Host) -> list[Command]:
        t = self.tool(host) or []
        if self.single_file and len(files) > 1:
            return [Command(t + [self.target(route, host), f]) for f in files]
        return [Command(t + [self.target(route, host), *files])]

    def install(self, app: App, route: Route, host: Host) -> list[Command]:
        return []

    def stop(self, app: App, route: Route, host: Host) -> Command | None:
        return None

    def run_program(self, app: App, route: Route, program: str, args: list[str], host: Host) -> Command | None:
        return None

    def exe_path(self, app: App, route: Route, host: Host) -> Path | None:
        return None

    def icon_file(self, app: App, route: Route, host: Host) -> Path | None:
        """A ready-made icon file the project ships for this app (svg/png)."""
        return None

    def icon_name(self, app: App, route: Route, host: Host) -> str | None:
        """An icon-theme name that the app's own package installs."""
        return None

    def target(self, route: Route, host: Host) -> str:
        return route.target

    def hint(self, host: Host) -> str:
        return ""

    def repo_url(self, host: Host) -> str:
        return f"https://github.com/{host.submodule_repo(self.project)}" if self.project else ""


def _newest(base: Path, pattern: str) -> Path | None:
    """Resolve a relative path whose folder may contain {year}, choosing the newest year."""
    parts = pattern.split("/")
    cur = base
    for part in parts:
        if "{year}" in part:
            rx = re.compile("^" + re.escape(part).replace(re.escape("{year}"), r"(\d{4})") + "$")
            try:
                found = sorted((m.group(1), e) for e in cur.iterdir() if (m := rx.match(e.name)))
            except OSError:
                return None
            if not found:
                return None
            cur = found[-1][1]
        else:
            cur = cur / part
    return cur if cur.exists() else None


# --------------------------------------------------------------------------- Microsoft 365 on Proton

class Ms365(Backend):
    name, label, project = "ms365", "Wine/Proton (office365_flake)", "office365_flake"

    def tool(self, host):
        if p := host.which("ms365"):
            return [p]
        if nix := host.which("nix"):
            sub = host.submodule_dir(self.project)
            flake = str(sub) if sub and (sub / "flake.nix").exists() else f"github:{host.submodule_repo(self.project)}"
            return [nix, "--extra-experimental-features", "nix-command flakes", "run", f"{flake}#ms365", "--"]
        return None

    def prefix(self, host: Host) -> Path:
        if p := host.env.get("MS365_PREFIX"):
            return Path(p)
        return Path(host.env.get("MS365_HOME") or host.home / ".local/share/ms365") / "prefix"

    def exe_path(self, app, route, host):
        if not route.exe:
            return None
        rel = Path("drive_c/Program Files/Microsoft Office/root/Office16") / route.exe
        for root in (self.prefix(host), self.prefix(host) / "pfx"):
            if (root / rel).is_file():
                return root / rel
        return None

    def installed(self, app, route, host):
        return self.exe_path(app, route, host) is not None

    def launch(self, app, route, files, host):
        return [Command((self.tool(host) or []) + ["run", route.target, *files])]

    def install(self, app, route, host):
        t = self.tool(host)
        return [Command(t + ["install"], label="Download and install Microsoft 365 (several GB)")] if t else []

    def stop(self, app, route, host):
        t = self.tool(host)
        return Command(t + ["kill"], label="Stop all Office processes") if t else None

    def run_program(self, app, route, program, args, host):
        t = self.tool(host)
        return Command(t + ["exec", program, *args]) if t else None

    def hint(self, host):
        return ("needs the office365_flake `ms365` command or Nix with flakes "
                f"(https://nixos.org/download), see {self.repo_url(host)}")


# --------------------------------------------------------------------------- Adobe on LinDobe

class LinDobe(Backend):
    name, label, project = "lindobe", "Wine (LinDobe)", "LinDobe"
    flatpak_id = "io.github.le_birnes.AdobeWine"

    def _via_flatpak(self, host: Host) -> bool:
        return not host.which("adobewine") and host.flatpak_installed(self.flatpak_id)

    def tool(self, host):
        if p := host.which("adobewine"):
            return [p]
        if host.flatpak_installed(self.flatpak_id) and (fp := host.which("flatpak")):
            return [fp, "run", "--command=adobewine", self.flatpak_id]
        sub = host.submodule_dir(self.project)
        if sub and (sub / "bin/adobewine").exists():
            if (sub / "runtime/bin/wine").exists() or (self.home(host) / "runtime/bin/wine").exists():
                return [str(sub / "bin/adobewine")]
        return None

    def home(self, host: Host) -> Path:
        if p := host.env.get("ADOBEWINE_HOME"):
            return Path(p)
        if self._via_flatpak(host):
            return host.home / ".var/app" / self.flatpak_id / "data/adobewine"
        return host.data_home / "adobewine"

    def exe_path(self, app, route, host):
        return _newest(self.home(host) / "prefix/drive_c/Program Files/Adobe", route.exe) if route.exe else None

    def installed(self, app, route, host):
        return self.exe_path(app, route, host) is not None

    def install(self, app, route, host):
        t = self.tool(host)
        if not t:
            return []
        cmds = [Command(t + ["setup"], label="Set up the LinDobe Wine prefix")]
        if not self.installed(app, route, host) and route.target != "cc":
            cmds.append(Command(t + ["cc"], label=f"Open Creative Cloud to install {app.name}"))
        return cmds

    def stop(self, app, route, host):
        t = self.tool(host)
        return Command(t + ["off"], label="Close Adobe apps and stop Wine") if t else None

    def run_program(self, app, route, program, args, host):
        t = self.tool(host)
        return Command(t + ["run", program, *args]) if t else None

    def hint(self, host):
        return (f"install LinDobe: the CCINSTALLER.flatpak from {self.repo_url(host)}/releases, "
                "its Arch package, or build third_party/LinDobe (docs/INSTALL.md)")


# --------------------------------------------------------------------------- Windows VM (WinApps / LinOffice)

