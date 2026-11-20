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

class WinApps(Backend):
    name, label, project = "winapps", "Windows VM (WinApps)", "winapps"
    single_file = True

    def tool(self, host):
        return [p] if (p := host.which("winapps") or host.which(str(host.home / ".local/bin/winapps"))) else None

    def ready(self, host):
        t = self.tool(host)
        if not t:
            return Check(False, self.hint(host))
        conf = host.config_home / "winapps/winapps.conf"
        if not conf.exists():
            return Check(False, f"WinApps is installed but {conf} is missing; run its setup")
        return Check(True, t[0])

    def _apps_dir(self, host):
        return host.data_home / "winapps/apps"

    def _resolve(self, route, host) -> tuple[str, bool | None]:
        names = route.target.split("|")
        if names == ["windows"]:
            return "windows", True
        d = self._apps_dir(host)
        if not d.is_dir():
            return names[0], None
        for n in names:
            if (d / n / "info").exists():
                return n, True
        return names[0], False

    def target(self, route, host):
        return self._resolve(route, host)[0]

    def installed(self, app, route, host):
        return self._resolve(route, host)[1]

    def icon_file(self, app, route, host):
        p = self._apps_dir(host) / self.target(route, host) / "icon.svg"
        return p if p.is_file() else None

    def install(self, app, route, host):
        sub = host.submodule_dir(self.project)
        if sub and (sub / "setup.sh").exists():
            return [Command(["bash", str(sub / "setup.sh")], interactive=True,
                            label="WinApps setup (finds the apps installed in your Windows VM)")]
        return []

    def stop(self, app, route, host):
        t = self.tool(host)
        return Command(t + ["killrdp"], label="Close the Windows app windows (FreeRDP)") if t else None

    def hint(self, host):
        return ("needs WinApps with a Windows VM (Docker, Podman or libvirt) and FreeRDP 3, "
                f"see {self.repo_url(host)}")


class LinOffice(Backend):
    name, label, project = "linoffice", "Windows VM (LinOffice)", "linoffice"
    flatpak_id = "io.github.eylenburg.LinOffice"
    single_file = True

    def tool(self, host):
        for c in ("linoffice", str(host.home / ".local/bin/linoffice/linoffice.sh")):
            if p := host.which(c):
                return [p]
        if host.flatpak_installed(self.flatpak_id) and (fp := host.which("flatpak")):
            return [fp, "run", "--command=/app/linoffice.sh", self.flatpak_id]
        return None

    def install(self, app, route, host):
        if fp := host.which("flatpak"):
            return [Command([fp, "remote-add", "--if-not-exists", "--user", "linoffice",
                             "https://eylenburg.github.io/linoffice/index.flatpakrepo"], label="Add the LinOffice remote"),
                    Command([fp, "install", "--user", "-y", "linoffice", self.flatpak_id], label="Install LinOffice"),
                    Command([fp, "run", self.flatpak_id], label="LinOffice setup (creates the Windows VM)")]
        sub = host.submodule_dir(self.project)
        if sub and (sub / "setup.sh").exists():
            return [Command(["bash", str(sub / "setup.sh")], interactive=True, label="LinOffice setup")]
        return []

    def stop(self, app, route, host):
        t = self.tool(host)
        return Command(t + ["--stopcontainer"], label="Shut down the Office VM") if t else None

    def hint(self, host):
        return f"needs LinOffice (Office in a Windows container, with Podman), see {self.repo_url(host)}"


# --------------------------------------------------------------------------- native Linux wrappers

_NATIVE_PROJECTS = {"teams-for-linux": "teams-for-linux", "prospect-mail": "prospect-mail",
                    "p3x-onenote": "onenote", "onedrive": "onedrive"}


class Flatpak(Backend):
    name, label = "flatpak", "Flatpak"

    def tool(self, host):
        return [p] if (p := host.which("flatpak")) else None

    def ready_app(self, app, host):
        route = next(r for r in app.routes if r.backend == self.name)
        fp = host.which("flatpak")
        if not fp:
            return Check(False, "needs flatpak")
        if route.remote or host.flatpak_installed(route.target):
            return Check(True, fp)
        # Not on a remote we know: only counts once you've installed the bundle yourself.
        return Check(False, f"install the {route.target} .flatpak bundle from the project's releases")

    def installed(self, app, route, host):
        return host.flatpak_installed(route.target)

    def launch(self, app, route, files, host):
        return [Command((self.tool(host) or ["flatpak"]) + ["run", route.target, *files])]

    def install(self, app, route, host):
        t = self.tool(host)
        if t and route.remote:
            return [Command(t + ["install", "--user", "-y", route.remote, route.target], label=f"Install {route.target}")]
        return []

    def stop(self, app, route, host):
        t = self.tool(host)
        return Command(t + ["kill", route.target]) if t else None

    def icon_name(self, app, route, host):
        return route.target

    def hint(self, host):
        return "needs flatpak"


class Native(Backend):
    name, label = "native", "Linux app"

    def ready(self, host):
        return Check(True, "")

    def ready_app(self, app, host):
        # A native wrapper is "set up" exactly when its program is on PATH.
        route = next(r for r in app.routes if r.backend == self.name)
        if p := host.which(route.target):
            return Check(True, p)
        where = self.release_url(route, host)
        return Check(False, f"install `{route.target}` from your distro" + (f" or {where}" if where else ""))

    def installed(self, app, route, host):
        return host.which(route.target) is not None

    def launch(self, app, route, files, host):
        return [Command([host.which(route.target) or route.target, *files])]

    def icon_name(self, app, route, host):
        return route.target

    def release_url(self, route: Route, host: Host) -> str:
        proj = _NATIVE_PROJECTS.get(route.target)
        return f"https://github.com/{host.submodule_repo(proj)}/releases" if proj else ""


class Service(Backend):
    """A sync daemon run as a systemd user service (OneDrive)."""
    name, label, project = "service", "systemd user service", "onedrive"

    def tool(self, host):
        return [p] if host.which("onedrive") and (p := host.which("systemctl")) else None

    def installed(self, app, route, host):
        return (host.config_home / "onedrive/refresh_token").exists()

    def sync_dir(self, host: Host) -> Path:
        try:
            for line in (host.config_home / "onedrive/config").read_text().splitlines():
                m = re.match(r'\s*sync_dir\s*=\s*"([^"]+)"', line)
                if m:
                    return host.expand(m.group(1))
        except OSError:
            pass
        return host.home / "OneDrive"

    def launch(self, app, route, files, host):
        cmds = [Command([(self.tool(host) or ["systemctl"])[0], "--user", "start", route.target])]
        if opener := host.which("xdg-open"):
            cmds.append(Command([opener, str(self.sync_dir(host))]))
        return cmds

    def install(self, app, route, host):
        t = self.tool(host)
        od = host.which("onedrive")
        if not t or not od:
            return []
        return [Command([od], interactive=True, label="Sign in to OneDrive (paste the redirect URL when asked)"),
                Command(t + ["--user", "enable", "--now", route.target], label="Start syncing at login")]

    def stop(self, app, route, host):
        t = self.tool(host)
        return Command(t + ["--user", "stop", route.target]) if t else None

    def hint(self, host):
        return f"needs the `onedrive` client (your distro's package, or {self.repo_url(host)}) and systemd"


# --------------------------------------------------------------------------- your own Windows apps on Wine / umu

