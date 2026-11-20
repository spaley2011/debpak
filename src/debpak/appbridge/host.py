"""The parts of the machine appbridge looks at, behind one object so tests can
fake a whole desktop in a temporary directory."""
from __future__ import annotations

import configparser
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

# Upstreams used when appbridge runs outside a debpak checkout. Inside a
# checkout, .gitmodules wins, so after scripts/fork-upstreams.sh the forks are used.
DEFAULT_UPSTREAMS = {
    "office365_flake": "Tombert/office365_flake",
    "umu-launcher": "Open-Wine-Components/umu-launcher",
    "winapps": "winapps-org/winapps",
    "linoffice": "eylenburg/linoffice",
    "LinDobe": "le-birnes/LinDobe",
    "wine-adobe-installers": "PhialsBasement/wine-adobe-installers",
    "teams-for-linux": "IsmaelMartinez/teams-for-linux",
    "prospect-mail": "julian-alarcon/prospect-mail",
    "onenote": "patrikx3/onenote",
    "onedrive": "abraunegg/onedrive",
}


def _find_checkout() -> Path | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".gitmodules").is_file() and (parent / "third_party").is_dir():
            return parent
    return None


@dataclass
class Host:
    """Environment, PATH lookup, XDG directories and the debpak checkout."""

    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    checkout: Path | None = field(default_factory=_find_checkout)

    # ------------------------------------------------------------------ paths
    @property
    def home(self) -> Path:
        return Path(self.env.get("HOME") or Path.home())

    def _xdg(self, var: str, default: str) -> Path:
        v = self.env.get(var)
        return Path(v) if v and os.path.isabs(v) else self.home / default

    @property
    def data_home(self) -> Path:
        return self._xdg("XDG_DATA_HOME", ".local/share")

    @property
    def config_home(self) -> Path:
        return self._xdg("XDG_CONFIG_HOME", ".config")

    @property
    def state_home(self) -> Path:
        return self._xdg("XDG_STATE_HOME", ".local/state")

    def expand(self, p: str) -> Path:
        if p.startswith("~/"):
            return self.home / p[2:]
        return Path(p)

    # ------------------------------------------------------------------ lookup
    def which(self, name: str) -> str | None:
        if os.sep in name:
            return name if os.access(name, os.X_OK) and os.path.isfile(name) else None
        return shutil.which(name, path=self.env.get("PATH", os.defpath))

    def flatpak_installed(self, app_id: str) -> bool:
        """True if a Flatpak app is installed per-user or system-wide."""
        dirs = [self.data_home / "flatpak/app", Path(self.env.get("APPBRIDGE_FLATPAK_SYSTEM_DIR", "/var/lib/flatpak/app"))]
        return any((d / app_id / "current").exists() for d in dirs)

    @property
    def desktop(self) -> str:
        """The running desktop, lower-case (kde, gnome, xfce, ...)."""
        return (self.env.get("XDG_CURRENT_DESKTOP") or self.env.get("DESKTOP_SESSION") or "").split(":")[0].lower()

    # ------------------------------------------------------------------ checkout
    def submodule_dir(self, name: str) -> Path | None:
        """third_party/<name> if it's checked out (has files), else None."""
        if not self.checkout:
            return None
        d = self.checkout / "third_party" / name
        return d if d.is_dir() and any(d.iterdir()) else None

    def submodule_repo(self, name: str) -> str:
        """owner/repo the checkout's .gitmodules points at (your fork, once forked)."""
        if self.checkout:
            cp = configparser.ConfigParser()
            try:
                cp.read(self.checkout / ".gitmodules")
            except configparser.Error:
                cp = None
            sec = f'submodule "third_party/{name}"'
            if cp and cp.has_section(sec):
                m = re.match(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", cp.get(sec, "url", fallback=""))
                if m:
                    return m.group(1)
        return DEFAULT_UPSTREAMS[name]
