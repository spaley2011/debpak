"""Running Flatpak's own tools when debpak itself runs as a Flatpak.

Inside a Flatpak sandbox (the io.github.spaley2011.debpak app) there's no
flatpak or flatpak-builder, and a sandbox can't build or install Flatpaks
anyway. Every command line debpak runs goes through command(), which puts
`flatpak-spawn --host` in front of the programs that have to run on the host;
that needs the --talk-name=org.freedesktop.Flatpak permission. Paths are
passed unchanged, so the files they name have to be ones the host sees at the
same path, which holds for anything under the home folder (--filesystem=home).
"""
from __future__ import annotations

import os
import shutil
import subprocess

# programs that only work on the host: flatpak and flatpak-builder install into
# the user's Flatpak installation, gpg signs with the user's own keys and agent,
# and xvfb-run gives a Windows installer under Wine a display (wineinstall.py)
HOST_PROGRAMS = frozenset({"flatpak", "flatpak-builder", "gpg", "xvfb-run", "xdotool"})

FLATPAK_INFO = "/.flatpak-info"

_found: dict[str, str | None] = {}


def in_flatpak() -> bool:
    """Return whether debpak is running inside a Flatpak sandbox."""
    return os.path.exists(FLATPAK_INFO)


def command(argv: list[str]) -> list[str]:
    """Return argv as it has to be run: through `flatpak-spawn --host` for a host program in a Flatpak.

    argv[0] may be a bare name or a path; on the host it's run by name, since
    a path found in the sandbox needn't exist there.
    """
    if not argv or not in_flatpak():
        return list(argv)
    name = os.path.basename(argv[0])
    if name not in HOST_PROGRAMS:
        return list(argv)
    return ["flatpak-spawn", "--host", name, *argv[1:]]


def which(name: str) -> str | None:
    """Like shutil.which, but a host program in a Flatpak is looked for on the host.

    Returns the name itself for a host program the host has (command() runs it
    by name), else None.
    """
    if not (in_flatpak() and name in HOST_PROGRAMS):
        return shutil.which(name)
    if name not in _found:
        try:
            r = subprocess.run(["flatpak-spawn", "--host", "sh", "-c", 'command -v "$1"', "sh", name],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            _found[name] = name if r.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            _found[name] = None
    return _found[name]


def data_home() -> str:
    """Return the host's XDG data folder, where its per-user Flatpak installation lives.

    In a Flatpak, XDG_DATA_HOME is the app's own folder under ~/.var/app;
    Flatpak passes the host's as HOST_XDG_DATA_HOME.
    """
    if in_flatpak():
        return os.environ.get("HOST_XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")


def sees(path) -> bool:
    """Return whether a host program would find path where debpak does: always outside a Flatpak, else under home."""
    if not in_flatpak():
        return True
    home = os.path.realpath(os.path.expanduser("~"))
    return os.path.realpath(path).startswith(home.rstrip("/") + "/")
