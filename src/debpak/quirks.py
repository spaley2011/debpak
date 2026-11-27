"""App-specific settings: convert options for one app that no general rule gives it.

debpak's rules are meant to fit every app, and a fix for one app is a general
rule where one can be found. Where none can (an app that needs a program
picked by hand, an environment variable only it reads, a winetricks verb only
it wants), its settings go here rather than into the general code: each entry
matches the package's file name and adds convert options, the same ones a
user would type, ahead of the user's own, which still win. `convert
--no-quirks` leaves them out.
"""
from __future__ import annotations

import re
from pathlib import Path

# (file-name pattern, convert options, why): the pattern is matched against the package's file name
# (re.search, case ignored), e.g. r"^OmaWrite.*\.exe$"; why says what the options fix, naming the app
QUIRKS: list[tuple[str, list[str], str]] = [
    (r"^AuthenticatorChooser\b.*\.(?:zip|exe)$", ["--background"],
     "AuthenticatorChooser is a background program with no window: it waits for Windows Security's FIDO "
     "dialogs and picks the security key in them, so running on without a window is what it does"),
    # PrazyCron edits the user's crontab and asks systemd about cron's service and timers; in a Flatpak
    # neither command is there, and its first start showed "[Errno 2] No such file or directory:
    # 'crontab'" in an error box. What it manages is the host's, so its commands run there
    (r"^prazycron_.*\.deb$",
     ["--host-command", "crontab", "--host-command", "systemctl", "--host-command", "systemd-analyze",
      "--host-command", "pkexec"],
     "PrazyCron is a front end to the host's cron and systemd"),
    (r"^ibm-aspera-connect_.*\.msi$", ["--background"],
     "IBM Aspera Connect is a helper web pages talk to: it starts its local server (http://127.0.0.1:33003) and "
     "waits, and opens its window only when a page starts a transfer"),
    (r"^Munt-[\d.]+-x64-linux\.tar\.gz$", ["--exec", "/opt/munt/Munt-daemon"],
     "Munt's (Gulden's) Linux tarball holds only its node, Munt-daemon, and two tools for it: Munt-cli, "
     "which talks to a running node, and Munt-tx, which edits a transaction it's given. Picked by size "
     "after the daemon and the -cli, Munt-tx said \"Error: too few parameters\" and crashed with no "
     "arguments; the node is what a user runs"),
]


def for_package(package: str) -> list[tuple[list[str], str]]:
    """Return the (options, why) of every entry whose pattern matches the package's file name."""
    name = Path(package).name
    return [(list(opts), why) for pat, opts, why in QUIRKS if re.search(pat, name, re.I)]
