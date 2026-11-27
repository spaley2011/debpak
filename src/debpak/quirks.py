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
QUIRKS: list[tuple[str, list[str], str]] = []


def for_package(package: str) -> list[tuple[list[str], str]]:
    """Return the (options, why) of every entry whose pattern matches the package's file name."""
    name = Path(package).name
    return [(list(opts), why) for pat, opts, why in QUIRKS if re.search(pat, name, re.I)]
