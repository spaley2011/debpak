"""A Mono runtime for .NET Framework apps built to run on Linux under Mono.

Some apps ship for Linux as their Windows .exe and .dll assemblies with a
start script that runs `mono EmuHawk.exe` (BizHawk's EmuHawkMono.sh). On the
desktop Mono comes from the distribution; the Freedesktop runtime has none,
so the script stopped at "mono: not found". Flathub's answer is the Mono SDK
extension, whose install.sh copies mono and the class libraries the app names
into /app at build time; debpak names every one, since which ones an app
loads is only known when it runs. A Windows Forms or System.Drawing app also
needs libgdiplus, which neither the runtime nor the extension has, so it is
added as a library the app loads, and comes from Ubuntu like any other.
"""
from __future__ import annotations

import re
from pathlib import Path

EXTENSION = "org.freedesktop.Sdk.Extension.mono6"
SDK_DIR = "/usr/lib/sdk/mono6"
MAX_ASSEMBLIES = 200
# `mono Foo.exe`, `exec mono "$dir/Foo.exe"`, `mono-sgen ...`, `$MONO ...` aside
RUNS_MONO = re.compile(r"(?m)(?:^|[\s;&|(`\"'])(?:exec\s+)?mono(?:-sgen)?(?:\s+--?[\w-]+(?:=\S+)?)*\s+\S*\.exe\b")
GDIPLUS_NAMESPACES = ("System.Drawing", "System.Windows.Forms")


def _assemblies(root: Path, limit: int = MAX_ASSEMBLIES) -> list[Path]:
    """Return the .exe and .dll files in root that are .NET assemblies."""
    candidates = sorted(p for p in root.rglob("*") if p.suffix.lower() in (".exe", ".dll"))[:max(limit, 0)]
    return [p for p in candidates if _is_assembly(p)]


def _is_assembly(p: Path) -> bool:
    """Return whether a file (a regular file, not a link) is a .NET assembly."""
    from .pe import PeError, read_pe
    if p.is_symlink() or not p.is_file():
        return False
    try:
        return read_pe(p).is_dotnet
    except (PeError, OSError, ValueError):
        return False


def bundled_mono(elf_paths) -> str | None:
    """Return the app's own mono program (bin/mono, an ELF file), or None."""
    for rel in sorted(elf_paths):
        if Path(rel).name in ("mono", "mono-sgen"):
            return rel
    return None


def needs_runtime(root: Path, elf_paths, main_exec: str | None) -> bool:
    """True if the app's entry point runs a .NET assembly with mono and the app has no mono of its own.

    The entry point is a script that runs `mono Something.exe`, or the .exe itself
    (given with --exec).
    """
    if not main_exec or bundled_mono(elf_paths):
        return False
    p = root / main_exec
    try:
        with open(p, "rb") as f:
            head = f.read(2)
    except OSError:
        return False
    if head == b"MZ":
        from .pe import PeError, read_pe
        try:
            return read_pe(p).is_dotnet
        except (PeError, OSError, ValueError):
            return False
    if head != b"#!":
        return False
    try:
        text = p.read_text("utf-8", "replace")
    except OSError:
        return False
    return bool(RUNS_MONO.search(text))


def needs_gdiplus(root: Path) -> bool:
    """True if one of the app's assemblies uses Windows Forms or System.Drawing, which load libgdiplus."""
    from .pe import dotnet_type_refs
    return any(ns.startswith(GDIPLUS_NAMESPACES) for a in _assemblies(root) for ns, _name in dotnet_type_refs(a))


def setup(root: Path) -> dict:
    """Return what the build needs: {"extension", "commands", "env", "libraries"}."""
    return {
        "extension": EXTENSION,
        "commands": [
            # every class library the extension has: install.sh copies a base set and the ones named
            f"{SDK_DIR}/install.sh $(ls {SDK_DIR}/lib/mono/gac)",
        ],
        "env": {},
        "libraries": ["libgdiplus.so.0"] if needs_gdiplus(root) else [],
    }
