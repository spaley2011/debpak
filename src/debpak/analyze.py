"""Package analysis: classify the app, find its entry point, and compute the
soname gap between what its ELF files need and what the runtime provides."""
from __future__ import annotations

import mmap
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .deb import DebPackage, resolve_in_root
from .elf import ElfError, ElfInfo, is_elf, max_version, read_elf
from .maintscripts import SCRIPTS, Finding, analyze_payload, analyze_scripts
from .runtime import RuntimeIndex

# Default runtime branches. Check https://flathub.org for newer ones and
# override with --runtime; these only drive the *suggestion*.
DEFAULT_RUNTIMES = {
    "freedesktop": "org.freedesktop.Platform//25.08",
    "gnome": "org.gnome.Platform//49",
    "kde6": "org.kde.Platform//6.9",
    "kde5": "org.kde.Platform//5.15-25.08",
}

# never bundle these: they must come from the runtime/host
NEVER_BUNDLE_PREFIXES = ("libc.so", "libm.so", "libpthread.so", "libdl.so", "librt.so", "libresolv.so",
                         "libutil.so", "libnsl.so", "libanl.so", "libBrokenLocale.so", "libnss_",
                         "ld-linux", "ld64.so", "libthread_db.so", "libmvec.so", "libcrypt.so.1")

BIN_DIRS = ("usr/bin", "bin", "usr/games", "usr/local/bin", "usr/sbin", "sbin")


@dataclass
class HardcodedPath:
    file: str
    path: str
    is_text: bool


@dataclass
class Analysis:
    pkg: DebPackage
    arch: str
    kind: str = "elf"
    kind_evidence: str = ""
    elfs: dict[str, ElfInfo] = field(default_factory=dict)          # rel path -> info
    foreign_arch: list[str] = field(default_factory=list)
    package_sonames: dict[str, str] = field(default_factory=dict)   # file name -> rel path of real file
    desktop_file: str | None = None
    desktop_exec_env: dict[str, str] = field(default_factory=dict)
    main_exec: str | None = None
    main_exec_is_script: bool = False
    main_exec_reason: str = ""
    hard_needed: set[str] = field(default_factory=set)
    soft_needed: set[str] = field(default_factory=set)
    missing_hard: set[str] = field(default_factory=set)
    missing_soft: set[str] = field(default_factory=set)
    never_bundle_missing: set[str] = field(default_factory=set)
    version_problems: list[str] = field(default_factory=list)
    max_glibc: str | None = None
    max_glibcxx: str | None = None
    findings: list[Finding] = field(default_factory=list)
    hardcoded: list[HardcodedPath] = field(default_factory=list)
    abs_rpath_dirs: set[str] = field(default_factory=set)
    runtime_suggestion: str = DEFAULT_RUNTIMES["freedesktop"]
    runtime: RuntimeIndex | None = None

    @property
    def root(self) -> Path:
        return self.pkg.root

    @property
    def blockers(self) -> list[str]:
        out = [str(f) for f in self.findings if f.category == "blocker"]
        if self.main_exec is None:
            out.append("could not determine the main executable (use --exec)")
        if self.never_bundle_missing:
            out.append("needs core system libraries the runtime lacks: " + ", ".join(sorted(self.never_bundle_missing)))
        out += [p for p in self.version_problems if "GLIBC_" in p]
        return out

    def all_symbols(self) -> set[str]:
        s: set[str] = set()
        for info in self.elfs.values():
            s |= info.undefined_symbols
        return s


def _walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            yield Path(dirpath) / fn
        for d in dirnames:
            p = Path(dirpath) / d
            if p.is_symlink():
                yield p


def _rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


def is_never_bundle(soname: str) -> bool:
    return soname.startswith(NEVER_BUNDLE_PREFIXES)


def find_desktop_files(root: Path) -> list[str]:
    d = root / "usr/share/applications"
    if not d.is_dir():
        return []
    return sorted(_rel(root, p) for p in d.glob("*.desktop"))


def parse_exec(exec_line: str) -> tuple[dict[str, str], str | None, list[str]]:
    """Split a desktop Exec= value into (env vars, program, args)."""
    try:
        tokens = shlex.split(exec_line)
    except ValueError:
        tokens = exec_line.split()
    env: dict[str, str] = {}
    if tokens and tokens[0] == "env":
        tokens = tokens[1:]
    while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
        k, _, v = tokens.pop(0).partition("=")
        env[k] = v
    if not tokens:
        return env, None, []
    return env, tokens[0], tokens[1:]


def desktop_entry_value(text: str, key: str) -> str | None:
    in_entry = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_entry = s == "[Desktop Entry]"
            continue
        if in_entry and s.startswith(key + "="):
            return s[len(key) + 1:]
    return None


def locate_program(root: Path, prog: str) -> str | None:
    if prog.startswith("/"):
        r = resolve_in_root(root, prog)
        return _rel(root.resolve(), r) if r and r.is_file() else None
    for d in BIN_DIRS:
        r = resolve_in_root(root, f"{d}/{prog}")
        if r and r.is_file():
            return _rel(root.resolve(), r)
    return None


def _is_script(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def classify(root: Path, external_needed: set[str], names: set[str]) -> tuple[str, str]:
    if "chrome-sandbox" in names or (root / "resources/app.asar").exists() or any(
            n in names for n in ("v8_context_snapshot.bin", "snapshot_blob.bin")) and "resources.pak" in names:
        return "electron", "Chromium/Electron runtime files present"
    has = lambda *p: next((s for s in sorted(external_needed) if s.startswith(p)), None)  # noqa: E731
    if (s := has("libQt6")):
        return "qt6", f"links system {s}"
    if (s := has("libQt5")):
        return "qt5", f"links system {s}"
    if (s := has("libgtk-4.so", "libadwaita-1.so")):
        return "gtk4", f"links {s}"
    if (s := has("libgtk-3.so")):
        return "gtk3", f"links {s}"
    if any(n.endswith(".jar") for n in names):
        return "java", ".jar files present"
    return "elf", "plain ELF application"


