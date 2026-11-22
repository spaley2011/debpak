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
    """An absolute install path found inside a file of the package.

    Attributes:
        file: The file the path was found in, relative to the package root.
        path: The path as it appears in the file, such as /opt/Vendor/lib.
        is_text: True for a script, whose paths debpak can rewrite; False for an
            ELF binary, where it can only report them.
    """
    file: str
    path: str
    is_text: bool


@dataclass
class Analysis:
    """Everything debpak learned about one package, for the report and for staging.

    Attributes:
        kind: The app's toolkit class: electron, qt6, qt5, gtk4, gtk3, java or elf.
        elfs: Every ELF file for the target architecture, by path relative to the
            package root.
        package_sonames: Library names the package provides itself, mapped to the
            real file that provides each one.
        main_exec: The program the Flatpak should start, relative to the root, or
            None if none could be found.
        hard_needed: Sonames that the executables need, directly or through the
            package's own libraries. Missing ones stop the app from starting.
        soft_needed: Sonames that only files outside that closure need, which in
            practice means plugins.
        missing_hard, missing_soft: The sonames above that the runtime lacks.
            Both stay empty when no runtime was given.
        never_bundle_missing: Missing core glibc libraries, which debpak must
            never copy into the bundle.
        version_problems: One line per symbol version that no provider defines.
        findings: Results of the maintainer-script and payload checks.
    """
    pkg: DebPackage
    arch: str
    kind: str = "elf"
    kind_evidence: str = ""
    elfs: dict[str, ElfInfo] = field(default_factory=dict)
    foreign_arch: list[str] = field(default_factory=list)
    package_sonames: dict[str, str] = field(default_factory=dict)
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
        """Return the problems that stop debpak from writing a manifest."""
        out = [str(f) for f in self.findings if f.category == "blocker"]
        if self.main_exec is None:
            out.append("could not determine the main executable (use --exec)")
        if self.never_bundle_missing:
            out.append("needs core system libraries the runtime lacks: " + ", ".join(sorted(self.never_bundle_missing)))
        out += [p for p in self.version_problems if "GLIBC_" in p]
        return out

    def all_symbols(self) -> set[str]:
        """Return the undefined dynamic symbols of every ELF file, for permission inference."""
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
    """Return True for core glibc libraries, which must come from the runtime."""
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
    """Return the value of key in the [Desktop Entry] group of a .desktop file, or None."""
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
    """Find the file a command runs inside the package.

    Args:
        root: The extracted package.
        prog: An absolute path such as /opt/Vendor/app, or a command name looked
            up in the usual bin directories.

    Returns:
        The file's path relative to root, following symlinks inside the package,
        or None if the package doesn't contain it.
    """
    if prog.startswith("/"):
        r = resolve_in_root(root, prog)
        return _rel(root.resolve(), r) if r and r.is_file() else None
    for d in BIN_DIRS:
        r = resolve_in_root(root, f"{d}/{prog}")
        if r and r.is_file():
            return _rel(root.resolve(), r)
    return None


ELECTRON_HELPERS = {"chrome-sandbox", "chrome_crashpad_handler", "crashpad_handler"}


def electron_binary(root: Path, elfs: dict, script: str) -> str | None:
    """Find the Electron executable a launcher script starts.

    It sits next to resources/app.asar or chrome-sandbox. When there are several
    executables there, the one the script names wins, then the largest.
    """
    dirs = {Path(r).parent for r in elfs if Path(r).name in ELECTRON_HELPERS}
    dirs |= {p.parent.parent.relative_to(root) for p in root.rglob("resources/app.asar")}
    cands = [r for r, i in elfs.items() if i.is_executable and Path(r).parent in dirs
             and Path(r).name not in ELECTRON_HELPERS and not Path(r).name.endswith(".so")]
    if not cands:
        return None
    try:
        text = (root / script).read_text("utf-8", "replace")
    except OSError:
        text = ""
    return max(cands, key=lambda r: (bool(re.search(rf"(^|[/\s\"']){re.escape(Path(r).name)}($|[\s\"'])", text, re.M)),
                                     (root / r).stat().st_size))


def _is_script(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def classify(root: Path, external_needed: set[str], names: set[str]) -> tuple[str, str]:
    """Classify the app by toolkit from the libraries it links and the files it ships.

    Returns:
        A (kind, evidence) tuple, such as ("qt6", "links system libQt6Core.so.6").
    """
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


def suggest_runtime(kind: str) -> str:
    """Return the default Flatpak runtime ref for an app kind from classify()."""
    return {"gtk4": DEFAULT_RUNTIMES["gnome"], "qt6": DEFAULT_RUNTIMES["kde6"],
            "qt5": DEFAULT_RUNTIMES["kde5"]}.get(kind, DEFAULT_RUNTIMES["freedesktop"])


def check_versions(elfs: dict[str, ElfInfo], providers: dict[str, set[str] | None]) -> list[str]:
    """Return human-readable problems where a required symbol version isn't provided."""
    problems = []
    for rel, info in sorted(elfs.items()):
        for lib, versions in sorted(info.verneed.items()):
            provided = providers.get(lib)
            if provided is None:
                continue
            lacking = sorted(v for v in versions if v not in provided)
            if lacking:
                problems.append(f"{rel} needs {lib} {', '.join(lacking)} (not provided)")
    return problems


def scan_hardcoded(root: Path, elfs: dict[str, ElfInfo], pkg_name: str, limit_per_file: int = 5) -> list[HardcodedPath]:
    """Find absolute install paths compiled into binaries or written into scripts.

    Only paths under the package's own install prefixes are looked for:
    /opt/<dir> for each folder the package puts in opt/, and
    /usr/share/<name> and /usr/lib/<name>.

    Args:
        root: The extracted package.
        elfs: The package's ELF files, from Analysis.elfs.
        pkg_name: The package name, for the /usr/share and /usr/lib prefixes.
        limit_per_file: Stop after this many distinct paths in one file.
    """
    prefixes = []
    opt = root / "opt"
    if opt.is_dir():
        prefixes += [f"/opt/{d.name}".encode() for d in opt.iterdir() if d.is_dir()]
    for base in ("usr/share", "usr/lib"):
        if (root / base / pkg_name).is_dir():
            prefixes.append(f"/{base}/{pkg_name}".encode())
    if not prefixes:
        return []
    pattern = re.compile(b"(?:" + b"|".join(re.escape(p) for p in prefixes) + rb")[^\x00\s\"'<>|;]*")
    out: list[HardcodedPath] = []
    candidates = [(rel, False) for rel in elfs]
    for p in _walk_files(root):
        if p.is_file() and not p.is_symlink() and _is_script(p):
            candidates.append((_rel(root, p), True))
    for rel, is_text in candidates:
        path = root / rel
        try:
            with open(path, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                if not size:
                    continue
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    found = []
                    for mt in pattern.finditer(m):
                        s = mt.group(0).decode("utf-8", "replace")
                        if s not in found:
                            found.append(s)
                        if len(found) >= limit_per_file:
                            break
        except OSError:
            continue
        out += [HardcodedPath(rel, s, is_text) for s in found]
    return out


def analyze(pkg: DebPackage, runtime: RuntimeIndex | None = None, exec_override: str | None = None) -> Analysis:
    """Analyze an extracted package against a runtime.

    Finds the entry point, works out which libraries the executables need, checks
    them and their symbol versions against the runtime, and runs the host
    integration checks. Without a runtime the result still has the entry point,
    the app kind and the needed libraries, but nothing is marked missing.

    Args:
        pkg: The extracted package (any format; see packages.open_package).
        runtime: The index of the target runtime, or None.
        exec_override: The program to use as the entry point instead of the
            one debpak would choose (the --exec option).

    Raises:
        ValueError: exec_override isn't in the package.
    """
    root = pkg.root
    arch = runtime.arch if runtime else (pkg.flatpak_arch or "x86_64")
    a = Analysis(pkg=pkg, arch=arch, runtime=runtime)

    names: set[str] = set()
    for p in _walk_files(root):
        names.add(p.name)
        if p.is_symlink():
            real = resolve_in_root(root, _rel(root, p))
            if real and ".so" in p.name and real.is_file() and is_elf(real):
                a.package_sonames.setdefault(p.name, _rel(root.resolve(), real))
            continue
        if not is_elf(p):
            continue
        rel = _rel(root, p)
        try:
            info = read_elf(p)
        except ElfError:
            continue
        if info.machine != arch:
            a.foreign_arch.append(rel)
            continue
        a.elfs[rel] = info
        if info.is_shared_library or ".so" in p.name:
            a.package_sonames.setdefault(p.name, rel)
            if info.soname:
                a.package_sonames.setdefault(info.soname, rel)
        for rp in info.rpath + info.runpath:
            if rp.startswith("/"):
                a.abs_rpath_dirs.add(rp)

    # --- entry point
    desktops = find_desktop_files(root)
    # a package can ship several .desktop files (helpers, URL handlers); the one
    # named after the package is most likely the main app, so try it first
    ordered = sorted(desktops, key=lambda d: (Path(d).stem != pkg.name, d))
    for d in ordered:
        text = (root / d).read_text("utf-8", "replace")
        exec_line = desktop_entry_value(text, "Exec")
        if not exec_line or desktop_entry_value(text, "NoDisplay") == "true":
            continue
        env, prog, _args = parse_exec(exec_line)
        loc = locate_program(root, prog) if prog else None
        if loc:
            a.desktop_file, a.desktop_exec_env = d, env
            a.main_exec, a.main_exec_reason = loc, f"Exec= in {d}"
            break
    if a.desktop_file is None and ordered:
        a.desktop_file = ordered[0]
    if exec_override:
        loc = locate_program(root, exec_override)
        if not loc:
            raise ValueError(f"--exec {exec_override} not found in package")
        a.main_exec, a.main_exec_reason = loc, "--exec"
    if a.main_exec is None:
        loc = locate_program(root, pkg.name)
        if loc:
            a.main_exec, a.main_exec_reason = loc, "binary named after the package"
    if a.main_exec is None:
        execs = [r for r, i in a.elfs.items() if i.is_executable]
        if execs:
            a.main_exec = max(execs, key=lambda r: (root / r).stat().st_size)
            a.main_exec_reason = "largest executable ELF (guess)"
    if a.main_exec:
        a.main_exec_is_script = _is_script(root / a.main_exec)

    # --- dependency closure: executables are roots, follow package libs
    by_soname_rel = a.package_sonames
    visited: set[str] = set()
    queue = [r for r, i in a.elfs.items() if i.is_executable]
    while queue:
        rel = queue.pop()
        if rel in visited:
            continue
        visited.add(rel)
        for n in a.elfs[rel].needed:
            if n in by_soname_rel:
                target = by_soname_rel[n]
                if target in a.elfs:
                    queue.append(target)
            else:
                a.hard_needed.add(n)
    # ELF files no executable reaches are plugins or loaded with dlopen(); what
    # they need is optional, since the app can start without it
    for rel, info in a.elfs.items():
        if rel not in visited:
            a.soft_needed |= {n for n in info.needed if n not in by_soname_rel}
    a.soft_needed -= a.hard_needed

    external = a.hard_needed | a.soft_needed
    a.kind, a.kind_evidence = classify(root, external, names)
    a.runtime_suggestion = suggest_runtime(a.kind)
    if a.kind == "electron" and a.main_exec and a.main_exec_is_script:
        # A launcher script (an AppImage's AppRun, a deb's /usr/bin wrapper) would start
        # Electron without zypak, and Chromium then dies on its sandbox inside Flatpak
        if (binary := electron_binary(root, a.elfs, a.main_exec)):
            a.main_exec_reason += f"; {a.main_exec} is a script, so the launcher runs the Electron binary it starts"
            a.main_exec, a.main_exec_is_script = binary, False

    all_verneed: dict[str, set[str]] = {}
    for info in a.elfs.values():
        for lib, vs in info.verneed.items():
            all_verneed.setdefault(lib, set()).update(vs)
    all_versions = set().union(*all_verneed.values()) if all_verneed else set()
    a.max_glibc = max_version(all_versions, "GLIBC")
    a.max_glibcxx = max_version(all_versions, "GLIBCXX")

    if runtime:
        def missing(sonames):
            return {s for s in sonames if not runtime.provides(s)}
        a.missing_hard = missing(a.hard_needed)
        a.missing_soft = missing(a.soft_needed)
        a.never_bundle_missing = {s for s in a.missing_hard | a.missing_soft if is_never_bundle(s)}
        providers: dict[str, set[str] | None] = {}
        for lib in all_verneed:
            if lib in a.package_sonames and a.package_sonames[lib] in a.elfs:
                providers[lib] = a.elfs[a.package_sonames[lib]].verdef
            elif runtime.provides(lib):
                providers[lib] = runtime.versions_of(lib)
        a.version_problems = check_versions(a.elfs, providers)

    scripts = {n: t for n in SCRIPTS if (t := pkg.maintainer_script(n))}
    a.findings = analyze_scripts(scripts) + analyze_payload(root)
    if a.foreign_arch:
        a.findings.append(Finding("warn", a.foreign_arch[0],
                                  f"{len(a.foreign_arch)} ELF file(s) for another architecture (ignored)"))
    a.hardcoded = scan_hardcoded(root, a.elfs, pkg.name)
    return a
