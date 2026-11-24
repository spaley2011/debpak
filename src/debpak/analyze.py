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
from .elf import ElfError, ElfInfo, is_elf, is_sharun, max_version, read_elf
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

# never bundle these: they must come from the runtime/host. libcrypt.so.1 isn't one: it
# comes from libxcrypt now, which needs nothing but libc, and the runtime has only
# libcrypt.so.2, so a program that links it gets Ubuntu's libcrypt1.
NEVER_BUNDLE_PREFIXES = ("libc.so", "libm.so", "libpthread.so", "libdl.so", "librt.so", "libresolv.so",
                         "libutil.so", "libnsl.so", "libanl.so", "libBrokenLocale.so", "libnss_",
                         "ld-linux", "ld64.so", "libthread_db.so", "libmvec.so")

BIN_DIRS = ("usr/bin", "bin", "usr/games", "usr/local/bin", "usr/sbin", "sbin")

# Kinds that bundle Chromium: they run under zypak with the Electron BaseApp
CHROMIUM_KINDS = ("electron", "cef")

# Libraries a program may dlopen() for its window and GPU (winit, wgpu, SDL, GLFW), or
# to reach the network without linking an HTTP or TLS library
DLOPEN_PATTERN = re.compile(rb"lib(?:X11|X11-xcb|xcb|wayland-client|wayland-egl|EGL|GLX|GL|vulkan"
                            rb"|curl(?:-gnutls|-nss)?|soup-[23]\.[0-9]|ssl|gnutls|nss3)\.so(?:\.[0-9]+)*")


@dataclass
class HardcodedPath:
    """An absolute install path found inside a file of the package.

    Attributes:
        file: The file the path was found in, relative to the package root.
        path: The path as it appears in the file, such as /opt/Vendor/lib.
        is_text: True for a script, whose paths debpak can rewrite; False for an
            ELF binary, where it can only report them.
        prefix: The install prefix to rewrite, when the scan worked it out (a
            /usr path in a script, such as /usr/lib/beyondcompare); empty
            otherwise, and stage takes it from the path.
    """
    file: str
    path: str
    is_text: bool
    prefix: str = ""


@dataclass
class Analysis:
    """Everything debpak learned about one package, for the report and for staging.

    Attributes:
        kind: The app's toolkit class: electron, cef, qt6, qt5, gtk4, gtk3, java or elf.
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
        loaded_needed: The part of soft_needed that libraries in the package's own
            library folders need (see loaded_needs()). They're fetched like
            hard_needed, but the app isn't blocked when no source has them.
        missing_hard, missing_soft, missing_loaded: The sonames above that the
            runtime lacks. All stay empty when no runtime was given.
        never_bundle_missing: Missing core glibc libraries, which debpak must
            never copy into the bundle.
        version_problems: One line per symbol version that no provider defines.
        findings: Results of the maintainer-script and payload checks.
        bypassed_script: The launcher script the entry point was, when debpak
            starts the Chromium binary it runs instead.
        dlopened: Display, GPU and network libraries the entry point names in
            its data but doesn't link, so it loads them with dlopen() (winit,
            wgpu and SDL programs do). Only used to suggest permissions.
        desktop_exec_args: The arguments the menu entry's Exec= passes to the
            entry point (field codes like %U left out). The launcher passes them
            when it is started with none, as `flatpak run` starts it.
        bus_names: D-Bus names the app may claim on the session bus, with
            where each was found (see bus_names()).
        downloads_client: The name of the app whose Electron client the
            package's downloader fetches into the home folder at first start
            (Discord's updater_bootstrap), or "".
        home_skel: (folder, home folder) when the package ships first-run files
            for the user's home in usr/share/<name>/skel, which the program
            copies into ~/.<name> (Parsec: usr/share/parsec/skel, ~/.parsec).
            It looks for them at /usr/share, so the launcher copies them.
        host_spawner: The package's program that, finding /.flatpak-info, runs
            its commands on the host with flatpak-spawn --host (WezTerm opens
            every terminal pane that way), or "" (see host_spawner()).
        home_folder: The home folder (".minecraft") a program from HOME_FOLDERS
            keeps itself and its data in, or "".
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
    desktop_exec_args: list[str] = field(default_factory=list)
    main_exec: str | None = None
    main_exec_is_script: bool = False
    main_exec_reason: str = ""
    bypassed_script: str | None = None
    hard_needed: set[str] = field(default_factory=set)
    soft_needed: set[str] = field(default_factory=set)
    loaded_needed: set[str] = field(default_factory=set)
    missing_hard: set[str] = field(default_factory=set)
    missing_soft: set[str] = field(default_factory=set)
    missing_loaded: set[str] = field(default_factory=set)
    never_bundle_missing: set[str] = field(default_factory=set)
    version_problems: list[str] = field(default_factory=list)
    max_glibc: str | None = None
    max_glibcxx: str | None = None
    findings: list[Finding] = field(default_factory=list)
    hardcoded: list[HardcodedPath] = field(default_factory=list)
    dlopened: set[str] = field(default_factory=set)
    abs_rpath_dirs: set[str] = field(default_factory=set)
    bus_names: dict[str, str] = field(default_factory=dict)
    downloads_client: str = ""
    home_skel: tuple[str, str] | None = None
    host_spawner: str = ""
    home_folder: str = ""
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

    def gui_reason(self) -> str | None:
        """Return why the app is graphical judging by its .desktop file (not Terminal=true), or None."""
        if not self.desktop_file:
            return None
        text = (self.root / self.desktop_file).read_text("utf-8", "replace")
        if desktop_entry_value(text, "Terminal") == "true":
            return None
        return f"{Path(self.desktop_file).name} starts a graphical app"

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


def find_other_desktop_files(root: Path) -> list[str]:
    """Return .desktop files outside usr/share/applications, such as opt/Vendor/bin/app.desktop.

    Some packages keep theirs next to the program and have postinst copy it
    into place. Autostart entries under etc/ are left out.
    """
    out = []
    for p in _walk_files(root):
        rel = _rel(root, p)
        if p.name.endswith(".desktop") and p.is_file() and not rel.startswith(("etc/", "usr/share/applications/")):
            out.append(rel)
    return sorted(out)


def is_library_name(name: str) -> bool:
    """Return True for shared library file names: libfoo.so, libQt6Core.so.6, foo.so.1.2.

    Some libraries can be run (libc, libQt6Core print their version), so the
    ELF header alone doesn't tell them from programs.
    """
    return re.search(r"\.so(\.[0-9]+)*$", name) is not None


def _is_helper(rel: str, others: list[str]) -> bool:
    """Return True if another program in the same folder has a name this one extends,
    as CiscoCollabHostCef extends CiscoCollabHost and zap-helper extends zap."""
    p = Path(rel)
    return any(Path(o).parent == p.parent and Path(o).name != p.name and p.name.startswith(Path(o).name)
               for o in others)


# names of helper programs and command-line twins of an app (app-cli, app_helper, appd-daemon)
HELPER_NAME_RE = re.compile(r"[-_.](cli|cmd|helper|daemon|server|agent|updater)$", re.I)


def named_program(elfs: dict[str, ElfInfo], name: str) -> str | None:
    """Return the one program named name anywhere in the package (opt/kitty/bin/kitty), or None."""
    hits = [r for r, i in elfs.items() if i.is_executable and Path(r).name == name]
    return hits[0] if len(hits) == 1 else None


def guess_main_exec(root: Path, elfs: dict[str, ElfInfo]) -> str | None:
    """Guess the entry point when nothing names it: the largest program.

    Libraries, Chromium helpers and helper programs named after another program
    are skipped. Files with the executable bit set come first, and programs
    named like helpers or command-line tools (HELPER_NAME_RE) last.
    """
    cands = [r for r, i in elfs.items() if i.is_executable and not is_library_name(Path(r).name)
             and not _is_electron_helper(Path(r).name)]
    cands = [r for r in cands if not _is_helper(r, cands)] or cands
    if not cands:
        return None
    return max(cands, key=lambda r: (os.access(root / r, os.X_OK), not HELPER_NAME_RE.search(Path(r).name),
                                     (root / r).stat().st_size))


def lib_family(soname: str) -> str:
    """Return the name a library shares with its other versions and siblings: libQt6Network.so.6 -> libqt."""
    m = re.match(r"lib[a-z]+", soname, re.I)
    return (m.group(0) if m else soname).lower()


def loaded_needs(elfs: dict[str, ElfInfo], reached: set[str], package_sonames: dict[str, str]) -> set[str]:
    """Return what the libraries no program links, but that sit beside ones they do, need from outside.

    Nothing links Webex's UI library, libspark-windows-desktop-ui.so: its loader
    opens it with dlopen(), by a name built at run time. It sits in opt/Webex/lib
    with the Qt the programs link, and needs libcrypt.so.1 (through Heimdal's
    libkrb5), which the runtime lacks, so the app exited at once and showed
    nothing. A library in a folder of the programs' own libraries is part of the
    app, whereas plugins live in folders of their own (Zoom's Qt/plugins).

    A library of a family the package ships itself (libQt6WaylandClient.so.6
    beside the vendor's libQt6Core.so.6, libcrypto.so.1.1 beside libcrypto.so.3)
    is left out: a distribution's build of it needn't match the vendor's.
    """
    lib_dirs = {str(Path(r).parent) for r in reached if not elfs[r].is_executable}
    shipped = {lib_family(s) for s in package_sonames}
    out: set[str] = set()
    for rel, info in elfs.items():
        if rel in reached or info.is_executable or str(Path(rel).parent) not in lib_dirs:
            continue
        out |= {n for n in info.needed
                if n not in package_sonames and lib_family(n) not in shipped and not is_never_bundle(n)}
    return out


def scan_dlopened(path: Path) -> set[str]:
    """Return the display, GPU and network libraries a program names in its data (see DLOPEN_PATTERN)."""
    try:
        with open(path, "rb") as f:
            if not os.fstat(f.fileno()).st_size:
                return set()
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                return {mt.group(0).decode() for mt in DLOPEN_PATTERN.finditer(m)}
    except OSError:
        return set()


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


# a desktop Exec= field code (%f, %U, %i, ...), alone or inside an argument (--file=%f)
FIELD_CODE = re.compile(r"%[a-zA-Z]")


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


def locate_by_name(root: Path, prog: str, near: str) -> str | None:
    """Find a program a .desktop file names at a path the package doesn't ship.

    Some packages have postinst make the link the menu entry runs (ln -s
    /opt/Vendor/app /usr/bin/app). The file is then looked for by name: in the
    .desktop file's own folder, else anywhere in the package if only one
    program has that name.

    Args:
        root: The extracted package.
        prog: The program as Exec= names it.
        near: The .desktop file, relative to root.
    """
    name = Path(prog).name
    if not name or name in (".", ".."):
        return None
    beside = resolve_in_root(root, f"{Path(near).parent.as_posix()}/{name}")
    if beside and beside.is_file() and os.access(beside, os.X_OK):
        return _rel(root.resolve(), beside)
    hits = [p for p in _walk_files(root) if p.name == name and p.is_file() and os.access(p, os.X_OK)]
    real = {r for p in hits if (r := resolve_in_root(root, _rel(root, p))) and r.is_file()}
    return _rel(root.resolve(), real.pop()) if len(real) == 1 else None


# Chromium's helper programs beside its main binary. Branded builds rename them:
# Edge ships msedge-sandbox and msedge_crashpad_handler.
ELECTRON_HELPER_RE = re.compile(r"(^|[-_])(sandbox|crashpad_handler)$")


def _is_electron_helper(name: str) -> bool:
    return bool(ELECTRON_HELPER_RE.search(name))


def sandbox_filename(root: Path, main_exec: str) -> str | None:
    """Return the name of a branded Chromium's setuid sandbox helper, such as Edge's
    msedge-sandbox, or None for the usual chrome-sandbox.

    zypak only stands in for the helper under the name it is told (ZYPAK_SANDBOX_FILENAME,
    chrome-sandbox by default); under any other name Chromium finds the real file, not
    setuid root, and aborts. A name counts when the file sits beside the program and the
    program has the name compiled in.
    """
    exe = resolve_in_root(root, main_exec) or root / main_exec
    if (exe.parent / "chrome-sandbox").exists():
        return None
    names = sorted(p.name for p in exe.parent.glob("*-sandbox") if p.is_file())
    if not names:
        return None
    try:
        with open(exe, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            for name in names:
                if m.find(name.encode() + b"\0") != -1:
                    return name
    except (OSError, ValueError):
        pass
    return None


def electron_binary(root: Path, elfs: dict, script: str) -> str | None:
    """Find the Electron (or Chromium) executable a launcher script starts.

    It sits next to resources/app.asar, chrome-sandbox (or a branded
    msedge-sandbox), or Chromium's V8 snapshot and resources.pak. When there
    are several executables there, the one the script names wins, then the largest.
    Copies of sharun's launcher left there (see packages.unwrap_sharun) aren't
    candidates, and a compiled launcher names nothing.
    """
    dirs = {Path(r).parent for r in elfs if _is_electron_helper(Path(r).name)}
    dirs |= {p.parent.parent.relative_to(root) for p in root.rglob("resources/app.asar")}
    for name in ("v8_context_snapshot.bin", "snapshot_blob.bin"):
        dirs |= {p.parent.relative_to(root) for p in root.rglob(name) if (p.parent / "resources.pak").exists()}
    cands = [r for r, i in elfs.items() if i.is_executable and Path(r).parent in dirs
             and not _is_electron_helper(Path(r).name) and not is_library_name(Path(r).name)
             and not is_sharun(root / r)]
    if not cands:
        return None
    try:
        text = (root / script).read_text("utf-8", "replace") if _is_script(root / script) else ""
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
    if "libcef.so" in names:
        # Chromium Embedded Framework (Webex, Spotify): Chromium without Electron,
        # its main program is the vendor's own (often a Qt or GTK app)
        return "cef", "Chromium Embedded Framework (libcef.so) present"
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


# Libraries only the GNOME runtime has: WebKitGTK, which Tauri and Wails apps link
GNOME_ONLY_PREFIXES = ("libwebkit2gtk-4.", "libjavascriptcoregtk-4.", "libwebkitgtk-6.", "libjavascriptcoregtk-6.")


def suggest_runtime(kind: str, needed: set[str] = frozenset()) -> str:
    """Return the default Flatpak runtime ref for an app kind from classify().

    Args:
        kind: The app kind.
        needed: Libraries the programs need; WebKitGTK picks the GNOME runtime,
            the only one that has it (bundling WebKit isn't practical).
    """
    if kind not in CHROMIUM_KINDS and any(s.startswith(GNOME_ONLY_PREFIXES) for s in needed):
        return DEFAULT_RUNTIMES["gnome"]
    return {"gtk4": DEFAULT_RUNTIMES["gnome"], "qt6": DEFAULT_RUNTIMES["kde6"],
            "qt5": DEFAULT_RUNTIMES["kde5"]}.get(kind, DEFAULT_RUNTIMES["freedesktop"])


def needed_path(root: Path, rel: str, name: str) -> str | None:
    """Return the package file a path-style DT_NEEDED entry names, or None.

    The dynamic linker loads a NEEDED entry with a slash by path, expanding
    $ORIGIN to the folder of the file that needs it: python-build-standalone's
    bin/python3 needs $ORIGIN/../lib/libpython3.11.so.1.0.

    Args:
        root: The extracted package.
        rel: The ELF file with the entry, relative to root.
        name: The entry.
    """
    if "/" not in name:
        return None
    path = name.replace("${ORIGIN}", "$ORIGIN")
    if path.startswith("$ORIGIN/") or path == "$ORIGIN":
        path = os.path.normpath(os.path.join(os.path.dirname(rel), path[len("$ORIGIN/"):]))
        if path.startswith(".."):
            return None
    elif not path.startswith("/"):
        return None             # relative to the working directory; can't tell
    real = resolve_in_root(root, path)
    if real is None or not real.is_file():
        return None
    return _rel(root.resolve(), real)


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


# Folders under /usr that many packages share: a path there names the package's own file only
# one level further down (/usr/share/icons/... is the icon theme, /usr/lib/beyondcompare is the app's)
SHARED_USR_DIRS = {
    "applications", "icons", "pixmaps", "doc", "man", "info", "help", "mime", "locale", "metainfo",
    "appdata", "dbus-1", "glib-2.0", "fonts", "themes", "menu", "polkit-1", "bash-completion",
    "zsh", "fish", "systemd", "udev", "sounds", "licenses", "gtk-2.0", "gtk-3.0", "gtk-4.0",
    "gnome-shell", "kservices5", "kservices6", "knotifications5", "knotifications6", "plugins",
    "qt5", "qt6", "gstreamer-1.0", "gdk-pixbuf-2.0", "girepository-1.0", "pkgconfig", "cmake",
    "python3", "python3.12", "dist-packages", "site-packages", "perl5", "perl", "debug", "lintian",
    "X11", "xml", "mime-info", "application-registry", "desktop-directories", "thumbnailers",
    "jvm", "java", "games", "aclocal", "emacs", "vim", "xsessions", "wayland-sessions", "kf5", "kf6",
    "ca-certificates", "ssl", "tmpfiles.d", "sysusers.d", "binfmt.d", "environment.d", "modules-load.d",
} | {f"{arch}-linux-gnu" for arch in ("x86_64", "aarch64", "i386", "arm", "powerpc64le", "s390x",
                                         "riscv64")} | {"arm-linux-gnueabihf"}

# an absolute /usr path in a script, not part of a longer path
USR_PATH = re.compile(rb"(?<![A-Za-z0-9._/~$-])/usr(?:/[A-Za-z0-9._+-]+)+")


def package_usr_prefix(root: Path, path: str) -> str | None:
    """Return the part of a /usr path in a script that the package installs, or None.

    That is the folder or file one level below /usr/lib, /usr/share, /usr/bin
    and the like when the package ships it: /usr/lib/beyondcompare for
    /usr/lib/beyondcompare/BCompare, /usr/bin/app for /usr/bin/app. In a
    folder packages share (SHARED_USR_DIRS, such as /usr/lib/x86_64-linux-gnu)
    only a file of the package counts, and only the whole path. A path the
    package doesn't ship, such as /usr/bin/env, gives None, so a script keeps
    using the runtime's programs.
    """
    parts = path.strip("/").split("/")
    if parts[0] != "usr":
        return None
    k = 4 if len(parts) > 1 and parts[1] == "local" else 3
    if len(parts) < k:
        return None
    top = root.joinpath(*parts[:k])
    if parts[k - 1] not in SHARED_USR_DIRS:
        return "/" + "/".join(parts[:k]) if top.exists() or top.is_symlink() else None
    full = root.joinpath(*parts)
    return "/" + "/".join(parts) if len(parts) > k and (full.is_file() or full.is_symlink()) else None


def scan_hardcoded(root: Path, elfs: dict[str, ElfInfo], pkg_name: str, limit_per_file: int = 5) -> list[HardcodedPath]:
    """Find absolute install paths compiled into binaries or written into scripts.

    Only paths under the package's own install prefixes are looked for:
    /opt/<dir> for each folder the package puts in opt/, and
    /usr/share/<name> and /usr/lib/<name>. Scripts are also searched for any
    /usr path whose file the package ships (see package_usr_prefix): Beyond
    Compare's launcher sets BC_LIB=/usr/lib/beyondcompare and runs ldd on
    $BC_LIB/BCompare.

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
    pattern = re.compile(b"(?:" + b"|".join(re.escape(p) for p in prefixes) + rb")[^\x00\s\"'<>|;]*") \
        if prefixes else None
    out: list[HardcodedPath] = []
    candidates = [(rel, False) for rel in elfs]
    for p in _walk_files(root):
        if p.is_file() and not p.is_symlink() and _is_script(p):
            candidates.append((_rel(root, p), True))
    for rel, is_text in candidates:
        if pattern is None and not is_text:
            continue
        path = root / rel
        try:
            with open(path, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                if not size:
                    continue
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    found = []
                    for mt in pattern.finditer(m) if pattern else ():
                        s = mt.group(0).decode("utf-8", "replace")
                        if s not in found:
                            found.append(s)
                        if len(found) >= limit_per_file:
                            break
                    usr: dict[str, str] = {}
                    for mt in USR_PATH.finditer(m) if is_text else ():
                        s = mt.group(0).decode("utf-8", "replace")
                        if s in found or s in usr or not (prefix := package_usr_prefix(root, s)):
                            continue
                        usr[s] = prefix
                        if len(usr) >= limit_per_file:
                            break
        except OSError:
            continue
        out += [HardcodedPath(rel, s, is_text) for s in found]
        out += [HardcodedPath(rel, s, is_text, prefix) for s, prefix in usr.items()]
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
    # without any in usr/share/applications, one kept elsewhere counts if it runs
    # a program of the package
    others = [] if desktops else sorted(find_other_desktop_files(root),
                                        key=lambda d: (Path(d).stem.lower() != pkg.name.lower(), d))
    for d in ordered + others:
        text = (root / d).read_text("utf-8", "replace")
        exec_line = desktop_entry_value(text, "Exec")
        if not exec_line or desktop_entry_value(text, "NoDisplay") == "true":
            continue
        env, prog, args = parse_exec(exec_line)
        loc = locate_program(root, prog) if prog else None
        how = f"Exec= in {d}"
        if not loc and prog and (loc := locate_by_name(root, prog, d)):
            how = f"Exec= in {d} names {prog}, which the package doesn't ship; found by name"
        if loc:
            a.desktop_file, a.desktop_exec_env = d, env
            a.desktop_exec_args = [t for t in args if not FIELD_CODE.search(t)]
            a.main_exec, a.main_exec_reason = loc, how
            break
    if a.desktop_file is None and ordered:
        a.desktop_file = ordered[0]
    if exec_override:
        loc = locate_program(root, exec_override)
        if not loc:
            raise ValueError(f"--exec {exec_override} not found in package")
        if loc != a.main_exec:
            a.desktop_exec_args = []     # the menu entry's arguments are for another program
        a.main_exec, a.main_exec_reason = loc, "--exec"
    if a.main_exec is None:
        loc = locate_program(root, pkg.name) or named_program(a.elfs, pkg.name)
        if loc:
            a.main_exec, a.main_exec_reason = loc, "binary named after the package"
    if a.main_exec is None:
        guess = guess_main_exec(root, a.elfs)
        if guess:
            a.main_exec, a.main_exec_reason = guess, "largest executable ELF (guess)"
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
            target = by_soname_rel.get(n) or needed_path(root, rel, n)
            if target:
                if target in a.elfs:
                    queue.append(target)
            else:
                a.hard_needed.add(n)
    # ELF files no executable reaches are plugins or loaded with dlopen(); what
    # they need is optional, since the app can start without it
    for rel, info in a.elfs.items():
        if rel not in visited:
            a.soft_needed |= {n for n in info.needed if n not in by_soname_rel and not needed_path(root, rel, n)}
    a.soft_needed -= a.hard_needed
    a.loaded_needed = loaded_needs(a.elfs, visited, a.package_sonames) & a.soft_needed

    external = a.hard_needed | a.soft_needed
    a.kind, a.kind_evidence = classify(root, external, names)
    downloaders = _downloaders(a.elfs) if a.kind not in CHROMIUM_KINDS else {}
    if downloaders:
        rel, (app, _flathub) = sorted(downloaders.items())[0]
        a.downloads_client = app
        a.kind, a.kind_evidence = "electron", f"{rel} downloads the {app} client (Electron) and starts it"
        if a.main_exec != rel and (a.main_exec_is_script or not a.main_exec):
            # zypak needs the program itself, not the package's wrapper script (Discord's .deb)
            a.main_exec_reason = f"{rel} is the program {a.main_exec or 'the menu entry'} starts"
            a.bypassed_script = a.main_exec or ""
            a.main_exec, a.main_exec_is_script = rel, False
            a.desktop_exec_args = []            # they were the script's
    a.runtime_suggestion = suggest_runtime(a.kind, a.hard_needed)
    sharun = bool(a.main_exec) and not a.main_exec_is_script and is_sharun(root / a.main_exec)
    if a.kind in CHROMIUM_KINDS and a.main_exec and (a.main_exec_is_script or sharun):
        # A launcher script (an AppImage's AppRun, a deb's /usr/bin wrapper) would start
        # Electron without zypak, and Chromium then dies on its sandbox inside Flatpak.
        # sharun's compiled AppRun is such a launcher too: it runs AppRun.sh and its hooks.
        if (binary := electron_binary(root, a.elfs, a.main_exec)):
            what = "sharun's launcher" if sharun else "a script"
            a.main_exec_reason += f"; {a.main_exec} is {what}, so the launcher runs the Electron binary it starts"
            a.bypassed_script = a.main_exec
            a.main_exec, a.main_exec_is_script = binary, False
    if a.kind not in CHROMIUM_KINDS and a.main_exec in a.elfs:
        a.dlopened = scan_dlopened(root / a.main_exec) - set(a.elfs[a.main_exec].needed)

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
        a.missing_loaded = missing(a.loaded_needed)
        # only a program's own needs stop it; a plugin that wants a missing glibc library just won't load
        a.never_bundle_missing = {s for s in a.missing_hard if is_never_bundle(s)}
        providers: dict[str, set[str] | None] = {}
        for lib in all_verneed:
            if lib in a.package_sonames and a.package_sonames[lib] in a.elfs:
                providers[lib] = a.elfs[a.package_sonames[lib]].verdef
            elif runtime.provides(lib):
                providers[lib] = runtime.versions_of(lib)
        a.version_problems = check_versions(a.elfs, providers)

    scripts = {n: t for n in SCRIPTS if (t := pkg.maintainer_script(n))}
    a.findings = analyze_scripts(scripts) + analyze_payload(root)
    a.findings += [Finding(cat, where, detail) for cat, where, detail in getattr(pkg, "extra", {}).get("findings", [])]
    if a.foreign_arch:
        a.findings.append(Finding("warn", a.foreign_arch[0],
                                  f"{len(a.foreign_arch)} ELF file(s) for another architecture (ignored)"))
    for rel, (app, flathub) in downloaders.items():
        a.findings.append(Finding("warn", rel, (
            f"{app}'s package holds only its installer: at first start it downloads the {app} client "
            "(Electron) into the app's data folder and starts it. The launcher runs the installer under "
            "zypak, whose settings the client inherits, with ZYPAK_DISABLE_SANDBOX=1 so Chromium's "
            "helper processes can reach a client that isn't part of the Flatpak (they run in the app's "
            f"sandbox, not a stricter one of their own); {flathub} on Flathub ships the whole client")))
    a.hardcoded = scan_hardcoded(root, a.elfs, pkg.name)
    a.bus_names = bus_names(root)
    names = {pkg.name, Path(a.desktop_file).stem if a.desktop_file else ""}
    keys = {re.sub(r"[^a-z0-9]", "", n.lower()) for n in names} - {""}
    # the program itself, or when a script starts it (an AppImage's AppRun), the programs named like the app
    programs = [a.main_exec] if a.main_exec in a.elfs else sorted(
        r for r, i in a.elfs.items() if i.is_executable and re.sub(r"[^a-z0-9]", "", Path(r).name.lower()) in keys)
    if a.main_exec and a.main_exec not in a.elfs:
        # and the programs the script names (Raspberry Pi Imager's AppRun runs usr/bin/rpi-imager)
        try:
            text = (root / a.main_exec).read_text("utf-8", "replace")
        except OSError:
            text = ""
        programs += sorted(r for r, i in a.elfs.items() if i.is_executable and r not in programs
                           and re.search(rf"(^|[/\s\"']){re.escape(Path(r).name)}($|[\s\"'])", text, re.M))
    for prog in programs[:3]:
        for name in compiled_app_ids(root / prog, names):
            if not name.startswith(FOREIGN_BUS_PREFIXES):
                a.bus_names.setdefault(name, f"application ID compiled into {prog}")
    for name, why in getattr(pkg, "extra", {}).get("bus_names", {}).items():
        # declared by the package itself (a snap's mpris slot), so even an org.mpris. name is the app's own
        a.bus_names.setdefault(name, why)
    a.home_skel = find_home_skel(root, pkg.name)
    # every program, since an AppImage's AppRun may itself be a compiled launcher
    executables = sorted(r for r, i in a.elfs.items() if i.is_executable and not is_library_name(Path(r).name))
    if (needs := next((p for p in executables if needs_root(root, p)), "")):
        a.findings.append(Finding("blocker", needs, (
            "needs root: the program refuses to work unless it runs as root (it says so and asks for "
            "sudo or pkexec), and nothing in a Flatpak can run as root. Raspberry Pi Imager writes SD "
            "cards this way; Flathub's build of it only works because of a patch to its source")))
    a.host_spawner = host_spawner(root, a.elfs)
    if a.host_spawner:
        a.findings.append(Finding("warn", a.host_spawner, (
            "runs its commands on the host with flatpak-spawn --host when it finds itself in a Flatpak, "
            "so the Flatpak may talk to org.freedesktop.Flatpak, which lets it run any program outside "
            "the sandbox; Flathub's builds of such apps (terminals) do the same")))
    a.home_folder = HOME_FOLDERS.get(pkg.name, "")
    return a


# What a program that won't work without root tells its user (Raspberry Pi Imager: "You are not running
# as root. Please run with elevated privileges"), and how it then asks for root
ROOT_ONLY = re.compile(rb"(?i)not running as root|must be run as root|needs? to be run as root|"
                       rb"requires? root privileges")
ROOT_HOW = re.compile(rb"pkexec|\bsudo ")


def needs_root(root: Path, main_exec: str) -> str:
    """Return the program when it refuses to work without root, or "".

    It must both say it needs root and name pkexec or sudo: plenty of
    programs warn against running as root, which is the opposite.
    """
    if not main_exec:
        return ""
    try:
        data = (root / main_exec).read_bytes()
    except OSError:
        return ""
    return main_exec if ROOT_ONLY.search(data) and ROOT_HOW.search(data) else ""


# The test a program makes for being in a Flatpak, and the command it then runs things on the host with
FLATPAK_INFO = b"/.flatpak-info"
FLATPAK_SPAWN_HOST = re.compile(rb"flatpak-spawn[\x00\s\"']{0,8}--host")


def host_spawner(root: Path, elfs: dict[str, ElfInfo]) -> str:
    """Return the first of the package's programs that runs commands on the host from a Flatpak, or "".

    WezTerm checks for /.flatpak-info and then starts each pane's shell as
    `flatpak-spawn --host ...`. Without a way to the host, flatpak-spawn
    exits at once, the pane closes, and with it the only window: WezTerm
    exits 0 having shown nothing. Programs are checked, not libraries: a
    library that knows about Flatpak only uses its portals.
    """
    for rel in sorted(r for r, i in elfs.items() if i.is_executable and not is_library_name(Path(r).name)):
        try:
            with open(root / rel, "rb") as f:
                if not os.fstat(f.fileno()).st_size:
                    continue
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    if m.find(FLATPAK_INFO) >= 0 and FLATPAK_SPAWN_HOST.search(m):
                        return rel
        except OSError:
            continue
    return ""


def compiled_app_ids(program: Path, names: set[str]) -> list[str]:
    """Return reverse-DNS application IDs compiled into a program that carry its name.

    A Flutter or GTK program registers the ID its source sets (AppFlowy's
    io.appflowy.appflowy), which may be written nowhere else in the package.
    Only IDs with a part equal to the package's or desktop file's name count,
    so library IDs the program merely mentions are left out.
    """
    want = {re.sub(r"[^a-z0-9]", "", n.lower()) for n in names if n}
    want.discard("")
    if not want:
        return []
    try:
        data = program.read_bytes()
    except OSError:
        return []
    out = []
    for m in re.finditer(rb"(?<![\w.-])((?:com|org|io|net|dev|app|me|de)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\x00", data):
        name = m.group(1).decode("ascii", "replace")
        parts = {re.sub(r"[^a-z0-9]", "", x.lower()) for x in name.split(".")[1:]}
        if parts & want and name not in out and REVERSE_DNS.fullmatch(name):
            out.append(name)
    return out[:3]


def find_home_skel(root: Path, pkg_name: str) -> tuple[str, str] | None:
    """Return (usr/share/<name>/skel, .<name>) when the package ships first-run files there.

    Parsec copies usr/share/parsec/skel (appdata.json and its parsecd-*.so) into
    ~/.parsec at first start, and refuses to start ("Skel Missing or Broken")
    when it can't find them at /usr/share/parsec/skel, which in the Flatpak is
    /app/share/parsec/skel.
    """
    skel = f"usr/share/{pkg_name}/skel"
    d = root / skel
    if d.is_dir() and not d.is_symlink() and any(d.iterdir()):
        return skel, f".{pkg_name}"
    return None


# Programs that keep themselves and everything of the user's in a home folder whose
# name the package spells out nowhere (Minecraft's launcher builds "~/.minecraft" at
# run time): package name -> folder. Without --persist that folder is on the sandbox's
# throwaway home, so each start downloads the real launcher again (over 500 MB) and
# the sign-in, game versions and worlds are gone when it exits.
HOME_FOLDERS = {"minecraft-launcher": ".minecraft"}


# Programs that are only a downloader for the real app, which they install in the
# user's home folder at first start: name -> (app, its Flathub ID). Discord's
# .deb, .rpm and .tar.gz hold just this since 1.0.136 (May 2026).
DOWNLOADERS = {"updater_bootstrap": ("Discord", "com.discordapp.Discord")}


def _downloaders(elfs: dict[str, ElfInfo]) -> dict[str, tuple[str, str]]:
    """Return the DOWNLOADERS among the package's programs, by path."""
    return {r: DOWNLOADERS[Path(r).name] for r, i in elfs.items()
            if Path(r).name in DOWNLOADERS and i.is_executable}


# A reverse-DNS name, as D-Bus well-known names and Flatpak app IDs are written (three parts or more)
REVERSE_DNS = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*){2,}")
# Names of desktop-wide services an app must never take over on the user's session bus
FOREIGN_BUS_PREFIXES = ("org.freedesktop.", "org.gnome.SessionManager", "org.kde.StatusNotifier",
                        "org.kde.kded", "org.kde.plasmashell", "org.mpris.")
# Desktop file keys that name the app's D-Bus service (KDE's X-DBUS-ServiceName and the like)
DBUS_NAME_KEY = re.compile(r"X-[A-Za-z0-9-]*DBUS[A-Za-z0-9-]*Name", re.I)


def bus_names(root: Path) -> dict[str, str]:
    """Return the D-Bus names the app may claim on the session bus, with where each was found.

    GApplication registers the application ID, and KDBusService the
    reverse-DNS name KDE apps are known by; neither starts when the name is
    taken or not allowed, and inside a Flatpak only names under the Flatpak's
    own app ID are allowed (Xournal++: "Failed to register:
    GDBus.Error:org.freedesktop.DBus.Error.ServiceUnknown"; Nextcloud: "Failed
    to register name 'com.nextcloud.desktopclient.nextcloud'"). The app's own
    ID is written in several places, and each reverse-DNS one counts:

      - the name of a .desktop file (its desktop file ID), and its Icon=, since
        Flathub-style apps name both after the app ID;
      - an X-*DBUS*Name= key of a .desktop file (X-DBUS-ServiceName=);
      - the <id> of an AppStream file (usr/share/metainfo, usr/share/appdata);
      - Name= of a D-Bus service file (usr/share/dbus-1/services/*.service)
        whose Exec= runs a program of the package.

    Names of desktop-wide services (FOREIGN_BUS_PREFIXES, such as
    org.freedesktop.Notifications) are left out, so the app can't take them over.
    """
    found: dict[str, str] = {}

    def add(name: str | None, why: str) -> None:
        name = (name or "").strip()
        if name.endswith(".desktop"):
            name = name[:-len(".desktop")]
        if REVERSE_DNS.fullmatch(name) and not name.startswith(FOREIGN_BUS_PREFIXES):
            found.setdefault(name, why)

    for p in _walk_files(root):
        rel = _rel(root, p)
        if rel.startswith("etc/") or not p.is_file():
            continue
        parent = p.parent.name
        if p.suffix == ".desktop":
            add(p.stem, f"desktop file ID ({rel})")
            text = p.read_text("utf-8", "replace")
            add(desktop_entry_value(text, "Icon"), f"Icon= in {rel}")
            for line in text.splitlines():
                key, _, value = line.partition("=")
                if DBUS_NAME_KEY.fullmatch(key.strip()):
                    add(value, f"{key.strip()}= in {rel}")
        elif p.suffix == ".xml" and parent in ("metainfo", "appdata"):
            m = re.search(r"<id(?:\s[^>]*)?>\s*([^<\s]+)\s*</id>", p.read_text("utf-8", "replace"))
            if m:
                add(m.group(1), f"AppStream ID ({rel})")
        elif p.suffix == ".service" and rel.endswith(f"dbus-1/services/{p.name}"):
            # the same key=value format as a .desktop file, under [D-BUS Service]
            text = p.read_text("utf-8", "replace").replace("[D-BUS Service]", "[Desktop Entry]")
            prog = parse_exec(desktop_entry_value(text, "Exec") or "")[1]
            if prog and (locate_program(root, prog) or locate_by_name(root, prog, rel)):
                add(desktop_entry_value(text, "Name"), f"D-Bus service file {rel}")
    return dict(sorted(found.items()))
