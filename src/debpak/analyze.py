"""Package analysis: classify the app, find its entry point, and compute the
soname gap between what its ELF files need and what the runtime provides."""
from __future__ import annotations

import mmap
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from . import javart, monort, pydeps
from .deb import DebPackage, resolve_in_root
from .elf import ElfError, ElfInfo, is_elf, is_sharun, max_version, read_elf
from .maintscripts import (SCRIPTS, Finding, analyze_payload, analyze_scripts, fronts_daemon,
                           is_service_finding, system_services)
from .runtime import TRIPLETS, RuntimeIndex

# Default runtime branches. Check https://flathub.org for newer ones and
# override with --runtime; these only drive the *suggestion*.
DEFAULT_RUNTIMES = {
    "freedesktop": "org.freedesktop.Platform//25.08",
    "gnome": "org.gnome.Platform//49",
    "kde6": "org.kde.Platform//6.10",
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


# Libraries a program loads by name with dlopen() and can't start without, as (alternatives, the one
# to bundle when the runtime has none): Tauri apps with a tray icon (libappindicator-sys) panic at
# start ("Failed to load ayatana-appindicator3 or appindicator3 dynamic library") without one
DLOPEN_REQUIRED = [((b"libayatana-appindicator3.so.1", b"libappindicator3.so.1"), "libayatana-appindicator3.so.1")]


def dlopen_required(path: Path) -> set[str]:
    """Return the DLOPEN_REQUIRED alternatives a program names in its data, by the one to bundle."""
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return {bundle for names, bundle in DLOPEN_REQUIRED if any(m.find(n) != -1 for n in names)}
    except (OSError, ValueError):
        return set()


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
        bus_clients: Desktop services on D-Bus (BUS_SERVICES) that the entry
            point and its own libraries name in their data, which they may
            reach with a D-Bus library of their own (see scan_bus_clients).
        desktop_exec_args: The arguments the menu entry's Exec= passes to the
            entry point (field codes like %U left out). The launcher passes them
            when it is started with none, as `flatpak run` starts it.
        bus_names: D-Bus names the app may claim on the session bus, with
            where each was found (see bus_names()).
        bus_access: Finish-args for D-Bus services the package says the app
            talks to (--system-talk-name=org.freedesktop.fwupd), with why: a
            snap's plugs, see snap.bus_access.
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
        runtime_replaces: The package's libraries that the runtime's own copies
            stand in for, which the Flatpak leaves out: {path: the names it goes
            by} (a snap's Ubuntu libraries, see snap.runtime_copies).
    """
    pkg: DebPackage
    arch: str
    kind: str = "elf"
    kind_evidence: str = ""
    elfs: dict[str, ElfInfo] = field(default_factory=dict)
    foreign_arch: list[str] = field(default_factory=list)
    musl: list[str] = field(default_factory=list)           # ELF files built against musl libc
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
    libm_lowered: dict[str, set[str]] = field(default_factory=dict)   # see lower_libm_needs
    max_glibc: str | None = None
    max_glibcxx: str | None = None
    findings: list[Finding] = field(default_factory=list)
    hardcoded: list[HardcodedPath] = field(default_factory=list)
    dlopened: set[str] = field(default_factory=set)
    bus_clients: set[str] = field(default_factory=set)
    abs_rpath_dirs: set[str] = field(default_factory=set)
    bus_names: dict[str, str] = field(default_factory=dict)
    bus_access: dict[str, str] = field(default_factory=dict)
    downloads_client: str = ""
    home_skel: tuple[str, str] | None = None
    host_spawner: str = ""
    home_folder: str = ""
    java: dict | None = None
    mono: dict | None = None                # a Mono runtime from the SDK extension, see monort
    no_chromium_sandbox: bool = False       # --no-chromium-sandbox
    writable: bool = False                  # --writable
    chdir: str = ""                         # why the launcher starts the program in its own folder (--chdir)
    chdir_to: str = ""                      # the folder it starts in instead, when not the program's own
    fd_limit: int | None = None             # --fd-limit
    python_modules: list[str] = field(default_factory=list)   # python3-* packages a Python script needs
    python_site: Path | None = None         # where convert put them (see pydeps)
    python_version: str = ""                # the Python its own compiled modules need, when not the runtime's
    python_home: Path | None = None         # where convert put that Python (see pydeps.fetch_interpreter)
    typelib_dir: Path | None = None         # and the GObject typelibs among them
    autostart: bool = False                 # the program manages a login item in ~/.config/autostart
    signal_onstack: str = ""                # why signal handlers are made to run on the signal stack (go_webkit)
    xlib_copies: list[str] = field(default_factory=list)   # libraries with Xlib linked in (see xlib_copies)
    runtime_suggestion: str = DEFAULT_RUNTIMES["freedesktop"]
    runtime: RuntimeIndex | None = None
    runtime_replaces: dict[str, list[str]] = field(default_factory=dict)
    # the commands of SCRIPT_STUBS the launcher script runs, which the launcher stands in for (see stage.STUB_DIR)
    script_stubs: list[str] = field(default_factory=list)

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
        out += [p for p in self.version_problems if "GLIBC_" in p and not self.is_side_program(p.split(" needs ")[0])]
        return out

    def is_side_program(self, rel: str) -> bool:
        """Return True for a program of the package's other than its entry point, in another folder.

        OpenWhispr's .deb carries helper programs in resources/bin (qdrant, an echo
        canceller) built for glibc 2.43, newer than any runtime's: the app starts
        without them, so they don't refuse it; only what they do is missing.
        """
        info = self.elfs.get(rel)
        if not info or not self.main_exec or self.main_exec not in self.elfs or rel == self.main_exec:
            return False
        return info.is_executable and not is_library_name(Path(rel).name) \
            and Path(rel).parent != Path(self.main_exec).parent

    def gui_reason(self) -> str | None:
        """Return why the app is graphical judging by its .desktop file (not Terminal=true), or None.

        A Java app that runs on the JDK debpak adds draws its windows with that JDK's
        libraries (AWT, Swing, JavaFX), so nothing in the package shows it's graphical.
        """
        if not self.desktop_file:
            if self.java:
                return "Java app (its windows come from the JDK debpak adds)"
            if self.mono and self.mono.get("libraries"):
                return "Windows Forms app (its windows come from the Mono debpak adds)"
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


def is_glibc_copy(info: ElfInfo, name: str) -> bool:
    """Return True for a package's own copy of one of glibc's libraries or its loader.

    It goes by a core glibc name (libanl.so.1, or its file libanl-2.31.so) and defines
    glibc's GLIBC_ symbol versions, which libnss_mdns, libnsl2 and the like don't.
    """
    so = info.soname or name
    if not (is_never_bundle(so) or is_never_bundle(re.sub(r"-2\.\d+\.so$", ".so", name))):
        return False
    return any(v.startswith("GLIBC_") for v in info.verdef)


def glibc_copies(elfs: dict[str, ElfInfo], package_sonames: dict[str, str], runtime) -> dict[str, list[str]]:
    """Return the package's copies of glibc's libraries that the Flatpak leaves out, by the names they go by.

    PonyPlayer's AppImage (built with appimage-builder) carries glibc 2.31 in
    runtime/compat for systems older than that, and its libanl-2.31.so, which
    needs its own libpthread's GLIBC_PRIVATE, refused the app. A library of
    glibc's works only with the loader and libc of the same build, and the
    programs run with the runtime's loader, so the runtime's glibc is what they
    must load. A package that ships glibc's loader as well may start a tool with
    that whole copy (Hydra does): it is kept then, though not judged either (see
    check_versions).
    """
    copies = {rel for rel, info in elfs.items() if is_glibc_copy(info, Path(rel).name)}
    if any((elfs[rel].soname or Path(rel).name).startswith(("ld-linux", "ld64.so")) for rel in copies):
        return {}
    names: dict[str, list[str]] = {}
    for so, rel in package_sonames.items():
        names.setdefault(rel, []).append(so)
    return {rel: sorted(names.get(rel, [Path(rel).name])) for rel in copies
            if runtime.provides(elfs[rel].soname or Path(rel).name)}


# Libraries that work only with each other's own builds: fontconfig is built against freetype, and
# freetype against harfbuzz, each needing the next one's newer functions; libxkbcommon-x11 reaches
# into libxkbcommon's private structures. A package that carries only some of a set gets the
# runtime's others, which load its older copies (see partial_set_copies)
MATCHED_SETS = (("libfontconfig.so.1", "libfreetype.so.6", "libharfbuzz.so.0"),
                ("libxkbcommon.so.0", "libxkbcommon-x11.so.0"))


def partial_set_copies(elfs: dict[str, ElfInfo], package_sonames: dict[str, str], runtime) -> dict[str, list[str]]:
    """Return the package's copies of libraries of a MATCHED_SETS set that the Flatpak leaves out, by the
    names they go by, when the package carries some of the set but not all of it.

    Dana's AppImage and ImagePlay's, built with linuxdeployqt on old systems,
    carry their own libfreetype.so.6 (ImagePlay its libharfbuzz.so.0 too) but
    not fontconfig, which then comes from the runtime and needs a newer
    freetype: Qt's xcb plugin didn't load ("libfontconfig.so.1: undefined
    symbol: FT_Done_MM_Var"), and the app aborted with "could not find or load
    the Qt platform plugin". With the runtime's freetype, ImagePlay's harfbuzz
    was too old for it in turn ("undefined symbol:
    hb_ot_tags_from_script_and_language"); AppImage's own tools have long left
    these three out of AppImages for this reason. Carthage's tarball and
    Dream-VoiceTraining's AppImage, PyInstaller and PySide6 builds, carry
    libxkbcommon-x11.so.0 without libxkbcommon.so.0, and crashed in the
    runtime's xkb_state_update_derived as Qt's xcb plugin set up the keyboard.
    The runtime's whole set is used instead, when it has all of it; a package
    that carries a whole set keeps its own, which match each other.
    """
    names: dict[str, list[str]] = {}
    for so, rel in package_sonames.items():
        names.setdefault(rel, []).append(so)
    out: dict[str, list[str]] = {}
    for libs in MATCHED_SETS:
        carried = {package_sonames[so] for so in libs if so in package_sonames}
        if not carried or all(so in package_sonames for so in libs) or not all(runtime.provides(so) for so in libs):
            continue
        out.update({rel: sorted(names[rel]) for rel in carried if rel in elfs})
    return out


# The libraries the GL extension's Mesa (libGLX_mesa.so.0, libEGL_mesa.so.0, libgallium) loads from the
# runtime. A package's older copy of one, first on the app's library path, is what Mesa then gets:
# ommpfritt's AppImage (linuxdeployqt, Ubuntu 18.04) carries libzstd.so.1 1.3, the runtime's libelf.so.1
# needs ZSTD_compressStream2 from it, so libGLX_mesa.so.0 didn't load, glvnd looked for a
# libGLX_indirect.so.0 that isn't there, and Qt stopped at "Could not initialize GLX". AppImage's own
# excludelist leaves most of these out of AppImages for this reason; libzstd and libelf it doesn't
MESA_DEPENDENCIES = ("libzstd.so.1", "libelf.so.1", "libexpat.so.1", "libz.so.1", "libdrm.so.2",
                     "libstdc++.so.6", "libgcc_s.so.1", "libX11.so.6", "libXext.so.6",
                     "libxshmfence.so.1", "libxcb-dri2.so.0", "libxcb-dri3.so.0", "libxcb-present.so.0",
                     "libxcb-sync.so.1", "libxcb-xfixes.so.0", "libxcb-randr.so.0", "libxcb-glx.so.0",
                     "libxcb-shm.so.0", "libX11-xcb.so.1", "libxcb.so.1", "libXxf86vm.so.1",
                     "libwayland-client.so.0", "libwayland-server.so.0")
# The OpenGL stack itself, which the GL extension brings to match the host's driver: glvnd's
# dispatch libraries, Mesa's vendor libraries and libdrm's per-GPU ones. A package's copy (an
# appimage-builder AppImage takes them from the distribution it was built on) loads its own old
# Mesa, which finds no driver it can use in the sandbox; the snap route leaves them out the same way
# (snap.runtime_copies). Only these versioned names: Electron's own libEGL.so and libGLESv2.so are
# ANGLE, which Electron loads from its own folder
GL_STACK = ("libGL.so.1", "libGLX.so.0", "libGLdispatch.so.0", "libOpenGL.so.0", "libEGL.so.1",
            "libGLESv2.so.2", "libGLESv1_CM.so.1", "libGLX_mesa.so.0", "libEGL_mesa.so.0", "libgbm.so.1",
            "libdrm_amdgpu.so.1", "libdrm_intel.so.1", "libdrm_nouveau.so.2", "libdrm_radeon.so.1")
# what a program that draws with OpenGL links or loads (Qt's xcb plugin loads libGL through its GLX plugin)
GL_LIBRARIES = ("libGL.so", "libEGL.so", "libOpenGL.so", "libGLX.so", "libGLESv2.so", "libgbm.so")


def mesa_dependency_copies(elfs: dict[str, ElfInfo], package_sonames: dict[str, str],
                           runtime) -> dict[str, list[str]]:
    """Return the package's copies of GL_STACK and MESA_DEPENDENCIES that the Flatpak leaves out, by the
    names they go by.

    Only a package that draws with OpenGL (one of its files links GL_LIBRARIES, or it carries Qt's
    xcbglintegrations plugins) loses them. A copy of GL_STACK always goes, as the GL extension
    provides those. A copy of MESA_DEPENDENCIES goes only when the runtime has it under the same
    name: the same name promises the same interface, and the runtime's copy is the one Mesa was
    built with. One that defines a symbol version the runtime's lacks stays, as the newer of the two.
    """
    gl = any(n.startswith(GL_LIBRARIES) for info in elfs.values() for n in info.needed) or \
        any("/xcbglintegrations/" in rel for rel in elfs) or any(so in package_sonames for so in GL_STACK)
    if not gl:
        return {}
    names: dict[str, list[str]] = {}
    for so, rel in package_sonames.items():
        names.setdefault(rel, []).append(so)
    out: dict[str, list[str]] = {}
    for so in GL_STACK + MESA_DEPENDENCIES:
        rel = package_sonames.get(so)
        if not rel or rel not in elfs or not runtime.provides(so):
            continue
        if so not in GL_STACK:
            if so not in runtime.sonames:
                continue
            have = runtime.versions_of(so) or set()
            if set(elfs[rel].verdef) - {so, elfs[rel].soname} - have:
                continue
        out[rel] = sorted(names[rel])
    return out


def built_for_musl(info: ElfInfo) -> bool:
    """Return True for an ELF file linked against musl libc (Alpine's), which a glibc runtime can't run.

    A musl program names its loader (ld-musl-x86_64.so.1) or libc.musl-x86_64.so.1; a musl library
    needs plain libc.so, musl's own soname, which glibc never uses (its is libc.so.6).
    """
    return "ld-musl" in (info.interp or "") or any(n.startswith(("libc.musl", "ld-musl")) or n == "libc.so"
                                                   for n in info.needed)


def find_desktop_files(root: Path) -> list[str]:
    d = root / "usr/share/applications"
    if not d.is_dir():
        return []
    return sorted(_rel(root, p) for p in d.glob("*.desktop"))


def script_desktop_entry(pkg) -> str | None:
    """Return the menu entry a maintainer script writes (echo or a here-document), or None.

    The shell variables the script sets plainly (I4J_INSTALL_LOCATION="/opt/Moneydance")
    are filled in, and the entry must name a program.
    """
    for name in ("postinst", "preinst"):
        text = pkg.maintainer_script(name) or ""
        start = text.find("[Desktop Entry]")
        if start < 0:
            continue
        values = {m.group(1): m.group(3) for m in
                  re.finditer(r"(?m)^\s*(?:export\s+)?([A-Za-z_]\w*)=([\"']?)([^\"'\s$`]*)\2\s*$", text[:start])}
        lines = ["[Desktop Entry]"]
        for line in text[start:].splitlines()[1:]:
            line = line.strip().replace('\\"', '"').replace("\\$", "$")
            if not re.match(r"^[A-Za-z][\w-]*(\[[^\]]*\])?\s*=", line):
                break
            lines.append(re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: values.get(m.group(1), m.group(0)), line))
        entry = "\n".join(lines) + "\n"
        if desktop_entry_value(entry, "Exec") and "$" not in (desktop_entry_value(entry, "Exec") or ""):
            return entry
    return None


SCHEMA_LIST = re.compile(r"<schemalist\b.*?</schemalist>", re.S)


def script_schemas(pkg) -> dict[str, str]:
    """Return the GSettings schemas a maintainer script writes from text of its own, by file name.

    gorsync's RPM, made with fpm, carries its schema as a here-document in the
    script run after installing, which writes it to /usr/share/glib-2.0/schemas
    and compiles it; the program looks its schema up at start and, finding
    none, crashed on the error dialog it made before it had a display. A
    schema list that parses is named after its first schema's id.
    """
    import xml.etree.ElementTree as ET
    out: dict[str, str] = {}
    for name in ("postinst", "preinst"):
        for m in SCHEMA_LIST.finditer(pkg.maintainer_script(name) or ""):
            try:
                ids = [e.get("id") for e in ET.fromstring(m.group(0)).iter("schema") if e.get("id")]
            except ET.ParseError:
                continue
            if ids and re.fullmatch(r"[\w.-]+", ids[0]):
                out.setdefault(f"{ids[0]}.gschema.xml", '<?xml version="1.0" encoding="UTF-8"?>\n' + m.group(0) + "\n")
    return out


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


def only_program_on_path(root: Path) -> str | None:
    """Return the program behind the package's only command in usr/bin and the like, or None.

    PowerShell's package has no menu entry and links /usr/bin/pwsh to
    /opt/microsoft/powershell/7/pwsh, a small program beside larger ones
    (createdump), which the largest-program guess took.
    """
    found = set()
    for d in BIN_DIRS:
        folder = root / d
        if not folder.is_dir() or folder.is_symlink():
            continue
        for f in folder.iterdir():
            loc = locate_program(root, f"/{d}/{f.name}")
            if loc and os.access(root / loc, os.X_OK):
                found.add(loc)
    return found.pop() if len(found) == 1 else None


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
    app, whereas plugins live in folders of their own (Zoom's Qt/plugins). So is
    one beside the programs themselves: Electrobun apps (Postbird) keep
    libNativeWrapper.so, which their launcher opens and which links WebKitGTK,
    in bin/ next to it.

    A library of a family the package ships itself (libQt6WaylandClient.so.6
    beside the vendor's libQt6Core.so.6, libcrypto.so.1.1 beside libcrypto.so.3)
    is left out: a distribution's build of it needn't match the vendor's.
    """
    lib_dirs = {str(Path(r).parent) for r in reached}
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


# Desktop services a program can reach over D-Bus with a D-Bus library of its own, linking
# nothing that shows it: Tauri apps keep their secrets with the keyring crate, which talks to
# org.freedesktop.secrets through zbus (Kunkun and Moosync panicked at start with "Platform
# secure storage failure: DBus error: org.freedesktop.DBus.Error.ServiceUnknown")
BUS_SERVICES = (b"org.freedesktop.secrets",)


def scan_bus_clients(path: Path) -> set[str]:
    """Return the BUS_SERVICES a program names in its data."""
    try:
        with open(path, "rb") as f:
            if not os.fstat(f.fileno()).st_size:
                return set()
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                return {n.decode() for n in BUS_SERVICES if m.find(n) != -1}
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
    if Path(tokens[0]).name in SHELLS and len(tokens) > 1 and not tokens[1].startswith("-"):
        # the menu entry runs a script through a shell: the script is the program (Angry IP
        # Scanner: Exec=sh /usr/bin/ipscan; Moneydance: Exec=/bin/sh "/opt/Moneydance/Moneydance" %U)
        tokens = tokens[1:]
    return env, tokens[0], tokens[1:]


SHELLS = {"sh", "bash", "dash", "ksh", "zsh"}


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


def _script_link(root: Path, prog: str, loc: str) -> str:
    """Return prog itself, relative to root, when it's a relative link to the script loc, else loc.

    A script finds its files from the name it was started by: Cryptomator's
    AppRun is a link to bin/cryptomator.sh, which does `cd $(dirname $0)`
    and runs bin/Cryptomator, so started by its own name it looks in bin/bin.
    """
    link = root / prog.lstrip("/")
    if not prog.startswith("/") or not link.is_symlink() or os.readlink(link).startswith("/") \
            or not _is_script(root / loc):
        return loc
    return _rel(root, link)


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
    def runnable(p: Path) -> bool:
        # a launcher script may lack its x bit, which postinst or the package's link gives it
        # (TrueConf's opt/trueconf/client/trueconf, run as /usr/bin/trueconf)
        return p.is_file() and (os.access(p, os.X_OK) or _is_script(p))

    beside = resolve_in_root(root, f"{Path(near).parent.as_posix()}/{name}")
    if beside and runnable(beside):
        return _rel(root.resolve(), beside)
    hits = [p for p in _walk_files(root) if p.name == name and runnable(p)]
    real = {r for p in hits if (r := resolve_in_root(root, _rel(root, p))) and r.is_file()}
    return _rel(root.resolve(), real.pop()) if len(real) == 1 else None


# Chromium's helper programs beside its main binary. Branded builds rename them:
# Edge ships msedge-sandbox and msedge_crashpad_handler.
ELECTRON_HELPER_RE = re.compile(r"(^|[-_])(sandbox|crashpad_handler)$")


def _is_electron_helper(name: str) -> bool:
    return bool(ELECTRON_HELPER_RE.search(name))


def sandbox_filename(root: Path, main_exec: str) -> str | None:
    """Return the name of a branded Chromium's setuid sandbox helper, such as Edge's
    msedge-sandbox or Opera's opera_sandbox, or None for the usual chrome-sandbox.

    zypak only stands in for the helper under the name it is told (ZYPAK_SANDBOX_FILENAME,
    chrome-sandbox by default); under any other name Chromium finds the real file, not
    setuid root, and aborts. A name counts when the file sits beside the program and the
    program has the name compiled in.
    """
    exe = resolve_in_root(root, main_exec) or root / main_exec
    if (exe.parent / "chrome-sandbox").exists():
        return None
    names = sorted(p.name for p in [*exe.parent.glob("*-sandbox"), *exe.parent.glob("*_sandbox")] if p.is_file())
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
    dirs |= {p.parent.parent.parent.relative_to(root) for p in root.rglob("resources/app/package.json")}
    for name in ("v8_context_snapshot.bin", "snapshot_blob.bin"):
        # Electron 2 has content_shell.pak where later ones have resources.pak (Bodhi's AppImage)
        dirs |= {p.parent.relative_to(root) for p in root.rglob(name)
                 if (p.parent / "resources.pak").exists() or (p.parent / "content_shell.pak").exists()}
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


# a path in a script that doesn't start at / or a variable: ./mercury/mercury, lib/app.jar
RELATIVE_PATH = re.compile(r"""(?:^|[\s=;&|(`"'])((?:\./)?[\w.+-]+(?:/[\w.+-]+)+|\./[\w.+-]+)(?=$|[\s;&|)`"'])""",
                           re.M)
# the script moves into a folder of its choosing first: cd "$(dirname "$0")", pushd "$HERE"
CHANGES_FOLDER = re.compile(r"(?m)^[^#\n]*\b(?:cd|pushd)\s+\S")


# a variable set from dirname (RUN_PATH=`dirname "${SCRIPTSRC}"`), and a cd line's argument
DIRNAME_VARIABLE = re.compile(r"(?m)^\s*(?:export\s+)?(\w+)=.*\bdirname\b")
CD_ARGUMENT = re.compile(r"(?m)^\s*(?:[^#\n]*(?:;|&&|\|\||\bthen|\bdo)\s*)?(?:cd|pushd)\s+(.+)$")   # not in a $(...)


def _cds_into_own_folder(text: str) -> bool:
    """Return True if a script changes into the folder it is in (cd "$(dirname "$0")", cd "$RUN_PATH")."""
    names = set(DIRNAME_VARIABLE.findall(text))
    return any("dirname" in arg or any(re.search(rf"\$\{{?{n}\b", arg) for n in names)
               for arg in CD_ARGUMENT.findall(text))


def script_start_folder(root: Path, script: str, limit: int = 256 << 10) -> str | None:
    """Return the folder a launcher script (or the snap command it runs) changes into, or None.

    Firestorm's snap runs ./firestorm, which does cd "${RUN_PATH}" (its own
    folder) and starts bin/do-not-directly-run-firestorm-bin, a CEF program
    that reads app_settings/ from the folder it's started in. When debpak
    starts that program itself (see the bypass in analyze), it has to start
    it there too, or it shows "Firestorm couldn't access some of the files it
    needs". For a snap's launcher (opt/NAME/.debpak-snap/APP) the scripts it
    runs under $SNAP are looked at too.

    Returns:
        The folder, relative to root.
    """
    todo, seen = [script], set()
    while todo and len(seen) < 6:
        rel = todo.pop(0)
        p = root / rel
        if rel in seen or not p.is_file() or not _is_script(p):
            continue
        seen.add(rel)
        try:
            if p.stat().st_size > limit:
                continue
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        if _cds_into_own_folder(text):
            return os.path.dirname(rel)
        if Path(rel).parent.name == ".debpak-snap":
            snap = Path(rel).parent.parent
            for m in re.finditer(r'"\$SNAP/([^"$]+)"', text):
                todo.append(os.path.normpath(str(snap / m.group(1))))
    return None


def relative_reference(script: Path, limit: int = 256 << 10) -> str | None:
    """Return a path the script uses relative to the current folder that only exists beside it, or None.

    Mercury's start script runs ./mercury/mercury and Java launchers often run
    `java -jar lib/app.jar`: they work when started from their own folder, as from
    a file manager or after `cd App`, and the launcher starts them in the home
    folder. A script that changes folder itself (cd "$(dirname "$0")") is
    left alone, as are paths that don't exist beside it (a URL's path, usr/bin/env).
    """
    try:
        if script.stat().st_size > limit:
            return None
        text = script.read_text("utf-8", "replace")
    except OSError:
        return None
    if CHANGES_FOLDER.search(text):
        return None
    here = script.parent
    for line in text.splitlines()[1:]:
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        for m in RELATIVE_PATH.finditer(code):
            ref = m.group(1)
            if ".." in ref.split("/") or "://" in code[max(0, m.start() - 8):m.end()]:
                continue
            if (here / ref).exists():
                return ref
    return None


def programs_a_script_runs(root: Path, script: str, elfs: dict, limit: int = 256 << 10) -> list[str]:
    """Return the package's programs that a start script names, for what they load.

    A game's start script (Ren'Py's renpy.sh runs lib/py3-linux-x86_64/renpy, Mercury's
    MERCURY_PORTABLE runs ./mercury/mercury) hides the program from the look at what the
    entry point loads, and a bundled SDL that opens X11 itself then left the app without
    a display.
    """
    try:
        if (root / script).stat().st_size > limit:
            return []
        text = (root / script).read_text("utf-8", "replace")
    except OSError:
        return []
    names = set(re.findall(r"[\w.+-]+", text))
    return [rel for rel, info in sorted(elfs.items()) if info.is_executable and Path(rel).name in names][:8]


# Commands a launcher script may run that can't do their job in a Flatpak, where the launcher puts
# stand-ins of its own first on PATH (stage.STUB_DIR). Plover's AppRun runs pkexec at every start, to
# install a udev rule, and before it notify-send, both under set -e: notify-send failed (no
# notification service the app may talk to) and the app exited with status 1 before Python started.
# Nothing in a Flatpak can become root, so the stand-in for sudo, pkexec and their kind runs a
# program of the app's own as the user and skips anything else (the host's setup: groupadd,
# udevadm, a rule in /etc) with status 0; the one for notify-send shows the notification when it
# can and never fails.
ROOT_HELPERS = ("pkexec", "sudo", "gksu", "gksudo", "kdesu", "kdesudo", "beesu", "doas", "lxsudo")
SCRIPT_STUBS = ROOT_HELPERS + ("notify-send",)
# a command where a shell runs one: at the start of a line or after ; & | ( ` then do else, maybe
# after exec, command or env VAR=..., and not quoted (echo "run it with sudo" says nothing)
_STUB_COMMAND = re.compile(
    r"(?:^|[;&|(`]|\b(?:then|do|else)\b)[ \t]*(?:(?:exec|command|nohup|env)[ \t]+(?:\w+=\S*[ \t]+)*)?"
    r"(" + "|".join(re.escape(n) for n in SCRIPT_STUBS) + r")(?=[ \t]|$)", re.M)


def script_stub_commands(path: Path, limit: int = 256 << 10) -> list[str]:
    """Return the commands of SCRIPT_STUBS that a shell script runs (see SCRIPT_STUBS)."""
    try:
        if path.stat().st_size > limit:
            return []
        text = path.read_text("utf-8", "replace")
    except OSError:
        return []
    if text.startswith("#!") and not re.match(r"#!\s*\S*(?:/|\s)(?:ba|da|k|z)?sh\b", text):
        return []           # a Python or Perl launcher: its "sudo" lines aren't commands
    lines = (line for line in text.splitlines() if not line.lstrip().startswith("#"))
    found = {m.group(1) for line in lines for m in _STUB_COMMAND.finditer(line)}
    return [n for n in SCRIPT_STUBS if n in found]


def _is_script(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def _is_bare_script(path: Path) -> bool:
    """Return True for a short text file a shell would run though it has no #! line.

    Oracle SQL Developer's /usr/local/bin/sqldeveloper is the one line
    "/opt/sqldeveloper/sqldeveloper.sh": execve() refuses it and the shell then
    runs it itself, so it's a script like any other, with a path to rewrite.
    """
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
            return False
        data = path.read_bytes()
    except OSError:
        return False
    return bool(data.strip()) and b"\0" not in data and not data.startswith((b"#!", b"\x7fELF")) \
        and re.match(rb"\s*(?:[/.$A-Za-z_\"'])", data) is not None


def xlib_copies(elfs: dict) -> list[str]:
    """Return the package's libraries, other than libX11, that carry a copy of Xlib, when the
    package's programs also use libX11 itself.

    python-appimage's libpython3.8 (Mu Editor's AppImage) has Tk linked in with an old Xlib, and
    exports its functions. Qt's xcb plugin, loaded later, then got XOpenDisplay from libpython and
    the rest of Xlib from the runtime's newer libX11, and Mu crashed as Qt opened the display, in
    the runtime's _XLockDisplay called from libpython's XCreateGC. The launcher preloads
    libX11.so.6, so its functions come first for every library (see stage.wrapper_script).
    """
    if not any("libX11.so.6" in i.needed for i in elfs.values()):
        return []
    return sorted(rel for rel, i in elfs.items() if i.defines_xlib and i.is_shared_library
                  and not Path(rel).name.startswith("libX11.so"))


def classify(root: Path, external_needed: set[str], names: set[str]) -> tuple[str, str]:
    """Classify the app by toolkit from the libraries it links and the files it ships.

    Returns:
        A (kind, evidence) tuple, such as ("qt6", "links system libQt6Core.so.6").
    """
    if "libcef.so" in names:
        # Chromium Embedded Framework (Webex, Spotify): Chromium without Electron,
        # its main program is the vendor's own (often a Qt or GTK app)
        return "cef", "Chromium Embedded Framework (libcef.so) present"
    # Opera names its files its own way (opera_sandbox, opera.pak) beside Chromium's V8 snapshot
    snapshot = any(n in names for n in ("v8_context_snapshot.bin", "snapshot_blob.bin"))
    # Qt WebEngine is Chromium too, with its V8 snapshot and .pak files, but the app around it is a
    # Qt one: Dream-VoiceTraining, Python and Qt 6 in an AppImage, was taken for an Electron app
    if "QtWebEngineProcess" in names or any(re.match(r"libQt[56]WebEngineCore\.so", n) for n in names):
        snapshot = False
    if "chrome-sandbox" in names or (root / "resources/app.asar").exists() or snapshot and (
            "resources.pak" in names or any(re.fullmatch(r"[\w.-]+[-_]sandbox", n) or n.endswith(".pak")
                                            for n in names)):
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


def _snap_content_runtime(root: Path, extra: dict, kind: str) -> str | None:
    """Return the DEFAULT_RUNTIMES key the snap's toolkit content snap maps to, or None (see snapcontent.runtime_for)."""
    from .snap import parse_yaml
    from .snapcontent import runtime_for
    yml = root / "opt" / str(extra.get("opt_name") or "") / "meta/snap.yaml"
    try:
        meta = parse_yaml(yml.read_text("utf-8", "replace")) if extra.get("opt_name") and yml.is_file() else {}
    except OSError:
        return None
    return runtime_for(meta, kind) if isinstance(meta, dict) else None


# the Qt 6 minor versions Flathub has a KDE runtime for (org.kde.Platform//6.N)
KDE_QT6_MINORS = (6, 7, 8, 9, 10, 11)


def kde_runtime_for_qt(verneed: dict[str, set[str]]) -> str | None:
    """Return the KDE runtime whose Qt the programs were built against, when the default's is too old.

    A program built against Qt 6.10 needs symbols tagged Qt_6.10 (Konqueror's snap:
    "version `Qt_6.10' not found"), and one that uses Qt's private API needs exactly
    the Qt it was built with (Notes: Qt_6.6_PRIVATE_API). Returns None when the
    default runtime does, or no KDE runtime has that Qt.
    """
    minors, private = set(), set()
    for lib, versions in verneed.items():
        if not lib.startswith("libQt6"):
            continue
        for v in versions:
            m = re.fullmatch(r"Qt_6\.(\d+)(_PRIVATE_API)?", v)
            if m:
                (private if m.group(2) else minors).add(int(m.group(1)))
    default = int(DEFAULT_RUNTIMES["kde6"].rsplit(".", 1)[1])
    if private:
        want = max(private)
        if want == default or want not in KDE_QT6_MINORS:
            return None
        return f"org.kde.Platform//6.{want}"
    if not minors or max(minors) <= default:
        return None
    fit = [m for m in KDE_QT6_MINORS if m >= max(minors)]
    return f"org.kde.Platform//6.{fit[0]}" if fit else None


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


def lower_libm_needs(root: Path, elfs: dict[str, ElfInfo], provided: set[str] | None) -> dict[str, set[str]]:
    """Take off the files' libm needs the versions the runtime lacks that stage can lower; return them by file.

    A program built on glibc 2.43 needs libm.so.6 at GLIBC_2.43 for sqrtf and the
    like, which got that version only for speed (see elf.SVID_ONLY_LIBM):
    ModelViewer-Qt and PlasmaZones on the KDE runtime, whose glibc is 2.42. The
    file's needs then name the base version instead, as they will once stage has
    lowered them (elf.lower_libm_versions).
    """
    from .elf import LIBM_BASE_VERSION, libm_versions_lowerable
    out: dict[str, set[str]] = {}
    if not provided:
        return out
    for rel, info in elfs.items():
        versions = info.verneed.get("libm.so.6")
        base = LIBM_BASE_VERSION.get(info.machine)
        if not versions or base not in provided:
            continue
        lacking = {v for v in versions if v not in provided}
        if lacking and libm_versions_lowerable(root / rel, lacking):
            info.verneed["libm.so.6"] = (versions - lacking) | {base}
            out[rel] = lacking
    return out


def check_versions(elfs: dict[str, ElfInfo], providers: dict[str, set[str] | None]) -> list[str]:
    """Return human-readable problems where a required symbol version isn't provided."""
    problems = []
    for rel, info in sorted(elfs.items()):
        if is_glibc_copy(info, Path(rel).name):
            continue        # a copy of glibc needs only its own build's parts (see glibc_copies)
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
        if p.is_file() and not p.is_symlink() and (
                _is_script(p) or (p.parent.relative_to(root).as_posix() in BIN_DIRS and _is_bare_script(p))):
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
        if built_for_musl(info):
            # a build for Alpine beside the glibc one (a Node module's prebuilds/linux-x64-musl): it
            # can't run on the runtime, and its libc.musl-x86_64.so.1 refused Dev-Suite Dashboard
            a.musl.append(rel)
            continue
        a.elfs[rel] = info
        if info.is_shared_library or ".so" in p.name:
            a.package_sonames.setdefault(p.name, rel)
            if info.soname:
                a.package_sonames.setdefault(info.soname, rel)
        for rp in info.rpath + info.runpath:
            if rp.startswith("/"):
                a.abs_rpath_dirs.add(rp)

    extra = getattr(pkg, "extra", {}) or {}
    if runtime and getattr(pkg, "format", "") == "snap" and extra.get("opt_name"):
        from .snap import runtime_copies
        a.runtime_replaces = runtime_copies(f"opt/{extra['opt_name']}", str(extra.get("base") or "core"), a.elfs,
                                            a.package_sonames, runtime, TRIPLETS.get(arch, f"{arch}-linux-gnu"))
        for rel in a.runtime_replaces:
            a.elfs.pop(rel, None)
        a.package_sonames = {so: rel for so, rel in a.package_sonames.items() if rel not in a.runtime_replaces}
    if runtime and (copies := glibc_copies(a.elfs, a.package_sonames, runtime)):
        a.runtime_replaces.update(copies)
        for rel in copies:
            a.elfs.pop(rel, None)
        a.package_sonames = {so: rel for so, rel in a.package_sonames.items() if rel not in copies}
    if runtime and getattr(pkg, "format", "") != "snap" \
            and (copies := partial_set_copies(a.elfs, a.package_sonames, runtime)):
        # a snap's are judged with its other Ubuntu libraries (snap.runtime_copies)
        a.runtime_replaces.update(copies)
        for rel in copies:
            a.elfs.pop(rel, None)
        a.package_sonames = {so: rel for so, rel in a.package_sonames.items() if rel not in copies}

    if runtime and getattr(pkg, "format", "") != "snap" \
            and (copies := mesa_dependency_copies(a.elfs, a.package_sonames, runtime)):
        # a snap's are judged with its other Ubuntu libraries (snap.runtime_copies)
        a.runtime_replaces.update(copies)
        for rel in copies:
            a.elfs.pop(rel, None)
        a.package_sonames = {so: rel for so, rel in a.package_sonames.items() if rel not in copies}

    schema_dir = root / "usr/share/glib-2.0/schemas"
    made_schemas = []
    for f, text in script_schemas(pkg).items():
        if not (schema_dir / f).exists():
            schema_dir.mkdir(parents=True, exist_ok=True)
            (schema_dir / f).write_text(text)
            made_schemas.append(f)

    # --- entry point
    desktops = find_desktop_files(root)
    if not desktops and not find_other_desktop_files(root) and (made := script_desktop_entry(pkg)):
        # install4j's .deb (Moneydance) has postinst write its menu entry; without it the entry
        # point was the largest program, the JDK's jspawnhelper
        d = root / "usr/share/applications" / f"{pkg.name}.desktop"
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_text(made)
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
            # --no-sandbox is how an AppImage's menu entry starts Chromium without its setuid helper;
            # in the Flatpak zypak does that, and an app that parses its own options refuses it
            # (CNCjs: "unknown option '--no-sandbox'")
            a.desktop_exec_args = [t for t in args if not FIELD_CODE.search(t) and t != "--no-sandbox"]
            a.main_exec, a.main_exec_reason = loc, how
            break
    if a.desktop_file is None and ordered:
        a.desktop_file = ordered[0]
    if exec_override:
        loc = locate_program(root, exec_override)
        if not loc:
            raise ValueError(f"--exec {exec_override} not found in package")
        loc = _script_link(root, exec_override, loc)
        if loc != a.main_exec:
            a.desktop_exec_args = []     # the menu entry's arguments are for another program
        a.main_exec, a.main_exec_reason = loc, "--exec"
    if a.main_exec is None:
        loc = locate_program(root, pkg.name) or named_program(a.elfs, pkg.name)
        if loc:
            a.main_exec, a.main_exec_reason = loc, "binary named after the package"
    if a.main_exec is None and (loc := only_program_on_path(root)):
        a.main_exec, a.main_exec_reason = loc, "the one program the package puts on PATH"
    if a.main_exec is None:
        guess = guess_main_exec(root, a.elfs)
        if guess:
            a.main_exec, a.main_exec_reason = guess, "largest executable ELF (guess)"
    if a.main_exec:
        a.main_exec_is_script = _is_script(root / a.main_exec) or _is_bare_script(root / a.main_exec)

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
    a.xlib_copies = xlib_copies(a.elfs)

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
    a.runtime_suggestion = suggest_runtime(a.kind, a.hard_needed | a.loaded_needed)
    if a.main_exec and a.main_exec_is_script and pydeps.is_python_script(root / a.main_exec):
        a.python_modules = pydeps.wanted(package_depends(pkg))
        if (toolkit := pydeps.toolkit_runtime(a.python_modules)):
            a.runtime_suggestion = DEFAULT_RUNTIMES[toolkit]
        if (version := pydeps.other_python(root)):
            a.python_version = version
            kind, suite, _mirror = pydeps.PYTHON_RELEASES[version]
            a.findings.append(Finding("handled", pydeps.abis(root)[version], (
                f"compiled Python modules built for Python {version}, not the runtime's "
                f"{pydeps.RUNTIME_PYTHON}: Python {version} and the modules it depends on come from "
                f"{kind.title()} {suite}")))
        elif (other := pydeps.foreign_abi(root)):
            a.findings.append(Finding("warn", other[0], (
                f"compiled Python modules built for Python {other[1]}, which the runtime's Python "
                f"({pydeps.RUNTIME_PYTHON}) can't load; the app fails where it imports them (dupeGuru's "
                "core.pe._block)")))
    sharun = bool(a.main_exec) and not a.main_exec_is_script and is_sharun(root / a.main_exec)
    if a.kind in CHROMIUM_KINDS and a.main_exec and (a.main_exec_is_script or sharun):
        # A launcher script (an AppImage's AppRun, a deb's /usr/bin wrapper) would start
        # Electron without zypak, and Chromium then dies on its sandbox inside Flatpak.
        # sharun's compiled AppRun is such a launcher too: it runs AppRun.sh and its hooks.
        if (binary := electron_binary(root, a.elfs, a.main_exec)):
            what = "sharun's launcher" if sharun else "a script"
            a.main_exec_reason += f"; {a.main_exec} is {what}, so the launcher runs the Electron binary it starts"
            a.bypassed_script = a.main_exec
            if (start := script_start_folder(root, a.main_exec)) is not None and start != os.path.dirname(binary):
                a.chdir = f"{a.main_exec} starts it in {start or 'the package folder'}"
                a.chdir_to = start
            a.main_exec, a.main_exec_is_script = binary, False
    programs = [a.main_exec] if a.main_exec in a.elfs else \
        programs_a_script_runs(root, a.main_exec, a.elfs) if a.main_exec and a.main_exec_is_script else []
    if a.kind not in CHROMIUM_KINDS and programs:
        todo = []
        for prog in programs:
            a.dlopened |= scan_dlopened(root / prog) - set(a.elfs[prog].needed)
            a.bus_clients |= scan_bus_clients(root / prog)
            todo += a.elfs[prog].needed
        # the libraries of its own it links load theirs too: a bundled SDL3 or GLFW opens X11
        # and Wayland itself, and its program then shows no sign of needing a display
        seen = set()
        while todo and len(seen) < 60:
            so = todo.pop()
            rel = a.package_sonames.get(so)
            if so in seen or not rel or rel not in a.elfs:
                continue
            seen.add(so)
            info = a.elfs[rel]
            if (root / rel).stat().st_size < (64 << 20):
                a.dlopened |= scan_dlopened(root / rel) - set(info.needed)
                a.bus_clients |= scan_bus_clients(root / rel)
            todo += info.needed
    if javart.needs_runtime(root, a.kind, a.elfs, a.main_exec):
        a.java = javart.setup(root)
    if a.main_exec and a.main_exec_is_script and (ref := relative_reference(root / a.main_exec)):
        a.chdir = f"{a.main_exec} uses {ref} relative to the folder it's started in"
    elif a.main_exec and (ndll := next(iter(sorted((root / a.main_exec).parent.glob("*.ndll"))), None)):
        # a Haxe program (Lime, OpenFL: Psych Engine) loads its modules, such as lime.ndll, from the
        # folder it's started in, and stopped at "Could not load module lime@lime_application_create__prime"
        a.chdir = f"{a.main_exec} is a Haxe program, which loads {ndll.name} from the folder it's started in"
    if monort.needs_runtime(root, a.elfs, a.main_exec):
        a.mono = monort.setup(root)
        a.loaded_needed |= set(a.mono["libraries"])

    all_verneed: dict[str, set[str]] = {}
    for rel, info in a.elfs.items():
        if is_glibc_copy(info, Path(rel).name):
            continue
        for lib, vs in info.verneed.items():
            all_verneed.setdefault(lib, set()).update(vs)
    all_versions = set().union(*all_verneed.values()) if all_verneed else set()
    a.max_glibc = max_version(all_versions, "GLIBC")
    a.max_glibcxx = max_version(all_versions, "GLIBCXX")
    if getattr(pkg, "format", "") == "snap" and a.runtime_suggestion == DEFAULT_RUNTIMES["freedesktop"] \
            and (content := _snap_content_runtime(root, extra, a.kind)):
        # the runtime of the toolkit the snap's content snap brought (gnome-46-2404: GNOME's)
        a.runtime_suggestion = DEFAULT_RUNTIMES[content]
    if a.runtime_suggestion == DEFAULT_RUNTIMES["kde6"] and (qt := kde_runtime_for_qt(all_verneed)):
        a.runtime_suggestion = qt

    if runtime:
        def missing(sonames):
            return {s for s in sonames if not runtime.provides(s)}
        a.missing_hard = missing(a.hard_needed)
        a.missing_soft = missing(a.soft_needed)
        a.missing_loaded = missing(a.loaded_needed)
        if a.main_exec in a.elfs:
            for bundle in dlopen_required(root / a.main_exec):
                alternatives = next(n for n, b in DLOPEN_REQUIRED if b == bundle)
                if not any(runtime.provides(n.decode()) for n in alternatives):
                    a.missing_loaded.add(bundle)
        # only a program's own needs stop it; a plugin that wants a missing glibc library just won't load
        a.never_bundle_missing = {s for s in a.missing_hard if is_never_bundle(s)}
        providers: dict[str, set[str] | None] = {}
        for lib in all_verneed:
            # glibc is always the runtime's: a copy in the package (Hydra keeps one for a tool it starts
            # with that copy's own loader) isn't what the app's programs and modules load
            if is_never_bundle(lib) and runtime.provides(lib):
                providers[lib] = runtime.versions_of(lib)
            elif lib in a.package_sonames and a.package_sonames[lib] in a.elfs:
                providers[lib] = a.elfs[a.package_sonames[lib]].verdef
            elif runtime.provides(lib):
                providers[lib] = runtime.versions_of(lib)
        a.libm_lowered = lower_libm_needs(root, a.elfs, providers.get("libm.so.6"))
        a.version_problems = check_versions(a.elfs, providers)

    scripts = {n: t for n in SCRIPTS if (t := pkg.maintainer_script(n))}
    a.findings = analyze_scripts(scripts) + analyze_payload(root, units=pkg.format not in ("appimage", "snap"))
    a.findings += [Finding(cat, where, detail) for cat, where, detail in getattr(pkg, "extra", {}).get("findings", [])]
    if made_schemas:
        a.findings.append(Finding("handled", "postinst", (
            f"writes the GSettings schema {', '.join(made_schemas)} from its own text; the Flatpak gets it, "
            "compiled")))
    if a.foreign_arch:
        a.findings.append(Finding("warn", a.foreign_arch[0],
                                  f"{len(a.foreign_arch)} ELF file(s) for another architecture (ignored)"))
    if a.musl:
        a.findings.append(Finding("warn", a.musl[0], f"{len(a.musl)} ELF file(s) built against musl libc, for "
                                  "Alpine (ignored: the runtime's libc is glibc)"))
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
    a.bus_access = dict(getattr(pkg, "extra", {}).get("bus_access", {}))
    if a.main_exec and a.main_exec_is_script:
        a.script_stubs = script_stub_commands(root / a.main_exec)
        if "notify-send" in a.script_stubs:
            a.bus_access.setdefault("--talk-name=org.freedesktop.Notifications",
                                    f"{a.main_exec} runs notify-send")
    a.home_skel = find_home_skel(root, pkg.name)
    # only the app's own program: helpers it ships (Cherry Studio's mise) may say such things
    if (needs := next((p for p in programs[:4] if needs_root(root, p)), "")):
        a.findings.append(Finding("blocker", needs, (
            "needs root: the program refuses to work unless it runs as root (it says so and asks for "
            "sudo or pkexec), and nothing in a Flatpak can run as root. Raspberry Pi Imager writes SD "
            "cards this way; Flathub's build of it only works because of a patch to its source")))
    a.findings += privileged_parts(pkg, root, list(dict.fromkeys(p for p in [a.main_exec, *programs[:3]] if p)))
    a.autostart = any(_mentions(root / p, b"autostart") for p in programs[:3])
    if (prog := go_webkit(root, a.elfs)):
        a.signal_onstack = f"{prog} is a Go program that links WebKitGTK"
    leave_out_services(a)
    a.host_spawner = host_spawner(root, a.elfs)
    if a.host_spawner:
        a.findings.append(Finding("warn", a.host_spawner, (
            "runs its commands on the host with flatpak-spawn --host when it finds itself in a Flatpak, "
            "so the Flatpak may talk to org.freedesktop.Flatpak, which lets it run any program outside "
            "the sandbox; Flathub's builds of such apps (terminals) do the same")))
    a.home_folder = HOME_FOLDERS.get(pkg.name, "")
    return a


# What a program that won't work without root tells its user, in one message: the reason and then how
# to get root (Raspberry Pi Imager: "You are not running as root.\n\nPlease run with elevated
# privileges"). Both parts must be in the same string: error tables of libraries list "must be run
# as root" on its own (Warp carries one)
ROOT_ONLY = re.compile(rb"(?i)(?:not running as root|must be run as root|needs? to be run as root|"
                       rb"requires? root privileges)[^\x00]{0,160}?(?:\b(?:sudo|pkexec) [a-z]|elevated privileges)"
                       # or it starts itself again as root when it isn't (Ventoy's GUI: "try restart self by
                       # pkexec ...", beside "### Please run with root privileges. ###")
                       rb"|\b(?:re-?start|re-?launch|re-?run|re-?exec)\w* (?:it)?self (?:by|with|via|using) "
                       rb"(?:sudo|pkexec)\b")


# the libraries of WebKitGTK's JavaScriptCore, which installs signal handlers of its own
JSC_LIBRARY = re.compile(r"lib(?:webkit2gtk|webkitgtk|javascriptcoregtk)-[\d.]+\.so")
# what the Go linker writes at the start of a program's .go.buildinfo section (Go 1.13 and later)
GO_BUILDINFO = b"\xff Go buildinf:"


def go_webkit(root: Path, elfs: dict) -> str:
    """Return a program of the package that is written in Go and links WebKitGTK, or "".

    Wails apps (ProKZee) and other Go programs with a WebKitGTK window: JavaScriptCore
    installs its handlers for SIGSEGV and SIGUSR1 without SA_ONSTACK, and passes a
    fault that isn't its own on to the handler it replaced, Go's, on the thread's own
    stack. Go refuses to run there and ends the whole program with "fatal error: non-Go
    code set up signal handler without SA_ONSTACK flag". The launcher then preloads
    a library that adds SA_ONSTACK to every handler installed (see stage.ONSTACK_SHIM).
    """
    for rel, info in sorted(elfs.items()):
        if info.is_executable and any(JSC_LIBRARY.match(n) for n in info.needed) \
                and _mentions(root / rel, GO_BUILDINFO):
            return rel
    return ""


def _mentions(path: Path, needle: bytes) -> bool:
    try:
        with open(path, "rb") as f:
            if not os.fstat(f.fileno()).st_size:
                return False
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                return m.find(needle) >= 0
    except (OSError, ValueError):
        return False


def package_depends(pkg) -> set[str]:
    """Return the names of the packages a .deb's Depends (and Pre-Depends) or an RPM's Requires name."""
    control = getattr(pkg, "control", None) or {}
    names: set[str] = set()
    for key in ("Pre-Depends", "Depends"):
        for alt in re.split(r"[,|]", control.get(key, "")):
            if (name := re.sub(r"[\s(\[<:].*$", "", alt.strip())):
                names.add(name)
    for req in getattr(pkg, "extra", {}).get("requires", []):
        if re.fullmatch(r"[A-Za-z0-9][\w.+-]*", req):
            names.add(req)
    return names


# a socket of a system-wide service: unix:///var/run/netbird.sock, /run/foo/foo.sock
# (Go keeps its strings end to end, with nothing between them)
SYSTEM_SOCKET = re.compile(rb"(?:unix://|(?<![\w./-]))/(?:var/)?run/([A-Za-z][\w-]*?)(?:/[\w.-]+?)?\.sock")


def privileged_parts(pkg, root: Path, programs: list[str]) -> list[Finding]:
    """Find what makes an app depend on root or on a system service the package doesn't carry.

    Such an app converts and starts, but does nothing: VeraCrypt's GUI opens, and
    then mounts volumes with sudo, dmsetup and its sbin/mount.veracrypt helper; NetBird's
    netbird-ui is the front end of the netbird daemon, which another package
    installs as a service and which it reaches at unix:///var/run/netbird.sock.
    """
    out = []
    deps = package_depends(pkg)
    # (VeraCrypt's Depends on sudo says the same, but alone it doesn't: RuDesktop's names it too,
    # for installing its service, and the app works without)
    for p in sorted(root.glob("*sbin/mount.*")) + sorted(root.glob("usr/*sbin/mount.*")):
        out.append(Finding("blocker", _rel(root, p), (
            "a mount helper: the app mounts filesystems, which needs root and the host's kernel "
            "(device mapper, FUSE), out of reach from a Flatpak")))
        break
    names = {pkg.name, *(Path(p).name for p in programs)}
    ships = {p.name for d in BIN_DIRS if (root / d).is_dir() for p in (root / d).iterdir()}
    for dep in sorted(deps):
        if not dep.startswith("lib") and dep not in ships and any(fronts_daemon(n, dep) for n in names):
            out.append(Finding("blocker", f"Depends: {dep}", (
                f"the app is the front end of {dep}, another package (its daemon or command-line "
                "program), which the Flatpak doesn't include and, as a system service, couldn't run")))
            return out
    for prog in programs:
        try:
            data = (root / prog).read_bytes()
        except OSError:
            continue
        for m in SYSTEM_SOCKET.finditer(data):
            daemon = m.group(1).decode()
            if daemon not in ships and any(fronts_daemon(n, daemon) or n.lower() == daemon.lower() for n in names):
                out.append(Finding("blocker", prog, (
                    f"the app is the front end of a system service: it talks to {daemon} through "
                    f"{m.group(0).decode()}, a daemon the package doesn't include and a Flatpak couldn't run")))
                return out
    return out


def leave_out_services(a: Analysis) -> None:
    """Convert a graphical app without the system service its package also installs.

    RuDesktop starts its own program as a root service for unattended access,
    Teleport Connect a VNet daemon, Citrix Workspace logging and USB daemons:
    the app on the menu works without them, and they were the only reason the
    package was refused. The service findings become warnings and a note says
    what was left out. A package whose menu entry is the front end of the
    service's program (TeamViewer's teamviewer and teamviewerd) stays refused,
    and so does one whose services aren't in the package to look at.
    """
    blockers = [f for f in a.findings if f.category == "blocker"]
    if not blockers or not all(is_service_finding(f) for f in blockers):
        return
    if not (a.main_exec and a.desktop_file and a.main_exec_reason.startswith("Exec=") and a.gui_reason()):
        return
    services = system_services(a.root)
    if not services:
        return
    gui = {Path(a.main_exec).name, a.pkg.name}
    if a.bypassed_script:
        gui.add(Path(a.bypassed_script).name)
    if any(fronts_daemon(g, prog) for g in gui for prog in services.values()):
        return
    for i, f in enumerate(a.findings):
        if f.category == "blocker":
            a.findings[i] = Finding("warn", f.where, f"{f.detail}: left out (see below)")
    shown = ", ".join(sorted({Path(u).name for u in services}))[:200]
    a.findings.append(Finding("warn", a.desktop_file, (
        f"the package also installs system services ({shown}), which are left out: a Flatpak can't "
        f"run them. The app its menu entry starts doesn't depend on them, but whatever they do for it "
        "(unattended access, a VPN, device sharing, logging) won't work")))


def needs_root(root: Path, program: str) -> str:
    """Return the program when it tells its user it only works as root, or ""."""
    if not program:
        return ""
    try:
        data = (root / program).read_bytes()
    except OSError:
        return ""
    return program if ROOT_ONLY.search(data) else ""


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
