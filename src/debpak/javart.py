"""A Java runtime for Java apps that don't bring their own.

Many Java apps ship as a folder of .jar files and a launcher script that runs
whatever `java` it finds (muCommander, Cytoscape's karaf), or an install4j
launcher that looks in INSTALL4J_JAVA_HOME (DbVisualizer). On the desktop that
is the distribution's Java; the Freedesktop runtime has none, so the app
stopped at "cannot find java VM". Flathub's answer is the OpenJDK SDK
extension, whose installjdk.sh copies a JDK into /app/jdk at build time; the
version is the oldest long-term one that runs the app's class files (a newer
Java refuses nothing an older one ran, but drops a few old APIs, so the
oldest that fits is the safest).
"""
from __future__ import annotations

import re
import shutil
import zipfile
from pathlib import Path

# long-term releases with an SDK extension for the 25.08 and 26.08 runtimes
LTS = (8, 11, 17, 21, 25)
LATEST_EXTENSION = "org.freedesktop.Sdk.Extension.openjdk"     # the newest Java, for class files past 25
JDK_DIR = "/app/jdk"
MAX_JARS = 400


def _class_version(jar: Path) -> int | None:
    """Return the Java version (8, 11, ...) the first plain class file in jar was compiled for."""
    try:
        with zipfile.ZipFile(jar) as z:
            for info in z.infolist():
                n = info.filename
                # a multi-release jar keeps newer builds of some classes under META-INF/versions
                if not n.endswith(".class") or n.startswith("META-INF/") or n.endswith("module-info.class"):
                    continue
                with z.open(info) as f:
                    head = f.read(8)
                if head[:4] != b"\xca\xfe\xba\xbe":
                    return None
                return int.from_bytes(head[6:8], "big") - 44
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError, EOFError):
        return None
    return None


def bundled_java(root: Path, elf_paths) -> str | None:
    """Return the app's own java program (bin/java, an ELF file), or None."""
    for rel in sorted(elf_paths):
        if rel.endswith("/bin/java") or rel == "bin/java":
            return rel
    return None


def needed_version(root: Path, limit: int = MAX_JARS) -> int | None:
    """Return the newest Java version any of the app's jars was compiled for, or None if it has no jars."""
    jars = sorted(root.rglob("*.jar"))[:max(limit, 0)]
    return max((v for v in map(_jar_version, jars) if v is not None), default=None)


def _jar_version(jar: Path) -> int | None:
    """Return the Java version a jar (a regular file, not a link) was compiled for, None if unknown or implausible."""
    if jar.is_symlink() or not jar.is_file():
        return None
    v = _class_version(jar)
    return v if v is not None and 1 <= v <= 99 else None


def extension_for(version: int | None) -> tuple[str, int | None]:
    """Return (SDK extension name, Java version) for class files of the given version (None: 21)."""
    if version is None:
        version = 21
    for v in LTS:
        if v >= version:
            return f"org.freedesktop.Sdk.Extension.openjdk{v}", v
    return LATEST_EXTENSION, None


def needs_runtime(root: Path, kind: str, elf_paths, main_exec: str | None) -> bool:
    """True if the app is a Java app with no Java of its own.

    It is when it has .jar files and no bin/java, and its entry point is a
    script or a jar, not a native program that only happens to ship a jar.
    """
    if bundled_java(root, elf_paths):
        return False
    if kind not in ("java", "elf"):
        return False
    if not any(True for _ in root.rglob("*.jar")):
        return False
    if main_exec and main_exec in set(elf_paths):
        # a native launcher: an install4j or launch4j stub has the strings to look for a JVM
        try:
            data = (root / main_exec).read_bytes()
        except OSError:
            return False
        return any(s in data for s in (b"INSTALL4J_JAVA_HOME", b"JAVA_HOME", b"libjvm.so", b"jli/libjli"))
    return True


def setup(root: Path, version_hint: int | None = None) -> dict:
    """Return what the build needs: {"extension", "version", "commands", "env"}."""
    ext, v = extension_for(version_hint if version_hint is not None else needed_version(root))
    return {
        "extension": ext,
        "version": v,
        "commands": [
            f"/usr/lib/sdk/{ext.rsplit('.', 1)[-1]}/installjdk.sh",
            # on PATH for launchers that run plain `java`
            f'for f in {JDK_DIR}/bin/*; do ln -sf "$f" /app/bin/; done',
        ],
        "env": {"JAVA_HOME": JDK_DIR, "INSTALL4J_JAVA_HOME": JDK_DIR, "JDK_HOME": JDK_DIR},
    }


# JavaFX, which Java left out of the JDK from 11 on: a .deb of a JavaFX app depends on Debian's openjfx
# and starts with --module-path /usr/share/openjfx/lib. lunaticsmtp's did, the runtime has no JavaFX, and
# it stopped at "Module javafx.web not found". Debian's openjfx (libopenjfx-java's jars, libopenjfx-jni's
# native libraries, WebKit's included) goes in APP_JAVAFX instead, laid out as the OpenJFX SDK's lib/
# folder is, the jars beside the libraries they load. Its windows are GTK 3's, so the app runs on GNOME's
# runtime. JavaFX's packages in Debian, Ubuntu and Fedora:
JAVAFX_PACKAGES = {"openjfx", "libopenjfx-java", "libopenjfx-jni", "java-openjfx", "openjfx8", "openjfx11"}
JAVAFX_DEBS = ("libopenjfx-java", "libopenjfx-jni")
APP_JAVAFX = "share/openjfx/lib"            # under /app
DEBIAN_JAVAFX = "/usr/share/openjfx"        # where a launcher looks for it (/usr/share/openjfx/lib)
JAVAFX_MODULES = ("javafx.base", "javafx.controls", "javafx.fxml", "javafx.graphics", "javafx.media",
                  "javafx.swing", "javafx.web")
JAVAFX_IN_SCRIPT = re.compile(rb"openjfx|javafx\.(?:base|controls|fxml|graphics|media|swing|web)\b")
# GTK 2's window toolkit library, which JavaFX uses only when asked to (jdk.gtk.version=2)
JAVAFX_GTK2 = "libglassgtk2.so"


def bundles_javafx(root: Path, limit: int = MAX_JARS) -> bool:
    """Whether the package carries a JavaFX of its own: its module jars, its native libraries, or a jar
    with JavaFX's classes in it (an app packed into one jar with everything it uses)."""
    return _has_javafx_files(root) or any(_jar_has_javafx(jar) for jar in sorted(root.rglob("*.jar"))[:max(limit, 0)])


def _has_javafx_files(root: Path) -> bool:
    """Whether a file under root is one of JavaFX's native libraries or its graphics module's jar."""
    import os
    return any(n in ("libglass.so", "libprism_es2.so") or re.fullmatch(r"javafx[.-]graphics[\w.-]*\.jar", n)
               for _d, _dirs, files in os.walk(root) for n in files)


def _jar_has_javafx(jar: Path) -> bool:
    """Whether jar holds JavaFX's own classes; False when it can't be read."""
    try:
        with zipfile.ZipFile(jar) as z:
            return "javafx/application/Application.class" in z.namelist()
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError):
        return False


def _main_class_uses_javafx(jar: Path) -> bool:
    try:
        with zipfile.ZipFile(jar) as z:
            manifest = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
            m = re.search(r"^Main-Class:\s*(\S+)", manifest, re.M)
            if not m:
                return False
            data = z.read(m.group(1).replace(".", "/") + ".class")
    except (OSError, KeyError, zipfile.BadZipFile, ValueError, RuntimeError):
        return False
    return b"javafx/" in data


def needs_javafx(root: Path, depends: set[str], limit: int = MAX_JARS) -> bool:
    """Whether a Java app uses JavaFX and doesn't carry it: its package depends on a distribution's
    JavaFX, a launcher script names it, or the main class of one of its jars uses it."""
    if bundles_javafx(root, limit):
        return False
    if depends & JAVAFX_PACKAGES:
        return True
    if any(_script_names_javafx(p) for d in ("usr/bin", "bin", "usr/games", "usr/local/bin")
           for p in (sorted((root / d).glob("*")) if (root / d).is_dir() else [])):
        return True
    return any(not jar.is_symlink() and _main_class_uses_javafx(jar)
               for jar in sorted(root.rglob("*.jar"))[:max(limit, 0)])


def _script_names_javafx(p: Path) -> bool:
    """Whether p is a launcher script (under 256 KB) that names JavaFX."""
    try:
        if p.is_file() and not p.is_symlink() and p.stat().st_size < (256 << 10):
            data = p.read_bytes()
            return data.startswith(b"#!") and bool(JAVAFX_IN_SCRIPT.search(data))
    except OSError:
        pass
    return False


def fetch_javafx(source, dest: Path) -> tuple[list[str], set[str], str]:
    """Copy Debian's JavaFX from source (a resolve.MirrorSource) into dest, the SDK's layout: the module
    jars (javafx.web.jar) beside the native libraries.

    Returns:
        (the packages not found, the libraries the native ones link, "version from suite").
    """
    missing, needed, version = [], set(), ""
    for name in JAVAFX_DEBS:
        try:
            pkg = source._package(name)
        except RuntimeError:
            pkg = None
        if pkg is None:
            missing.append(name)
            continue
        version = f"{pkg.version} from {source.suite}"
        dest.mkdir(parents=True, exist_ok=True)
        _copy_javafx_jars(pkg.root, dest)
        needed |= _copy_javafx_libraries(pkg.root, dest)
    own = {p.name for p in dest.iterdir()} if dest.is_dir() else set()
    return missing, needed - own, version


def _copy_javafx_jars(pkg_root: Path, dest: Path) -> None:
    """Copy a JavaFX package's module jars into dest under the SDK's names (javafx-web-11.jar -> javafx.web.jar)."""
    for jar in sorted(pkg_root.glob("usr/share/java/javafx-*.jar")):
        m = re.fullmatch(r"javafx-(\w+)-[\d.]+\.jar", jar.name)
        if m and jar.is_file() and not jar.is_symlink():
            shutil.copy2(jar, dest / f"javafx.{m.group(1)}.jar")


def _copy_javafx_libraries(pkg_root: Path, dest: Path) -> set[str]:
    """Copy a JavaFX package's native libraries (but GTK 2's) into dest; return the libraries they link."""
    from .elf import ElfError, read_elf
    needed: set[str] = set()
    for lib in sorted(pkg_root.glob("usr/lib/*/jni/*.so")):
        if lib.name == JAVAFX_GTK2 or lib.is_symlink() or not lib.is_file():
            continue
        shutil.copy2(lib, dest / lib.name)
        try:
            needed |= set(read_elf(lib).needed)
        except ElfError:
            pass
    return needed
