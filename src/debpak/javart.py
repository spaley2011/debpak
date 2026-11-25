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
    best = None
    for i, jar in enumerate(sorted(root.rglob("*.jar"))):
        if i >= limit:
            break
        if jar.is_symlink() or not jar.is_file():
            continue
        v = _class_version(jar)
        if v is not None and 1 <= v <= 99:
            best = v if best is None else max(best, v)
    return best


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
