"""32-bit x86 programs in a 64-bit Flatpak, on Flathub's Compat.i386 extension.

BlackBox Component Builder's snap (bbcb) and S4A's are labelled amd64, built
on core18, but the programs they run are i386 ELF files: blackbox and
s4a_squeak_vm ask for the loader /lib/ld-linux.so.2, which the 64-bit
runtime doesn't have, and they stopped at "No such file or directory" and
"cannot execute: required file not found".

Flathub has no i386 runtime; 64-bit apps that start 32-bit programs (Steam)
add the extension org.freedesktop.Platform.Compat.i386, the i386 build of
the same Freedesktop platform, at /app/lib/i386-linux-gnu, and
org.freedesktop.Platform.GL32 at /app/lib/i386-linux-gnu/GL for the 32-bit
Mesa. The x86-64 runtime has /usr/lib/i386-linux-gnu as a link to
/app/lib/i386-linux-gnu and /usr/lib/ld-linux.so.2 as a link to
i386-linux-gnu/ld-linux.so.2 (freedesktop-sdk's multiarch elements), so
with the extension in place the loader is found at its usual path and looks
for libraries in its own folder. /app/etc/ld.so.conf names that folder too,
as Steam's does, with the package's own i386 library folders and the
folder of the i386 libraries debpak adds, so the linker's cache lists them
for 32-bit programs (it keeps 32-bit and 64-bit libraries apart).

The extension's libraries are taken to be the 64-bit runtime's (it is the
same platform built for i386), so what the package's 32-bit files need
beyond those and their own comes from its distribution as i386 packages
(for a snap, its base's Ubuntu). The package's own copy of a 32-bit glibc
(bbcb carries Ubuntu 18.04's, which its launcher puts first on the library
path) is left out, since the extension's loader can only work with its own
glibc; so is its 32-bit GL stack when GL32 is added, which has to match the
host's driver.
"""
from __future__ import annotations

import re
from dataclasses import replace

COMPAT_EXTENSION = "org.freedesktop.Platform.Compat.i386"
GL32_EXTENSION = "org.freedesktop.Platform.GL32"
COMPAT_DIR = "lib/i386-linux-gnu"               # under /app, where the extension is mounted
BUNDLED_LIBDIR = "lib/debpak-i386"              # under /app, the i386 libraries debpak adds
OWN_DIR = "lib/i386-linux-gnu-own"              # under /app, a package's own usr/lib/i386-linux-gnu
LOADER = "ld-linux.so.2"
# GL32's folders that its drivers merge (Steam's x-gl-merge-dirs)
GL_MERGE_DIRS = ("vulkan/icd.d;glvnd/egl_vendor.d;egl/egl_external_platform.d;OpenCL/vendors;lib/dri;lib/d3d;"
                 "lib/gbm;vulkan/explicit_layer.d;vulkan/implicit_layer.d;vdpau")
# what a program that draws with OpenGL or Vulkan links or loads
GL_NAMES = ("libGL.so", "libEGL.so", "libOpenGL.so", "libGLX.so", "libGLESv2.so", "libGLESv1_CM.so", "libvulkan.so",
            "libgbm.so", "libSDL2-2.0.so", "libSDL-1.2.so", "libglfw.so", "libGLU.so")
# the Freedesktop branch the GNOME and KDE runtimes are built on, whose Compat.i386 fits them
GNOME_ON_FREEDESKTOP = {"46": "23.08", "47": "24.08", "48": "24.08", "49": "25.08", "50": "25.08", "51": "26.08"}
KDE_ON_FREEDESKTOP = {"6.7": "23.08", "6.8": "24.08", "6.9": "24.08", "6.10": "25.08", "6.11": "25.08"}
DEFAULT_BRANCH = "25.08"
# folders whose 32-bit programs aren't the app's: Node modules' prebuilt helpers for other machines,
# and the helper programs distribution packages keep in their library folders (gdk-pixbuf-query-loaders)
NOT_THE_APPS = ("node_modules", "prebuilds")
ARCH_SUFFIX = re.compile(r"[._-]?(?:x86_64|amd64|x64|64|i[3-6]86|x86|ia32|32)$", re.I)


def freedesktop_branch(runtime_ref: str) -> str:
    """Return the Freedesktop branch the runtime is built on (25.08 for GNOME 49), whose Compat.i386 it takes."""
    parts = runtime_ref.replace("//", "/x/").split("/")
    rid, branch = parts[0], parts[-1]
    if rid.startswith("org.freedesktop."):
        return branch
    if "-" in branch:                       # org.kde.Platform//5.15-25.08
        return branch.rsplit("-", 1)[1]
    if rid.startswith("org.gnome."):
        return GNOME_ON_FREEDESKTOP.get(branch, DEFAULT_BRANCH)
    if rid.startswith("org.kde."):
        return KDE_ON_FREEDESKTOP.get(branch, DEFAULT_BRANCH)
    return DEFAULT_BRANCH


def _stem(rel: str) -> str:
    name = rel.rsplit("/", 1)[-1]
    return ARCH_SUFFIX.sub("", name).lower()


def programs(i386_elfs: dict, own_elfs: dict) -> list[str]:
    """Return the package's 32-bit x86 programs that are the app's, by path.

    A program is an ELF file that names the i386 loader. Those in a library
    folder (usr/lib/i386-linux-gnu/glib-2.0/gio-querymodules) or a Node
    module's prebuilt helpers aren't the app's, and neither is one beside a
    64-bit program of the same name (a release with both builds: the 64-bit
    one runs).
    """
    beside = {(rel.rsplit("/", 1)[0] if "/" in rel else "", _stem(rel))
              for rel, info in own_elfs.items() if info.interp}
    out = []
    for rel, info in sorted(i386_elfs.items()):
        if not (info.interp or "").endswith(LOADER):
            continue
        parts = rel.split("/")
        if any(p in NOT_THE_APPS for p in parts) or any(p.endswith("-linux-gnu") for p in parts[:-1]):
            continue
        if ((rel.rsplit("/", 1)[0] if "/" in rel else ""), _stem(rel)) in beside:
            continue
        out.append(rel)
    return out


def own_sonames(i386_elfs: dict) -> dict[str, str]:
    """Return soname (and file name) -> path of the package's 32-bit libraries."""
    out: dict[str, str] = {}
    for rel, info in sorted(i386_elfs.items()):
        if info.interp and not info.soname:
            continue
        name = rel.rsplit("/", 1)[-1]
        if ".so" in name or info.soname:
            out.setdefault(name, rel)
            if info.soname:
                out.setdefault(info.soname, rel)
    return out


def needed(progs: list[str], i386_elfs: dict, own: dict[str, str]) -> tuple[set[str], set[str]]:
    """Return (what the programs need, through the package's own libraries; what its other 32-bit files need).

    Neither holds what the package's own 32-bit libraries provide.
    """
    hard: set[str] = set()
    queue, seen = list(progs), set()
    while queue:
        rel = queue.pop()
        if rel in seen or rel not in i386_elfs:
            continue
        seen.add(rel)
        for n in i386_elfs[rel].needed:
            if n in own:
                queue.append(own[n])
            else:
                hard.add(n)
    soft = {n for rel, info in i386_elfs.items() if rel not in seen for n in info.needed if n not in own} - hard
    return hard, soft


def uses_gl(i386_elfs: dict) -> bool:
    """Return True if a 32-bit file of the package links OpenGL, Vulkan or a library that draws with them."""
    return any(n.startswith(GL_NAMES) for info in i386_elfs.values() for n in info.needed)


def runtime_view(runtime):
    """Return the runtime's index as the extension's: the same libraries, for i386."""
    return replace(runtime, arch="i386", ref=re.sub(r"/x86_64/", "/i386/", runtime.ref))


def add_extensions(branch: str, gl: bool) -> dict:
    """Return the manifest's add-extensions for Compat.i386 (and GL32), as Steam's manifest has them."""
    out = {COMPAT_EXTENSION: {"directory": COMPAT_DIR, "version": branch}}
    if gl:
        out[GL32_EXTENSION] = {
            "directory": f"{COMPAT_DIR}/GL", "version": "1.4", "versions": f"{branch};{branch}-extra;1.4",
            "subdirectories": True, "no-autodownload": True, "autodelete": False, "add-ld-path": "lib",
            "merge-dirs": GL_MERGE_DIRS, "download-if": "active-gl-driver", "enable-if": "active-gl-driver",
            "autoprune-unless": "active-gl-driver"}
    return out


def ld_conf_lines(gl: bool, lib_dirs: list[str], bundled: bool) -> list[str]:
    """Return the lines of /app/etc/ld.so.conf for 32-bit programs: GL32's drivers first, then the
    extension's folder, the libraries debpak added and the package's own 32-bit library folders."""
    lines = ["include /run/flatpak/ld.so.conf.d/app-*-org.freedesktop.Platform.GL32.*.conf"] if gl else []
    lines.append(f"/app/{COMPAT_DIR}")
    if bundled:
        lines.append(f"/app/{BUNDLED_LIBDIR}")
    return lines + [d for d in lib_dirs if d not in lines]


def install_refs(manifest: dict, arch: str = "x86_64") -> list[str]:
    """Return the extensions to install from Flathub beside the app, from its manifest's add-extensions.

    flatpak installs an app's extensions from the remote the app came from,
    and a converted app comes from a repository of its own, so Compat.i386
    (and GL32's Mesa build, GL32.default) are installed for it.
    """
    out = []
    for name, ext in (manifest.get("add-extensions") or {}).items():
        if name == COMPAT_EXTENSION:
            out.append(f"{name}/{arch}/{ext['version']}")
        elif name == GL32_EXTENSION:
            branch = str(ext.get("versions", "")).split(";")[0] or ext["version"]
            out.append(f"{name}.default/{arch}/{branch}")
    return out
