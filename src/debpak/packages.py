"""Input packages of every format debpak converts.

Each format is unpacked into the same shape the rest of the pipeline expects:
a `root` directory laid out like an installed system (usr/..., opt/...), plus
name, version, architecture, description, homepage, license and the
package's install scripts under Debian's names (preinst, postinst, prerm,
postrm), so the host-integration checks read them the same way.

  .deb                    deb.py
  .rpm                    rpm.py (pure Python: headers + cpio payload)
  .pkg.tar.{zst,xz,gz}    Arch Linux / pacman: tar with .PKGINFO and .INSTALL
  .AppImage               squashfs (or DwarFS) after an ELF runtime; placed under opt/NAME
  .tar.gz/.tar.xz/.zip    a vendor's "unpack and run" archive; placed under opt/NAME
  .run                    a Makeself installer or a GOG game installer; placed under opt/NAME

Windows and Mac programs take other routes (Electron or Wine); see foreign.py.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import re
import zlib
import shutil
import struct
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ARCH_TO_FLATPAK = {
    # Debian
    "amd64": "x86_64", "arm64": "aarch64", "i386": "i386", "armhf": "arm",
    # RPM / pacman / uname
    "x86_64": "x86_64", "aarch64": "aarch64", "i686": "i386", "i586": "i386", "armv7hl": "arm",
    "armv7h": "arm",
}
FLATPAK_TO_DEB = {"x86_64": "amd64", "aarch64": "arm64", "i386": "i386", "arm": "armhf"}
ELF_MACHINES = {0x3E: "x86_64", 0xB7: "aarch64", 0x03: "i386", 0x28: "arm"}
FORMATS = ("deb", "rpm", "pacman", "appimage", "tarball", "snap", "run", "Windows .exe/.msi/.msix",
           "macOS .dmg/.app (Electron)")


class PackageError(Exception):
    """A package debpak can't recognise or unpack."""
    pass


@dataclass
class Package:
    """A package of any format, unpacked into the layout of an installed system.

    Every extractor returns one of these (deb.extract returns the compatible
    DebPackage), so the rest of the pipeline doesn't care about the format.

    Attributes:
        format: deb, rpm, pacman, appimage, tarball or snap.
        root: The unpacked files, laid out as they'd be installed (usr/, opt/).
        pkg_arch: The format's own architecture name (amd64, x86_64, any,
            noarch ...); flatpak_arch translates it.
        scripts: Install scripts under Debian's names (preinst, postinst,
            prerm, postrm), so the same checks read every format.
        default_exec: The entry point when the format implies one (AppRun, a
            snap's app launcher, an archive's main executable).
        notes: Messages for the report about how the package was unpacked.
        extra: Format-specific values that staging needs, such as opt_name.
    """
    format: str
    path: Path
    root: Path
    name: str
    version: str = "0"
    pkg_arch: str = ""
    summary: str = ""
    long_description: str = ""
    homepage: str = ""
    license: str = ""
    scripts: dict[str, str] = field(default_factory=dict)
    default_exec: str | None = None
    notes: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    @property
    def flatpak_arch(self) -> str | None:
        """Return the Flatpak architecture, or None for architecture-independent packages."""
        if self.pkg_arch in ("noarch", "any", "all", ""):
            return None
        return ARCH_TO_FLATPAK.get(self.pkg_arch)

    @property
    def deb_arch(self) -> str:      # older callers
        """Return pkg_arch (the name DebPackage uses)."""
        return self.pkg_arch

    @property
    def control(self) -> dict[str, str]:   # older callers
        """Return Debian-style control fields, for code written for .debs."""
        return {"Package": self.name, "Version": self.version, "Homepage": self.homepage}

    def maintainer_script(self, name: str) -> str | None:
        """Return an install script by its Debian name, or None."""
        return self.scripts.get(name)


# --------------------------------------------------------------------------- detection

def detect_format(path: str | Path) -> str:
    """Return the format of a package file or installed snap folder.

    Magic bytes decide where the format has them (ar, RPM lead, ELF with the
    AppImage marker, squashfs); file names decide the rest.

    Raises:
        PackageError: The file is a plain ELF program, a folder that isn't an
            installed snap, or in no supported format.
    """
    from .foreign import detect as detect_foreign
    p = Path(path)
    if p.is_dir():
        if (p / "meta/snap.yaml").is_file():
            return "snap"           # an installed snap: /snap/NAME/current
        foreign = detect_foreign(p)
        if foreign:
            return foreign
        raise PackageError(f"{p}: a folder, but not an installed snap (no meta/snap.yaml), a Mac .app or a "
                           "Windows program's folder")
    with open(p, "rb") as f:
        head = f.read(16384)
    if _web_page(head):
        raise PackageError(f"{p.name} is a web page (HTML), not the download: the link led to a download or error "
                           "page instead of the file. Open it in a browser, save the real file, and convert that")
    if head[:2] == b"#!" and (MAKESELF_RE.search(head) or b"MojoSetup" in head or
                              p.name.lower().endswith(".run")):
        return "run"
    foreign = detect_foreign(p)
    if foreign:
        return foreign
    if head.startswith(b"!<arch>\n"):
        return "deb"
    if head[:4] == b"\xed\xab\xee\xdb":
        return "rpm"
    if head[:4] == b"\x7fELF":
        # newer runtimes (uruntime, some electron-builder builds) leave out the "AI" marker,
        # so an ELF file named .AppImage, or one with a filesystem image after it, is one too
        if head[8:11] in (b"AI\x02", b"AI\x01") or p.name.lower().endswith(".appimage") or _has_appimage_image(p):
            return "appimage"
        raise PackageError(f"{p}: an ELF program, not a package (to check one binary use `debpak smoke --exec`)")
    name = p.name.lower()
    if head[:4] == b"hsqs" or name.endswith(".snap"):
        return "snap"
    if re.search(r"\.pkg\.tar(\.(zst|xz|gz|bz2))?$", name):
        return "pacman"
    if name.endswith(".appimage"):
        return "appimage"
    if re.search(r"\.(tar\.(gz|xz|bz2|zst)|tgz|txz|tbz2?|tar|zip)$", name) or head[:2] == b"PK" or \
            head[:2] == b"\x1f\x8b" or head[:6] == b"\xfd7zXZ\x00" or head[:4] == b"\x28\xb5\x2f\xfd":
        return "tarball"
    raise PackageError(f"{p}: unknown package format (supported: {', '.join(FORMATS)})")


def _has_appimage_image(p: Path) -> bool:
    """Return True if an ELF file carries a squashfs or DwarFS image after its end, like an AppImage."""
    try:
        appimage_image(p)
    except (PackageError, OSError, struct.error):
        return False
    return True


def _web_page(head: bytes) -> bool:
    """Return True if a file's first bytes are an HTML page (a download link that served a web page)."""
    text = head[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if text.startswith((b"<!doctype html", b"<html")):
        return True
    return text.startswith((b"<!--", b"<?xml", b"<head", b"<meta")) and b"<html" in text


# What the archive libraries raise for damaged input. open_package turns these into PackageError,
# so a corrupted download gets a message instead of a traceback.
DAMAGED = (zipfile.BadZipFile, tarfile.TarError, EOFError, NotImplementedError, struct.error, zlib.error,
           lzma.LZMAError, UnicodeDecodeError)


def open_package(path: str | Path, dest: str | Path, allow_run: bool = False, wine_branch: str | None = None):
    """Unpack a package of any supported format (see _open_package); damaged archives raise PackageError.

    Raises:
        PackageError: The file is damaged, unsupported, or unsafe to unpack.
        DebError: A damaged .deb.
    """
    try:
        return _open_package(path, dest, allow_run, wine_branch)
    except DAMAGED as e:
        raise PackageError(f"{Path(path).name}: damaged or unsupported archive ({type(e).__name__}: {e})") from e
    except OSError as e:
        if isinstance(e, PackageError) or getattr(e, "filename", None) == str(path):
            raise
        raise PackageError(f"{Path(path).name}: damaged archive or unpacking failed ({e})") from e


def _open_package(path: str | Path, dest: str | Path, allow_run: bool = False, wine_branch: str | None = None):
    """Unpack a package of any supported format into dest.

    Args:
        path: The package file, an installed snap's folder, a Mac .app or a
            Windows program's folder.
        dest: An empty working folder.
        allow_run: Let an AppImage unpack itself when unsquashfs is missing.
            This runs the AppImage.
        wine_branch: The org.winehq.Wine branch a Windows installer that
            nothing can unpack runs under (foreign.unpack_windows).

    Returns:
        A Package, or a DebPackage for a .deb. Windows and Mac programs give
        a Package whose format is "electron" or "wine".

    Raises:
        PackageError, DebError: The package can't be recognised or unpacked.
    """
    path, dest = Path(path), Path(dest)
    fmt = detect_format(path)
    if fmt == "deb":
        from .deb import extract
        return extract(path, dest)
    if fmt == "rpm":
        from .rpm import extract_rpm
        return extract_rpm(path, dest)
    if fmt == "pacman":
        return extract_pacman(path, dest)
    if fmt == "appimage":
        return extract_appimage(path, dest, allow_run=allow_run)
    if fmt == "snap":
        from .snap import extract_snap
        return extract_snap(path, dest)
    if fmt == "run":
        return extract_run(path, dest)
    if fmt in ("dmg", "macapp", "windows"):
        from .foreign import open_foreign
        return open_foreign(path, dest, fmt, wine_branch)
    return extract_tarball(path, dest)


def is_package_file(p: Path) -> bool:
    """Return True for files that --deps-dir can take libraries from (.deb, .rpm, .pkg.tar.*)."""
    n = p.name.lower()
    return n.endswith((".deb", ".rpm")) or bool(re.search(r"\.pkg\.tar(\.(zst|xz|gz|bz2))?$", n))


# --------------------------------------------------------------------------- shared helpers

def _decompressed(path: Path):
    """Open a possibly compressed tarball, picking the decompressor by magic bytes."""
    with open(path, "rb") as f:
        head = f.read(6)
    if head[:2] == b"\x1f\x8b":
        return gzip.open(path, "rb")
    if head[:6] == b"\xfd7zXZ\x00":
        return lzma.open(path, "rb")
    if head[:3] == b"BZh":
        return bz2.open(path, "rb")
    if head[:4] == b"\x28\xb5\x2f\xfd":
        from .deb import _zstd_stream
        raw = open(path, "rb")
        s = _zstd_stream(raw)
        if s is not None:
            return s
        raw.close()
        if shutil.which("zstd"):
            out = subprocess.run(["zstd", "-dc", str(path)], capture_output=True, check=True).stdout
            return io.BytesIO(out)
        raise PackageError(f"{path.name} is zstd-compressed; install the 'zstandard' Python module "
                           "(pip install debpak[zstd]) or the zstd command-line tool")
    return open(path, "rb")


def _safe_tar_extract(fileobj, dest: Path, take=None) -> list[str]:
    """Extract a tar stream into dest, refusing paths that escape it.

    Args:
        fileobj: The (decompressed) tar stream.
        dest: The destination folder.
        take: Optional callback take(name, member, tar); when it returns True,
            the member is skipped (the callback has handled it).

    Returns:
        The names of the extracted members.
    """
    names = []
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=fileobj, mode="r|*") as tf:
        for m in tf:
            n = m.name.removeprefix("./")
            if not n or n == ".":
                continue
            if take and take(n, m, tf):
                continue
            names.append(n)
            if hasattr(tarfile, "tar_filter"):
                tf.extract(m, dest, filter="tar")     # blocks traversal, strips setuid
            else:  # pragma: no cover
                tf.extract(m, dest)
    return names


def safe_unzip(path: Path, dest: Path) -> None:
    """Extract a zip into dest, keeping Unix modes and refusing paths that escape it.

    Symbolic links (common in zipped Mac apps) are skipped rather than
    written as small text files.

    Raises:
        PackageError: An entry would land outside dest.
    """
    from .unpack import UnpackError, unzip
    try:
        unzip(path, dest)
    except UnpackError as e:
        raise PackageError(str(e)) from e


def _slug(s: str) -> str:
    """Turn a display name into a lower-case name for /opt: 'Foo App 2' -> 'foo-app-2'."""
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "app"


def _desktop_value(text: str, key: str) -> str | None:
    """Return a [Desktop Entry] value; see analyze.desktop_entry_value."""
    from .analyze import desktop_entry_value
    return desktop_entry_value(text, key)


def _set_desktop_exec(text: str, program: str, keep_args: bool = False) -> str:
    """Point Exec= (and TryExec=) at program, keeping field codes like %U.

    With keep_args the other arguments stay too. An AppImage's menu entry names
    the AppImage's own program, which AppRun starts, so its arguments are
    AppRun's: Espanso's is `espanso launcher`.
    """
    from .analyze import parse_exec
    from .desktop import _quote_arg
    out = []
    lines = text.splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]           # Tor Browser's start-*.desktop is also a script
    for line in lines:
        if line.startswith("Exec=") and keep_args:
            line = "Exec=" + " ".join([program, *(_quote_arg(t) for t in parse_exec(line[5:])[2])])
        elif line.startswith("Exec="):
            codes = [t for t in line[5:].split() if re.fullmatch(r"%[fFuUick]", t)]
            line = "Exec=" + " ".join([program, *codes])
        elif line.startswith("TryExec="):
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def _place_icon(src: Path, root: Path, icon_name: str) -> None:
    """Install an icon as icon_name in hicolor, at the standard size nearest the PNG's own (SVGs go in scalable)."""
    if src.suffix.lower() == ".svg":
        d = root / "usr/share/icons/hicolor/scalable/apps"
        name = f"{icon_name}.svg"
    else:
        size = _png_size(src) or 256
        size = min((16, 22, 24, 32, 48, 64, 96, 128, 192, 256, 512), key=lambda s: abs(s - size))
        d = root / f"usr/share/icons/hicolor/{size}x{size}/apps"
        name = f"{icon_name}.png"
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, d / name)


def _png_size(p: Path) -> int | None:
    """Return a PNG's width from its header, or None."""
    try:
        with open(p, "rb") as f:
            head = f.read(24)
        if head[:8] == b"\x89PNG\r\n\x1a\n":
            return struct.unpack(">I", head[16:20])[0]
    except OSError:
        pass
    return None


def _version_from_filename(stem: str) -> tuple[str, str]:
    """Guess (name, version) from a file name: 'Foo-App-1.2.3-linux-x86_64' -> ('Foo-App', '1.2.3')."""
    m = re.match(r"^(?P<name>.+?)[-_ .]v?(?P<ver>\d+(?:\.\d+)+[\w.+~-]*?)(?:[-_.](?:linux|x86_64|amd64|x64|"
                 r"aarch64|arm64|portable|setup|appimage).*)?$", stem, re.I)
    if m:
        return _without_platform(m.group("name")), m.group("ver")
    return _without_platform(stem), "0"


PLATFORM_RE = re.compile(r"[-_. ](linux|x86[-_]64|x86|amd64|x64|aarch64|arm64|portable|setup|appimage)$", re.I)


def _without_platform(name: str) -> str:
    """Drop platform words from the end of a name: 'zen.linux-x86_64' -> 'zen'."""
    while (short := PLATFORM_RE.sub("", name)) != name and short:
        name = short
    return name


def _elf_machine(path: Path) -> str | None:
    """Return the Flatpak architecture of an ELF file from its header, or None."""
    try:
        with open(path, "rb") as f:
            h = f.read(20)
    except OSError:
        return None
    if h[:4] != b"\x7fELF":
        return None
    endian = "<" if h[5] == 1 else ">"
    return ELF_MACHINES.get(struct.unpack(endian + "H", h[18:20])[0])


# --------------------------------------------------------------------------- pacman (.pkg.tar.*)

PACMAN_META = (".PKGINFO", ".MTREE", ".BUILDINFO", ".INSTALL", ".CHANGELOG")


def parse_pkginfo(text: str) -> dict[str, list[str]]:
    """Parse an Arch .PKGINFO file into {key: [values]}; keys like depend repeat."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or " = " not in line:
            continue
        k, _, v = line.partition(" = ")
        out.setdefault(k.strip(), []).append(v.strip())
    return out


def extract_pacman(path: Path, dest: Path) -> Package:
    """Unpack an Arch package, reading .PKGINFO for its metadata.

    The package's .INSTALL file holds bash functions (pre_install,
    post_install, ...) rather than separate scripts, so the whole file is
    checked as the postinst.

    Raises:
        PackageError: The archive has no .PKGINFO.
    """
    root = dest / "root"
    meta = dest / "meta"
    meta.mkdir(parents=True, exist_ok=True)

    def take_meta(name, m, tf):
        if name in PACMAN_META:
            if m.isfile():
                (meta / name[1:]).write_bytes(tf.extractfile(m).read())
            return True
        return False

    with _decompressed(path) as f:      # one streaming pass: metadata aside, payload into root
        _safe_tar_extract(f, root, take_meta)
    if not (meta / "PKGINFO").is_file():
        raise PackageError(f"{path.name}: no .PKGINFO (not a pacman package?)")
    info = parse_pkginfo((meta / "PKGINFO").read_text("utf-8", "replace"))
    first = lambda k, d="": (info.get(k) or [d])[0]  # noqa: E731
    scripts = {}
    if (meta / "INSTALL").is_file():
        # .INSTALL defines pre_install/post_install/... functions in one bash file
        scripts["postinst"] = (meta / "INSTALL").read_text("utf-8", "replace")
    return Package("pacman", path, root, first("pkgname", path.name.split("-")[0]),
                   first("pkgver", "0"), first("arch", "x86_64"), first("pkgdesc"), "", first("url"),
                   " AND ".join(info.get("license", [])), scripts)


# --------------------------------------------------------------------------- AppImage

# uruntime ("anylinux" AppImages) may put a small squashfs of AppImage metadata at the
# ELF boundary, zero-padded to 128 KiB, with the app's DwarFS image after it
DWARFS_METADATA_SLOT = 128 * 1024


def _elf_ends(f) -> list[int]:
    """Return where an ELF runtime may end: the end of its section-header table (the
    AppImage runtime's rule), then the end of its last section or segment (uruntime's).

    Raises:
        PackageError: Not an ELF file.
    """
    f.seek(0)
    h = f.read(64)
    if h[:4] != b"\x7fELF" or len(h) < 52:
        raise PackageError("not an ELF AppImage")
    e = "<" if h[5] == 1 else ">"
    if h[4] == 2:      # 64-bit
        phoff, shoff = struct.unpack(e + "QQ", h[0x20:0x30])
        phentsize, phnum, shentsize, shnum = struct.unpack(e + "HHHH", h[0x36:0x3E])
        word, seg_at, sec_at = e + "Q", (8, 32), (24, 32)      # where p_offset/p_filesz, sh_offset/sh_size are
    else:
        phoff, shoff = struct.unpack(e + "II", h[0x1C:0x24])
        phentsize, phnum, shentsize, shnum = struct.unpack(e + "HHHH", h[0x2A:0x32])
        word, seg_at, sec_at = e + "I", (4, 16), (16, 20)
    table_end = shoff + shentsize * shnum
    last = max(table_end, phoff + phentsize * phnum)
    for off, n, size, (at_off, at_size), is_section in ((phoff, phnum, phentsize, seg_at, False),
                                                       (shoff, shnum, shentsize, sec_at, True)):
        if not n or size < at_size + struct.calcsize(word):
            continue
        f.seek(off)
        table = f.read(n * size)
        for i in range(len(table) // size):
            entry = table[i * size:(i + 1) * size]
            if is_section and struct.unpack_from(e + "I", entry, 4)[0] == 8:   # SHT_NOBITS (.bss): no file data
                continue
            start, length = struct.unpack_from(word, entry, at_off)[0], struct.unpack_from(word, entry, at_size)[0]
            if length:
                last = max(last, start + length)
    return [table_end] if last == table_end else [table_end, last]


# how far past the ELF's end to look for an image that a runtime placed at an aligned offset
IMAGE_SCAN_LIMIT = 4 * 1024 * 1024


def _squashfs_superblock(head: bytes) -> bool:
    """Return True if head starts with a plausible squashfs 4 superblock (not just the magic)."""
    if len(head) < 32 or head[:4] != b"hsqs":
        return False
    block_size, = struct.unpack_from("<I", head, 12)
    block_log, = struct.unpack_from("<H", head, 22)
    major, = struct.unpack_from("<H", head, 28)
    return major == 4 and 12 <= block_log <= 20 and block_size == 1 << block_log


def _scan_for_image(f, start: int) -> tuple[int, str] | None:
    """Look for a squashfs or DwarFS image a little after the ELF's end, for runtimes that
    pad or align it. Returns (offset, kind) or None."""
    f.seek(start)
    data = f.read(IMAGE_SCAN_LIMIT + 64)
    hits = []
    for magic, kind in ((b"hsqs", "squashfs"), (b"DWARFS\x02", "dwarfs")):
        i = data.find(magic)
        while i != -1:
            if kind == "dwarfs" or _squashfs_superblock(data[i:i + 32]):
                hits.append((i, kind))
                break
            i = data.find(magic, i + 1)
    if not hits:
        return None
    i, kind = min(hits)
    return start + i, kind


def appimage_image(path: Path) -> tuple[int, str]:
    """Return where an AppImage's filesystem image starts and its kind, "squashfs" or "dwarfs".

    Type 2 AppImages append a squashfs to the ELF runtime; uruntime ("anylinux",
    sharun) AppImages may append a DwarFS image instead (magic "DWARFS").

    Raises:
        PackageError: Not an ELF file, a type 1 (ISO 9660) AppImage, or no image found.
    """
    with open(path, "rb") as f:
        try:
            ends = _elf_ends(f)
        except PackageError as e:
            raise PackageError(f"{path.name}: {e}") from None
        f.seek(8)
        type1 = f.read(3) == b"AI\x01"
        for off in ends:
            f.seek(off)
            head = f.read(48)
            if head[:6] == b"DWARFS":
                return off, "dwarfs"
            if head[:4] == b"hsqs":
                used = struct.unpack("<Q", head[40:48])[0] if len(head) == 48 else 0
                if used <= DWARFS_METADATA_SLOT:
                    f.seek(off + DWARFS_METADATA_SLOT)
                    if f.read(6) == b"DWARFS":
                        return off + DWARFS_METADATA_SLOT, "dwarfs"
                return off, "squashfs"
        found = _scan_for_image(f, max(ends))
        if found:
            return found
    if type1:
        raise PackageError(f"{path.name}: a type 1 AppImage (ISO 9660), which isn't supported")
    raise PackageError(f"{path.name}: no squashfs or DwarFS image after the AppImage runtime "
                       "(damaged download, or a type 1 AppImage, which is ISO 9660 and not supported)")


def appimage_offset(path: Path) -> int:
    """Return where an AppImage's filesystem image (squashfs or DwarFS) starts.

    Raises:
        PackageError: Not an ELF file, a type 1 (ISO 9660) AppImage, or no image found.
    """
    return appimage_image(path)[0]


def _unpack_appimage(path: Path, out: Path, allow_run: bool) -> None:
    """Unpack an AppImage's squashfs with unsquashfs (a DwarFS image with
    dwarfsextract), or with the AppImage itself.

    Raises:
        PackageError: The tool for the image is missing and allow_run is False,
            or the unpacking failed.
    """
    off, kind = appimage_image(path)
    if kind == "squashfs" and (us := shutil.which("unsquashfs")):
        r = subprocess.run([us, "-no-xattrs", "-o", str(off), "-d", str(out), str(path)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise PackageError(f"unsquashfs failed: {r.stderr.strip()[-400:]}")
        return
    if kind == "dwarfs" and (dx := shutil.which("dwarfsextract")):
        out.mkdir(parents=True, exist_ok=True)          # dwarfsextract wants an existing folder
        r = subprocess.run([dx, "-i", str(path), "-o", str(out), f"--image-offset={off}"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise PackageError(f"dwarfsextract failed: {r.stderr.strip()[-400:]}")
        return
    if allow_run:
        # The AppImage's own runtime can unpack itself; this executes the file.
        work = out.parent
        exe = work / "appimage.bin"
        shutil.copy2(path, exe)
        exe.chmod(0o755)
        r = subprocess.run([str(exe), "--appimage-extract"], cwd=work, capture_output=True, text=True,
                           env={**os.environ, "APPIMAGE_EXTRACT_AND_RUN": ""}, timeout=600)
        exe.unlink()
        link = work / "squashfs-root"
        if r.returncode != 0 or not link.is_dir():
            raise PackageError(f"--appimage-extract failed: {r.stderr.strip()[-400:]}")
        # uruntime unpacks into AppDir and makes squashfs-root a symlink to it
        link.resolve().rename(out)
        if link.is_symlink():
            link.unlink()
        return
    if kind == "dwarfs":
        raise PackageError("this AppImage holds a DwarFS image (an uruntime/\"anylinux\" AppImage); unpacking it "
                           "needs `dwarfsextract` (package dwarfs), or pass --allow-run to let the AppImage unpack "
                           "itself (that runs it)")
    raise PackageError("unpacking an AppImage needs `unsquashfs` (package squashfs-tools), or pass "
                       "--allow-run to let the AppImage unpack itself (that runs it)")


def extract_appimage(path: Path, dest: Path, allow_run: bool = False) -> Package:
    """Unpack an AppImage into opt/<name>, with AppRun as the entry point.

    The name and version come from the AppImage's own .desktop file, else from
    its file name. The .desktop file is installed pointing at AppRun, along with
    its icon (or .DirIcon).
    """
    dest.mkdir(parents=True, exist_ok=True)
    appdir = dest / "appdir"
    _unpack_appimage(path, appdir, allow_run)
    desktops = sorted(d for d in appdir.glob("*.desktop") if d.is_file())
    text = desktops[0].read_text("utf-8", "replace") if desktops else ""
    display = _desktop_value(text, "Name") if text else None
    fname, fver = _version_from_filename(path.stem)
    name = _slug(display or fname)
    version = (_desktop_value(text, "X-AppImage-Version") if text else None) or fver
    root = dest / "root"
    opt = root / "opt" / name
    opt.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(appdir), str(opt))
    entry = f"/opt/{name}/AppRun"
    if text:
        icon = _desktop_value(text, "Icon") or name
        apps = root / "usr/share/applications"
        apps.mkdir(parents=True, exist_ok=True)
        (apps / f"{name}.desktop").write_text(_set_desktop_exec(text, entry, keep_args=True))
        for cand in [opt / f"{icon}.svg", opt / f"{icon}.png", opt / ".DirIcon"]:
            real = cand.resolve()
            # .DirIcon is usually a symlink; only follow links that stay inside the AppDir
            if real.is_file() and opt.resolve() in real.parents:
                _place_icon(real, root, icon)
                break
    arch = _elf_machine(path) or "x86_64"
    pkg = Package("appimage", path, root, name, version, arch,
                  (_desktop_value(text, "Comment") if text else "") or "", "", "", "", {},
                  default_exec=entry, extra={"opt_name": name})
    pkg.notes.append("AppImage contents are under /app/opt/" + name + "; AppRun is the entry point")
    if (moved := unwrap_sharun(opt)):
        pkg.extra["sharun"] = moved
        pkg.notes.append("a sharun AppImage: put the real programs from shared/bin in place of the launcher "
                         "copies of " + ", ".join(t for _real, targets in moved for t in targets))
    # uim's GTK input module reads its Scheme files from /usr/share/uim, which no
    # Flatpak runtime has, and exits the app when they're missing (Xournal++)
    dropped = [p for p in opt.rglob("im-uim.so*") if p.is_file() or p.is_symlink()]
    for p in dropped:
        p.unlink()
    if dropped:
        pkg.notes.append("removed the bundled uim input module (it needs /usr/share/uim, which the runtime "
                         "lacks, and quits the app without it)")
    return pkg


def _self_contained(path: Path) -> bool:
    """Return True for a statically linked program, which runs without sharun's loader."""
    from .elf import ElfError, read_elf
    try:
        info = read_elf(path, want_symbols=False)
    except (ElfError, OSError):
        return False
    return info.interp is None and not info.needed


def unwrap_sharun(opt: Path) -> list[tuple[str, list[str]]]:
    """Put a sharun AppDir's real programs in place of the launcher copies that stand for them.

    sharun (anylinux AppImages) replaces each program with a copy of one static
    launcher, which starts the real one in shared/bin with the bundled glibc's loader
    and libraries, after AppRun's hooks; one of them tries `unshare -Urm`, which fails
    in Flatpak with "unprivileged user-namespaces are disabled". A Chromium or Electron
    program has to run under zypak instead, and it doesn't need sharun: it finds its
    own libraries beside it by RPATH $ORIGIN and the rest in the runtime, so the real
    program goes in the folder that holds Chromium's resources.pak, with its helpers
    (chrome-sandbox, chrome_crashpad_handler). Statically linked programs (VSCodium's
    rg) go wherever a launcher copy stands for them. Other programs keep the launcher,
    since they may need the bundled glibc, which can't go on LD_LIBRARY_PATH under the
    runtime's loader.

    Returns:
        (real program, launcher copies it replaced) pairs, relative to opt; the last
        copy gets the file itself and the others a copy, which apply_extra repeats.
    """
    from .elf import is_sharun
    shared = opt / "shared" / "bin"
    if not shared.is_dir() or shared.is_symlink() or not any(is_sharun(opt / n) for n in ("sharun", "AppRun")):
        return []
    real = {p.name: p for p in shared.iterdir() if p.is_file() and not p.is_symlink()}
    chromium = set()
    copies: dict[str, list[Path]] = {}
    for top, dirs, files in os.walk(opt):
        here = Path(top)
        if here == shared:
            continue
        if "resources.pak" in files and ({"v8_context_snapshot.bin", "snapshot_blob.bin"} & set(files)):
            chromium.add(here)
        if here == opt:
            continue    # AppRun and sharun itself
        for f in files:
            if f in real and is_sharun(here / f):
                copies.setdefault(f, []).append(here / f)
    out = []
    for name, stubs in sorted(copies.items()):
        stubs = [s for s in sorted(stubs) if s.parent in chromium or _self_contained(real[name])]
        if not stubs:
            continue
        for s in stubs:
            # a hard link to the launcher is unlinked first; writing through it would overwrite AppRun
            s.unlink()
        for s in stubs[:-1]:
            shutil.copy2(real[name], s)
        real[name].rename(stubs[-1])
        out.append((real[name].relative_to(opt).as_posix(), [s.relative_to(opt).as_posix() for s in stubs]))
    return out


# --------------------------------------------------------------------------- plain archives

def extract_tarball(path: Path, dest: Path) -> Package:
    """Unpack a vendor's archive (.tar.*, .zip) into opt/<name>.

    A single top-level folder is stripped. The entry point is the program a
    .desktop file in the archive runs, else the one named like the app, else the
    largest (see archive_entry_point); --exec overrides it.
    Name and version come from the file name, such as App-1.2.3-linux-x64.tar.gz.

    Raises:
        PackageError: A zip entry would land outside the destination.
    """
    raw = dest / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(path):
        safe_unzip(path, raw)
    else:
        with _decompressed(path) as f:
            _safe_tar_extract(f, raw)
    stem = re.sub(r"\.(tar\.(gz|xz|bz2|zst)|tgz|txz|tbz2?|tar|zip)$", "", path.name, flags=re.I)
    return _archive_package("tarball", path, dest, raw, *_version_from_filename(stem))


def archive_entry_point(opt: Path, want: set[str]) -> tuple[Path | None, Path | None]:
    """Choose the program an unpacked archive starts, and the .desktop file that goes with it.

    The program a .desktop file in the archive runs comes first (kitty's tarball
    ships share/applications/kitty.desktop, which runs bin/kitty, beside the
    larger bin/kitten), then the one _archive_entry picks. A .desktop file named
    like the app, and one in an applications folder, are tried first.

    Args:
        opt: The unpacked archive.
        want: Names the app goes by, lower case.

    Returns:
        (program, .desktop file); either can be None.
    """
    from .analyze import parse_exec
    # only files: a Java runtime's legal/java.desktop is a folder
    desktops = sorted((d for d in opt.rglob("*.desktop") if d.is_file()),
                      key=lambda d: (d.stem.lower() not in want, "applications" not in d.parts, d.as_posix()))
    folders = [opt] + sorted(d for d in opt.iterdir() if d.is_dir() and not d.is_symlink())
    for d in desktops:
        text = d.read_text("utf-8", "replace")
        exec_line = _desktop_value(text, "Exec")
        if not exec_line or _desktop_value(text, "NoDisplay") == "true":
            continue
        _env, prog, _args = parse_exec(exec_line)
        base = Path(prog).name if prog else ""
        if not base or base in (".", ".."):
            continue
        hits = [p for f in folders for p in _programs(f) if p.name == base]
        if not hits:     # the program sits deeper in the archive, such as lib/app/app
            hits = [p for p in sorted(opt.rglob("*")) if p.name == base and not p.is_symlink()
                    and p.parent not in folders and p in _programs(p.parent)]
        if hits:
            return hits[0], d
    return _archive_entry(opt, want), (desktops[0] if desktops else None)


def _restore_exec_bits(root: Path) -> None:
    """Make the programs in an unpacked archive executable when the archive didn't say they are.

    A zip made on Windows carries no Unix modes (WindTerm's, Psych Engine's), so its
    programs came out unexecutable ("Permission denied"). A file counts as a
    program when it's an ELF executable: it has an interpreter or is ET_EXEC.
    """
    from .elf import ElfError, read_elf
    for f in root.rglob("*"):
        if f.is_symlink() or not f.is_file() or os.stat(f).st_mode & 0o111:
            continue
        try:
            with open(f, "rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    continue
            if read_elf(f, want_symbols=False).is_executable:
                os.chmod(f, os.stat(f).st_mode | 0o755)
        except (OSError, ElfError):
            continue


def _archive_package(fmt: str, path: Path, dest: Path, raw: Path, display: str, version: str) -> Package:
    """Move unpacked files from raw into root/opt/NAME and find the entry point, desktop file and icon.

    Shared by extract_tarball and extract_run.
    """
    entries = [e for e in raw.iterdir() if not e.name.startswith(".")] if raw.is_dir() else []
    strip = 1 if len(entries) == 1 and entries[0].is_dir() else 0
    top = entries[0] if strip else raw
    name = _slug(display)
    root = dest / "root"
    opt = root / "opt" / name
    opt.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(top), str(opt))
    _restore_exec_bits(opt)

    extra = {"opt_name": name, "strip": strip}
    notes = []
    want = {name, display.lower(), name.replace("-", "")}
    main = _tor_style_browser(opt, want)
    if main:
        # Tor Browser and Mullvad Browser run in portable mode, keeping the profile beside
        # the program, which is read-only in a Flatpak; this file turns that off
        extra["marker"] = (main.parent / "is-packaged-app").relative_to(opt).as_posix()
        (opt / extra["marker"]).touch()
        notes.append(f"a Tor Browser-style bundle: starting {main.relative_to(opt)} directly (its start script "
                     "sets HOME to the read-only bundle), with is-packaged-app beside it so the profile isn't "
                     "kept in the bundle")
        desktop = next(iter(sorted(d for d in opt.rglob("*.desktop") if d.is_file())), None)
    else:
        main, desktop = archive_entry_point(opt, want)
    main_rel = main.relative_to(opt).as_posix() if main else None
    default_exec = f"/opt/{name}/{main_rel}" if main else None

    pkg_desc = ""
    if desktop and default_exec:
        text = desktop.read_text("utf-8", "replace")
        apps = root / "usr/share/applications"
        apps.mkdir(parents=True, exist_ok=True)
        (apps / f"{name}.desktop").write_text(_set_desktop_exec(text, default_exec))
        pkg_desc = _desktop_value(text, "Comment") or ""
        icon = _desktop_value(text, "Icon")
        if icon and not icon.startswith("/"):
            for cand in sorted(opt.rglob(f"{icon}.svg")) + sorted(opt.rglob(f"{icon}.png")):
                _place_icon(cand, root, icon)
                break
    arch = (_elf_machine(main) if main else None) or ""
    pkg = Package(fmt, path, root, name, version, arch, pkg_desc, default_exec=default_exec, extra=extra)
    pkg.notes.append(f"archive contents are under /app/opt/{name}"
                     + (f"; entry point {main_rel} (guessed; override with --exec)" if main else
                        "; no executable found, pass --exec"))
    pkg.notes += notes
    return pkg


def _programs(folder: Path) -> list[Path]:
    """Return the programs directly in folder: executable ELF programs (not shared
    libraries, which vendors often mark executable too) and scripts, but not .desktop
    files, which Tor Browser makes executable."""
    from .elf import ElfError, read_elf
    out = []
    for p in sorted(folder.iterdir()):
        if not p.is_file() or not os.access(p, os.X_OK) or p.name.endswith(".desktop") or \
                re.search(r"\.so(\.[0-9]+)*$", p.name):
            continue
        with open(p, "rb") as f:
            head = f.read(4)
        if head[:2] == b"#!":
            out.append(p)
        elif head == b"\x7fELF":
            try:
                if read_elf(p, want_symbols=False).is_shared_library:
                    continue
            except ElfError:
                pass            # can't tell; keep it
            out.append(p)
    return out


def _for_this_cpu(programs: list[Path]) -> list[Path]:
    """Drop programs built for another processor when some are built for this one.

    Ventoy's archive has VentoyGUI.x86_64, .i386, .aarch64 and .mips64el side
    by side, and the largest was for MIPS. Scripts always stay.
    """
    from .runtime import host_arch
    here = host_arch()
    if not any(_elf_machine(p) == here for p in programs):
        return programs
    keep = []
    for p in programs:
        with open(p, "rb") as f:
            elf = f.read(4) == b"\x7fELF"
        if not elf or _elf_machine(p) == here:
            keep.append(p)
    return keep


def _archive_entry(opt: Path, want: set[str]) -> Path | None:
    """Return an archive's main program: one named like the app, else the largest, at the
    top level, else in a folder one level down (an app kept in bin/ or Browser/)."""
    from .analyze import HELPER_NAME_RE, _is_electron_helper
    for folder in [opt] + sorted(d for d in opt.iterdir() if d.is_dir() and not d.is_symlink()):
        execs = _for_this_cpu(_programs(folder))
        main = next((p for p in execs if p.name.lower() in want or p.stem.lower() in want), None)
        if main is None and execs:
            # helpers and command-line twins (app-cli, app_helper, chrome-sandbox) come last
            main = max(execs, key=lambda p: (not (HELPER_NAME_RE.search(p.name) or _is_electron_helper(p.name)),
                                             p.stat().st_size))
        if main:
            return main
    return None


def _tor_style_browser(opt: Path, want: set[str]) -> Path | None:
    """Return the browser program of a Tor Browser-style bundle (Tor Browser, Mullvad Browser), or None.

    Such a bundle's top level holds only start-*.desktop, an executable .desktop file
    whose X-*-ExecShell= names the start script (./Browser/start-mullvad-browser). That
    script sets HOME to its own read-only folder and runs the browser, which is the
    program in that folder the script names (the largest, as it also runs ./abicheck),
    or NAME.real when the script names NAME and NAME is itself a wrapper script.
    """
    for d in sorted(d for d in opt.glob("*.desktop") if d.is_file()):
        text = d.read_text("utf-8", "replace")
        m = re.search(r"^X-[A-Za-z]+-ExecShell=\s*(\S+)", text, re.M)
        if not m:
            continue
        script = (opt / m.group(1)).resolve()
        if not script.is_file() or opt.resolve() not in script.parents:
            continue
        body = script.read_text("utf-8", "replace")
        folder = opt / script.parent.relative_to(opt.resolve())
        progs = _programs(folder)
        elfs = [p for p in progs if _elf_machine(p)]
        named = [p for p in progs if re.search(rf"(^|[/\s\"']){re.escape(p.name)}($|[\s\"'])", body, re.M)]
        # Mullvad Browser 16's mullvadbrowser is a wrapper script that runs mullvadbrowser.real
        named = [p.with_name(p.name + ".real") if p not in elfs and p.with_name(p.name + ".real") in elfs else p
                 for p in named]
        named = [p for p in named if p in elfs]
        if named:
            return max(named, key=lambda p: p.stat().st_size)
        return next((p for p in elfs if p.name.lower() in want), None)
    return None


# --------------------------------------------------------------------------- .run installers

MAKESELF_RE = re.compile(rb"Makeself|^filesizes=\"\d", re.M)


def _makeself_layout(head: bytes) -> tuple[int, int, str | None]:
    """Return (header line count, payload size, setup script) from a Makeself header.

    Raises:
        PackageError: The header doesn't say where the payload is, or the payload is encrypted.
    """
    text = head.decode("latin-1")
    if re.search(r'^ENCRYPT="?(gpg|openssl)', text, re.M) or "gpg -d" in text or "openssl enc -d" in text:
        raise PackageError("this .run installer is encrypted; debpak can't open it")
    sizes = re.search(r'^filesizes="([\d ]+)"', text, re.M)
    lines = re.search(r'^skip="(\d+)"', text, re.M) or re.search(r'head -n "?(\d+)"? ', text) or \
        re.search(r'^SKIP="?(\d+)', text, re.M)
    if not (sizes and lines):
        raise PackageError("not a Makeself installer debpak understands (no filesizes= or header length)")
    script = re.search(r'^script="([^"]*)"', text, re.M)
    return int(lines.group(1)), sum(int(x) for x in sizes.group(1).split()), (script.group(1) if script else None)


def extract_run(path: Path, dest: Path) -> Package:
    """Unpack a self-extracting .run installer into opt/<name>, without running it.

    Two kinds are understood. A GOG/MojoSetup game installer carries a zip
    after its scripts, with the game in data/noarch/game. A Makeself
    installer carries a tar archive (plain, gzip, bzip2, xz or zstd) after a
    header of known length. Makeself's own setup script isn't run; its text is
    kept as the postinst script so the host-integration checks read it.

    Raises:
        PackageError: The payload can't be found, is encrypted, or isn't a tar archive.
    """
    raw = dest / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"\.(run|sh|bin)$", "", path.name, flags=re.I)
    display, version = _version_from_filename(stem)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if any(i.flag_bits & 0x1 for i in z.infolist()):
                raise PackageError(f"{path.name}: the installer's files are encrypted")
            info = z.read("data/noarch/gameinfo").decode("utf-8", "replace").splitlines() \
                if "data/noarch/gameinfo" in names else []
        if not any(n.startswith("data/noarch/game/") for n in names):
            raise PackageError(f"{path.name}: a zip after a script, but not a GOG game (no data/noarch/game)")
        unz = dest / "unzipped"
        safe_unzip(path, unz)
        shutil.move(str(unz / "data/noarch/game"), str(raw / "game"))
        if len(info) >= 2:
            display, version = info[0].strip() or display, info[1].strip() or version
        pkg = _archive_package("run", path, dest, raw, display, version)
        pkg.extra["replay"] = {"steps": [{"kind": "zip"}], "take": "data/noarch/game", "drop": []}
        start = unz / "data/noarch/start.sh"
        if start.is_file():
            pkg.scripts["postinst"] = start.read_text("utf-8", "replace")
        pkg.notes.insert(0, "GOG game installer: took the game from data/noarch/game")
        return pkg

    with open(path, "rb") as f:
        head = f.read(1 << 20)          # headers with a long license text run past 64 KB
    nlines, size, script = _makeself_layout(head)
    offset = 0
    for _ in range(nlines):
        nl = head.find(b"\n", offset)
        if nl == -1:
            raise PackageError(f"{path.name}: header shorter than the {nlines} lines it claims")
        offset = nl + 1
    payload = dest / "payload"
    with open(path, "rb") as src, open(payload, "wb") as out:
        src.seek(offset)
        remaining = size
        while remaining > 0:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                raise PackageError(f"{path.name}: payload is {size - remaining} bytes, expected {size}")
            out.write(chunk)
            remaining -= len(chunk)
    with open(payload, "rb") as f:
        zstd = f.read(4) == b"\x28\xb5\x2f\xfd"
    try:
        with _decompressed(payload) as f:
            _safe_tar_extract(f, raw)
    except tarfile.TarError as e:
        raise PackageError(f"{path.name}: the payload isn't a tar archive ({e})") from e
    payload.unlink()
    entries = [e for e in raw.iterdir() if not e.name.startswith(".")]
    top = entries[0].name if len(entries) == 1 and entries[0].is_dir() else ""
    label = re.search(rb'^label="([^"]*)"', head, re.M)
    script_text = None
    if script:
        rel = script.split()[0].removeprefix("./")
        cand = raw / rel
        if cand.is_file() and not cand.is_symlink():
            data = cand.read_bytes()
            if b"\0" not in data[:8192]:         # a program, not a script: nothing to check
                script_text = data.decode("utf-8", "replace")
    pkg = _archive_package("run", path, dest, raw, display, version)
    if not zstd:            # unpack.py has no zstd decoder (the runtime's Python lacks one)
        pkg.extra["replay"] = {"steps": [{"kind": "makeself", "offset": offset, "size": size}], "take": top,
                               "drop": []}
    if label and pkg.summary == "":
        pkg.summary = label.group(1).decode("utf-8", "replace").strip()
    if script_text is not None:
        pkg.scripts["postinst"] = script_text
        pkg.notes.insert(0, f"Makeself installer: unpacked without running its setup script ({script}); the "
                            "checks below read that script")
    elif script:
        pkg.notes.insert(0, f"Makeself installer: its setup script ({script}) wasn't run")
    return pkg
