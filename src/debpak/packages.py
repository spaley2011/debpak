"""Input packages of every format debpak converts.

Each format is unpacked into the same shape the rest of the pipeline expects:
a `root` directory laid out like an installed system (usr/..., opt/...), plus
name, version, architecture, description, homepage, license and the
package's install scripts under Debian's names (preinst, postinst, prerm,
postrm), so the host-integration checks read them the same way.

  .deb                    deb.py
  .rpm                    rpm.py (pure Python: headers + cpio payload)
  .pkg.tar.{zst,xz,gz}    Arch Linux / pacman: tar with .PKGINFO and .INSTALL
  .AppImage               squashfs after an ELF runtime; placed under opt/NAME
  .tar.gz/.tar.xz/.zip    a vendor's "unpack and run" archive; placed under opt/NAME
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import re
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
FORMATS = ("deb", "rpm", "pacman", "appimage", "tarball")


class PackageError(Exception):
    pass


@dataclass
class Package:
    format: str
    path: Path
    root: Path
    name: str
    version: str = "0"
    pkg_arch: str = ""            # the format's own architecture name (amd64, x86_64, any, noarch ...)
    summary: str = ""
    long_description: str = ""
    homepage: str = ""
    license: str = ""
    scripts: dict[str, str] = field(default_factory=dict)   # preinst/postinst/prerm/postrm
    default_exec: str | None = None   # entry point when the package has no .desktop file
    notes: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)                # format-specific (extra-data unpacking)

    @property
    def flatpak_arch(self) -> str | None:
        if self.pkg_arch in ("noarch", "any", "all", ""):
            return None
        return ARCH_TO_FLATPAK.get(self.pkg_arch)

    @property
    def deb_arch(self) -> str:      # older callers
        return self.pkg_arch

    @property
    def control(self) -> dict[str, str]:   # older callers
        return {"Package": self.name, "Version": self.version, "Homepage": self.homepage}

    def maintainer_script(self, name: str) -> str | None:
        return self.scripts.get(name)


# --------------------------------------------------------------------------- detection

def detect_format(path: str | Path) -> str:
    p = Path(path)
    with open(p, "rb") as f:
        head = f.read(512)
    if head.startswith(b"!<arch>\n"):
        return "deb"
    if head[:4] == b"\xed\xab\xee\xdb":
        return "rpm"
    if head[:4] == b"\x7fELF":
        if head[8:11] in (b"AI\x02", b"AI\x01"):
            return "appimage"
        raise PackageError(f"{p}: an ELF program, not a package (to check one binary use `debpak smoke --exec`)")
    name = p.name.lower()
    if re.search(r"\.pkg\.tar(\.(zst|xz|gz|bz2))?$", name):
        return "pacman"
    if name.endswith(".appimage"):
        return "appimage"
    if re.search(r"\.(tar\.(gz|xz|bz2|zst)|tgz|txz|tbz2?|tar|zip)$", name) or head[:2] == b"PK" or \
            head[:2] == b"\x1f\x8b" or head[:6] == b"\xfd7zXZ\x00" or head[:4] == b"\x28\xb5\x2f\xfd":
        return "tarball"
    raise PackageError(f"{p}: unknown package format (supported: {', '.join(FORMATS)})")


def open_package(path: str | Path, dest: str | Path, allow_run: bool = False):
    """Unpack any supported package into dest; returns a Package (or DebPackage)."""
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
    return extract_tarball(path, dest)


def is_package_file(p: Path) -> bool:
    n = p.name.lower()
    return n.endswith((".deb", ".rpm")) or bool(re.search(r"\.pkg\.tar(\.(zst|xz|gz|bz2))?$", n))


# --------------------------------------------------------------------------- shared helpers

def _decompressed(path: Path):
    """A file object for a (possibly compressed) archive, by its magic bytes."""
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
    """Stream-extract a tar, refusing paths that escape dest. `take(name, member, tar)` may
    claim a member (return True) so it isn't extracted. Returns the extracted names."""
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


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "app"


def _desktop_value(text: str, key: str) -> str | None:
    from .analyze import desktop_entry_value
    return desktop_entry_value(text, key)


def _set_desktop_exec(text: str, program: str) -> str:
    """Point Exec= (and TryExec=) at program, keeping field codes like %U."""
    out = []
    for line in text.splitlines():
        if line.startswith("Exec="):
            codes = [t for t in line[5:].split() if re.fullmatch(r"%[fFuUick]", t)]
            line = "Exec=" + " ".join([program, *codes])
        elif line.startswith("TryExec="):
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def _place_icon(src: Path, root: Path, icon_name: str) -> None:
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
    try:
        with open(p, "rb") as f:
            head = f.read(24)
        if head[:8] == b"\x89PNG\r\n\x1a\n":
            return struct.unpack(">I", head[16:20])[0]
    except OSError:
        pass
    return None


def _version_from_filename(stem: str) -> tuple[str, str]:
    """('Foo-App', '1.2.3') from 'Foo-App-1.2.3-linux-x86_64'."""
    m = re.match(r"^(?P<name>.+?)[-_ .]v?(?P<ver>\d+(?:\.\d+)+[\w.+~-]*?)(?:[-_.](?:linux|x86_64|amd64|x64|"
                 r"aarch64|arm64|portable|setup|appimage).*)?$", stem, re.I)
    if m:
        return m.group("name"), m.group("ver")
    return stem, "0"


def _elf_machine(path: Path) -> str | None:
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
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or " = " not in line:
            continue
        k, _, v = line.partition(" = ")
        out.setdefault(k.strip(), []).append(v.strip())
    return out


def extract_pacman(path: Path, dest: Path) -> Package:
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

def appimage_offset(path: Path) -> int:
    """Where the squashfs starts: right after the ELF runtime (its section headers end it)."""
    with open(path, "rb") as f:
        h = f.read(64)
        if h[:4] != b"\x7fELF":
            raise PackageError(f"{path.name}: not an ELF AppImage")
        endian = "<" if h[5] == 1 else ">"
        if h[4] == 2:      # 64-bit
            shoff, = struct.unpack(endian + "Q", h[0x28:0x30])
            shentsize, shnum = struct.unpack(endian + "HH", h[0x3A:0x3E])
        else:
            shoff, = struct.unpack(endian + "I", h[0x20:0x24])
            shentsize, shnum = struct.unpack(endian + "HH", h[0x2E:0x32])
        off = shoff + shentsize * shnum
        f.seek(off)
        if f.read(4) != b"hsqs":
            raise PackageError(f"{path.name}: no squashfs image after the runtime (type 1 AppImages "
                               "are ISO 9660 and not supported)")
    return off


def _unpack_appimage(path: Path, out: Path, allow_run: bool) -> None:
    off = appimage_offset(path)
    if us := shutil.which("unsquashfs"):
        r = subprocess.run([us, "-no-xattrs", "-o", str(off), "-d", str(out), str(path)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise PackageError(f"unsquashfs failed: {r.stderr.strip()[-400:]}")
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
        if r.returncode != 0 or not (work / "squashfs-root").is_dir():
            raise PackageError(f"--appimage-extract failed: {r.stderr.strip()[-400:]}")
        (work / "squashfs-root").rename(out)
        return
    raise PackageError("unpacking an AppImage needs `unsquashfs` (package squashfs-tools), or pass "
                       "--allow-run to let the AppImage unpack itself (that runs it)")


def extract_appimage(path: Path, dest: Path, allow_run: bool = False) -> Package:
    dest.mkdir(parents=True, exist_ok=True)
    appdir = dest / "appdir"
    _unpack_appimage(path, appdir, allow_run)
    desktops = sorted(appdir.glob("*.desktop"))
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
        (apps / f"{name}.desktop").write_text(_set_desktop_exec(text, entry))
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
    return pkg


# --------------------------------------------------------------------------- plain archives

def extract_tarball(path: Path, dest: Path) -> Package:
    raw = dest / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                target = (raw / info.filename).resolve()
                if not str(target).startswith(str(raw.resolve()) + os.sep) and target != raw.resolve():
                    raise PackageError(f"{path.name}: unsafe path {info.filename!r}")
                z.extract(info, raw)
                mode = (info.external_attr >> 16) & 0o777
                if mode and not info.is_dir():
                    os.chmod(target, mode)
    else:
        with _decompressed(path) as f:
            _safe_tar_extract(f, raw)
    entries = [e for e in raw.iterdir() if not e.name.startswith(".")] if raw.is_dir() else []
    strip = 1 if len(entries) == 1 and entries[0].is_dir() else 0
    top = entries[0] if strip else raw
    stem = re.sub(r"\.(tar\.(gz|xz|bz2|zst)|tgz|txz|tbz2?|tar|zip)$", "", path.name, flags=re.I)
    display, version = _version_from_filename(stem)
    name = _slug(display)
    root = dest / "root"
    opt = root / "opt" / name
    opt.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(top), str(opt))

    # entry point: an executable named like the app, else the only (or largest) top-level executable
    execs = [p for p in opt.iterdir() if p.is_file() and os.access(p, os.X_OK) and
             (_elf_machine(p) or p.read_bytes()[:2] == b"#!")]
    want = {name, display.lower(), name.replace("-", "")}
    main = next((p for p in execs if p.name.lower() in want or p.stem.lower() in want), None)
    if main is None and execs:
        main = max(execs, key=lambda p: p.stat().st_size)
    default_exec = f"/opt/{name}/{main.name}" if main else None

    desktops = sorted(opt.rglob("*.desktop"))
    pkg_desc = ""
    if desktops and default_exec:
        text = desktops[0].read_text("utf-8", "replace")
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
    pkg = Package("tarball", path, root, name, version, arch, pkg_desc, default_exec=default_exec,
                  extra={"opt_name": name, "strip": strip})
    pkg.notes.append(f"archive contents are under /app/opt/{name}"
                     + (f"; entry point {main.name} (guessed; override with --exec)" if main else
                        "; no executable found, pass --exec"))
    return pkg
