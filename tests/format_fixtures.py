"""Writers for the non-.deb formats, built from the same package trees the .deb
fixtures use: RPM (lead, signature and main headers, gzip/xz cpio payload, with
the header and payload SHA-256 digests rpm itself writes), Arch packages,
vendor tarballs and AppImages (an ELF runtime followed by a squashfs marker)."""
from __future__ import annotations

import gzip
import hashlib
import io
import lzma
import os
import stat
import struct
import tarfile
from pathlib import Path

# ------------------------------------------------------------------ RPM

STRING, STRING_ARRAY, INT32, BIN, I18N = 6, 8, 4, 7, 9


def _header(entries: list[tuple[int, int, object]]) -> bytes:
    """An RPM header structure from (tag, type, value) entries."""
    index, store = b"", bytearray()
    for tag, typ, value in sorted(entries, key=lambda e: e[0]):
        if typ == INT32:
            while len(store) % 4:
                store += b"\0"
            vals = value if isinstance(value, list) else [value]
            off, count, data = len(store), len(vals), struct.pack(f">{len(vals)}I", *vals)
        elif typ in (STRING_ARRAY, I18N):
            vals = value if isinstance(value, list) else [value]
            off, count, data = len(store), len(vals), b"".join(v.encode() + b"\0" for v in vals)
        elif typ == BIN:
            off, count, data = len(store), len(value), value
        else:
            off, count, data = len(store), 1, str(value).encode() + b"\0"
        store += data
        index += struct.pack(">IIII", tag, typ, off, count)
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", len(entries), len(store)) + index + bytes(store)


def cpio_newc(tree: Path, extra: list[tuple[str, int, bytes, int, int]] = (), skip=("DEBIAN",)) -> bytes:
    """newc archive of a directory tree ("./path" names, like rpm), plus raw extra
    entries (name, mode, data, ino, nlink) for hard links and hostile paths."""
    out = io.BytesIO()
    ino = [100]

    def entry(name: str, mode: int, data: bytes, inode: int | None = None, nlink: int = 1):
        if inode is None:
            ino[0] += 1
            inode = ino[0]
        nb = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(nb), 0]
        out.write(b"070701" + b"".join(f"{v:08X}".encode() for v in fields) + nb)
        out.write(b"\0" * ((4 - (110 + len(nb)) % 4) % 4))
        out.write(data + b"\0" * ((4 - len(data) % 4) % 4))

    for dirpath, dirnames, filenames in os.walk(tree):
        rel_dir = Path(dirpath).relative_to(tree)
        if rel_dir.parts and rel_dir.parts[0] in skip:
            continue
        dirnames.sort()
        for d in list(dirnames):
            p = Path(dirpath) / d
            if (rel_dir / d).parts[0] in skip:
                continue
            if p.is_symlink():
                entry(f"./{rel_dir / d}", stat.S_IFLNK | 0o777, os.readlink(p).encode())
                dirnames.remove(d)
            else:
                entry(f"./{rel_dir / d}", stat.S_IFDIR | 0o755, b"")
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.is_symlink():
                entry(f"./{rel_dir / fn}", stat.S_IFLNK | 0o777, os.readlink(p).encode())
            else:
                entry(f"./{rel_dir / fn}", stat.S_IFREG | (p.stat().st_mode & 0o7777), p.read_bytes())
    for name, mode, data, inode, nlink in extra:
        entry(name, mode, data, inode, nlink)
    entry("TRAILER!!!", 0, b"", 0)
    return out.getvalue()


def build_rpm(tree: Path, out: Path, name: str, version: str = "1.2.3", release: str = "1",
              arch: str = "x86_64", summary: str = "test package", license: str = "MIT",
              url: str = "https://example.com", scripts: dict[str, str] | None = None,
              compression: str = "gzip", extra_entries=(), corrupt_payload: bool = False) -> Path:
    raw = cpio_newc(tree, extra_entries)
    if compression == "gzip":
        payload = gzip.compress(raw, mtime=0)
    elif compression == "xz":
        payload = lzma.compress(raw, format=lzma.FORMAT_XZ)
    elif compression == "fake-zstd":     # zstd magic + raw cpio; the test's stand-in zstd strips it
        payload = b"\x28\xb5\x2f\xfd" + raw
    elif compression == "zstd":          # real zstd; ImportError if Python has no zstd module
        try:
            import zstandard
            payload = zstandard.ZstdCompressor().compress(raw)
        except ImportError:
            from compression import zstd     # Python 3.14+
            payload = zstd.compress(raw)
    else:
        raise ValueError(compression)
    tags = [(1000, STRING, name), (1001, STRING, version), (1002, STRING, release), (1004, I18N, [summary]),
            (1005, I18N, [f"{summary}.\n\nLonger text."]), (1014, STRING, license), (1020, STRING, url),
            (1022, STRING, arch), (1124, STRING, "cpio"),
            (1125, STRING, {"gzip": "gzip", "xz": "xz", "fake-zstd": "zstd", "zstd": "zstd"}[compression]),
            (5092, STRING_ARRAY, [hashlib.sha256(payload).hexdigest()]), (5093, INT32, [8])]
    for key, tag in (("pre", 1023), ("post", 1024), ("preun", 1025), ("postun", 1026)):
        if scripts and key in scripts:
            tags += [(tag, STRING, scripts[key]), (tag + 62, STRING, "/bin/sh")]
    header = _header(tags)
    sig = _header([(273, STRING, hashlib.sha256(header).hexdigest())])
    sig += b"\0" * ((8 - len(sig) % 8) % 8)
    lead = (b"\xed\xab\xee\xdb\x03\x00\x00\x00\x00\x01" + name.encode()[:65].ljust(66, b"\0")
            + b"\x00\x01\x00\x05" + b"\0" * 16)
    assert len(lead) == 96
    if corrupt_payload:
        payload = payload[:-20] + bytes(b ^ 0xFF for b in payload[-20:-10]) + payload[-10:]
    out.write_bytes(lead + sig + header + payload)
    return out


def rpm_repo(repo: Path, rpms: list[tuple[Path, str, list[str]]]) -> Path:
    """repodata/ for (rpm path, package name, [provides]) entries; RPMs are copied into Packages/."""
    pk = repo / "Packages"
    pk.mkdir(parents=True, exist_ok=True)
    items = []
    for path, name, provides in rpms:
        (pk / path.name).write_bytes(path.read_bytes())
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        prov = "".join(f'<rpm:entry name="{p}"/>' for p in provides)
        items.append(f'<package type="rpm"><name>{name}</name><arch>x86_64</arch>'
                     f'<version epoch="0" ver="1.2.3" rel="1"/><checksum type="sha256" pkgid="YES">{sha}</checksum>'
                     f'<location href="Packages/{path.name}"/><format><rpm:provides>{prov}</rpm:provides>'
                     f'</format></package>')
    primary = ('<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" '
               'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="%d">%s</metadata>'
               % (len(items), "".join(items)))
    rd = repo / "repodata"
    rd.mkdir(exist_ok=True)
    (rd / "abc-primary.xml.gz").write_bytes(gzip.compress(primary.encode()))
    (rd / "repomd.xml").write_text('<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo">'
                                   '<data type="primary"><location href="repodata/abc-primary.xml.gz"/></data>'
                                   '</repomd>')
    return repo


# ------------------------------------------------------------------ Arch / pacman

def build_pacman(tree: Path, out: Path, name: str, install: str | None = None, license: str = "MIT",
                 compression: str = "xz") -> Path:
    pkginfo = (f"# Generated by makepkg\npkgname = {name}\npkgbase = {name}\npkgver = 1.2.3-1\n"
               f"pkgdesc = {name} for tests\nurl = https://example.com/{name}\narch = x86_64\n"
               f"license = {license}\ndepend = glibc\n")
    mode = {"xz": "w:xz", "gz": "w:gz"}[compression]
    with tarfile.open(out, mode) as tf:
        def add_bytes(n, data):
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        add_bytes(".PKGINFO", pkginfo.encode())
        add_bytes(".MTREE", b"#mtree\n")
        if install:
            add_bytes(".INSTALL", install.encode())
        for child in sorted(tree.iterdir()):
            if child.name != "DEBIAN":
                tf.add(child, arcname=child.name)
    return out


# ------------------------------------------------------------------ vendor tarball

def build_tarball(files: dict[str, bytes | Path], out: Path, top: str | None, modes: dict[str, int] | None = None):
    modes = modes or {}
    with tarfile.open(out, "w:gz") as tf:
        for rel, data in files.items():
            raw = data.read_bytes() if isinstance(data, Path) else data
            ti = tarfile.TarInfo(f"{top}/{rel}" if top else rel)
            ti.size = len(raw)
            ti.mode = modes.get(rel, 0o644)
            tf.addfile(ti, io.BytesIO(raw))
    return out


# ------------------------------------------------------------------ AppImage

def build_appimage(runtime_elf: Path, out: Path) -> tuple[Path, int]:
    """An AppImage-shaped file: an ELF runtime with the AppImage type-2 magic,
    followed by (the start of) a squashfs image. Returns (path, squashfs offset)."""
    elf = bytearray(runtime_elf.read_bytes())
    elf[8:11] = b"AI\x02"
    if elf[4] == 2:
        shoff, = struct.unpack("<Q", elf[0x28:0x30])
        shentsize, shnum = struct.unpack("<HH", elf[0x3A:0x3E])
    else:
        shoff, = struct.unpack("<I", elf[0x20:0x24])
        shentsize, shnum = struct.unpack("<HH", elf[0x2E:0x32])
    offset = shoff + shentsize * shnum
    elf = elf[:offset] + b"\0" * max(0, offset - len(elf))
    out.write_bytes(bytes(elf) + b"hsqs" + b"\0" * 92)
    out.chmod(0o755)
    return out, offset
