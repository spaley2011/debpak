"""Windows and Mac programs: Electron apps on the Linux build of Electron, other
Windows programs under Wine, and self-extracting .run installers.

The executables are built by pe_write, the asar archives by asar.write_asar,
and the outside tools (7z, innoextract, msiextract, and wine for the
launcher test) are stand-in scripts. Electron's downloads are answered by a
fake fetch, so nothing here touches the network.
"""
import contextlib
import gzip
import hashlib
import io
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

from debpak import electron, winres
from debpak.asar import Asar, write_asar
from debpak.cli import main
from debpak.foreign import detect, icns_png, pick_main_exe
from debpak.packages import PackageError, detect_format, extract_run, open_package
from debpak.pe_write import PeSpec, build_pe, icon_resources, version_info
from debpak.wine import WineIndex
from fixtures import tiny_png
from isolate import offline

MACHO = b"\xcf\xfa\xed\xfe" + bytes(60)
ELF = b"\x7fELF\x02\x01\x01" + bytes(57)
STUBTAR = b"\nSTUBTAR\n"
SUMS = {f"electron-v30.1.2-linux-{a}.zip": hashlib.sha256(a.encode()).hexdigest() for a in ("x64", "arm64")}


def run_cli(*argv):
    out = io.StringIO()
    with offline(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


def fake_fetch(url: str) -> bytes:
    if url.endswith("/v30.1.2/SHASUMS256.txt"):
        return "".join(f"{h} *{n}\n" for n, h in SUMS.items()).encode()
    if url == electron.RELEASE_LIST:
        return json.dumps([{"version": "31.0.0", "chrome": "126.0.6478.36"},
                           {"version": "30.1.2", "chrome": "124.0.6367.243"}]).encode()
    raise OSError(f"no network in tests: {url}")


def exe_bytes(name="Acme Notes", version="2.3.1", imports=None, arch="x86_64", icon=True, subsystem=2,
              description=None, extra=b"") -> bytes:
    res = [version_info({"CompanyName": "Acme", "ProductName": name, "ProductVersion": version,
                         "FileDescription": description or name})]
    if icon:
        res += icon_resources(tiny_png(64), 64)
    return build_pe(PeSpec(arch=arch, is_dll=False, imports=imports or {"kernel32.dll": ["ExitProcess"]},
                           resources=res, subsystem=subsystem)) + extra


def dib_icon(size: int) -> bytes:
    """Return a size x size 32-bit icon image as old .exe files carry it: a DIB with an AND mask, not a PNG."""
    head = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    return head + b"\x20\x40\x80\xff" * size * size + bytes(((size + 31) // 32) * 4 * size)


def png_chunk(tag: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)


def filtered_png(width: int, height: int, rgba: bytes, filters: list[int]) -> bytes:
    """Return an RGBA PNG whose rows use the given filter types (0 none, 1 sub, 2 up, 3 average, 4 Paeth)."""
    def paeth(a, b, c):
        p = a + b - c
        pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
        return a if pa <= pb and pa <= pc else b if pb <= pc else c
    stride, raw, prev = width * 4, b"", bytes(width * 4)
    for y in range(height):
        line, kind = rgba[y * stride:(y + 1) * stride], filters[y % len(filters)]
        out = bytearray([kind])
        for i, v in enumerate(line):
            a = line[i - 4] if i >= 4 else 0
            b, c = prev[i], prev[i - 4] if i >= 4 else 0
            pred = [0, a, b, (a + b) // 2, paeth(a, b, c)][kind]
            out.append((v - pred) & 0xFF)
        raw += bytes(out)
        prev = line
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + png_chunk(b"IDAT", zlib.compress(raw)) + png_chunk(b"IEND", b""))


def dll_bytes() -> bytes:
    return build_pe(PeSpec(is_dll=True, exports=["napi_register_module_v1"]))


def elf_library(interp: bool = False) -> bytes:
    """A 64-bit ET_DYN ELF file: a shared library, or with interp a PIE program (a PT_INTERP header)."""
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 1,
                                                                0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 3 if interp else 1, 4, 0, 0, 0, 0, 0, 1)
    return header + phdr + bytes(64)


def write(path: Path, data, mode=0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(textwrap.dedent(data).lstrip("\n"))
    else:
        path.write_bytes(data)
    path.chmod(mode)
    return path


PACKAGE_JSON = {"name": "acme-notes", "productName": "Acme Notes", "version": "2.3.1",
                "description": "Notes for testing", "homepage": "https://acme.example", "license": "MIT",
                "main": "main.js", "devDependencies": {"electron": "^30.0.0"}}


def app_asar(res: Path, natives=None, unpacked=(), pj=None) -> None:
    files = {"package.json": json.dumps(pj or PACKAGE_JSON).encode(), "main.js": b"require('electron')\n"}
    files.update(natives or {})
    write_asar(res / "app.asar", files, set(unpacked))


def electron_win_folder(root: Path, natives=None, unpacked=(), version_string=True, pj=None) -> Path:
    """An electron-builder 'win-unpacked' folder."""
    extra = b"\0Chrome/124.0.6367.243 Electron/30.1.2\0" if version_string else b"\0Chrome/124.0.6367.243\0"
    write(root / "Acme Notes.exe", exe_bytes(extra=extra))
    write(root / "ffmpeg.dll", dll_bytes())
    app_asar(root / "resources", natives, unpacked, pj)
    write(root / "resources/elevate.exe", exe_bytes("elevate"))
    return root


def icns(png: bytes) -> bytes:
    body = b"ic08" + struct.pack(">I", 8 + len(png)) + png
    big = tiny_png(16)          # pretend 1024 px entry, to check the size limit
    big = big[:16] + struct.pack(">II", 1024, 1024) + big[24:]
    body += b"ic10" + struct.pack(">I", 8 + len(big)) + big
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def electron_mac_app(root: Path, electron_app=True) -> Path:
    app = root / "Acme Notes.app" / "Contents"
    write(app / "Info.plist", plistlib.dumps({"CFBundleName": "Acme Notes", "CFBundleExecutable": "Acme Notes",
                                              "CFBundleShortVersionString": "2.3.1",
                                              "CFBundleIconFile": "icon.icns"}))
    write(app / "MacOS/Acme Notes", MACHO, 0o755)
    write(app / "Resources/icon.icns", icns(tiny_png(256)))
    write(app / "Resources/en.lproj/InfoPlist.strings", b"x")
    if electron_app:
        fw = app / "Frameworks/Electron Framework.framework/Versions/A"
        write(fw / "Resources/Info.plist", plistlib.dumps({"CFBundleVersion": "30.1.2"}))
        write(fw / "Electron Framework", MACHO)
        app_asar(app / "Resources", {"node_modules/fsevents/fsevents.node": MACHO},
                 {"node_modules/fsevents/fsevents.node"})
    return root / "Acme Notes.app"


def zip_tree(src: Path, dest: Path, prefix: bytes = b"") -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(src.parent if src.is_dir() and src.suffix == ".app" else src).as_posix())
    dest.write_bytes(prefix + buf.getvalue())
    return dest


def cab_installer(tmp: Path) -> Path:
    """A Total Commander style installer: a self-extracting zip of INSTALL.CAB (the program) and INSTALL.INF."""
    cab = tmp / "cab-src"
    write(cab / "TOTALCMD64.EXE", exe_bytes("Total Commander", extra=bytes(20000)))
    write(cab / "TOTALCMD.EXE", exe_bytes("Total Commander", arch="i386"))
    write(cab / "TCMADM64.EXE", exe_bytes("Total Commander admin"))
    write(cab / "LANGUAGE/WCMD_DEU.LNG", "x")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("INSTALL.CAB", b"MSCF" + STUBTAR + tar_bytes(cab))
        z.writestr("INSTALL.INF", "[auto]\nDir=c:\\totalcmd\n")
    return write(tmp / "tcmd115801x64.exe", exe_bytes("Total Commander Installer") + buf.getvalue())


def burn_bundle(payloads: list[bytes], gap: int = 0) -> bytes:
    """A WiX bundle: a PE whose .wixburn section's header gives the cabinets that follow the 0x400-byte stub.

    Each payload gets a cabinet's signature and size in front; gap bytes (a
    signature) go between the first cabinet and the rest.
    """
    containers = [b"MSCF\0\0\0\0" + struct.pack("<I", len(p) + 12) + p for p in payloads]
    mz = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0x22)
    section = b".wixburn" + struct.pack("<IIIIIIHHI", 0x100, 0x1000, 0x100, 0x200, 0, 0, 0, 0, 0)
    header = struct.pack("<II16sIIIIII", 0x00F14300, 2, bytes(16), 0x400, 0, 0, 0, 1, len(containers))
    header += struct.pack(f"<{len(containers)}I", *map(len, containers))
    stub = (mz + coff + section).ljust(0x200, b"\0") + header
    return stub.ljust(0x400, b"\0") + containers[0] + b"SIGNATURE"[:gap].ljust(gap, b"\0") + b"".join(containers[1:])


def sevenzip_sfx(tmp: Path) -> Path:
    """A 7-Zip style installer: a small program, then a 7z archive (a start header the stub 7z skips, then a tar).

    A signature with a wrong CRC comes first, as a stray copy of the bytes would.
    """
    files = tmp / "7z-src"
    write(files / "7zFM.exe", exe_bytes("7-Zip", extra=bytes(20000)))
    write(files / "7zG.exe", exe_bytes("7-Zip"))
    write(files / "7z.exe", exe_bytes("7-Zip", subsystem=3))
    write(files / "Uninstall.exe", exe_bytes("7-Zip Uninstaller"))
    write(files / "7z.dll", dll_bytes())
    body = STUBTAR + tar_bytes(files)
    start = struct.pack("<QQI", len(body) - 40, 40, 0)
    header = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start
    stray = b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(24)
    # an Authenticode signature would follow the archive; it mustn't reach 7z
    return write(tmp / "7z2606-x64.exe", exe_bytes("7-Zip", description="7-Zip Installer",
                                                   extra=stray + header + body + b"SIGNATURE" * 100))


def tar_bytes(src: Path, arcname: str = ".") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        t.add(src, arcname=arcname)
    return buf.getvalue()


# Stand-ins: each reads a tar that follows the STUBTAR marker (or a zip) and logs its arguments.
STUB = """#!{python}
import io, os, sys, tarfile, zipfile
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write("{name} " + " ".join(args) + "\\n")
if "--list-languages" in args:
    # innoextract's listing: STUB_INNO_LANGS="en: English;de: Deutsch" gives " - en: English" and so on
    print("".join(" - " + l + "\\n" for l in os.environ.get("STUB_INNO_LANGS", "").split(";") if l))
    sys.exit(0)
src = args[-1]
if "{name}" == "7z":
    out = next(a[2:] for a in args if a.startswith("-o"))
elif "{name}" == "innoextract":
    out = args[args.index("--output-dir") + 1]
else:
    out = args[args.index("-C") + 1]
data = open(src, "rb").read()
if "{name}" == "bsdtar" and data[:2] == b"MZ":
    # like bsdtar on EditPlus's RAR self-extractor, which it reads only once cut from the .exe
    sys.exit("bsdtar: Couldn't find out RAR header")
os.makedirs(out, exist_ok=True)
i = data.find(b"\\nSTUBTAR\\n")
if i != -1:
    t = tarfile.open(fileobj=io.BytesIO(data[i + 9:]))
    # like real 7z, keep absolute links (a .dmg has Applications -> /Applications); Python
    # 3.14's default "data" filter would refuse them
    t.extractall(out, **({{"filter": "tar"}} if hasattr(tarfile, "tar_filter") else {{}}))
elif zipfile.is_zipfile(src):
    zipfile.ZipFile(src).extractall(out)
else:
    sys.exit("stub: nothing to extract")
"""


# Wine through Flatpak, for an installer run under Wine: org.winehq.Wine is installed when
# STUB_WINE is set, and "running" an installer unpacks the tar after its STUBTAR marker into
# the prefix's drive_c when its switches are STUB_WINE's; anything else goes to the real flatpak
FLATPAK_STUB = """#!{python}
import io, os, sys, tarfile
args = sys.argv[1:]
if not any(a.startswith("org.winehq.Wine") for a in args):
    os.execv("/usr/bin/flatpak", ["flatpak", *args])
with open(os.environ["STUB_LOG"], "a") as f:
    f.write("flatpak " + " ".join(args) + "\\n")
wine = os.environ.get("STUB_WINE")
if args[0] in ("info", "install"):
    sys.exit(0 if wine else 1)
prefix = next(a.split("=", 2)[2] for a in args if a.startswith("--env=WINEPREFIX="))
i = next(n for n, a in enumerate(args) if a.startswith("org.winehq.Wine"))
_script, before, _seconds, _idle, setup, *switches = args[i + 1:]
race = os.environ.get("STUB_WINE_RACE")       # a file counting the starts Flatpak itself fails
if race and len(open(race).read()) < 2:
    open(race, "a").write("x")
    sys.exit("bwrap: Can't get type of source /run/user/1000/.flatpak/1334214619: No such file or directory")
open(before, "w").close()
if not os.path.isfile(setup):
    print('wine: failed to open "' + setup + '"')
    sys.exit(print("debpak: installer exit status 53"))
data = open(setup, "rb").read()
if os.environ.get("STUB_WINE_MOVES"):         # an installer that moves itself where it installs (osu!'s)
    os.remove(setup)
j = data.find(b"\\nSTUBTAR\\n")
online = not os.environ.get("STUB_WINE_NET") or "--share=network" in args
if (" ".join(switches) == wine or wine == "(clicked)" and not switches) and j != -1 and online:
    drive = os.path.join(prefix, "drive_c")
    os.makedirs(drive, exist_ok=True)
    t = tarfile.open(fileobj=io.BytesIO(data[j + 9:]))
    t.extractall(drive, **({{"filter": "tar"}} if hasattr(tarfile, "tar_filter") else {{}}))
elif os.environ.get("STUB_WINE_USAGE"):
    print(os.environ["STUB_WINE_USAGE"])
print("debpak: installer exit status 0")
"""
# xvfb-run: run the command without a display
XVFB_STUB = """#!/bin/sh
while [ "$1" = -a ] || [ "$1" = -s ]; do [ "$1" = -s ] && shift; shift; done
exec "$@"
"""


class StubTools:
    def __init__(self, base: Path, names=("7z", "innoextract", "msiextract", "bsdtar")):
        self.bin = base / "stub-bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.log = base / "stub.log"
        for n in names:
            write(self.bin / n, STUB.format(python=sys.executable, name=n), 0o755)
        write(self.bin / "flatpak", FLATPAK_STUB.format(python=sys.executable), 0o755)
        write(self.bin / "xvfb-run", XVFB_STUB, 0o755)
        write(self.bin / "xdotool", "#!/bin/sh\nexit 0\n", 0o755)
        self.env = {"PATH": f"{self.bin}:/usr/bin:/bin", "STUB_LOG": str(self.log)}

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="debpak-foreign-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stubs = StubTools(self.tmp)
        env = mock.patch.dict(os.environ, {**self.stubs.env, "XDG_CACHE_HOME": str(self.tmp / "cache"),
                                           "XDG_DATA_HOME": str(self.tmp / "data")})
        env.start()
        self.addCleanup(env.stop)
        f = mock.patch.object(electron, "fetch", fake_fetch)
        f.start()
        self.addCleanup(f.stop)
        # what the installed Wine base app has is the host's business: by default nothing is known
        b = mock.patch("debpak.winapp.wine_base_dlls", return_value=None)
        b.start()
        self.addCleanup(b.stop)

    # tests of the Electron route itself see its refusals, not the Wine route it falls back to
    electron_only = False

    def convert(self, src, *extra):
        out = self.tmp / "out"
        if self.electron_only:
            extra = ("--no-wine-fallback", *extra)
        code, text = run_cli("convert", str(src), "-o", str(out), "--no-build", "--no-flathub-check", *extra)
        return code, text, out

    def manifest(self, out: Path) -> dict:
        return json.loads(next(p for p in out.glob("*.json") if p.name != "report.json").read_text())


# --------------------------------------------------------------------------- readers

class ReaderTests(Base):
    def test_asar_round_trip(self):
        write_asar(self.tmp / "app.asar", {"a/b.js": b"hello", "c.node": ELF, "d.txt": b"x" * 10}, {"c.node"})
        a = Asar(self.tmp / "app.asar")
        self.assertEqual(a.read("a/b.js"), b"hello")
        self.assertEqual(a.read("c.node"), ELF)
        self.assertTrue((self.tmp / "app.asar.unpacked/c.node").is_file())
        self.assertEqual(sorted(p for p, _ in a.walk()), ["a/b.js", "c.node", "d.txt"])
        self.assertEqual(a.head("d.txt", 3), b"xxx")

    def test_version_strings_and_icon(self):
        exe = write(self.tmp / "a.exe", exe_bytes())
        v = winres.version_strings(exe)
        self.assertEqual((v["ProductName"], v["ProductVersion"], v["CompanyName"]), ("Acme Notes", "2.3.1", "Acme"))
        png = winres.extract_png(exe)
        self.assertEqual(struct.unpack(">II", png[16:24]), (64, 64))
        self.assertEqual(winres.version_strings(write(self.tmp / "b.exe", exe_bytes(icon=False)[:200])), {})
        self.assertIsNone(winres.extract_png(self.tmp / "b.exe"))

    def test_png_pixels_and_scale(self):
        # an RGBA image written with each of PNG's row filters, then a palette one with transparency
        w, h = 3, 5
        rgba = bytes((x * 80 + y * 7) % 256 for y in range(h) for x in range(w) for _ in range(4))
        png = filtered_png(w, h, rgba, [0, 1, 2, 3, 4])
        self.assertEqual(winres.png_pixels(png), (w, h, rgba))
        pal = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 3, 0, 0, 0))
               + png_chunk(b"PLTE", b"\x10\x20\x30\xff\x00\x00") + png_chunk(b"tRNS", b"\x00")
               + png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x01")) + png_chunk(b"IEND", b""))
        self.assertEqual(winres.png_pixels(pal), (2, 1, b"\x10\x20\x30\x00\xff\x00\x00\xff"))
        # nearest-pixel scaling: a 2x1 image at 4x4 is two 2-pixel-wide columns
        big = winres.png_pixels(winres.scale_png(pal, 4))
        self.assertEqual(big[:2], (4, 4))
        self.assertEqual(big[2][:16], b"\x10\x20\x30\x00" * 2 + b"\xff\x00\x00\xff" * 2)
        with self.assertRaises(ValueError):
            winres.png_pixels(b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 16, 2, 0, 0, 0)))
        with self.assertRaises(ValueError):
            winres.scale_png(b"not a png", 128)

    def test_icns_picks_largest_png_up_to_512(self):
        png = icns_png(write(self.tmp / "i.icns", icns(tiny_png(256))))
        self.assertEqual(struct.unpack(">I", png[16:20])[0], 256)
        self.assertIsNone(icns_png(write(self.tmp / "bad.icns", b"nope")))

    def test_detect(self):
        mac = electron_mac_app(self.tmp / "m")
        self.assertEqual(detect(mac), "macapp")
        self.assertEqual(detect(zip_tree(mac, self.tmp / "m.zip")), "macapp")
        self.assertEqual(detect(write(self.tmp / "x.dmg", b"anything")), "dmg")
        self.assertEqual(detect(write(self.tmp / "setup.bin", exe_bytes())), "windows")
        self.assertEqual(detect(write(self.tmp / "a.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(8))), "windows")
        self.assertEqual(detect(electron_win_folder(self.tmp / "w")), "windows")
        self.assertIsNone(detect(write(self.tmp / "notes.txt", "hi")))
        self.assertEqual(detect_format(self.tmp / "w"), "windows")
        self.assertEqual(detect_format(write(self.tmp / "plain.zip", b"")), "tarball")
        mixed = self.tmp / "mixed"
        write(mixed / "game/game.x86_64", ELF)
        write(mixed / "game/libsteam_api.so", ELF)
        write(mixed / "game/redist/setup.exe", exe_bytes())
        self.assertEqual(detect_format(zip_tree(mixed, self.tmp / "game-linux.zip")), "tarball")
        write(mixed / "game/libsteam_api.so", b"")
        (mixed / "game/libsteam_api.so").unlink()
        (mixed / "game/game.x86_64").unlink()
        self.assertEqual(detect_format(zip_tree(mixed, self.tmp / "game-win.zip")), "windows")
        # Cmder carries shell scripts deep in its vendor folder; one near the top is a Linux app's
        cmder = self.tmp / "cmder"
        write(cmder / "Cmder.exe", exe_bytes("Cmder"))
        write(cmder / "vendor/conemu-maximus5/ConEmu/wsl/wsl-boot.sh", "#!/bin/sh\n")
        self.assertEqual(detect_format(zip_tree(cmder, self.tmp / "cmder_mini.zip")), "windows")
        # Mission Planner carries Linux libraries and a script beside MissionPlanner.exe
        planner = self.tmp / "planner"
        write(planner / "MissionPlanner.exe", exe_bytes("Mission Planner"))
        write(planner / "aot.sh", "#!/bin/sh\n")
        write(planner / "x64/libSkiaSharp.so", ELF)
        self.assertEqual(detect_format(zip_tree(planner, self.tmp / "MissionPlanner-latest.zip")), "windows")
        # a Linux program near the top decides for Linux
        write(planner / "bin/planner", ELF)
        self.assertEqual(detect_format(zip_tree(planner, self.tmp / "planner-linux.zip")), "tarball")
        # a zip of the .msi alone (ScrambleID's, with a README) is Windows, not a tarball
        scramble = self.tmp / "scramble"
        write(scramble / "ScrambleId_2.0.54_x64.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(8))
        write(scramble / "README.md", "# ScrambleID\n")
        self.assertEqual(detect_format(zip_tree(scramble, self.tmp / "ScrambleID-2.0.54.zip")), "windows")
        # ShaderGlass's Windows zip carries an ELF library beside ShaderGlass.exe: libraries alone, by
        # name or by their headers (ET_DYN with no interpreter), don't make it Linux, as nothing in it
        # would run them; a PIE program (ET_DYN with PT_INTERP) or a script near the top still does
        glass = self.tmp / "glass"
        write(glass / "ShaderGlass.exe", exe_bytes("ShaderGlass"))
        write(glass / "Shaders/capture/pipewire-capture", elf_library())
        self.assertEqual(detect_format(zip_tree(glass, self.tmp / "ShaderGlass-1.3.2-win-x64.zip")), "windows")
        deep = self.tmp / "deep"
        write(deep / "a/b/c/Viewer.exe", exe_bytes("Viewer"))
        write(deep / "a/b/c/libcapture.so.0", elf_library())
        write(deep / "README.txt", "readme\n")
        self.assertEqual(detect_format(zip_tree(deep, self.tmp / "viewer-1.0.zip")), "windows")
        write(deep / "a/b/c/viewer", elf_library(interp=True))
        self.assertEqual(detect_format(zip_tree(deep, self.tmp / "viewer-1.0b.zip")), "tarball")
        (deep / "a/b/c/viewer").unlink()
        write(deep / "start", "#!/bin/sh\nexec a/b/c/viewer\n")
        self.assertEqual(detect_format(zip_tree(deep, self.tmp / "viewer-1.0c.zip")), "tarball")

    def test_pick_main_exe_skips_helpers(self):
        root = self.tmp / "p"
        write(root / "unins000.exe", exe_bytes("Uninstall") + bytes(5000))
        write(root / "Update.exe", exe_bytes("Update") + bytes(5000))
        write(root / "tool-cli.exe", exe_bytes("cli", subsystem=3) + bytes(9000))
        write(root / "bin/Acme.exe", exe_bytes())
        self.assertEqual(pick_main_exe(root).name, "Acme.exe")
        self.assertEqual(pick_main_exe(root, product="Acme").name, "Acme.exe")
        self.assertEqual(pick_main_exe(root, wanted="bin\\Acme.exe").name, "Acme.exe")
        self.assertIsNone(pick_main_exe(root, wanted="missing.exe"))

    def test_pick_main_exe_prefers_the_gui_to_its_command_line_twin(self):
        # DiscordChatExporter's CLI download is named like the twin, so the product name matches it
        for twin in ("DiscordChatExporter.Cli.exe", "DiscordChatExporter-cli.exe", "DiscordChatExporterConsole.exe"):
            with self.subTest(twin=twin):
                root = self.tmp / twin
                write(root / twin, exe_bytes("DiscordChatExporter.Cli", extra=bytes(90000)))
                write(root / "DiscordChatExporter.exe", exe_bytes("DiscordChatExporter"))
                self.assertEqual(pick_main_exe(root, product=["DiscordChatExporter.Cli.win"]).name,
                                 "DiscordChatExporter.exe")
                self.assertEqual(pick_main_exe(root).name, "DiscordChatExporter.exe")
        # a CLI with no GUI next to it is still the program
        root = self.tmp / "cli-only"
        write(root / "DiscordChatExporter.Cli.exe", exe_bytes("DiscordChatExporter.Cli", subsystem=3))
        write(root / "Other.Cli.exe", exe_bytes("Other", subsystem=3))
        self.assertEqual(pick_main_exe(root, product="DiscordChatExporter.Cli").name, "DiscordChatExporter.Cli.exe")

    def test_pick_main_exe_never_takes_arm64_over_x64(self):
        root = self.tmp / "arch"
        write(root / "arm64/LightBulb.exe", exe_bytes("LightBulb", arch="arm64", extra=bytes(9000)))
        write(root / "x64/LightBulb.Launcher.exe", exe_bytes("Launcher"))
        self.assertEqual(pick_main_exe(root, product="LightBulb").name, "LightBulb.Launcher.exe")
        write(root / "x86/LightBulb.exe", exe_bytes("LightBulb", arch="i386"))
        self.assertEqual(pick_main_exe(root, product="LightBulb").relative_to(root).as_posix(), "x86/LightBulb.exe")
        # 7-Zip ships 7z.exe and 7zG.exe, which other programs carry as helpers; 7zFM.exe is its own
        root = self.tmp / "7zip"
        for n in ("7z.exe", "7zG.exe", "7za.exe", "Uninstall.exe"):
            write(root / n, exe_bytes("7-Zip") + bytes(50000))
        write(root / "7zFM.exe", exe_bytes("7-Zip"))
        self.assertEqual(pick_main_exe(root).name, "7zFM.exe")
        # XYplorer's 64-bit helper is named like the product but isn't the program
        root = self.tmp / "xy"
        write(root / "XY64contents.exe", exe_bytes("XYplorer", description="XYplorer 64-bit File Contents Extraction Helper",
                                                   extra=bytes(90000)))
        write(root / "XYplorer.exe", exe_bytes("XYplorer", arch="i386"))
        self.assertEqual(pick_main_exe(root, product="XYplorer").name, "XYplorer.exe")
        write(root / "XY64.exe", exe_bytes("XYplorer", description="XYplorer 64-bit", extra=bytes(90000)))
        self.assertEqual(pick_main_exe(root, product="XYplorer").name, "XYplorer.exe")
        # Sysinternals ships procexp.exe and procexp64.exe: both are named for it, so x64 wins
        root = self.tmp / "procexp"
        write(root / "procexp.exe", exe_bytes("Process Explorer", arch="i386"))
        write(root / "procexp64.exe", exe_bytes("Process Explorer"))
        self.assertEqual(pick_main_exe(root, product="procexp").name, "procexp64.exe")
        # LaserGRBL is a 32-bit .NET program; the 64-bit Autotrace/autotrace.exe beside it is a console tool
        root = self.tmp / "lasergrbl"
        write(root / "LaserGRBL.exe", exe_bytes("LaserGRBL", arch="i386"))
        write(root / "Autotrace/autotrace.exe", exe_bytes("autotrace", subsystem=3, extra=bytes(90000)))
        self.assertEqual(pick_main_exe(root, product="install").name, "LaserGRBL.exe")

    def test_pick_main_exe_reads_the_product_name_without_its_tail(self):
        # MediaMonkey's installer calls it "MediaMonkey 2024", and the larger MediaMonkeyEngine.exe
        # (its browser engine, named like the product too) won over MediaMonkey.exe
        root = self.tmp / "mm"
        write(root / "MediaMonkeyEngine.exe", exe_bytes("MediaMonkey", arch="i386", extra=bytes(90000)))
        write(root / "MediaMonkey.exe", exe_bytes("MediaMonkey", arch="i386"))
        self.assertEqual(pick_main_exe(root, product=["MediaMonkey 2024", "MediaMonkey-2024"]).name,
                         "MediaMonkey.exe")
        # PotPlayer's download is PotPlayerSetup64.exe, and its program's name begins with the product's
        root = self.tmp / "pot"
        write(root / "KakaoUtil64.exe", exe_bytes("KakaoUtil", extra=bytes(90000)))
        write(root / "PotPlayerMini64.exe", exe_bytes("Daum"))
        self.assertEqual(pick_main_exe(root, product="PotPlayerSetup64").name, "PotPlayerMini64.exe")
        # Tableau Public's bin folder has QtWebEngineProcess.exe, a page process of the engine it embeds
        root = self.tmp / "tab"
        write(root / "bin/QtWebEngineProcess.exe", exe_bytes("Qt6", description="QtWebEngine internal process",
                                                             extra=bytes(90000)))
        write(root / "bin/CefSharp.BrowserSubprocess.exe", exe_bytes("CefSharp", extra=bytes(90000)))
        write(root / "bin/tabcmdhelper.exe", exe_bytes("Tableau", subsystem=3, extra=bytes(90000)))
        write(root / "bin/tableau.exe", exe_bytes("Tableau"))
        self.assertEqual(pick_main_exe(root, product="TableauPublicDesktop-64bit-2026-3-2").name, "tableau.exe")


# --------------------------------------------------------------------------- Electron

class ElectronTests(Base):
    electron_only = True

    def test_windows_folder_converts(self):
        src = electron_win_folder(self.tmp / "win-unpacked")
        code, text, out = self.convert(src, "--app-id", "org.example.AcmeNotes")
        self.assertEqual(code, 0, text)
        self.assertIn("30.1.2 (from a version string in Acme Notes.exe)", text)
        self.assertIn("resources/elevate.exe is a Windows program", text)
        m = self.manifest(out)
        self.assertEqual((m["base"], m["base-version"], m["runtime-version"]),
                         ("org.electronjs.Electron2.BaseApp", "25.08", "25.08"))
        self.assertEqual(m["command"], "acme-notes")
        srcs = m["modules"][0]["sources"]
        self.assertEqual({s["only-arches"][0]: s["sha256"] for s in srcs},
                         {"x86_64": SUMS["electron-v30.1.2-linux-x64.zip"],
                          "aarch64": SUMS["electron-v30.1.2-linux-arm64.zip"]})
        self.assertTrue(all(s["strip-components"] == 0 for s in srcs))
        self.assertIn("--socket=x11", m["finish-args"])
        app = out / "app"
        self.assertTrue((app / "resources/app.asar").is_file())
        self.assertNotIn("Electron methods that only exist", text)
        self.assertFalse((app / "resources/app.asar.unpacked/debpak-shim.js").exists())
        launcher = (app / "bin/acme-notes").read_text()
        # named after the app: Electron's app.isPackaged is false for a program called electron (Notion
        # then acts as in development and opens no window)
        self.assertIn("exec zypak-wrapper /app/lib/acme-notes/acme-notes", launcher)
        electron = [mod for mod in m["modules"] if mod["name"] == "electron"][0]
        self.assertIn("mv ${FLATPAK_DEST}/lib/acme-notes/electron ${FLATPAK_DEST}/lib/acme-notes/acme-notes",
                      electron["build-commands"])
        desktop = (app / "share/applications/org.example.AcmeNotes.desktop").read_text()
        self.assertIn("Name=Acme Notes", desktop)
        self.assertIn("StartupWMClass=Acme Notes", desktop)
        self.assertTrue((app / "share/icons/hicolor/64x64/apps/org.example.AcmeNotes.png").is_file())
        md = (app / "share/metainfo/org.example.AcmeNotes.metainfo.xml").read_text()
        self.assertIn("<project_license>MIT</project_license>", md)
        self.assertIn("https://acme.example", md)
        self.assertEqual(json.loads((out / "report.json").read_text())["route"], "electron")
        self.assertEqual(m["x-debpak"]["kind"], "electron")     # convert's check knows it's Chromium

    def test_old_electron_runs_without_zypak(self):
        # zypak only works with Electron 5 and later; React Proto's Electron 2 crashed under it at once
        self.assertEqual(electron.launch_line("/app/lib/x/x", "30.1.2", False), 'exec zypak-wrapper /app/lib/x/x "$@"\n')
        old = electron.launch_line("/app/lib/x/x", "4.2.12", False)
        self.assertTrue(old.endswith('\nexec /app/lib/x/x --no-sandbox "$@"\n'), old)
        self.assertIn("Electron 4.2.12 is older than zypak supports", old)
        # convert's check passes --no-chromium-sandbox when the app crashed at start; an Electron 5 or
        # later is told by ELECTRON_DISABLE_SANDBOX, which the app's option parser doesn't see (Fether
        # refused --no-sandbox as an unknown option)
        line = electron.launch_line("/app/lib/x/x", "30.1.2", True)
        self.assertIn('export ELECTRON_DISABLE_SANDBOX=1\nexec /app/lib/x/x "$@"', line)
        self.assertNotIn("--no-sandbox", line)
        self.assertNotIn("ELECTRON_DISABLE_SANDBOX", old)
        src = electron_win_folder(self.tmp / "win-unpacked")
        code, text, out = self.convert(src, "--app-id", "org.example.AcmeNotes", "--no-chromium-sandbox")
        self.assertEqual(code, 0, text)
        self.assertIn('ELECTRON_DISABLE_SANDBOX=1\nexec /app/lib/acme-notes/acme-notes "$@"',
                      (out / "app/bin/acme-notes").read_text())

    def test_electron_program_is_not_called_electron(self):
        self.assertEqual(electron.electron_exe_name("notion"), "notion")
        self.assertEqual(electron.electron_exe_name("electron"), "electron-app")       # still isPackaged
        self.assertEqual(electron.electron_exe_name("locales"), "locales-app")         # a folder of the zip

    def test_windows_native_module_blocks_until_replaced(self):
        natives = {"node_modules/sqlite/build/Release/sqlite.node": dll_bytes(),
                   "node_modules/keytar/keytar.node": dll_bytes(),
                   "node_modules/win-ca/roots.node": dll_bytes(),
                   "node_modules/@img/sharp-win32-x64/lib/sharp.node": dll_bytes()}
        src = electron_win_folder(self.tmp / "w", natives, unpacked={"node_modules/keytar/keytar.node"})
        code, text, out = self.convert(src)
        self.assertEqual(code, 2, text)
        self.assertIn("native module app.asar/node_modules/sqlite/build/Release/sqlite.node is built for Windows",
                      text)
        self.assertIn("win-ca/roots.node is Windows-only", text)
        self.assertIn("the Windows build of @img/sharp; the app will look for @img/sharp-linux-x64", text)
        self.assertFalse(out.exists())

        nd = self.tmp / "linux-natives"
        write(nd / "node_modules/sqlite/build/Release/sqlite.node", ELF)
        write(nd / "keytar.node", ELF)
        code, text, out = self.convert(src, "--native-dir", str(nd))
        self.assertEqual(code, 0, text)
        res = out / "app/resources"
        a = Asar(res / "app.asar")
        self.assertTrue(a.entry("node_modules/sqlite/build/Release/sqlite.node")["unpacked"])
        self.assertEqual(a.read("node_modules/sqlite/build/Release/sqlite.node"), ELF)
        self.assertEqual(a.read("node_modules/keytar/keytar.node"), ELF)
        self.assertEqual(json.loads(a.read("package.json"))["name"], "acme-notes")
        # the source folder was hard-linked, never written through
        self.assertEqual((src / "resources/app.asar.unpacked/node_modules/keytar/keytar.node").read_bytes()[:2],
                         b"MZ")

    def test_native_module_loaded_only_inside_try_is_left_out(self):
        """A bundle that catches the failure to load a module (Claude's @ant/claude-native and its
        MSAL runtime) starts without it; a plain require at the top of a file still blocks."""
        natives = {
            "node_modules/@acme/native/binding.node": dll_bytes(),
            "node_modules/@acme/native/index.js": b"module.exports = require('./binding.node')\n",
            "dist/main.js": b'function q(){return require("@acme/native")}var c;'
                            b'function g(){if(c!==void 0)return c;try{c=q()}catch(e){c=null}return c}'
                            b'function u(){let e=(c??require("@acme/native")).x()}'
                            b'function v(){try{let e=(c??require("@acme/native")).x()}catch{}}\n',
            "res/mail/broker.node": dll_bytes(),
            "res/mail/server.mjs": b'var b;try{b=r("./broker.node")}catch{b=new Fallback}\n',
        }
        src = electron_win_folder(self.tmp / "w", natives)
        code, text, _ = self.convert(src)
        # u() loads the module outside a try block
        self.assertEqual(code, 2, text)
        self.assertIn("@acme/native/binding.node is built for Windows, and no Linux build was found", text)
        self.assertIn("app.asar/res/mail/broker.node is built for Windows, and no Linux build was found "
                      "(not inside node_modules, so there's no package to look up); the app loads it only "
                      "where it catches the failure (app.asar/res/mail/server.mjs)", text)

        natives["dist/main.js"] = natives["dist/main.js"].replace(b"function u(){", b"function u(){try{") \
            .replace(b".x()}function v", b".x()}catch{}}function v")
        src = electron_win_folder(self.tmp / "w2", natives)
        code, text, _ = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("the app loads it only where it catches the failure (app.asar/dist/main.js), so it starts "
                      "without it, but whatever needs it won't work", text)

        top = dict(natives, **{"dist/other.js": b'const n = require("@acme/native");\n'})
        src = electron_win_folder(self.tmp / "w3", top)
        code, text, _ = self.convert(src)
        self.assertEqual(code, 2, text)

    def test_caught_native_rules(self):
        cn = electron.caught_native
        pkg = ("@a/n", "app.asar/node_modules/@a/n")
        rel = "app.asar/node_modules/@a/n/n.node"
        own = ("app.asar/node_modules/@a/n/index.js", "module.exports=require('@a/n/n.node')")
        self.assertIsNone(cn(rel, pkg, [own]))                     # never loaded by the app: nothing to go on
        self.assertEqual(cn(rel, pkg, [own, ("a.js", "try { x = require('@a/n') } catch (e) {}")]), "a.js")
        # a loader function whose only call isn't caught
        self.assertIsNone(cn(rel, pkg, [("a.js", "f=()=>require('@a/n');var x=f();")]))
        self.assertEqual(cn(rel, pkg, [("a.js", "f=()=>require('@a/n');try{x=f()}catch{}")]), "a.js")
        # the try block has ended before the require
        self.assertIsNone(cn(rel, pkg, [("a.js", "try{a()}catch{}x=require('@a/n')")]))
        self.assertIsNone(cn(rel, pkg, [("a.js", "try{if(a){x=require('@a/n')}}catch{}")]))
        loose = "app.asar/lib/x.node"
        self.assertEqual(cn(loose, None, [("m.js", "try{h=require(path.join(__dirname,'x.node'))}catch{}")]),
                         "m.js")
        self.assertIsNone(cn(loose, None, [("m.js", "h=require('./x.node')")]))
        self.assertIsNone(cn(loose, None, [("m.js", "h=require('./ax.node')")]))

    def test_windows_only_electron_methods_get_stand_ins(self):
        main = b"const {app, BrowserWindow} = require('electron');\n" \
               b"app.whenReady().then(() => { const w = new BrowserWindow(); w.hookWindowMessage(0x81, f); });\n"
        src = electron_win_folder(self.tmp / "w", {"main.js": main})
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("the app calls Electron methods that only exist on Windows or macOS "
                      "(BrowserWindow.hookWindowMessage)", text)
        res = out / "app/resources"
        a = Asar(res / "app.asar")
        pj = json.loads(a.read("package.json"))
        self.assertEqual(pj["main"], "debpak-shim.js")
        self.assertEqual(pj["productName"], "Acme Notes")
        shim = a.read("debpak-shim.js").decode()
        self.assertIn("if (typeof win.hookWindowMessage !== 'function') win.hookWindowMessage = function () {};",
                      shim)
        self.assertNotIn("setJumpList", shim)
        self.assertTrue(shim.endswith("require(require('path').join(__dirname, \"main.js\"));\n"))
        self.assertEqual(a.read("main.js"), main)
        # the source's package.json is untouched
        self.assertEqual(json.loads(Asar(src / "resources/app.asar").read("package.json"))["main"], "main.js")
    def test_bundle_compiled_for_windows_blocks(self):
        # GitHub Desktop's webpack build: process.platform became "win32" and the other platforms'
        # code was dropped, so it loads registry.node at startup whatever debpak puts in its place
        filler = b"function f%d(e){return e+%d}\n"
        folded = (b'a=process.env.GRACEFUL_FS_PLATFORM||"win32";o.set("platform","win32");\n'
                  + b"".join(filler % (i, i) for i in range(4000)))
        src = electron_win_folder(self.tmp / "w", {"main.js": folded})
        code, text, out = self.convert(src)
        self.assertEqual(code, 2, text)
        self.assertIn('its JavaScript was built for Windows only: main.js', text)
        self.assertIn('replaced process.platform with "win32"', text)
        self.assertFalse(out.exists())

        # the same bundle still asking which platform it runs on converts; so does a small main.js
        kept = folded.replace(b'||"win32"', b'||process.platform')
        for i, main in enumerate((kept, folded[:4000])):
            code, text, _ = self.convert(electron_win_folder(self.tmp / f"k{i}", {"main.js": main}))
            self.assertEqual(code, 0, text)
            self.assertNotIn("built for Windows only", text)
        # a bundle naming several platforms didn't have its checks compiled out
        both = folded + b'x="darwin";'
        code, text, _ = self.convert(electron_win_folder(self.tmp / "b", {"main.js": both}))
        self.assertEqual(code, 0, text)
        # "main" naming a folder resolves to its index.js, as in Node
        pj = dict(PACKAGE_JSON, main="./dist/")
        code, text, _ = self.convert(electron_win_folder(self.tmp / "d", {"dist/index.js": folded}, pj=pj))
        self.assertEqual(code, 2, text)
        self.assertIn("built for Windows only: dist/index.js", text)

    def test_version_from_chromium_then_package_json_then_option(self):
        src = electron_win_folder(self.tmp / "w", version_string=False)
        code, text, _ = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("Chromium 124.0.6367.243", text)

        pj = dict(PACKAGE_JSON, devDependencies={"electron": "30.1.2"})
        src2 = electron_win_folder(self.tmp / "w2", version_string=False, pj=pj)
        with mock.patch.object(electron, "fetch", side_effect=lambda u: fake_fetch(u) if "SHASUMS" in u
                               else (_ for _ in ()).throw(OSError("offline"))):
            code, text, _ = self.convert(src2)
        self.assertEqual(code, 0, text)
        self.assertIn('package.json ("electron": "30.1.2"', text)

        src3 = electron_win_folder(self.tmp / "w3", version_string=False, pj=dict(PACKAGE_JSON, devDependencies={}))
        (src3 / "Acme Notes.exe").write_bytes(exe_bytes())
        code, text, _ = self.convert(src3)
        self.assertEqual(code, 2)
        self.assertIn("pass --electron-version", text)
        code, text, _ = self.convert(src3, "--electron-version", "v30.1.2")
        self.assertEqual(code, 0, text)

    def test_missing_checksums_is_an_error(self):
        src = electron_win_folder(self.tmp / "w")
        code, text, _ = self.convert(src, "--electron-version", "29.0.0")
        self.assertEqual(code, 1)
        self.assertIn("pass --electron-zip", text)
        z = write(self.tmp / "electron.zip", b"zipdata")
        code, text, out = self.convert(src, "--electron-version", "29.0.0", "--electron-zip", str(z))
        self.assertEqual(code, 0, text)
        self.assertEqual(self.manifest(out)["modules"][0]["sources"][0]["sha256"],
                         hashlib.sha256(b"zipdata").hexdigest())

    def test_mac_zip_and_dmg(self):
        app = electron_mac_app(self.tmp / "m")
        z = zip_tree(app, self.tmp / "Acme-Notes-2.3.1-mac.zip")
        code, text, out = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("30.1.2 (from the Electron framework's Info.plist)", text)
        self.assertIn("fsevents.node is Mac-only", text)
        self.assertTrue((out / "app/share/icons/hicolor/256x256/apps/local.debpak.acme_notes.png").is_file())
        self.assertFalse(list((out / "app/resources").glob("*.lproj")))

        dmg = self.tmp / "dmg-src"
        shutil.copytree(app, dmg / "Acme Notes.app")
        (dmg / "Applications").symlink_to("/Applications")
        image = write(self.tmp / "Acme.dmg", b"koly-ish" + STUBTAR + tar_bytes(dmg))
        shutil.rmtree(self.tmp / "out")
        code, text, out = self.convert(image)
        self.assertEqual(code, 0, text)
        self.assertTrue(any(c.startswith("7z x -y") for c in self.stubs.calls()))

    def test_native_mac_app_is_refused(self):
        app = electron_mac_app(self.tmp / "m", electron_app=False)
        code, text, _ = self.convert(app)
        self.assertEqual(code, 1)
        self.assertIn("native macOS app", text)
        self.assertIn("machgap scan", text)

    def test_dmg_needs_7z(self):
        image = write(self.tmp / "A.dmg", b"x")
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            code, text, _ = self.convert(image)
        self.assertEqual(code, 1)
        self.assertIn("install 7-Zip", text)

    def test_nsis_electron_builder_installer(self):
        inner = electron_win_folder(self.tmp / "inner")
        payload = self.tmp / "payload"
        write(payload / "$PLUGINSDIR/app-64.7z", b"7z" + STUBTAR + tar_bytes(inner))
        write(payload / "$PLUGINSDIR/nsis7z.dll", dll_bytes())
        setup = write(self.tmp / "Acme Notes Setup 2.3.1.exe",
                      exe_bytes("Acme Notes", extra=b"NullsoftInst" + STUBTAR + tar_bytes(payload)))
        code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as nsis", text)
        self.assertEqual(self.manifest(out)["x-debpak"]["route"], "electron")
        self.assertEqual(len([c for c in self.stubs.calls() if c.startswith("7z")]), 2)

    def test_squirrel_setup(self):
        inner = electron_win_folder(self.tmp / "inner")
        nupkg = io.BytesIO()
        with zipfile.ZipFile(nupkg, "w") as z:
            z.writestr("acme.nuspec", "<package><metadata><id>acme</id><version>2.3.1</version>"
                                      "<title>Acme Notes</title><description>From nuspec</description>"
                                      "</metadata></package>")
            for p in sorted(inner.rglob("*")):
                if p.is_file():
                    z.write(p, "lib/net45/" + p.relative_to(inner).as_posix())
        data = build_pe(PeSpec(is_dll=False, imports={"kernel32.dll": ["ExitProcess"]},
                               resources=[(10, 131, nupkg.getvalue())]))
        setup = write(self.tmp / "AcmeSetup.exe", data + bytes(70000))     # trailing data: not a zip
        code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as squirrel", text)
        self.assertIn("From nuspec", (out / "app/share/metainfo/local.debpak.acme_notes.metainfo.xml").read_text())

    def test_squirrel_setup_from_releasify(self):
        # what Squirrel's releasify really embeds (GitHub Desktop, Figma): a zip of Update.exe,
        # RELEASES and APP-VERSION-full.nupkg, with the app inside that inner package
        inner = electron_win_folder(self.tmp / "inner")
        nupkg = io.BytesIO()
        with zipfile.ZipFile(nupkg, "w") as z:
            z.writestr("acme.nuspec", "<package><metadata><id>acme</id><version>2.3.1</version>"
                                      "<title>Acme Notes</title><description>Nested</description>"
                                      "</metadata></package>")
            for p in sorted(inner.rglob("*")):
                if p.is_file():
                    z.write(p, "lib/net45/" + p.relative_to(inner).as_posix())
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("Update.exe", exe_bytes("Squirrel Update"))
            z.writestr("RELEASES", "0123abcd acme-2.3.1-full.nupkg 1234\n")
            z.writestr("acme-2.3.1-full.nupkg", nupkg.getvalue())
        data = build_pe(PeSpec(is_dll=False, imports={"kernel32.dll": ["ExitProcess"]},
                               resources=[(10, 131, outer.getvalue())]))
        setup = write(self.tmp / "AcmeSetup.exe", data)
        for mode in ([], ["--mode", "extra-data", "--url", "https://acme.example/AcmeSetup.exe"]):
            out = self.tmp / ("o" + str(len(mode)))
            code, text = run_cli("convert", str(setup), "-o", str(out), "--no-build", "--no-flathub-check", *mode)
            self.assertEqual(code, 0, text)
            self.assertIn("unpacked as squirrel", text)
            self.assertIn("Nested", (out / "app/share/metainfo/local.debpak.acme_notes.metainfo.xml").read_text())


# --------------------------------------------------------------------------- Wine

def table_in_bss(data: bytes, directory: int = 13) -> bytes:
    """Point a data directory (13: delay-load imports) into the uninitialized tail of the last section."""
    b = bytearray(data)
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    nsec, opt_size = struct.unpack_from("<H", b, pe + 6)[0], struct.unpack_from("<H", b, pe + 20)[0]
    opt = pe + 24
    dirs = opt + (112 if struct.unpack_from("<H", b, opt)[0] == 0x20B else 96)
    sec = opt + opt_size + 40 * (nsec - 1)
    vsize, va, rawsize = struct.unpack_from("<III", b, sec + 8)
    struct.pack_into("<I", b, sec + 8, max(vsize, rawsize) + 0x1000)      # grow its virtual size
    struct.pack_into("<II", b, dirs + 8 * directory, va + max(vsize, rawsize) + 0x10, 32)
    return bytes(b)


class ElectronWineFallbackTests(Base):
    """A Windows Electron app the Electron route refuses is converted as its Windows build under Wine."""

    def launcher(self, out: Path) -> str:
        m = self.manifest(out)
        return (out / "app/bin" / m["command"]).read_text()

    def test_electron_on_gtk2_runs_under_wine(self):
        # Loop Drop: Electron 1.6.6, whose Linux build ended with "error while loading shared libraries:
        # libgtk-x11-2.0.so.0" on a runtime with only GTK 3
        src = electron_win_folder(self.tmp / "w", version_string=False)
        write(src / "version", "v1.6.6")
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("Electron 1.6.6's Linux build needs GTK 2 (libgtk-x11-2.0.so.0)", text)
        self.assertEqual(self.manifest(out)["x-debpak"]["route"], "wine")
        shutil.rmtree(out)
        write(src / "version", "v2.0.0")
        code, text, out = self.convert(src, "--no-wine-fallback")
        self.assertNotIn("GTK 2", text)

    def test_native_module_without_linux_build_runs_under_wine(self):
        # Descript: beamcoder.node is built for Windows and has no Linux build anywhere
        natives = {"node_modules/beamcoder/build/Release/beamcoder.node": dll_bytes()}
        src = electron_win_folder(self.tmp / "w", natives)
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("The Electron route can't convert Acme Notes, so it's converted as its Windows build "
                      "running under Wine", text)
        self.assertIn("beamcoder.node is built for Windows, and no Linux build was found", text)
        self.assertIn("(Windows program, runs under Wine)", text)
        self.assertIn("this is the Windows build of the app, running under Wine", text)
        m = self.manifest(out)
        self.assertEqual(m["base"], "org.winehq.Wine")
        self.assertEqual(m["x-debpak"]["route"], "wine")
        self.assertEqual(m["x-debpak"]["entry-point"], "/app/opt/acme-notes/Acme Notes.exe")
        self.assertTrue((out / "app/opt/acme-notes/resources/app.asar").is_file())
        script = self.launcher(out)
        self.assertIn('CHROMIUM_ARGS="${DEBPAK_CHROMIUM_ARGS---no-sandbox --disable-gpu --disable-gpu-sandbox '
                      '--in-process-gpu}"', script)
        self.assertIn('wine "$PROGRAM"/\'Acme Notes.exe\' $CHROMIUM_ARGS "$@"', script)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(report["route"], "wine")
        self.assertEqual(report["blockers"], [])

        # --no-wine-fallback keeps the refusal
        shutil.rmtree(out)
        code, text, out = self.convert(src, "--no-wine-fallback")
        self.assertEqual(code, 2, text)
        self.assertIn("beamcoder.node is built for Windows", text)
        self.assertNotIn("under Wine", text)
        self.assertFalse(out.exists())

        # inspect shows the route convert would take
        code, text = run_cli("inspect", str(src), "--no-flathub-check")
        self.assertEqual(code, 0, text)
        self.assertIn("(Windows program, runs under Wine)", text)
        code, text = run_cli("inspect", str(src), "--no-flathub-check", "--json")
        self.assertEqual(json.loads(text)["route"], "wine")

    def test_native_module_beside_the_program_runs_under_wine(self):
        # Discord's app.asar loads updater.node from beside Discord.exe, and on Linux Electron, with none
        # there, it said "Cannot find module 'discord_desktop_core'" and showed no window
        main = b'const p=require("path");let u;try{u=require(p.join(process.execPath,"..","updater.node"))}' \
               b'catch(e){if("MODULE_NOT_FOUND"===e.code)u=null}\n'
        src = electron_win_folder(self.tmp / "d", {"main.js": main})
        write(src / "updater.node", dll_bytes())
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("native module updater.node, beside the app's program, is built for Windows", text)
        self.assertEqual(self.manifest(out)["base"], "org.winehq.Wine")
        # one the app's JavaScript never names stays out of it
        shutil.rmtree(out)
        src = electron_win_folder(self.tmp / "e")
        write(src / "updater.node", dll_bytes())
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertNotIn("updater.node", text)
        self.assertNotEqual(self.manifest(out).get("base"), "org.winehq.Wine")

    def test_back_end_of_windows_programs_runs_under_wine(self):
        # Cactus Blockchain starts "cactus" from app.asar.unpacked/daemon, which holds only its Windows
        # build (cactus.exe), and on Linux Electron stopped at "spawn .../daemon/cactus ENOENT"
        main = (b'const i=require("path"),r=i.join(__dirname,"../../../app.asar.unpacked/daemon"),s="cactus";'
                b'const x=require("child_process").spawn(i.join(r,"win32"===process.platform?s+".exe":s));\n')
        src = electron_win_folder(self.tmp / "c", {"main.js": main})
        write(src / "resources/app.asar.unpacked/daemon/cactus.exe", exe_bytes("cactus"))
        write(src / "resources/app.asar.unpacked/daemon/daemon.exe", exe_bytes("daemon"))
        write(src / "resources/app.asar.unpacked/daemon/_internal/python310.dll", dll_bytes())
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("the app runs its own programs from resources/app.asar.unpacked/daemon (app.asar/main.js "
                      "names that folder), and they're built for Windows (cactus.exe, daemon.exe)", text)
        self.assertEqual(self.manifest(out)["base"], "org.winehq.Wine")
        # a folder that holds a Linux build too, or one the app never names, stays on Linux Electron
        for name, main2 in (("l", main), ("n", b'console.log("hi")\n')):
            shutil.rmtree(out)
            src = electron_win_folder(self.tmp / name, {"main.js": main2})
            write(src / "resources/app.asar.unpacked/daemon/cactus.exe", exe_bytes("cactus"))
            if name == "l":
                write(src / "resources/app.asar.unpacked/daemon/cactus", ELF)
            code, text, out = self.convert(src)
            self.assertEqual(code, 0, text)
            self.assertNotIn("runs its own programs", text)
            self.assertNotEqual(self.manifest(out).get("base"), "org.winehq.Wine")

    def test_bundle_built_for_windows_and_unknown_version_run_under_wine(self):
        # GitHub Desktop: the JavaScript only knows win32
        filler = b"function f%d(e){return e+%d}\n"
        folded = b'o.set("platform","win32");\n' + b"".join(filler % (i, i) for i in range(4000))
        code, text, out = self.convert(electron_win_folder(self.tmp / "g", {"main.js": folded}))
        self.assertEqual(code, 0, text)
        self.assertIn("its JavaScript was built for Windows only", text)
        self.assertEqual(self.manifest(out)["base"], "org.winehq.Wine")

        # Amazon Games: no Electron version anywhere; --electron-version still takes the Electron route
        src = electron_win_folder(self.tmp / "v", version_string=False, pj=dict(PACKAGE_JSON, devDependencies={}))
        (src / "Acme Notes.exe").write_bytes(exe_bytes())
        shutil.rmtree(out)
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        self.assertIn("can't tell which Electron version", text)
        self.assertEqual(self.manifest(out)["base"], "org.winehq.Wine")
        shutil.rmtree(out)
        code, text, out = self.convert(src, "--electron-version", "v30.1.2")
        self.assertEqual(code, 0, text)
        self.assertNotIn("under Wine", text)
        self.assertNotEqual(self.manifest(out).get("base"), "org.winehq.Wine")

    def test_mac_app_keeps_its_refusal(self):
        # a Mac app has no Windows build to run under Wine
        app = electron_mac_app(self.tmp / "m")
        app_asar(app / "Contents/Resources", {"node_modules/beamcoder/build/Release/beamcoder.node": MACHO})
        code, text, out = self.convert(app)
        self.assertEqual(code, 2, text)
        self.assertIn("beamcoder.node is built for Mac", text)
        self.assertNotIn("under Wine", text)
        self.assertFalse(out.exists())

    def test_squirrel_app_runs_from_its_version_folder(self):
        # Squirrel installs keep the app in app-VERSION/ beside Update.exe and a stub of the same name
        root = self.tmp / "sq"
        write(root / "Update.exe", exe_bytes("Update"))
        write(root / "Acme Notes.exe", exe_bytes(extra=bytes(9000)))
        electron_win_folder(root / "app-2.3.1", {"node_modules/beamcoder/build/Release/beamcoder.node": dll_bytes()})
        code, text, out = self.convert(root)
        self.assertEqual(code, 0, text)
        self.assertEqual(self.manifest(out)["x-debpak"]["entry-point"], "/app/opt/acme-notes/Acme Notes.exe")
        self.assertTrue((out / "app/opt/acme-notes/resources/app.asar").is_file())
        self.assertIn("--no-sandbox", self.launcher(out))

    def test_chromium_programs_are_told_apart(self):
        from debpak.winapp import chromium_program
        d = self.tmp / "c"
        exe = write(d / "a/App.exe", exe_bytes("App"))
        self.assertIsNone(chromium_program(exe))
        write(d / "a/resources/electron.asar", b"x")
        self.assertIn("resources/electron.asar", chromium_program(exe))
        # an Electron exe whose version strings weren't rewritten
        self.assertIn("Electron", chromium_program(write(d / "b/electron.exe", exe_bytes("Electron"))))
        # a Chromium shell takes Chromium's switches; a CEF app's own .exe decides what reaches Chromium
        exe = write(d / "c/Browser.exe", exe_bytes("Browser"))
        write(d / "c/chrome_100_percent.pak", b"x")
        self.assertIn("chrome_100_percent.pak", chromium_program(exe))
        write(d / "c/libcef.dll", dll_bytes())
        self.assertIsNone(chromium_program(exe))

        # an ordinary Windows program gets no Chromium switches
        z = self.tmp / "plain.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Plain.exe", exe_bytes("Plain"))
        code, text, out = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertNotIn("CHROMIUM_ARGS", self.launcher(out))


class WineTests(Base):
    def zip_of(self, name: str, files: dict[str, bytes]) -> Path:
        out = self.tmp / name
        with zipfile.ZipFile(out, "w") as z:
            for n, data in files.items():
                z.writestr(n, data)
        return out

    def main_program(self, src: Path) -> str:
        code, text, out = self.convert(src)
        self.assertEqual(code, 0, text)
        return re.search(r"program:\s+(\S+)", text).group(1)

    def test_download_name_names_the_product(self):
        # xyplorer_full_noinstall.zip: the name without "_full_noinstall" picks XYplorer.exe (32-bit)
        # over XY64.exe, a 64-bit helper that "cannot be run standalone"
        z = self.zip_of("xyplorer_full_noinstall.zip", {"XY64.exe": exe_bytes("XY64", extra=bytes(9000)),
                                                         "XYplorer.exe": exe_bytes("XYplorer", arch="i386")})
        self.assertEqual(self.main_program(z), "XYplorer.exe")
        # Garmin Express: the Squirrel stub carries the product's name, the program doesn't
        z = self.zip_of("GarminExpress.zip", {
            "Garmin Express_ExecutionStub.exe": exe_bytes("Garmin Express", extra=bytes(9000)),
            "express.exe": exe_bytes("Garmin Express")})
        self.assertEqual(self.main_program(z), "express.exe")

    def test_zip_with_backslash_paths(self):
        # Flow Launcher's portable zip names entries FlowLauncher\Update.exe and so on
        z = self.zip_of("Flow-Launcher-Portable.zip", {
            "FlowLauncher\\Update.exe": exe_bytes("Update"),
            "FlowLauncher\\Flow.Launcher.exe": exe_bytes("Flow Launcher"),
            "FlowLauncher\\app-2.1.4\\Flow.Launcher.exe": exe_bytes("Flow Launcher", extra=bytes(5000)),
            "FlowLauncher\\app-2.1.4\\Flow.Launcher.Core.dll": dll_bytes()})
        # the zip's single top folder is the program folder, and Update.exe (Squirrel's) is a helper
        self.assertEqual(self.main_program(z), "Flow.Launcher.exe")
        # mpv.net's zip, made on Windows, leaves stray bits where Unix modes go (0o10, 0o2)
        from debpak import unpack
        odd = self.tmp / "mpv.net-portable-x64.zip"
        with zipfile.ZipFile(odd, "w") as z:
            for n, bits, system in (("mpvnet.exe", 0o10, 0), ("MediaInfo.dll", 0o2, 0), ("run.sh", 0o500, 3)):
                info = zipfile.ZipInfo(n)
                info.external_attr, info.create_system = (0o100000 | bits) << 16, system
                z.writestr(info, b"x")
        unpack.unzip(odd, self.tmp / "odd")
        umask = os.umask(0o22)
        os.umask(umask)
        plain = 0o666 & ~umask
        self.assertEqual({p.name: p.stat().st_mode & 0o777 for p in (self.tmp / "odd").iterdir()},
                         {"mpvnet.exe": plain, "MediaInfo.dll": plain, "run.sh": 0o700})
        bad = self.zip_of("evil.zip", {"..\\..\\evil.exe": exe_bytes("Evil")})
        code, text, _ = self.convert(bad)
        self.assertNotEqual(code, 0)
        self.assertIn("unsafe path", text)

    def test_main_program_ranking(self):
        # each is a real layout the first compatibility run picked wrong
        paint = self.zip_of("paint.net.5.2.portable.x64.zip", {
            "paintdotnet.exe": exe_bytes("Paint.NET"),
            "ildasm.exe": exe_bytes("Microsoft .NET Framework", extra=bytes(200000))})
        self.assertEqual(self.main_program(paint), "paintdotnet.exe")
        si = self.zip_of("systeminformer-4.0.26241.138-bin.zip", {
            "arm64/SystemInformer.exe": exe_bytes("System Informer", arch="arm64", extra=bytes(9000)),
            "amd64/SystemInformer.exe": exe_bytes("System Informer"),
            "i386/SystemInformer.exe": exe_bytes("System Informer", arch="i386")})
        self.assertEqual(self.main_program(si), "amd64/SystemInformer.exe")
        bcu = self.zip_of("BCUninstaller_6.3.0_net8.0-windows10.0.18362.0.zip", {
            "BCUninstaller.exe": exe_bytes("BCUninstaller"),
            "SimpleTreeMapTestApp.exe": exe_bytes("SimpleTreeMapTests", extra=bytes(200000))})
        self.assertEqual(self.main_program(bcu), "BCUninstaller.exe")
        pn = self.zip_of("Playnite1065.zip", {
            "Playnite.DesktopApp.exe": exe_bytes("Playnite"),
            "Playnite.FullscreenApp.exe": exe_bytes("Playnite", extra=bytes(90000))})
        self.assertEqual(self.main_program(pn), "Playnite.DesktopApp.exe")

    def test_dotnet_runtime_detection(self):
        from debpak.winapp import dotnet_needs
        d = self.tmp / "net"
        d.mkdir()
        exe = write(d / "App.exe", exe_bytes("App"))
        rc = d / "App.runtimeconfig.json"

        def needs(framework=None, extra=None, dll=b""):
            opts = {"framework": framework} if framework else {}
            opts.update(extra or {})
            rc.write_text(json.dumps({"runtimeOptions": opts}))
            (d / "App.dll").write_bytes(dll)
            return dotnet_needs(exe, True)[:2]
        desktop9 = {"name": "Microsoft.WindowsDesktop.App", "version": "9.0.0"}
        self.assertEqual(needs(desktop9, dll=b"..PresentationFramework.."), (["dotnetdesktop9"], True))
        self.assertEqual(needs(desktop9), (["dotnetdesktop9"], False))                     # WinForms
        self.assertEqual(needs({"name": "Microsoft.NETCore.App", "version": "8.0.11"}), (["dotnet8"], False))
        self.assertEqual(needs(extra={"frameworks": [{"name": "Microsoft.NETCore.App", "version": "8.0.0"},
                                                     desktop9]}), (["dotnetdesktop9"], False))
        self.assertEqual(needs(extra={"includedFrameworks": [desktop9]}), ([], False))     # self-contained
        self.assertEqual(needs({"name": "Microsoft.NETCore.App", "version": "3.1.0"})[0], [])
        # a .NET newer than the Wine base app's winetricks knows comes from Microsoft's zips: OpenDirectoryDownloader
        # 5.1 was built for .NET 11 the month it came out
        self.assertEqual(needs({"name": "Microsoft.NETCore.App", "version": "11.0.0"}), (["dotnet11"], False))
        # and every framework it names: OpenDirectoryDownloader 5.1 names ASP.NET Core 11 beside .NET 11,
        # and given dotnet11 alone it ended with status 150 at "Framework: 'Microsoft.AspNetCore.App'"
        core11 = {"name": "Microsoft.NETCore.App", "version": "11.0.0"}
        asp11 = {"name": "Microsoft.AspNetCore.App", "version": "11.0.0"}
        self.assertEqual(needs(extra={"frameworks": [core11, asp11]}), (["aspnetcore11"], False))
        self.assertEqual(needs(extra={"frameworks": [core11, asp11, {**desktop9, "version": "11.0.0"}]})[0],
                         ["dotnetdesktop11", "aspnetcore11"])
        rc.write_text(json.dumps({"runtimeOptions": {"frameworks": [core11, asp11]}}))
        self.assertIn("needs Microsoft.AspNetCore.App 11.0.0 (from App.runtimeconfig.json), so the first start "
                      "installs aspnetcore11", dotnet_needs(exe, True)[2])
        rc.unlink()
        write(d / "Framework.exe", exe_bytes("F", extra=b"PresentationFramework"))
        self.assertEqual(dotnet_needs(d / "Framework.exe", True)[:2], (["dotnet48"], True))
        self.assertEqual(dotnet_needs(d / "App.exe", True)[:2], ([], False))               # wine-mono is fine
        # wine-mono can't load a mixed-mode C++/CLI assembly, which Snagit's editor has beside it
        m = self.tmp / "mixed"
        main = write(m / "SnagitEditor.exe", build_pe(PeSpec(dotnet=True)))
        write(m / "Pure.dll", build_pe(PeSpec(is_dll=True, dotnet=True)))
        self.assertEqual(dotnet_needs(main, True)[0], [])
        write(m / "TechSmith.Native.dll", build_pe(PeSpec(is_dll=True, dotnet=True, clr_flags=0)))
        verbs, _wpf, why = dotnet_needs(main, True)
        self.assertEqual(verbs, ["dotnet48"])
        self.assertIn("TechSmith.Native.dll, a mixed-mode C++/CLI assembly", why)

    def test_single_file_dotnet_app(self):
        # ScreenToGif's portable .exe is one file: apphost, then the bundled .dll and runtimeconfig.json
        from debpak.winapp import dotnet_needs
        d = self.tmp / "single"
        d.mkdir()
        config = b'{\r\n  "runtimeOptions": {\r\n    "tfm": "net9.0",\r\n    "framework": {\r\n      "name": ' \
                 b'"Microsoft.WindowsDesktop.App",\r\n      "version": "9.0.0"\r\n    }\r\n  }\r\n}'
        exe = write(d / "ScreenToGif.exe", exe_bytes("ScreenToGif") + b"\0" * 64 + b"..PresentationFramework.."
                    + b"\0" * 32 + config + b"\0{bad json" + b"\0" * 16)
        verbs, wpf, why = dotnet_needs(exe, False)
        self.assertEqual((verbs, wpf), (["dotnetdesktop9"], True))
        self.assertIn("inside ScreenToGif.exe", why)
        selfc = write(d / "Self.exe", exe_bytes("Self") + b'{"runtimeOptions": {"includedFrameworks": '
                      b'[{"name": "Microsoft.NETCore.App", "version": "8.0.1"}]}}')
        self.assertEqual(dotnet_needs(selfc, False)[0], [])
        self.assertEqual(dotnet_needs(write(d / "Plain.exe", exe_bytes("Plain")), False)[0], [])

    def test_dotnet_program_using_wmi_gets_the_framework_too(self):
        # AuthenticatorChooser, a .NET 8 single-file program, asks WMI for the Windows version, and
        # System.Management loads the .NET Framework's wminet_utils.dll for that, even on .NET 8
        from debpak.winapp import dotnet_needs
        d = self.tmp / "wmi"
        d.mkdir()
        config = b'{"runtimeOptions": {"tfm": "net8.0", "framework": {"name": "Microsoft.WindowsDesktop.App", ' \
                 b'"version": "8.0.0"}}}'
        exe = write(d / "AuthenticatorChooser.exe", exe_bytes("AuthenticatorChooser") + b"\0" * 64
                    + "wminet_utils.dll".encode("utf-16-le") + b"\0" * 32 + config)
        verbs, _wpf, why = dotnet_needs(exe, False)
        self.assertEqual(verbs, ["dotnetdesktop8", "dotnet48"])
        self.assertIn("System.Management, which loads the .NET Framework's wminet_utils.dll", why)
        # beside the program, as System.Management.dll
        app = write(d / "App.exe", exe_bytes("App"))
        write(d / "App.runtimeconfig.json", config.decode())
        self.assertEqual(dotnet_needs(app, True)[0], ["dotnetdesktop8"])
        write(d / "System.Management.dll", b"MZ..." + b"wminet_utils.dll" + b"...")
        self.assertEqual(dotnet_needs(app, True)[0], ["dotnetdesktop8", "dotnet48"])

    def test_python_program_with_pythonnet_gets_the_framework(self):
        # Creallo Atlas, frozen by PyInstaller, opens its window with pywebview, which loads
        # System.Windows.Forms through pythonnet; wine-mono's copy was an "Invalid Image"
        from debpak.winapp import dotnet_needs
        d = self.tmp / "pyn"
        onedir = write(d / "dir/Creallo3DViewer.exe", exe_bytes("Creallo3DViewer"))
        write(d / "dir/_internal/python312.dll", b"MZ")
        self.assertEqual(dotnet_needs(onedir, False)[0], [])
        write(d / "dir/_internal/pythonnet/runtime/Python.Runtime.dll", b"MZ")
        verbs, wpf, why = dotnet_needs(onedir, False)
        self.assertEqual((verbs, wpf), (["dotnet48"], False))
        self.assertIn("carries pythonnet (Python.Runtime.dll)", why)
        # a onefile build names it in the archive at its end, beside its Python
        onefile = write(d / "one/App.exe", exe_bytes("App") + b"\0" * 4096 + b"python312.dll\0"
                        + b"pythonnet\\runtime\\Python.Runtime.dll\0MEI\x0c\x0b\x0a\x0b\x0e")
        self.assertEqual(dotnet_needs(onefile, False)[0], ["dotnet48"])
        # a .NET program that ships it (to host Python) is no Python program
        self.assertEqual(dotnet_needs(write(d / "dir/Host.exe", exe_bytes("Host")), True)[0], [])

    def test_dotnet_app_gets_its_runtime(self):
        # ScreenToGif 2.43: an apphost .exe, a WPF .dll and a runtimeconfig naming .NET 9's desktop runtime
        z = self.zip_of("ScreenToGif.2.43.2.Light.Portable.x64.zip", {
            "ScreenToGif.exe": exe_bytes("ScreenToGif"),
            "ScreenToGif.dll": b"MZ...PresentationFramework...",
            "ScreenToGif.runtimeconfig.json": json.dumps({"runtimeOptions": {"tfm": "net9.0", "framework": {
                "name": "Microsoft.WindowsDesktop.App", "version": "9.0.0"}}})})
        code, text, out = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("so the first start installs dotnetdesktop9", text)
        launcher = next((out / "app/bin").iterdir()).read_text()
        self.assertIn('RUNTIMES="dotnetdesktop9 corefonts"', launcher)
        self.assertIn("DisableHWAcceleration", launcher)
        self.assertIn("--share=network", self.manifest(out)["finish-args"])        # winetricks downloads
        # the .NET installers winetricks runs include 32-bit ones, which need multiarch in Flatpak
        self.assertIn("--allow=multiarch", self.manifest(out)["finish-args"])
        self.assertEqual(self.manifest(out)["build-options"], {"no-debuginfo": True})

    def test_wine_mono_skips_the_dotnet_runtime(self):
        # WinCompose 0.9.11: a WPF program for .NET Framework gets dotnet48, whose culture code then fails
        # under Wine (CultureData.get_STEXTINFO), so --wine-runtime wine-mono keeps it on wine-mono
        spec = PeSpec(arch="i386", is_dll=False, dotnet=True, imports={"mscoree.dll": ["_CorExeMain"]},
                      resources=[version_info({"ProductName": "WinCompose", "ProductVersion": "0.9.11"})])
        exe = write(self.tmp / "wincompose.exe", build_pe(spec) + b"..PresentationFramework..")
        code, text, out = self.convert(exe)
        self.assertEqual(code, 0, text)
        launcher = next((out / "app/bin").iterdir()).read_text()
        self.assertIn('RUNTIMES="dotnet48 corefonts"', launcher)
        code, text, out = self.convert(exe, "--wine-runtime", "wine-mono")
        self.assertEqual(code, 0, text)
        self.assertIn("runs on wine-mono (--wine-runtime wine-mono), so dotnet48 isn't installed", text)
        self.assertNotIn("--wine-runtime dotnet48", text)            # and isn't suggested either
        launcher = next((out / "app/bin").iterdir()).read_text()
        self.assertIn('RUNTIMES="corefonts"', launcher)               # WPF still gets its fonts
        self.assertIn("DisableHWAcceleration", launcher)
        self.assertNotIn("wine-mono", launcher)                       # never handed to winetricks
        self.assertEqual(self.manifest(out)["x-debpak"]["runtimes"], ["corefonts"])

    def test_dotnet_type_refs(self):
        # the compiler keeps PropertyGrid only as the end of FilteredPropertyGrid, as in mRemoteNG.exe,
        # so the TypeRef table has to be read
        from debpak.pe import dotnet_type_refs
        refs = [("System.Windows.Forms", "PropertyGrid"), ("System", "Object")]
        data = build_pe(PeSpec(arch="i386", is_dll=False, dotnet=True, type_refs=refs))
        self.assertNotIn(b"\0PropertyGrid\0", data)
        self.assertEqual(dotnet_type_refs(write(self.tmp / "Grid.exe", data)), set(refs))
        self.assertEqual(dotnet_type_refs(write(self.tmp / "Plain.exe", exe_bytes("Plain"))), set())
        self.assertEqual(dotnet_type_refs(write(self.tmp / "Bad.exe", data.replace(b"BSJB", b"XXXX"))), set())
        cut = data.index(b"#Strings")          # the stream table runs off the end of the file
        self.assertEqual(dotnet_type_refs(write(self.tmp / "Cut.exe", data[:cut])), set())
        self.assertEqual(dotnet_type_refs(self.tmp / "missing.exe"), set())

    def test_property_grid_gets_dotnet48(self):
        # mRemoteNG 1.76: wine-mono's PropertyGrid draws its Config panel's category row and labels as
        # black boxes; on dotnet48 they read Display, Name, Password protect
        def program(name, refs):
            spec = PeSpec(arch="i386", is_dll=False, dotnet=True, type_refs=refs, imports={
                "mscoree.dll": ["_CorExeMain"]}, resources=[version_info({"ProductName": name,
                                                                          "ProductVersion": "1.76.20"})])
            return write(self.tmp / f"{name}.exe", build_pe(spec))
        code, text, out = self.convert(program("mRemoteNG", [("System.Windows.Forms", "Form"),
                                                             ("System.Windows.Forms", "PropertyGrid")]))
        self.assertEqual(code, 0, text)
        self.assertIn("WinForms program with a PropertyGrid", text)
        launcher = next((out / "app/bin").iterdir()).read_text()
        self.assertIn('RUNTIMES="dotnet48"', launcher)
        self.assertNotIn("DisableHWAcceleration", launcher)               # not WPF
        # a WinForms program without one stays on wine-mono, and so does one that asks for it
        code, text, out = self.convert(program("Plain", [("System.Windows.Forms", "Form"),
                                                         ("Acme.Controls", "PropertyGrid")]))
        self.assertNotIn("RUNTIMES=", next((out / "app/bin").iterdir()).read_text())
        code, text, out = self.convert(program("mRemoteNG", [("System.Windows.Forms", "PropertyGrid")]),
                                       "--wine-runtime", "wine-mono")
        self.assertIn("so dotnet48 isn't installed", text)

    def test_obfuscated_program_gets_dotnet48(self):
        # Fiddler Classic (SmartAssembly) and S3 Browser (Babel's "babelvm", a UTF-16 string): wine-mono
        # stops on their code with "Invalid IL code" and "babel e3 ... NotImplementedException"
        def program(name, extra):
            spec = PeSpec(arch="i386", is_dll=False, dotnet=True, type_refs=[("System.Windows.Forms", "Form")],
                          imports={"mscoree.dll": ["_CorExeMain"]},
                          resources=[version_info({"ProductName": name, "ProductVersion": "5.0"})])
            return write(self.tmp / f"{name}.exe", build_pe(spec) + extra)
        for name, extra, tool in (("Fiddler", b"FiddlerCore.Utilities.SmartAssembly.Attributes\0", "SmartAssembly"),
                                  ("S3Browser", "babelvm".encode("utf-16-le"), "Babel")):
            code, text, out = self.convert(program(name, extra))
            self.assertEqual(code, 0, text)
            self.assertIn(f"is obfuscated with {tool}", text)
            self.assertIn('RUNTIMES="dotnet48"', next((out / "app/bin").iterdir()).read_text())

    def test_table_in_uninitialized_data(self):
        # Rufus 4.16: a table's RVA lies past the section's file data; the loader reads zeros there
        exe = write(self.tmp / "Tool.exe", table_in_bss(exe_bytes("Tool")))
        from debpak.pe import read_pe
        info = read_pe(exe)
        self.assertTrue(info.problems)
        self.assertIn("kernel32.dll", info.imported_dlls)                 # the normal imports still read
        code, text, out = self.convert(exe)
        self.assertEqual(code, 0, text)
        self.assertIn("imports were only partly checked", text)

    def test_portable_program(self):
        exe = write(self.tmp / "AcmeTool.exe", exe_bytes("Acme Tool", "1.4.0", imports={
            "kernel32.dll": ["ExitProcess"], "ws2_32.dll": ["connect"]}))
        code, text, out = self.convert(exe, "--app-id", "org.example.AcmeTool")
        self.assertEqual(code, 0, text)
        self.assertIn("Acme Tool 1.4.0 (Windows program, runs under Wine)", text)
        m = self.manifest(out)
        self.assertEqual((m["base"], m["base-version"], m["runtime-version"]), ("org.winehq.Wine", "wow64-25.08",
                                                                                 "25.08"))
        self.assertEqual(m["inherit-extensions"], ["org.winehq.Wine.gecko-wow64", "org.winehq.Wine.mono-wow64"])
        self.assertIn("--share=network", m["finish-args"])
        self.assertIn("no Wine index is cached", text)
        launcher = (out / "app/bin/acme-tool").read_text()
        self.assertIn('wine "$PROGRAM"/AcmeTool.exe "$@"\nstatus=$?\n', launcher)
        self.assertIn("\nwineserver -w\nexit \"$status\"\n", launcher)
        self.assertNotIn("Program Files", launcher)      # run where it is, not from a copy
        self.assertTrue((out / "app/opt/acme-tool/AcmeTool.exe").is_file())
        desktop = (out / "app/share/applications/org.example.AcmeTool.desktop").read_text()
        self.assertIn("StartupWMClass=acmetool.exe", desktop)
        self.assertIn("Exec=acme-tool %F", desktop)
        self.assertTrue((out / "app/share/icons/hicolor/64x64/apps/org.example.AcmeTool.png").is_file())

    def test_no_icon_gets_a_placeholder(self):
        # appstreamcli compose (run by flatpak-builder) fails a desktop app that has no icon
        exe = write(self.tmp / "Bare.exe", exe_bytes("Bare Tool", icon=False))
        code, text, out = self.convert(exe, "--app-id", "org.example.Bare")
        self.assertEqual(code, 0, text)
        icon = out / "app/share/icons/hicolor/128x128/apps/org.example.Bare.png"
        self.assertTrue(icon.read_bytes().startswith(b"\x89PNG"))
        self.assertIn("made a plain placeholder icon", text)

    def test_small_icon_gets_a_scaled_up_copy(self):
        # NirSoft's HashMyFiles, SharpKeys and others carry nothing over 32x32, and
        # appstreamcli compose finds no icon under 64x64: "E: icon-not-found"
        exe = build_pe(PeSpec(imports={"kernel32.dll": ["ExitProcess"]}, subsystem=2, resources=[
            version_info({"ProductName": "Hash Tool", "ProductVersion": "2.0"}), *icon_resources(dib_icon(32), 32)]))
        code, text, out = self.convert(write(self.tmp / "HashTool.exe", exe), "--app-id", "org.example.HashTool")
        self.assertEqual(code, 0, text)
        icons = out / "app/share/icons/hicolor"
        self.assertEqual(sorted(p.parts[-3] for p in icons.glob("*/apps/org.example.HashTool.png")),
                         ["128x128", "32x32"])
        w, h, px = winres.png_pixels((icons / "128x128/apps/org.example.HashTool.png").read_bytes())
        self.assertEqual((w, h, px[:4], px[-4:]), (128, 128, b"\x80\x40\x20\xff", b"\x80\x40\x20\xff"))
        self.assertIn("only 32x32; added a 128x128 copy", text)
        # a 64x64 icon is big enough on its own
        code, text, out = self.convert(write(self.tmp / "Big.exe", exe_bytes("Big Tool")), "--app-id", "org.example.Big")
        self.assertEqual([p.parts[-3] for p in (out / "app/share/icons/hicolor").glob("*/apps/*.png")], ["64x64"])
        self.assertNotIn("scaled up", text)

    def test_runtime_26_08_uses_stable_branch(self):
        exe = write(self.tmp / "AcmeTool.exe", exe_bytes("Acme Tool"))
        code, text, out = self.convert(exe, "--runtime", "org.freedesktop.Platform//26.08")
        self.assertEqual(code, 0, text)
        m = self.manifest(out)
        self.assertEqual((m["base-version"], m["inherit-extensions"]),
                         ("stable-26.08", ["org.winehq.Wine.gecko", "org.winehq.Wine.mono"]))
        code, text, out = self.convert(exe, "--wine-branch", "wow64-24.08")
        self.assertEqual(self.manifest(out)["runtime-version"], "24.08")

    def test_inno_installer_and_exec_override(self):
        payload = self.tmp / "inno"
        write(payload / "app/Acme.exe", exe_bytes("Acme"))
        write(payload / "app/unins000.exe", exe_bytes("Setup/Uninstall") + bytes(9000))
        write(payload / "app/tools/convert.exe", exe_bytes("Converter", subsystem=3))
        setup = write(self.tmp / "acme-setup-3.0.exe",
                      exe_bytes("Acme Setup", description="Acme Setup", extra=b"Inno Setup Setup Data (6.2.0)"
                                + STUBTAR + tar_bytes(payload)))
        code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Acme.exe", text)
        self.assertIn("installer's own steps", text)
        self.assertTrue(any(c.startswith("innoextract --silent") for c in self.stubs.calls()))
        self.assertFalse(any("--language " in c for c in self.stubs.calls()))
        code, text, out = self.convert(setup, "--exec", "tools/convert.exe", "--writable")
        self.assertEqual(code, 0, text)
        launcher = (out / "app/bin/acme").read_text()
        self.assertIn('cd "$PROGRAM"/tools', launcher)
        self.assertIn("drive_c/Program Files/acme", launcher)
        code, text, _ = self.convert(setup, "--exec", "nope.exe")
        self.assertEqual(code, 2)

    def test_self_extracting_zip_with_a_cab(self):
        # Total Commander: tcmd*.exe is a zip of INSTALL.CAB (the program files) and INSTALL.INF
        setup = cab_installer(self.tmp)
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable TOTALCMD64.EXE", text)
        self.assertIn("unpacked as cab", text)
        self.assertIn("installer's own steps", text)
        self.assertTrue(any(c.startswith("7z ") and c.endswith("INSTALL.CAB") for c in self.stubs.calls()))
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            code, text, _ = self.convert(setup)
        self.assertEqual(code, 1)
        self.assertIn("unpacking this needs 7z", text)
        # a zip with a program next to a .cab is an ordinary program zip
        z = self.zip_of("tool.zip", {"tool/Tool.exe": exe_bytes("Tool"), "tool/data.cab": b"MSCF"})
        self.assertEqual(self.main_program(z), "Tool.exe")

    def test_rar_self_extractor(self):
        # WinRAR's installer (winrar-x64-723.exe) is a program with a RAR archive after it
        files = self.tmp / "rar-src"
        write(files / "WinRAR.exe", exe_bytes("WinRAR", extra=bytes(20000)))
        write(files / "Rar.exe", exe_bytes("WinRAR", subsystem=3))
        write(files / "Uninstall.exe", exe_bytes("WinRAR uninstaller"))
        write(files / "RarExtInstaller.exe", exe_bytes("WinRAR shell extension installer"))
        setup = write(self.tmp / "winrar-x64-723.exe",
                      exe_bytes("WinRAR", description="WinRAR installer",
                                extra=b"Rar!\x1a\x07\x01\x00" + STUBTAR + tar_bytes(files)))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as rar-sfx", text)
        # on the archive cut from the .exe, which bsdtar reads where it can't read the .exe whole
        # (EditPlus's epp610_0780_64bit.exe)
        self.assertTrue(any(c.startswith("bsdtar -x -C ") and c.endswith("step0.rar") for c in self.stubs.calls()))
        self.assertIn("main executable WinRAR.exe", text)
        from debpak import unpack
        self.assertFalse(unpack.sfx_rar(write(self.tmp / "plain.exe", exe_bytes("Plain"))))

    def test_7zip_self_extractor_of_installers(self):
        # Hex Editor Neo's download is a 7-Zip self-extractor of installers, one per architecture;
        # setup_x64.exe was taken for the program, and it installed nothing and exited
        def sfx(files: Path, name: str, **kw) -> bytes:
            body = STUBTAR + tar_bytes(files)
            start = struct.pack("<QQI", len(body) - 40, 40, 0)
            header = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start
            return exe_bytes(name, extra=header + body, **kw)
        app = self.tmp / "hex-app"
        write(app / "HexFrame.exe", exe_bytes("Hex Editor Neo"))
        inner = self.tmp / "hex-sfx"
        write(inner / "setup.exe", exe_bytes("Hex Editor Neo Setup", arch="i386"))
        write(inner / "setup_x86.exe", exe_bytes("Hex Editor Neo Setup", arch="i386", extra=bytes(5000)))
        write(inner / "setup_x64.exe", sfx(app, "Hex Editor Neo Setup"))
        outer = write(self.tmp / "free-hex-editor-neo.exe", sfx(inner, "Hex Editor Neo Setup Package"))
        code, text, _ = self.convert(outer)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable HexFrame.exe", text)
        self.assertEqual(len([c for c in self.stubs.calls() if c.startswith("7z ")]), 2)

    def test_7zip_self_extractor(self):
        # 7-Zip's installer (7z2606-x64.exe) is a program with a 7z archive after it
        setup = sevenzip_sfx(self.tmp)
        code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as 7z-sfx", text)
        self.assertTrue((out / "local.debpak._7_zip.json").is_file())       # an app ID part can't start with 7
        self.assertIn("main executable 7zFM.exe", text)
        self.assertIn("installer's own steps", text)
        (call,) = [c for c in self.stubs.calls() if c.startswith("7z ")]
        self.assertTrue(call.endswith("step0.7z"), call)
        from debpak import unpack
        offset = unpack.sfx_7z_offset(setup)
        unpack.cut_7z(setup, offset, self.tmp / "cut.7z")
        self.assertEqual((self.tmp / "cut.7z").read_bytes(), setup.read_bytes()[offset:-900])
        with self.assertRaisesRegex(unpack.UnpackError, "no 7z archive"):
            unpack.cut_7z(setup, offset + 1, self.tmp / "bad.7z")
        self.assertIsNone(unpack.sfx_7z_offset(write(self.tmp / "plain.exe", exe_bytes("Plain"))))
        self.assertTrue(next((out / "app/opt").iterdir()).joinpath("7z.dll").is_file())
        # a program with only a stray signature after it, and no valid archive, is still refused
        stray = write(self.tmp / "AcmeSetup.exe", exe_bytes("Acme Setup", extra=b"7z\xbc\xaf\x27\x1c" + bytes(40)))
        code, text, _ = self.convert(stray)
        self.assertEqual(code, 1, text)
        self.assertIn("looks like an installer", text)

    def test_inno_installer_with_both_builds_keeps_the_64_bit_one(self):
        # Active@ KillDisk's setup has a 32-bit and a 64-bit KillDisk.exe and Qt5Core.dll under the same
        # names; innoextract wrote each over the one before, leaving the 64-bit program beside the 32-bit
        # Qt5Core.dll, which Wine couldn't load (c000007b, status 53). Asked to rename them, it writes
        # NAME$0, NAME$1 in the installer's order
        from debpak.pe import read_pe
        payload = self.tmp / "inno"
        write(payload / "app/KillDisk.exe$0", exe_bytes("KillDisk", arch="i386"))
        write(payload / "app/KillDisk.exe$1", exe_bytes("KillDisk"))
        write(payload / "app/Qt5Core.dll$0", build_pe(PeSpec(arch="x86_64", is_dll=True)))
        write(payload / "app/Qt5Core.dll$1", build_pe(PeSpec(arch="i386", is_dll=True)))
        # anything else keeps its last copy, as when one was written over the other
        write(payload / "app/readme.txt$0", b"first")
        write(payload / "app/readme.txt$1", b"second")
        # a name of its own that ends in $<n> is left alone
        write(payload / "app/cache$2", b"data")
        write(payload / "app/cache", b"data")
        setup = write(self.tmp / "KillDisk-Setup.exe",
                      exe_bytes("KillDisk Setup", extra=b"Inno Setup Setup Data (6.2.0)" + STUBTAR + tar_bytes(payload)))
        code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertTrue(any("--collisions rename-all" in c for c in self.stubs.calls()))
        (slug,) = (out / "app/opt").iterdir()
        self.assertEqual(read_pe(slug / "KillDisk.exe").machine, "x86_64")
        self.assertEqual(read_pe(slug / "Qt5Core.dll").machine, "x86_64")
        self.assertEqual((slug / "readme.txt").read_bytes(), b"second")
        self.assertTrue((slug / "cache$2").is_file())
        self.assertFalse([p.name for p in slug.iterdir() if re.search(r"\$[01]$", p.name)])

    def test_inno_installer_extracts_one_language(self):
        # TreeSize Free 3.4.5's installer has English and German; extracting both left the German
        # translation TreeSizeFree.DE beside the .exe and the program started in German
        payload = self.tmp / "inno"
        write(payload / "app/TreeSizeFree.exe", exe_bytes("TreeSize Free"))
        setup = write(self.tmp / "TreeSizeFreeSetup.exe",
                      exe_bytes("TreeSize Free Setup", extra=b"Inno Setup Setup Data (5.5.7) (u)"
                                + STUBTAR + tar_bytes(payload)))
        for langs, want in (("de: Deutsch;en: English", "--language en "),
                            ("deutsch: Deutsch;english: English (US)", "--language english "),
                            ("fr: Fran\u00e7ais;de: Deutsch", "--language fr ")):
            with mock.patch.dict(os.environ, {"STUB_INNO_LANGS": langs}):
                self.stubs.log.unlink(missing_ok=True)
                code, text, out = self.convert(setup)
            self.assertEqual(code, 0, text)
            extract = [c for c in self.stubs.calls() if "--extract" in c]
            self.assertTrue(extract and want in extract[0], (langs, extract))
        # one language (or a listing innoextract can't give): everything is extracted
        with mock.patch.dict(os.environ, {"STUB_INNO_LANGS": "en: English"}):
            self.stubs.log.unlink(missing_ok=True)
            code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertFalse(any("--language " in c for c in self.stubs.calls()))

    def test_inno_installer_newer_than_innoextract(self):
        # innoextract 1.9 stops at Inno Setup 6.2.2; Notepad3's installer is newer
        write(self.stubs.bin / "innoextract", textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = --version ]; then echo "innoextract 1.9"; exit 0; fi
            echo "Stream error while parsing setup headers!" >&2
            echo "If you are sure the setup file is not corrupted, consider filing a bug report" >&2
            echo "Done with 1 error and 2 warnings." >&2
            exit 1
            """), 0o755)
        new = write(self.tmp / "Notepad3_7.26.602.1_x64_Setup.exe",
                    exe_bytes("Notepad3 Setup", extra=b"Inno Setup Setup Data (6.4.3)\0"))
        code, text, _ = self.convert(new)
        self.assertEqual(code, 1, text)
        self.assertIn("was made with Inno Setup 6.4.3, which is newer than innoextract 1.9 can read", text)
        self.assertIn("up to Inno Setup 6.2.2", text)
        self.assertIn("Install it in Wine instead", text)
        old = write(self.tmp / "old-setup.exe", exe_bytes("Old Setup", extra=b"Inno Setup Setup Data (6.2.2) (u)\0"))
        code, text, _ = self.convert(old)
        self.assertEqual(code, 1, text)
        self.assertIn("innoextract failed:", text)
        self.assertIn("(old-setup.exe was made with Inno Setup 6.2.2)", text)
        self.assertNotIn("newer than", text)
        # with Wine there, the installer runs silently under it instead
        drive = self.tmp / "drive"
        write(drive / "users/me/AppData/Local/Programs/Notepad3/Notepad3.exe", exe_bytes("Notepad3"))
        write(drive / "Program Files/Windows NT/Accessories/wordpad.exe", exe_bytes("WordPad") + bytes(50000))
        new = write(self.tmp / "Notepad3_7.26.602.1_x64_Setup.exe",
                    exe_bytes("Notepad3 Setup", extra=b"Inno Setup Setup Data (6.4.3)\0" + STUBTAR + tar_bytes(drive)))
        with mock.patch.dict(os.environ, {"STUB_WINE": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /CURRENTUSER /LOG=C:\\debpak-setup.log"}):
            code, text, _ = self.convert(new)
        self.assertEqual(code, 0, text)
        self.assertIn("running it silently under Wine instead", text)
        self.assertIn("main executable Notepad3.exe", text)
        (run,) = [c for c in self.stubs.calls() if c.startswith("flatpak run ")]
        self.assertIn("--sandbox", run)
        self.assertIn("--unshare=network", run)

    def test_wix_bundle_with_its_msi_inside(self):
        # Foxit PDF Reader's bundle: the .msi is in the second container, as payload a1
        prog = self.tmp / "msi"
        write(prog / "Program Files/Foxit Software/Foxit PDF Reader/FoxitPDFReader.exe", exe_bytes("Foxit PDF Reader"))
        ux = self.tmp / "ux"
        write(ux / "0", '<BurnManifest xmlns="http://wixtoolset.org/schemas/v4/2008/Burn">'
              '<Payload Id="p0" FilePath="de.mst" SourcePath="a0" Container="WixAttachedContainer"/>'
              '<Payload Id="p1" FilePath="FoxitPDFReader.msi" SourcePath="a1" Container="WixAttachedContainer"/>'
              '</BurnManifest>')
        attached = self.tmp / "attached"
        write(attached / "a0", b"transform")
        write(attached / "a1", b"MSI" + STUBTAR + tar_bytes(prog))
        cabs = [STUBTAR + tar_bytes(ux), STUBTAR + tar_bytes(attached)]
        setup = write(self.tmp / "FoxitPDFReader_Setup_x64.exe", burn_bundle(cabs, gap=21161))
        from debpak import unpack
        data = setup.read_bytes()
        self.assertEqual([data[o:o + 4] for o, _ in unpack.burn_containers(setup)], [b"MSCF", b"MSCF"])
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as wix", text)
        self.assertIn("main executable Program Files/Foxit Software/Foxit PDF Reader/FoxitPDFReader.exe", text)
        (msi,) = [c for c in self.stubs.calls() if c.startswith("msiextract")]
        self.assertTrue(msi.endswith("/payloads/FoxitPDFReader.msi"), msi)       # by its own name
        # a bundle that downloads its packages has only the first container
        stub = write(self.tmp / "EAappInstaller.exe", burn_bundle(cabs[:1]))
        code, text, _ = self.convert(stub)
        self.assertEqual(code, 1, text)
        self.assertIn("is a WiX bundle with no .msi inside, and running it under Wine didn't work either", text)

    def test_installer_with_its_program_in_a_cabinet(self):
        # NCH Software's wavepadfsetup64.exe keeps WavePad.exe in a cabinet among its resources
        files = self.tmp / "nch"
        write(files / "WavePad.exe", exe_bytes("WavePad"))
        body = STUBTAR + tar_bytes(files)
        cab = b"MSCF\0\0\0\0" + struct.pack("<I", 36 + len(body)) + bytes(12) + bytes([3, 1]) + bytes(10) + body
        setup = write(self.tmp / "wavepadfsetup64.exe", exe_bytes("WavePad Setup", description="Setup", extra=cab))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as cab-sfx", text)
        self.assertIn("main executable WavePad.exe", text)

    def test_installer_of_a_printer_driver_is_refused_as_a_driver(self):
        # pdfFactory's pdf936pro.exe, an installer nothing here reads, keeps the driver of the virtual
        # printer it installs in cabinets among its resources; taken for a portable program it ran on
        # with no window
        def cab(files: Path) -> bytes:
            body = STUBTAR + tar_bytes(files)
            return b"MSCF\0\0\0\0" + struct.pack("<I", 36 + len(body)) + bytes(12) + bytes([3, 1]) + bytes(10) + body
        drv = self.tmp / "drv"
        write(drv / "fpp9_x64_driver.inf", b";\r\n; pdfFactory Pro 9\r\n[Version]\r\nSignature=\"$Windows NT$\"\r\n"
                                           b"Class=Printer\r\nClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\r\n")
        setup = write(self.tmp / "pdf936pro.exe", exe_bytes("pdfFactory", description="pdfFactory", extra=cab(drv)))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 2, text)
        self.assertIn("pdf936pro.exe installs a printer driver (fpp9_x64_driver.inf, of Windows' Printer class)", text)
        # a program that carries some other .inf (a USB device's, in UTF-16) is a program
        write(drv / "fpp9_x64_driver.inf", "[Version]\r\nClass=USB\r\n".encode("utf-16"))
        setup = write(self.tmp / "tool.exe", exe_bytes("Tool", description="Tool", extra=cab(drv)))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as portable", text)

    def test_program_carrying_a_zip_of_resources(self):
        # JetBrains' dotPeek64.exe is the portable dotPeek: a zip of resources rides inside it,
        # with no program in the zip, and Wine is no help (it installs nothing)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("Resources/#10/HOSTCOMP.STG", b"x" * 100)
        exe = write(self.tmp / "dotPeek64.2026.3.0.2.exe",
                    exe_bytes("dotPeek", description="JetBrains dotPeek", extra=buf.getvalue()))
        self.assertTrue(zipfile.is_zipfile(exe))
        code, text, _ = self.convert(exe)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as portable", text)
        self.assertIn("main executable dotPeek64.2026.3.0.2.exe", text)

    def test_installer_with_a_larger_cabinet_of_its_own_before_the_program(self):
        # Doxillion's doxpsetup.exe: a cabinet of the setup's own resource.dat, larger than the
        # one with Doxillion.exe, comes first
        def cab(files: Path) -> bytes:
            body = STUBTAR + tar_bytes(files)
            return b"MSCF\0\0\0\0" + struct.pack("<I", 36 + len(body)) + bytes(12) + bytes([3, 1]) + bytes(10) + body
        own, prog = self.tmp / "own", self.tmp / "prog"
        write(own / "resource.dat", os.urandom(200_000))
        write(prog / "Doxillion.exe", exe_bytes("Doxillion"))
        setup = write(self.tmp / "doxpsetup.exe", exe_bytes("Doxillion", description="Doxillion Document Converter",
                                                            extra=cab(own) + cab(prog)))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as cab-sfx", text)
        self.assertIn("main executable Doxillion.exe", text)

    def test_msi_folder_named_with_a_colon(self):
        # LTspice's and PhraseExpress's .msi: msiextract writes a folder "APPDIR:.", and Wine can't
        # open a program under it
        tree = self.tmp / "msi-tree"
        write(tree / "APPDIR:./LTspice.exe", exe_bytes("LTspice"))
        write(tree / "APPDIR:./lib/sub.dll", dll_bytes())
        msi = write(self.tmp / "LTspice64.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(tree))
        code, text, _ = self.convert(msi)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable APPDIR/LTspice.exe", text)

    def test_zip_of_an_msi_alone(self):
        # Ableton Live's zip holds Setup.msi and nothing else, ScrambleID's its .msi and a README:
        # taken for Linux tarballs, they had no main executable
        tree = self.tmp / "live-msi"
        write(tree / "Program Files 64/Ableton/Live 10 Suite/Program/Ableton Live 10 Suite.exe",
              exe_bytes("Ableton Live 10 Suite") + bytes(9000))
        write(tree / "Program Files 64/Ableton/Live 10 Suite/Program/Ableton Index.exe", exe_bytes("Ableton Index"))
        z = self.tmp / "ableton_live_suite_10.1.43_64.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Setup.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(tree))
        code, text, _ = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Program Files 64/Ableton/Live 10 Suite/Program/Ableton Live 10 Suite.exe",
                      text)

    def test_zip_of_an_msi_with_its_setup_and_helpers(self):
        # Quark Update's zip: Quark Update.msi with its Data1.cab, the InstallShield setup.exe that
        # runs it, vcredist_x64.exe and SelfUpdater.exe; nothing was taken, as SelfUpdater.exe isn't
        # an installer. The .msi names System64Folder ".:System64", and its program gives its version
        # as "2,7,2,0"
        tree = self.tmp / "quark-msi"
        write(tree / "Program Files 64/Quark/Quark Update/CheckUpdate.exe", exe_bytes("CheckUpdate", version="2,7,2,0"))
        write(tree / "Program Files 64/Quark/Quark Update/.:System64/qlib.dll", dll_bytes())
        z = self.tmp / "QuarkUpdate272_50034B_Win.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Quark Update.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(tree))
            zf.writestr("Data1.cab", b"MSCF" + bytes(100))
            zf.writestr("setup.exe", exe_bytes("Quark Update Setup", extra=b"InstallShield"))
            zf.writestr("vcredist_x64.exe", exe_bytes("Microsoft Visual C++ Redistributable"))
            zf.writestr("SelfUpdater.exe", exe_bytes("SelfUpdater"))
        code, text, _ = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Program Files 64/Quark/Quark Update/CheckUpdate.exe", text)
        self.assertIn("CheckUpdate 2.7.2.0 (Windows program", text)
        self.assertNotIn("2,7,2,0", text)
        # a program beside the installers is still the program, not the .msi
        with zipfile.ZipFile(self.tmp / "portable.zip", "w") as zf:
            zf.writestr("Acme.exe", exe_bytes("Acme"))
            zf.writestr("runtime.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        code, text, _ = self.convert(self.tmp / "portable.zip")
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Acme.exe", text)

    def test_zip_of_an_inno_setup_with_encrypted_files(self):
        # Winaero Tweaker's zip holds its Inno setup, whose files are encrypted: innoextract leaves
        # {app} without a program, so the setup inside the zip runs under Wine
        files = self.tmp / "winaero"
        write(files / "app/readme.txt", "encrypted files are skipped")
        write(files / "Program Files/Winaero Tweaker/WinaeroTweaker.exe", exe_bytes("Winaero Tweaker"))
        setup = exe_bytes("Winaero Tweaker Setup", extra=b"Inno Setup Setup Data (6.2.0)" + STUBTAR + tar_bytes(files))
        z = self.tmp / "winaerotweaker.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("SilentSetup.cmd", "WinaeroTweaker-1.65.0.0-setup.exe /SP- /VERYSILENT\r\n")
            zf.writestr("If the app does not start.txt", "...")
            zf.writestr("WinaeroTweaker-1.65.0.0-setup.exe", setup)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /CURRENTUSER "
                                                       "/LOG=C:\\debpak-setup.log"}):
            code, text, _ = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("innoextract unpacked no program into its {app} folder", text)
        self.assertIn("main executable WinaeroTweaker.exe", text)

    def test_msi_of_a_library_is_not_an_app(self):
        # SDL3Installer.msi installs SDL3.dll, a licence and a readme, and puts the folder on PATH
        tree = self.tmp / "sdl3"
        write(tree / "PFiles64/SDL3/LICENSE.txt", "zlib")
        write(tree / "PFiles64/SDL3/lib/SDL3.dll", dll_bytes())
        msi = write(self.tmp / "SDL3Installer.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(tree))
        code, text, _ = self.convert(msi)
        self.assertEqual(code, 1, text)
        self.assertIn("SDL3Installer.msi installs no program, only libraries (SDL3.dll)", text)

    def test_electron_helper_of_a_bigger_program_is_not_the_app(self):
        # AnyLogic University's folder: AnyLogic.exe, a Java program, at the top, and al-animation, an
        # Electron viewer it starts with a model's URL, below; the viewer was converted as the app
        top = self.tmp / "anylogic/AnyLogic"
        electron_win_folder(top / "plugins/al-animation")
        write(top / "AnyLogic.exe", exe_bytes("AnyLogic", version="8.9.10"))
        write(top / "jre/bin/javaw.exe", exe_bytes("Java"))
        code, text, _ = self.convert(zip_tree(self.tmp / "anylogic", self.tmp / "anylogic-university-8.9.10.zip"))
        self.assertEqual(code, 0, text)
        self.assertIn("main executable AnyLogic.exe", text)
        self.assertNotIn("(Electron app)", text)
        # a Squirrel app's stub beside its app-VERSION folder is a copy of the app's program, not another
        squirrel = self.tmp / "squirrel/Acme"
        electron_win_folder(squirrel / "app-2.3.1")
        write(squirrel / "Acme Notes.exe", exe_bytes("Acme Notes"))
        write(squirrel / "Update.exe", exe_bytes("Update"))
        code, text, _ = self.convert(zip_tree(self.tmp / "squirrel", self.tmp / "AcmeNotes-2.3.1.zip"))
        self.assertEqual(code, 0, text)
        self.assertIn("(Electron app)", text)

    def test_install_in_wine_runs_an_installer_debpak_could_unpack(self):
        # DBT's .msi unpacked to its program, but not to the version.xml a custom action of the package
        # writes as it installs; with --install-in-wine (the check's last remedy) msiexec installs it
        from debpak import foreign
        drive = self.tmp / "drive"
        write(drive / "Program Files/Duxbury/DBT 15.1/dbtw.exe", exe_bytes("DBT") + bytes(9000))
        write(drive / "Program Files/Duxbury/DBT 15.1/version.xml", b"<version/>")
        msi = write(self.tmp / "dbt-1501sr2.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(drive))

        def unpacked(path, out):
            write(out / "Program Files/Duxbury/DBT 15.1/dbtw.exe", exe_bytes("DBT") + bytes(9000))
        foreign.forget_installed()
        with mock.patch.dict(os.environ, {"STUB_WINE": "/qn /norestart"}), \
                mock.patch.object(foreign, "_msiextract", unpacked):
            code, text, out = self.convert(msi)
            self.assertEqual(code, 0, text)
            self.assertIn("unpacked as msi", text)
            self.assertFalse([c for c in self.stubs.calls() if c.startswith("flatpak run ")])
            code, text, out = self.convert(msi, "--install-in-wine")
        foreign.forget_installed()
        self.assertEqual(code, 0, text)
        self.assertIn("is to be installed under Wine, so that its own steps run", text)
        self.assertIn("ran its installer silently under Wine (/qn /norestart)", text)
        opt = next((out / "app/opt").iterdir())
        (exe,) = opt.rglob("dbtw.exe")
        self.assertTrue((exe.parent / "version.xml").is_file())
        # an Inno setup too
        payload = self.tmp / "inno"
        write(payload / "app/Acme.exe", exe_bytes("Acme"))
        idrive = self.tmp / "idrive"
        write(idrive / "Program Files/Acme/Acme.exe", exe_bytes("Acme"))
        write(idrive / "Program Files/Acme/made-by-setup.ini", b"[x]")
        setup = write(self.tmp / "acme-setup.exe", exe_bytes("Acme Setup", extra=b"Inno Setup Setup Data (6.2.0)"
                                                             + STUBTAR + tar_bytes(idrive)))
        with mock.patch.dict(os.environ, {"STUB_WINE": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /CURRENTUSER "
                                                       "/LOG=C:\\debpak-setup.log"}):
            code, text, out = self.convert(setup, "--install-in-wine")
        foreign.forget_installed()
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as wine-install", text)
        self.assertTrue((next((out / "app/opt").iterdir()) / "made-by-setup.ini").is_file())

    def test_msi_read_to_no_program_is_installed_by_msiexec(self):
        # SMART Notebook's zip holds SMARTEducationSoftware.msi, which msiextract read to no program at
        # all; msiexec under Wine installs it, with /qn
        from debpak import foreign, wineinstall
        drive = self.tmp / "drive"
        write(drive / "Program Files/SMART Technologies/Education Software/Notebook.exe",
              exe_bytes("SMART Notebook") + bytes(9000))
        msi_data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(drive)
        z = self.tmp / "smart25-0admin.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("SMARTEducationSoftware.msi", msi_data)
            zf.writestr("Support/readme.txt", "admin install")

        def nothing(msi, out):
            out.mkdir(parents=True, exist_ok=True)
            write(out / "readme.txt", "the files lie elsewhere")
        foreign.forget_installed()
        with mock.patch.dict(os.environ, {"STUB_WINE": "/qn /norestart"}), \
                mock.patch.object(foreign, "_msiextract", nothing):
            code, text, _ = self.convert(z)
        foreign.forget_installed()
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Education Software/Notebook.exe", text)
        self.assertIn("ran its installer silently under Wine (/qn /norestart)", text)
        runs = [c for c in self.stubs.calls() if c.startswith("flatpak run ")]
        self.assertTrue(runs and runs[0].split()[-3].endswith("SMARTEducationSoftware.msi"), runs)
        self.assertIn('*.msi) wine msiexec /i "${@:4}"', wineinstall.SCRIPT)
        # one msiextract can't read at all goes the same way
        msi = write(self.tmp / "Acme.msi", msi_data)

        def broken(msi, out):
            raise PackageError("msiextract failed: unsupported compression")
        with mock.patch.dict(os.environ, {"STUB_WINE": "/qn /norestart"}), \
                mock.patch.object(foreign, "_msiextract", broken):
            code, text, _ = self.convert(msi)
        foreign.forget_installed()
        self.assertEqual(code, 0, text)
        self.assertIn("msiextract failed: unsupported compression; running it silently under Wine instead", text)
        self.assertEqual(wineinstall.kind_of(msi, None), "msi")

    def test_installshield_suite_setup_with_its_msi_inside(self):
        # SketchUp 2023's SketchUpStudio.exe, an InstallShield Suite setup: under Wine it stopped while
        # staging its parts ("Invalid handle"), silent or clicked through, so its .msi is read from
        # the stream after the program
        from debpak import unpack

        def encode(name: str, data: bytes) -> bytes:
            key = unpack._issetup_key(name)
            unit = (key * (1024 // len(key) + 1))[:1024]
            out = bytearray()
            for i in range(0, len(data), 1024):
                piece = bytes(b ^ unit[j] for j, b in enumerate(data[i:i + 1024]))
                out += piece.translate(unpack._NIBBLE_SWAP)
            return bytes(out)

        def suite(files: dict[str, bytes]) -> bytes:
            body = b"ISSetupStream\0" + struct.pack("<HI", len(files), 4) + bytes(26)
            for name, data in files.items():
                packed = encode(name, zlib.compress(data))
                wname = name.encode("utf-16-le")
                body += struct.pack("<IIHI", len(wname), 6, 0, len(packed)) + bytes(34) + wname + packed
            return exe_bytes("SketchUp 2023", description="SketchUp Installer") + body + b"InstallShield"

        tree = self.tmp / "sketchup-msi"
        write(tree / "Program Files 64/SketchUp/SketchUp 2023/SketchUp.exe", exe_bytes("SketchUp Application"))
        write(tree / "Program Files 64/SketchUp/SketchUp 2023/LayOut/LayOut.exe", exe_bytes("LayOut"))
        msi = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(tree) + os.urandom(3000)
        setup = write(self.tmp / "SketchUpStudio-2023-1-340-117.exe", suite({
            "{F8189C0F-1462-4521-9287-D0AB7EF9EFFC}\\Windows6.1-KB2999226-x64.msu": b"MSCF" + bytes(5000),
            "{8CE8A0DB-60F2-4764-B072-6AEFB244781D}\\ndp472-kb4054531-web.exe": exe_bytes(".NET Setup"),
            "{03CB7BC4-3C9C-452B-BFD7-1C3616BE96BD}\\SketchUp 2023.msi": msi,
            "{03CB7BC4-3C9C-452B-BFD7-1C3616BE96BD}\\1033.mst": b"\xd0\xcf\x11\xe0",
            "Setup.xml": b"<Setup/>"}))
        work = self.tmp / "is-work"
        names = unpack.issetup_stream(setup, work)
        self.assertEqual(len(names), 5)
        self.assertEqual((work / "{03CB7BC4-3C9C-452B-BFD7-1C3616BE96BD}/SketchUp 2023.msi").read_bytes(), msi)
        self.assertEqual((work / "Setup.xml").read_bytes(), b"<Setup/>")
        self.assertIsNone(unpack.issetup_stream(write(self.tmp / "plain.exe", exe_bytes("Plain"))))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Program Files 64/SketchUp/SketchUp 2023/SketchUp.exe", text)
        self.assertFalse(any(c.startswith("flatpak run ") for c in self.stubs.calls()))
        # a cut-short stream isn't read, and the setup runs under Wine as before
        data = setup.read_bytes()
        cut = write(self.tmp / "cut-setup.exe", data[:len(data) - 2500] + b"InstallShield")
        code, text, _ = self.convert(cut)
        self.assertEqual(code, 1, text)
        self.assertIn("looks like an installer debpak can't unpack", text)

    def test_what_an_installer_installed(self):
        from debpak.wineinstall import _program_root, installed
        self.assertEqual(_program_root(("laragon", "laragon.exe")), ("laragon",))          # C:\laragon
        self.assertEqual(_program_root(("Program Files", "Acme", "acme.exe")), ("Program Files", "Acme"))
        self.assertIsNone(_program_root(("windows", "system32", "x.dll")))
        self.assertIsNone(_program_root(("users", "me", "Desktop", "x.exe")))
        self.assertIsNone(_program_root(("setup.log",)))
        drive = self.tmp / "prefix/drive_c"
        write(drive / "laragon/laragon.exe", exe_bytes("Laragon"))
        write(drive / "laragon/bin/php/php.exe", exe_bytes("PHP") + bytes(9000))
        write(drive / "Program Files/Common Files/x.exe", exe_bytes("X") + bytes(99000))
        self.assertEqual(installed(self.tmp / "prefix", set()), (drive / "laragon", None))
        # v2rayA: its only Start menu shortcut is the uninstaller's, which is no program
        v2 = self.tmp / "v2/drive_c"
        write(v2 / "Program Files/v2rayA/bin/v2raya.exe", exe_bytes("v2rayA"))
        write(v2 / "Program Files/v2rayA/unins000.exe", exe_bytes("Setup/Uninstall"))
        write(v2 / "ProgramData/Microsoft/Windows/Start Menu/Programs/v2rayA/Uninstall v2rayA.lnk",
              b"L\0\0\0" + "C:\\Program Files\\v2rayA\\unins000.exe".encode("utf-16-le") + b"\0\0")
        self.assertEqual(installed(self.tmp / "v2", set()), (v2 / "Program Files/v2rayA", None))

    def test_why_an_inno_setup_stopped(self):
        from debpak.wineinstall import _setup_log
        prefix = self.tmp / "log"
        self.assertEqual(_setup_log(prefix), "")
        stamp = "2026-11-27 05:13:40.100   "
        head = [stamp + s for s in ("Setup version: Inno Setup version 6.7.0", "Original Setup EXE: Z:\\in\\Setup.exe",
                                    "Setup command line: /VERYSILENT", "Windows version: 10.0.19045")]
        log = write(prefix / "drive_c/debpak-setup.log",
                    "\n".join(head + [stamp + "Exception message:", stamp + "Message box (OK): PrepareToInstall failed: "
                                      "x", stamp + "Deinitializing Setup.", stamp + "Log closed."]))
        self.assertEqual(_setup_log(prefix), "Message box (OK): PrepareToInstall failed: x")
        # none of the words that say it failed (Lamina's setup, exit status 5): the last thing it did
        log.write_text("\n".join(head + [stamp + "Starting the installation process.",
                                         stamp + "Creating directory: C:\\users\\u\\AppData\\Local\\Lamina",
                                         stamp + "Deinitializing Setup.", stamp + "Log closed."]))
        self.assertEqual(_setup_log(prefix), 'its log ends with "Creating directory: C:\\users\\u\\AppData\\Local\\Lamina"')
        log.write_text("\n".join(head + [stamp + "Log closed."]))
        self.assertEqual(_setup_log(prefix), "")

    def test_installer_that_installs_an_app_package(self):
        # Hardware Monitor's Inno setup (6.7.0, newer than innoextract) installs only
        # HardwareMonitorExtension.msix and a certificate, then registers the package with PowerShell
        from debpak.wineinstall import installed
        drive = self.tmp / "hm/drive_c"
        write(drive / "Program Files/HardwareMonitorExtension/HardwareMonitorExtension.msix", b"PK" + bytes(900))
        write(drive / "Program Files/HardwareMonitorExtension/HardwareMonitor.cer", b"cert")
        self.assertEqual(installed(self.tmp / "hm", set()), (drive / "Program Files/HardwareMonitorExtension",
                                                             "HardwareMonitorExtension.msix"))
        # a program beside it is what counts
        write(drive / "Program Files/HardwareMonitorExtension/Monitor.exe", exe_bytes("Monitor"))
        self.assertEqual(installed(self.tmp / "hm", set()), (drive / "Program Files/HardwareMonitorExtension", None))

        def package(name, application):
            d = self.tmp / name
            write(d / "AppxManifest.xml", f"""
                <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
                  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
                  xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
                  xmlns:com="http://schemas.microsoft.com/appx/manifest/com/windows10">
                  <Identity Name="{name}" Version="0.1.7.0" ProcessorArchitecture="x64"/>
                  <Properties><DisplayName>{name}</DisplayName></Properties>
                  <Applications>{application}</Applications>
                </Package>""")
            write(d / f"{name}.exe", exe_bytes(name))
            return zip_tree(d, self.tmp / f"{name}.msix")
        ext = ('<uap3:Extension Category="windows.appExtension"><uap3:AppExtension '
               'Name="com.microsoft.commandpalette" Id="ID" PublicFolder="Public" DisplayName="x"/></uap3:Extension>')
        com = ('<com:Extension Category="windows.comServer"><com:ComServer><com:ExeServer Executable="{0}.exe" '
               'Arguments="-RegisterProcessAsComServer" DisplayName="x"/></com:ComServer></com:Extension>')
        msix = package("HardwareMonitorExtension", '<Application Id="App" Executable="HardwareMonitorExtension.exe">'
                       '<uap:VisualElements DisplayName="x" AppListEntry="none"/><Extensions>' + ext
                       + com.format("HardwareMonitorExtension") + '</Extensions></Application>')
        prog = self.tmp / "inst/Program Files/HardwareMonitorExtension"
        write(prog / "HardwareMonitorExtension.msix", msix.read_bytes())
        write(prog / "HardwareMonitor.cer", b"cert")
        setup = write(self.tmp / "HardwareMonitorExtension-Setup-0.1.7.0-x64.exe",
                      exe_bytes("Hardware Monitor (PawnIO)", extra=b"Inno Setup Setup Data (6.7.0)\0" + STUBTAR
                                + tar_bytes(self.tmp / "inst")))
        flags = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /CURRENTUSER /LOG=C:\\debpak-setup.log"
        with mock.patch.dict(os.environ, {"STUB_WINE": flags}):
            code, text, _ = self.convert(setup)
        self.assertEqual(code, 1, text)
        self.assertIn("installs no program, only an extension that another program loads (an app package that "
                      "plugs into com.microsoft.commandpalette", text)
        # the COM server alone tells too, and so does a package given as it is
        quiet = package("Quiet", '<Application Id="App" Executable="Quiet.exe"><uap:VisualElements DisplayName="x"/>'
                        '<Extensions>' + ext + com.format("Quiet") + '</Extensions></Application>')
        code, text, _ = self.convert(quiet)
        self.assertEqual(code, 1, text)
        self.assertIn("plugs into com.microsoft.commandpalette", text)
        # an app with a Start menu entry of its own that also offers an extension is an app
        both = package("Both", '<Application Id="App" Executable="Both.exe"><uap:VisualElements DisplayName="x"/>'
                       '<Extensions>' + ext + '</Extensions></Application>')
        code, text, _ = self.convert(both)
        self.assertEqual(code, 0, text)
        # and an app package installed for a program is unpacked and converted
        prog2 = self.tmp / "inst2/Program Files/Both"
        write(prog2 / "Both.msix", both.read_bytes())
        setup2 = write(self.tmp / "Both-Setup.exe", exe_bytes("Both Setup", extra=b"Inno Setup Setup Data (6.7.0)\0"
                                                             + STUBTAR + tar_bytes(self.tmp / "inst2")))
        with mock.patch.dict(os.environ, {"STUB_WINE": flags}):
            code, text, _ = self.convert(setup2)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Both.exe", text)
        # an .msixbundle holds a package for each architecture, and the x64 one is taken
        bundle = self.tmp / "bundle"
        write(bundle / "AppxMetadata/AppxBundleManifest.xml", """
            <Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Packages>
              <Package Type="application" Architecture="arm64" FileName="Both_arm64.msix"/>
              <Package Type="application" Architecture="x64" FileName="Both_x64.msix"/>
              <Package Type="resource" FileName="Both_scale-200.msix"/>
            </Packages></Bundle>""")
        write(bundle / "Both_x64.msix", both.read_bytes())
        write(bundle / "Both_arm64.msix", b"PK not this one")
        code, text, _ = self.convert(zip_tree(bundle, self.tmp / "Both_1.0_x64_arm64.msixbundle"))
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Both.exe", text)

    def test_installed_program_is_named_by_its_installer(self):
        # v2rayA: its programs carry no version resource, and its setup's does (ProductName v2rayA, 2.5.16)
        def bare(subsystem, size):
            return build_pe(PeSpec(is_dll=False, imports={"kernel32.dll": ["ExitProcess"]}, resources=[],
                                   subsystem=subsystem)) + bytes(size)
        drive = self.tmp / "drive"
        write(drive / "Program Files/v2rayA/bin/v2raya.exe", bare(3, 1000))
        write(drive / "Program Files/v2rayA/bin/v2raya_core.exe", bare(3, 9000))
        write(drive / "Program Files/v2rayA/unins000.exe", exe_bytes("v2rayA", description="Setup/Uninstall"))
        setup = write(self.tmp / "installer_windows_inno_x64_2.5.16.exe",
                      exe_bytes("v2rayA", "2.5.16", description="v2rayA Setup", extra=STUBTAR + tar_bytes(drive)))
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S"}):
            code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("v2rayA 2.5.16 (Windows program, runs under Wine)", text)
        self.assertIn("main executable bin/v2raya.exe", text)
        # a setup that calls itself only that names nothing
        from debpak.foreign import GENERIC_PRODUCT
        self.assertTrue(GENERIC_PRODUCT.fullmatch("Setup"))
        self.assertTrue(GENERIC_PRODUCT.fullmatch("Installer"))
        self.assertFalse(GENERIC_PRODUCT.fullmatch("v2rayA"))

    def test_install4j_installer_without_its_java_runs_under_wine(self):
        # OpenRocket's install4j installer opens as a zip of its launcher and jar, without the Java
        # runtime it installs beside them, and the launcher stopped at "No JVM could be found"
        drive = self.tmp / "drive"
        write(drive / "Program Files/OpenRocket/OpenRocket.exe", exe_bytes("OpenRocket"))
        write(drive / "Program Files/OpenRocket/OpenRocket.jar", b"PK\5\6" + bytes(18))
        write(drive / "Program Files/OpenRocket/jre/bin/server/jvm.dll", build_pe(PeSpec(is_dll=True)))
        def installer(with_java: bool) -> bytes:
            zbuf = io.BytesIO()
            with zipfile.ZipFile(zbuf, "w") as zf:
                zf.writestr(".install4j/i4jinst.dll", build_pe(PeSpec(is_dll=True)))
                zf.writestr("OpenRocket.exe", exe_bytes("OpenRocket"))
                zf.writestr("OpenRocket.jar", b"jar")
                if with_java:
                    zf.writestr("jre/bin/server/jvm.dll", build_pe(PeSpec(is_dll=True)))
            return exe_bytes("OpenRocket Setup", extra=b"install4j" + STUBTAR + tar_bytes(drive)) + zbuf.getvalue()
        setup = write(self.tmp / "OpenRocket-23.09-Windows.exe", installer(False))
        with mock.patch.dict(os.environ, {"STUB_WINE": "-q"}):
            code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("is an install4j installer whose Java runtime isn't in the part debpak can read", text)
        self.assertIn("unpacked as wine-install", text)
        opt = next((out / "app/opt").iterdir())
        self.assertTrue((opt / "jre/bin/server/jvm.dll").is_file())
        # one whose zip has the runtime is read as before
        setup.write_bytes(installer(True))
        with mock.patch.dict(os.environ, {"STUB_WINE": "-q"}):
            code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as zip", text)

    def test_installer_nothing_reads_runs_under_wine(self):
        # a WiX bundle (Foxit PDF Reader, PowerToys): the shortcut it makes names the program
        drive = self.tmp / "drive"
        write(drive / "Program Files/Acme/Acme.exe", exe_bytes("Acme"))
        write(drive / "Program Files/Acme/AcmeUpdate.exe", exe_bytes("Acme") + bytes(90000))
        write(drive / "Program Files/Acme/unins000.exe", exe_bytes("Uninstall"))
        write(drive / "ProgramData/Package Cache/{1234}/AcmeSetup.exe", exe_bytes("Acme Setup") + bytes(200000))
        write(drive / "ProgramData/Microsoft/Windows/Start Menu/Programs/Acme.lnk",
              b"L\0\0\0" + "C:\\Program Files\\Acme\\Acme.exe".encode("utf-16-le") + b"\0\0")
        setup = write(self.tmp / "AcmeSetup.exe", burn_bundle([b"no manifest"]) + STUBTAR + tar_bytes(drive))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 1, text)
        self.assertIn("is a WiX bundle with no .msi inside, and running it under Wine didn't work either: "
                      "running it needs org.winehq.Wine", text)
        self.assertIn("Install it in Wine instead", text)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/quiet /norestart"}):
            code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Acme.exe", text)
        self.assertIn("unpacked as wine-install", text)
        self.assertIn("ran its installer silently under Wine (/quiet /norestart)", text)
        opt = next((out / "app/opt").iterdir())
        self.assertTrue((opt / "AcmeUpdate.exe").is_file())
        self.assertFalse((opt / "Package Cache").exists())
        # an installer of no known kind gets the usual silent switches in turn
        other = write(self.tmp / "OtherSetup.exe", exe_bytes("Other Setup", extra=STUBTAR + tar_bytes(drive)))
        self.stubs.log.unlink(missing_ok=True)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/silent"}):
            code, text, _ = self.convert(other)
        self.assertEqual(code, 0, text)
        runs = [c.rsplit("OtherSetup.exe", 1)[1].strip() for c in self.stubs.calls() if c.startswith("flatpak run ")]
        self.assertEqual(runs, ["/S", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "/quiet /norestart", "/silent"])
        # one that takes none of the silent switches is clicked through
        with mock.patch.dict(os.environ, {"STUB_WINE": "(clicked)"}):
            code, text, _ = self.convert(other)
        self.assertEqual(code, 0, text)
        self.assertIn("clicked through its installer under Wine", text)
        # Xenu's Link Sleuth: a zip that holds only its installer
        z = self.tmp / "XENU.ZIP"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Setup.exe", other.read_bytes())
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S"}):
            code, text, _ = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Acme.exe", text)
        # an Inno Setup installer whose files all go outside {app} (Advanced IP Scanner)
        elsewhere = self.tmp / "inno-pf"
        write(elsewhere / "commonpf/Acme/Acme.exe", exe_bytes("Acme"))
        inno = write(self.tmp / "acme_2.5.exe", exe_bytes("Acme Setup", extra=b"Inno Setup Setup Data (6.2.0)"
                                                             + STUBTAR + tar_bytes(elsewhere)))
        with mock.patch.dict(os.environ, {"STUB_WINE": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /CURRENTUSER /LOG=C:\\debpak-setup.log"}):
            code, text, _ = self.convert(inno)
        self.assertIn("innoextract found no program files ({app} folder); running it silently under Wine", text)
        # a small one that installs nothing offline downloads the program: it runs again with the network
        self.stubs.log.unlink(missing_ok=True)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S", "STUB_WINE_NET": "1"}):
            code, text, _ = self.convert(other)
        self.assertEqual(code, 0, text)
        runs = [c for c in self.stubs.calls() if c.startswith("flatpak run ")]
        self.assertEqual(len(runs), 5)
        self.assertTrue(all("--unshare=network" in c for c in runs[:4]))
        self.assertIn("--share=network", runs[4])
        self.assertIn("before.txt 600 60 ", runs[4])        # a download takes longer than a guess
        self.assertIn("sandboxed with the network, as it downloads the program itself", text)

    def test_silent_switches_an_installer_names(self):
        # Amazon Games' setup keeps "/silent" among its own (UTF-16) strings, Internet Download
        # Manager's "-skipdlgs": tried before the usual guesses
        drive = self.tmp / "drive"
        write(drive / "Program Files/Acme/Acme.exe", exe_bytes("Acme"))
        named = write(self.tmp / "AcmeGamesSetup.exe", exe_bytes("Acme Setup", extra=b"\0\0" + "/silent".encode(
            "utf-16-le") + b"\0\0/advanced\0x -quiet x\0" + STUBTAR + tar_bytes(drive)))
        with mock.patch.dict(os.environ, {"STUB_WINE": "/silent"}):
            code, text, _ = self.convert(named)
        self.assertEqual(code, 0, text)
        runs = [c for c in self.stubs.calls() if c.startswith("flatpak run ")]
        self.assertEqual(len(runs), 1)          # "-quiet" inside a longer string isn't one
        self.assertIn("ran its installer silently under Wine (/silent)", text)
        # Bitvise's prints its usage for a switch it doesn't know: the silent switch it names comes next
        other = write(self.tmp / "OtherSetup.exe", exe_bytes("Other Setup", extra=STUBTAR + tar_bytes(drive)))
        self.stubs.log.unlink(missing_ok=True)
        with mock.patch.dict(os.environ, {"STUB_WINE": "-unattended",
                                          "STUB_WINE_USAGE": "usage: OtherSetup [-unattended] [-dir=PATH]"}):
            code, text, _ = self.convert(other)
        self.assertEqual(code, 0, text)
        runs = [c.rsplit("OtherSetup.exe", 1)[1].strip() for c in self.stubs.calls() if c.startswith("flatpak run ")]
        self.assertEqual(runs, ["/S", "-unattended"])
        from debpak import wineinstall
        self.assertEqual(wineinstall.named_switches(b"[-silent] [/auto] x-silent /silently --quiet"),
                         [["-silent"], ["/auto"], ["--quiet"]])
        self.assertEqual(wineinstall.named_switches(b"Usage: BvSshClient-Inst -acceptEULA [-target=x86|x64|*]"),
                         [["-acceptEULA"]])

    def test_installer_switches_that_need_more_than_a_word(self):
        # Bitvise's usage wants a folder to install to along with -acceptEULA: alone, it was a usage error
        from debpak import wineinstall
        usage = (b" BvSshClient-Inst -installDir=directory\n    [-force OR -continueOnError[=error-code-list]]\n"
                 b"    [-acceptEULA] [-interactive] [-noRollback] [-exitZero]")
        self.assertEqual(wineinstall.named_switches(usage, folder="BvSshClient"),
                         [["-acceptEULA", "-installDir=C:\\Program Files\\BvSshClient"]])
        self.assertEqual(wineinstall.named_switches(usage), [["-acceptEULA"]])
        self.assertEqual(wineinstall.folder_name(Path("BvSshClient-Inst.exe")), "BvSshClient")
        self.assertEqual(wineinstall.folder_name(Path("osu!install.exe")), "osu_")
        drive = self.tmp / "drive"
        write(drive / "Program Files/BvSshClient/BvSsh.exe", exe_bytes("Bitvise SSH Client"))
        setup = write(self.tmp / "BvSshClient-Inst.exe", exe_bytes("Bitvise Setup", extra=STUBTAR + tar_bytes(drive)))
        with mock.patch.dict(os.environ, {"STUB_WINE": "-acceptEULA -installDir=C:\\Program Files\\BvSshClient",
                                          "STUB_WINE_USAGE": usage.decode()}):
            code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable BvSsh.exe", text)

    def test_installer_run_afresh_each_attempt(self):
        # osu!'s installer moves itself into the folder it installs to: the next attempt found nothing
        # to run ("wine: failed to open", exit status 53)
        drive = self.tmp / "drive"
        write(drive / "users/me/AppData/Local/osu!/osu!.exe", exe_bytes("osu!"))
        setup = write(self.tmp / "osu!install.exe", exe_bytes("osu!", extra=STUBTAR + tar_bytes(drive)))
        with mock.patch.dict(os.environ, {"STUB_WINE": "/silent", "STUB_WINE_MOVES": "1"}):
            code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("ran its installer silently under Wine (/silent)", text)
        # Battle.net's: Flatpak failed to set up the sandbox, a race with other Flatpak apps starting
        # and stopping ("bwrap: Can't get type of source /run/user/1000/.flatpak/..."); it's started again
        race = write(self.tmp / "race", "")
        self.stubs.log.unlink(missing_ok=True)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S", "STUB_WINE_RACE": str(race)}), \
                mock.patch("time.sleep"):
            code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertEqual(len([c for c in self.stubs.calls() if c.startswith("flatpak run ")]), 3)
        # one that fails to start for a reason of its own isn't
        from debpak import wineinstall
        self.assertIsNone(wineinstall.FLATPAK_RACE.search("error: Could not connect: Connection refused"))

    def test_setup_that_carries_a_bundle_is_not_one(self):
        # Rockstar Games Launcher's setup has the Visual C++ runtimes' WiX bundles among its resources,
        # so ".wixburn" is in it, but no .wixburn section of its own: it was given only /quiet /norestart
        drive = self.tmp / "drive"
        write(drive / "Program Files/Rockstar Games/Launcher/Launcher.exe", exe_bytes("Rockstar Games Launcher"))
        setup = write(self.tmp / "Rockstar-Games-Launcher.exe",
                      exe_bytes("Rockstar Games Launcher", extra=burn_bundle([b"vc_redist"]) + b"\0\0"
                                + "/silent".encode("utf-16-le") + b"\0\0" + STUBTAR + tar_bytes(drive)))
        from debpak import unpack
        self.assertFalse(unpack.is_burn_bundle(setup))
        self.assertTrue(unpack.is_burn_bundle(write(self.tmp / "b.exe", burn_bundle([b"x"]))))
        with mock.patch.dict(os.environ, {"STUB_WINE": "/silent"}):
            code, text, _ = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("looks like an installer debpak can't unpack; running it silently under Wine", text)
        self.assertIn("ran its installer silently under Wine (/silent)", text)

    def test_bundle_that_downloads_its_msi(self):
        # EA app's bundle names its .msi with the URL, size and hash Burn would fetch and check it with
        import hashlib
        from debpak import foreign
        prog = self.tmp / "msi"
        write(prog / "Electronic Arts/EA Desktop/EADesktop.exe", exe_bytes("EA app"))
        write(prog / "Electronic Arts/EA Desktop/EABackgroundService.exe", exe_bytes("EA Background Service"))
        msi = b"MSI" + STUBTAR + tar_bytes(prog)
        sha1 = hashlib.sha1(msi).hexdigest().upper()

        def bundle(digest: str, url: str = "https://example.com/EAapp-13.msi") -> Path:
            ux = self.tmp / "ux"
            write(ux / "0", '<BurnManifest xmlns="http://schemas.microsoft.com/wix/2008/Burn">'
                  '<UX><Payload Id="u0" FilePath="ba.dll" SourcePath="u0" Container="WixUXContainer"/></UX>'
                  f'<Payload Id="m" FilePath="EAapp-13.msi" FileSize="{len(msi)}" Hash="{digest}" '
                  f'DownloadUrl="{url}" Packaging="external" SourcePath="EAapp-13.msi"/></BurnManifest>')
            return write(self.tmp / "EAappInstaller.exe", burn_bundle([STUBTAR + tar_bytes(ux)]))

        fetched = []

        def download(url, dest, timeout=120, tries=3):
            fetched.append(url)
            write(dest, msi)
            return dest
        services = [{"name": "EABackgroundService", "exe": "EABackgroundService.exe"}]
        with mock.patch("debpak.net.download", download), \
                mock.patch.object(foreign, "msi_services", return_value=services):
            code, text, _ = self.convert(bundle(sha1))
            self.assertEqual(fetched, ["https://example.com/EAapp-13.msi"])
            self.assertIn("downloads its packages: fetching EAapp-13.msi", text)
            # it relies on a service of its own, which a Flatpak can't run
            self.assertIn("relies on EABackgroundService, a Windows system service its installer sets up", text)
            self.assertNotEqual(code, 0, text)
            (msiextract,) = [c for c in self.stubs.calls() if c.startswith("msiextract")]
            self.assertTrue(msiextract.endswith("/payloads/EAapp-13.msi"), msiextract)
            # one whose download isn't the file the bundle names is left to its installer
            code, text, _ = self.convert(bundle("0" * 40))
            self.assertIn("came down unlike the one the bundle names", text)
            self.assertIn("is a WiX bundle with no .msi inside", text)
            # and only https URLs are fetched
            fetched.clear()
            self.convert(bundle(sha1, "http://example.com/EAapp-13.msi"))
            self.assertEqual(fetched, [])

    def test_install_media_in_an_archive(self):
        from debpak import foreign
        ole = bytes.fromhex("d0cf11e0a1b11ae1")

        def msi(files: dict) -> bytes:
            d = self.tmp / f"msi-{len(files)}-{sorted(files)[0].replace('/', '_')}"
            for rel, data in files.items():
                write(d / rel, data)
            return ole + STUBTAR + tar_bytes(d)
        redist = exe_bytes("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34438")
        # Quark Update's zip: setup.exe starts Quark Update.msi, whose files are in Data1.cab beside it,
        # with SelfUpdater.exe and the Visual C++ runtime's installer; "no program found" was all it got
        z = self.tmp / "QuarkUpdate272_50034B_Win.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("setup.exe", exe_bytes("Quark Update", description="Contact:  Your local administrator"))
            zf.writestr("SelfUpdater.exe", exe_bytes("", icon=False))
            zf.writestr("vcredist_x64.exe", redist)
            zf.writestr("Data1.cab", b"MSCF")
            zf.writestr("Quark Update.msi", msi({"Program Files 64/Quark/Quark Update/AutoUpdate.exe":
                                                 exe_bytes("Quark Update")}))
        code, text, _ = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("unpacked as msi", text)
        self.assertIn("main executable Program Files 64/Quark/Quark Update/AutoUpdate.exe", text)
        # SMART Notebook's: its .msi at the top, and in Support the .NET Framework's installer (a 7-Zip
        # self-extractor, which was opened instead) and the Visual C++ runtime's
        z = self.tmp / "smart25-0admin.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("SMARTEducationSoftware.msi", msi({"Program Files/SMART Technologies/Education Software/"
                                                           "Notebook.exe": exe_bytes("SMART Notebook")}))
            zf.writestr("Support/ndp481-x86-x64-allos-enu.exe", exe_bytes("Microsoft .NET Framework 4.8.1 Setup"))
            zf.writestr("Support/vc_redist.x64.exe", redist)
            zf.writestr("Support/SMART Install Manager.exe", exe_bytes("SMART Install Manager"))
            zf.writestr("Support/Galleries/SMARTGalleryEssentials.msi", ole + bytes(5000))
        code, text, _ = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Program Files/SMART Technologies/Education Software/Notebook.exe", text)
        # Apple's AirPortSetup.exe: SetupAdmin.exe and the .msi files it installs, the product's by its name
        media = self.tmp / "airport"
        write(media / "SetupAdmin.exe", exe_bytes("Apple Installer (Elevated)", arch="i386"))
        write(media / "AirPort.msi", ole + bytes(100))
        write(media / "Bonjour.msi", ole + bytes(1000))
        write(media / "AppleSoftwareUpdate.msi", ole + bytes(500))
        self.assertEqual(foreign._only_installer(media, "AirPortSetup"), media / "AirPort.msi")
        self.assertEqual(foreign._only_installer(media), media / "Bonjour.msi")         # else the largest
        # a program beside an .msi, with no setup.exe to start it, makes the archive the program's
        write(media / "Tool.exe", exe_bytes("Tool"))
        self.assertIsNone(foreign._only_installer(media, "AirPortSetup"))
        # an installer beside a runtime's is still the one to open
        kit = self.tmp / "kit"
        write(kit / "Acme-2.0-setup.exe", exe_bytes("Acme Setup"))
        write(kit / "vc_redist.x64.exe", redist)
        self.assertEqual(foreign._only_installer(kit), kit / "Acme-2.0-setup.exe")

    def test_an_installer_in_an_archive_that_unpacks_to_no_program_is_run(self):
        # an installer in a zip that debpak opened and found no program in is run under Wine, as one
        # downloaded on its own is (Winaero Tweaker's zip holds WinaeroTweaker-1.65.0.0-setup.exe)
        drive = self.tmp / "drive"
        write(drive / "Program Files/Acme/Acme.exe", exe_bytes("Acme"))
        # a self-extracting zip of the installer's own resources, as debpak sees it
        res = io.BytesIO()
        with zipfile.ZipFile(res, "w") as zf:
            zf.writestr("readme.txt", "hi")
        setup = exe_bytes("Acme Setup", extra=STUBTAR + tar_bytes(drive) + bytes(1024) + res.getvalue())
        z = self.tmp / "acme.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Acme-1.0-setup.exe", setup)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S"}):
            code, text, _ = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("no program (.exe) found in acme.zip; running it silently under Wine", text)
        self.assertIn("unpacked as wine-install); main executable Acme.exe", text)

    def test_the_program_an_msi_puts_in_the_start_menu(self):
        # AirPort.msi's one shortcut starts APUtil.exe; APDiskPrefs.exe beside it was taken instead
        from debpak import foreign
        tables = {
            "Shortcut": "Shortcut\tDirectory_\tName\tComponent_\tTarget\n\n\n"
                        "APUtil\tProgramMenuFolder\t9fjewr8a.sho|AirPort Utility\tAPUtil.exe\tAirPort\n"
                        "Help\tProgramMenuFolder\tHelp\tHelpC\t[#helpchm]\n"
                        "Un\tProgramMenuFolder\tUninstall\tUnC\t[#unins]\n"
                        "Tool\tDesktopFolder\tTool\tToolC\t[INSTALLDIR]tool.exe\n",
            "Component": "Component\n\n\nAPUtil.exe\t{1}\tINSTALLDIR\t0\t\tAPUtil.exe\nHelpC\t{2}\tD\t0\t\thelpchm\n",
            "File": "File\n\n\nAPUtil.exe\tAPUtil.exe\tAPUtil.exe\nhelpchm\tHelpC\thelp.chm\n"
                    "unins\tUnC\tUNINST~1.EXE|uninstall.exe\n",
        }
        for name, text in tables.items():
            write(self.tmp / "tables" / name, text)
        write(self.stubs.bin / "msiinfo", f"#!/bin/sh\ncat \"{self.tmp}/tables/$3\" 2>/dev/null\n", 0o755)
        self.assertEqual(foreign.msi_shortcut_programs(self.tmp / "x.msi"), ["APUtil.exe", "tool.exe"])
        del tables["Shortcut"]
        (self.tmp / "tables/Shortcut").write_text(
            "Shortcut\tDirectory_\tName\tComponent_\tTarget\n\n\nA\tProgramMenuFolder\tA\tAPUtil.exe\tAirPort\n")
        prog = self.tmp / "ap"
        write(prog / "Program Files/AirPort/APUtil.exe", exe_bytes("AirPort Utility", extra=bytes(10)))
        write(prog / "Program Files/AirPort/APDiskPrefs.exe", exe_bytes("AirPort Disk", extra=bytes(5000)))
        # a target folder of "." is the one above it: Quark Update.msi's ".:System64"
        write(prog / ".:System64/AutoUpdatePlugin.cpl", b"cpl")
        m = write(self.tmp / "AirPort.msi", bytes.fromhex("d0cf11e0a1b11ae1") + STUBTAR + tar_bytes(prog))
        code, text, _ = self.convert(m)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Program Files/AirPort/APUtil.exe", text)
        out = self.tmp / "msi-out"
        foreign._msiextract(m, out)
        self.assertTrue((out / "AutoUpdatePlugin.cpl").is_file())
        self.assertFalse(any(":" in p.name for p in out.rglob("*")))

    def test_services_an_msi_installs(self):
        # read from its ServiceInstall table with msiinfo; an updater's service doesn't count
        from debpak import foreign
        tables = {
            "ServiceInstall": "ServiceInstall\tName\tDisplayName\tServiceType\tStartType\tErrorControl\t"
                              "LoadOrderGroup\tDependencies\tStartName\tPassword\tArguments\tComponent_\n"
                              "s72\n" "ServiceInstall\tServiceInstall\n"
                              "svc\tEABackgroundService\tEABackgroundService\t272\t3\t1\t\t\t\t\t-start\tSvc\n"
                              "upd\tpexUpdateService\tPhraseExpress Update Service\t16\t2\t1\t\t\t\t\t\tUpd\n",
            "Component": "Component\n\n\nSvc\t{1}\tDIR\t0\t\tsvcfile\nUpd\t{2}\tDIR\t0\t\tupdfile\n",
            "File": "File\n\n\nsvcfile\tSvc\tEABACK~1.EXE|EABackgroundService.exe\nupdfile\tUpd\tpexUpd.exe\n",
        }
        for name, text in tables.items():
            write(self.tmp / "tables" / name, text)
        write(self.stubs.bin / "msiinfo", f"#!/bin/sh\ncat \"{self.tmp}/tables/$3\" 2>/dev/null\n", 0o755)
        self.assertEqual(foreign.msi_services(self.tmp / "x.msi"),
                         [{"name": "EABackgroundService", "exe": "EABackgroundService.exe"}])

    def test_files_an_msi_duplicates_are_copied(self):
        # SketchUp 2023's .msi keeps Qt5Core.dll in LayOut's folder and copies it into SketchUp's
        # with its DuplicateFile table, which msiextract doesn't read; SketchUp.exe exited with 53
        from debpak import foreign
        tables = {
            "Directory": "Directory\tDirectory_Parent\tDefaultDir\n\n\n"
                         "TARGETDIR\t\tSourceDir\nPF\tTARGETDIR\t.:Prog64~1|Program Files 64\n"
                         "SU\tPF\tSKETCH~1|SketchUp 2023\nINSTALLDIR\tSU\t.\nLAYOUT2\tINSTALLDIR\tLayOut\n"
                         "UP\tINSTALLDIR\t..\n",
            "Component": "Component\n\n\nSketchUp.exe\t{1}\tINSTALLDIR\t256\t\tsketchup.exe\n"
                         "LAYOUT\t{2}\tLAYOUT2\t256\t\t\n",
            "File": "File\n\n\nsketchup.exe\tSketchUp.exe\tSketchUp.exe\nqt5core.dll\tLAYOUT\tQt5Core.dll\n"
                    "kdd\tLAYOUT\tKDDOCK~1.DLL|kddockwidgets.dll\ngone\tLAYOUT\tgone.dll\n",
            "DuplicateFile": "FileKey\tComponent_\tFile_\tDestName\tDestFolder\n\n\n"
                             "d1\tSketchUp.exe\tqt5core.dll\tQt5Core.dll\tINSTALLDIR\n"
                             "d2\tSketchUp.exe\tkdd\t\t\n"
                             "d3\tSketchUp.exe\tgone\tgone.dll\tINSTALLDIR\n"
                             "d4\tSketchUp.exe\tkdd\t\tLAYOUT2\n"
                             "d5\tSketchUp.exe\tqt5core.dll\tQt5Core.dll\tUP\n",
        }
        for name, text in tables.items():
            write(self.tmp / "tables" / name, text)
        write(self.stubs.bin / "msiinfo", f"#!/bin/sh\ncat \"{self.tmp}/tables/$3\" 2>/dev/null\n", 0o755)
        out = self.tmp / "su"
        app = out / "Program Files 64/SketchUp 2023"
        write(app / "SketchUp.exe", b"exe")
        write(app / "LayOut/qt5core.dll", b"qt")        # letter case as Windows would ignore it
        write(app / "LayOut/kddockwidgets.dll", b"kdd")
        self.assertEqual(foreign._msi_duplicates(self.tmp / "x.msi", out), 2)
        self.assertEqual((app / "Qt5Core.dll").read_bytes(), b"qt")
        self.assertEqual((app / "kddockwidgets.dll").read_bytes(), b"kdd")
        # nothing for a source that isn't there, nothing over a file, nothing outside the folder
        self.assertFalse((app / "gone.dll").exists())
        self.assertEqual(sorted(p.name for p in (app / "LayOut").iterdir()), ["kddockwidgets.dll", "qt5core.dll"])
        self.assertFalse((out / "Program Files 64/Qt5Core.dll").exists())
        self.assertEqual(sorted(p.name for p in app.iterdir()),
                         ["LayOut", "Qt5Core.dll", "SketchUp.exe", "kddockwidgets.dll"])

    def test_installed_program_is_kept_for_converting_again(self):
        # convert checks the app and may convert again; OpenIV's installer took a quarter of an hour
        # each time it ran
        from debpak import foreign
        drive = self.tmp / "drive"
        write(drive / "Program Files/Acme/Acme.exe", exe_bytes("Acme"))
        setup = write(self.tmp / "AcmeSetup.exe", exe_bytes("Acme Setup", extra=STUBTAR + tar_bytes(drive)))
        foreign.forget_installed()
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S"}):
            first = foreign.wine_install(setup, self.tmp / "d1", None, "wow64-25.08", "why")
            runs = len([c for c in self.stubs.calls() if c.startswith("flatpak run ")])
            shutil.rmtree(self.tmp / "d1")
            again = foreign.wine_install(setup, self.tmp / "d2", None, "wow64-25.08", "why")
            self.assertEqual(len([c for c in self.stubs.calls() if c.startswith("flatpak run ")]), runs)
            self.assertTrue((again.root / "Acme.exe").is_file())
            self.assertEqual(again.meta, first.meta)
            foreign.forget_installed()          # a new conversion installs it afresh
            foreign.wine_install(setup, self.tmp / "d3", None, "wow64-25.08", "why")
            self.assertGreater(len([c for c in self.stubs.calls() if c.startswith("flatpak run ")]), runs)
        foreign.forget_installed()

    def test_nsis_installer_7z_cant_decode_runs_under_wine(self):
        # BomberClone 0.11.9: 7z gave "Data Error" on five of its pictures, and the conversion stopped
        from debpak import foreign, unpack
        drive = self.tmp / "drive"
        write(drive / "Program Files/Acme/Acme.exe", exe_bytes("Acme"))
        write(drive / "Program Files/Acme/data/player3.png", b"png")
        setup = write(self.tmp / "acme-0.11.9.exe",
                      exe_bytes("Acme Setup", extra=b"NullsoftInst" + STUBTAR + tar_bytes(drive)))
        real = unpack.unpack

        def seven_zip(path, steps, work):
            if Path(path) == setup:
                raise unpack.UnpackError("7z failed: ERROR: Data Error : data/player3.png")
            return real(path, steps, work)
        foreign.forget_installed()
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S"}), mock.patch.object(unpack, "unpack", seven_zip), \
                contextlib.redirect_stdout(io.StringIO()) as said:
            u = foreign.unpack_windows(setup, self.tmp / "d", "wow64-25.08")
        foreign.forget_installed()
        self.assertEqual(u.how, "wine-install")
        self.assertTrue((u.root / "Acme.exe").is_file())
        self.assertTrue((u.root / "data/player3.png").is_file())
        self.assertIn("Data Error", said.getvalue())
        self.assertFalse((self.tmp / "d/win").exists())

    def test_installer_kinds_by_their_marks(self):
        from debpak import wineinstall
        for mark, kind in ((b"Setup Factory 9", "setup-factory"), (b"WiseMain", "wise"),
                           (b"Smart Install Maker", "smart-install-maker"),
                           ("MetaTrader Setup".encode("utf-16-le"), "metaquotes"), (b"nothing", "other")):
            with self.subTest(kind=kind):
                f = write(self.tmp / "setup.exe", exe_bytes("Setup", extra=b"\0" + mark + b"\0"))
                self.assertEqual(wineinstall.kind_of(f, None), kind)
                self.assertTrue(wineinstall.SILENT[kind])
        # the mark can lie past the first megabytes (an InstallBuilder installer's, after its payload)
        f = write(self.tmp / "setup.exe", exe_bytes("Setup", extra=bytes(5 << 20) + b"BitRock InstallBuilder"))
        self.assertEqual(wineinstall.kind_of(f, None), "installbuilder")

    def test_files_an_earlier_attempt_wrote_count_when_written_again(self):
        # TypingMaster's installer, stopped while its message box waited, had written its files; the
        # run that finished wrote the same ones again, and they're the program
        import time
        from debpak.wineinstall import installed
        drive = self.tmp / "prefix/drive_c"
        exe = write(drive / "Program Files/Acme/Acme.exe", exe_bytes("Acme"))
        os.utime(exe, (1e9, 1e9))                   # installers keep the time the file was built
        self.assertIsNone(installed(self.tmp / "prefix", {"Program Files/Acme/Acme.exe"}, time.time() + 5))
        self.assertEqual(installed(self.tmp / "prefix", {"Program Files/Acme/Acme.exe"}, time.time() - 5),
                         (drive / "Program Files/Acme", None))
        # and the Temp folders are emptied between attempts (Unreal Commander's web installer quit
        # on finding its uncom.tmp from the attempt before)
        from debpak.wineinstall import _clear_temp
        left = write(drive / "users/me/AppData/Local/Temp/uncom.tmp/E5FD/x.exe", b"x")
        _clear_temp(self.tmp / "prefix")
        self.assertFalse(left.parent.parent.exists())
        self.assertTrue((drive / "users/me/AppData/Local/Temp").is_dir())
        self.assertTrue(exe.is_file())

    def test_installer_that_waits_is_stopped(self):
        # one that writes nothing for the idle seconds is waiting on a window, and stops then
        from debpak.wineinstall import SCRIPT
        bin_ = self.tmp / "wbin"
        write(bin_ / "wine", "#!/bin/sh\nmkdir -p \"$WINEPREFIX/drive_c/Acme\"\n"
              "echo x > \"$WINEPREFIX/drive_c/Acme/a.txt\"\n"
              # a log written all along doesn't count (EdgeUpdate's, under ActivePresenter's installer)
              "i=0; while [ $i -lt 60 ]; do echo x >> \"$WINEPREFIX/drive_c/Acme/update.log\"; sleep 1; "
              "i=$((i+1)); done\n", 0o755)
        for n in ("wineboot", "wineserver"):
            write(bin_ / n, "#!/bin/sh\nexit 0\n", 0o755)
        script = write(self.tmp / "install.sh", SCRIPT)
        (self.tmp / "prefix/drive_c").mkdir(parents=True)
        import time
        t = time.time()
        r = subprocess.run(["bash", str(script), str(self.tmp / "before.txt"), "120", "5", "setup.exe"],
                           capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}",
                                "WINEPREFIX": str(self.tmp / "prefix")})
        self.assertLess(time.time() - t, 30)
        self.assertIn("debpak: installer exit status idle", r.stdout)
        self.assertTrue((self.tmp / "before.txt").is_file())

    def test_web_page_instead_of_the_download(self):
        # WinSCP's download link is a page that starts the download from JavaScript
        page = write(self.tmp / "WinSCP-6.7.1-Portable.zip",
                     b"\xef\xbb\xbf\n  <!DOCTYPE html>\n<html lang=en><head><title>Download</title></head></html>")
        code, text, _ = self.convert(page)
        self.assertEqual(code, 1, text)
        self.assertIn("WinSCP-6.7.1-Portable.zip is a web page (HTML), not the download", text)
        for head in (b"<HTML><body>x</body></HTML>", b"<!-- a comment -->\n<html>", b'<?xml version="1.0"?>\n<html>'):
            with self.subTest(head=head), self.assertRaisesRegex(PackageError, "web page"):
                detect_format(write(self.tmp / "page.exe", head))
        # XML that isn't a web page still goes to the usual checks
        with self.assertRaisesRegex(PackageError, "unknown package format"):
            detect_format(write(self.tmp / "notes.xml", b'<?xml version="1.0"?>\n<notes/>'))

    def test_msix(self):
        d = self.tmp / "msix"
        write(d / "AppxManifest.xml", """
            <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
              <Identity Name="Acme.Paint" Version="5.1.0.0" ProcessorArchitecture="x64"/>
              <Properties><DisplayName>Acme Paint</DisplayName><Description>Paint it</Description></Properties>
              <Applications><Application Id="App" Executable="VFS\\ProgramFiles\\Paint\\paint.exe"/></Applications>
            </Package>""")
        write(d / "VFS/ProgramFiles/Paint/paint.exe", exe_bytes("whatever"))
        write(d / "VFS/ProgramFiles/Paint/big-helper.exe", exe_bytes("helper") + bytes(50000))
        pkg = zip_tree(d, self.tmp / "AcmePaint.msix")
        code, text, out = self.convert(pkg)
        self.assertEqual(code, 0, text)
        self.assertIn("Acme Paint 5.1.0.0", text)
        self.assertIn("VFS/ProgramFiles/Paint/paint.exe", text)

    def test_unknown_installer_and_missing_msiextract(self):
        setup = write(self.tmp / "AcmeInstaller.exe", exe_bytes("Acme Installer"))
        code, text, _ = self.convert(setup)
        self.assertEqual(code, 1)
        self.assertIn("convert the installed folder", text)
        msi = write(self.tmp / "a.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(100))
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            code, text, _ = self.convert(msi)
        self.assertIn("install msitools", text)

    def test_msi_through_msiextract(self):
        payload = self.tmp / "msi"
        write(payload / "Program Files/Acme/Acme Viewer/viewer.exe", exe_bytes("Acme Viewer"))
        msi = write(self.tmp / "viewer.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + STUBTAR + tar_bytes(payload))
        code, text, out = self.convert(msi)
        self.assertEqual(code, 0, text)
        self.assertTrue((out / "app/opt/acme-viewer/Program Files/Acme/Acme Viewer/viewer.exe").is_file())

    def test_wine_check_blocks_missing_dll(self):
        cache = self.tmp / "cache/debpak/wine"
        cache.mkdir(parents=True)
        idx = WineIndex(version="11.0", arch="x86_64", source="spec",
                        dlls={"kernel32.dll": {"e": {"ExitProcess": "i"}, "o": {}}})
        idx.save(cache / "11.0_x86_64.json")
        exe = write(self.tmp / "Acme.exe", exe_bytes(imports={"kernel32.dll": ["ExitProcess"],
                                                             "acmedrm.dll": ["Check"]}))
        code, text, _ = self.convert(exe)
        self.assertEqual(code, 2, text)
        self.assertIn("acmedrm.dll", text)
        code, text, _ = self.convert(exe, "--force")
        self.assertEqual(code, 0, text)

    def test_arm64_program_is_refused(self):
        exe = write(self.tmp / "Acme.exe", exe_bytes(arch="arm64"))
        code, text, _ = self.convert(exe)
        self.assertEqual(code, 2)
        self.assertIn("x86_64 only", text)

    def test_inspect(self):
        exe = write(self.tmp / "Acme.exe", exe_bytes())
        code, text = run_cli("inspect", str(exe), "--no-flathub-check", "--json")
        self.assertEqual(code, 0, text)
        self.assertEqual(json.loads(text)["route"], "wine")

    def test_runtime_suggestions_and_install(self):
        # the runtimes a program was built against are installed up front (GPT4All, TouchOSC and
        # instigator import msvcp140.dll and vcruntime140.dll without shipping them, and failed on
        # Wine's own); gdiplus, a download of most of a gigabyte, is only suggested
        exe = write(self.tmp / "Tool.exe", exe_bytes("Tool", imports={"kernel32.dll": ["ExitProcess"],
                                                                     "MSVCP140.dll": ["x"], "d3dx9_43.dll": ["y"],
                                                                     "gdiplus.dll": ["GdiplusStartup"]}))
        code, text, out = self.convert(exe)
        self.assertEqual(code, 0, text)
        self.assertIn("imports msvcp140.dll without shipping it, so the first start installs vcrun2022", text)
        self.assertIn("imports d3dx9_43.dll without shipping it, so the first start installs d3dx9", text)
        self.assertIn("imports gdiplus.dll without shipping it: if the program won't start, convert with "
                      "--wine-runtime gdiplus", text)
        m = json.loads(next(p for p in out.glob("*.json") if p.name != "report.json").read_text())
        self.assertEqual(m["x-debpak"]["runtimes"], ["d3dx9", "vcrun2022"])
        self.assertIn("--share=network", m["finish-args"])
        write(self.tmp / "dir/Tool.exe", exe.read_bytes())
        write(self.tmp / "dir/msvcp140.dll", dll_bytes())
        code, text, out = self.convert(self.tmp / "dir")
        self.assertNotIn("vcrun2022", text)                 # shipped, so nothing to install

        code, text, out = self.convert(exe, "--wine-runtime", "vcrun2022", "--wine-runtime", "corefonts")
        self.assertEqual(code, 0, text)
        launcher = (out / "app/bin/tool").read_text()
        self.assertIn('RUNTIMES="vcrun2022 corefonts d3dx9"', launcher)
        m = json.loads(next(p for p in out.glob("*.json") if p.name != "report.json").read_text())
        self.assertIn("--share=network", m["finish-args"])
        self.assertEqual(m["x-debpak"]["runtimes"], ["vcrun2022", "corefonts", "d3dx9"])
        self.assertEqual(m["x-debpak"]["convert-options"]["wine_runtime"], ["vcrun2022", "corefonts"])
        code, text, _ = self.convert(exe, "--wine-runtime", "rm -rf /")
        self.assertEqual(code, 2)
        self.assertIn("isn't a winetricks verb name", text)

    def test_hostile_names_stay_inert(self):
        """File and product names from the installer can't add shell commands or desktop keys."""
        evil = 'Evil\nExec=sh -c "touch /tmp/pwned"'
        d = self.tmp / "evil"
        write(d / "a$(touch pwned)`id`.exe", exe_bytes(evil, description=evil))
        code, text, out = self.convert(d, "--writable")
        self.assertEqual(code, 0, text)
        (launcher,) = (out / "app/bin").iterdir()
        script = launcher.read_text()
        self.assertIn("'a$(touch pwned)`id`.exe'", script)                 # single-quoted, never expanded
        self.assertFalse(any(line.startswith("Exec=") for line in script.splitlines()))
        (desktop,) = (out / "app/share/applications").iterdir()
        keys = [line.split("=", 1)[0] for line in desktop.read_text().splitlines() if "=" in line]
        self.assertEqual(keys.count("Exec"), 1)
        for sh in ("dash", "bash"):
            if shutil.which(sh):
                r = subprocess.run([sh, "-n", str(launcher)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_launcher_variant_is_valid_sh(self):
        from debpak.packages import Package
        from debpak.unpack import APPLY_EXTRA
        from debpak.winapp import launcher
        pkg = Package("wine", self.tmp, self.tmp, "acme", "1", extra={"display_name": "Acme 'quoted' \"name\""})
        scripts = [launcher(pkg, "acme", main, w, "1.0-abc", rt, symbol_fonts=sf, core_fonts=cf, cjk_fonts=cf,
                            webview2=cf)
                   for main in ("app.exe", "sub dir/My App.exe")
                   for w in (False, True) for rt in (None, ["vcrun2022", "corefonts"])
                   for sf in (None, ["Segoe UI Symbol"]) for cf in (False, True)]
        scripts.append(APPLY_EXTRA)
        for sh in ("dash", "bash"):
            if not shutil.which(sh):
                continue
            for i, text in enumerate(scripts):
                f = write(self.tmp / f"s{i}.sh", text)
                r = subprocess.run([sh, "-n", str(f)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, f"{sh}: {r.stderr}\n{text}")

    def test_categories(self):
        from debpak.foreign import categories
        from debpak.packages import Package
        def cat(name, summary="", category=""):
            return categories(Package("wine", self.tmp, self.tmp, "x", "1", summary=summary,
                                      extra={"display_name": name, "category": category}))
        self.assertEqual(cat("Anything", category="public.app-category.developer-tools"), "Development;")
        self.assertEqual(cat("Anything", category="Office"), "Office;")
        self.assertEqual(cat("Anything", category="AudioVideo;Audio;"), "AudioVideo;Audio;")
        self.assertEqual(cat("Mp3tag", "the universal tag editor for audio files"), "AudioVideo;Audio;")
        self.assertEqual(cat("Notion", "Your connected workspace for notes and docs"), "Office;")
        self.assertEqual(cat("Acme Tool"), "Utility;")
        app = electron_mac_app(self.tmp / "m")
        plist = app / "Contents/Info.plist"
        info = plistlib.loads(plist.read_bytes())
        info["LSApplicationCategoryType"] = "public.app-category.music"
        plist.write_bytes(plistlib.dumps(info))
        code, text, out = self.convert(app)
        self.assertEqual(code, 0, text)
        (desktop,) = (out / "app/share/applications").iterdir()
        self.assertIn("Categories=AudioVideo;Audio;Music;", desktop.read_text())

    def test_runtime_launcher_installs_once(self):
        from debpak.packages import Package
        from debpak.winapp import launcher
        prog = self.tmp / "prog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "wbin"
        for n in ("wine", "wineboot"):
            write(bin_ / n, f'#!/bin/sh\necho "{n} $*" >> "$WLOG"\n', 0o755)
        write(bin_ / "winetricks", '#!/bin/sh\necho "winetricks $*" >> "$WLOG"\nexit "${TRICKS_RC:-0}"\n', 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        script = write(self.tmp / "launch.sh", launcher(pkg, "acme", "app.exe", False, "s", ["vcrun2022", "corefonts"])
                       .replace("/app/opt/acme", str(prog)), 0o755)
        log = self.tmp / "wlog"
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "xdg"), "WLOG": str(log)}
        subprocess.run([str(script)], env={**env, "TRICKS_RC": "1"}, check=True, capture_output=True)
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        calls = [line for line in log.read_text().splitlines() if line.startswith("winetricks -q")]
        # failed once, then done; win10 undoes the Windows 7 that winetricks' .NET verbs leave set
        self.assertEqual(calls, ["winetricks -q --unattended vcrun2022 corefonts win10"] * 2)
        # a prefix whose runtimes went in before win10 was added gets it on the next start
        (self.tmp / "xdg/wine/.debpak-runtimes").write_text("vcrun2022 corefonts\n")
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        calls = [line for line in log.read_text().splitlines() if line.startswith("winetricks -q")]
        self.assertEqual(len(calls), 3)
        # a .NET this winetricks doesn't know comes from Microsoft's zips (Git Extensions needs .NET 10)
        write(bin_ / "winetricks", '#!/bin/sh\necho "winetricks $*" >> "$WLOG"\n'
              '[ "$1" = list-all ] && echo "dotnetdesktop8          MS .NET Desktop Runtime 8.0"\nexit 0\n', 0o755)
        write(bin_ / "curl", f"#!{sys.executable}\nimport os, sys, zipfile\n"
              "out, url = sys.argv[sys.argv.index('-o') + 1], sys.argv[-1]\n"
              "open(os.environ['WLOG'], 'a').write('curl ' + url + '\\n')\n"
              "with zipfile.ZipFile(out, 'w') as z: z.writestr(url.rsplit('/', 1)[1] + '.txt', 'x')\n", 0o755)
        script = write(self.tmp / "launch10.sh", launcher(pkg, "acme", "app.exe", False, "s", ["dotnetdesktop10"])
                       .replace("/app/opt/acme", str(prog)), 0o755)
        env["XDG_DATA_HOME"] = str(self.tmp / "xdg10")
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        dotnet = self.tmp / "xdg10/wine/drive_c/Program Files/dotnet"
        self.assertEqual(sorted(p.name for p in dotnet.iterdir()),
                         ["dotnet-runtime-win-x64.zip.txt", "windowsdesktop-runtime-win-x64.zip.txt"])
        self.assertIn("curl https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-x64.zip", log.read_text())
        tricks = [line for line in log.read_text().splitlines() if line.startswith("winetricks -q")]
        self.assertEqual(tricks[-1], "winetricks -q --unattended win10")
        self.assertEqual((self.tmp / "xdg10/wine/.debpak-runtimes").read_text(), "dotnetdesktop10 win10\n")
        # winetricks' dotnet11 is the .NET Framework 1.1, so .NET 11 comes from the zips too
        # (OpenDirectoryDownloader 5.1), while its dotnet48 and a modern .NET it has stay its own
        write(bin_ / "winetricks", '#!/bin/sh\necho "winetricks $*" >> "$WLOG"\n'
              '[ "$1" = list-all ] && printf "%s\\n" "dotnet11       MS .NET 1.1 (Microsoft, 2003)" '
              '"dotnet48       MS .NET 4.8 (Microsoft, 2019)" "dotnet9        MS .NET Runtime 9.0 LTS (Microsoft, 2026)"'
              '\nexit 0\n', 0o755)
        script = write(self.tmp / "launch11.sh", launcher(pkg, "acme", "app.exe", False, "s",
                                                          ["dotnet11", "dotnet48", "dotnet9"])
                       .replace("/app/opt/acme", str(prog)), 0o755)
        env["XDG_DATA_HOME"] = str(self.tmp / "xdg11")
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        self.assertIn("curl https://aka.ms/dotnet/11.0/dotnet-runtime-win-x64.zip", log.read_text())
        self.assertNotIn("aka.ms/dotnet/48.0", log.read_text())
        tricks = [line for line in log.read_text().splitlines() if line.startswith("winetricks -q")]
        self.assertEqual(tricks[-1], "winetricks -q --unattended dotnet48 dotnet9 win10")
        # ASP.NET Core, which winetricks has no verb for, from its own zip, which holds the .NET runtime too
        script = write(self.tmp / "launchasp.sh", launcher(pkg, "acme", "app.exe", False, "s", ["aspnetcore8"])
                       .replace("/app/opt/acme", str(prog)), 0o755)
        env["XDG_DATA_HOME"] = str(self.tmp / "xdgasp")
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        dotnet = self.tmp / "xdgasp/wine/drive_c/Program Files/dotnet"
        self.assertEqual([p.name for p in dotnet.iterdir()], ["aspnetcore-runtime-win-x64.zip.txt"])
        self.assertEqual((self.tmp / "xdgasp/wine/.debpak-runtimes").read_text(), "aspnetcore8 win10\n")
        from debpak.winapp import modern_dotnet
        self.assertEqual([v for v in ("dotnet11", "dotnetdesktop10", "dotnet8", "aspnetcore11", "dotnet48", "dotnet40",
                                      "vcrun2022") if modern_dotnet(v)],
                         ["dotnet11", "dotnetdesktop10", "dotnet8", "aspnetcore11"])
        # a Windows version the user asked for is left alone
        text = launcher(pkg, "acme", "app.exe", False, "s", ["dotnet40", "winxp"])
        self.assertIn('VERBS="$RUNTIMES"', text)
        self.assertIn('VERBS="$RUNTIMES win10"', launcher(pkg, "acme", "app.exe", False, "s", ["dotnet48"]))

    def test_runtime_survey(self):
        from debpak.winrt import cjk_text, survey
        d = self.tmp / "survey"
        main = write(d / "app.exe", exe_bytes("App"))
        vc = {"vcruntime140.dll", "msvcp140.dll", "msvcr120.dll", "d3dcompiler_47.dll", "gdiplus.dll", "kernel32.dll"}
        rt = survey(main, [main], vc)
        self.assertEqual(rt.verbs, ["d3dcompiler_47", "vcrun2022", "vcrun2013"])
        self.assertEqual(rt.suggest, {"gdiplus": "gdiplus.dll"})
        self.assertTrue(rt.core_fonts)
        self.assertEqual((rt.cjk, rt.webview2), ("", ""))
        # a DLL the program ships is its own
        ship = write(d / "msvcp140.dll", dll_bytes())
        self.assertEqual(survey(main, [main, ship], {"msvcp140.dll"}).verbs, [])
        # Chinese text in its string table, or in UTF-8 strings (a Go or Qt program)
        table = struct.pack("<H", 4) + "\u6253\u5f00\u6587\u4ef6".encode("utf-16-le") + bytes(30)
        zh = write(d / "zh.exe", build_pe(PeSpec(arch="x86_64", is_dll=False, imports={"kernel32.dll": ["ExitProcess"]},
                                                 resources=[(6, 1, table)], subsystem=2)))
        self.assertIn("\u6253\u5f00", cjk_text(zh))
        utf8 = write(d / "go.exe", exe_bytes("Go", extra=b"\0".join("\u6253\u5f00\u6587\u4ef6\u5939".encode() for _ in range(3))))
        self.assertEqual(cjk_text(utf8), "it holds strings in Chinese, Japanese or Korean")
        self.assertEqual(cjk_text(write(d / "one.exe", exe_bytes("One", extra="\u7b80\u4f53\u4e2d\u6587".encode()))), "")
        # WebView2: its loader, or the runtime's client GUID in the program (Tauri links the loader in)
        tauri = write(d / "tauri/app.exe", exe_bytes("T", extra="{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}".encode("utf-16-le")))
        self.assertIn("F3017226", survey(tauri, [tauri], set()).webview2)
        self.assertEqual(survey(main, [main], {"webview2loader.dll"}).webview2, "it imports WebView2Loader.dll")
        # one that brings its own copy of the runtime needs nothing
        write(d / "tauri/runtime/msedgewebview2.exe", exe_bytes("Edge"))
        self.assertEqual(survey(tauri, [tauri], set()).webview2, "")

    def test_webview2_program_gets_the_runtime_on_first_start(self):
        """Netstat Cat (Tauri) showed "Error" and QShell (Wails) "Missing Requirements": no WebView2 runtime."""
        import hashlib
        from debpak.packages import Package
        from debpak.winapp import launcher
        from debpak.winrt import WEBVIEW2_CAB, WEBVIEW2_PAGE, WEBVIEW2_SHA256
        prog = self.tmp / "wprog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "wvbin"
        write(bin_ / "wineboot", "#!/bin/sh\n", 0o755)
        write(bin_ / "wineserver", "#!/bin/sh\n", 0o755)
        write(bin_ / "wine", '#!/bin/sh\nprintf "%s\\n" "wine $* [$WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS]" >> "$WLOG"\n',
              0o755)
        newer = ("https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/0a1b-2c/"
                 "Microsoft.WebView2.FixedVersionRuntime.160.0.1.2.x64.cab")
        page = '{"url":"' + newer.replace("/", "\\u002F") + '"}'
        # curl: the page, or a "cab" that names its runtime's version
        write(bin_ / "curl", f"#!{sys.executable}\nimport os, sys\nurl = sys.argv[-1]\n"
              "open(os.environ['WLOG'], 'a').write('curl ' + url + '\\n')\n"
              f"if url == {WEBVIEW2_PAGE!r}: print({page!r}); sys.exit(0)\n"
              "if os.environ.get('CURL_FAIL'): sys.exit(22)\n"
              "open(sys.argv[sys.argv.index('-o') + 1], 'w').write(url.split('Runtime.')[1].rsplit('.x64', 1)[0])\n",
              0o755)
        write(bin_ / "cabextract", f"#!{sys.executable}\nimport os, sys\n"
              "out, cab = sys.argv[sys.argv.index('-d') + 1], sys.argv[-1]\n"
              "open(os.environ['WLOG'], 'a').write('installing ' + str(os.path.exists(os.path.join("
              "os.environ['XDG_DATA_HOME'], 'wine', '.debpak-installing'))) + '\\n')\n"
              "d = os.path.join(out, 'Microsoft.WebView2.FixedVersionRuntime.' + open(cab).read() + '.x64')\n"
              "os.makedirs(d + '/Locales')\nopen(d + '/msedgewebview2.exe', 'w').close()\n"
              "for n in ('en-US', 'de', 'pt-BR', 'pt-PT', 'copilot_overlay_strings_pt-BR', 'copilot_overlay_strings_fr'):\n"
              "    open(d + '/Locales/' + n + '.pak', 'w').close()\n", 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        text = launcher(pkg, "acme", "app.exe", False, "s", webview2=True).replace("/app/opt/acme", str(prog))
        # the pinned cab is checked against its SHA-256: the stand-in's own is put in its place
        stub = hashlib.sha256(b"158.0.4370.45").hexdigest() if "158.0.4370.45" in WEBVIEW2_CAB else ""
        script = write(self.tmp / "wv.sh", text.replace(WEBVIEW2_SHA256, stub), 0o755)
        log = self.tmp / "wvlog"
        xdg = self.tmp / "wvxdg"
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(xdg), "WLOG": str(log), "LANG": "pt_BR.UTF-8"}
        for x in (xdg, self.tmp / "wvxdg2", self.tmp / "wvxdg3"):
            # a prefix Wine has set up (the launcher sets up again one without kernel32.dll, or unfinished)
            write(x / "wine/drive_c/windows/system32/kernel32.dll", b"")
            write(x / "wine/.debpak-prefix", b"")
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        home = xdg / "wine/drive_c/Program Files (x86)/Microsoft/EdgeWebView/Application/158.0.4370.45"
        self.assertTrue((home / "msedgewebview2.exe").exists())
        # en-US and the user's language are kept
        self.assertEqual(sorted(p.name for p in (home / "Locales").iterdir()),
                         ["copilot_overlay_strings_pt-BR.pak", "en-US.pak", "pt-BR.pak"])
        lines = log.read_text().splitlines()
        self.assertIn("installing True", lines)
        self.assertEqual([ln for ln in lines if ln.startswith("curl")], ["curl " + WEBVIEW2_CAB])
        self.assertIn("wine reg add HKLM\\Software\\Microsoft\\EdgeUpdate\\ClientState\\"
                      "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} /v EBWebView /t REG_SZ /d C:\\Program Files (x86)\\"
                      "Microsoft\\EdgeWebView\\Application\\158.0.4370.45 /reg:32 /f []", lines)
        self.assertIn("wine reg add HKCU\\Software\\Wine\\AppDefaults\\msedgewebview2.exe /v Version /t REG_SZ /d win7 "
                      "/f []", lines)
        # the program is started with Chromium's switches for Wine
        self.assertTrue(lines[-1].endswith("app.exe [--no-sandbox --disable-gpu]"), lines[-1])
        self.assertEqual((xdg / "wine/.debpak-webview2").read_text(), "158.0.4370.45\n")
        self.assertFalse((xdg / "wine/.debpak-installing").exists())
        self.assertFalse((xdg / "wine/debpak-webview2").exists())
        # once is enough; a runtime folder that has gone is fetched again
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        self.assertEqual(sum(ln.startswith("curl") for ln in log.read_text().splitlines()), 1)
        shutil.rmtree(home)
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        self.assertEqual(sum(ln.startswith("curl") for ln in log.read_text().splitlines()), 2)
        # a pinned cab that changed is passed over for the newest on Microsoft's page
        log.unlink()
        xdg2 = self.tmp / "wvxdg2"
        script = write(self.tmp / "wv2.sh", text, 0o755)
        subprocess.run([str(script)], env={**env, "XDG_DATA_HOME": str(xdg2), "LANG": "C"}, check=True,
                       capture_output=True)
        self.assertEqual([ln for ln in log.read_text().splitlines() if ln.startswith("curl")],
                         ["curl " + WEBVIEW2_CAB, "curl " + WEBVIEW2_PAGE, "curl " + newer])
        self.assertEqual((xdg2 / "wine/.debpak-webview2").read_text(), "160.0.1.2\n")
        newer_home = xdg2 / "wine/drive_c/Program Files (x86)/Microsoft/EdgeWebView/Application/160.0.1.2"
        self.assertEqual(sorted(p.name for p in (newer_home / "Locales").iterdir()), ["en-US.pak"])
        # no network: it says so, starts the program anyway, and tries again next time
        xdg3 = self.tmp / "wvxdg3"
        r = subprocess.run([str(script)], env={**env, "XDG_DATA_HOME": str(xdg3), "CURL_FAIL": "1"}, check=True,
                           capture_output=True, text=True)
        self.assertIn("WebView2's runtime didn't install", r.stderr)
        self.assertFalse((xdg3 / "wine/.debpak-webview2").exists())
        self.assertFalse((xdg3 / "wine/.debpak-installing").exists())
        # switches the user set, even none, are kept
        r = subprocess.run([str(script)], env={**env, "XDG_DATA_HOME": str(xdg2),
                                               "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": ""}, check=True)
        self.assertTrue(log.read_text().splitlines()[-1].endswith("app.exe []"))

    def test_webview2_program_that_crashes_as_it_starts_is_started_again(self):
        """Netstat Cat crashed in Wine's RevokeDragDrop on about one start in four, racing WebView2's browser."""
        from debpak.packages import Package
        from debpak.winapp import launcher
        prog = self.tmp / "rprog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "rbin"
        for n in ("wineboot", "wineserver"):
            write(bin_ / n, "#!/bin/sh\n", 0o755)
        # the program crashes (status 5) as many times as CRASHES says; wine reg and the rest succeed
        write(bin_ / "wine", '#!/bin/sh\ncase "$1" in *app.exe) n=$(cat "$WLOG" 2>/dev/null | wc -l); '
              'echo run >> "$WLOG"; [ "$n" -lt "$CRASHES" ] && exit 5; exit "${STATUS:-0}";; esac\nexit 0\n', 0o755)
        xdg = self.tmp / "rxdg"
        wv2 = xdg / "wine/drive_c/Program Files (x86)/Microsoft/EdgeWebView/Application/1.2.3.4"
        write(wv2 / "msedgewebview2.exe", b"")
        write(xdg / "wine/.debpak-webview2", "1.2.3.4\n")
        write(xdg / "wine/drive_c/windows/system32/kernel32.dll", b"")
        write(xdg / "wine/.debpak-prefix", b"")
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        script = write(self.tmp / "r.sh", launcher(pkg, "acme", "app.exe", False, "s", webview2=True)
                       .replace("/app/opt/acme", str(prog)), 0o755)
        log = self.tmp / "rlog"
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(xdg), "WLOG": str(log)}
        # Routa crashed on three starts in a row on a busy machine and came up on the fourth
        for crashes, runs, status in ((0, 1, 0), (2, 3, 0), (3, 4, 0), (7, 8, 0), (9, 8, 5)):
            log.unlink(missing_ok=True)
            r = subprocess.run([str(script)], env={**env, "CRASHES": str(crashes)}, capture_output=True, text=True)
            self.assertEqual((len(log.read_text().split()), r.returncode), (runs, status), r.stderr)
        # another failure is the program's own, and its status is passed on
        log.unlink()
        r = subprocess.run([str(script)], env={**env, "CRASHES": "0", "STATUS": "3"}, capture_output=True)
        self.assertEqual((len(log.read_text().split()), r.returncode), (1, 3))

    def test_webview2_program_is_planned_to_get_the_runtime(self):
        d = self.tmp / "netstatcat"
        write(d / "netstat-cat.exe", exe_bytes("Netstat Cat", extra="{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
                                                .encode("utf-16-le")))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("the first start downloads Microsoft's Fixed Version runtime", text)
        m = self.manifest(out)
        self.assertTrue(m["x-debpak"]["webview2"])
        self.assertIn("--share=network", m["finish-args"])
        (script,) = (out / "app/bin").iterdir()
        self.assertIn("EBWebView", script.read_text())
        self.assertIn("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", script.read_text())
        # a program without it gets none of it
        write(d / "netstat-cat.exe", exe_bytes("Netstat Cat"))
        code, text, out = self.convert(d)
        self.assertFalse(self.manifest(out)["x-debpak"]["webview2"])
        (script,) = (out / "app/bin").iterdir()
        self.assertNotIn("WebView2", script.read_text())

    def test_cjk_program_gets_cjk_fonts(self):
        table = struct.pack("<H", 4) + "\u6253\u5f00\u6587\u4ef6".encode("utf-16-le") + bytes(30)
        d = self.tmp / "zh"
        write(d / "Tool.exe", build_pe(PeSpec(arch="x86_64", is_dll=False, imports={"kernel32.dll": ["ExitProcess"]},
                                              resources=[(6, 1, table), version_info({"ProductName": "Tool"})],
                                              subsystem=2)))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("shows Chinese, Japanese or Korean text", text)
        launcher = next((out / "app/bin").iterdir()).read_text()
        self.assertIn("sans-serif:lang=$lang", launcher)
        code, text, out = self.convert(write(self.tmp / "plain/Tool.exe", exe_bytes("Tool")).parent)
        launcher = next((out / "app/bin").iterdir()).read_text()
        self.assertIn("'Times New Roman' 'Liberation Serif'", launcher)
        self.assertNotIn("lang=", launcher)

    def test_font_launcher_sets_them_once(self):
        # Arial and the rest as the runtime's metric-compatible fonts, always; Windows' CJK fonts as
        # the sandbox's CJK font for a CJK program, with Wine's dialog fonts linked to it
        from debpak.packages import Package
        from debpak.winapp import launcher
        prog = self.tmp / "prog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "fbin"
        write(bin_ / "wineboot", "#!/bin/sh\n", 0o755)
        write(bin_ / "wine", '#!/bin/sh\nprintf "%s\\n" "wine $*" >> "$WLOG"\n'
              '[ "$1" = regedit ] && cp "$3" "$WLOG.reg"\nexit 0\n', 0o755)
        write(bin_ / "wineserver", "#!/bin/sh\n", 0o755)
        write(bin_ / "fc-match", '#!/bin/sh\ncase "$*" in *zh-cn*|*ja*) ;; *) printf /usr/share/fonts/DejaVuSans.ttf; '
              'exit 0;; esac\n'
              'case "$*" in *file*) printf /run/host/fonts/NotoSansCJK-Regular.ttc ;; '
              '*zh-cn*) printf "Noto Sans CJK SC" ;; *) printf "Noto Sans CJK JP" ;; esac\n', 0o755)
        write(bin_ / "fc-list", '#!/bin/sh\ncase "$1" in *zh-cn*|*ja*) echo /run/host/fonts/NotoSansCJK-Regular.ttc: ;; '
              'esac\n', 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        script = write(self.tmp / "fonts.sh", launcher(pkg, "acme", "app.exe", False, "s", core_fonts=True,
                                                       cjk_fonts=True).replace("/app/opt/acme", str(prog)), 0o755)
        log = Path(str(self.tmp / "flog"))
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "fxdg"), "WLOG": str(log)}
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        reg = Path(f"{log}.reg").read_text(newline="")
        self.assertIn('"Arial"="Liberation Sans"\r\n', reg)
        self.assertIn('"Calibri"="Carlito"\r\n', reg)
        self.assertIn('"SimSun"="Noto Sans CJK SC"\r\n', reg)
        self.assertIn('"MS UI Gothic"="Noto Sans CJK JP"\r\n', reg)
        self.assertNotIn("Gulim", reg)                    # no Korean font in this sandbox
        links = [ln for ln in log.read_text().splitlines() if "SystemLink" in ln]
        self.assertEqual(len(links), 8)
        self.assertIn("/v Tahoma /t REG_MULTI_SZ /d NotoSansCJK-Regular.ttc,Noto Sans CJK SC\\0"
                      "NotoSansCJK-Regular.ttc,Noto Sans CJK JP /f", links[0])
        self.assertFalse((self.tmp / "fxdg/wine/debpak-fonts.reg").exists())
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        self.assertEqual(sum("regedit" in ln for ln in log.read_text().splitlines()), 1)

    def test_runtime_install_leaves_a_marker_while_it_runs(self):
        # the check waits while it's there (see selfcheck.OBSERVER)
        from debpak.packages import Package
        from debpak.winapp import launcher
        prog = self.tmp / "mprog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "mbin"
        for n in ("wine", "wineboot", "wineserver"):
            write(bin_ / n, "#!/bin/sh\n", 0o755)
        write(bin_ / "winetricks", '#!/bin/sh\n[ "$1" = list-all ] && exit 0\n'
              'ls -a "$WINEPREFIX" >> "$WLOG"; exit 0\n', 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        script = write(self.tmp / "m.sh", launcher(pkg, "acme", "app.exe", False, "s", ["vcrun2022"])
                       .replace("/app/opt/acme", str(prog)), 0o755)
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "mxdg"), "WLOG": str(self.tmp / "mlog")}
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        self.assertIn(".debpak-installing", (self.tmp / "mlog").read_text().split())
        self.assertFalse((self.tmp / "mxdg/wine/.debpak-installing").exists())
        self.assertTrue((self.tmp / "mxdg/wine/.debpak-runtimes").exists())

    def test_python_3_15_program_gets_microsofts_ucrtbase(self):
        """GAM, on Python 3.15: its calendar module asks strftime for "%OB", which Wine's ucrtbase.dll rejects."""
        d = self.tmp / "gam"
        write(d / "gam.exe", exe_bytes("GAM", subsystem=3))
        write(d / "lib/python315.dll", dll_bytes())
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("runs on Python 3.15", text)
        self.assertEqual(self.manifest(out)["x-debpak"]["runtimes"], ["ucrtbase2019"])
        self.assertIn("--share=network", self.manifest(out)["finish-args"])
        # a onefile build names its DLL in the archive at the end of the .exe
        write(self.tmp / "one/Tool.exe", exe_bytes("Tool", extra=b"\0" * 4096 + b"MEI\x0c\x0b\x0a\x0b\x0epython315.dll"))
        code, text, out = self.convert(self.tmp / "one")
        self.assertIn("ucrtbase2019", self.manifest(out)["x-debpak"]["runtimes"])
        # an older Python is left on Wine's own
        (d / "lib/python315.dll").rename(d / "lib/python313.dll")
        code, text, out = self.convert(d)
        self.assertNotIn("ucrtbase", text)

    def test_launcher_forces_a_runtime_wine_has_a_dll_for(self):
        """Wine's ucrtbase.dll is in system32, so winetricks took ucrtbase2019 as done and skipped it."""
        from debpak.packages import Package
        from debpak.winapp import launcher
        prog = self.tmp / "prog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "wbin"
        for n in ("wine", "wineboot", "wineserver"):
            write(bin_ / n, f'#!/bin/sh\necho "{n} $*" >> "$WLOG"\n', 0o755)
        write(bin_ / "winetricks", '#!/bin/sh\necho "winetricks $*" >> "$WLOG"\n', 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        script = write(self.tmp / "launch.sh", launcher(pkg, "acme", "app.exe", False, "s", ["vcrun2022", "ucrtbase2019"])
                       .replace("/app/opt/acme", str(prog)), 0o755)
        log = self.tmp / "wlog"
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "xdg"), "WLOG": str(log)}
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        calls = [line for line in log.read_text().splitlines() if line.startswith("winetricks -q")]
        self.assertEqual(calls, ["winetricks -q --unattended vcrun2022 win10",
                                 "winetricks -q --unattended --force ucrtbase2019"])
        self.assertEqual((self.tmp / "xdg/wine/.debpak-runtimes").read_text(), "vcrun2022 ucrtbase2019 win10\n")

    def test_visual_basic_6_program_gets_its_runtime(self):
        # Wine has no MSVBVM60.DLL at all, so XYplorer can't start without winetricks' vb6run
        d = self.tmp / "vb6"
        write(d / "XYplorer.exe", exe_bytes("XYplorer", arch="i386",
                                            imports={"MSVBVM60.DLL": ["ThunRTMain"], "kernel32.dll": ["ExitProcess"]}))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("so vb6run is installed", text)
        (launcher,) = (out / "app/bin").iterdir()
        self.assertIn('RUNTIMES="vb6run"', launcher.read_text())
        # one that ships the DLL beside it doesn't need it
        write(d / "msvbvm60.dll", dll_bytes())
        code, text, out = self.convert(d)
        self.assertNotIn("vb6run", text)
        # nor has Wine any MFC: TrafficMonitor imports mfc140u.dll and exited with status 53, Dependency
        # Walker MFC42.DLL; a DLL the program ships that imports it counts as well
        d = self.tmp / "mfc-apps"
        write(d / "TrafficMonitor.exe", exe_bytes("TrafficMonitor", imports={"mfc140u.dll": ["CWinApp"],
                                                                               "kernel32.dll": ["ExitProcess"]}))
        write(d / "plugins/Skin.dll", build_pe(PeSpec(arch="i386", is_dll=True, imports={"MFC42.DLL": ["CWnd"]})))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("imports mfc140u.dll, which Wine doesn't have, so vcrun2022 is installed", text)
        self.assertIn("imports mfc42.dll, which Wine doesn't have, so mfc42 is installed", text)
        # winetricks' mfc42 is 32-bit only, so Dependency Walker's x64 build (status 53 even with it) is refused
        d = self.tmp / "depends64"
        write(d / "depends.exe", exe_bytes("Dependency Walker", imports={"MFC42.DLL": ["CWnd"],
                                                                         "kernel32.dll": ["ExitProcess"]}))
        code, text, out = self.convert(d)
        self.assertEqual(code, 2, text)
        self.assertIn("64-bit program that imports mfc42.dll", text)
        self.assertIn("32-bit build", text)

    def test_dll_wine_is_built_without_gets_a_stand_in(self):
        # Flathub's Wine has no winscard.dll (it's built without pcsc-lite), and Belfius Connector,
        # which imports it, exited with status 53 before it ran
        from debpak.pe import read_pe
        d = self.tmp / "belfius"
        write(d / "BelfiusConnector/belfiusconnector-api.exe", exe_bytes(
            "BelfiusConnector", subsystem=3, imports={"kernel32.dll": ["ExitProcess"],
                                                       "WinSCard.dll": ["SCardEstablishContext", "SCardAccessStartedEvent"]}))
        for base in (None, {"kernel32.dll", "ntdll.dll"}):
            with mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
                code, text, out = self.convert(d)
            self.assertEqual(code, 0, text)
            self.assertIn("imports WinSCard.dll, which Wine lacks for smart cards", text)
            (slug,) = (out / "app/opt").iterdir()
            stand_in = slug / "BelfiusConnector/WinSCard.dll"
            info = read_pe(stand_in)
            self.assertEqual(set(info.exports), {"SCardEstablishContext", "SCardAccessStartedEvent"})
            data = stand_in.read_bytes()
            # the SCard functions say the service isn't running (SCARD_E_NO_SERVICE); a handle is NULL
            self.assertIn(bytes.fromhex("b81d001080c3"), data)
            self.assertIn(bytes.fromhex("b800000000c3"), data)
        # a Wine that has it uses its own
        with mock.patch("debpak.winapp.wine_base_dlls", return_value={"kernel32.dll", "winscard.dll"}):
            code, text, out = self.convert(d)
        self.assertNotIn("stand-in", text)
        self.assertFalse(any(out.rglob("WinSCard.dll")))

    def test_dll_another_package_of_the_installer_has_is_put_beside_the_program(self):
        # Apple's AirPortSetup.exe installs AirPort.msi with Bonjour.msi, whose dnssd.dll APUtil.exe imports;
        # APUtil.exe, from AirPort.msi alone, was refused for lacking it
        from debpak.pe import read_pe
        prog = self.tmp / "ap"
        write(prog / "Program Files/AirPort/APUtil.exe", exe_bytes(
            "AirPort Utility", arch="i386", imports={"kernel32.dll": ["ExitProcess"], "dnssd.dll": ["DNSServiceBrowse"]}))
        bonjour = self.tmp / "bj"
        write(bonjour / "Program Files/Bonjour/mDNSResponder.exe", exe_bytes("Bonjour Service", arch="i386"))
        write(bonjour / "Program Files 64/dnssd.dll", build_pe(PeSpec(is_dll=True, exports=["DNSServiceBrowse"])))
        write(bonjour / "dnssd.dll", build_pe(PeSpec(arch="i386", is_dll=True, exports=["DNSServiceBrowse"])))
        ole = bytes.fromhex("d0cf11e0a1b11ae1") + STUBTAR
        msis = {"AirPort.msi": ole + tar_bytes(prog), "Bonjour.msi": ole + tar_bytes(bonjour),
                "vcredist_x86.msi": ole + tar_bytes(bonjour)}
        z = self.tmp / "AirPortSetup.zip"
        with zipfile.ZipFile(z, "w") as zf:
            for name, data in msis.items():
                zf.writestr(name, data)
        base = {"kernel32.dll", "ntdll.dll"}
        with mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, out = self.convert(z)
        self.assertEqual(code, 0, text)
        self.assertIn("main executable Program Files/AirPort/APUtil.exe", text)
        self.assertIn("imports dnssd.dll, which Bonjour.msi, another package its installer installs, has", text)
        (slug,) = (out / "app/opt").iterdir()
        # the 32-bit one, for a 32-bit program
        self.assertEqual(read_pe(slug / "Program Files/AirPort/dnssd.dll").machine, "i386")
        # with nothing beside it that has the DLL, it's refused as before
        z.unlink()
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("AirPort.msi", msis["AirPort.msi"])
        with mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, out = self.convert(z)
        self.assertEqual(code, 2, text)
        self.assertIn("needs dnssd.dll to start", text)

    def test_dll_its_installer_put_in_the_system_folder_is_put_beside_the_program(self):
        # Brinno Video Player's DeployMaster setup, run under Wine, put C++Builder 5's packages in
        # C:\windows\system32 (SysWOW64 for a 32-bit installer), and bvplay.exe, taken from its own
        # folder, was refused for lacking VCL50.BPL, VCLX50.BPL and TSILANG_CB5R.BPL
        from debpak import foreign
        from debpak.pe import read_pe
        drive = self.tmp / "drive"
        write(drive / "Program Files/Brinno Video Player/bvplay.exe", exe_bytes(
            "Brinno Video Player", arch="i386",
            imports={"kernel32.dll": ["ExitProcess"], "VCL50.BPL": ["@Forms@initialization$qqrv"]}))
        # a package imports another from the same folder; the 64-bit copy is the wrong one
        write(drive / "windows/syswow64/VCL50.BPL", build_pe(PeSpec(
            arch="i386", is_dll=True, exports=["@Forms@initialization$qqrv"], imports={"RTL50.BPL": ["@System@x"]})))
        write(drive / "windows/syswow64/RTL50.BPL", build_pe(PeSpec(arch="i386", is_dll=True, exports=["@System@x"])))
        write(drive / "windows/system32/VCL50.BPL", build_pe(PeSpec(is_dll=True, exports=["@Forms@initialization$qqrv"])))
        write(drive / "windows/syswow64/unused.dll", build_pe(PeSpec(arch="i386", is_dll=True, exports=["f"])))
        setup = write(self.tmp / "Setup Brinno Video Player.exe",
                      exe_bytes("DeployMaster", extra=STUBTAR + tar_bytes(drive)))
        base = {"kernel32.dll", "ntdll.dll"}
        foreign.forget_installed()
        self.addCleanup(foreign.forget_installed)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S"}), \
                mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertIn("imports VCL50.BPL, which its installer put in Windows' system folder", text)
        self.assertIn("imports RTL50.BPL, which its installer put in Windows' system folder", text)
        (slug,) = (out / "app/opt").iterdir()
        self.assertEqual(read_pe(slug / "VCL50.BPL").machine, "i386")
        self.assertTrue((slug / "RTL50.BPL").is_file())
        self.assertFalse((slug / "unused.dll").exists())
        # converting again (after the check) takes them from what was kept
        shutil.rmtree(out)
        with mock.patch.dict(os.environ, {"STUB_WINE": "/S"}), \
                mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, out = self.convert(setup)
        self.assertEqual(code, 0, text)
        self.assertTrue((next((out / "app/opt").iterdir()) / "RTL50.BPL").is_file())

    def test_dll_neither_the_program_nor_wine_has_stops_the_conversion(self):
        # a DLL Wine lacks, that nothing stands in for: status 53 (Bonjour's dnssd.dll, which AirPort
        # Utility imports, when nothing else in the installer has it)
        d = self.tmp / "qfield"
        write(d / "bin/qfield.exe", exe_bytes("QField", imports={"kernel32.dll": ["ExitProcess"], "icu.dll": ["u_strlen"],
                                                                  "Qt6Core.dll": ["qVersion"]}))
        write(d / "bin/Qt6Core.dll", build_pe(PeSpec(is_dll=True, imports={"MFCORE.dll": ["MFCreateMediaSession"],
                                                                             "dnssd.dll": ["DNSServiceBrowse"],
                                                                             "ntdll.dll": ["NtClose"]})))
        # a DLL nothing loads at start, and one only delay-loaded, don't count
        write(d / "bin/plugins/geo.dll", build_pe(PeSpec(is_dll=True, imports={"absent.dll": ["Nope"]})))
        base = {"kernel32.dll", "ntdll.dll", "mf.dll"}
        with mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, _out = self.convert(d)
        self.assertEqual(code, 2, text)
        # icu.dll it gets (see test_program_that_imports_windows_icu_gets_icu), and MFCORE.dll (see
        # test_dll_windows_split_out_of_another_passes_its_functions_on): dnssd.dll stops it
        self.assertIn("needs dnssd.dll to start", text)
        self.assertNotIn("MFCORE.dll to start", text)
        self.assertIn("status 53", text)
        self.assertNotIn("absent.dll", text)
        # when runtimes were asked for, one of them may bring it
        with mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, _out = self.convert(d, "--wine-runtime", "vcrun2022")
        self.assertEqual(code, 0, text)
        self.assertIn("may bring it", text)
        # with no installed base to look at, nothing is said
        code, text, _out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertNotIn("status 53", text)

    def test_dll_shipped_under_another_suffix_counts_as_shipped(self):
        # ARES Mechanical's DLLs import the Teigha modules it ships as ACCAMERA_26.8_17.tx; the scan
        # looked at .exe and .dll files only, and refused it for DLLs "neither the program nor Wine has"
        d = self.tmp / "ares"
        write(d / "BIN/aresm.exe", exe_bytes("ARES", imports={"kernel32.dll": ["ExitProcess"],
                                                              "DDKernel.dll": ["Start"]}))
        write(d / "BIN/DDKernel.dll", build_pe(PeSpec(is_dll=True, imports={"ACCAMERA_26.8_17.tx": ["Cam"],
                                                                             "kernel32.dll": ["ExitProcess"]})))
        write(d / "BIN/ACCAMERA_26.8_17.tx", build_pe(PeSpec(is_dll=True, imports={"dnssd.dll": ["DNSServiceBrowse"],
                                                                                    "ntdll.dll": ["NtClose"]})))
        # a data file that only happens to have the name stays a data file
        write(d / "BIN/notes.tx", b"plain text")
        base = {"kernel32.dll", "ntdll.dll"}
        with mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, _out = self.convert(d)
        self.assertEqual(code, 2, text)
        # the .tx module is the program's own; what it imports in turn is still looked at
        self.assertNotIn("needs ACCAMERA_26.8_17.tx", text)
        self.assertIn("ACCAMERA_26.8_17.tx needs dnssd.dll to start", text)
        (d / "BIN/ACCAMERA_26.8_17.tx").write_bytes(build_pe(PeSpec(is_dll=True, imports={"ntdll.dll": ["NtClose"]})))
        with mock.patch("debpak.winapp.wine_base_dlls", return_value=base):
            code, text, _out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertNotIn("status 53", text)

    def test_functions_wine_only_stubs_come_from_a_stand_in(self):
        # Media Remote's Flutter plugin for DNS-SD imports DnsServiceConstructInstance from DNSAPI.dll,
        # which Wine exports only as a stub: "unimplemented function DNSAPI.dll.DnsServiceConstructInstance,
        # aborting", and a crash box a second after it started
        from debpak.pe import read_pe
        d = self.tmp / "mediaremote"
        write(d / "mdremote.exe", exe_bytes("Media Remote", imports={"kernel32.dll": ["ExitProcess"],
                                                                     "bonsoir_windows_plugin.dll": ["Register"]}))
        write(d / "bonsoir_windows_plugin.dll", build_pe(PeSpec(is_dll=True, exports=["Register"], imports={
            "DNSAPI.dll": ["DnsServiceConstructInstance", "DnsServiceRegister", "DnsQuery_W"],
            "kernel32.dll": ["ExitProcess"]})))
        # a module that imports only what Wine has is left alone
        write(d / "connectivity_plus_plugin.dll", build_pe(PeSpec(is_dll=True, imports={"DNSAPI.dll": ["DnsQuery_W"]})))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("bonsoir_windows_plugin.dll imports DnsServiceConstructInstance, DnsServiceRegister from "
                      "DNSAPI.dll, for DNS service discovery (mDNS)", text)
        (slug,) = (out / "app/opt").iterdir()
        imports = {(i.dll, i.name) for i in read_pe(slug / "bonsoir_windows_plugin.dll").imports}
        self.assertIn(("DNSAP_.dll", "DnsServiceConstructInstance"), imports)
        self.assertIn(("DNSAP_.dll", "DnsQuery_W"), imports)
        self.assertFalse(any(dll == "DNSAPI.dll" for dll, _n in imports))
        # the unpacked copy is untouched
        self.assertIn("DNSAPI.dll", {i.dll for i in read_pe(d / "bonsoir_windows_plugin.dll").imports})
        standin = read_pe(slug / "DNSAP_.dll")
        self.assertEqual(standin.forwarders.get("DnsQuery_W"), "DNSAPI.DnsQuery_W")
        self.assertIn("DnsServiceConstructInstance", standin.exports)
        self.assertNotIn("DnsQuery_W", set(standin.exports) - set(standin.forwarders))
        data = (slug / "DNSAP_.dll").read_bytes()
        # NULL from the constructor, ERROR_NOT_SUPPORTED from the rest
        self.assertIn(b"\xb8\x00\x00\x00\x00\xc3", data)
        self.assertIn(b"\xb8\x32\x00\x00\x00\xc3", data)
        self.assertIn("DNSAPI.dll", {i.dll for i in read_pe(slug / "connectivity_plus_plugin.dll").imports})

    def test_dll_windows_split_out_of_another_passes_its_functions_on(self):
        # QField's qfield.exe imports MFCORE.dll, which Windows 10 split out of mf.dll, and Wine has its
        # functions in mf.dll alone: it was refused, status 53
        from debpak.pe import read_pe
        d = self.tmp / "qfield"
        names = ["MFCreateMediaSession", "MFCreateTopology"]
        write(d / "bin/qfield.exe", exe_bytes("QField", imports={"kernel32.dll": ["ExitProcess"], "MFCORE.dll": names}))
        with mock.patch("debpak.winapp.wine_base_dlls", return_value={"kernel32.dll", "mf.dll"}):
            code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("imports MFCORE.dll, Media Foundation's core, which Windows 10 split out of mf.dll", text)
        (slug,) = (out / "app/opt").iterdir()
        data = (slug / "bin/MFCORE.dll").read_bytes()
        self.assertEqual(set(read_pe(slug / "bin/MFCORE.dll").exports), set(names))
        for n in names:
            self.assertIn(f"mf.{n}\0".encode(), data)
        # a Wine without mf.dll has nowhere to pass them on to
        with mock.patch("debpak.winapp.wine_base_dlls", return_value={"kernel32.dll"}):
            code, text, out = self.convert(d)
        self.assertEqual(code, 2, text)
        self.assertIn("needs MFCORE.dll to start", text)

    def test_program_that_imports_windows_icu_gets_icu(self):
        # Premiere Companion's PyQt6 holds Qt6Core.dll, which imports icuuc.dll and icuin.dll, Windows' own
        # ICU; Python loads it, so nothing the program imports leads there
        from debpak import icunames
        from debpak.pe import read_pe
        d = self.tmp / "pc"
        write(d / "Premiere Companion.exe", exe_bytes("Premiere Companion"))
        write(d / "Lib/PyQt6/Qt6/bin/Qt6Core.dll", build_pe(PeSpec(is_dll=True, imports={
            "icuuc.dll": ["u_strToLower", "ucnv_open", "u_gone_from_icu78"], "icuin.dll": ["ucol_open"],
            "kernel32.dll": ["ExitProcess"]})))
        with mock.patch("debpak.winapp.wine_base_dlls", return_value={"kernel32.dll"}):
            code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("imports icuin.dll, icuuc.dll, Windows' own ICU, which Wine doesn't have", text)
        (slug,) = (out / "app/opt").iterdir()
        uc = read_pe(slug / "icuuc.dll")
        self.assertEqual(uc.forwarders, {"u_strToLower": "icuuc78.u_strToLower_78", "ucnv_open": "icuuc78.ucnv_open_78"})
        self.assertIn("u_gone_from_icu78", uc.exports)          # a stub
        self.assertEqual(read_pe(slug / "icuin.dll").forwarders, {"ucol_open": "icuin78.ucol_open_78"})
        manifest = json.loads(next(p for p in out.glob("*.json") if p.name != "report.json").read_text())
        (module,) = manifest["modules"]
        self.assertIn({"type": "archive", "url": icunames.URL, "sha256": icunames.SHA256, "strip-components": 0,
                       "dest": "icu"}, module["sources"])
        self.assertIn(f"cp -n icu/bin64/icuuc78.dll icu/bin64/icuin78.dll icu/bin64/icudt78.dll "
                      f"${{FLATPAK_DEST}}/opt/{slug.name}/.", module["build-commands"])
        # one that ships ICU under Windows' names needs nothing
        write(d / "icuuc.dll", build_pe(PeSpec(is_dll=True, exports=["u_strToLower"])))
        write(d / "icuin.dll", build_pe(PeSpec(is_dll=True, exports=["ucol_open"])))
        code, text, out = self.convert(d)
        self.assertNotIn("Windows' own ICU", text)

    def test_qt_quick_program_draws_with_opengl(self):
        # OmaWrite, a Qt 6 Quick editor, crashed as it started inside Wine's own DLLs, setting up Direct3D 11
        d = self.tmp / "oma"
        write(d / "omawrite.exe", exe_bytes("OmaWrite"))
        write(d / "Qt6Quick.dll", build_pe(PeSpec(is_dll=True)))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("draws with Qt 6's Qt Quick (Qt6Quick.dll)", text)
        launcher = next((out / "app/bin").iterdir()).read_text()
        self.assertIn('export QSG_RHI_BACKEND="${QSG_RHI_BACKEND:-opengl}"', launcher)
        (d / "Qt6Quick.dll").unlink()
        write(d / "Qt6Widgets.dll", build_pe(PeSpec(is_dll=True)))
        code, text, out = self.convert(d)
        self.assertNotIn("QSG_RHI_BACKEND", next((out / "app/bin").iterdir()).read_text())

    def test_winui3_program_gets_a_note(self):
        # Scanner Decoder App and JavaScript Obfuscator, WinUI 3 programs, ended before any window under Wine
        d = self.tmp / "scan"
        write(d / "Scanner_Decoder_App.exe", exe_bytes("Scanner Decoder App"))
        write(d / "Microsoft.UI.Xaml.dll", build_pe(PeSpec(is_dll=True)))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("is a WinUI 3 app (it ships Microsoft.UI.Xaml.dll", text)
        (d / "Microsoft.UI.Xaml.dll").unlink()
        code, text, out = self.convert(d)
        self.assertNotIn("WinUI 3", text)

    def test_gpui_program_is_kept_off_direct_composition(self):
        # Sonora, a GPUI music player, panicked with "Creating DirectX resources ... Not implemented.
        # (0x80004001)": Wine's dxgi has no swap chain for DirectComposition. GPUI's switch turns it off
        d = self.tmp / "sonora"
        write(d / "sonora.exe", exe_bytes("Sonora") + b"\0GPUI_DISABLE_DIRECT_COMPOSITIONtrue1\0")
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("sonora.exe draws through DirectComposition unless GPUI_DISABLE_DIRECT_COMPOSITION is set", text)
        launcher = next((out / "app/bin").iterdir())
        self.assertIn('export GPUI_DISABLE_DIRECT_COMPOSITION="${GPUI_DISABLE_DIRECT_COMPOSITION:-1}"',
                      launcher.read_text())
        subprocess.run(["sh", "-n", str(launcher)], check=True)
        write(d / "sonora.exe", exe_bytes("Sonora") + b"\0DCompositionCreateDevice\0")
        code, text, out = self.convert(d)
        self.assertNotIn("DIRECT_COMPOSITION", next((out / "app/bin").iterdir()).read_text())

    def test_program_that_reads_the_windows_machine_id_gets_one(self):
        # Media Remote, a Flutter app, reads HKLM\SOFTWARE\Microsoft\SQMClient's MachineId (device_info_plus)
        # and stopped at "WindowsException HRESULT(0x80070002): File not found": Wine's prefix has no such key
        d = self.tmp / "mr"
        write(d / "mdremote.exe", exe_bytes("Media Remote"))
        write(d / "flutter_windows.dll", build_pe(PeSpec(is_dll=True)))
        write(d / "data/app.so", b"\x7fELF" + bytes(64) + b"SOFTWARE\\Microsoft\\SQMClient\0MachineId\0")
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("app.so reads the machine ID Windows keeps in HKLM\\SOFTWARE\\Microsoft\\SQMClient", text)
        launcher = next((out / "app/bin").iterdir())
        body = launcher.read_text()
        self.assertIn("wine reg add 'HKLM\\SOFTWARE\\Microsoft\\SQMClient' /v MachineId /t REG_SZ", body)
        self.assertIn("/reg:32", body)
        subprocess.run(["sh", "-n", str(launcher)], check=True)
        # a C# or C++ program names it in UTF-16, however it spells "Software"
        (d / "data/app.so").unlink()
        code, text, out = self.convert(d)
        self.assertNotIn("SQMClient", next((out / "app/bin").iterdir()).read_text())
        write(d / "telemetry.dll", build_pe(PeSpec(is_dll=True)) + "Software\\Microsoft\\SQMClient".encode("utf-16-le"))
        code, text, out = self.convert(d)
        self.assertIn("telemetry.dll reads the machine ID", text)

    def test_64_bit_mfc_toolbars_get_a_note(self):
        # Wine blanked the labels of 64-bit WinMerge's menu bar, an MFC CToolBar; its 32-bit build is fine
        d = self.tmp / "mfc"
        write(d / "WinMergeU.exe", exe_bytes("WinMerge", extra="AfxControlBar140su".encode("utf-16-le")))
        code, text, _out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("64-bit MFC program with toolbars", text)
        write(d / "WinMergeU.exe", exe_bytes("WinMerge", arch="i386", extra=b"AfxControlBar140s"))
        code, text, _out = self.convert(d)
        self.assertNotIn("MFC program", text)
        write(d / "WinMergeU.exe", exe_bytes("WinMerge"))
        code, text, _out = self.convert(d)
        self.assertNotIn("MFC program", text)

    def test_symbol_font_gets_a_stand_in(self):
        # WinDirStat draws its toolbar icons as Segoe UI Symbol characters through GDI+, which draws
        # nothing with a family Wine doesn't have: the icons came out as flat grey squares
        d = self.tmp / "wds"
        write(d / "x64/WinDirStat.exe", exe_bytes("WinDirStat", extra="Segoe UI Symbol".encode("utf-16-le")))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("draws with the Segoe UI Symbol font", text)
        (launcher,) = (out / "app/bin").iterdir()
        script = launcher.read_text()
        self.assertIn("Fonts\\Replacements' /v 'Segoe UI Symbol' /t REG_SZ /d 'DejaVu Sans'", script)
        self.assertIn("SystemLink' /v 'DejaVu Sans Bold' /t REG_MULTI_SZ", script)
        write(d / "x64/WinDirStat.exe", exe_bytes("WinDirStat"))
        code, text, out = self.convert(d)
        self.assertNotIn("Segoe UI Symbol", text)
        (launcher,) = (out / "app/bin").iterdir()
        self.assertNotIn("Segoe UI Symbol", launcher.read_text())

    def test_symbol_font_launcher_sets_it_once(self):
        from debpak.packages import Package
        from debpak.winapp import launcher
        prog = self.tmp / "prog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "wbin"
        write(bin_ / "wineboot", '#!/bin/sh\n', 0o755)
        # printf, since dash's echo would turn the \0 separators into NULs
        write(bin_ / "wine", '#!/bin/sh\nprintf "wine %s\\n" "$*" >> "$WLOG"\nexit "${REG_RC:-0}"\n', 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        script = write(self.tmp / "launch.sh", launcher(pkg, "acme", "app.exe", False, "s", symbol_fonts=["Segoe UI Symbol"])
                       .replace("/app/opt/acme", str(prog)), 0o755)
        log = self.tmp / "wlog"
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "xdg"), "WLOG": str(log)}

        def regs():
            return [line for line in log.read_text().splitlines() if line.startswith("wine reg add")]
        subprocess.run([str(script)], env={**env, "REG_RC": "1"}, capture_output=True)
        self.assertEqual(len(regs()), 1)                            # stops at the first failure
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        self.assertEqual(len(regs()), 4)                            # retried once, then remembered
        self.assertIn("/d DejaVuSansMono.ttf,DejaVu Sans Mono\\0FreeSerif.ttf,FreeSerif\\0DejaVuSerif.ttf,DejaVu Serif",
                      regs()[-1])

    def test_folder_indexer_gets_its_folders(self):
        """Everything can't read an NTFS file table under Wine: the launcher writes Everything.ini with
        the folders the sandbox grants, once, quoting backslashes and quotes as the file wants."""
        from debpak.winapp import launcher
        from debpak.packages import Package
        d = self.tmp / "ev"
        write(d / "Everything.exe", exe_bytes("Everything"))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("indexes NTFS volumes", text)
        (script_text,) = [p.read_text() for p in (out / "app/bin").iterdir()]
        self.assertIn("Program Files", script_text)                  # runs from a copy it can write to

        prog = self.tmp / "prog-ev"
        write(prog / "everything.exe", b"x")
        bin_ = self.tmp / "evbin"
        write(bin_ / "wineboot", '#!/bin/sh\n', 0o755)
        write(bin_ / "wine", '#!/bin/sh\n', 0o755)
        write(bin_ / "xdg-user-dir", '#!/bin/sh\ncase "$1" in DOCUMENTS) echo "$H/Docs";; *) echo "$H/Down";; esac\n',
              0o755)
        write(bin_ / "winepath", '#!/bin/sh\nprintf \'Z:%s\\n\' "$2" | tr / \'\\\\\'\n', 0o755)
        home = self.tmp / 'h"ome'
        (home / "Docs").mkdir(parents=True)
        (home / "Down").mkdir()
        pkg = Package("wine", prog, prog, "everything", "1", extra={"display_name": "Everything"})
        script = write(self.tmp / "ev.sh", launcher(pkg, "everything", "everything.exe", False, "s",
                                                    folder_index="Everything.ini")
                       .replace("/app/opt/everything", str(prog)), 0o755)
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "xdg"), "H": str(home)}
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        ini = (prog / "Everything.ini").read_bytes().decode()
        w = str(home).replace("/", "\\\\").replace('"', '\\"')
        self.assertEqual(ini, f'[Everything]\r\nfolders="Z:{w}\\\\Docs","Z:{w}\\\\Down"\r\n')
        (prog / "Everything.ini").write_text("folders=mine")       # what the user set stays
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        self.assertEqual((prog / "Everything.ini").read_text(), "folders=mine")

    def test_portable_program_runs_from_a_copy(self):
        """A settings file named like the .exe turns on --writable by itself (Notepad3.ini)."""
        from debpak.winapp import keeps_settings_beside
        d = self.tmp / "np3"
        write(d / "Notepad3.exe", exe_bytes("Notepad3"))
        self.assertIsNone(keeps_settings_beside(d / "Notepad3.exe"))
        write(d / "Notepad3.ini", "[Settings]\n")
        self.assertEqual(keeps_settings_beside(d / "Notepad3.exe"), "Notepad3.ini")
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("Notepad3.ini beside the program", text)
        (launcher,) = (out / "app/bin").iterdir()
        self.assertIn("Program Files", launcher.read_text())

    def test_writable_launcher_keeps_user_changes(self):
        """Run the generated launcher with stand-in wine tools: copy, update, keep edited files."""
        from debpak.winapp import launcher
        from debpak.packages import Package
        prog = self.tmp / "prog"
        write(prog / "app.exe", b"v1")
        write(prog / "settings.ini", b"default")
        (prog / "log").mkdir()          # vimacc's installer leaves it empty for the program's logs
        bin_ = self.tmp / "wbin"
        write(bin_ / "wine", '#!/bin/sh\necho "wine $*" >> "$WLOG"\n', 0o755)
        write(bin_ / "wineboot", '#!/bin/sh\necho "wineboot $*" >> "$WLOG"\nd="$WINEPREFIX/drive_c/windows/system32"\n'
              'mkdir -p "$d" && touch "$d/kernel32.dll"\n', 0o755)
        write(bin_ / "winepath", '#!/bin/sh\necho "Z:$2"\n', 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})

        def run(stamp, *args):
            script = write(self.tmp / "launch.sh", launcher(pkg, "acme", "app.exe", True, stamp)
                           .replace("/app/opt/acme", str(prog)), 0o755)
            env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "xdg"),
                   "WLOG": str(self.tmp / "wlog")}
            subprocess.run([str(script), *args], env=env, check=True, capture_output=True)

        dest = self.tmp / "xdg/wine/drive_c/Program Files/acme"
        run("1-a", str(self.tmp / "launch.sh"), "--flag")
        self.assertEqual((dest / "app.exe").read_bytes(), b"v1")
        self.assertTrue((dest / "log").is_dir())
        log = (self.tmp / "wlog").read_text()
        self.assertIn(f"wine {dest}/app.exe Z:{self.tmp}/launch.sh --flag", log)
        self.assertIn("wineboot --init", log)
        (dest / "settings.ini").write_bytes(b"user edited")
        (prog / "app.exe").write_bytes(b"v2")
        (prog / "settings.ini").write_bytes(b"new default")
        run("2-b")
        self.assertEqual((dest / "app.exe").read_bytes(), b"v2")
        self.assertEqual((dest / "settings.ini").read_bytes(), b"user edited")

    def test_launcher_sets_up_a_cut_short_prefix_again(self):
        """Intel's BCT: a check stopped wineboot before kernel32.dll, and every start after failed with c0000135."""
        from debpak.winapp import launcher
        from debpak.packages import Package
        prog = self.tmp / "prog"
        write(prog / "app.exe", b"x")
        bin_ = self.tmp / "wbin"
        for n in ("wine", "wineserver"):
            write(bin_ / n, f'#!/bin/sh\necho "{n} $*" >> "$WLOG"\n', 0o755)
        # the stand-in wineboot makes the prefix whole, as Wine's does
        write(bin_ / "wineboot", '#!/bin/sh\necho "wineboot $*" >> "$WLOG"\nd="$WINEPREFIX/drive_c/windows/system32"\n'
              'mkdir -p "$d" && touch "$d/kernel32.dll" "$WINEPREFIX/system.reg"\n', 0o755)
        pkg = Package("wine", prog, prog, "acme", "1", extra={"display_name": "Acme"})
        script = write(self.tmp / "launch.sh", launcher(pkg, "acme", "app.exe", False, "s")
                       .replace("/app/opt/acme", str(prog)), 0o755)
        log = self.tmp / "wlog"

        def run(prefix=None):
            env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "xdg"), "WLOG": str(log)}
            if prefix:
                env["WINEPREFIX"] = str(prefix)
            log.unlink(missing_ok=True)
            r = subprocess.run([str(script)], env=env, check=True, capture_output=True, text=True)
            return log.read_text(), r.stderr

        p = self.tmp / "xdg/wine"
        # what the check left: Wine's timestamp, the registry, part of system32, and no kernel32.dll
        for f in (".update-timestamp", "system.reg", "drive_c/windows/system32/ntdll.dll"):
            write(p / f, b"x")
        calls, err = run()
        self.assertIn("setting it up again", err)
        self.assertIn("wineboot --init", calls)
        self.assertFalse((p / ".update-timestamp").exists())
        self.assertTrue((p / "drive_c/windows/system32/kernel32.dll").exists())
        self.assertTrue((p / ".debpak-prefix").exists())
        self.assertFalse((p / ".debpak-installing").exists())
        # a whole prefix is left as it is, and not set up again
        write(p / "drive_c/users/me/save.dat", b"mine")
        calls, err = run()
        self.assertNotIn("wineboot", calls)
        self.assertEqual((p / "drive_c/users/me/save.dat").read_bytes(), b"mine")
        # Racemo: cut short after kernel32.dll, with Wine's timestamp but not what wine.inf registers;
        # wineboot --init, finding the timestamp current, would have left it so
        (p / ".debpak-prefix").unlink()
        write(p / "system.reg", b"WINE REGISTRY Version 2\n")
        calls, err = run()
        self.assertIn("setting it up again", err)
        self.assertIn("wineboot --init", calls)
        self.assertFalse((p / "drive_c/users/me/save.dat").exists())
        # one set up whole before the launcher marked it so has wine.inf's services, and is kept
        (p / ".debpak-prefix").unlink()
        write(p / "system.reg", b"[System\\\\ControlSet001\\\\Services\\\\RpcSs] 1795754926\n")
        write(p / "drive_c/users/me/save.dat", b"mine")
        calls, err = run()
        self.assertNotIn("wineboot", calls)
        self.assertTrue((p / ".debpak-prefix").exists())
        self.assertEqual((p / "drive_c/users/me/save.dat").read_bytes(), b"mine")
        # its registry never saved: the timestamp goes, so wineboot sets it up rather than skip it
        (p / "system.reg").unlink()
        write(p / ".update-timestamp", b"0")
        calls, err = run()
        self.assertNotIn("setting it up again", err)
        self.assertIn("wineboot --init", calls)
        self.assertFalse((p / ".update-timestamp").exists())
        self.assertEqual((p / "drive_c/users/me/save.dat").read_bytes(), b"mine")
        # a prefix the user names is never removed, whole or not
        theirs = self.tmp / "theirs"
        write(theirs / ".update-timestamp", b"x")
        write(theirs / "drive_c/notes.txt", b"keep")
        run(theirs)
        self.assertEqual((theirs / "drive_c/notes.txt").read_bytes(), b"keep")


    def test_console_program_gets_a_console_window(self):
        """Far Manager is a console program; started from the menu, Wine gave it no window."""
        d = self.tmp / "far"
        write(d / "Far Manager/Far.exe", exe_bytes("Far Manager", subsystem=3))
        code, text, out = self.convert(d)
        self.assertEqual(code, 0, text)
        self.assertIn("Far.exe is a console program", text)
        (script,) = (out / "app/bin").iterdir()
        prog = self.tmp / "farprog"
        write(prog / "Far Manager/Far.exe", b"MZ")
        bin_ = self.tmp / "fbin"
        for n in ("wine", "wineconsole", "wineboot"):
            write(bin_ / n, f'#!/bin/sh\necho "{n} $*" >> "$WLOG"\n', 0o755)
        text = script.read_text()
        script = write(self.tmp / "far.sh", re.sub(r"PROGRAM=/app/opt/\S+", f"PROGRAM={prog}", text), 0o755)
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "XDG_DATA_HOME": str(self.tmp / "xdg"), "WLOG": str(self.tmp / "flog")}
        write(bin_ / "wineserver", '#!/bin/sh\necho "wineserver $*" >> "$WLOG"\n', 0o755)
        # no terminal (the menu, the check after a build): Wine's console window
        subprocess.run([str(script)], env=env, check=True, capture_output=True, stdin=subprocess.DEVNULL)
        self.assertIn(f"wineconsole {prog}/Far Manager/Far.exe\nwineserver -w", (self.tmp / "flog").read_text())
        # the launcher waits for what the program left running in the prefix, and keeps its exit status
        write(bin_ / "wineconsole", '#!/bin/sh\necho "wineconsole $*" >> "$WLOG"\nexit 53\n', 0o755)
        r = subprocess.run([str(script)], env=env, capture_output=True, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 53)
        self.assertTrue((self.tmp / "flog").read_text().endswith("wineserver -w\n"))
        # debpak's check asks for it outside the console window, to read what it prints (fio, TrId2Console)
        subprocess.run([str(script)], env={**env, "DEBPAK_WINECONSOLE": "0"}, capture_output=True,
                       stdin=subprocess.DEVNULL)
        self.assertTrue((self.tmp / "flog").read_text().endswith(f"wine {prog}/Far Manager/Far.exe\nwineserver -w\n"))
        manifest = next(m for m in out.glob("*.json") if "modules" in json.loads(m.read_text()))
        self.assertTrue(json.loads(manifest.read_text())["x-debpak"]["console"])
        # a GUI program is started with wine as before
        write(d / "Far Manager/Far.exe", exe_bytes("Far Manager"))
        code, text, out = self.convert(d)
        (script,) = (out / "app/bin").iterdir()
        self.assertNotIn("wineconsole", script.read_text())

# --------------------------------------------------------------------------- .run installers

def makeself(dest: Path, payload_dir: Path, *, old_style=False, compress=True, script="./setup.sh",
             encrypt=False) -> Path:
    payload = tar_bytes(payload_dir)
    if compress:
        payload = gzip.compress(payload)
    head = ["#!/bin/sh", "# This script was generated using Makeself 2.5.0", 'label="Acme Game 1.0"',
            f'script="{script}"', f'filesizes="{len(payload)}"']
    if encrypt:
        head.append('ENCRYPT="gpg"')
    if old_style:
        head.append('offset=`head -n NN "$1" | wc -c | tr -d " "`')
    else:
        head.append('skip="NN"')
    head += ["echo extracting", "exit 0"]
    n = len(head)
    text = "\n".join(head).replace("NN", str(n)) + "\n"
    dest.write_bytes(text.encode() + payload)
    return dest


class RunTests(Base):
    def payload(self) -> Path:
        d = self.tmp / "payload"
        write(d / "acmegame", ELF[:4] + b"\x02\x01\x01" + bytes(9) + struct.pack("<H", 2) +
              struct.pack("<H", 0x3E) + bytes(40), 0o755)
        write(d / "setup.sh", "#!/bin/sh\nsystemctl enable acme.service\ncp acme.rules /etc/udev/rules.d/\n", 0o755)
        write(d / "data/level1.dat", b"x")
        return d

    def test_makeself(self):
        for old in (False, True):
            with self.subTest(old_style=old):
                run = makeself(self.tmp / "AcmeGame-1.0.run", self.payload(), old_style=old)
                self.assertEqual(detect_format(run), "run")
                dest = self.tmp / f"x{old}"
                pkg = extract_run(run, dest)
                self.assertEqual((pkg.format, pkg.name, pkg.version), ("run", "acmegame", "1.0"))
                self.assertTrue((pkg.root / "opt/acmegame/data/level1.dat").is_file())
                self.assertIn("systemctl enable", pkg.scripts["postinst"])
                self.assertEqual(pkg.default_exec, "/opt/acmegame/acmegame")
                self.assertIn("setup script (./setup.sh)", pkg.notes[0])

    def test_uncompressed_and_encrypted(self):
        run = makeself(self.tmp / "a.run", self.payload(), compress=False)
        self.assertTrue((extract_run(run, self.tmp / "d").root / "opt").is_dir())
        enc = makeself(self.tmp / "b.run", self.payload(), encrypt=True)
        with self.assertRaisesRegex(PackageError, "encrypted"):
            extract_run(enc, self.tmp / "e")
        with self.assertRaisesRegex(PackageError, "Makeself"):
            extract_run(write(self.tmp / "c.run", "#!/bin/sh\necho hi\n"), self.tmp / "f")

    def test_gog(self):
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("data/noarch/gameinfo", "Acme Quest\n1.2.3\n")
            zf.writestr("data/noarch/start.sh", "#!/bin/bash\ncd game && ./AcmeQuest\n")
            zf.writestr("data/noarch/game/AcmeQuest", ELF)
            zf.writestr("data/noarch/game/assets/a.pak", "x")
        run = write(self.tmp / "acme_quest_1_2_3.sh",
                    b"#!/bin/sh\n# This script was generated using Makeself 2.4.0\n# MojoSetup\nexit 0\n" + z.getvalue())
        self.assertEqual(detect_format(run), "run")
        pkg = open_package(run, self.tmp / "g")
        self.assertEqual((pkg.name, pkg.version), ("acme-quest", "1.2.3"))
        self.assertTrue((pkg.root / "opt/acme-quest/assets/a.pak").is_file())
        self.assertIn("GOG game installer", pkg.notes[0])

    def test_extra_data_refused_for_zstd(self):
        from debpak.packages import _archive_package  # noqa: F401  (layout helper exists)
        pkg = extract_run(makeself(self.tmp / "a.run", self.payload()), self.tmp / "d")
        self.assertIn("replay", pkg.extra)
        pkg.extra.pop("replay")
        from debpak.stage import apply_extra_script
        with self.assertRaisesRegex(ValueError, "zstd"):
            apply_extra_script(mock.Mock(pkg=pkg), "a.run")


# --------------------------------------------------------------------------- extra-data

def tree(root: Path) -> dict:
    """Relative path -> SHA-256 of every regular file under root."""
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


class ExtraDataTests(Base):
    """Bundle mode copies the unpacked files; extra-data mode replays the unpacking at install time.
    Each test checks that the replay gives exactly the files bundle mode copied."""

    def both(self, src: Path, *extra) -> tuple[Path, Path, dict]:
        """Convert src both ways; return (bundle output, extra-data output, unpack plan)."""
        b, e = self.tmp / "bundle", self.tmp / "extra-out"
        for out, mode in ((b, []), (e, ["--mode", "extra-data", "--url", "https://vendor.example/file"])):
            shutil.rmtree(out, ignore_errors=True)
            code, text = run_cli("convert", str(src), "-o", str(out), "--no-build", "--no-flathub-check",
                                 "--app-id", "org.example.App", *extra, *mode)
            self.assertEqual(code, 0, text)
        return b, e, json.loads((e / "app/share/debpak/unpack.json").read_text())

    def replay(self, src: Path, out: Path) -> Path:
        """Do what apply_extra does: run the shipped helper in a fake /app/extra holding the download."""
        plan = json.loads((out / "app/share/debpak/unpack.json").read_text())
        cwd = self.tmp / "app-extra"
        shutil.rmtree(cwd, ignore_errors=True)
        cwd.mkdir()
        shutil.copy2(src, cwd / plan["source"])
        for n in plan.get("natives", []):
            n["from"] = str(out / "app" / n["from"].removeprefix("/app/"))
        (self.tmp / "plan.json").write_text(json.dumps(plan))
        r = subprocess.run([sys.executable, str(out / "app/bin/debpak-unpack"), str(self.tmp / "plan.json")],
                           cwd=cwd, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((cwd / plan["source"]).exists())
        self.assertFalse((cwd / ".debpak-unpack").exists())
        return cwd / plan["target"]

    def manifest_of(self, out: Path) -> dict:
        return json.loads((out / "org.example.App.json").read_text())

    def test_electron_nsis_with_native_module(self):
        inner = electron_win_folder(self.tmp / "inner", {"node_modules/k/k.node": dll_bytes()})
        payload = self.tmp / "payload"
        write(payload / "$PLUGINSDIR/app-64.7z", b"7z" + STUBTAR + tar_bytes(inner))
        setup = write(self.tmp / "Acme Setup.exe", exe_bytes(extra=b"NullsoftInst" + STUBTAR + tar_bytes(payload)))
        nd = self.tmp / "nd"
        write(nd / "k.node", ELF)
        b, e, plan = self.both(setup, "--native-dir", str(nd))
        self.assertEqual(tree(self.replay(setup, e)), tree(b / "app/resources"))
        self.assertEqual(plan["natives"][0]["asar_unpack"], "node_modules/k/k.node")
        m = self.manifest_of(e)
        self.assertEqual([x["name"] for x in m["modules"]], ["7zip", "electron", "acme-notes"])
        self.assertNotIn("CFLAGS_WARN_WALL", m["modules"][0]["build-commands"][0])
        last = m["modules"][-1]
        self.assertIn("ln -s /app/extra/resources ${FLATPAK_DEST}/lib/acme-notes/resources", last["build-commands"])
        xd = last["sources"][1]
        self.assertEqual((xd["type"], xd["url"], xd["size"], xd["sha256"]),
                         ("extra-data", "https://vendor.example/file", setup.stat().st_size,
                          hashlib.sha256(setup.read_bytes()).hexdigest()))
        self.assertFalse((e / "app/resources").exists())
        self.assertEqual((e / "app/bin/apply_extra").read_text().splitlines()[-1],
                         "python3 /app/bin/debpak-unpack /app/share/debpak/unpack.json")

    def test_electron_stand_ins_replayed(self):
        main = b"require('electron').app.setJumpList([]);\n"
        inner = electron_win_folder(self.tmp / "inner", {"main.js": main})
        payload = self.tmp / "payload"
        write(payload / "$PLUGINSDIR/app-64.7z", b"7z" + STUBTAR + tar_bytes(inner))
        setup = write(self.tmp / "Acme Setup.exe", exe_bytes(extra=b"NullsoftInst" + STUBTAR + tar_bytes(payload)))
        b, e, plan = self.both(setup)
        self.assertIn("app.setJumpList", plan["main_shim"])
        self.assertEqual(tree(self.replay(setup, e)), tree(b / "app/resources"))
        self.assertEqual(json.loads((b / "app/resources/app.asar.unpacked/package.json").read_text())["main"],
                         "debpak-shim.js")

    def test_mac_zip_and_dmg(self):
        app = electron_mac_app(self.tmp / "m")
        z = zip_tree(app, self.tmp / "Acme.zip")
        b, e, plan = self.both(z)
        self.assertEqual(tree(self.replay(z, e)), tree(b / "app/resources"))
        self.assertEqual(plan["steps"], [{"kind": "zip"}])
        self.assertEqual(plan["take"], "Acme Notes.app/Contents/Resources")
        self.assertEqual([x["name"] for x in self.manifest_of(e)["modules"]], ["electron", "acme-notes"])
        dmg_src = self.tmp / "dmg-src"
        shutil.copytree(app, dmg_src / "Acme Notes.app")
        image = write(self.tmp / "Acme.dmg", b"x" + STUBTAR + tar_bytes(dmg_src))
        b, e, plan = self.both(image, "--runtime", "org.freedesktop.Platform//26.08")
        self.assertEqual(tree(self.replay(image, e)), tree(b / "app/resources"))
        self.assertIn('CFLAGS_WARN_WALL="-Wall -Wextra"', self.manifest_of(e)["modules"][0]["build-commands"][0])

    def test_squirrel(self):
        inner = electron_win_folder(self.tmp / "inner")
        nupkg = io.BytesIO()
        with zipfile.ZipFile(nupkg, "w") as z:
            z.writestr("acme.nuspec", "<package><metadata><id>acme</id><version>2.3.1</version></metadata></package>")
            for p in sorted(inner.rglob("*")):
                if p.is_file():
                    z.write(p, "lib/net45/" + p.relative_to(inner).as_posix())
        setup = write(self.tmp / "Setup.exe", build_pe(PeSpec(is_dll=False, imports={"kernel32.dll": ["ExitProcess"]},
                                                                resources=[(10, 131, nupkg.getvalue())])) + bytes(70000))
        b, e, plan = self.both(setup)
        self.assertEqual(plan["steps"], [{"kind": "squirrel"}])
        self.assertEqual(tree(self.replay(setup, e)), tree(b / "app/resources"))

    def test_wine_portable_msix_and_plain_nsis(self):
        exe = write(self.tmp / "Tool.exe", exe_bytes("Tool"))
        b, e, plan = self.both(exe)
        self.assertEqual(tree(self.replay(exe, e)), tree(b / "app/opt/tool"))
        m = self.manifest_of(e)["modules"][0]
        self.assertIn("install -d ${FLATPAK_DEST}/opt && ln -s /app/extra/program ${FLATPAK_DEST}/opt/tool",
                      m["build-commands"])
        self.assertEqual(m["build-commands"][0], "cp -a bin share ${FLATPAK_DEST}/")
        self.assertFalse((e / "app/opt").exists())

        d = self.tmp / "msix"
        write(d / "AppxManifest.xml", '<Package><Identity Name="A" Version="1.0.0.0"/><Properties>'
                                      '<DisplayName>Acme Paint</DisplayName></Properties><Applications>'
                                      '<Application Executable="P\\paint.exe"/></Applications></Package>')
        write(d / "P/paint.exe", exe_bytes("Paint"))
        pkg = zip_tree(d, self.tmp / "Paint.msix")
        b, e, plan = self.both(pkg)
        self.assertEqual(tree(self.replay(pkg, e)), tree(b / "app/opt/acme-paint"))

        payload = self.tmp / "nsis"
        write(payload / "Viewer.exe", exe_bytes("Viewer"))
        write(payload / "$PLUGINSDIR/System.dll", dll_bytes())
        write(payload / "$TEMP/x.txt", "x")
        setup = write(self.tmp / "viewer-setup.exe", exe_bytes("Viewer Setup", description="Viewer Setup",
                                                               extra=b"Nullsoft Install System" + STUBTAR
                                                               + tar_bytes(payload)))
        b, e, plan = self.both(setup, "--exec", "Viewer.exe")
        self.assertEqual(plan["drop"], ["$PLUGINSDIR", "$TEMP"])
        (opt,) = (b / "app/opt").iterdir()
        self.assertEqual(sorted(tree(opt)), ["Viewer.exe"])
        self.assertEqual(tree(self.replay(setup, e)), tree(opt))

    def test_nsis_program_under_a_variable(self):
        # Wrye Bash's installer puts Mopy in each game it finds, a folder 7z names after the variable
        # that holds it ($_16_, $_17_, ...); nothing lies outside them
        payload = self.tmp / "wrye"
        for var in ("$_16_", "$_17_"):
            write(payload / var / "Mopy/Wrye Bash.exe", exe_bytes("Wrye Bash"))
            write(payload / var / "Mopy/bash/x.py", "x")
        write(payload / "$PLUGINSDIR/nsDialogs.dll", dll_bytes())
        write(payload / "$PLUGINSDIR/helper.exe", exe_bytes("Helper"))
        setup = write(self.tmp / "Wrye.Bash.315.-.Installer.exe",
                      exe_bytes("Wrye Bash", description="Wrye Bash Installer",
                                extra=b"Nullsoft Install System" + STUBTAR + tar_bytes(payload)))
        b, e, plan = self.both(setup)
        self.assertEqual((plan["take"], plan["drop"]), ("$_16_", []))
        (opt,) = (b / "app/opt").iterdir()
        self.assertEqual(sorted(tree(opt)), ["Mopy/Wrye Bash.exe", "Mopy/bash/x.py"])
        self.assertEqual(tree(self.replay(setup, e)), tree(opt))

    def test_cab_in_self_extracting_zip(self):
        setup = cab_installer(self.tmp)
        b, e, plan = self.both(setup)
        self.assertEqual(plan["steps"], [{"kind": "zip", "inner": "INSTALL.CAB"}, {"kind": "7z"}])
        (opt,) = (b / "app/opt").iterdir()
        self.assertIn("TOTALCMD64.EXE", tree(opt))
        self.assertEqual(tree(self.replay(setup, e)), tree(opt))

    def test_7zip_self_extractor(self):
        setup = sevenzip_sfx(self.tmp)
        b, e, plan = self.both(setup)
        self.assertEqual(len(plan["steps"]), 1)
        self.assertEqual(plan["steps"][0]["kind"], "7z")
        self.assertEqual(setup.read_bytes()[plan["steps"][0]["offset"]:][:6], b"7z\xbc\xaf\x27\x1c")
        (opt,) = (b / "app/opt").iterdir()
        self.assertIn("7zFM.exe", tree(opt))
        self.assertEqual(tree(self.replay(setup, e)), tree(opt))

    def test_url_with_spaces_is_encoded(self):
        # flatpak refuses an extra-data URL with a space ("URL using bad/illegal format")
        exe = write(self.tmp / "Acme Tool 1.0.exe", exe_bytes("Acme Tool"))
        out = self.tmp / "spaces"
        code, text = run_cli("convert", str(exe), "-o", str(out), "--no-build", "--no-flathub-check",
                             "--app-id", "org.example.App", "--mode", "extra-data",
                             "--url", "http://127.0.0.1:8000/Acme Tool 1.0.exe")
        self.assertEqual(code, 0, text)
        m = json.loads((out / "org.example.App.json").read_text())
        urls = [s["url"] for mod in m["modules"] if isinstance(mod, dict) for s in mod.get("sources", [])
                if isinstance(s, dict) and s.get("type") == "extra-data"]
        self.assertEqual(urls, ["http://127.0.0.1:8000/Acme%20Tool%201.0.exe"])

    def test_refused_inputs(self):
        folder = electron_win_folder(self.tmp / "w")
        code, text = run_cli("convert", str(folder), "-o", str(self.tmp / "o"), "--no-build", "--no-flathub-check",
                             "--mode", "extra-data", "--url", "https://x.example/y")
        self.assertEqual(code, 2)
        self.assertIn("a folder has nothing to download", text)
        payload = self.tmp / "inno"
        write(payload / "app/Acme.exe", exe_bytes("Acme"))
        setup = write(self.tmp / "acme-setup.exe", exe_bytes("Acme Setup", extra=b"Inno Setup Setup Data (6)"
                                                             + STUBTAR + tar_bytes(payload)))
        code, text = run_cli("convert", str(setup), "-o", str(self.tmp / "o"), "--no-build", "--no-flathub-check",
                             "--mode", "extra-data", "--url", "https://x.example/y")
        self.assertEqual(code, 2)
        self.assertIn("innoextract isn't available inside the Flatpak", text)
        code, text = run_cli("convert", str(setup), "-o", str(self.tmp / "o"), "--no-build", "--no-flathub-check",
                             "--mode", "extra-data")
        self.assertIn("requires --url", text)

    def test_run_installers(self):
        from debpak.runtime import index_root
        (self.tmp / "runtime/usr/lib").mkdir(parents=True)
        idx = self.tmp / "runtime.json"
        index_root(self.tmp / "runtime", "org.freedesktop.Platform/x86_64/25.08", "x86_64").save(idx)
        self.both = lambda src, *a: ExtraDataTests.both(self, src, "--runtime-index", str(idx), *a)
        payload = RunTests.payload(self)
        for src in (makeself(self.tmp / "AcmeGame-1.0.run", payload),):
            b, e, plan = self.both(src, "--force")
            self.assertEqual(plan["steps"][0]["kind"], "makeself")
            self.assertEqual(tree(self.replay(src, e)), tree(b / "app/opt/acmegame"))
            self.assertIn("python3 /app/bin/debpak-unpack", (e / "app/bin/apply_extra").read_text())
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("data/noarch/gameinfo", "Acme Quest\n1.2.3\n")
            zf.writestr("data/noarch/game/AcmeQuest", ELF)
            zf.writestr("data/noarch/game/assets/a.pak", "x")
        gog = write(self.tmp / "acme_quest.sh", b"#!/bin/sh\n# Makeself\nexit 0\n" + z.getvalue())
        b, e, plan = self.both(gog, "--exec", "/opt/acme-quest/AcmeQuest", "--force")
        self.assertEqual(tree(self.replay(gog, e)), tree(b / "app/opt/acme-quest"))


class UnpackHelperTests(Base):
    def test_errors(self):
        from debpak import unpack
        src = write(self.tmp / "a.zip", b"")
        with zipfile.ZipFile(src, "w") as z:
            z.writestr("x/y.txt", "y")
        cwd = self.tmp / "cwd"
        cwd.mkdir()
        shutil.copy2(src, cwd / "a.zip")
        for plan, msg in (({"steps": [{"kind": "nope"}], "target": "t"}, "unknown step"),
                          ({"steps": [{"kind": "zip"}], "take": "../..", "target": "t"}, "isn't in"),
                          ({"steps": [{"kind": "zip"}], "take": "x", "target": "../t"}, "outside"),
                          ({"steps": [{"kind": "7z"}], "target": "t"}, "7z isn't installed")):
            with self.subTest(msg=msg), mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
                with self.assertRaisesRegex(unpack.UnpackError, msg):
                    unpack.apply({"source": "a.zip", "remove_source": False, **plan}, cwd)
        r = subprocess.run([sys.executable, str(Path(unpack.__file__))], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_main_shim_for_es_modules_and_unpacked_apps(self):
        from debpak import unpack
        res = self.tmp / "res"
        write(res / "app/package.json", json.dumps({"name": "x", "type": "module", "main": "dist/main.js"}))
        unpack.install_main_shim(res, "globalThis.shimmed = 1;\n")
        pj = json.loads((res / "app/package.json").read_text())
        self.assertEqual(pj["main"], "debpak-shim.cjs")
        shim = (res / "app/debpak-shim.cjs").read_text()
        self.assertTrue(shim.startswith("globalThis.shimmed = 1;\n"))
        self.assertIn("import(require('url').pathToFileURL(require('path').join(__dirname, \"dist/main.js\")).href)",
                      shim)
        res2 = self.tmp / "res2"
        write_asar(res2 / "app.asar", {"package.json": b'{"name": "y"}', "index.js": b"1"})
        unpack.install_main_shim(res2, "// shim\n")
        a = Asar(res2 / "app.asar")
        self.assertEqual(json.loads(a.read("package.json")), {"name": "y", "main": "debpak-shim.js"})
        self.assertIn("join(__dirname, \"index.js\")", a.read("debpak-shim.js").decode())
        self.assertEqual(a.read("index.js"), b"1")
        with self.assertRaisesRegex(unpack.UnpackError, "package.json"):
            unpack.install_main_shim(self.tmp / "nothing", "")

    def test_helper_is_standalone(self):
        """The copy in the Flatpak runs without the debpak package around it."""
        from debpak import unpack
        text = Path(unpack.__file__).read_text()
        self.assertNotIn("from .", text)
        self.assertNotIn("import debpak", text)


if __name__ == "__main__":
    unittest.main()
