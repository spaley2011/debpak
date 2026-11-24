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
src = args[-1]
if "{name}" == "7z":
    out = next(a[2:] for a in args if a.startswith("-o"))
elif "{name}" == "innoextract":
    out = args[args.index("--output-dir") + 1]
else:
    out = args[args.index("-C") + 1]
data = open(src, "rb").read()
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


class StubTools:
    def __init__(self, base: Path, names=("7z", "innoextract", "msiextract", "bsdtar")):
        self.bin = base / "stub-bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.log = base / "stub.log"
        for n in names:
            write(self.bin / n, STUB.format(python=sys.executable, name=n), 0o755)
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

    def convert(self, src, *extra):
        out = self.tmp / "out"
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


# --------------------------------------------------------------------------- Electron

class ElectronTests(Base):
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

    def test_zip_with_backslash_paths(self):
        # Flow Launcher's portable zip names entries FlowLauncher\Update.exe and so on
        z = self.zip_of("Flow-Launcher-Portable.zip", {
            "FlowLauncher\\Update.exe": exe_bytes("Update"),
            "FlowLauncher\\Flow.Launcher.exe": exe_bytes("Flow Launcher"),
            "FlowLauncher\\app-2.1.4\\Flow.Launcher.exe": exe_bytes("Flow Launcher", extra=bytes(5000)),
            "FlowLauncher\\app-2.1.4\\Flow.Launcher.Core.dll": dll_bytes()})
        # the zip's single top folder is the program folder, and Update.exe (Squirrel's) is a helper
        self.assertEqual(self.main_program(z), "Flow.Launcher.exe")
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
        rc.unlink()
        write(d / "Framework.exe", exe_bytes("F", extra=b"PresentationFramework"))
        self.assertEqual(dotnet_needs(d / "Framework.exe", True)[:2], (["dotnet48"], True))
        self.assertEqual(dotnet_needs(d / "App.exe", True)[:2], ([], False))               # wine-mono is fine

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
        self.assertIn('exec wine "$PROGRAM"/AcmeTool.exe "$@"', launcher)
        self.assertNotIn("drive_c", launcher)
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
        self.assertTrue(any(c.startswith("bsdtar -x -C ") for c in self.stubs.calls()))
        self.assertIn("main executable WinRAR.exe", text)
        from debpak import unpack
        self.assertFalse(unpack.sfx_rar(write(self.tmp / "plain.exe", exe_bytes("Plain"))))

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
        exe = write(self.tmp / "Tool.exe", exe_bytes("Tool", imports={"kernel32.dll": ["ExitProcess"],
                                                                     "MSVCP140.dll": ["x"], "d3dx9_43.dll": ["y"]}))
        code, text, out = self.convert(exe)
        self.assertEqual(code, 0, text)
        self.assertIn("imports msvcp140.dll without shipping it: if the program won't start, convert with "
                      "--wine-runtime vcrun2022", text)
        self.assertIn("--wine-runtime d3dx9", text)
        write(self.tmp / "dir/Tool.exe", exe.read_bytes())
        write(self.tmp / "dir/msvcp140.dll", dll_bytes())
        code, text, out = self.convert(self.tmp / "dir")
        self.assertNotIn("vcrun2022", text)                 # shipped, so nothing to suggest

        code, text, out = self.convert(exe, "--wine-runtime", "vcrun2022", "--wine-runtime", "corefonts")
        self.assertEqual(code, 0, text)
        launcher = (out / "app/bin/tool").read_text()
        self.assertIn('RUNTIMES="vcrun2022 corefonts"', launcher)
        m = json.loads(next(p for p in out.glob("*.json") if p.name != "report.json").read_text())
        self.assertIn("--share=network", m["finish-args"])
        self.assertEqual(m["x-debpak"]["runtimes"], ["vcrun2022", "corefonts"])
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
        scripts = [launcher(pkg, "acme", main, w, "1.0-abc", rt)
                   for main in ("app.exe", "sub dir/My App.exe")
                   for w in (False, True) for rt in (None, ["vcrun2022", "corefonts"])]
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
        calls = [line for line in log.read_text().splitlines() if line.startswith("winetricks")]
        # failed once, then done; win10 undoes the Windows 7 that winetricks' .NET verbs leave set
        self.assertEqual(calls, ["winetricks -q --unattended vcrun2022 corefonts win10"] * 2)
        # a prefix whose runtimes went in before win10 was added gets it on the next start
        (self.tmp / "xdg/wine/.debpak-runtimes").write_text("vcrun2022 corefonts\n")
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        subprocess.run([str(script)], env=env, check=True, capture_output=True)
        calls = [line for line in log.read_text().splitlines() if line.startswith("winetricks")]
        self.assertEqual(len(calls), 3)
        # a Windows version the user asked for is left alone
        text = launcher(pkg, "acme", "app.exe", False, "s", ["dotnet40", "winxp"])
        self.assertIn('VERBS="$RUNTIMES"', text)
        self.assertIn('VERBS="$RUNTIMES win10"', launcher(pkg, "acme", "app.exe", False, "s", ["dotnet48"]))

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
        bin_ = self.tmp / "wbin"
        for n in ("wine", "wineboot"):
            write(bin_ / n, f'#!/bin/sh\necho "{n} $*" >> "$WLOG"\n', 0o755)
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
        log = (self.tmp / "wlog").read_text()
        self.assertIn(f"wine {dest}/app.exe Z:{self.tmp}/launch.sh --flag", log)
        self.assertIn("wineboot --init", log)
        (dest / "settings.ini").write_bytes(b"user edited")
        (prog / "app.exe").write_bytes(b"v2")
        (prog / "settings.ini").write_bytes(b"new default")
        run("2-b")
        self.assertEqual((dest / "app.exe").read_bytes(), b"v2")
        self.assertEqual((dest / "settings.ini").read_bytes(), b"user edited")


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

    def test_helper_is_standalone(self):
        """The copy in the Flatpak runs without the debpak package around it."""
        from debpak import unpack
        text = Path(unpack.__file__).read_text()
        self.assertNotIn("from .", text)
        self.assertNotIn("import debpak", text)


if __name__ == "__main__":
    unittest.main()
