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
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile
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

MACHO = b"\xcf\xfa\xed\xfe" + bytes(60)
ELF = b"\x7fELF\x02\x01\x01" + bytes(57)
STUBTAR = b"\nSTUBTAR\n"
SUMS = {f"electron-v30.1.2-linux-{a}.zip": hashlib.sha256(a.encode()).hexdigest() for a in ("x64", "arm64")}


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
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
    tarfile.open(fileobj=io.BytesIO(data[i + 9:])).extractall(out)
elif zipfile.is_zipfile(src):
    zipfile.ZipFile(src).extractall(out)
else:
    sys.exit("stub: nothing to extract")
"""


class StubTools:
    def __init__(self, base: Path, names=("7z", "innoextract", "msiextract")):
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
        self.assertIn("exec zypak-wrapper /app/lib/acme-notes/electron", launcher)
        desktop = (app / "share/applications/org.example.AcmeNotes.desktop").read_text()
        self.assertIn("Name=Acme Notes", desktop)
        self.assertIn("StartupWMClass=Acme Notes", desktop)
        self.assertTrue((app / "share/icons/hicolor/64x64/apps/org.example.AcmeNotes.png").is_file())
        md = (app / "share/metainfo/org.example.AcmeNotes.metainfo.xml").read_text()
        self.assertIn("<project_license>MIT</project_license>", md)
        self.assertIn("https://acme.example", md)
        self.assertEqual(json.loads((out / "report.json").read_text())["route"], "electron")

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


# --------------------------------------------------------------------------- Wine

class WineTests(Base):
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
        self.assertIn('exec wine "$PROGRAM/AcmeTool.exe" "$@"', launcher)
        self.assertNotIn("drive_c", launcher)
        self.assertTrue((out / "app/opt/acme-tool/AcmeTool.exe").is_file())
        desktop = (out / "app/share/applications/org.example.AcmeTool.desktop").read_text()
        self.assertIn("StartupWMClass=acmetool.exe", desktop)
        self.assertIn("Exec=acme-tool %F", desktop)
        self.assertTrue((out / "app/share/icons/hicolor/64x64/apps/org.example.AcmeTool.png").is_file())

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
        self.assertIn('cd "$PROGRAM/tools"', launcher)
        self.assertIn("drive_c/Program Files/acme", launcher)
        code, text, _ = self.convert(setup, "--exec", "nope.exe")
        self.assertEqual(code, 2)

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

    def test_extra_data_refused(self):
        from debpak.stage import apply_extra_script
        pkg = extract_run(makeself(self.tmp / "a.run", self.payload()), self.tmp / "d")
        with self.assertRaisesRegex(ValueError, "bundle mode"):
            apply_extra_script(mock.Mock(pkg=pkg), "a.run")


if __name__ == "__main__":
    unittest.main()
