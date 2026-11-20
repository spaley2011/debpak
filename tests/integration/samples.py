"""Sample apps for the integration run: small, real, and safe to build anywhere.

Every sample prints a marker when it runs, so run.py can tell it worked:

    hello            a C program for Linux ("hello from debpak")
    hello.deb        hello as a Debian package (built here, no dpkg-deb needed)
    hello.run        hello as a Makeself installer
    hello.exe        a C program for Windows ("hello from wine"), if mingw is
                     installed; otherwise debpak's stub .exe, which exits 1
    hello-win.zip    hello.exe in a zip (a portable program)
    hello-setup.exe  hello.exe in an NSIS installer (needs makensis)
    hello.msi        hello.exe in an MSI (needs wixl, from msitools)
    electron-win.zip     an Electron app as electron-builder's win-unpacked folder
    electron-setup.exe   the same app in an electron-builder-style NSIS installer
                         (needs makensis and 7z)
    electron-mac.zip     the same app as a zipped macOS .app

The Electron app prints "debpak-electron-ok VERSION" and quits.
"""
from __future__ import annotations

import gzip
import io
import json
import lzma
import plistlib
import shutil
import subprocess
import sys
import tarfile
import textwrap
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "src"))

from debpak.asar import write_asar  # noqa: E402
from debpak.pe_write import PeSpec, build_pe, version_info  # noqa: E402

HELLO_C = r'''
#include <stdio.h>
int main(int argc, char **argv) { printf("hello from %s\n", HELLO_FROM); return 0; }
'''
ELECTRON_MAIN = """
const { app } = require('electron');
app.whenReady().then(() => {
  console.log('debpak-electron-ok ' + process.versions.electron);
  app.quit();
});
"""


def _ar(members: list[tuple[str, bytes]]) -> bytes:
    out = bytearray(b"!<arch>\n")
    now = int(time.time())
    for name, data in members:
        out += f"{name + '/':<16}{now:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
        out += data + (b"\n" if len(data) % 2 else b"")
    return bytes(out)


def _tar(files: dict[str, tuple[bytes, int]], compress) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        dirs = set()
        for path in sorted(files):
            parts = path.split("/")
            for i in range(1, len(parts)):
                d = "/".join(parts[:i])
                if d not in dirs:
                    dirs.add(d)
                    info = tarfile.TarInfo("./" + d)
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    t.addfile(info)
            data, mode = files[path]
            info = tarfile.TarInfo("./" + path)
            info.size, info.mode = len(data), mode
            t.addfile(info, io.BytesIO(data))
    return compress(buf.getvalue())


def build_deb(out: Path, name: str, version: str, files: dict[str, tuple[bytes, int]], description: str) -> Path:
    """Write a minimal binary .deb (ar archive with control.tar.gz and data.tar.xz)."""
    control = textwrap.dedent(f"""\
        Package: {name}
        Version: {version}
        Architecture: amd64
        Maintainer: debpak tests <tests@debpak.invalid>
        Description: {description}
         Built by debpak's integration run.
        """).encode()
    out.write_bytes(_ar([("debian-binary", b"2.0\n"),
                         ("control.tar.gz", _tar({"control": (control, 0o644)}, gzip.compress)),
                         ("data.tar.xz", _tar(files, lzma.compress))]))
    return out


def build_makeself(out: Path, payload_dir: Path, label: str) -> Path:
    """Write a Makeself-style .run: a header with skip= and filesizes=, then a gzip tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        t.add(payload_dir, arcname=".")
    payload = buf.getvalue()
    head = ["#!/bin/sh", "# This script was generated using Makeself 2.5.0", f'label="{label}"',
            'script="./hello"', f'filesizes="{len(payload)}"', 'skip="NN"',
            'echo "this sample is only meant to be converted by debpak"', "exit 0"]
    text = "\n".join(head).replace("NN", str(len(head))) + "\n"
    out.write_bytes(text.encode() + payload)
    out.chmod(0o755)
    return out


def _zip_dir(src: Path, out: Path, prefix: str = "") -> Path:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                info = zipfile.ZipInfo(prefix + p.relative_to(src).as_posix(), time.localtime(p.stat().st_mtime)[:6])
                info.external_attr = (p.stat().st_mode & 0o777 | 0o100000) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, p.read_bytes())
    return out


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{r.stdout}\n{r.stderr}")


def build_all(out: Path, electron_version: str) -> dict:
    """Build every sample the installed tools allow into out; return {sample: details} (details['skip'] if not)."""
    out.mkdir(parents=True, exist_ok=True)
    made: dict = {}
    src = out / "src"
    src.mkdir(exist_ok=True)
    (src / "hello.c").write_text(HELLO_C)

    # Linux hello, .deb and .run
    if shutil.which("cc"):
        _run(["cc", "-O2", '-DHELLO_FROM="debpak"', "-o", str(src / "hello"), str(src / "hello.c")])
        hello = (src / "hello").read_bytes()
        build_deb(out / "hello_1.0.0_amd64.deb", "debpak-hello", "1.0.0",
                  {"usr/bin/debpak-hello": (hello, 0o755)}, "debpak integration sample")
        made["deb"] = {"file": "hello_1.0.0_amd64.deb", "expect": "hello from debpak"}
        payload = src / "run-payload"
        payload.mkdir(exist_ok=True)
        shutil.copy2(src / "hello", payload / "hello")
        build_makeself(out / "DebpakHello-1.0.0.run", payload, "Debpak Hello 1.0.0")
        made["run"] = {"file": "DebpakHello-1.0.0.run", "expect": "hello from debpak"}
    else:
        made["deb"] = made["run"] = {"skip": "no C compiler (cc)"}

    # Windows hello.exe
    mingw = shutil.which("x86_64-w64-mingw32-gcc")
    win = src / "win"
    win.mkdir(exist_ok=True)
    if mingw:
        _run([mingw, "-O2", '-DHELLO_FROM="wine"', "-o", str(win / "hello.exe"), str(src / "hello.c")])
        expect = {"expect": "hello from wine"}
    else:
        (win / "hello.exe").write_bytes(build_pe(PeSpec(is_dll=False, subsystem=3,
                                                        imports={"kernel32.dll": ["ExitProcess"]},
                                                        resources=[version_info({"ProductName": "Debpak Hello",
                                                                                 "ProductVersion": "1.0.0"})])))
        expect = {"expect_rc": 1, "note": "no mingw: stub .exe, checked by its exit status"}
    _zip_dir(win, out / "DebpakHello-1.0.0-win.zip", "DebpakHello/")
    shutil.copy2(win / "hello.exe", out / "DebpakHello.exe")
    made["exe"] = {"file": "DebpakHello.exe", **expect}
    made["exe-zip"] = {"file": "DebpakHello-1.0.0-win.zip", **expect}
    makensis = shutil.which("makensis")
    if makensis:
        (win / "hello.nsi").write_text(textwrap.dedent("""\
            Name "Debpak Hello"
            OutFile "hello-setup.exe"
            InstallDir "$PROGRAMFILES64\\DebpakHello"
            RequestExecutionLevel user
            Section
              SetOutPath "$INSTDIR"
              File "hello.exe"
            SectionEnd
            """))
        _run([makensis, "-V2", "hello.nsi"], cwd=win)
        shutil.move(str(win / "hello-setup.exe"), out / "DebpakHello-Setup-1.0.0.exe")
        made["exe-nsis"] = {"file": "DebpakHello-Setup-1.0.0.exe", **expect}
    else:
        made["exe-nsis"] = {"skip": "no makensis"}
    wixl = shutil.which("wixl")
    if wixl:
        (win / "hello.wxs").write_text(textwrap.dedent("""\
            <?xml version="1.0" encoding="utf-8"?>
            <Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
              <Product Id="*" Name="Debpak Hello" Language="1033" Version="1.0.0"
                       Manufacturer="debpak" UpgradeCode="6b1d4c47-3d4b-4b3f-9c55-2f0e1f3e9a11">
                <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine"/>
                <Media Id="1" Cabinet="hello.cab" EmbedCab="yes"/>
                <Directory Id="TARGETDIR" Name="SourceDir">
                  <Directory Id="ProgramFiles64Folder">
                    <Directory Id="INSTALLDIR" Name="DebpakHello">
                      <Component Id="Main" Guid="2a4f3c1e-8a52-4f3b-a5b6-0e0f8c9d1a22" Win64="yes">
                        <File Id="HelloExe" Source="hello.exe" KeyPath="yes"/>
                      </Component>
                    </Directory>
                  </Directory>
                </Directory>
                <Feature Id="All" Level="1"><ComponentRef Id="Main"/></Feature>
              </Product>
            </Wix>
            """))
        _run([wixl, "-a", "x64", "-o", str(out / "DebpakHello-1.0.0.msi"), "hello.wxs"], cwd=win)
        made["exe-msi"] = {"file": "DebpakHello-1.0.0.msi", **expect}
    else:
        made["exe-msi"] = {"skip": "no wixl"}

    # Electron app, three ways
    pj = {"name": "debpak-hello-electron", "productName": "Debpak Hello Electron", "version": "1.0.0",
          "main": "main.js", "description": "debpak integration sample"}
    files = {"package.json": json.dumps(pj).encode(), "main.js": ELECTRON_MAIN.encode()}
    ew = src / "electron-win"
    if ew.exists():
        shutil.rmtree(ew)
    write_asar(ew / "resources/app.asar", files)
    (ew / "Debpak Hello Electron.exe").write_bytes(build_pe(PeSpec(is_dll=False, imports={
        "kernel32.dll": ["ExitProcess"]}, resources=[version_info({"ProductName": "Debpak Hello Electron",
                                                                   "ProductVersion": "1.0.0"})])))
    _zip_dir(ew, out / "DebpakHelloElectron-1.0.0-win.zip")
    expect_e = {"expect": f"debpak-electron-ok {electron_version}", "electron": electron_version}
    made["electron-zip"] = {"file": "DebpakHelloElectron-1.0.0-win.zip", **expect_e}
    seven = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    if makensis and seven:
        nsis = src / "electron-nsis"
        nsis.mkdir(exist_ok=True)
        _run([seven, "a", "-bd", str(nsis / "app-64.7z"), "."], cwd=ew)
        (nsis / "setup.nsi").write_text(textwrap.dedent("""\
            Name "Debpak Hello Electron"
            OutFile "setup.exe"
            RequestExecutionLevel user
            Section
              InitPluginsDir
              SetOutPath "$PLUGINSDIR"
              File "app-64.7z"
            SectionEnd
            """))
        _run([makensis, "-V2", "setup.nsi"], cwd=nsis)
        shutil.move(str(nsis / "setup.exe"), out / "Debpak Hello Electron Setup 1.0.0.exe")
        made["electron-nsis"] = {"file": "Debpak Hello Electron Setup 1.0.0.exe", **expect_e}
    else:
        made["electron-nsis"] = {"skip": "needs makensis and 7z"}
    mac = src / "mac" / "Debpak Hello Electron.app" / "Contents"
    if mac.parent.parent.exists():
        shutil.rmtree(mac.parent.parent)
    fw = mac / "Frameworks/Electron Framework.framework/Versions/A"
    (fw / "Resources").mkdir(parents=True)
    (fw / "Resources/Info.plist").write_bytes(plistlib.dumps({"CFBundleVersion": electron_version}))
    (fw / "Electron Framework").write_bytes(b"\xcf\xfa\xed\xfe" + bytes(60))
    (mac / "MacOS").mkdir(parents=True)
    (mac / "MacOS/Debpak Hello Electron").write_bytes(b"\xcf\xfa\xed\xfe" + bytes(60))
    (mac / "Info.plist").write_bytes(plistlib.dumps({"CFBundleName": "Debpak Hello Electron",
                                                     "CFBundleShortVersionString": "1.0.0"}))
    write_asar(mac / "Resources/app.asar", files)
    _zip_dir(mac.parent.parent, out / "DebpakHelloElectron-1.0.0-mac.zip")
    made["electron-mac"] = {"file": "DebpakHelloElectron-1.0.0-mac.zip", **expect_e}
    (out / "samples.json").write_text(json.dumps(made, indent=2) + "\n")
    return made
