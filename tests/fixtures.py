"""Build real .deb fixtures with gcc + dpkg-deb (skips if unavailable)."""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import textwrap
import zlib
from pathlib import Path

TRIPLET = "x86_64-linux-gnu"
HOST_LIBDIR = Path("/lib") / TRIPLET


def have_toolchain() -> bool:
    return bool(shutil.which("gcc") and shutil.which("dpkg-deb")) and os.uname().machine == "x86_64"


def tiny_png(size: int) -> bytes:
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\x80\x40\x20" * size for _ in range(size))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def _write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip())
    path.chmod(mode)


def _control(pkgdir: Path, name: str, extra: str = "") -> None:
    _write(pkgdir / "DEBIAN/control", f"""
        Package: {name}
        Version: 1.2.3-1
        Architecture: amd64
        Maintainer: Test <test@example.com>
        Homepage: https://example.com/{name}
        Description: {name} test package
         A package used by the debpak test-suite.
         .
         Second paragraph.
        """ + extra)


def _build_deb(pkgdir: Path, out: Path, compression: str = "xz") -> Path:
    subprocess.run(["dpkg-deb", f"-Z{compression}", "--root-owner-group", "-b", str(pkgdir), str(out)],
                   check=True, capture_output=True)
    return out


def _cc(args: list[str]) -> None:
    subprocess.run(["gcc", *args], check=True, capture_output=True)


class Fixtures:
    """Creates, under `base`:
      runtime/             fake runtime usr tree (glibc only)
      deps/libfake1.deb    provides libfake.so.1 (needs libfakedep.so.2)
      deps/libfakedep2.deb provides libfakedep.so.2
      fakeapp.deb          app needing libfake.so.1, with launcher script, desktop file, icon, maint scripts
      service.deb          app that installs a systemd service (blocker)
      electron.deb         fake Electron layout
      webex.deb            fake CEF app (Webex's layout): no .desktop file, a runnable libQt6Core.so.6
      pybundle.deb         ships a python whose DT_NEEDED is $ORIGIN/../lib/libpython3.11.so.1.0
      tauri.deb            links libwebkit2gtk-4.1.so.0 (Jan, Yaak)
      winit.deb            dlopen()s its display and GPU libraries (Warp)
    """

    def __init__(self, base: Path, compression: str = "xz"):
        self.base = base
        self.compression = compression
        self.src = base / "src"
        self.src.mkdir(parents=True)
        self._build_libs()
        self.runtime_root = self._build_runtime()
        self.deps = base / "deps"
        self.deps.mkdir()
        self.libfake_deb = self._lib_deb("libfake1", "libfake.so.1", "libfake.so.1.0.0")
        self.libfakedep_deb = self._lib_deb("libfakedep2", "libfakedep.so.2", "libfakedep.so.2.0.0")
        self.app_deb = self._app_deb()
        self.service_deb = self._service_deb()
        self.electron_deb = self._electron_deb()
        self.electron_script_deb = self._electron_deb(script=True)
        self.webex_deb = self._webex_deb()
        self.pybundle_deb = self._pybundle_deb()
        self.tauri_deb = self._tauri_deb()
        self.winit_deb = self._winit_deb()

    def _build_libs(self) -> None:
        s = self.src
        _write(s / "fakedep.c", "int fakedep_value(void) { return 40; }\n")
        _cc(["-shared", "-fPIC", "-Wl,-soname,libfakedep.so.2", "-o", str(s / "libfakedep.so.2.0.0"), str(s / "fakedep.c")])
        (s / "libfakedep.so").symlink_to("libfakedep.so.2.0.0")
        (s / "libfakedep.so.2").symlink_to("libfakedep.so.2.0.0")
        _write(s / "fake.c", "int fakedep_value(void);\nint fake_value(void) { return fakedep_value() + 2; }\n")
        _cc(["-shared", "-fPIC", "-Wl,-soname,libfake.so.1", "-o", str(s / "libfake.so.1.0.0"), str(s / "fake.c"),
             f"-L{s}", "-lfakedep"])
        (s / "libfake.so").symlink_to("libfake.so.1.0.0")
        _write(s / "app.c", """
            #include <stdio.h>
            #include <math.h>
            #include <sys/socket.h>
            int fake_value(void);
            int main(int argc, char **argv) {
                volatile int use_socket = argc > 99;
                if (use_socket) socket(AF_INET, SOCK_STREAM, 0);
                printf("fakeapp says %d %.0f\\n", fake_value(), sqrt(16.0));
                return 0;
            }
            """)
        _cc(["-o", str(s / "fakeapp"), str(s / "app.c"), f"-L{s}", "-lfake", "-lm",
             f"-Wl,-rpath-link,{s}"])

        # python-build-standalone names libpython by path relative to the program
        _write(s / "py.c", "int py_value(void) { return 3; }\n")
        _cc(["-shared", "-fPIC", "-Wl,-soname,$ORIGIN/../lib/libpython3.11.so.1.0",
             "-o", str(s / "libpython3.11.so.1.0"), str(s / "py.c")])
        _write(s / "python.c", "int py_value(void);\nint main(void) { return py_value() - 3; }\n")
        _cc(["-o", str(s / "python3"), str(s / "python.c"), str(s / "libpython3.11.so.1.0")])
        # Tauri: a program linking WebKitGTK, which only the GNOME runtime has
        _write(s / "webkit.c", "int webkit_value(void) { return 1; }\n")
        _cc(["-shared", "-fPIC", "-Wl,-soname,libwebkit2gtk-4.1.so.0", "-o", str(s / "libwebkit2gtk-4.1.so.0"),
             str(s / "webkit.c")])
        _write(s / "tauri.c", "int webkit_value(void);\nint main(void) { return webkit_value() - 1; }\n")
        _cc(["-o", str(s / "tauri"), str(s / "tauri.c"), str(s / "libwebkit2gtk-4.1.so.0")])
        # winit/wgpu: display and GPU libraries are named, not linked
        _write(s / "winit.c", """
            #include <stdio.h>
            static const char *libs[] = {"libX11.so.6", "libxcb.so.1", "libwayland-client.so.0",
                                         "libvulkan.so.1", "libEGL.so.1"};
            int main(int argc, char **argv) { puts(libs[argc % 5]); return 0; }
            """)
        _cc(["-o", str(s / "winit"), str(s / "winit.c")])

    def _build_runtime(self) -> Path:
        root = self.base / "runtime"
        libdir = root / "lib" / TRIPLET
        libdir.mkdir(parents=True)
        for name in ("libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2"):
            src = HOST_LIBDIR / name
            if src.exists():
                shutil.copy2(src.resolve(), libdir / name)
        return root

    def _lib_deb(self, pkg: str, soname: str, real: str) -> Path:
        d = self.base / f"pkg-{pkg}"
        lib = d / "usr/lib" / TRIPLET
        lib.mkdir(parents=True)
        shutil.copy2(self.src / real, lib / real)
        (lib / soname).symlink_to(real)
        _control(d, pkg)
        return _build_deb(d, self.deps / f"{pkg}.deb", self.compression)

    def _app_deb(self) -> Path:
        d = self.base / "pkg-fakeapp"
        (d / "opt/Fake").mkdir(parents=True)
        shutil.copy2(self.src / "fakeapp", d / "opt/Fake/fakeapp")
        _write(d / "opt/Fake/launch.sh", """
            #!/bin/sh
            cd /opt/Fake
            exec /opt/Fake/fakeapp "$@"
            """, 0o755)
        (d / "usr/bin").mkdir(parents=True)
        (d / "usr/bin/fakeapp").symlink_to("/opt/Fake/launch.sh")
        _write(d / "usr/share/applications/fakeapp.desktop", """
            [Desktop Entry]
            Type=Application
            Name=Fake App
            Exec=env FAKE_MODE=1 fakeapp --flag "a b" %U
            TryExec=fakeapp
            Icon=fakeapp
            Categories=Utility;

            [Desktop Action new]
            Name=New Window
            Exec=fakeapp --new-window
            """)
        icon = d / "usr/share/icons/hicolor/64x64/apps/fakeapp.png"
        icon.parent.mkdir(parents=True)
        icon.write_bytes(tiny_png(64))
        (d / "usr/share/pixmaps").mkdir(parents=True)
        (d / "usr/share/pixmaps/fakeapp.png").write_bytes(tiny_png(48))
        _write(d / "etc/cron.daily/fakeapp", "#!/bin/sh\necho add-apt-repo\n", 0o755)
        _write(d / "usr/share/doc/fakeapp/copyright", "Proprietary.\n")
        _control(d, "fakeapp", "Depends: libfake1\n")
        _write(d / "DEBIAN/postinst", """
            #!/bin/sh
            set -e
            ldconfig
            update-desktop-database -q || true
            exit 0
            """, 0o755)
        return _build_deb(d, self.base / "fakeapp.deb", self.compression)

    def _service_deb(self) -> Path:
        d = self.base / "pkg-svc"
        (d / "usr/bin").mkdir(parents=True)
        shutil.copy2(self.src / "fakeapp", d / "usr/bin/svc")
        _write(d / "lib/systemd/system/svc.service", "[Service]\nExecStart=/usr/bin/svc\n")
        _control(d, "svc")
        _write(d / "DEBIAN/postinst", "#!/bin/sh\nsystemctl enable --now svc.service\n", 0o755)
        return _build_deb(d, self.base / "svc.deb", self.compression)

    def _electron_deb(self, script: bool = False) -> Path:
        """A fake Electron app; with script, the .desktop file runs a shell wrapper
        (as Heynote's AppRun and Yaak's /usr/bin/yaak do)."""
        d = self.base / ("pkg-electron-script" if script else "pkg-electron")
        app = d / "opt/Zap"
        (app / "resources").mkdir(parents=True)
        shutil.copy2(self.src / "fakeapp", app / "zap")
        shutil.copy2(self.src / "libfake.so.1.0.0", app / "libfake.so.1")
        shutil.copy2(self.src / "libfakedep.so.2.0.0", app / "libfakedep.so.2")
        (app / "chrome-sandbox").write_bytes(b"\x00")
        (app / "resources/app.asar").write_bytes(b"asar")
        (d / "usr/bin").mkdir(parents=True)
        shutil.copy2(self.src / "fakeapp", app / "zap-helper")      # another executable beside it
        if script:
            _write(d / "usr/bin/zap", '#!/bin/sh\nexport ZAP_FLAG=1\nexec "/opt/Zap/zap" "$@"\n', 0o755)
        else:
            (d / "usr/bin/zap").symlink_to("/opt/Zap/zap")
        _write(d / "usr/share/applications/zap.desktop", f"""
            [Desktop Entry]
            Type=Application
            Name=Zap
            Exec={"/usr/bin/zap" if script else "/opt/Zap/zap"} %U
            Icon=zap
            """)
        _write(d / "DEBIAN/postinst", "#!/bin/sh\nchmod 4755 '/opt/Zap/chrome-sandbox' || true\n", 0o755)
        _control(d, "zap")
        return _build_deb(d, self.base / ("zap-script.deb" if script else "zap.deb"), self.compression)

    def _webex_deb(self) -> Path:
        """Webex's layout: Qt + CEF under opt/Webex, no .desktop file in usr/share/applications.

        libQt6Core.so.6 has an interpreter (it prints Qt's version when run) and is
        the largest ELF, but has no executable bit; CiscoCollabHostCef is CEF's
        helper for CiscoCollabHost.
        """
        d = self.base / "pkg-webex"
        bin_, lib = d / "opt/Webex/bin", d / "opt/Webex/lib"
        bin_.mkdir(parents=True)
        lib.mkdir(parents=True)
        shutil.copy2(self.src / "fakeapp", bin_ / "CiscoCollabHost")
        shutil.copy2(self.src / "fakeapp", bin_ / "CiscoCollabHostCef")
        with open(bin_ / "CiscoCollabHostCef", "ab") as f:
            f.write(b"\0" * 4096)
        shutil.copy2(self.src / "fakeapp", lib / "libQt6Core.so.6")
        with open(lib / "libQt6Core.so.6", "ab") as f:
            f.write(b"\0" * 65536)
        (lib / "libQt6Core.so.6").chmod(0o644)
        shutil.copy2(self.src / "libfake.so.1.0.0", lib / "libfake.so.1")
        shutil.copy2(self.src / "libfakedep.so.2.0.0", lib / "libfakedep.so.2")
        shutil.copy2(self.src / "libfakedep.so.2.0.0", lib / "libcef.so")
        for name in ("resources.pak", "snapshot_blob.bin", "v8_context_snapshot.bin"):
            (lib / name).write_bytes(b"\0")
        _control(d, "webex")
        return _build_deb(d, self.base / "webex.deb", self.compression)

    def _pybundle_deb(self) -> Path:
        d = self.base / "pkg-pybundle"
        py = d / "opt/PyApp/python"
        (py / "bin").mkdir(parents=True)
        (py / "lib").mkdir(parents=True)
        shutil.copy2(self.src / "python3", py / "bin/python3")
        shutil.copy2(self.src / "libpython3.11.so.1.0", py / "lib/libpython3.11.so.1.0")
        shutil.copy2(self.src / "fakeapp", d / "opt/PyApp/pyapp")
        shutil.copy2(self.src / "libfake.so.1.0.0", d / "opt/PyApp/libfake.so.1")
        shutil.copy2(self.src / "libfakedep.so.2.0.0", d / "opt/PyApp/libfakedep.so.2")
        _control(d, "pyapp")
        return _build_deb(d, self.base / "pyapp.deb", self.compression)

    def _tauri_deb(self) -> Path:
        d = self.base / "pkg-tauri"
        (d / "usr/bin").mkdir(parents=True)
        shutil.copy2(self.src / "tauri", d / "usr/bin/yaak-app")
        _write(d / "usr/share/applications/yaak.desktop", """
            [Desktop Entry]
            Type=Application
            Name=Yaak
            Exec=yaak-app
            """)
        _control(d, "yaak")
        return _build_deb(d, self.base / "yaak.deb", self.compression)

    def _winit_deb(self) -> Path:
        d = self.base / "pkg-winit"
        (d / "opt/warpdotdev/warp-terminal").mkdir(parents=True)
        shutil.copy2(self.src / "winit", d / "opt/warpdotdev/warp-terminal/warp")
        _write(d / "usr/share/applications/dev.warp.Warp.desktop", """
            [Desktop Entry]
            Type=Application
            Name=Warp
            Exec=warp-terminal %U
            Terminal=false
            """)
        _control(d, "warp-terminal")
        return _build_deb(d, self.base / "warp.deb", self.compression)
