import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from debpak.analyze import analyze, parse_exec
from debpak.cli import main
from debpak.deb import extract, parse_control, read_ar
from debpak.desktop import rewrite_desktop
from debpak.elf import max_version, read_elf
from debpak.permissions import infer
from debpak.runtime import RuntimeIndex, index_root

from fixtures import Fixtures, have_toolchain
from isolate import offline


def run_cli(*argv):
    out = io.StringIO()
    with offline(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()


class UnitTests(unittest.TestCase):
    def test_parse_control_continuation(self):
        c = parse_control("Package: x\nDescription: short\n long one\n .\n two\n")
        self.assertEqual(c["Package"], "x")
        self.assertEqual(c["Description"], "short\nlong one\n\ntwo")

    def test_same_named_flathub_app_from_someone_else(self):
        from debpak import manage
        from debpak.manage import FlathubHit, different_app, site
        self.assertEqual(site("https://www.warp.dev/download"), "warp.dev")
        self.assertEqual(site("http://foo.example.co.uk:8080/x"), "example.co.uk")
        drey = FlathubHit("app.drey.Warp", "Warp")
        homepages = {"app.drey.Warp": "https://apps.gnome.org/Warp/",
                     "com.onepassword.OnePassword": "https://1password.com"}
        with mock.patch.object(manage, "_HOMEPAGES", homepages):
            # Warp the terminal (dev.warp.Warp, warp.dev) isn't Warp the file sender
            self.assertIn("dev.warp.Warp", different_app(drey, desktop_id="dev.warp.Warp"))
            self.assertIn("warp.dev", different_app(drey, homepage="https://www.warp.dev"))
            self.assertEqual(different_app(drey), "")                          # nothing to go on
            one = FlathubHit("com.onepassword.OnePassword", "1Password")
            self.assertEqual(different_app(one, homepage="https://1password.com", desktop_id="1password"), "")
            code = FlathubHit("com.visualstudio.code", "Visual Studio Code")
            self.assertEqual(different_app(code, homepage="https://code.visualstudio.com/"), "")
            self.assertEqual(different_app(code, desktop_id="com.visualstudio.code"), "")

    def test_apparmor_profile_is_not_a_service(self):
        # Cursor 3.31's postinst: Ubuntu loads a profile so Chromium's sandbox may use user namespaces
        from debpak.maintscripts import analyze_scripts
        cursor = ("#!/bin/sh\nset -e\nif command -v apparmor_parser >/dev/null 2>&1; then\n"
                  "\tif systemctl is-active --quiet apparmor 2>/dev/null; then\n"
                  "\t\tapparmor_parser -r /etc/apparmor.d/cursor-sandbox 2>/dev/null || true\n\tfi\nfi\n")
        found = analyze_scripts({"postinst": cursor, "prerm": cursor.replace("-r ", "-R ")})
        self.assertEqual({f.category for f in found}, {"ignore"})
        for service in ("systemctl enable --now svc.service", "systemctl --no-block restart svc",
                        "systemctl daemon-reload", "deb-systemd-invoke start svc"):
            self.assertIn("blocker", {f.category for f in analyze_scripts({"postinst": service})}, service)

    def test_checking_for_systemctl_is_not_a_service(self):
        # Termius was refused for "installs/starts a system service" in postinst and postrm, with no
        # unit files in the package: asking whether systemctl exists isn't starting a service
        from debpak.maintscripts import analyze_scripts
        script = ("#!/bin/sh\nif command -v systemctl >/dev/null 2>&1 \\\n"
                  "   && systemctl is-active --quiet apparmor; then\n"
                  "  systemctl reload \\\n    apparmor.service\nfi\n"
                  "[ -x /bin/systemctl ] && echo systemd\nwhich systemctl > /dev/null || exit 0\n")
        found = analyze_scripts({"postinst": script, "postrm": script})
        self.assertEqual({f.category for f in found}, {"ignore"}, found)
        (f,) = analyze_scripts({"postinst": "#!/bin/sh\nsystemctl --user enable app-agent.service\n"})
        self.assertEqual(f.category, "warn")
        for service in ("command -v systemctl >/dev/null && systemctl start svc",
                        "systemctl \\\n  enable svc.service"):
            self.assertIn("blocker", {f.category for f in analyze_scripts({"postinst": service})}, service)

    def test_icon_too_small_or_odd_sized_gets_an_appstream_copy(self):
        # appstreamcli compose failed with icon-not-found: Beyond Compare ships a 32x32 icon
        # (as Icon=bcompare.png), MongoDB Compass a 276x276 one in /usr/share/pixmaps
        from debpak.desktop import install_icons, png_size
        from fixtures import tiny_png
        for icon, size, made in (("bcompare.png", 32, "128x128"), ("mongodb-compass", 276, "256x256")):
            with tempfile.TemporaryDirectory() as t:
                root, share = Path(t) / "root", Path(t) / "app/share"
                (root / "usr/share/pixmaps").mkdir(parents=True)
                (root / "usr/share/pixmaps" / (icon.removesuffix(".png") + ".png")).write_bytes(tiny_png(size))
                installed, warnings = install_icons(root, icon, share, "org.example.App")
                self.assertEqual(sorted(Path(i).parts[3] for i in installed), sorted([f"{size}x{size}", made]))
                copy = share / "icons/hicolor" / made / "apps/org.example.App.png"
                self.assertEqual(png_size(copy), (int(made.split("x")[0]),) * 2)
                self.assertTrue(any("AppStream" in w for w in warnings), warnings)
        with tempfile.TemporaryDirectory() as t:         # a 64x64 icon is enough
            root, share = Path(t) / "root", Path(t) / "app/share"
            p = root / "usr/share/icons/hicolor/64x64/apps/app.png"
            p.parent.mkdir(parents=True)
            p.write_bytes(tiny_png(64))
            installed, warnings = install_icons(root, "app", share, "org.example.App")
            self.assertEqual(installed, ["share/icons/hicolor/64x64/apps/org.example.App.png"])
            self.assertEqual(warnings, [])

    def test_icon_that_isnt_an_image_is_skipped(self):
        # flatpak's export refused zsync2's empty zsync2.svg: "is not a valid icon: Format not recognized"
        from debpak.desktop import install_icons
        from fixtures import tiny_png
        with tempfile.TemporaryDirectory() as t:
            root, share = Path(t) / "root", Path(t) / "app/share"
            d = root / "usr/share/icons/hicolor"
            (d / "scalable/apps").mkdir(parents=True)
            (d / "scalable/apps/zsync2.svg").write_bytes(b"")
            (d / "64x64/apps").mkdir(parents=True)
            (d / "64x64/apps/zsync2.png").write_bytes(b"<html>not found</html>")
            installed, warnings = install_icons(root, "zsync2", share, "org.example.App")
            self.assertEqual(installed, [])
            self.assertIn("skipped zsync2.svg: the file is empty", warnings)
            self.assertIn("skipped zsync2.png: it isn't a PNG image", warnings)
            (d / "scalable/apps/zsync2.svg").write_text('<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" '
                                                        'viewBox="0 0 16 16"/>')
            installed, _ = install_icons(root, "zsync2", share, "org.example.App")
            self.assertEqual(installed, ["share/icons/hicolor/scalable/apps/org.example.App.svg"])

    def test_icon_in_a_0x0_folder_is_sized_by_its_image(self):
        # electron-builder put Slipstream GUI's 1024x1024 icon in hicolor/0x0, and debpak scaled it
        # "to fit its folder", which flatpak's export then refused
        from debpak.desktop import install_icons, png_size
        from fixtures import tiny_png
        with tempfile.TemporaryDirectory() as t:
            root, share = Path(t) / "root", Path(t) / "app/share"
            p = root / "usr/share/icons/hicolor/0x0/apps/slipstream-gui.png"
            p.parent.mkdir(parents=True)
            p.write_bytes(tiny_png(1024))
            installed, warnings = install_icons(root, "slipstream-gui", share, "org.example.App")
            self.assertNotIn("0x0", " ".join(installed))
            self.assertIn("share/icons/hicolor/512x512/apps/org.example.App.png", installed)
            self.assertEqual(png_size(share / "icons/hicolor/512x512/apps/org.example.App.png"), (512, 512))

    def test_network_through_gio_or_a_dlopened_library(self):
        # the Minecraft launcher downloads the real launcher, yet got no --share=network
        perms = {p.arg for p in infer({"libgtk-3.so.0"}, {"g_socket_client_connect_to_host"}, "gtk3")}
        self.assertIn("--share=network", perms)
        perms = {p.arg: p.reason for p in infer({"libgtk-3.so.0"}, set(), "gtk3", dlopened={"libcurl.so.4"})}
        self.assertEqual(perms["--share=network"], "dlopens libcurl.so.4")
        self.assertNotIn("--share=network", {p.arg for p in infer({"libgtk-3.so.0"}, {"g_strdup"}, "gtk3")})

    def test_categories_are_added_when_missing(self):
        # JetBrains Toolbox's .desktop file has no Categories=, and appstreamcli compose
        # failed the build: "E: no-valid-category"
        text = rewrite_desktop("[Desktop Entry]\nName=JetBrains Toolbox\nExec=jetbrains-toolbox %u\n"
                               "Icon=jetbrains-toolbox\n\n[Desktop Action x]\nName=X\nExec=jetbrains-toolbox\n",
                               "com.example.Toolbox", "debpak-run")
        self.assertIn("Icon=com.example.Toolbox\nCategories=Utility;\n\n[Desktop Action x]", text)
        self.assertEqual(text.count("Categories="), 1)
        text = rewrite_desktop("[Desktop Entry]\nName=X\nExec=x\nCategories=GTK;X-Vendor\n", "com.example.X", "r")
        self.assertIn("Categories=GTK;X-Vendor;Utility;", text)

    def test_vendor_service_installers_are_blockers(self):
        # TeamViewer: its scripts enable teamviewerd.service, which it keeps in
        # /opt/teamviewer/tv_bin/script; the GUI can't work without that daemon
        from debpak.maintscripts import analyze_payload, analyze_scripts
        for script in ('"$TV_SCRIPT_DIR/teamviewer" daemon enable\n',
                       "teamviewer daemon start || true\n",
                       "cp -f /opt/teamviewer/tv_bin/script/teamviewerd.service /etc/systemd/system/\n",
                       "ln -s /opt/Vendor/vendord.service /lib/systemd/system/vendord.service\n"):
            cats = [f.category for f in analyze_scripts({"postinst": script})]
            self.assertEqual(cats, ["blocker"], script)
        (f,) = analyze_scripts({"postinst": "echo the daemon is running\n"})
        self.assertEqual(f.category, "warn")
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            script = root / "opt/teamviewer/tv_bin/script"
            script.mkdir(parents=True)
            for prog in ("opt/teamviewer/tv_bin/teamviewerd", "opt/teamviewer/agent"):
                (root / prog).write_text("")
            # a D-Bus activated helper in a systemd/user folder is a user unit (Slack's snap: dconf)
            from debpak.maintscripts import service_unit_kind
            user_dir = root / "usr/lib/systemd/user"
            user_dir.mkdir(parents=True)
            dconf = user_dir / "dconf.service"
            dconf.write_text("[Unit]\nDescription=User preferences database\n\n[Service]\nType=dbus\n"
                             "BusName=ca.desrt.dconf\nExecStart=/usr/libexec/dconf-service\n")
            self.assertEqual(service_unit_kind(dconf), "user")
            loose = root / "opt/dconf.service"
            loose.write_text(dconf.read_text())
            self.assertEqual(service_unit_kind(loose), "user")
            loose.write_text("[Service]\nExecStart=/usr/bin/x\n\n[Install]\nWantedBy=multi-user.target\n")
            self.assertEqual(service_unit_kind(loose), "system")
            # Wayle's desktop shell, started with the graphical session, which only the user manager has
            loose.write_text("[Unit]\nPartOf=graphical-session.target\nAfter=graphical-session.target\n\n"
                             "[Service]\nExecStart=/usr/bin/wayle shell\nSlice=session.slice\n\n"
                             "[Install]\nWantedBy=graphical-session.target\n")
            self.assertEqual(service_unit_kind(loose), "user")
            loose.write_text("[Unit]\nPartOf=graphical-session.target\n\n[Service]\nExecStart=/usr/bin/x\n")
            self.assertEqual(service_unit_kind(loose), "user")
            loose.write_text("[Service]\nExecStart=/usr/bin/x\n\n[Install]\n"
                             "WantedBy=graphical-session.target multi-user.target\n")
            self.assertEqual(service_unit_kind(loose), "system")
            loose.unlink()
            dconf.unlink()
            # the operating system's own units in an AppImage built from a system image
            from debpak.maintscripts import OS_UNIT
            for name in ("emergency.service", "dbus.service", "console-getty.service", "getty@.service",
                         "systemd-journald.service"):
                self.assertTrue(OS_UNIT.match(name), name)
            self.assertFalse(OS_UNIT.match("teamviewerd.service"))
            # a unit for a program the package doesn't ship is left over from where it was built
            # (LocalSend's AppImage has console-getty.service, which runs /sbin/agetty)
            (script / "console-getty.service").write_text(
                "[Service]\nExecStart=-/sbin/agetty --noclear --keep-baud console 115200 $TERM\n\n"
                "[Install]\nWantedBy=getty.target\n")
            # a D-Bus service file is also *.service, and isn't a systemd unit
            (script / "com.teamviewer.TeamViewer.service").write_text(
                "[D-BUS Service]\nName=com.teamviewer.TeamViewer\nExec=/opt/teamviewer/tv_bin/TeamViewer\n")
            self.assertEqual(analyze_payload(root), [])
            (script / "agent.service").write_text("[Unit]\nDescription=Agent\n\n[Service]\n"
                                                  "ExecStart=/opt/teamviewer/agent\n\n[Install]\n"
                                                  "WantedBy=default.target\n")
            self.assertEqual([f.category for f in analyze_payload(root)], ["warn"])
            (script / "teamviewerd.service").write_text(
                "[Unit]\nDescription = TeamViewer remote control daemon\n\n[Service]\nType = simple\n"
                "ExecStart = /opt/teamviewer/tv_bin/teamviewerd -f\n\n[Install]\nWantedBy = multi-user.target\n")
            blockers = [f for f in analyze_payload(root) if f.category == "blocker"]
            self.assertEqual([f.where for f in blockers], ["opt/teamviewer/tv_bin/script/teamviewerd.service"])
            self.assertIn("system service", blockers[0].detail)

    def test_parse_exec_env_and_args(self):
        env, prog, args = parse_exec('env A=1 B="x y" /opt/foo/bar --x "a b" %U')
        self.assertEqual(env, {"A": "1", "B": "x y"})
        self.assertEqual(prog, "/opt/foo/bar")
        self.assertEqual(args, ["--x", "a b", "%U"])

    def test_rewrite_desktop(self):
        text = "[Desktop Entry]\nName=X\nExec=env A=1 x --y \"a b\" %U\nTryExec=x\nIcon=x\n[Desktop Action n]\nExec=x --new\n"
        out = rewrite_desktop(text, "org.example.X", "debpak-run")
        self.assertIn('Exec=debpak-run --y "a b" %U', out)
        # Quickgui's MimeType=null made flatpak refuse to start it, citing the administrator's policy
        odd = rewrite_desktop("[Desktop Entry]\nName=Q\nExec=q %u\nMimeType=null\n", "org.example.Q", "debpak-run")
        self.assertNotIn("MimeType", odd)
        both = rewrite_desktop("[Desktop Entry]\nExec=q\nMimeType=null;text/plain;x-scheme-handler/q\n", "o.Q", "r")
        self.assertIn("MimeType=text/plain;x-scheme-handler/q;\n", both)
        self.assertIn("Exec=debpak-run --new", out)
        self.assertIn("Icon=org.example.X", out)
        self.assertNotIn("TryExec", out)
        # Ghostty's entry is D-Bus activatable, and flatpak-builder wouldn't export it without the service
        dbus = rewrite_desktop("[Desktop Entry]\nName=G\nExec=ghostty\nDBusActivatable=true\n", "o.G", "r")
        self.assertNotIn("DBusActivatable", dbus)

    def test_program_named_after_the_package_anywhere(self):
        # kitty's tarball keeps it in bin/; the guess took the larger bin/kitten
        from debpak.analyze import guess_main_exec, named_program
        from debpak.elf import ElfInfo
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            elfs = {}
            for rel, size in (("opt/kitty/bin/kitty", 10), ("opt/kitty/bin/kitten", 50),
                              ("opt/app/app", 10), ("opt/app/app-cli", 50)):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(b"\0" * size)
                (root / rel).chmod(0o755)
                elfs[rel] = ElfInfo(rel, "x86_64", 3, 64, interp="/lib64/ld-linux-x86-64.so.2")
            self.assertEqual(named_program(elfs, "kitty"), "opt/kitty/bin/kitty")
            self.assertIsNone(named_program(elfs, "nothing"))
            app = {r: i for r, i in elfs.items() if r.startswith("opt/app/")}
            self.assertEqual(guess_main_exec(root, app), "opt/app/app")

    def test_download_that_stops_early_is_tried_again(self):
        # a Snipaste AppImage arrived as 28 of its 37 MB without an error
        from email.message import Message
        from debpak import net

        class Reply(io.BytesIO):
            def __init__(self, body, length):
                super().__init__(body)
                self.headers = Message()
                self.headers["Content-Length"] = str(length)

        replies = [Reply(b"x" * 28, 37), Reply(b"x" * 37, 37)]
        with tempfile.TemporaryDirectory() as t, mock.patch.object(net, "urlopen", lambda *a, **k: replies.pop(0)):
            dest = net.download("https://example.com/a.AppImage", Path(t) / "a")
            self.assertEqual(dest.stat().st_size, 37)
            replies[:] = [Reply(b"x" * 28, 37) for _ in range(3)]
            with self.assertRaisesRegex(OSError, "stopped at 28 of 37 bytes"):
                net.download("https://example.com/a.AppImage", Path(t) / "a")

    def test_the_one_program_on_path(self):
        # PowerShell links /usr/bin/pwsh to a small program beside a larger createdump
        from debpak.analyze import only_program_on_path
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "opt/ms/7").mkdir(parents=True)
            for name, size in (("pwsh", 10), ("createdump", 500)):
                (root / "opt/ms/7" / name).write_bytes(b"\x7fELF" + bytes(size))
                (root / "opt/ms/7" / name).chmod(0o755)
            (root / "usr/bin").mkdir(parents=True)
            os.symlink("/opt/ms/7/pwsh", root / "usr/bin/pwsh")
            self.assertEqual(only_program_on_path(root), "opt/ms/7/pwsh")
            os.symlink("/opt/ms/7/createdump", root / "usr/bin/createdump")
            self.assertIsNone(only_program_on_path(root))

    def test_script_started_by_its_link(self):
        # Cryptomator's AppRun is a link to bin/cryptomator.sh, which runs bin/Cryptomator from $(dirname $0)
        from debpak.analyze import _script_link, locate_program
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "opt/crypt/bin").mkdir(parents=True)
            (root / "opt/crypt/bin/cryptomator.sh").write_text('#!/bin/sh\ncd $(dirname $0)\nbin/Cryptomator "$@"\n')
            (root / "opt/crypt/bin/Cryptomator").write_bytes(b"\x7fELF")
            os.symlink("bin/cryptomator.sh", root / "opt/crypt/AppRun")
            os.symlink("Cryptomator", root / "opt/crypt/bin/run")
            loc = locate_program(root, "/opt/crypt/AppRun")
            self.assertEqual(loc, "opt/crypt/bin/cryptomator.sh")
            self.assertEqual(_script_link(root, "/opt/crypt/AppRun", loc), "opt/crypt/AppRun")
            # a link to a program keeps its target
            loc = locate_program(root, "/opt/crypt/bin/run")
            self.assertEqual(_script_link(root, "/opt/crypt/bin/run", loc), "opt/crypt/bin/Cryptomator")

    def test_elf_system_binary(self):
        info = read_elf("/bin/ls")
        self.assertTrue(info.is_executable)
        self.assertIn("libc.so.6", info.needed)
        self.assertIsNotNone(max_version(info.verneed["libc.so.6"], "GLIBC"))

    def test_permissions_heuristics(self):
        perms = {p.arg for p in infer({"libX11.so.6", "libasound.so.2", "libGL.so.1"}, {"getaddrinfo"}, "elf")}
        self.assertTrue({"--socket=x11", "--socket=pulseaudio", "--device=dri", "--share=network"} <= perms)
        self.assertNotIn("--filesystem=home", perms)
        perms = {p.arg for p in infer({"libwayland-client.so.0"}, set(), "elf")}
        self.assertIn("--socket=wayland", perms)
        self.assertIn("--socket=fallback-x11", perms)

    def test_permissions_for_dlopened_display_libraries(self):
        # Warp links neither X11 nor Wayland; winit dlopens them, and without a
        # display socket it panics (exit status 101). It uses X11 by default.
        perms = {p.arg: p.reason for p in infer({"libasound.so.2"}, {"connect"}, "elf",
                                                dlopened={"libX11.so.6", "libwayland-client.so.0", "libvulkan.so.1"})}
        for arg in ("--share=ipc", "--socket=x11", "--socket=wayland", "--device=dri"):
            self.assertIn(arg, perms)
        self.assertEqual(perms["--socket=x11"], "dlopens libX11.so.6")
        self.assertNotIn("--socket=fallback-x11", perms)
        perms = {p.arg for p in infer(set(), set(), "elf", dlopened={"libwayland-client.so.0"})}
        self.assertTrue({"--socket=wayland", "--socket=fallback-x11"} <= perms)
        # a .desktop launcher alone still gets a window
        perms = {p.arg for p in infer(set(), set(), "elf", gui="warp.desktop starts a graphical app")}
        self.assertTrue({"--share=ipc", "--socket=x11"} <= perms)
        self.assertFalse({p.arg for p in infer(set(), set(), "elf")} & {"--socket=x11", "--share=ipc"})
        # WebKitGTK composites on the GPU (Tauri apps)
        perms = {p.arg for p in infer({"libwebkit2gtk-4.1.so.0", "libgtk-3.so.0"}, set(), "gtk3")}
        self.assertIn("--device=dri", perms)

    def test_keyring_reached_over_its_own_dbus_library(self):
        # Kunkun (Tauri) keeps secrets with the keyring crate over zbus, linking nothing that shows it,
        # and panicked at start with "Platform secure storage failure: ... ServiceUnknown"
        from debpak.analyze import scan_bus_clients
        prog = Path(tempfile.mkdtemp()) / "kunkun"
        prog.write_bytes(b"\x7fELF" + bytes(100) + b"service org.freedesktop.secretsorg.freedesktop.Secret.Service")
        self.assertEqual(scan_bus_clients(prog), {"org.freedesktop.secrets"})
        prog.write_bytes(b"\x7fELF" + bytes(100))
        self.assertEqual(scan_bus_clients(prog), set())
        perms = {p.arg: p.reason for p in infer({"libgtk-3.so.0"}, set(), "gtk3",
                                                bus_clients={"org.freedesktop.secrets"})}
        self.assertIn("reaches over D-Bus itself", perms["--talk-name=org.freedesktop.secrets"])
        self.assertNotIn("--talk-name=org.freedesktop.secrets", {p.arg for p in infer({"libgtk-3.so.0"}, set(), "gtk3")})

    def test_qt_quick_and_qt_tray_permissions(self):
        # MEGAsync: Qt Quick draws with OpenGL, yet the app links no GL library; and its
        # QSystemTrayIcon found no tray without the StatusNotifierWatcher
        perms = {p.arg: p.reason for p in infer(
            {"libQt5Core.so.5", "libQt5Gui.so.5", "libQt5Quick.so.5", "libQt5Widgets.so.5"},
            {"_ZN15QSystemTrayIconC1EP7QObject", "_ZN15QSystemTrayIcon4showEv"}, "qt5")}
        self.assertEqual(perms["--device=dri"], "links libQt5Quick.so.5 (Qt Quick draws with OpenGL)")
        self.assertEqual(perms["--talk-name=org.kde.StatusNotifierWatcher"], "uses QSystemTrayIcon (Qt's tray icon)")
        perms = {p.arg for p in infer({"libQt5Core.so.5", "libQt5Widgets.so.5"}, {"_ZN7QWidget4showEv"}, "qt5")}
        self.assertFalse(perms & {"--device=dri", "--talk-name=org.kde.StatusNotifierWatcher"})

    def test_cef_permissions_match_electron(self):
        cef = {p.arg for p in infer(set(), set(), "cef")}
        self.assertEqual(cef, {p.arg for p in infer(set(), set(), "electron")})

    def test_library_names(self):
        from debpak.analyze import is_library_name
        for name in ("libQt6Core.so.6", "libcef.so", "libfoo.so.1.2.3", "foo.so"):
            self.assertTrue(is_library_name(name), name)
        for name in ("CiscoCollabHost", "warp", "python3.11", "foo.sock", "app.so-helper"):
            self.assertFalse(is_library_name(name), name)

    def test_webkit_needs_the_gnome_runtime(self):
        from debpak.analyze import DEFAULT_RUNTIMES, suggest_runtime
        gnome = DEFAULT_RUNTIMES["gnome"]
        self.assertEqual(suggest_runtime("gtk3", {"libwebkit2gtk-4.1.so.0", "libgtk-3.so.0"}), gnome)
        self.assertEqual(suggest_runtime("gtk4", {"libwebkitgtk-6.0.so.4"}), gnome)
        self.assertEqual(suggest_runtime("gtk3", {"libgtk-3.so.0"}), DEFAULT_RUNTIMES["freedesktop"])
        self.assertEqual(suggest_runtime("electron", {"libwebkit2gtk-4.1.so.0"}), DEFAULT_RUNTIMES["freedesktop"])

    def test_needed_by_path(self):
        from debpak.analyze import needed_path
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "opt/X/python/lib").mkdir(parents=True)
            (root / "opt/X/python/lib/libpython3.11.so.1.0").write_bytes(b"\x7fELF")
            (root / "opt/X/python/lib/libpython3.so").symlink_to("libpython3.11.so.1.0")
            self.assertEqual(needed_path(root, "opt/X/python/bin/python3", "$ORIGIN/../lib/libpython3.11.so.1.0"),
                             "opt/X/python/lib/libpython3.11.so.1.0")
            self.assertEqual(needed_path(root, "opt/X/python/bin/python3", "${ORIGIN}/../lib/libpython3.so"),
                             "opt/X/python/lib/libpython3.11.so.1.0")
            self.assertEqual(needed_path(root, "opt/X/bin/a", "/opt/X/python/lib/libpython3.11.so.1.0"),
                             "opt/X/python/lib/libpython3.11.so.1.0")
            self.assertIsNone(needed_path(root, "opt/X/python/bin/python3", "$ORIGIN/../lib/libgone.so"))
            self.assertIsNone(needed_path(root, "a", "$ORIGIN/../../etc/passwd"))
            self.assertIsNone(needed_path(root, "opt/X/python/bin/python3", "libpython3.11.so.1.0"))

    def test_plugin_libraries_the_skipped_script_put_on_the_path(self):
        # ONLYOFFICE's .deb: debpak runs DesktopEditors, not the /usr/bin script that sets
        # LD_LIBRARY_PATH, and Qt's xcb plugin then can't find libQt5XcbQpa.so.5 beside the program
        from types import SimpleNamespace

        from debpak.analyze import Analysis
        from debpak.elf import ET_DYN, ElfInfo
        from debpak.stage import library_path_dirs
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "opt/oo/platforms").mkdir(parents=True)
            (root / "usr/bin").mkdir(parents=True)
            script = root / "usr/bin/onlyoffice"
            script.write_text("#!/bin/sh\nexport LD_LIBRARY_PATH=/opt/oo$LDLPATH\nexec /opt/oo/DesktopEditors \"$@\"\n")
            prog = ElfInfo("DesktopEditors", "x86_64", ET_DYN, 64, interp="/lib64/ld-linux-x86-64.so.2",
                           needed=["libQt5Core.so.5", "libc.so.6"], runpath=["$ORIGIN"])
            plugin = ElfInfo("libqxcb.so", "x86_64", ET_DYN, 64, needed=["libQt5Core.so.5", "libQt5XcbQpa.so.5"],
                             runpath=["$ORIGIN/../../lib"])
            a = Analysis(pkg=SimpleNamespace(root=root), arch="x86_64", kind="cef",
                         elfs={"opt/oo/DesktopEditors": prog, "opt/oo/platforms/libqxcb.so": plugin,
                               "opt/oo/libQt5Core.so.5": ElfInfo("c", "x86_64", ET_DYN, 64),
                               "opt/oo/libQt5XcbQpa.so.5": ElfInfo("x", "x86_64", ET_DYN, 64)},
                         package_sonames={"libQt5Core.so.5": "opt/oo/libQt5Core.so.5",
                                          "libQt5XcbQpa.so.5": "opt/oo/libQt5XcbQpa.so.5"},
                         main_exec="opt/oo/DesktopEditors", bypassed_script="usr/bin/onlyoffice")
            self.assertEqual(library_path_dirs(a, "bundle", False), ["/app/opt/oo"])
            self.assertEqual(library_path_dirs(a, "extra-data", True), ["/app/lib/debpak", "/app/extra/opt/oo"])
            # libQt5Core.so.5 is loaded by then: a plugin needing only it doesn't count
            plugin.needed.remove("libQt5XcbQpa.so.5")
            self.assertEqual(library_path_dirs(a, "bundle", False), [])
            plugin.needed.append("libQt5XcbQpa.so.5")
            # nor does anything when the script didn't set the path
            script.write_text("#!/bin/sh\nexec /opt/oo/DesktopEditors \"$@\"\n")
            self.assertEqual(library_path_dirs(a, "bundle", False), [])

    def test_app_libraries_loaded_with_dlopen(self):
        # Webex's .deb: its loader dlopen()s libspark-windows-desktop-ui.so, which nothing links,
        # and that needs libcrypt.so.1 through Heimdal's libkrb5.so.26; the runtime has only
        # libcrypt.so.2, so the app exited at once without a window
        from debpak.analyze import is_never_bundle, lib_family, loaded_needs
        from debpak.elf import ET_DYN, ElfInfo
        prog = ElfInfo("WebexFileSelector", "x86_64", ET_DYN, 64, interp="/lib64/ld-linux-x86-64.so.2",
                       needed=["libQt6Core.so.6", "libc.so.6"])
        elfs = {
            "opt/Webex/bin/WebexFileSelector": prog,
            "opt/Webex/lib/libQt6Core.so.6": ElfInfo("c", "x86_64", ET_DYN, 64, needed=["libc.so.6"]),
            "opt/Webex/lib/libspark-windows-desktop-ui.so": ElfInfo(
                "ui", "x86_64", ET_DYN, 64, needed=["libkrb5.so.26", "libQt6Core.so.6", "libgssapi_krb5.so.2"]),
            "opt/Webex/lib/libkrb5.so.26": ElfInfo("k", "x86_64", ET_DYN, 64, needed=["libcrypt.so.1", "libnsl.so.1"]),
            # Qt's own pieces the vendor didn't ship, and an old OpenSSL beside its new one
            "opt/Webex/lib/libQt6Network.so.6": ElfInfo("n", "x86_64", ET_DYN, 64, needed=["libQt6Dav.so.6"]),
            "opt/Webex/lib/libcrypto.so.3": ElfInfo("o", "x86_64", ET_DYN, 64),
            "opt/Webex/lib/libssl1.so": ElfInfo("s", "x86_64", ET_DYN, 64, needed=["libcrypto.so.1.1"]),
            # a plugin in a folder of its own stays optional
            "opt/Webex/bin/accessories/plugin.so": ElfInfo("p", "x86_64", ET_DYN, 64, needed=["libusb-1.0.so.0"]),
        }
        sonames = {Path(r).name: r for r in elfs if ".so" in r}
        reached = {"opt/Webex/bin/WebexFileSelector", "opt/Webex/lib/libQt6Core.so.6"}
        self.assertEqual(loaded_needs(elfs, reached, sonames), {"libcrypt.so.1", "libgssapi_krb5.so.2"})
        # with no library reached, nothing is the app's own
        self.assertEqual(loaded_needs(elfs, {"opt/Webex/bin/WebexFileSelector"}, sonames), set())
        # Postbird (Electrobun): its launcher opens libNativeWrapper.so beside it in bin/, which links
        # WebKitGTK; the app then needs the GNOME runtime, and stopped with "missing libwebkit2gtk-4.1"
        from debpak.analyze import suggest_runtime
        launcher = ElfInfo("launcher", "x86_64", ET_DYN, 64, interp="/lib64/ld-linux-x86-64.so.2", needed=["libc.so.6"])
        wrapper = ElfInfo("w", "x86_64", ET_DYN, 64, needed=["libwebkit2gtk-4.1.so.0", "libayatana-appindicator3.so.1"])
        elfs = {"opt/postbird/bin/launcher": launcher, "opt/postbird/bin/libNativeWrapper.so": wrapper}
        needs = loaded_needs(elfs, {"opt/postbird/bin/launcher"}, {"libNativeWrapper.so": "opt/postbird/bin/libNativeWrapper.so"})
        self.assertEqual(needs, {"libwebkit2gtk-4.1.so.0", "libayatana-appindicator3.so.1"})
        self.assertTrue(suggest_runtime("gtk3", needs).startswith("org.gnome.Platform"))
        self.assertEqual(lib_family("libQt6Network.so.6"), "libqt")
        self.assertNotEqual(lib_family("libcrypt.so.1"), lib_family("libcrypto.so.3"))
        # libxcrypt provides libcrypt.so.1 now; glibc's own libraries are still never bundled
        self.assertFalse(is_never_bundle("libcrypt.so.1"))
        self.assertTrue(is_never_bundle("libnsl.so.1"))

    def test_opt_folder_without_blanks(self):
        # Beekeeper Studio's .rpm: Chromium splits its sandbox helper's path at the blank when it
        # starts the zygote, which died with "failed to execvp: /app/opt/Beekeeper"
        from debpak.stage import install_path, map_bundle
        self.assertEqual(map_bundle("opt/Beekeeper Studio/beekeeper-studio-bin"),
                         "opt/Beekeeper-Studio/beekeeper-studio-bin")
        self.assertEqual(install_path("/opt/Beekeeper Studio", "extra-data"), "/app/extra/opt/Beekeeper-Studio")
        self.assertEqual(map_bundle("usr/lib/mongodb-compass/MongoDB Compass"), "lib/mongodb-compass/MongoDB Compass")
        self.assertEqual(map_bundle("opt/Zap/resources/a b.png"), "opt/Zap/resources/a b.png")


@unittest.skipUnless(have_toolchain(), "needs gcc + dpkg-deb on x86_64")
class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="debpak-test-")
        cls.base = Path(cls._tmp.name)
        cls.fx = Fixtures(cls.base / "xz", compression="xz")
        cls.fx_zst = Fixtures(cls.base / "zst", compression="zstd")
        cls.index = index_root(cls.fx.runtime_root, "org.test.Platform/x86_64/1", "x86_64")
        cls.index_path = cls.base / "runtime.json"
        cls.index.save(cls.index_path)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def out_dir(self, name):
        return self.base / "out" / name

    # --- building blocks
    def test_ar_members(self):
        names = [m.name for m in read_ar(self.fx.app_deb)]
        self.assertEqual(names[0], "debian-binary")
        self.assertTrue(any(n.startswith("data.tar") for n in names))

    def test_zstd_extraction(self):
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx_zst.app_deb, t)
            self.assertEqual(pkg.name, "fakeapp")
            self.assertTrue((pkg.root / "opt/Fake/fakeapp").is_file())

    def test_runtime_index(self):
        self.assertIn("libc.so.6", self.index.sonames)
        self.assertTrue(self.index.glibc.startswith("GLIBC_2."))
        self.assertTrue(self.index.provides("libGL.so.1"))  # GL extension
        self.assertFalse(self.index.provides("libfake.so.1"))
        again = RuntimeIndex.load(self.index_path)
        self.assertEqual(again.sonames, self.index.sonames)

    # --- analysis
    def test_analyze_app(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.app_deb, t), self.index)
            self.assertEqual(a.kind, "elf")
            self.assertEqual(a.main_exec, "opt/Fake/launch.sh")
            self.assertTrue(a.main_exec_is_script)
            self.assertEqual(a.desktop_exec_env, {"FAKE_MODE": "1"})
            self.assertEqual(a.missing_hard, {"libfake.so.1"})
            self.assertFalse(a.blockers)
            ignored = {f.detail for f in a.findings if f.category == "ignore"}
            self.assertIn("linker cache; Flatpak builds its own", ignored)
            self.assertFalse([f for f in a.findings if f.category in ("warn", "blocker")])
            self.assertTrue(any(h.is_text and h.path.startswith("/opt/Fake") for h in a.hardcoded))

    def test_glibc_mismatch_is_a_blocker(self):
        crippled = RuntimeIndex.from_json(self.index.to_json())
        crippled.verdefs["libc.so.6"] = ["GLIBC_2.2.5"]
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.app_deb, t), crippled)
            self.assertTrue(any("GLIBC_" in b for b in a.blockers))

    def test_newer_glibc_takes_the_next_runtime(self):
        # OpenWhispr and RSS Guard need GLIBC_2.43; 25.08 has 2.42 and 26.08 has 2.44
        from types import SimpleNamespace
        from debpak import cli
        old = RuntimeIndex("org.freedesktop.Platform/x86_64/25.08", "x86_64", glibc="GLIBC_2.42")
        new = RuntimeIndex("org.freedesktop.Platform/x86_64/26.08", "x86_64", glibc="GLIBC_2.44")
        args = SimpleNamespace(runtime=None, runtime_index=None, no_build=True)
        with mock.patch.object(cli, "get_index", lambda ref, arch: new):
            self.assertIs(cli._newer_runtime(args, old, SimpleNamespace(max_glibc="GLIBC_2.43"), "x86_64"), new)
            self.assertIsNone(cli._newer_runtime(args, old, SimpleNamespace(max_glibc="GLIBC_2.39"), "x86_64"))
            self.assertIsNone(cli._newer_runtime(args, old, SimpleNamespace(max_glibc="GLIBC_2.45"), "x86_64"))
            named = SimpleNamespace(runtime="org.freedesktop.Platform//25.08", runtime_index=None, no_build=True)
            self.assertIsNone(cli._newer_runtime(named, old, SimpleNamespace(max_glibc="GLIBC_2.43"), "x86_64"))
        # a GTK 4 app on GNOME 49 goes to GNOME 51, built on 26.08
        gnome49 = RuntimeIndex("org.gnome.Platform/x86_64/49", "x86_64", glibc="GLIBC_2.42")
        gnome51 = RuntimeIndex("org.gnome.Platform/x86_64/51", "x86_64", glibc="GLIBC_2.44")
        asked = []
        with mock.patch.object(cli, "get_index", lambda ref, arch: asked.append(ref) or gnome51):
            self.assertIs(cli._newer_runtime(args, gnome49, SimpleNamespace(max_glibc="GLIBC_2.43"), "x86_64"), gnome51)
        self.assertEqual(asked, ["org.gnome.Platform//51"])

    def test_registry_kept_whole_by_conversions_at_once(self):
        # the compat suite runs many conversions at once; each used to read, change and write
        # the whole registry through one shared temporary file
        with tempfile.TemporaryDirectory() as t:
            code = ("import sys\nfrom debpak.manage import update_registry\n"
                    "for i in range(20):\n"
                    "    update_registry(lambda reg: reg.__setitem__(f'{sys.argv[1]}.{i}', {}))\n")
            src = str(Path(__file__).parents[1] / "src")
            path = os.pathsep.join([src, os.environ.get("PYTHONPATH", "")])
            env = {**os.environ, "XDG_DATA_HOME": t, "PYTHONPATH": path}
            procs = [subprocess.Popen([sys.executable, "-c", code, f"app{n}"], env=env) for n in range(8)]
            self.assertEqual([p.wait() for p in procs], [0] * 8)
            reg = json.loads((Path(t) / "debpak/apps.json").read_text())
            self.assertEqual(len(reg), 160)
            self.assertEqual([p.name for p in (Path(t) / "debpak").iterdir() if p.suffix == ".tmp"], [])

    @unittest.skipUnless(shutil.which("cc"), "needs a C compiler")
    def test_library_of_a_library_beside_it(self):
        # Reqable: its RUNPATH $ORIGIN/lib finds libayatana-appindicator3.so.1 there, but a RUNPATH
        # serves only the program's own needs, so libdbusmenu-gtk3.so.4 beside it wasn't found
        from debpak.stage import library_path_dirs
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            app = pkg.root / "opt/Reqable"
            (app / "lib").mkdir(parents=True)
            src = Path(t) / "src"
            src.mkdir()
            (src / "b.c").write_text("int b(void) { return 1; }\n")
            (src / "a.c").write_text("int b(void);\nint a(void) { return b(); }\n")
            (src / "m.c").write_text("int a(void);\nint main(void) { return a(); }\n")
            cc = ["cc", "-shared", "-fPIC"]
            subprocess.run([*cc, "-o", str(app / "lib/libdbusmenu-gtk3.so.4"), "-Wl,-soname,libdbusmenu-gtk3.so.4",
                            str(src / "b.c")], check=True)
            subprocess.run([*cc, "-o", str(app / "lib/libayatana-appindicator3.so.1"),
                            "-Wl,-soname,libayatana-appindicator3.so.1", str(src / "a.c"),
                            str(app / "lib/libdbusmenu-gtk3.so.4")], check=True)
            subprocess.run(["cc", "-o", str(app / "reqable"), str(src / "m.c"),
                            str(app / "lib/libayatana-appindicator3.so.1"), f"-Wl,-rpath-link,{app / 'lib'}",
                            "-Wl,--enable-new-dtags,-rpath,$ORIGIN/lib"], check=True)
            a = analyze(pkg, self.index, exec_override="/opt/Reqable/reqable")
            self.assertIn("/app/opt/Reqable/lib", library_path_dirs(a, "bundle", False))

    @unittest.skipUnless(shutil.which("cc"), "needs a C compiler")
    def test_glibc_copy_in_the_package_is_not_the_one_loaded(self):
        # Hydra keeps a glibc for a tool it starts with that copy's own loader; the app's
        # programs get the runtime's, so the copy's older versions aren't a problem
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            src = Path(t) / "old.c"
            src.write_text("int old_libc(void) { return 0; }\n")
            (Path(t) / "old.map").write_text("GLIBC_2.2.5 { global: old_libc; local: *; };\n")
            (pkg.root / "opt/Fake/glibc").mkdir()
            subprocess.run(["cc", "-shared", "-fPIC", "-o", str(pkg.root / "opt/Fake/glibc/libc.so.6"),
                            "-Wl,-soname,libc.so.6", f"-Wl,--version-script={Path(t) / 'old.map'}", str(src)],
                           check=True)
            a = analyze(pkg, self.index)
            self.assertFalse([b for b in a.blockers if "GLIBC_" in b], a.blockers)

    @unittest.skipUnless(shutil.which("cc"), "needs a C compiler")
    def test_glibc_copies_are_left_out_and_not_judged(self):
        # PonyPlayer's AppImage carries glibc 2.31 in runtime/compat, whose libanl needs its
        # own libpthread's GLIBC_PRIVATE: the app was refused, though it runs on the runtime's glibc
        def lib(t, out, soname, version, extra=(), body="0"):
            src, fn = Path(t) / f"{soname}.c", "f_" + soname.split(".")[0].replace("-", "_")
            src.write_text(f"int f_libpthread(void);\nint {fn}(void) {{ return {body}; }}\n")
            (Path(t) / f"{soname}.map").write_text(f"{version} {{ global: {fn}; local: *; }};\n")
            subprocess.run(["cc", "-shared", "-fPIC", "-o", str(out), f"-Wl,-soname,{soname}",
                            f"-Wl,--version-script={Path(t) / (soname + '.map')}", str(src), *extra], check=True)

        for with_loader in (False, True):
            with tempfile.TemporaryDirectory() as t:
                pkg = extract(self.fx.app_deb, t)
                compat = pkg.root / "opt/Fake/runtime/compat/lib"
                compat.mkdir(parents=True)
                lib(t, compat / "libpthread-2.31.so", "libpthread.so.0", "GLIBC_2.99")
                (compat / "libpthread.so.0").symlink_to("libpthread-2.31.so")
                lib(t, compat / "libanl-2.31.so", "libanl.so.1", "GLIBC_2.2.3",
                    [str(compat / "libpthread-2.31.so")], "f_libpthread()")
                if with_loader:
                    lib(t, compat / "ld-2.31.so", "ld-linux-x86-64.so.2", "GLIBC_2.3")
                a = analyze(pkg, self.index)
                self.assertFalse([b for b in a.blockers if "GLIBC_" in b], a.blockers)
                dropped = "opt/Fake/runtime/compat/lib/libpthread-2.31.so" in a.runtime_replaces
                self.assertEqual(dropped, not with_loader)
                if dropped:
                    self.assertEqual(a.runtime_replaces["opt/Fake/runtime/compat/lib/libpthread-2.31.so"],
                                     ["libpthread-2.31.so", "libpthread.so.0"])
                    self.assertNotIn("libpthread.so.0", a.package_sonames)

    def test_32_bit_x86_code_gets_multiarch(self):
        # Subway Surfers' AppImage runs a 32-bit game with its own Wine, and Flatpak's seccomp filter
        # killed its 32-bit calls: "Bad system call (core dumped)"
        import struct
        from debpak.cli import _home_permissions
        elf32 = b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack("<HHIIIIIHHHHHH", 3, 3, 1, 0, 0, 0, 0, 52, 32, 0, 40, 0, 0)
        for where, data in (("opt/Fake/usr/lib/wine/i386-unix/ntdll.so", elf32),
                            ("opt/Fake/usr/lib/wine/i386-windows/kernel32.dll", b"MZ" + bytes(62))):
            with tempfile.TemporaryDirectory() as t:
                pkg = extract(self.fx.app_deb, t)
                self.assertEqual(analyze(pkg, self.index).multiarch, "")
                (pkg.root / where).parent.mkdir(parents=True)
                (pkg.root / where).write_bytes(data)
                a = analyze(pkg, self.index)
                self.assertIn(str(Path(where).parent if where.endswith(".dll") else where), a.multiarch)
                self.assertIn("--allow=multiarch", [p.arg for p in _home_permissions(a)])

    def test_a_partial_set_of_libraries_gives_way_to_the_runtimes(self):
        # Dana's AppImage carries an old libfreetype.so.6 and not fontconfig, whose runtime copy then
        # failed on it: "libfontconfig.so.1: undefined symbol: FT_Done_MM_Var"; ImagePlay's carries
        # libharfbuzz.so.0 too, too old for the runtime's freetype
        from types import SimpleNamespace
        from debpak.analyze import partial_set_copies
        from debpak.elf import ElfInfo
        everything = SimpleNamespace(provides=lambda so: True)
        lib = "opt/dana/usr/lib/"
        elfs = {lib + n: ElfInfo(path=n, machine="x86_64", elf_type=3, bits=64, soname=n.split(".so")[0] + ".so."
                                 + n.split(".so.")[1].split(".")[0])
                for n in ("libfreetype.so.6.11.1", "libharfbuzz.so.0.10200.4", "libQt5Gui.so.5")}
        sonames = {"libfreetype.so.6": lib + "libfreetype.so.6.11.1", "libfreetype.so.6.11.1": lib + "libfreetype.so.6.11.1",
                   "libharfbuzz.so.0": lib + "libharfbuzz.so.0.10200.4", "libQt5Gui.so.5": lib + "libQt5Gui.so.5"}
        self.assertEqual(partial_set_copies(elfs, sonames, everything),
                         {lib + "libfreetype.so.6.11.1": ["libfreetype.so.6", "libfreetype.so.6.11.1"],
                          lib + "libharfbuzz.so.0.10200.4": ["libharfbuzz.so.0"]})
        # the whole stack matches itself, and stays; a runtime without one of them can't stand in
        whole = dict(sonames, **{"libfontconfig.so.1": lib + "libfontconfig.so.1"})
        elfs[lib + "libfontconfig.so.1"] = ElfInfo(path="f", machine="x86_64", elf_type=3, bits=64)
        self.assertEqual(partial_set_copies(elfs, whole, everything), {})
        no_harfbuzz = SimpleNamespace(provides=lambda so: so != "libharfbuzz.so.0")
        self.assertEqual(partial_set_copies(elfs, sonames, no_harfbuzz), {})
        self.assertEqual(partial_set_copies(elfs, {"libQt5Gui.so.5": lib + "libQt5Gui.so.5"}, everything), {})
        # Carthage's PyInstaller build carries libxkbcommon-x11 without libxkbcommon, and crashed in the
        # runtime's xkb_state_update_derived
        x11 = "opt/carthage/_internal/libxkbcommon-x11.so.0"
        elfs[x11] = ElfInfo(path="x", machine="x86_64", elf_type=3, bits=64, soname="libxkbcommon-x11.so.0")
        self.assertEqual(partial_set_copies(elfs, {"libxkbcommon-x11.so.0": x11}, everything),
                         {x11: ["libxkbcommon-x11.so.0"]})
        both = {"libxkbcommon-x11.so.0": x11, "libxkbcommon.so.0": lib + "libfontconfig.so.1"}
        self.assertEqual(partial_set_copies(elfs, both, everything), {})
        # BiliBili ShadowReplay's rpm carries libglib-2.0 for its FFmpeg, not GObject, and the runtime's
        # libgobject-2.0 failed on it: "undefined symbol: g_string_copy"; a whole GLib stays
        glib = "usr/lib/bili-shadowreplay/ffmpeg-runtime/libglib-2.0.so.0"
        elfs[glib] = ElfInfo(path="g", machine="x86_64", elf_type=3, bits=64, soname="libglib-2.0.so.0")
        self.assertEqual(partial_set_copies(elfs, {"libglib-2.0.so.0": glib}, everything),
                         {glib: ["libglib-2.0.so.0"]})
        whole_glib = {so: glib for so in ("libglib-2.0.so.0", "libgobject-2.0.so.0", "libgio-2.0.so.0",
                                          "libgmodule-2.0.so.0")}
        self.assertEqual(partial_set_copies(elfs, whole_glib, everything), {})

    def test_a_gl_apps_copies_of_mesas_libraries_give_way_to_the_runtimes(self):
        # ommpfritt's AppImage carries Ubuntu 18.04's libzstd.so.1, too old for the runtime's libelf,
        # so the GL extension's libGLX_mesa.so.0 didn't load and Qt stopped at "Could not initialize
        # GLX"; an appimage-builder AppImage carries the OpenGL stack itself
        from types import SimpleNamespace
        from debpak.analyze import mesa_dependency_copies
        from debpak.elf import ElfInfo
        from debpak.runtime import EXTENSION_PROVIDED_PREFIXES
        rt_sonames = {"libzstd.so.1", "libz.so.1", "libstdc++.so.6", "libQt5Gui.so.5"}
        rt = SimpleNamespace(sonames=rt_sonames,
                             provides=lambda so: so in rt_sonames or so.startswith(EXTENSION_PROVIDED_PREFIXES),
                             versions_of=lambda so: {"ZLIB_1.2.0", "ZLIB_1.2.9"} if so == "libz.so.1" else
                             {"GLIBCXX_3.4", "GLIBCXX_3.4.33"} if so == "libstdc++.so.6" else None)
        lib = "opt/omm/usr/lib/"

        def elf(n, soname, needed=(), verdef=()):
            return ElfInfo(path=n, machine="x86_64", elf_type=3, bits=64, soname=soname,
                           needed=list(needed), verdef=set(verdef))
        elfs = {lib + "libzstd.so.1": elf("z", "libzstd.so.1"),
                lib + "libz.so.1": elf("z", "libz.so.1", verdef={"ZLIB_1.2.0", "ZLIB_1.2.12"}),
                lib + "libstdc++.so.6": elf("s", "libstdc++.so.6", verdef={"GLIBCXX_3.4"}),
                lib + "libelf.so.1": elf("e", "libelf.so.1"),
                lib + "libQt5Gui.so.5": elf("q", "libQt5Gui.so.5"),
                "opt/omm/usr/bin/omm": elf("b", "", needed=["libQt5Gui.so.5", "libzstd.so.1"])}
        sonames = {Path(rel).name: rel for rel in elfs if "/lib/" in rel}
        # no OpenGL: nothing goes
        self.assertEqual(mesa_dependency_copies(elfs, sonames, rt), {})
        # with Qt's GLX plugin: libzstd and libstdc++ go; libz defines a newer version, and the
        # runtime has no libelf, so they stay, as does Qt
        elfs[lib + "../plugins/xcbglintegrations/libqxcb-glx-integration.so"] = elf("g", "")
        self.assertEqual(mesa_dependency_copies(elfs, sonames, rt),
                         {lib + "libzstd.so.1": ["libzstd.so.1"], lib + "libstdc++.so.6": ["libstdc++.so.6"]})
        # the OpenGL stack goes whatever the runtime's index says, but not Electron's ANGLE
        app = "opt/app/usr/lib/x86_64-linux-gnu/"
        elfs = {app + "libGLX_mesa.so.0.0.0": elf("m", "libGLX_mesa.so.0"), app + "libGL.so.1.7.0": elf("g", "libGL.so.1"),
                "opt/app/libEGL.so": elf("a", "libEGL.so"), "opt/app/app": elf("b", "", needed=["libEGL.so"])}
        sonames = {"libGLX_mesa.so.0": app + "libGLX_mesa.so.0.0.0", "libGL.so.1": app + "libGL.so.1.7.0",
                   "libGL.so.1.7.0": app + "libGL.so.1.7.0", "libEGL.so": "opt/app/libEGL.so"}
        self.assertEqual(mesa_dependency_copies(elfs, sonames, rt),
                         {app + "libGLX_mesa.so.0.0.0": ["libGLX_mesa.so.0"],
                          app + "libGL.so.1.7.0": ["libGL.so.1", "libGL.so.1.7.0"]})
        # PonyPlayer's AppImage (appimage-builder): a second libzstd in another folder, Mesa's own
        # libEGL_mesa and libglapi, which no runtime index lists, and its dri drivers all go
        pony = "opt/pony/"
        elfs = {pony + "lib/x86_64-linux-gnu/libzstd.so.1": elf("z", "libzstd.so.1"),
                pony + "usr/lib/x86_64-linux-gnu/libzstd.so.1.4.4": elf("z", "libzstd.so.1"),
                pony + "lib/x86_64-linux-gnu/libEGL_mesa.so.0": elf("m", "libEGL_mesa.so.0", needed=["libglapi.so.0"]),
                pony + "lib/x86_64-linux-gnu/libglapi.so.0": elf("a", "libglapi.so.0"),
                pony + "lib/x86_64-linux-gnu/dri/iris_dri.so": elf("d", "", needed=["libglapi.so.0"]),
                pony + "lib/x86_64-linux-gnu/libQt6Gui.so.6": elf("q", "libQt6Gui.so.6", needed=["libEGL.so.1"]),
                pony + "lib/x86_64-linux-gnu/libva-drm.so.2": elf("v", "libva-drm.so.2")}
        sonames = {"libzstd.so.1": pony + "usr/lib/x86_64-linux-gnu/libzstd.so.1.4.4",
                   "libEGL_mesa.so.0": pony + "lib/x86_64-linux-gnu/libEGL_mesa.so.0",
                   "libglapi.so.0": pony + "lib/x86_64-linux-gnu/libglapi.so.0"}
        self.assertEqual(mesa_dependency_copies(elfs, sonames, rt),
                         {pony + "lib/x86_64-linux-gnu/libzstd.so.1": ["libzstd.so.1"],
                          pony + "usr/lib/x86_64-linux-gnu/libzstd.so.1.4.4": ["libzstd.so.1"],
                          pony + "lib/x86_64-linux-gnu/libEGL_mesa.so.0": ["libEGL_mesa.so.0"],
                          pony + "lib/x86_64-linux-gnu/libglapi.so.0": ["libglapi.so.0"],
                          pony + "lib/x86_64-linux-gnu/dri/iris_dri.so": ["iris_dri.so"]})

    def test_apprun_env_loses_its_gl_driver_settings(self):
        # PonyPlayer's appimage-builder AppRun.env points LIBGL_DRIVERS_PATH at the AppImage's own dri folder
        from types import SimpleNamespace
        from debpak.stage import _apprun_env
        with tempfile.TemporaryDirectory() as t:
            app = Path(t)
            opt = app / "opt/pony"
            opt.mkdir(parents=True)
            (opt / "AppRun").write_bytes(b"\x7fELF")
            (opt / "AppRun.env").write_text("APPDIR=$ORIGIN\nLIBGL_DRIVERS_PATH=$APPDIR/lib/x86_64-linux-gnu/dri\n"
                                            "__EGL_VENDOR_LIBRARY_DIRS=$APPDIR/usr/share/glvnd/egl_vendor.d\n"
                                            "GDK_PIXBUF_MODULEDIR=$APPDIR/usr/lib/gdk-pixbuf\n")
            res = SimpleNamespace(notes=[])
            _apprun_env(app, res)
            self.assertEqual((opt / "AppRun.env").read_text(),
                             "APPDIR=$ORIGIN\nGDK_PIXBUF_MODULEDIR=$APPDIR/usr/lib/gdk-pixbuf\n")
            self.assertIn("LIBGL_DRIVERS_PATH, __EGL_VENDOR_LIBRARY_DIRS", res.notes[0])
            # a file of that name without an AppRun beside it is left alone
            (opt / "AppRun").unlink()
            (opt / "AppRun.env").write_text("LIBGL_DRIVERS_PATH=x\n")
            _apprun_env(app, res)
            self.assertEqual((opt / "AppRun.env").read_text(), "LIBGL_DRIVERS_PATH=x\n")

    def test_inspect_cli(self):
        code, out = run_cli("inspect", str(self.fx.app_deb), "--runtime-index", str(self.index_path))
        self.assertEqual(code, 0, out)
        self.assertIn("libfake.so.1", out)
        self.assertIn("looks convertible", out)
        code, out = run_cli("inspect", str(self.fx.app_deb), "--json")
        self.assertEqual(json.loads(out)["entry_point"], "opt/Fake/launch.sh")

    # --- conversion
    def test_convert_bundle(self):
        out = self.out_dir("bundle")
        code, log = run_cli("convert", str(self.fx.app_deb), "--app-id", "org.example.FakeApp",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.fx.deps),
                            "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "org.example.FakeApp.json").read_text())
        self.assertEqual(m["runtime"], "org.test.Platform")
        self.assertEqual(m["sdk"], "org.test.Sdk")
        self.assertEqual(m["command"], "debpak-run")
        self.assertIn("--share=network", m["finish-args"])  # socket() import
        self.assertEqual(set(m["x-debpak"]["bundled-libraries"]), {"libfake.so.1", "libfakedep.so.2"})

        app = out / "app"
        wrapper = (app / "bin/debpak-run").read_text()
        self.assertIn('LD_LIBRARY_PATH="/app/lib/debpak', wrapper)
        # and in the app's linker cache, for a program that sets its own LD_LIBRARY_PATH:
        # ZoomLauncher ran zoom without the libgssapi_krb5.so.2 debpak had added
        self.assertEqual((app / "etc/ld.so.conf").read_text(), "/app/lib/debpak\n")
        self.assertIn("export FAKE_MODE=1", wrapper)
        # `flatpak run` passes no arguments: the launcher then passes the menu entry's
        self.assertIn('[ "$#" -gt 0 ] || set -- --flag \'a b\'\n/app/opt/Fake/launch.sh "$@"', wrapper)
        self.assertTrue(os.access(app / "bin/debpak-run", os.X_OK))

        launch = (app / "opt/Fake/launch.sh").read_text()
        self.assertIn("cd /app/opt/Fake", launch)
        self.assertIn("exec /app/opt/Fake/fakeapp", launch)

        desktop = (app / "share/applications/org.example.FakeApp.desktop").read_text()
        self.assertIn('Exec=debpak-run --flag "a b" %U', desktop)
        self.assertIn("Icon=org.example.FakeApp", desktop)
        self.assertTrue((app / "share/icons/hicolor/64x64/apps/org.example.FakeApp.png").is_file())
        self.assertIn("<id>org.example.FakeApp</id>",
                      (app / "share/metainfo/org.example.FakeApp.metainfo.xml").read_text())

        self.assertFalse((app / "etc/cron.daily").exists())
        self.assertFalse((app / "share/applications/fakeapp.desktop").exists())
        self.assertTrue((app / "share/doc/fakeapp/copyright").is_file())
        link = app / "bin/fakeapp"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "../opt/Fake/launch.sh")

        # the bundled closure actually satisfies the binary's dependencies
        run = subprocess.run([str(app / "opt/Fake/fakeapp")], capture_output=True, text=True,
                             env={**os.environ, "LD_LIBRARY_PATH": str(app / "lib/debpak")})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "fakeapp says 42 4")

    def test_convert_extra_data(self):
        out = self.out_dir("extra")
        code, log = run_cli("convert", str(self.fx.app_deb), "--app-id", "org.example.FakeApp",
                            "--runtime-index", str(self.index_path), "--deps-dir", str(self.fx.deps),
                            "--mode", "extra-data", "--url", "https://example.com/fakeapp.deb", "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "org.example.FakeApp.json").read_text())
        extra = [s for s in m["modules"][0]["sources"] if s["type"] == "extra-data"][0]
        self.assertEqual(extra["size"], self.fx.app_deb.stat().st_size)
        self.assertEqual(len(extra["sha256"]), 64)
        app = out / "app"
        self.assertFalse((app / "opt").exists())  # vendor payload is NOT redistributed
        apply_extra = (app / "bin/apply_extra").read_text()
        self.assertIn("bsdtar -Oxf fakeapp.deb", apply_extra)
        self.assertIn("rm -rf etc/cron.daily", apply_extra)
        self.assertIn("/app/extra/opt/Fake", apply_extra)
        self.assertIn("\n/app/extra/opt/Fake/launch.sh", (app / "bin/debpak-run").read_text())

        # the generated sed program really rewrites the launcher
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            sed_line = next(ln for ln in apply_extra.splitlines() if ln.startswith("sed -i"))
            launch = pkg.root / "opt/Fake/launch.sh"
            # XPipe's AppRun: a path after a variable is relative to it, and stays
            launch.write_text(launch.read_text() + 'EXEC="${HERE}/opt/Fake/fakeapp"\n')
            subprocess.run(sed_line, shell=True, cwd=pkg.root, check=True)
            text = launch.read_text()
            self.assertIn("cd /app/extra/opt/Fake\n", text)
            self.assertIn("exec /app/extra/opt/Fake/fakeapp", text)
            self.assertIn('EXEC="${HERE}/opt/Fake/fakeapp"', text)

    def test_convert_without_deps_is_incomplete(self):
        code, log = run_cli("convert", str(self.fx.app_deb), "--runtime-index", str(self.index_path),
                            "-o", str(self.out_dir("nodeps")), "--no-auto-mirror")
        self.assertEqual(code, 2)
        self.assertIn("INCOMPLETE", log)
        self.assertFalse((self.out_dir("nodeps")).exists())

    def test_convert_fills_gaps_from_ubuntu_by_default(self):
        # Zoom, Viber, Google Earth and AppFlowy name no library source, and were refused for
        # libgssapi_krb5.so.2, libGLU.so.1 and libkeybinder-3.0.so.0, which Ubuntu has
        from debpak.resolve import LocalDebSource, MirrorSource
        asked = []
        with tempfile.TemporaryDirectory() as t:
            local = LocalDebSource(self.fx.deps, "x86_64", Path(t))

            def find(src, soname):
                asked.append((src.mirror, src.suite, soname))
                # Tiny RDM's webkit2gtk-4.0 is only in jammy; this stands in for such a library
                if soname == "libfakedep.so.2" and src.suite in ("noble", "jammy"):
                    return None
                return local.find(soname)
            out = self.out_dir("auto-mirror")
            with mock.patch.object(MirrorSource, "find", find):
                code, log = run_cli("convert", str(self.fx.app_deb), "--app-id", "org.example.FakeApp",
                                    "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("missing libraries come from Ubuntu noble", log)
        self.assertEqual(asked[0], ("http://archive.ubuntu.com/ubuntu", "noble", "libfake.so.1"))
        self.assertIn(("http://archive.ubuntu.com/ubuntu", "jammy", "libfakedep.so.2"), asked)
        self.assertIn(("http://archive.ubuntu.com/ubuntu", "focal", "libfakedep.so.2"), asked)
        m = json.loads((out / "org.example.FakeApp.json").read_text())
        self.assertEqual(set(m["x-debpak"]["bundled-libraries"]), {"libfake.so.1", "libfakedep.so.2"})
        self.assertNotIn("mirror", m["x-debpak"]["convert-options"])

    def test_a_program_the_package_depends_on_and_runs_is_added(self):
        # gorsync's RPM requires rsync and runs it; the runtime has no rsync, and the app stopped at start
        # with an error dialog it couldn't show. rsync comes from Ubuntu; git, which needs its git-core
        # folder, sudo, libraries and programs the app never names don't
        from debpak.resolve import add_programs, wanted_programs
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, Path(t) / "app")
            pkg.control["Depends"] = "libfoo1, rsync (>= 3), git, sudo, xdg-utils | wslu, zenity, gtk3"
            prog = pkg.root / "opt/Fake/fakeapp"
            with open(prog, "ab") as f:
                f.write(b"\x00*rsync.Options\x00git\x00sudo\x00zenity\x00xdg-utilsx\x00gtk3-dev\x00")
            self.assertEqual(wanted_programs(pkg, {"zenity", "sh"}), ["git", "rsync"])
            self.assertEqual(wanted_programs(pkg, {"zenity", "rsync", "git"}), [])

            class Dep:
                def __init__(self, name):
                    self.name, self.version, self.root = name, "1.0", Path(t) / "mirror" / name

            class Ubuntu:
                name, suite = "mirror", "noble"

                def _package(self, name):
                    dep = Dep(name)
                    return dep if dep.root.is_dir() else None
            for name in ("rsync", "git"):
                (Path(t) / f"mirror/{name}/usr/bin").mkdir(parents=True)
                shutil.copy2(self.fx.src / "fakeapp", Path(t) / f"mirror/{name}/usr/bin/{name}")
            (Path(t) / "mirror/git/usr/lib/git-core").mkdir(parents=True)
            with open(Path(t) / "mirror/git/usr/bin/git", "ab") as f:
                f.write(b"\x00/usr/lib/git-core\x00")
            added = add_programs(["git", "rsync"], [Ubuntu()], pkg.root)
            self.assertEqual(added, {"rsync": "rsync (1.0) from noble"})
            self.assertTrue(os.access(pkg.root / "usr/bin/rsync", os.X_OK))
            self.assertFalse((pkg.root / "usr/bin/git").exists())
            # the package carries rsync now, so it isn't wanted again
            self.assertEqual(wanted_programs(pkg, {"zenity"}), ["git"])

    def test_a_library_only_helper_programs_need_doesnt_stop_the_app(self):
        # VideoJaNai's tarball: aji_kernel_test and aji_harness need NVIDIA's libcudart.so.13, which no
        # source has; its own program doesn't, so they no longer stop it. A script entry point might
        # start any program, and one whose own program needs the library is still stopped
        import dataclasses
        from debpak.analyze import helper_only_needs
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.app_deb, t), self.index)
            info = a.elfs["opt/Fake/fakeapp"]
            a.elfs["opt/Fake/inference/aji_kernel_test"] = dataclasses.replace(info, needed=["libcudart.so.13"])
            a.elfs["opt/Fake/libaji_trt.so"] = dataclasses.replace(info, needed=["libnvinfer.so.11"], interp=None)
            a.missing_hard |= {"libcudart.so.13"}
            a.missing_soft |= {"libnvinfer.so.11"}
            unresolved = {"libcudart.so.13", "libnvinfer.so.11"}
            a.main_exec, a.main_exec_is_script = "opt/Fake/fakeapp", False
            self.assertEqual(helper_only_needs(a, unresolved),
                             {"libcudart.so.13": ["opt/Fake/inference/aji_kernel_test"]})
            a.main_exec_is_script = True
            self.assertEqual(helper_only_needs(a, unresolved), {})
            a.main_exec_is_script = False
            self.assertEqual(helper_only_needs(a, unresolved | {"libfake.so.1"}), {})

    def test_an_avalonia_app_with_no_menu_entry_gets_a_window(self):
        # VideoJaNai is a .NET app drawn by Avalonia, which opens X11 itself; it has no .desktop file
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            shutil.rmtree(pkg.root / "usr/share/applications")
            self.assertIsNone(analyze(pkg, self.index).gui_reason())
            (pkg.root / "opt/Fake/Avalonia.X11.dll").write_bytes(b"MZ")
            a = analyze(pkg, self.index)
            self.assertIn("Avalonia.X11.dll", a.gui_reason())
            perms = infer(set(), set(), a.kind, gui=a.gui_reason())
            self.assertIn("--socket=x11", [p.arg for p in perms])
            # FPV DVR Cleaner: a single-file .NET program, with Avalonia.X11.dll inside it
            (pkg.root / "opt/Fake/Avalonia.X11.dll").unlink()
            prog = pkg.root / "opt/Fake/fakeapp"
            with open(prog, "ab") as f:
                f.write(b"\x00Avalonia.X11.dll\x00")
            self.assertIsNone(analyze(pkg, self.index).gui_reason())     # not .NET's host
            with open(prog, "ab") as f:
                f.write(b"\x00DOTNET_ROOT\x00")
            self.assertIn("Avalonia.X11.dll", analyze(pkg, self.index).gui_reason())

    def test_an_app_with_the_aws_sdk_reads_the_aws_profiles(self):
        # DynamoIt's jar carries the AWS SDK for Java, which reads ~/.aws/credentials; without the folder
        # it stopped with "profile file cannot be null" even where the user had a profile
        from debpak.cli import _home_permissions
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            self.assertEqual(analyze(pkg, self.index).tool_settings, {})
            (pkg.root / "opt/Fake/app.jar").write_bytes(b"PK\x03\x04com/amazonaws/auth/profile/ProfilesConfigFile.class")
            a = analyze(pkg, self.index)
            self.assertEqual(a.tool_settings, {".aws": "opt/Fake/app.jar"})
            self.assertIn("--filesystem=~/.aws:ro", [p.arg for p in _home_permissions(a)])


    def test_an_avalonia_app_in_one_file_gets_a_window(self):
        # FPV DVR Cleaner is one .NET program published as a single file: Avalonia.X11.dll is inside it,
        # named only in the bundle's manifest at its end, and the app got no X11 socket
        import struct
        from debpak.analyze import DOTNET_BUNDLE_SIGNATURE, dotnet_bundle_files
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            shutil.rmtree(pkg.root / "usr/share/applications")
            prog = pkg.root / "opt/Fake/fakeapp"
            body = prog.read_bytes()
            header = len(body) + 8 + 32 + 64
            manifest = b"\x06\x00\x00\x00\x1aFpvDvrCleaner.Launcher.dll\x10Avalonia.X11.dll\x0bApp.deps.json"
            prog.write_bytes(body + struct.pack("<q", header) + DOTNET_BUNDLE_SIGNATURE + bytes(64) + manifest)
            self.assertIn("Avalonia.X11.dll", dotnet_bundle_files(prog))
            a = analyze(pkg, self.index)
            self.assertEqual(a.main_exec, "opt/Fake/launch.sh")    # which runs fakeapp
            self.assertIn("Avalonia.X11.dll", a.gui_reason())
            # a program that isn't a bundle names nothing
            self.assertEqual(dotnet_bundle_files(self.fx.src / "fakeapp"), set())

    def test_an_mpris_player_may_own_its_mpris_name(self):
        # Festival registers org.mpris.MediaPlayer2.festival (souvlaki); refused it, the app panicked
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            self.assertFalse([n for n in analyze(pkg, self.index).bus_names if "mpris" in n])
            prog = pkg.root / "opt/Fake/fakeapp"
            prog.write_bytes(prog.read_bytes() + b"org.mpris.MediaPlayer2.Player\0/org/mpris/MediaPlayer2\0")
            a = analyze(pkg, self.index)
            self.assertIn("org.mpris.MediaPlayer2.fakeapp", a.bus_names)
            self.assertIn("org.mpris.MediaPlayer2.fakeapp.*", a.bus_names)
            perms = [p.arg for p in infer(set(), set(), a.kind, bus_names=a.bus_names)]
            self.assertIn("--own-name=org.mpris.MediaPlayer2.fakeapp", perms)

    def test_a_mirror_index_is_read_with_only_the_fields_debpak_uses(self):
        # Ubuntu noble's universe Packages index, read whole with every field kept, took over a gigabyte
        from debpak.resolve import PACKAGES_FIELDS, _stanzas
        text = ("Package: rsync\nVersion: 3.2.7\nDescription: fast\n copy\n .\n more\n"
                "Depends: libpopt0,\n zlib1g\nFilename: pool/r/rsync.deb\nSHA256: ab\n\n\n"
                "Package: two\nFilename: pool/t/two.deb\n")
        got = list(_stanzas(io.StringIO(text), PACKAGES_FIELDS))
        self.assertEqual(got, [{"Package": "rsync", "Version": "3.2.7", "Depends": "libpopt0,\nzlib1g",
                                "Filename": "pool/r/rsync.deb", "SHA256": "ab"},
                               {"Package": "two", "Filename": "pool/t/two.deb"}])

    def test_webkit_helpers_come_with_it(self):
        # Pot, a Tauri 1 app, needs webkit2gtk-4.0 from Ubuntu; WebKit starts WebKitNetworkProcess
        # from the folder beside it, so that folder goes along and the launcher points WebKit there
        from debpak.resolve import Provided, Source, fill_gaps
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            lib = Path(t) / "deb/usr/lib/x86_64-linux-gnu"
            (lib / "webkit2gtk-4.0/injected-bundle").mkdir(parents=True)
            shutil.copy2(self.fx.src / "libfake.so.1.0.0", lib / "libwebkit2gtk-4.0.so.37")
            shutil.copy2(self.fx.src / "fakeapp", lib / "webkit2gtk-4.0/WebKitNetworkProcess")

            class Ubuntu(Source):
                def find(self, soname):
                    f = lib / soname
                    return Provided(soname, f, "libwebkit2gtk-4.0-37 from jammy") if f.is_file() else None
            res = fill_gaps({"libwebkit2gtk-4.0.so.37"}, self.index, set(), [Ubuntu()], Path(t) / "stage")
            self.assertIn("libwebkit2gtk-4.0.so.37", res.bundled)
            self.assertTrue((Path(t) / "stage/webkit2gtk-4.0/WebKitNetworkProcess").is_file())
            a = analyze(extract(self.fx.app_deb, Path(t) / "app"), self.index)
            text = wrapper_script(a, "bundle", [], {"WEBKIT_EXEC_PATH": "/app/lib/debpak/webkit2gtk-4.0"})
            self.assertIn("export WEBKIT_EXEC_PATH=/app/lib/debpak/webkit2gtk-4.0\n", text)

    def test_writable_runs_from_a_copy(self):
        # Factorio and Etterna write next to themselves; --writable runs them from a copy in the app's data
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.app_deb, Path(t) / "app"), self.index)
            a.main_exec, a.writable = "opt/fake game/bin/fakeapp", True
            text = wrapper_script(a, "bundle", [])
            self.assertIn("debpak-writable/fake-game", text)
            self.assertIn('/debpak-writable/fake-game/bin/fakeapp" "$@"', text)
            self.assertEqual(subprocess.run(["sh", "-n"], input=text, text=True).returncode, 0)

    def test_bypassed_script_that_changes_into_its_folder_starts_the_program_there(self):
        # Firestorm's snap runs ./firestorm, which does cd "${RUN_PATH}" before starting its CEF
        # program bin/do-not-directly-run-firestorm-bin; started from home instead, that found no
        # app_settings/ and showed "Missing Files"
        from debpak.analyze import script_start_folder
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            snap = t / "opt/fs"
            write = lambda rel, text: ((snap / rel).parent.mkdir(parents=True, exist_ok=True),
                                       (snap / rel).write_text(text))
            write(".debpak-snap/firestorm", '#!/bin/sh\nSNAP="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"\n'
                                            'exec "$SNAP/./firestorm" "$@"\n')
            write("firestorm", '#!/bin/bash\nSCRIPTSRC=`readlink -f "$0" || echo "$0"`\n'
                               'RUN_PATH=`dirname "${SCRIPTSRC}" || echo .`\ncd "${RUN_PATH}"\n'
                               'bin/do-not-directly-run-firestorm-bin "$@"\n')
            write("plain", '#!/bin/sh\nX="$(cd "$(dirname "$0")" && pwd)"\nexec "$X/bin/app"\n')
            self.assertEqual(script_start_folder(t, "opt/fs/.debpak-snap/firestorm"), "opt/fs")
            self.assertEqual(script_start_folder(t, "opt/fs/firestorm"), "opt/fs")
            self.assertIsNone(script_start_folder(t, "opt/fs/plain"))     # a cd in $(...) changes nothing

            a = analyze(extract(self.fx.app_deb, t / "app"), self.index)
            a.main_exec, a.main_exec_is_script = "opt/fs/bin/do-not-directly-run-firestorm-bin", False
            a.chdir, a.chdir_to = "opt/fs/.debpak-snap/firestorm starts it in opt/fs", "opt/fs"
            self.assertIn("cd /app/opt/fs || exit 1", wrapper_script(a, "bundle", []))

    def test_script_that_uses_its_own_folder_starts_there(self):
        # Mercury's start script runs ./mercury/mercury, which is only found from the script's own folder;
        # the launcher starts it there, and a file named relative to where it was started keeps working
        from debpak.analyze import relative_reference
        from debpak.stage import wrapper_script
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            game = t / "game"
            (game / "mercury").mkdir(parents=True)
            (game / "mercury/mercury").write_text("#!/bin/sh\necho \"$PWD\" \"$@\"\n")
            (game / "mercury/mercury").chmod(0o755)
            (game / "start.sh").write_text("#!/bin/sh\n./mercury/mercury \"$@\"  # see https://x.org/a/b\n")
            (game / "start.sh").chmod(0o755)
            self.assertEqual(relative_reference(game / "start.sh"), "./mercury/mercury")
            (game / "own.sh").write_text('#!/bin/sh\ncd "$(dirname "$0")"\n./mercury/mercury\n')
            self.assertIsNone(relative_reference(game / "own.sh"))
            (game / "other.sh").write_text("#!/bin/sh\nexec usr/bin/thing ./nothing/here\n")
            self.assertIsNone(relative_reference(game / "other.sh"))

            a = analyze(extract(self.fx.app_deb, t / "app"), self.index)
            a.main_exec, a.main_exec_is_script = "opt/game/start.sh", True
            a.chdir = "opt/game/start.sh uses ./mercury/mercury relative to the folder it's started in"
            text = wrapper_script(a, "bundle", []).replace("/app/opt/game", str(game))
            (t / "here").mkdir()
            (t / "here/save.txt").write_text("")
            r = subprocess.run(["sh", "-c", text, "debpak-run", "save.txt", "--flag", "/abs"], cwd=t / "here",
                               capture_output=True, text=True)
            self.assertEqual(r.stdout.strip(), f"{game} {t}/here/save.txt --flag /abs", r.stderr)

    def test_launcher_script_that_runs_pkexec_and_notify_send_goes_on(self):
        # Plover's AppRun runs notify-send and then pkexec, to install a udev rule, at every start under
        # set -e: notify-send found no notification service and the app exited with status 1. The
        # launcher's stand-ins skip the root step with status 0, run a program of the app's own as the
        # user, and let a notification fail quietly
        from debpak.analyze import script_stub_commands
        from debpak.stage import STUB_DIR, stub_files, wrapper_script
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            run = t / "AppRun"
            run.write_text('#!/bin/bash\nset -e\nif [ ! -f /etc/udev/rules.d/99-x.rules ]; then\n'
                           '  notify-send -t 10000 "Installing udev rules" "You will be prompted"\n'
                           '  pkexec bash -c "groupadd plover; udevadm trigger"\nfi\n'
                           'echo "or run it with sudo" && exec sudo -E "$APPDIR/usr/bin/python" -m plover\n')
            self.assertEqual(script_stub_commands(run), ["pkexec", "sudo", "notify-send"])
            (t / "talk.sh").write_text('#!/bin/sh\n# sudo make install\necho "needs sudo or pkexec"\n')
            self.assertEqual(script_stub_commands(t / "talk.sh"), [])
            (t / "tool.py").write_text("#!/usr/bin/python3\nsudo = 1\n")
            self.assertEqual(script_stub_commands(t / "tool.py"), [])

            a = analyze(extract(self.fx.app_deb, t / "app"), self.index)
            a.main_exec, a.main_exec_is_script, a.script_stubs = "opt/plover/AppRun", True, ["pkexec", "notify-send"]
            self.assertIn(f'export PATH="/app/{STUB_DIR}:$PATH"', wrapper_script(a, "bundle", []))
            stubs = t / "stubs"
            stubs.mkdir()
            a.script_stubs = ["pkexec", "sudo", "notify-send"]
            for n, text in stub_files(a).items():
                (stubs / n).write_text(text.replace("/usr/bin/notify-send", str(t / "missing")))
                (stubs / n).chmod(0o755)
            env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}
            r = subprocess.run(["bash", "-c", 'set -e; notify-send a b; pkexec bash -c "touch $0"; '
                                'sudo -u root -E VAR=1 sh -c "touch $0"; echo went-on', str(t / "made")],
                               env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "went-on")
            self.assertIn("skipped pkexec bash", r.stderr)
            self.assertFalse((t / "made").exists())
            # a program of the app's own is run, as the user
            text = (stubs / "pkexec").read_text()
            self.assertIn("/app/*) exec", text)
            (stubs / "pkexec").write_text(text.replace("/app/*", f"{t}/*"))
            (t / "own.sh").write_text(f'#!/bin/sh\ntouch {t}/made\n')
            (t / "own.sh").chmod(0o755)
            r = subprocess.run(["pkexec", "--user", "root", str(t / "own.sh")], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((t / "made").exists())

    def test_service_is_blocked(self):
        code, log = run_cli("convert", str(self.fx.service_deb), "--runtime-index", str(self.index_path),
                            "--deps-dir", str(self.fx.deps), "-o", str(self.out_dir("svc")))
        self.assertEqual(code, 2)
        self.assertIn("NOT CONVERTIBLE", log)
        self.assertIn("system service", log)

    def test_electron(self):
        out = self.out_dir("electron")
        code, log = run_cli("convert", str(self.fx.electron_deb), "--app-id", "com.example.Zap",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "com.example.Zap.json").read_text())
        self.assertEqual(m["base"], "org.electronjs.Electron2.BaseApp")
        self.assertIn("--device=dri", m["finish-args"])
        self.assertIn("\nzypak-wrapper /app/opt/Zap/zap", (out / "app/bin/debpak-run").read_text())
        self.assertIn("setuid helper", log)

    def test_categories_get_their_main_category(self):
        from debpak.desktop import fix_categories, rewrite_desktop
        self.assertEqual(fix_categories("TerminalEmulator;"), "TerminalEmulator;System;")   # Hyper
        self.assertEqual(fix_categories("Utility;TerminalEmulator;"), "Utility;TerminalEmulator;")
        self.assertEqual(fix_categories("Development;IDE;"), "Development;IDE;")
        self.assertEqual(fix_categories("IDE;Debugger"), "IDE;Debugger;Development;")
        self.assertEqual(fix_categories("Network;WebBrowser;"), "Network;WebBrowser;")
        # appstreamcli compose drops an app with no main category (no-valid-category) and the build fails:
        # Jan (Tauri) writes an empty Categories=, AppFlowy a made-up one
        self.assertEqual(fix_categories("X-Vendor;"), "X-Vendor;Utility;")
        self.assertEqual(fix_categories(""), "Utility;")
        self.assertEqual(fix_categories("Productivity;"), "Productivity;Utility;")
        self.assertEqual(fix_categories("Network;Productivity;"), "Network;Productivity;")
        text = rewrite_desktop("[Desktop Entry]\nName=Hyper\nExec=/opt/Hyper/hyper %U\n"
                               "Categories=TerminalEmulator;\n", "com.example.Hyper", "debpak-run")
        self.assertIn("Categories=TerminalEmulator;System;", text)
        text = rewrite_desktop("[Desktop Entry]\nName=Jan\nExec=Jan-Desktop\nCategories=\n", "com.example.Jan", "x")
        self.assertIn("\nCategories=Utility;\n", text)
        text = rewrite_desktop("[Desktop Entry]\nName=A\nExec=a\n\n[Desktop Action n]\nExec=a -n\n",
                               "com.example.A", "x")
        self.assertEqual(text, "[Desktop Entry]\nName=A\nExec=x\nCategories=Utility;\n\n"
                               "[Desktop Action n]\nExec=x -n\n")

    def test_icons_over_512px_are_skipped(self):
        from debpak.desktop import install_icons
        from fixtures import tiny_png
        with tempfile.TemporaryDirectory() as t:
            root, share = Path(t) / "root", Path(t) / "app/share"
            for size in ("1024x1024", "512x512", "256x256@2"):
                p = root / "usr/share/icons/hicolor" / size / "apps/hyper.png"
                p.parent.mkdir(parents=True)
                p.write_bytes(tiny_png(16))
            installed, warnings = install_icons(root, "hyper", share, "com.example.Hyper")
            self.assertEqual(sorted(Path(i).parts[3] for i in installed), ["256x256@2", "512x512"])
            self.assertTrue(any("1024x1024" in w for w in warnings))
            # an image bigger than its folder says is rejected by flatpak too (1Password)
            odd = root / "usr/share/icons/hicolor/48x48/apps/hyper.png"
            odd.parent.mkdir(parents=True)
            odd.write_bytes(tiny_png(49))
            installed, warnings = install_icons(root, "hyper", share, "com.example.Hyper")
            self.assertNotIn("48x48", " ".join(installed))
            self.assertTrue(any("49x49" in w for w in warnings))

    def test_only_icon_over_512px_is_scaled_down(self):
        # Xenia's only icon is 1024x1024, and flatpak build-export refused it: "Image too large"
        from debpak.desktop import install_icons, png_size
        from debpak.winres import _png
        with tempfile.TemporaryDirectory() as t:
            root, share = Path(t) / "root", Path(t) / "app/share"
            p = root / "usr/share/icons/hicolor/1024x1024/apps/xenia.png"
            p.parent.mkdir(parents=True)
            p.write_bytes(_png(1024, 1024, bytes([200, 10, 10, 255]) * (1024 * 1024)))
            installed, _ = install_icons(root, "xenia", share, "com.example.Xenia")
            self.assertIn("share/icons/hicolor/512x512/apps/com.example.Xenia.png", installed)
            self.assertEqual(png_size(share / "icons/hicolor/512x512/apps/com.example.Xenia.png"), (512, 512))

    def test_hidpi_icon_over_512px_is_skipped(self):
        # Uncode's 512x512@2x icon is 1024 pixels: flatpak build-export refused it
        from debpak.desktop import install_icons
        from debpak.winres import _png
        with tempfile.TemporaryDirectory() as t:
            root, share = Path(t) / "root", Path(t) / "app/share"
            for size, px in (("512x512", 512), ("512x512@2x", 1024), ("128x128@2", 256)):
                p = root / "usr/share/icons/hicolor" / size / "apps/uncode.png"
                p.parent.mkdir(parents=True)
                p.write_bytes(_png(px, px, bytes(4) * (px * px)))
            installed, _ = install_icons(root, "uncode", share, "com.example.Uncode")
            self.assertEqual(sorted(Path(i).parts[3] for i in installed), ["128x128@2", "512x512"])

    def test_png_icons_are_made_square(self):
        # Satisfactory Mod Manager's 64x64 icon is 64x61, and flatpak-validate-icon refuses it
        from debpak.desktop import install_icons
        from debpak.winres import _png, png_pixels
        with tempfile.TemporaryDirectory() as t:
            root, share = Path(t) / "root", Path(t) / "app/share"
            p = root / "usr/share/icons/hicolor/64x64/apps/smm.png"
            p.parent.mkdir(parents=True)
            p.write_bytes(_png(64, 61, b"\x10\x20\x30\xff" * 64 * 61))
            installed, warnings = install_icons(root, "smm", share, "com.example.SMM")
            self.assertEqual(installed, ["share/icons/hicolor/64x64/apps/com.example.SMM.png"])
            w, h, rgba = png_pixels((share.parent / installed[0]).read_bytes())
            self.assertEqual((w, h), (64, 64))
            self.assertEqual(rgba[:4], b"\0\0\0\0")                          # the added row is transparent
            self.assertEqual(rgba[64 * 4 * 2:64 * 4 * 2 + 4], b"\x10\x20\x30\xff")
            self.assertTrue(any("64x61" in w for w in warnings))

    def test_svg_icons_are_made_square(self):
        # AppFlowy's appflowy.svg: "Expected a square icon but got: 41x40", and flatpak's export fails
        import gzip
        from debpak.desktop import install_icons, square_svg
        with tempfile.TemporaryDirectory() as t:
            root, share = Path(t) / "root", Path(t) / "app/share"
            src = root / "usr/share/icons/hicolor/scalable/apps/appflowy.svg"
            src.parent.mkdir(parents=True)
            src.write_text('<?xml version="1.0"?>\n<svg width="41" height="40" viewBox="0 0 41 40" fill="none" '
                           'xmlns="http://www.w3.org/2000/svg"><path stroke-width="2" d="M0 0h41v40z"/></svg>\n')
            installed, warnings = install_icons(root, "appflowy", share, "com.example.AppFlowy")
            self.assertEqual(installed, ["share/icons/hicolor/scalable/apps/com.example.AppFlowy.svg"])
            out = (share.parent / installed[0]).read_text()
            self.assertIn('<svg width="41" height="41" viewBox="0 -0.5 41 41" fill="none"', out)
            self.assertIn('stroke-width="2"', out)
            self.assertTrue(any("isn't square" in w for w in warnings))

            def squared(text: str, name: str = "i.svg"):
                f = Path(t) / name
                f.write_bytes(gzip.compress(text.encode()) if name.endswith("z") else text.encode())
                r = square_svg(f)
                return r if r is None else (gzip.decompress(r) if name.endswith("z") else r).decode()
            self.assertIn('viewBox="-5 0 20 20"', squared('<svg viewBox="0 0 10 20"><g/></svg>'))
            self.assertIn('<svg width="32" height="32" viewBox="0 -4 32 32">',
                          squared('<svg width="32px" height="24px"><g/></svg>'))
            self.assertIn('height="20" viewBox="0 -5 20 20"', squared('<svg width="20" height="10">', "i.svgz"))
            self.assertIsNone(squared('<svg width="48" height="48" viewBox="0 0 10 20"/>'))  # square already
            self.assertIsNone(squared('<svg width="10mm" height="20mm"/>'))                 # units: left alone

    def test_udev_reload_is_a_warning(self):
        # Webex reloads udev rules for headsets; the app itself runs without them
        from debpak.maintscripts import analyze_scripts
        (f,) = analyze_scripts({"postinst": "#!/bin/sh\nudevadm control --reload-rules\n"})
        self.assertEqual(f.category, "warn")

    def test_runtime_is_installed_for_the_build(self):
        from debpak import cli
        calls = []

        def load(args, fallback, arch):
            if not calls:
                raise RuntimeError("runtime org.kde.Platform/x86_64/6.9 is not installed. Install it with: ...")
            return RuntimeIndex.load(self.index_path)
        out, buf = self.out_dir("autoruntime"), io.StringIO()
        real_which = cli.shutil.which
        with mock.patch.object(cli, "_load_runtime", side_effect=load), \
                mock.patch.object(cli, "_install_runtime", side_effect=lambda r, a: calls.append(r) or True), \
                mock.patch.object(cli.shutil, "which", side_effect=lambda t, *a: "/usr/bin/flatpak-builder"
                                  if t == "flatpak-builder" else real_which(t, *a)), \
                mock.patch("debpak.manage.flathub_search", return_value=[]), \
                mock.patch.object(cli, "_run_teed", return_value=(1, "")), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            main(["convert", str(self.fx.app_deb), "--deps-dir", str(self.fx.deps), "-o", str(out)])
        self.assertEqual(len(calls), 1, buf.getvalue())
        self.assertIn("Building and installing", buf.getvalue())       # it went on to the build

    def test_electron_behind_a_launcher_script(self):
        # Running the script would start Electron without zypak, and Chromium aborts on its sandbox
        out = self.out_dir("electron-script")
        code, log = run_cli("convert", str(self.fx.electron_script_deb), "--app-id", "com.example.Zap",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("\nzypak-wrapper /app/opt/Zap/zap ", (out / "app/bin/debpak-run").read_text())
        self.assertIn("is a script, so the launcher runs the Electron binary", log)
        # an Electron program takes Chromium's own --no-sandbox, and then runs without zypak
        code, log = run_cli("convert", str(self.fx.electron_script_deb), "--app-id", "com.example.Zap",
                            "--no-chromium-sandbox", "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn('\n/app/opt/Zap/zap --no-sandbox "$@"\n', (out / "app/bin/debpak-run").read_text())
        # vendor binaries go in untouched: flatpak-builder would strip them into a .Debug extension
        manifest = json.loads((out / "com.example.Zap.json").read_text())
        self.assertEqual(manifest["build-options"], {"no-debuginfo": True})

    def test_branded_chromium_behind_a_launcher_script(self):
        # Microsoft Edge: no chrome-sandbox (it's msedge-sandbox), so the launcher ran the
        # microsoft-edge script without zypak, and msedge aborted on its SUID sandbox
        out = self.out_dir("edge")
        code, log = run_cli("convert", str(self.fx.edge_deb), "--app-id", "com.example.Edge",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("kind:         electron", log)
        self.assertIn("entry point:  opt/microsoft/msedge/msedge  [", log)
        wrapper = (out / "app/bin/debpak-run").read_text()
        self.assertIn("\nzypak-wrapper /app/opt/microsoft/msedge/msedge ", wrapper)
        # what the script it doesn't run tells the browser (Slimjet won't start without its SLIMJET_WRAPPER)
        self.assertIn("\nexport CHROME_WRAPPER=/app/bin/debpak-run\nexport CHROME_DESKTOP=\"$FLATPAK_ID.desktop\"\n",
                      wrapper)
        # zypak stands in for the sandbox helper only under the name it's given; Edge found the real
        # msedge-sandbox, not setuid root, and aborted
        self.assertIn("export ZYPAK_SANDBOX_FILENAME=msedge-sandbox\n", wrapper)
        # Edge's welcome page failed on the empty list of browsers to import from, which is all
        # the sandbox lets it see, and stopped at a blank dialog with no browser window
        self.assertIn("\nzypak-wrapper /app/opt/microsoft/msedge/msedge --no-first-run \"$@\"\n", wrapper)
        # Opera names its files its own way: opera_sandbox and opera.pak beside the V8 snapshot
        from debpak.analyze import classify, sandbox_filename
        with tempfile.TemporaryDirectory() as t:
            opera = Path(t) / "opera-stable"
            opera.mkdir()
            prog = opera / "opera"
            prog.write_bytes((self.fx.src / "fakeapp").read_bytes() + b"\0opera_sandbox\0")
            for name in ("opera_sandbox", "opera.pak", "v8_context_snapshot.bin"):
                (opera / name).write_bytes(b"\0")
            names = {p.name for p in opera.iterdir()}
            self.assertEqual(classify(opera, set(), names)[0], "electron")
            self.assertEqual(sandbox_filename(opera, "opera"), "opera_sandbox")
        # Qt WebEngine has the snapshot and .pak files too: Dream-VoiceTraining is a Python and Qt 6 app
        names = {"v8_context_snapshot.bin", "qtwebengine_resources.pak", "QtWebEngineProcess",
                 "libQt6WebEngineCore.so.6", "python3.14"}
        self.assertNotEqual(classify(Path("/nonexistent"), set(), names)[0], "electron")
        self.assertEqual(classify(Path("/nonexistent"), {"libQt6Core.so.6"}, names)[0], "qt6")

    def test_only_a_browser_skips_the_first_run(self):
        # an Electron app's arguments are its own; one that opens web links is still no browser
        from debpak.stage import is_chromium_browser, wrapper_script
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.edge_deb, t), self.index)
            self.assertTrue(is_chromium_browser(a))
            desktop = a.root / a.desktop_file
            desktop.write_text(desktop.read_text().replace("MimeType=", "X-Mime="))
            self.assertFalse(is_chromium_browser(a))
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.electron_deb, t), self.index)
            desktop = a.root / a.desktop_file
            desktop.write_text(desktop.read_text() + "MimeType=x-scheme-handler/http;\n")
            self.assertFalse(is_chromium_browser(a))
            self.assertNotIn("--no-first-run", wrapper_script(a, "bundle", []))

    def test_chrome_sandbox_needs_no_zypak_name(self):
        out = self.out_dir("electron-sandbox-name")
        code, log = run_cli("convert", str(self.fx.electron_deb), "--app-id", "com.example.Zap",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertNotIn("ZYPAK_SANDBOX_FILENAME", (out / "app/bin/debpak-run").read_text())

    def test_electron_in_an_opt_folder_with_a_blank(self):
        # Beekeeper Studio's .rpm installs in "/opt/Beekeeper Studio"; Chromium split the path of
        # chrome-sandbox at the blank and the zygote died: "failed to execvp: /app/opt/Beekeeper"
        from fixtures import _build_deb, _control, _write
        d = self.base / "pkg-blank"
        app = d / "opt/Bee Studio"
        (app / "resources").mkdir(parents=True)
        shutil.copy2(self.fx.src / "fakeapp", app / "bee-bin")
        shutil.copy2(self.fx.src / "libfake.so.1.0.0", app / "libfake.so.1")
        shutil.copy2(self.fx.src / "libfakedep.so.2.0.0", app / "libfakedep.so.2")
        (app / "chrome-sandbox").write_bytes(b"\x00")
        (app / "resources/app.asar").write_bytes(b"asar")
        _write(app / "bee", '#!/bin/sh\nexec "/opt/Bee Studio/bee-bin" "$@"\n', 0o755)
        (d / "usr/bin").mkdir(parents=True)
        (d / "usr/bin/bee").symlink_to("/opt/Bee Studio/bee")
        _write(d / "usr/share/applications/bee.desktop",
               '[Desktop Entry]\nType=Application\nName=Bee\nExec="/opt/Bee Studio/bee" %U\n')
        _control(d, "bee")
        deb = _build_deb(d, self.base / "bee.deb")
        out = self.out_dir("blank")
        code, log = run_cli("convert", str(deb), "--app-id", "com.example.Bee",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        app_out = out / "app"
        self.assertIn("\nzypak-wrapper /app/opt/Bee-Studio/bee-bin ", (app_out / "bin/debpak-run").read_text())
        self.assertTrue((app_out / "opt/Bee-Studio/chrome-sandbox").is_file())
        self.assertEqual(os.readlink(app_out / "bin/bee"), "../opt/Bee-Studio/bee")
        self.assertIn('exec "/app/opt/Bee-Studio/bee-bin"', (app_out / "opt/Bee-Studio/bee").read_text())
        out = self.out_dir("blank-extra")
        code, log = run_cli("convert", str(deb), "--app-id", "com.example.Bee", "--mode", "extra-data",
                            "--url", "https://example.com/bee.deb", "--runtime-index", str(self.index_path),
                            "-o", str(out))
        self.assertEqual(code, 0, log)
        script = (out / "app/bin/apply_extra").read_text()
        self.assertIn("mv 'opt/Bee Studio' opt/Bee-Studio\n", script)
        self.assertIn("opt/Bee-Studio/bee\n", script)          # the sed runs on the moved file
        self.assertLess(script.index("mv 'opt/Bee Studio'"), script.index("sed -i"))
        self.assertIn("\nzypak-wrapper /app/extra/opt/Bee-Studio/bee-bin ", (out / "app/bin/debpak-run").read_text())

    def test_cef_app_without_desktop_file(self):
        # Webex: the guess picked opt/Webex/lib/libQt6Core.so.6 (runnable, largest, mode 0644),
        # and zypak-helper failed to exec it: Permission denied
        out = self.out_dir("webex")
        code, log = run_cli("convert", str(self.fx.webex_deb), "--app-id", "com.example.Webex",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        self.assertIn("kind:         cef", log)
        self.assertIn("entry point:  opt/Webex/bin/CiscoCollabHost  [largest executable ELF (guess)]", log)
        m = json.loads((out / "com.example.Webex.json").read_text())
        self.assertEqual(m["base"], "org.electronjs.Electron2.BaseApp")
        self.assertIn("--socket=x11", m["finish-args"])
        wrapper = (out / "app/bin/debpak-run").read_text()
        self.assertIn("export ZYPAK_CEF_LIBRARY_PATH=/app/opt/Webex/lib/libcef.so\n", wrapper)
        self.assertIn("\nzypak-wrapper /app/opt/Webex/bin/CiscoCollabHost ", wrapper)
        self.assertNotIn("ZYPAK_DISABLE_SANDBOX", wrapper)
        # with --no-chromium-sandbox (convert's check passes it after a crash at start) a CEF app keeps
        # zypak, with unsandboxed helpers: its program is the vendor's own and refuses --no-sandbox
        # (Amazon WorkSpaces: "Unknown option --no-sandbox")
        code, log = run_cli("convert", str(self.fx.webex_deb), "--app-id", "com.example.Webex", "--no-chromium-sandbox",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        wrapper = (out / "app/bin/debpak-run").read_text()
        self.assertIn("\nexport ZYPAK_DISABLE_SANDBOX=1\n", wrapper)
        self.assertIn("\nzypak-wrapper /app/opt/Webex/bin/CiscoCollabHost \"$@\"\n", wrapper)
        self.assertNotIn("--no-sandbox", wrapper)

    def test_writable_chromium_app_starts_its_helpers_in_the_apps_sandbox(self):
        # MiMo Studio, an Electron tarball, ran from its --writable copy in the app's data, which the
        # sandbox zypak gives Chromium's helpers can't see: its zygote failed to exec, and no window came
        out = self.out_dir("webex-writable")
        code, log = run_cli("convert", str(self.fx.webex_deb), "--app-id", "com.example.Webex", "--writable",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        wrapper = (out / "app/bin/debpak-run").read_text()
        self.assertIn("\nexport ZYPAK_DISABLE_SANDBOX=1\n", wrapper)
        self.assertIn('zypak-wrapper "${XDG_DATA_HOME:-$HOME/.local/share}/debpak-writable/Webex/bin/CiscoCollabHost"',
                      wrapper)

    def test_cef_app_without_its_sandbox_starts_directly(self):
        # Spotify ships no chrome-sandbox and runs CEF with the sandbox off; under zypak it
        # quit at once ("[2 zypak-helper] Wait found events, but sd-event found none"), and
        # Flathub's com.spotify.Client starts it directly
        from debpak.stage import uses_zypak, wrapper_script
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.webex_deb, t), self.index)
            self.assertTrue(uses_zypak(a))            # Webex loads an AppArmor profile for the sandbox
            a.findings = [f for f in a.findings if f.where != "postinst"]
            self.assertFalse(uses_zypak(a))
            wrapper = wrapper_script(a, "bundle", [])
            self.assertIn("\n/app/opt/Webex/bin/CiscoCollabHost \"$@\"\n", wrapper)
            self.assertNotIn("ZYPAK", wrapper)
            sandbox = a.root / "opt/Webex/lib/chrome-sandbox"
            shutil.copy2(a.root / "opt/Webex/bin/CiscoCollabHost", sandbox)
            a.elfs["opt/Webex/lib/chrome-sandbox"] = read_elf(sandbox)
            self.assertTrue(uses_zypak(a))

    def test_launcher_waits_for_what_the_program_leaves_running(self):
        # Sublime Text and Sublime Merge fork into the background and exit 0, and Rocket.Chat
        # restarts itself; Flatpak then ended the sandbox and the app with it
        from debpak.stage import WAIT_FOR_OTHERS
        if subprocess.run(["unshare", "-rpf", "--mount-proc", "true"], capture_output=True).returncode:
            self.skipTest("needs unshare with user and PID namespaces")
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            shutil.copy2(shutil.which("sleep"), t / "chrome_crashpad_handler")
            prog = t / "prog"
            prog.write_text(f"#!/bin/sh\n(sleep 1; touch {t}/forked) &\n{t}/chrome_crashpad_handler 60 &\nexit 3\n")
            prog.chmod(0o755)
            run = t / "debpak-run"
            run.write_text(f'#!/bin/sh\n{prog} "$@"\n{WAIT_FOR_OTHERS}\n')
            run.chmod(0o755)
            # outside a sandbox's PID namespace it waits for nothing
            r = subprocess.run([str(run)], timeout=20)
            self.assertEqual(r.returncode, 3)
            self.assertFalse((t / "forked").exists())
            time.sleep(1.5)
            (t / "forked").unlink()
            # as Flatpak runs it: bubblewrap's init (PID 1, which reaps orphans) starts it as PID 2
            init = ("import os, subprocess, sys\np = subprocess.Popen(sys.argv[1:])\nwhile True:\n"
                    "    pid, st = os.wait()\n    if pid == p.pid:\n        sys.exit(os.waitstatus_to_exitcode(st))\n")
            start = time.monotonic()
            r = subprocess.run(["unshare", "-rpf", "--mount-proc", sys.executable, "-I", "-c", init, str(run)],
                               timeout=30)
            self.assertEqual(r.returncode, 3)
            self.assertTrue((t / "forked").exists())    # it waited for the forked process ...
            self.assertLess(time.monotonic() - start, 20)   # ... but not for the crash reporter

    def test_first_run_files_for_the_home_folder(self):
        # Parsec copies /usr/share/parsec/skel into ~/.parsec, and with the skel at
        # /app/share/parsec/skel showed "File System Error - Skel Missing or Broken"
        from fixtures import _build_deb, _control
        d = self.base / "pkg-parsec"
        (d / "usr/bin").mkdir(parents=True)
        shutil.copy2(self.fx.src / "fakeapp", d / "usr/bin/parsecd")
        skel = d / "usr/share/parsec/skel"
        skel.mkdir(parents=True)
        (skel / "appdata.json").write_text('{"so_name": "parsecd-150-1.so"}\n')
        shutil.copy2(self.fx.src / "libfake.so.1.0.0", skel / "parsecd-150-1.so")
        _control(d, "parsec")
        deb = _build_deb(d, self.base / "parsec.deb")
        out = self.out_dir("parsec")
        code, log = run_cli("convert", str(deb), "--app-id", "com.example.Parsec", "--runtime-index",
                            str(self.index_path), "--deps-dir", str(self.fx.deps), "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "com.example.Parsec.json").read_text())
        self.assertIn("--persist=.parsec", m["finish-args"])
        wrapper = (out / "app/bin/debpak-run").read_text()
        self.assertIn("for f in /app/share/parsec/skel/*; do", wrapper)
        # run the copying part against the staged tree
        with tempfile.TemporaryDirectory() as home:
            seed = wrapper.split("\n/app/bin/parsecd")[0].replace("/app/share/", f"{out}/app/share/")
            (Path(home) / ".parsec").mkdir()
            (Path(home) / ".parsec/appdata.json").write_text("kept\n")
            subprocess.run(["sh", "-c", seed], env={**os.environ, "HOME": home}, check=True)
            self.assertEqual((Path(home) / ".parsec/appdata.json").read_text(), "kept\n")
            self.assertTrue((Path(home) / ".parsec/parsecd-150-1.so").is_file())

    def test_known_home_folder_is_kept(self):
        # Minecraft's launcher downloads itself into ~/.minecraft, a name its binary
        # builds at run time; on the sandbox's temporary home every start fetched
        # over 500 MB again and lost the sign-in and worlds
        from fixtures import _build_deb, _control
        d = self.base / "pkg-minecraft"
        (d / "usr/bin").mkdir(parents=True)
        shutil.copy2(self.fx.src / "fakeapp", d / "usr/bin/minecraft-launcher")
        _control(d, "minecraft-launcher")
        deb = _build_deb(d, self.base / "minecraft.deb")
        out = self.out_dir("minecraft")
        code, log = run_cli("convert", str(deb), "--app-id", "com.example.Minecraft", "--runtime-index",
                            str(self.index_path), "--deps-dir", str(self.fx.deps), "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "com.example.Minecraft.json").read_text())
        self.assertIn("--persist=.minecraft", m["finish-args"])
        self.assertIn("~/.minecraft", m["x-debpak"]["permission-reasons"]["--persist=.minecraft"])

    def test_desktop_file_kept_next_to_the_program(self):
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.webex_deb, t)
            (pkg.root / "opt/Webex/bin/webex.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Webex\nExec=/opt/Webex/bin/CiscoCollabHostCef %U\n")
            (pkg.root / "etc/xdg/autostart").mkdir(parents=True)
            (pkg.root / "etc/xdg/autostart/webex.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Webex\nExec=/opt/Webex/bin/CiscoCollabHost\n")
            a = analyze(pkg, self.index)
            self.assertEqual(a.main_exec, "opt/Webex/bin/CiscoCollabHostCef")
            self.assertEqual(a.desktop_file, "opt/Webex/bin/webex.desktop")

    def test_desktop_exec_link_made_by_postinst(self):
        # Google Earth Pro: the menu entry sits beside the program, and the link its Exec= names
        # may be one postinst makes; the entry point was libQt5Core.so.5 ("largest ELF (guess)")
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.webex_deb, t)
            app = pkg.root / "opt/google/earth/pro"
            app.mkdir(parents=True)
            (app / "googleearth").write_text('#!/bin/sh\ncd "$(dirname "$0")"\nexec ./googleearth-bin "$@"\n')
            (app / "googleearth").chmod(0o755)
            (app / "google-earth-pro").symlink_to("googleearth")
            (app / "google-earth-pro.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Google Earth Pro\nExec=/usr/bin/google-earth-pro %f\n")
            a = analyze(pkg, self.index)
            self.assertEqual(a.desktop_file, "opt/google/earth/pro/google-earth-pro.desktop")
            self.assertEqual(a.main_exec, "opt/google/earth/pro/googleearth")
            self.assertIn("found by name", a.main_exec_reason)

    def test_downloader_only_package_runs_under_zypak(self):
        # Discord 1.0.170's .deb and .tar.gz: a launcher script and updater_bootstrap, which fetches
        # the Electron client into ~/.config/discord at first start and runs it. Run under zypak, the
        # client inherits zypak's LD_PRELOAD and settings; ZYPAK_DISABLE_SANDBOX=1 lets Chromium's
        # helpers reach a program that isn't in /app
        from debpak.stage import stage
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            boot = pkg.root / "usr/share/fakeapp/updater_bootstrap"
            boot.parent.mkdir(parents=True)
            shutil.copy2(pkg.root / "opt/Fake/fakeapp", boot)
            a = analyze(pkg, self.index)
            self.assertFalse(a.blockers)
            (w,) = [f for f in a.findings if f.where == "usr/share/fakeapp/updater_bootstrap"]
            self.assertEqual(w.category, "warn")
            self.assertIn("com.discordapp.Discord", w.detail)
            self.assertEqual((a.kind, a.downloads_client), ("electron", "Discord"))
            perms = infer(set(), set(), a.kind)
            out = Path(t) / "out"
            res = stage(a, out, "com.example.Discord", "org.test.Platform/x86_64/1", "bundle", perms, {}, None)
            m = json.loads(res.manifest_path.read_text())
            self.assertEqual(m["base"], "org.electronjs.Electron2.BaseApp")
            self.assertIn("--socket=pulseaudio", m["finish-args"])
            wrapper = (out / "app/bin/debpak-run").read_text()
            self.assertIn("export ZYPAK_DISABLE_SANDBOX=1\n", wrapper)
            # zypak needs the program, not the vendor's script ("/app/bin/discord is not an ELF file",
            # then "Bootstrap failed" in the real .deb)
            self.assertIn('\nzypak-wrapper /app/share/fakeapp/updater_bootstrap "$@"', wrapper)
            self.assertNotIn("set --", wrapper)
            # with Discord's own script, its first-run download is done the same way, and the client
            # runs under zypak (updater_bootstrap alone stops: "required arguments were not provided")
            script = pkg.root / "usr/bin/discord"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text('#!/bin/sh\nCHANNEL=stable\nDOWNLOAD=https://updates.discord.com/\nDIR=discord\n'
                              'EXE=Discord\nexec "$discord_host" "$@"\n')
            script.chmod(0o755)
            a.bypassed_script = "usr/bin/discord"
            res = stage(a, Path(t) / "out2", "com.example.Discord", "org.test.Platform/x86_64/1", "bundle",
                        perms, {}, None)
            wrapper = (Path(t) / "out2/app/bin/debpak-run").read_text()
            self.assertIn('app_dir=$(/app/share/fakeapp/updater_bootstrap "$config_home"/discord stable '
                          'https://updates.discord.com/)', wrapper)
            self.assertIn('\nzypak-wrapper "$client" "$@"', wrapper)
            for sh in ("dash", "bash"):
                if shutil.which(sh):
                    subprocess.run([sh, "-n", str(Path(t) / "out2/app/bin/debpak-run")], check=True)

    def test_program_that_only_works_as_root_is_refused(self):
        # Raspberry Pi Imager: "You are not running as root. Please run with elevated privileges",
        # then it offers to restart itself with pkexec; a Flatpak can't give it root
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            prog = pkg.root / "opt/Fake/fakeapp"
            base = prog.read_bytes()
            prog.write_bytes(base + b"\x00It is not recommended to run as root.\x00sudo \x00")
            self.assertFalse([b for b in analyze(pkg, self.index).blockers if "needs root" in b])
            # a library's error table (Warp carries one) isn't the program asking for root
            prog.write_bytes(base + b"\x00requested operation requires superuser privilegemust be run as root"
                                    b"must be superuser\x00pkexec\x00")
            self.assertFalse([b for b in analyze(pkg, self.index).blockers if "needs root" in b])
            prog.write_bytes(base + b"\x00You are not running as root.\n\nPlease run with elevated privileges\x00")
            (b,) = [b for b in analyze(pkg, self.index).blockers if "needs root" in b]
            self.assertIn("opt/Fake/fakeapp", b)
            # Ventoy's GUI starts itself again with pkexec when it isn't root
            prog.write_bytes(base + b"\x00### Please run with root privileges. ###\x00"
                                    b"try restart self by pkexec ...\x00")
            self.assertTrue([b for b in analyze(pkg, self.index).blockers if "needs root" in b])
            # WireGuide starts its tunnel helper as root with pkexec, and quits without it
            prog.write_bytes(base + b"\x00pkexec not found: PolicyKit is required for privilege elevation \x00")
            self.assertTrue([b for b in analyze(pkg, self.index).blockers if "needs root" in b])

    def test_tray_library_loaded_by_name_is_bundled(self):
        # Tauri apps with a tray icon load libayatana-appindicator3 with dlopen() and panic without it
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            prog = pkg.root / "opt/Fake/fakeapp"
            base = prog.read_bytes()
            a = analyze(pkg, self.index, exec_override="/opt/Fake/fakeapp")
            self.assertNotIn("libayatana-appindicator3.so.1", a.missing_loaded)
            prog.write_bytes(base + b"\x00libayatana-appindicator3.so.1\x00libappindicator3.so.1\x00")
            a = analyze(pkg, self.index, exec_override="/opt/Fake/fakeapp")
            self.assertIn("libayatana-appindicator3.so.1", a.missing_loaded)

    def test_application_id_compiled_into_a_program_a_script_starts(self):
        # AppFlowy's AppImage starts AppFlowy through AppRun, a script; the ID is in AppFlowy
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            prog = pkg.root / "opt/Fake/fakeapp"
            prog.write_bytes(prog.read_bytes() + f"\x00io.{pkg.name}.{pkg.name}\x00".encode())
            run = pkg.root / "opt/Fake/AppRun"
            run.write_text('#!/bin/sh\nexec "$(dirname "$0")/fakeapp" "$@"\n')
            run.chmod(0o755)
            a = analyze(pkg, self.index, exec_override="/opt/Fake/AppRun")
            self.assertIn(f"io.{pkg.name}.{pkg.name}", a.bus_names)

    def test_application_id_compiled_into_the_program(self):
        # AppFlowy (Flutter) registers io.appflowy.appflowy, written nowhere but its binary
        from debpak.analyze import compiled_app_ids
        with tempfile.TemporaryDirectory() as t:
            prog = Path(t) / "AppFlowy"
            prog.write_bytes(b"\x7fELF..\x00io.appflowy.appflowy\x00org.gtk.Settings.FileChooser\x00"
                             b"com.example.other.thing\x00io.appflowy.appflowy\x00")
            self.assertEqual(compiled_app_ids(prog, {"appflowy", "AppFlowy"}), ["io.appflowy.appflowy"])
            self.assertEqual(compiled_app_ids(prog, {"unrelated"}), [])

    def test_program_that_runs_commands_on_the_host_from_a_flatpak(self):
        # WezTerm starts each pane's shell as flatpak-spawn --host when /.flatpak-info exists; without
        # org.freedesktop.Flatpak the shell exits at once and WezTerm quits (status 0) with no window
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            self.assertEqual(analyze(pkg, self.index).host_spawner, "")
            self.assertNotIn("--talk-name=org.freedesktop.Flatpak",
                             [p.arg for p in infer(set(), set(), "elf", host_spawner="")])
            prog = pkg.root / "opt/Fake/fakeapp"
            # Rust keeps its strings back to back, without NULs
            prog.write_bytes(prog.read_bytes() + b"mux::domain/.flatpak-info\x00flatpak-spawn--host--directory=")
            a = analyze(pkg, self.index)
            self.assertEqual(a.host_spawner, "opt/Fake/fakeapp")
            self.assertTrue([f for f in a.findings if f.category == "warn" and "outside the sandbox" in f.detail])
            perms = {p.arg: p.reason for p in infer(set(), set(), "elf", host_spawner=a.host_spawner)}
            self.assertIn("flatpak-spawn --host", perms["--talk-name=org.freedesktop.Flatpak"])

    def test_knowing_about_flatpak_is_not_enough_for_host_access(self):
        # GLib, Qt and Chromium check /.flatpak-info to use portals; only flatpak-spawn --host counts
        from debpak.analyze import host_spawner
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            prog = pkg.root / "opt/Fake/fakeapp"
            prog.write_bytes(prog.read_bytes() + b"\x00/.flatpak-info\x00org.freedesktop.portal.Flatpak\x00")
            elfs = {"opt/Fake/fakeapp": read_elf(prog)}
            self.assertEqual(host_spawner(pkg.root, elfs), "")
            prog.write_bytes(prog.read_bytes() + b"flatpak-spawn\x00\x00\x00--host\x00")    # C strings, aligned
            self.assertEqual(host_spawner(pkg.root, elfs), "opt/Fake/fakeapp")

    def test_menu_entry_arguments_are_for_its_own_program(self):
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            self.assertEqual(analyze(pkg, self.index).desktop_exec_args, ["--flag", "a b"])
            self.assertEqual(analyze(pkg, self.index, exec_override="/opt/Fake/fakeapp").desktop_exec_args, [])

    def test_apps_own_bus_names(self):
        # Xournal++ (GApplication) and Nextcloud (KDBusService) exit when they can't register their
        # reverse-DNS name, and inside a Flatpak only names under its own app ID are allowed
        from debpak.analyze import bus_names
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            r = pkg.root
            (r / "opt/Fake/com.github.fake.Fake.desktop").write_text(          # an AppImage's own .desktop
                "[Desktop Entry]\nName=Fake\nExec=fakeapp\nIcon=com.fake.desktopclient.fake\n"
                "X-DBUS-ServiceName=org.kde.fakeapp\n")
            (r / "usr/share/metainfo").mkdir(parents=True)
            (r / "usr/share/metainfo/io.fake.Fake.appdata.xml").write_text(
                '<?xml version="1.0"?>\n<component type="desktop-application">\n  <id>io.fake.Fake.desktop</id>\n'
                "</component>\n")
            services = r / "usr/share/dbus-1/services"
            services.mkdir(parents=True)
            for name, prog in (("com.fake.Helper", "/opt/Fake/fakeapp"), ("com.fake.Missing", "/usr/bin/nothere"),
                               ("org.freedesktop.Notifications", "/opt/Fake/fakeapp")):
                (services / f"{name}.service").write_text(f"[D-BUS Service]\nName={name}\nExec={prog} --daemon\n")
            names = bus_names(r)
            self.assertEqual(set(names), {"com.github.fake.Fake", "com.fake.desktopclient.fake", "org.kde.fakeapp",
                                          "io.fake.Fake", "com.fake.Helper"})
            self.assertIn("opt/Fake/com.github.fake.Fake.desktop", names["com.github.fake.Fake"])
            a = analyze(pkg, self.index)
            self.assertEqual(a.bus_names, names)
            perms = {p.arg: p.reason for p in infer(set(), set(), "elf", bus_names=a.bus_names)}
            self.assertIn("--own-name=io.fake.Fake", perms)
            self.assertIn("AppStream ID", perms["--own-name=io.fake.Fake"])
            self.assertFalse([p for p in perms if "freedesktop" in p])           # never a desktop service

    def test_usr_paths_in_scripts_are_rewritten(self):
        # Beyond Compare's /usr/bin/bcompare: BC_LIB=/usr/lib/beyondcompare, then ldd $BC_LIB/BCompare
        # ("ldd: /usr/lib/beyondcompare/BCompare: No such file or directory")
        from debpak.analyze import package_usr_prefix
        from debpak.stage import stage
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            r = pkg.root
            (r / "usr/lib/beyondcompare").mkdir(parents=True)
            shutil.copy2(r / "opt/Fake/fakeapp", r / "usr/lib/beyondcompare/BCompare")
            (r / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
            (r / "usr/lib/x86_64-linux-gnu/libbc.so").write_bytes(b"")
            (r / "usr/bin/bcompare").write_text(
                "#!/bin/sh\nBC_LIB=/usr/lib/beyondcompare\nexport BC_LIB\nldd $BC_LIB/BCompare | grep -q found\n"
                "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libbc.so:/usr/lib/x86_64-linux-gnu/libnot.so\n"
                "[ -d /usr/share/icons/hicolor ] && /usr/bin/env true\nexec \"$BC_LIB/BCompare\" \"$@\"\n")
            (r / "usr/bin/bcompare").chmod(0o755)
            self.assertEqual(package_usr_prefix(r, "/usr/lib/beyondcompare/BCompare"), "/usr/lib/beyondcompare")
            self.assertEqual(package_usr_prefix(r, "/usr/bin/bcompare"), "/usr/bin/bcompare")
            self.assertIsNone(package_usr_prefix(r, "/usr/bin/env"))
            self.assertIsNone(package_usr_prefix(r, "/usr/lib/x86_64-linux-gnu"))
            self.assertIsNone(package_usr_prefix(r, "/usr/lib/x86_64-linux-gnu/libnot.so"))
            self.assertEqual(package_usr_prefix(r, "/usr/lib/x86_64-linux-gnu/libbc.so"),
                             "/usr/lib/x86_64-linux-gnu/libbc.so")
            a = analyze(pkg, self.index)
            hits = {h.path: h.prefix for h in a.hardcoded if h.file == "usr/bin/bcompare"}
            self.assertEqual(hits, {"/usr/lib/beyondcompare": "/usr/lib/beyondcompare",
                                    "/usr/lib/x86_64-linux-gnu/libbc.so": "/usr/lib/x86_64-linux-gnu/libbc.so"})
            out = Path(t) / "out"
            stage(a, out, "com.example.BC", "org.test.Platform/x86_64/1", "bundle", [], {}, None)
            script = (out / "app/bin/bcompare").read_text()
            self.assertIn("BC_LIB=/app/lib/beyondcompare\n", script)
            self.assertIn("LD_PRELOAD=/app/lib/x86_64-linux-gnu/libbc.so:/usr/lib/x86_64-linux-gnu/libnot.so", script)
            self.assertIn("[ -d /usr/share/icons/hicolor ] && /usr/bin/env true", script)    # the runtime's

    def test_usr_paths_in_a_binary_are_pointed_at_app(self):
        # Ned's .deb: its program in /usr/lib/Ned looks for its settings in /usr/share/Ned, which in the
        # Flatpak is /app/share/Ned, a path of the same length; a path in /opt would get longer
        from debpak.stage import stage
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            r = pkg.root
            (r / f"usr/lib/{pkg.name}").mkdir(parents=True)
            (r / f"usr/share/{pkg.name}/config").mkdir(parents=True)
            prog = r / f"usr/lib/{pkg.name}/editor"
            shutil.copy2(r / "opt/Fake/fakeapp", prog)
            with open(prog, "ab") as f:
                f.write(f"\0/usr/share/{pkg.name}/config/app.json\0x/usr/share/{pkg.name}/merged\0".encode())
            only_usr = r / f"usr/lib/{pkg.name}/helper"
            shutil.copy2(r / "opt/Fake/fakeapp", only_usr)
            with open(only_usr, "ab") as f:
                f.write(f"\0/usr/lib/{pkg.name}/queries\0".encode())
            with open(prog, "ab") as f:
                f.write(b"\0/opt/Fake/data\0")
            a = analyze(pkg, self.index)
            out = Path(t) / "out"
            res = stage(a, out, "com.example.Ned", "org.test.Platform/x86_64/1", "bundle", [], {}, None)
            data = (out / f"app/lib/{pkg.name}/editor").read_bytes()
            self.assertIn(f"\0/app/share/{pkg.name}/config/app.json\0".encode(), data)
            self.assertIn(f"x/usr/share/{pkg.name}/merged\0".encode(), data)   # not where a string begins
            self.assertIn(b"\0/opt/Fake/data\0", data)
            self.assertIn(f"\0/app/lib/{pkg.name}/queries\0".encode(), (out / f"app/lib/{pkg.name}/helper").read_bytes())
            self.assertEqual(data[:4], b"\x7fELF")
            self.assertEqual(len(data), prog.stat().st_size)
            note = next(n for n in res.notes if n.startswith("binaries contain"))
            self.assertIn(f"usr/lib/{pkg.name}/editor", note)
            self.assertNotIn("helper", note)

    def test_share_data_is_linked_beside_a_program_in_lib(self):
        # Ned's .deb: its program in /usr/lib/Ned looks for its settings in resources/ beside itself, and
        # the package keeps them in /usr/share/Ned; what lib/Ned has of its own is left as it is
        from debpak.stage import stage
        with tempfile.TemporaryDirectory() as t:
            pkg = extract(self.fx.app_deb, t)
            r = pkg.root
            name = pkg.name
            (r / f"usr/lib/{name}/queries").mkdir(parents=True)
            (r / f"usr/share/{name}/resources/config").mkdir(parents=True)
            (r / f"usr/share/{name}/resources/config/app.json").write_text("{}")
            (r / f"usr/share/{name}/queries").mkdir()
            shutil.copy2(r / "opt/Fake/fakeapp", r / f"usr/lib/{name}/editor")
            (r / "usr/share/other").mkdir(parents=True)     # no program in lib/other: nothing linked
            (r / "usr/share/other/data").write_text("x")
            a = analyze(pkg, self.index)
            out = Path(t) / "out"
            res = stage(a, out, "com.example.Ned", "org.test.Platform/x86_64/1", "bundle", [], {}, None)
            res_link = out / f"app/lib/{name}/resources"
            self.assertTrue(res_link.is_symlink())
            self.assertEqual((res_link / "config/app.json").read_text(), "{}")
            self.assertFalse((out / f"app/lib/{name}/queries").is_symlink())
            self.assertFalse((out / "app/lib/other").exists())
            self.assertTrue(any(f"lib/{name}" in n and "beside the program" in n for n in res.notes))

    def test_libreoffice_is_started_again_when_it_asks(self):
        # LibreItalia's AppImage starts soffice.bin, not oosplash; its first start sets up the
        # profile and exits with 81, which oosplash would answer by starting it again
        from debpak.stage import install_path, restarts_itself, wrapper_script
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.app_deb, t), self.index)
            self.assertFalse(restarts_itself(a))
            self.assertNotIn("81", wrapper_script(a, "bundle", []))
            a.elfs["opt/lo/program/soffice.bin"] = next(iter(a.elfs.values()))
            self.assertTrue(restarts_itself(a))
            wrapper = wrapper_script(a, "bundle", [])
            t = Path(t)
            count = t / "count"
            prog = t / "soffice"
            prog.write_text(f'#!/bin/sh\necho "$@" >> {count}\n[ $(wc -l < {count}) -ge 3 ] && exit 5\nexit 81\n')
            prog.chmod(0o755)
            run = t / "run"
            run.write_text(wrapper.replace(install_path(a.main_exec, "bundle"), str(prog)))
            run.chmod(0o755)
            r = subprocess.run([run, "--calc"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 5)
            self.assertEqual(count.read_text(), "--calc\n" * 3)

    def test_no_library_as_entry_point(self):
        from debpak.analyze import guess_main_exec
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.webex_deb, t), self.index)
            lib_only = {r: i for r, i in a.elfs.items() if r.endswith("libQt6Core.so.6")}
            self.assertIsNone(guess_main_exec(a.root, lib_only))

    def test_libpython_by_origin_path(self):
        # LM Studio: "required by executables (1): $ORIGIN/../lib/libpython3.11.so.1.0", shipped beside it
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.pybundle_deb, t), self.index)
            self.assertFalse(a.missing_hard, a.missing_hard)
            self.assertFalse(a.missing_soft, a.missing_soft)
        code, log = run_cli("convert", str(self.fx.pybundle_deb), "--app-id", "com.example.PyApp",
                            "--runtime-index", str(self.index_path), "-o", str(self.out_dir("pyapp")))
        self.assertEqual(code, 0, log)
        self.assertNotIn("$ORIGIN", log)

    def test_tauri_app_targets_gnome(self):
        # Jan and Yaak need libwebkit2gtk-4.1.so.0, which org.freedesktop.Platform lacks
        with tempfile.TemporaryDirectory() as t:
            a = analyze(extract(self.fx.tauri_deb, t), None)
            self.assertEqual(a.runtime_suggestion, "org.gnome.Platform//49")
        code, log = run_cli("inspect", str(self.fx.tauri_deb), "--json")
        self.assertEqual(code, 0, log)
        self.assertEqual(json.loads(log)["runtime_suggestion"], "org.gnome.Platform//49")

    def test_winit_app_gets_a_display(self):
        # Warp: kind elf, no display library linked, exit status 101 with no socket
        out = self.out_dir("winit")
        code, log = run_cli("convert", str(self.fx.winit_deb), "--app-id", "com.example.Warp",
                            "--runtime-index", str(self.index_path), "-o", str(out))
        self.assertEqual(code, 0, log)
        m = json.loads((out / "com.example.Warp.json").read_text())
        for arg in ("--share=ipc", "--socket=x11", "--socket=wayland", "--device=dri"):
            self.assertIn(arg, m["finish-args"])
        self.assertIn("dlopens libX11.so.6", log)


if __name__ == "__main__":
    unittest.main()
