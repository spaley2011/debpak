"""Sandbox permission inference.

Heuristics over linked libraries and imported symbols. Every suggestion
carries a reason, which is written into the manifest's `x-debpak` block and
the report so a human can review it. The home folder is only granted
with --permissive. The one way out of the sandbox granted without it is for
a program written to run its commands on the host from a Flatpak (WezTerm),
which does nothing otherwise; the report warns about it.
"""
from __future__ import annotations

from collections.abc import Callable
from collections.abc import Set as AbstractSet
from dataclasses import dataclass


@dataclass(frozen=True)
class Permission:
    """One finish-args entry, such as --share=network, with the reason debpak suggests it."""
    arg: str
    reason: str


def _any(sonames: AbstractSet[str], *prefixes: str) -> str | None:
    """Return the first soname that starts with one of prefixes, or None."""
    for s in sorted(sonames):
        if s.startswith(prefixes):
            return s
    return None


# QSystemTrayIcon's members, as a Qt 5 or Qt 6 program imports them
QT_TRAY_SYMBOLS = ("_ZN15QSystemTrayIcon", "_ZNK15QSystemTrayIcon")

NETWORK_SYMBOLS = {"socket", "connect", "getaddrinfo", "gethostbyname", "curl_easy_perform",
                   "SSL_connect", "PR_Connect", "g_socket_client_connect"}
# families of network calls in GLib/GIO, libsoup, libcurl and GnuTLS (a GTK program can download
# with GIO alone: g_socket_client_connect_to_host, g_file_read on an https:// GFile)
NETWORK_PREFIXES = ("g_socket_client_connect", "g_socket_connect", "g_resolver_lookup_by_name",
                    "g_network_address_parse_uri", "soup_session_", "curl_easy_", "gnutls_handshake")


def infer(sonames: set[str], symbols: set[str], kind: str, permissive: bool = False,
          dlopened: AbstractSet[str] = frozenset(), gui: str | None = None,
          bus_names: dict[str, str] | None = None, host_spawner: str = "",
          bus_clients: AbstractSet[str] = frozenset(), bus_access: dict[str, str] | None = None) -> list[Permission]:
    """Suggest Flatpak permissions from what the app links and imports.

    Every permission comes with the library or symbol that triggered it, so the
    manifest and report can say why. File access defaults to portals plus
    ~/Downloads.

    Args:
        sonames: Libraries the app needs.
        symbols: Undefined dynamic symbols across the app's ELF files.
        kind: The app kind from analyze.classify (Electron and CEF apps get extra).
        permissive: Grant --filesystem=home.
        dlopened: Display, GPU and network libraries the program loads with dlopen()
            rather than linking (Analysis.dlopened).
        gui: Why the app is graphical when nothing above shows it, such as
            its .desktop file; it then gets an X11 window.
        bus_names: D-Bus names the app may register, with where each was found
            (Analysis.bus_names). Each gets --own-name: the Flatpak's app ID is
            usually not the app's own, and GApplication and KDBusService exit
            when they can't register their name.
        host_spawner: A program that runs its commands on the host with
            flatpak-spawn --host once it finds itself in a Flatpak
            (Analysis.host_spawner). It gets --talk-name=org.freedesktop.Flatpak,
            the only way flatpak-spawn --host works.
        bus_clients: Desktop services the program names in its data
            (Analysis.bus_clients), reached with a D-Bus library of its own.
        bus_access: --talk-name and --system-talk-name finish-args the package
            declares itself (Analysis.bus_access), with why.
    """
    perms: list[Permission] = []

    def add(arg: str, reason: str) -> None:
        if not any(p.arg == arg for p in perms):
            perms.append(Permission(arg, reason))

    electron = kind in ("electron", "cef")
    label = "Electron" if kind == "electron" else "CEF"
    _display(add, sonames, dlopened, electron, label, gui)
    _gpu_audio_network(add, sonames, symbols, dlopened, electron, label)
    _desktop_services(add, sonames, symbols, bus_clients, electron, label)
    _bus(add, bus_names or {}, bus_access or {}, host_spawner)
    _devices_and_files(add, sonames, permissive)
    return perms


Add = Callable[[str, str], None]


def _bus(add: Add, bus_names: dict[str, str], bus_access: dict[str, str], host_spawner: str) -> None:
    """Grant the D-Bus names the app owns, the access its package declares, and flatpak-spawn --host."""
    for name, where in sorted(bus_names.items()):
        add(f"--own-name={name}", f"{where}; the app may register it on the session bus")

    for arg, why in sorted(bus_access.items()):
        add(arg, why)

    if host_spawner:
        # the program was written to work this way in a Flatpak and does nothing without it
        # (WezTerm's shell exits at once, closing its only window); this is host access, as
        # Flathub's WezTerm has, which the report warns about
        add("--talk-name=org.freedesktop.Flatpak",
            f"{host_spawner} runs its commands on the host with flatpak-spawn --host")


def _devices_and_files(add: Add, sonames: AbstractSet[str], permissive: bool) -> None:
    """Grant USB devices when the app links a hardware library, and the home folder or Downloads."""
    usb = _any(sonames, "libusb-1.0.so", "libudev.so", "libhidapi")
    if usb:
        add("--device=all", f"links {usb} (hardware access; host udev rules may also be needed)")

    if permissive:
        add("--filesystem=home", "--permissive requested")
    else:
        add("--filesystem=xdg-download", "conservative default: file access via portals + Downloads")


def _display(add: Add, sonames: AbstractSet[str], dlopened: AbstractSet[str], electron: bool, label: str,
             gui: str | None) -> None:
    """Grant the display: Wayland, X11 or both, from what the app links or dlopens, or why it's graphical."""
    if _linked_display(add, sonames, electron, label) or _dlopened_display(add, dlopened):
        return
    if gui:
        add("--share=ipc", "GUI app (X11 shared memory)")
        add("--socket=x11", gui)


def _linked_display(add: Add, sonames: AbstractSet[str], electron: bool, label: str) -> bool:
    """Grant the display an Electron app or one linking a display library needs; return whether it is one."""
    wayland = _any(sonames, "libwayland-client.so")
    x11 = _any(sonames, "libX11.so", "libxcb.so", "libgtk-3.so", "libgtk-x11", "libQt5Gui", "libQt6Gui",
               "libSDL2", "libSDL3", "libSDL-1.2", "libglfw", "libsfml-window", "libraylib", "libfltk", "libglut",
               "libwx_gtk", "libgdk-3.so", "libgdk_pixbuf_xlib", "libXext.so", "libXrender.so", "libXrandr.so")
    if not (electron or x11 or wayland):
        return False
    add("--share=ipc", "GUI app (X11 shared memory)")
    if wayland and not electron:
        add("--socket=wayland", f"links {wayland}")
        add("--socket=fallback-x11", "X11 fallback for Wayland-capable toolkit")
    else:
        add("--socket=x11", f"{label} app" if electron else f"links {x11}")
    return True


def _dlopened_display(add: Add, dlopened: AbstractSet[str]) -> bool:
    """Grant the display an app that dlopens its display libraries needs; return whether it does."""
    dl_wayland = _any(dlopened, "libwayland-client.so")
    dl_x11 = _any(dlopened, "libX11.so", "libX11-xcb.so", "libxcb.so")
    if not (dl_x11 or dl_wayland):
        return False
    # winit and friends load their display libraries at run time. Which one the
    # program uses can't be told from outside (Warp takes X11 unless its Wayland
    # setting is on, and panics without a display), so it gets both
    add("--share=ipc", "GUI app (X11 shared memory)")
    if dl_wayland:
        add("--socket=wayland", f"dlopens {dl_wayland}")
    if dl_x11:
        add("--socket=x11", f"dlopens {dl_x11}")
    else:
        add("--socket=fallback-x11", "X11 fallback for Wayland-capable toolkit")
    return True


def _gpu_reason(sonames: AbstractSet[str], dlopened: AbstractSet[str], electron: bool, label: str) -> str | None:
    """Return why the app needs the GPU, or None."""
    if electron:
        return f"{label} (GPU compositing)"
    if (gl := _any(sonames, "libGL.so", "libEGL.so", "libGLX", "libvulkan.so", "libOpenGL.so", "libgbm.so")):
        return f"links {gl}"
    if (dl_gl := _any(dlopened, "libGL.so", "libEGL.so", "libGLX", "libvulkan.so")):
        return f"dlopens {dl_gl}"
    if (webkit := _any(sonames, "libwebkit2gtk-", "libwebkitgtk-")):
        return f"links {webkit} (GPU compositing)"
    # Qt Quick draws every window with OpenGL (Qt 6: OpenGL or Vulkan) through Qt's own
    # libraries, so the app links neither; without the GPU it falls back to Mesa's software
    # renderer, which is slow
    if (quick := _any(sonames, "libQt5Quick.so", "libQt6Quick.so")):
        return f"links {quick} (Qt Quick draws with OpenGL)"
    return None


def _network_reason(sonames: AbstractSet[str], symbols: AbstractSet[str], dlopened: AbstractSet[str],
                    electron: bool, label: str) -> str | None:
    """Return why the app needs the network, or None."""
    if electron:
        return f"{label} app"
    if (net_lib := _any(sonames, "libcurl", "libssl.so", "libnss3.so", "libsoup", "libQt5Network", "libQt6Network",
                        "libgnutls")):
        return f"links {net_lib}"
    if (net_sym := sorted(s for s in symbols if s in NETWORK_SYMBOLS or s.startswith(NETWORK_PREFIXES))):
        return f"imports {net_sym[0]}()"
    if (net_dl := _any(dlopened, "libcurl", "libsoup", "libssl.so", "libgnutls", "libnss3.so")):
        return f"dlopens {net_dl}"
    return None


def _gpu_audio_network(add: Add, sonames: AbstractSet[str], symbols: AbstractSet[str], dlopened: AbstractSet[str],
                       electron: bool, label: str) -> None:
    if (why := _gpu_reason(sonames, dlopened, electron, label)):
        add("--device=dri", why)
    audio = _any(sonames, "libpulse", "libasound.so", "libpipewire", "libportaudio", "libopenal", "libSDL2")
    if electron or audio:
        add("--socket=pulseaudio", f"{label} (Chromium audio)" if electron else f"links {audio}")
    if (why := _network_reason(sonames, symbols, dlopened, electron, label)):
        add("--share=network", why)


def _desktop_services(add: Add, sonames: AbstractSet[str], symbols: AbstractSet[str],
                      bus_clients: AbstractSet[str], electron: bool, label: str) -> None:
    """Grant notifications, the tray and the keyring."""
    if (why := _notify_reason(sonames, electron, label)):
        add("--talk-name=org.freedesktop.Notifications", why)
    if (why := _tray_reason(sonames, symbols, electron)):
        add("--talk-name=org.kde.StatusNotifierWatcher", why)
    if (why := _secret_reason(sonames, bus_clients, electron, label)):
        add("--talk-name=org.freedesktop.secrets", why)


def _notify_reason(sonames: AbstractSet[str], electron: bool, label: str) -> str | None:
    """Return why the app shows notifications, or None."""
    if electron:
        return f"{label} notifications"
    if (notify := _any(sonames, "libnotify.so")):
        return f"links {notify}"
    return None


def _tray_reason(sonames: AbstractSet[str], symbols: AbstractSet[str], electron: bool) -> str | None:
    """Return why the app shows a tray icon, or None."""
    if electron:
        return "tray icon support"
    if (tray := _any(sonames, "libappindicator", "libayatana-appindicator", "libdbusmenu")):
        return f"links {tray}"
    # Qt's QSystemTrayIcon shows itself through the StatusNotifierWatcher on D-Bus; without
    # access to it, Qt only tries the old X11 tray, which Wayland desktops don't have, and
    # MEGAsync says "We couldn't find a system tray"
    if any(s.startswith(QT_TRAY_SYMBOLS) for s in symbols):
        return "uses QSystemTrayIcon (Qt's tray icon)"
    return None


def _secret_reason(sonames: AbstractSet[str], bus_clients: AbstractSet[str], electron: bool,
                   label: str) -> str | None:
    """Return why the app uses the desktop's keyring, or None."""
    if (secret := _any(sonames, "libsecret-1.so", "libgnome-keyring", "libkwallet")):
        return f"links {secret}"
    # Chromium loads libsecret at run time for Electron's safeStorage; apps that keep their
    # keys there (Tuta: "Could not decrypt local data using secret storage") stop without it
    if electron:
        return f"{label} safeStorage (the desktop's keyring)"
    if "org.freedesktop.secrets" in bus_clients:
        return "names org.freedesktop.secrets (the desktop's keyring), which it reaches over D-Bus itself"
    return None
