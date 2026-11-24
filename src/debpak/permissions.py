"""Sandbox permission inference.

Heuristics over linked libraries and imported symbols. Every suggestion
carries a reason, which is written into the manifest's `x-debpak` block and
the report so a human can review it. Nothing grants blanket host access
unless --permissive is given.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Permission:
    """One finish-args entry, such as --share=network, with the reason debpak suggests it."""
    arg: str
    reason: str


def _any(sonames: set[str], *prefixes: str) -> str | None:
    """Return the first soname that starts with one of prefixes, or None."""
    for s in sorted(sonames):
        if s.startswith(prefixes):
            return s
    return None


NETWORK_SYMBOLS = {"socket", "connect", "getaddrinfo", "gethostbyname", "curl_easy_perform",
                   "SSL_connect", "PR_Connect", "g_socket_client_connect"}
# families of network calls in GLib/GIO, libsoup, libcurl and GnuTLS (a GTK program can download
# with GIO alone: g_socket_client_connect_to_host, g_file_read on an https:// GFile)
NETWORK_PREFIXES = ("g_socket_client_connect", "g_socket_connect", "g_resolver_lookup_by_name",
                    "g_network_address_parse_uri", "soup_session_", "curl_easy_", "gnutls_handshake")


def infer(sonames: set[str], symbols: set[str], kind: str, permissive: bool = False,
          dlopened: set[str] = frozenset(), gui: str | None = None,
          bus_names: dict[str, str] | None = None) -> list[Permission]:
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
    """
    perms: list[Permission] = []

    def add(arg: str, reason: str) -> None:
        if not any(p.arg == arg for p in perms):
            perms.append(Permission(arg, reason))

    electron = kind in ("electron", "cef")
    label = "Electron" if kind == "electron" else "CEF"
    wayland = _any(sonames, "libwayland-client.so")
    x11 = _any(sonames, "libX11.so", "libxcb.so", "libgtk-3.so", "libgtk-x11", "libQt5Gui", "libQt6Gui",
               "libSDL2", "libglfw")
    dl_wayland = _any(dlopened, "libwayland-client.so")
    dl_x11 = _any(dlopened, "libX11.so", "libX11-xcb.so", "libxcb.so")
    if electron or x11 or wayland:
        add("--share=ipc", "GUI app (X11 shared memory)")
        if wayland and not electron:
            add("--socket=wayland", f"links {wayland}")
            add("--socket=fallback-x11", "X11 fallback for Wayland-capable toolkit")
        else:
            add("--socket=x11", f"{label} app" if electron else f"links {x11}")
    elif dl_x11 or dl_wayland:
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
    elif gui:
        add("--share=ipc", "GUI app (X11 shared memory)")
        add("--socket=x11", gui)

    gl = _any(sonames, "libGL.so", "libEGL.so", "libGLX", "libvulkan.so", "libOpenGL.so", "libgbm.so")
    dl_gl = _any(dlopened, "libGL.so", "libEGL.so", "libGLX", "libvulkan.so")
    webkit = _any(sonames, "libwebkit2gtk-", "libwebkitgtk-")
    if electron or gl or dl_gl or webkit:
        add("--device=dri", f"{label} (GPU compositing)" if electron else
            f"links {gl}" if gl else f"dlopens {dl_gl}" if dl_gl else f"links {webkit} (GPU compositing)")

    audio = _any(sonames, "libpulse", "libasound.so", "libpipewire", "libportaudio", "libopenal", "libSDL2")
    if electron or audio:
        add("--socket=pulseaudio", f"{label} (Chromium audio)" if electron else f"links {audio}")

    net_lib = _any(sonames, "libcurl", "libssl.so", "libnss3.so", "libsoup", "libQt5Network", "libQt6Network",
                   "libgnutls")
    net_sym = sorted(s for s in symbols if s in NETWORK_SYMBOLS or s.startswith(NETWORK_PREFIXES))
    net_dl = _any(dlopened, "libcurl", "libsoup", "libssl.so", "libgnutls", "libnss3.so")
    if electron or net_lib or net_sym or net_dl:
        why = (f"{label} app" if electron else f"links {net_lib}" if net_lib else
               f"imports {net_sym[0]}()" if net_sym else f"dlopens {net_dl}")
        add("--share=network", why)

    notify = _any(sonames, "libnotify.so")
    if electron or notify:
        add("--talk-name=org.freedesktop.Notifications", f"{label} notifications" if electron else f"links {notify}")

    tray = _any(sonames, "libappindicator", "libayatana-appindicator", "libdbusmenu")
    if electron or tray:
        add("--talk-name=org.kde.StatusNotifierWatcher", "tray icon support" if electron else f"links {tray}")

    secret = _any(sonames, "libsecret-1.so", "libgnome-keyring", "libkwallet")
    if secret or electron:
        # Chromium loads libsecret at run time for Electron's safeStorage; apps that keep their
        # keys there (Tuta: "Could not decrypt local data using secret storage") stop without it
        add("--talk-name=org.freedesktop.secrets",
            f"links {secret}" if secret else f"{label} safeStorage (the desktop's keyring)")

    for name, where in sorted((bus_names or {}).items()):
        add(f"--own-name={name}", f"{where}; the app may register it on the session bus")

    usb = _any(sonames, "libusb-1.0.so", "libudev.so", "libhidapi")
    if usb:
        add("--device=all", f"links {usb} (hardware access; host udev rules may also be needed)")

    if permissive:
        add("--filesystem=home", "--permissive requested")
    else:
        add("--filesystem=xdg-download", "conservative default: file access via portals + Downloads")

    return perms
