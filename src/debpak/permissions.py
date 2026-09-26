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
    arg: str
    reason: str


def _any(sonames: set[str], *prefixes: str) -> str | None:
    for s in sorted(sonames):
        if s.startswith(prefixes):
            return s
    return None


NETWORK_SYMBOLS = {"socket", "connect", "getaddrinfo", "gethostbyname", "curl_easy_perform",
                   "SSL_connect", "PR_Connect", "g_socket_client_connect"}


def infer(sonames: set[str], symbols: set[str], kind: str, permissive: bool = False) -> list[Permission]:
    perms: list[Permission] = []

    def add(arg: str, reason: str) -> None:
        if not any(p.arg == arg for p in perms):
            perms.append(Permission(arg, reason))

    electron = kind == "electron"
    wayland = _any(sonames, "libwayland-client.so")
    x11 = _any(sonames, "libX11.so", "libxcb.so", "libgtk-3.so", "libgtk-x11", "libQt5Gui", "libQt6Gui",
               "libSDL2", "libglfw")
    if electron or x11 or wayland:
        add("--share=ipc", "GUI app (X11 shared memory)")
        if wayland and not electron:
            add("--socket=wayland", f"links {wayland}")
            add("--socket=fallback-x11", "X11 fallback for Wayland-capable toolkit")
        else:
            add("--socket=x11", "Electron app" if electron else f"links {x11}")

    gl = _any(sonames, "libGL.so", "libEGL.so", "libGLX", "libvulkan.so", "libOpenGL.so", "libgbm.so")
    if electron or gl:
        add("--device=dri", "Electron (GPU compositing)" if electron else f"links {gl}")

    audio = _any(sonames, "libpulse", "libasound.so", "libpipewire", "libportaudio", "libopenal", "libSDL2")
    if electron or audio:
        add("--socket=pulseaudio", "Electron (Chromium audio)" if electron else f"links {audio}")

    net_lib = _any(sonames, "libcurl", "libssl.so", "libnss3.so", "libsoup", "libQt5Network", "libQt6Network",
                   "libgnutls")
    net_sym = sorted(symbols & NETWORK_SYMBOLS)
    if electron or net_lib or net_sym:
        why = "Electron app" if electron else (f"links {net_lib}" if net_lib else f"imports {net_sym[0]}()")
        add("--share=network", why)

    notify = _any(sonames, "libnotify.so")
    if electron or notify:
        add("--talk-name=org.freedesktop.Notifications", "Electron notifications" if electron else f"links {notify}")

    tray = _any(sonames, "libappindicator", "libayatana-appindicator", "libdbusmenu")
    if electron or tray:
        add("--talk-name=org.kde.StatusNotifierWatcher", "tray icon support" if electron else f"links {tray}")

    secret = _any(sonames, "libsecret-1.so", "libgnome-keyring", "libkwallet")
    if secret:
        add("--talk-name=org.freedesktop.secrets", f"links {secret}")

    usb = _any(sonames, "libusb-1.0.so", "libudev.so", "libhidapi")
    if usb:
        add("--device=all", f"links {usb} (hardware access; host udev rules may also be needed)")

    if permissive:
        add("--filesystem=home", "--permissive requested")
    else:
        add("--filesystem=xdg-download", "conservative default: file access via portals + Downloads")

    return perms
