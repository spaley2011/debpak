#!/usr/bin/env python3
"""A very small X11 window manager for the test's virtual screens. compat.py runs it on each Xvfb.

    DISPLAY=:91 python3 tests/compat/miniwm.py

It maps every window that asks to be shown and lets it move and resize as it
asks, like no window manager at all, with one exception: a size the window's
own WM_NORMAL_HINTS rule out is held to its minimum and maximum, as every
desktop's window manager does. Apps count on that: MEGAsync refreshes its
fixed-size Qt Quick dialogs by resizing them to 1x1 and leaving the window
manager to put them back at their fixed size, so on a bare Xvfb they stay
1x1 and the screen looks black.

It also keeps each window's WM_STATE property, as ICCCM asks of every window
manager: NormalState once it maps a window, WithdrawnState once the client
unmaps it, IconicState when the client asks to be iconified. Wine 10 and
later wait for that property to change before they send a managed window's
next map or unmap, so without it a window Wine has mapped once can never be
hidden again: Flow Launcher's search bar, hidden at startup and on Escape,
stays on the screen with a stale picture of itself.

It doesn't draw frames, focus or stack anything.

Only libX11 through ctypes, so it runs wherever Xvfb does.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import sys

UNMAP_NOTIFY, DESTROY_NOTIFY, MAP_REQUEST, CONFIGURE_NOTIFY, CONFIGURE_REQUEST = 18, 17, 20, 22, 23
CLIENT_MESSAGE = 33
WITHDRAWN, NORMAL, ICONIC = 0, 1, 3
STRUCTURE_NOTIFY, SUBSTRUCTURE_REDIRECT, SUBSTRUCTURE_NOTIFY = 1 << 17, 1 << 20, 1 << 19
CW_WIDTH, CW_HEIGHT = 1 << 2, 1 << 3
P_MIN_SIZE, P_MAX_SIZE = 1 << 4, 1 << 5


class ConfigureRequest(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("parent", ctypes.c_ulong), ("window", ctypes.c_ulong),
                ("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int), ("height", ctypes.c_int),
                ("border_width", ctypes.c_int), ("above", ctypes.c_ulong), ("detail", ctypes.c_int),
                ("value_mask", ctypes.c_ulong)]


class MapRequest(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("parent", ctypes.c_ulong), ("window", ctypes.c_ulong)]


class WindowEvent(ctypes.Structure):
    """The start of UnmapNotify and DestroyNotify, which name the window after the one selected on."""
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("event", ctypes.c_ulong), ("window", ctypes.c_ulong)]


class ClientMessage(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("window", ctypes.c_ulong), ("message_type", ctypes.c_ulong),
                ("format", ctypes.c_int), ("data", ctypes.c_long * 5)]


class ConfigureNotify(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("event", ctypes.c_ulong), ("window", ctypes.c_ulong),
                ("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int), ("height", ctypes.c_int),
                ("border_width", ctypes.c_int), ("above", ctypes.c_ulong), ("override_redirect", ctypes.c_int)]


class WindowChanges(ctypes.Structure):
    _fields_ = [("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int), ("height", ctypes.c_int),
                ("border_width", ctypes.c_int), ("sibling", ctypes.c_ulong), ("stack_mode", ctypes.c_int)]


class SizeHints(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_long), ("x", ctypes.c_int), ("y", ctypes.c_int),
                ("width", ctypes.c_int), ("height", ctypes.c_int),
                ("min_width", ctypes.c_int), ("min_height", ctypes.c_int),
                ("max_width", ctypes.c_int), ("max_height", ctypes.c_int),
                ("width_inc", ctypes.c_int), ("height_inc", ctypes.c_int),
                ("min_aspect", ctypes.c_int * 2), ("max_aspect", ctypes.c_int * 2),
                ("base_width", ctypes.c_int), ("base_height", ctypes.c_int), ("win_gravity", ctypes.c_int)]


def clamp(size: int, low: int | None, high: int | None) -> int:
    """Hold a requested width or height to a window's minimum and maximum (0 or None: no limit)."""
    if high and high > 0:
        size = min(size, high)
    if low and low > 0:
        size = max(size, low)
    return max(size, 1)


def wm_state(known: dict[int, int], kind: int, window: int, synthetic: bool = False,
             wanted: int | None = None) -> int | None:
    """Return the WM_STATE a window gets after an event, or None to leave it alone.

    known holds the state of each window this window manager has mapped and is
    kept up to date. kind is the event: a MapRequest, an UnmapNotify (synthetic
    when the client withdraws a window that is already unmapped, ICCCM 4.1.4),
    a DestroyNotify, or a WM_CHANGE_STATE ClientMessage asking for state wanted.
    """
    if kind == MAP_REQUEST:
        known[window] = NORMAL
        return NORMAL
    if kind == UNMAP_NOTIFY:
        if window not in known:
            return None
        # the unmap that iconifies a window is this window manager's own; it stays iconic
        if known[window] == ICONIC and not synthetic:
            return None
        del known[window]
        return WITHDRAWN
    if kind == CLIENT_MESSAGE and wanted == ICONIC and known.get(window) == NORMAL:
        known[window] = ICONIC
        return ICONIC
    if kind == DESTROY_NOTIFY:
        known.pop(window, None)
    return None


def tell(x, dpy, window: int) -> None:
    """Send a window a synthetic ConfigureNotify with the geometry it has."""
    root, gx, gy = ctypes.c_ulong(), ctypes.c_int(), ctypes.c_int()
    w, h, border, depth = ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint()
    if not x.XGetGeometry(dpy, window, ctypes.byref(root), ctypes.byref(gx), ctypes.byref(gy), ctypes.byref(w),
                          ctypes.byref(h), ctypes.byref(border), ctypes.byref(depth)):
        return
    ev = ConfigureNotify(CONFIGURE_NOTIFY, 0, 1, dpy, window, window, gx.value, gy.value, w.value, h.value,
                         border.value, 0, 0)
    buf = (ctypes.c_char * 192)()
    ctypes.memmove(buf, ctypes.byref(ev), ctypes.sizeof(ev))
    x.XSendEvent(dpy, window, 0, STRUCTURE_NOTIFY, buf)


def main() -> int:
    name = ctypes.util.find_library("X11")
    if not name:
        print("miniwm: libX11 not found", file=sys.stderr)
        return 1
    x = ctypes.CDLL(name)
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XDefaultRootWindow.restype = ctypes.c_ulong
    x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x.XSelectInput.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_long]
    x.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    x.XMapWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    x.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
    x.XConfigureWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint, ctypes.POINTER(WindowChanges)]
    x.XGetGeometry.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)] + \
        [ctypes.POINTER(ctypes.c_int)] * 2 + [ctypes.POINTER(ctypes.c_uint)] * 4
    x.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
    x.XGetWMNormalHints.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(SizeHints),
                                    ctypes.POINTER(ctypes.c_long)]
    x.XInternAtom.restype = ctypes.c_ulong
    x.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    x.XChangeProperty.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    x.XUnmapWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    # a window that's gone by the time its request is handled makes Xlib's default handler exit
    handler = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)(lambda d, e: 0)
    x.XSetErrorHandler(handler)

    dpy = x.XOpenDisplay(None)
    if not dpy:
        print("miniwm: can't open the display", file=sys.stderr)
        return 1
    x.XSelectInput(dpy, x.XDefaultRootWindow(dpy), SUBSTRUCTURE_REDIRECT | SUBSTRUCTURE_NOTIFY)
    x.XSync(dpy, 0)
    wm_state_atom = x.XInternAtom(dpy, b"WM_STATE", 0)
    change_state_atom = x.XInternAtom(dpy, b"WM_CHANGE_STATE", 0)
    known: dict[int, int] = {}

    def set_state(window: int, state: int | None) -> None:
        if state is not None:
            # WM_STATE is the state and an icon window, which there never is
            value = (ctypes.c_long * 2)(state, 0)
            x.XChangeProperty(dpy, window, wm_state_atom, wm_state_atom, 32, 0, value, 2)

    event = (ctypes.c_char * 192)()
    while True:
        x.XNextEvent(dpy, event)
        kind = ctypes.c_int.from_buffer(event).value
        if kind == MAP_REQUEST:
            window = MapRequest.from_buffer(event).window
            x.XMapWindow(dpy, window)
            set_state(window, wm_state(known, kind, window))
        elif kind in (UNMAP_NOTIFY, DESTROY_NOTIFY):
            e = WindowEvent.from_buffer(event)
            set_state(e.window, wm_state(known, kind, e.window, synthetic=bool(e.send_event)))
        elif kind == CLIENT_MESSAGE:
            m = ClientMessage.from_buffer(event)
            if m.message_type == change_state_atom:
                state = wm_state(known, kind, m.window, wanted=m.data[0])
                if state == ICONIC:
                    x.XUnmapWindow(dpy, m.window)
                set_state(m.window, state)
        elif kind == CONFIGURE_REQUEST:
            e = ConfigureRequest.from_buffer(event)
            change = WindowChanges(e.x, e.y, e.width, e.height, e.border_width, e.above, e.detail)
            if e.value_mask & (CW_WIDTH | CW_HEIGHT):
                hints, supplied = SizeHints(), ctypes.c_long()
                if x.XGetWMNormalHints(dpy, e.window, ctypes.byref(hints), ctypes.byref(supplied)):
                    low = hints.flags & P_MIN_SIZE
                    high = hints.flags & P_MAX_SIZE
                    change.width = clamp(e.width, hints.min_width if low else None, hints.max_width if high else None)
                    change.height = clamp(e.height, hints.min_height if low else None,
                                          hints.max_height if high else None)
            x.XConfigureWindow(dpy, e.window, e.value_mask, ctypes.byref(change))
            if (change.width, change.height) != (e.width, e.height):
                # The window keeps a size other than the one it asked for, possibly the one it
                # has, and then the server sends it nothing; Qt would go on drawing at the size
                # it asked for (ICCCM 4.1.5: tell the client with a synthetic ConfigureNotify)
                tell(x, dpy, e.window)
        x.XSync(dpy, 0)


if __name__ == "__main__":
    sys.exit(main())
