"""Smoke test for the AppBridge window.

With PySide6 or PyQt6 installed it drives the real window offscreen. Without
Qt it runs the same code against a permissive stand-in for the Qt modules, which
still catches mistakes in appbridge's own code (wrong attributes, bad logic)
though not wrong Qt calls."""
import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from debpak.appbridge.core import READY, Bridge

from appbridge_fixtures import FakeDesktop


def _real_qt():
    for name in ("PySide6", "PyQt6"):
        try:
            importlib.import_module(f"{name}.QtWidgets")
            return name
        except ImportError:
            continue
    return None


class _Meta(type):
    def __getattr__(cls, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return mock.MagicMock(name=f"{cls.__name__}.{name}")


class _QBase(metaclass=_Meta):
    def __init__(self, *a, **k):
        pass

    # the few Qt calls whose results appbridge does arithmetic or looping on
    def findData(self, *a):
        return -1

    def topLevelItemCount(self):
        return 0

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        m = mock.MagicMock(name=name)
        object.__setattr__(self, name, m)
        return m


def _fake_qt_modules():
    pkg = types.ModuleType("PySide6")
    mods = {}
    for sub in ("QtCore", "QtGui", "QtWidgets"):
        m = types.ModuleType(f"PySide6.{sub}")

        def _ga(name, _m=m):
            if name.startswith("__"):
                raise AttributeError(name)
            if name[:1] == "Q" or name == "Qt":
                cls = _Meta(name, (_QBase,), {})
                setattr(_m, name, cls)
                return cls
            raise AttributeError(name)
        m.__getattr__ = _ga
        setattr(pkg, sub, m)
        mods[f"PySide6.{sub}"] = m
    mods["PySide6"] = pkg
    return mods


class GuiSmokeTest(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = FakeDesktop(Path(self._t.name))
        self.d.tool("ms365")
        self.d.office("WINWORD.EXE")
        self.d.winapps("visio")
        self.d.tool("adobewine")
        self.bridge = Bridge(self.d.host())

    def tearDown(self):
        self._t.cleanup()

    def _exercise(self, gui_qt, real: bool):
        win = gui_qt.MainWindow(self.bridge)
        self.assertEqual(win.results["word"].status, READY)
        for res in win.results.values():
            win.details.show_app(res)           # every app's detail pane renders
            win.app_icon(res)
        win.details.show_app(None)
        win._build_tray_menu()
        win.refresh(force=True, keep="word")
        # choosing a backend in the combo saves a preference
        win.details.show_app(win.results["word"])
        with mock.patch.object(win.details.route, "itemData", return_value="winapps"):
            win.details._route_chosen(1)
        self.assertEqual(Bridge(self.d.host()).config.prefer.get("word"), "winapps")
        # the add-app dialog adds a custom app
        dlg = gui_qt.AddAppDialog(win, self.bridge)
        if real:
            dlg.name.setText("Acme Tool")
            dlg.exe.setText(str(self.d.put("acme/tool.exe", b"MZ")))
            dlg._accept()
        else:
            with mock.patch.object(self.bridge, "add_custom", wraps=self.bridge.add_custom) as add:
                dlg.id = mock.MagicMock(**{"text.return_value": "acme-tool"})
                dlg.exe = mock.MagicMock(**{"text.return_value": str(self.d.put("acme/tool.exe", b"MZ"))})
                dlg.name = mock.MagicMock(**{"text.return_value": "Acme Tool"})
                dlg.runner = mock.MagicMock(**{"currentData.return_value": "wine"})
                for f in ("prefix", "installer", "mime"):
                    setattr(dlg, f, mock.MagicMock(**{"text.return_value": ""}))
                dlg._accept()
                add.assert_called_once()
        self.assertIsNotNone(dlg.added)
        self.assertEqual(dlg.added.id, "acme-tool")
        win.refresh(force=True, keep="acme-tool")
        self.assertIn("acme-tool", win.results)
        # menu integration from the GUI
        win.toggle_menu(win.results["word"])
        self.assertTrue((self.d.home / ".local/share/applications/appbridge-word.desktop").exists())
        win.toggle_menu(win.results["word"])
        self.assertFalse((self.d.home / ".local/share/applications/appbridge-word.desktop").exists())
        # system check dialog builds
        gui_qt.DoctorDialog(win, self.bridge)
        # the process dialog queues commands and wraps interactive ones in a terminal
        self.d.tool("konsole")
        from debpak.appbridge.backends import Command
        pd = gui_qt.ProcessDialog(win, self.bridge, "t", [Command(["true"], interactive=True)])
        pd._next() if not real else None
        return win

    def test_window(self):
        name = _real_qt()
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
        if name:
            with mock.patch.dict(os.environ, env):
                sys.modules.pop("debpak.appbridge.gui_qt", None)
                gui_qt = importlib.import_module("debpak.appbridge.gui_qt")
                app = gui_qt.QtWidgets.QApplication.instance() or gui_qt.QtWidgets.QApplication(["test"])
                self._exercise(gui_qt, real=True)
                app.processEvents()
        else:
            with mock.patch.dict(sys.modules, _fake_qt_modules()):
                sys.modules.pop("debpak.appbridge.gui_qt", None)
                gui_qt = importlib.import_module("debpak.appbridge.gui_qt")
                try:
                    self._exercise(gui_qt, real=False)
                finally:
                    sys.modules.pop("debpak.appbridge.gui_qt", None)

    def test_missing_qt_message(self):
        from debpak.appbridge import gui
        sys.modules.pop("debpak.appbridge.gui_qt", None)
        with mock.patch.dict(sys.modules, {"PySide6": None, "PyQt6": None}):
            with mock.patch("sys.stderr") as err:
                code = gui.main([])
        sys.modules.pop("debpak.appbridge.gui_qt", None)
        self.assertEqual(code, 1)
        self.assertIn("PySide6", "".join(str(c) for c in err.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
