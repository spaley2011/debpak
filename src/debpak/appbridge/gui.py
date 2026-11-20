"""Entry point for the AppBridge window. The window itself is in gui_qt.py and
needs PySide6 or PyQt6; everything it does goes through the same core as the CLI."""
from __future__ import annotations

import sys

INSTALL_HELP = """\
The AppBridge window needs Qt for Python (PySide6 or PyQt6).

On KDE Plasma, install your distribution's package so the window uses the
system Qt and the Breeze theme:
  Fedora:          sudo dnf install python3-pyside6
  Arch / Manjaro:  sudo pacman -S pyside6
  Debian / Ubuntu: sudo apt install python3-pyqt6
  openSUSE:        sudo zypper install python3-PyQt6
Or from PyPI:      pip install 'debpak[gui]'

Everything is also available from the command line: appbridge --help
"""


def main(argv: list[str] | None = None) -> int:
    try:
        from . import gui_qt
    except ImportError as e:
        if "PySide6" in str(e) or "PyQt6" in str(e) or "Qt" in str(e):
            print(INSTALL_HELP, file=sys.stderr)
            return 1
        raise
    return gui_qt.run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
