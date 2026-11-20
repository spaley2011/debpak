"""The AppBridge window (Qt 6: PySide6, or PyQt6 as a fallback).

A list of every app grouped by suite, with its status and how it runs; a detail
pane to open, install, stop, pick a backend and add it to the app menu; a
system tray menu for quick launching; and drag-and-drop of files onto an app.
Uses the desktop's icon theme (Breeze on KDE) and registers itself with the
desktop through its .desktop file name.
"""
from __future__ import annotations

import html
import re
import time
from pathlib import Path

try:
    from PySide6 import QtCore, QtGui, QtWidgets
except ImportError:
    from PyQt6 import QtCore, QtGui, QtWidgets

from .backends import Command
from .catalog import SUITES, App
from .cli import doctor_lines
from .core import NO_BACKEND, NOT_INSTALLED, READY, Bridge, Resolved
from .integrate import SELF_ID, Integrator

Qt = QtCore.Qt
ROLE = Qt.ItemDataRole.UserRole
STATUS_TEXT = {READY: "Ready", NOT_INSTALLED: "Not installed", NO_BACKEND: "Not set up"}
STATUS_ICON = {READY: "emblem-ok-symbolic", NOT_INSTALLED: "emblem-downloads", NO_BACKEND: "emblem-unavailable"}
GENERIC_ICON = "application-x-executable"


def theme_icon(*names: str) -> QtGui.QIcon:
    for n in names:
        if n and QtGui.QIcon.hasThemeIcon(n):
            return QtGui.QIcon.fromTheme(n)
    return QtGui.QIcon.fromTheme(names[-1] if names else GENERIC_ICON)


def _link(url_text: str) -> str:
    """Escape for a QLabel and turn URLs into links."""
    esc = html.escape(url_text)
    return re.sub(r"(https?://[^\s;,)]+)", r'<a href="\1">\1</a>', esc)


# --------------------------------------------------------------------------- running commands

class ProcessDialog(QtWidgets.QDialog):
    """Runs install commands one after another and shows their output.
    Commands that ask questions open in the desktop's terminal (Konsole on KDE)."""

    def __init__(self, parent, bridge: Bridge, title: str, commands: list[Command]):
        super().__init__(parent)
        self.bridge = bridge
        self.queue = list(commands)
        self.failed = False
        self.setWindowTitle(title)
        self.resize(760, 420)
        lay = QtWidgets.QVBoxLayout(self)
        self.heading = QtWidgets.QLabel()
        self.heading.setWordWrap(True)
        lay.addWidget(self.heading)
        self.out = QtWidgets.QPlainTextEdit(readOnly=True)
        self.out.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        self.out.setMaximumBlockCount(5000)
        lay.addWidget(self.out)
        self.buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Close)
        self.cancel = self.buttons.addButton("Stop", QtWidgets.QDialogButtonBox.ButtonRole.RejectRole)
        self.buttons.button(QtWidgets.QDialogButtonBox.StandardButton.Close).setEnabled(False)
        self.buttons.button(QtWidgets.QDialogButtonBox.StandardButton.Close).clicked.connect(self.accept)
        self.cancel.clicked.connect(self._stop)
        lay.addWidget(self.buttons)
        self.proc = QtCore.QProcess(self)
        self.proc.setProcessChannelMode(QtCore.QProcess.ProcessChannelMode.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._read)
        self.proc.finished.connect(self._finished)
        self.proc.errorOccurred.connect(self._error)
        QtCore.QTimer.singleShot(0, self._next)

    def _next(self):
        if not self.queue:
            self._done("Finished." if not self.failed else "Stopped after an error.")
            return
        cmd = self.queue.pop(0)
        if cmd.interactive:
            try:
                cmd = self.bridge.terminal(cmd)
            except RuntimeError as e:
                self.out.appendPlainText(str(e))
                self.failed = True
                self._done("No terminal found for a step that asks questions.")
                return
        self.heading.setText(f"<b>{html.escape(cmd.label or 'Running')}</b>")
        self.out.appendPlainText(f"$ {cmd.shell()}")
        env = QtCore.QProcessEnvironment()
        for k, v in self.bridge.env_for(cmd).items():
            env.insert(k, v)
        self.proc.setProcessEnvironment(env)
        self.proc.start(cmd.argv[0], cmd.argv[1:])

    def _read(self):
        text = bytes(self.proc.readAllStandardOutput().data()).decode(errors="replace")
        self.out.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        self.out.insertPlainText(text)
        self.out.moveCursor(QtGui.QTextCursor.MoveOperation.End)

    def _finished(self, code, status=None):
        if code != 0:
            self.out.appendPlainText(f"\n[exit status {code}]")
            self.failed = True
            self.queue.clear()
        self._next()

    def _error(self, err):
        if err == QtCore.QProcess.ProcessError.FailedToStart:
            self.out.appendPlainText(f"\ncould not start: {self.proc.program()}")
            self.failed = True
            self.queue.clear()
            self._next()

    def _stop(self):
        self.queue.clear()
        if self.proc.state() != QtCore.QProcess.ProcessState.NotRunning:
            self.proc.terminate()
            if not self.proc.waitForFinished(3000):
                self.proc.kill()
        else:
            self._done("Stopped.")

    def _done(self, msg):
        self.heading.setText(f"<b>{html.escape(msg)}</b>")
        self.cancel.setEnabled(False)
        self.buttons.button(QtWidgets.QDialogButtonBox.StandardButton.Close).setEnabled(True)

    def closeEvent(self, e):
        if self.proc.state() != QtCore.QProcess.ProcessState.NotRunning:
            self._stop()
        super().closeEvent(e)


# --------------------------------------------------------------------------- dialogs

class AddAppDialog(QtWidgets.QDialog):
    """Add your own Windows program (company tools and the like), run with Wine or Proton."""

    def __init__(self, parent, bridge: Bridge):
        super().__init__(parent)
        self.bridge = bridge
        self.setWindowTitle("Add a Windows App")
        form = QtWidgets.QFormLayout(self)
        self.name = QtWidgets.QLineEdit(placeholderText="Expense Reports")
        self.id = QtWidgets.QLineEdit(placeholderText="expense-reports")
        self.name.textChanged.connect(self._sync_id)
        self.exe = QtWidgets.QLineEdit(placeholderText="C:\\Program Files\\Vendor\\App.exe or /path/to/App.exe")
        self.installer = QtWidgets.QLineEdit(placeholderText="optional: setup .exe to run first")
        self.prefix = QtWidgets.QLineEdit(placeholderText="default: ~/.local/share/appbridge/prefixes/<id>")
        self.runner = QtWidgets.QComboBox()
        self.runner.addItem("Wine (system wine)", "wine")
        self.runner.addItem("Proton (umu-launcher, GE-Proton)", "umu")
        self.mime = QtWidgets.QLineEdit(placeholderText="optional: application/x-vendor-doc, ...")
        form.addRow("Name", self.name)
        form.addRow("ID", self.id)
        form.addRow("Program", self._with_browse(self.exe, "Choose the program", "Programs (*.exe)"))
        form.addRow("Installer", self._with_browse(self.installer, "Choose the installer",
                                                   "Installers (*.exe *.msi)"))
        form.addRow("Runs with", self.runner)
        form.addRow("Wine prefix", self._with_browse(self.prefix, "Choose a folder", None))
        form.addRow("Opens files", self.mime)
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Ok
                                        | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)
        self.added: App | None = None
        self._id_edited = False
        self.id.textEdited.connect(lambda _t: setattr(self, "_id_edited", True))

    def _with_browse(self, edit, title, filt):
        w = QtWidgets.QWidget()
        h = QtWidgets.QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(edit)
        b = QtWidgets.QPushButton(theme_icon("document-open", "folder-open"), "")
        b.setToolTip("Browse…")

        def pick(_checked=False):
            if filt is None:
                p = QtWidgets.QFileDialog.getExistingDirectory(self, title, str(Path.home()))
            else:
                p, _ = QtWidgets.QFileDialog.getOpenFileName(self, title, str(Path.home()), filt)
            if p:
                edit.setText(p)
        b.clicked.connect(pick)
        h.addWidget(b)
        return w

    def _sync_id(self, text):
        if not self._id_edited:
            self.id.setText(re.sub(r"[^a-z0-9._-]+", "-", text.lower()).strip("-"))

    def _accept(self):
        try:
            self.added = self.bridge.add_custom(
                self.id.text().strip(), self.exe.text().strip(), name=self.name.text().strip(),
                runner=self.runner.currentData(), prefix=self.prefix.text().strip(),
                installer=self.installer.text().strip(),
                mime=[m.strip() for m in self.mime.text().split(",") if m.strip()])
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Can't add this app", str(e))
            return
        self.accept()


