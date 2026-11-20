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


class DoctorDialog(QtWidgets.QDialog):
    def __init__(self, parent, bridge: Bridge):
        super().__init__(parent)
        self.setWindowTitle("System Check")
        self.resize(820, 520)
        lay = QtWidgets.QVBoxLayout(self)
        tree = QtWidgets.QTreeWidget()
        tree.setHeaderLabels(["Item", "Details"])
        tree.setRootIsDecorated(False)
        for ok, item, detail in doctor_lines(bridge):
            it = QtWidgets.QTreeWidgetItem([item, detail])
            it.setIcon(0, theme_icon({True: "dialog-ok-apply", False: "dialog-warning", None: "dialog-information"}[ok]))
            it.setToolTip(1, detail)
            tree.addTopLevelItem(it)
        tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        lay.addWidget(tree)
        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(self.reject)
        bb.accepted.connect(self.accept)
        bb.button(QtWidgets.QDialogButtonBox.StandardButton.Close).clicked.connect(self.accept)
        lay.addWidget(bb)


# --------------------------------------------------------------------------- detail pane

class Details(QtWidgets.QWidget):
    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.win = win
        self.res: Resolved | None = None
        lay = QtWidgets.QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignTop)
        top = QtWidgets.QHBoxLayout()
        self.icon = QtWidgets.QLabel()
        self.icon.setFixedSize(64, 64)
        top.addWidget(self.icon)
        names = QtWidgets.QVBoxLayout()
        self.title = QtWidgets.QLabel()
        f = self.title.font()
        f.setPointSizeF(f.pointSizeF() * 1.4)
        f.setBold(True)
        self.title.setFont(f)
        self.subtitle = QtWidgets.QLabel()
        self.subtitle.setEnabled(False)
        names.addWidget(self.title)
        names.addWidget(self.subtitle)
        top.addLayout(names, 1)
        lay.addLayout(top)

        self.status = QtWidgets.QLabel()
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.TextFormat.RichText)
        self.status.setOpenExternalLinks(True)
        lay.addWidget(self.status)

        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel("Run with:"))
        self.route = QtWidgets.QComboBox()
        self.route.activated.connect(self._route_chosen)
        row.addWidget(self.route, 1)
        lay.addLayout(row)

        grid = QtWidgets.QGridLayout()
        self.open_btn = QtWidgets.QPushButton(theme_icon("media-playback-start", "system-run"), "Open")
        self.file_btn = QtWidgets.QPushButton(theme_icon("document-open"), "Open File…")
        self.install_btn = QtWidgets.QPushButton(theme_icon("run-install", "download", "system-software-install"),
                                                 "Install")
        self.stop_btn = QtWidgets.QPushButton(theme_icon("process-stop", "media-playback-stop"), "Stop")
        self.menu_btn = QtWidgets.QPushButton(theme_icon("bookmark-new", "list-add"), "Add to App Menu")
        self.default_btn = QtWidgets.QPushButton(theme_icon("preferences-desktop-default-applications"),
                                                 "Use for Its File Types")
        for i, b in enumerate((self.open_btn, self.file_btn, self.install_btn, self.stop_btn, self.menu_btn,
                               self.default_btn)):
            grid.addWidget(b, i // 2, i % 2)
        lay.addLayout(grid)
        self.open_btn.clicked.connect(lambda _c=False: self.win.launch(self.res))
        self.file_btn.clicked.connect(lambda _c=False: self.win.open_files(self.res))
        self.install_btn.clicked.connect(lambda _c=False: self.win.install(self.res))
        self.stop_btn.clicked.connect(lambda _c=False: self.win.stop(self.res))
        self.menu_btn.clicked.connect(lambda _c=False: self.win.toggle_menu(self.res))
        self.default_btn.clicked.connect(lambda _c=False: self.win.make_default(self.res))

        self.routes_box = QtWidgets.QLabel()
        self.routes_box.setWordWrap(True)
        self.routes_box.setTextFormat(Qt.TextFormat.RichText)
        self.routes_box.setOpenExternalLinks(True)
        self.routes_box.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        lay.addWidget(self.routes_box)
        self.remove_btn = QtWidgets.QPushButton(theme_icon("edit-delete", "list-remove"), "Remove This App")
        self.remove_btn.clicked.connect(lambda _c=False: self.win.remove_custom(self.res))
        lay.addWidget(self.remove_btn)
        lay.addStretch(1)
        self.show_app(None)

    def show_app(self, res: Resolved | None):
        self.res = res
        for w in (self.open_btn, self.file_btn, self.install_btn, self.stop_btn, self.menu_btn,
                  self.default_btn, self.route, self.remove_btn):
            w.setVisible(res is not None)
        if res is None:
            self.title.setText("AppBridge")
            self.subtitle.setText("Pick an app on the left")
            self.icon.setPixmap(theme_icon("preferences-desktop-default-applications").pixmap(64, 64))
            self.status.setText("Microsoft 365, Adobe and other Windows apps, through Wine, Proton or a "
                                "Windows VM. Drop a file on an app to open it there.")
            self.routes_box.setText("")
            return
        a, b = res.app, self.win.bridge
        self.title.setText(a.name)
        self.subtitle.setText(f"{a.generic + ' · ' if a.generic else ''}{a.suite}")
        self.icon.setPixmap(self.win.app_icon(res).pixmap(64, 64))
        colour = {READY: "#27ae60", NOT_INSTALLED: "#f67400", NO_BACKEND: "#da4453"}[res.status]
        text = f'<span style="color:{colour}"><b>{STATUS_TEXT[res.status]}</b></span> — {_link(res.summary)}'
        if res.status != READY:
            hint = b.install_hint(res)
            if hint and hint not in res.summary:
                text += f"<br>{_link(hint)}"
        pref = b.config.prefer.get(a.id)
        if pref and res.backend and res.backend.name != pref:
            label = next((s.backend.label for s in res.routes if s.backend.name == pref), pref)
            text += f"<br><i>Your choice, {html.escape(label)}, can't open it right now, so another way is used.</i>"
        self.status.setText(text)

        self.route.clear()
        self.route.addItem("Automatic (best available)", None)
        for s in res.routes:
            mark = "✓" if s.usable else ("◐" if s.check.ok else "✗")
            self.route.addItem(f"{mark} {s.backend.label}", s.backend.name)
        self.route.setCurrentIndex(max(0, self.route.findData(pref)) if pref else 0)

        ready = res.status == READY
        self.open_btn.setEnabled(ready)
        self.file_btn.setEnabled(ready and bool(a.mime))
        cmds = b.install_commands(res)
        self.install_btn.setEnabled(bool(cmds))
        self.install_btn.setText("Repair / Update" if ready and cmds else ("Set Up" if a.kind == "service" else "Install"))
        self.stop_btn.setEnabled(b.stop_command(res) is not None)
        in_menu = self.win.integrator.integrated(a.id)
        self.menu_btn.setText("Remove from App Menu" if in_menu else "Add to App Menu")
        self.menu_btn.setIcon(theme_icon("bookmark-remove", "list-remove") if in_menu
                              else theme_icon("bookmark-new", "list-add"))
        self.menu_btn.setEnabled(in_menu or ready)
        self.default_btn.setEnabled(ready and bool(a.mime))
        self.remove_btn.setVisible(a.suite == "Custom")

        rows = []
        for s in res.routes:
            state = ("ready" if s.usable else "set up, app not installed" if s.check.ok else _link(s.check.detail))
            chosen = " ← used" if s is res.state and ready else ""
            rows.append(f"<li><b>{html.escape(s.backend.label)}</b>: {state}{chosen}</li>")
        self.routes_box.setText("<p>Ways to run it, best first:</p><ul>" + "".join(rows) + "</ul>")

    def _route_chosen(self, index):
        if not self.res:
            return
        name = self.route.itemData(index)
        b = self.win.bridge
        if name:
            b.config.prefer[self.res.app.id] = name
        else:
            b.config.prefer.pop(self.res.app.id, None)
        b.config.save()
        self.win.refresh(keep=self.res.app.id)


# --------------------------------------------------------------------------- main window

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, bridge: Bridge, tray_mode: bool = False):
        super().__init__()
        self.bridge = bridge
        self.integrator = Integrator(bridge)
        self.tray_mode = tray_mode
        self._last_refresh = 0.0
        self.results: dict[str, Resolved] = {}
        self.setWindowTitle("AppBridge")
        self.setWindowIcon(theme_icon("preferences-desktop-default-applications"))
        self.resize(1100, 640)
        self.setAcceptDrops(True)

        tb = self.addToolBar("Main")
        tb.setObjectName("main-toolbar")
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        tb.setMovable(False)
        tb.addAction(theme_icon("view-refresh"), "Refresh", lambda _c=False: self.refresh(force=True))
        tb.addAction(theme_icon("list-add"), "Add Windows App…", lambda _c=False: self.add_app())
        tb.addAction(theme_icon("bookmark-new", "list-add"), "Add Ready Apps to Menu", lambda _c=False: self.integrate_all())
        tb.addAction(theme_icon("tools-report-bug", "dialog-information"), "System Check", lambda _c=False: self.doctor())

        split = QtWidgets.QSplitter()
        self.suites = QtWidgets.QListWidget()
        self.suites.setMaximumWidth(220)
        for label, key, icon in [("All Apps", "*", "view-list-icons"), ("Ready", "ready", "emblem-ok-symbolic")] + \
                [(s, s, {"Microsoft 365": "x-office-document", "Adobe": "applications-graphics",
                         "Communication & sync": "internet-group-chat", "Windows VM": "computer",
                         "Custom": "wine"}.get(s, "folder")) for s in SUITES]:
            it = QtWidgets.QListWidgetItem(theme_icon(icon, "folder"), label)
            it.setData(ROLE, key)
            self.suites.addItem(it)
        self.suites.setCurrentRow(0)
        self.suites.currentRowChanged.connect(lambda _r: self._fill())
        split.addWidget(self.suites)

        mid = QtWidgets.QWidget()
        ml = QtWidgets.QVBoxLayout(mid)
        ml.setContentsMargins(0, 0, 0, 0)
        self.search = QtWidgets.QLineEdit(placeholderText="Search apps…", clearButtonEnabled=True)
        self.search.textChanged.connect(lambda _t: self._fill())
        ml.addWidget(self.search)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["App", "Status", "Runs via"])
        self.tree.setRootIsDecorated(False)
        self.tree.setIconSize(QtCore.QSize(32, 32))
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
        self.tree.header().setStretchLastSection(False)
        self.tree.currentItemChanged.connect(self._selected)
        self.tree.itemActivated.connect(lambda it, _c: self.launch(self.results.get(it.data(0, ROLE))))
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        ml.addWidget(self.tree)
        split.addWidget(mid)

        self.details = Details(self)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidget(self.details)
        scroll.setWidgetResizable(True)
        scroll.setMinimumWidth(360)
        split.addWidget(scroll)
        split.setStretchFactor(1, 1)
        self.setCentralWidget(split)

        self.tray = None
        if QtWidgets.QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QtWidgets.QSystemTrayIcon(theme_icon("preferences-desktop-default-applications"), self)
            self.tray.setToolTip("AppBridge")
            self.tray.activated.connect(self._tray_activated)
            self.tray.show()
        self.refresh(force=True)

    # ------------------------------------------------------------------ data
    def app_icon(self, res: Resolved) -> QtGui.QIcon:
        try:
            ic = self.integrator.icon_for(res) if res.status == READY else res.app.icon
        except OSError:
            ic = res.app.icon
        if ic.startswith("/") and Path(ic).exists():
            return QtGui.QIcon(ic)
        return theme_icon(ic, res.app.icon, GENERIC_ICON)

    def refresh(self, force: bool = False, keep: str | None = None):
        now = time.monotonic()
        if not force and now - self._last_refresh < 2:
            return
        self._last_refresh = now
        cur = keep or (self.tree.currentItem().data(0, ROLE) if self.tree.currentItem() else None)
        try:
            self.bridge.reload()
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Configuration error", str(e))
        self.results = {a.id: self.bridge.resolve(a) for a in self.bridge.apps}
        self._fill(cur)
        self._build_tray_menu()

    def _fill(self, select: str | None = None):
        if select is None and self.tree.currentItem():
            select = self.tree.currentItem().data(0, ROLE)
        key = self.suites.currentItem().data(ROLE) if self.suites.currentItem() else "*"
        q = self.search.text().strip().lower()
        self.tree.clear()
        order = {READY: 0, NOT_INSTALLED: 1, NO_BACKEND: 2}
        rows = list(self.results.values())
        if key == "ready":
            rows = [r for r in rows if r.status == READY]
        elif key != "*":
            rows = [r for r in rows if r.app.suite == key]
        if q:
            rows = [r for r in rows if q in " ".join((r.app.name, r.app.id, r.app.generic, *r.app.keywords)).lower()]
        rows.sort(key=lambda r: (order[r.status], SUITES.index(r.app.suite), r.app.name))
        chosen = None
        for r in rows:
            it = QtWidgets.QTreeWidgetItem([r.app.name, STATUS_TEXT[r.status], r.backend.label if r.backend else "—"])
            it.setIcon(0, self.app_icon(r))
            it.setIcon(1, theme_icon(STATUS_ICON[r.status], "dialog-information"))
            it.setToolTip(0, r.summary)
            it.setToolTip(1, r.summary)
            it.setData(0, ROLE, r.app.id)
            if r.status != READY:
                for c in (0, 2):
                    it.setForeground(c, self.palette().brush(QtGui.QPalette.ColorGroup.Disabled,
                                                             QtGui.QPalette.ColorRole.Text))
            self.tree.addTopLevelItem(it)
            if r.app.id == select:
                chosen = it
        for c in (1, 2):
            self.tree.resizeColumnToContents(c)
        if chosen:
            self.tree.setCurrentItem(chosen)
        else:
            self.details.show_app(None)

    def _selected(self, cur, _prev):
        self.details.show_app(self.results.get(cur.data(0, ROLE)) if cur else None)

    # ------------------------------------------------------------------ actions
    def _status(self, msg: str):
        self.statusBar().showMessage(msg, 6000)

    def launch(self, res: Resolved | None, files: list[str] | None = None):
        if not res:
            return
        if res.status != READY:
            if it := self._item(res.app.id):
                self.tree.setCurrentItem(it)
            self._status(f"{res.app.name} isn't ready yet: {res.summary}")
            return
        try:
            log = self.bridge.log_path(res.app.id)
            for c in self.bridge.launch_commands(res, files or []):
                self.bridge.spawn(c, log)
        except OSError as e:
            QtWidgets.QMessageBox.critical(self, f"Can't open {res.app.name}", str(e))
            return
        self._status(f"Starting {res.app.name} {res.summary} (log: {log})")
        if self.tray_mode:
            self.hide()

    def open_files(self, res: Resolved | None):
        if not res:
            return
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(self, f"Open in {res.app.name}", str(Path.home()))
        if files:
            self.launch(res, files)

    def install(self, res: Resolved | None):
        if not res:
            return
        cmds = self.bridge.install_commands(res)
        if not cmds:
            QtWidgets.QMessageBox.information(self, res.app.name, self.bridge.install_hint(res))
            return
        steps = "\n".join(f"• {c.label or c.shell()}" for c in cmds)
        if QtWidgets.QMessageBox.question(self, f"Install {res.app.name}",
                                          f"AppBridge will run:\n\n{steps}\n\nContinue?") != \
                QtWidgets.QMessageBox.StandardButton.Yes:
            return
        ProcessDialog(self, self.bridge, f"Installing {res.app.name}", cmds).exec()
        self.refresh(force=True, keep=res.app.id)

    def stop(self, res: Resolved | None):
        c = self.bridge.stop_command(res) if res else None
        if c:
            self.bridge.spawn(c)
            self._status(c.label or f"Stopping {res.app.name}")
            QtCore.QTimer.singleShot(1500, lambda: self.refresh(force=True))

    def toggle_menu(self, res: Resolved | None):
        if not res:
            return
        if self.integrator.integrated(res.app.id):
            self.integrator.remove([res.app.id])
            self._status(f"Removed {res.app.name} from the app menu")
        else:
            r = self.integrator.add([res.app.id], include_self=False)
            if r.skipped:
                if QtWidgets.QMessageBox.question(
                        self, "Add to App Menu", f"{r.skipped[0][1]}.\n\nAdd it anyway?") != \
                        QtWidgets.QMessageBox.StandardButton.Yes:
                    return
                self.integrator.add([res.app.id], include_self=False, force=True)
            self._status(f"Added {res.app.name} to the app menu, search and Open With")
        self.details.show_app(self.results.get(res.app.id))

    def make_default(self, res: Resolved | None):
        if not res:
            return
        r = self.integrator.add([res.app.id], include_self=False, set_default=True, force=True)
        if r.defaults:
            self._status(f"{res.app.name} now opens {len(r.defaults)} file types by default")
        else:
            QtWidgets.QMessageBox.warning(self, res.app.name, "Couldn't set default apps (is xdg-mime installed?)")
        self.details.show_app(self.results.get(res.app.id))

    def integrate_all(self):
        r = self.integrator.add(None, include_self=True)
        n = len([p for p in r.written if p.name.startswith("appbridge-")])
        msg = f"Added {n} app{'s' if n != 1 else ''} to the app menu."
        if r.skipped:
            msg += "\n\nSkipped:\n" + "\n".join(f"• {i}: {why}" for i, why in r.skipped)
        if r.refreshed:
            msg += f"\n\nRefreshed: {', '.join(r.refreshed)}"
        QtWidgets.QMessageBox.information(self, "App Menu", msg)
        self.refresh(force=True)

    def add_app(self):
        d = AddAppDialog(self, self.bridge)
        if d.exec() and d.added:
            self.refresh(force=True, keep=d.added.id)
            res = self.results.get(d.added.id)
            if res and res.status == NOT_INSTALLED and self.bridge.install_commands(res):
                self.install(res)

    def remove_custom(self, res: Resolved | None):
        if not res or res.app.suite != "Custom":
            return
        if QtWidgets.QMessageBox.question(self, "Remove App",
                                          f"Remove {res.app.name} from AppBridge? Its Wine prefix is kept.") != \
                QtWidgets.QMessageBox.StandardButton.Yes:
            return
        self.integrator.remove([res.app.id])
        self.bridge.remove_custom(res.app.id)
        self.refresh(force=True)

    def doctor(self):
        DoctorDialog(self, self.bridge).exec()

    # ------------------------------------------------------------------ helpers
    def _item(self, app_id: str):
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            if it.data(0, ROLE) == app_id:
                return it
        return None

    def _context_menu(self, pos):
        it = self.tree.itemAt(pos)
        res = self.results.get(it.data(0, ROLE)) if it else None
        if not res:
            return
        m = QtWidgets.QMenu(self)
        m.addAction(theme_icon("media-playback-start"), "Open", lambda _c=False: self.launch(res)).setEnabled(res.status == READY)
        for s in res.routes:
            if s.usable and s is not res.state:
                m.addAction(f"Open with {s.backend.label}",
                            lambda _c=False, s=s: self.launch(Resolved(res.app, READY, s, res.routes)))
        m.addSeparator()
        m.addAction("Install / Set Up…", lambda _c=False: self.install(res)).setEnabled(bool(self.bridge.install_commands(res)))
        m.addAction("Add to / Remove from App Menu", lambda _c=False: self.toggle_menu(res))
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _build_tray_menu(self):
        if not self.tray:
            return
        menu = QtWidgets.QMenu(self)
        ready = [r for r in self.results.values() if r.status == READY]
        for suite in SUITES:
            group = sorted((r for r in ready if r.app.suite == suite), key=lambda r: r.app.name)
            if not group:
                continue
            sub = menu.addMenu(suite)
            for r in group:
                sub.addAction(self.app_icon(r), r.app.name, lambda _c=False, r=r: self.launch(r))
        if not ready:
            menu.addAction("No apps ready yet").setEnabled(False)
        menu.addSeparator()
        menu.addAction(theme_icon("window-new"), "Show AppBridge", lambda _c=False: self._show())
        menu.addAction(theme_icon("application-exit"), "Quit", lambda _c=False: QtWidgets.QApplication.quit())
        self.tray.setContextMenu(menu)
        self._tray_menu = menu

    def _tray_activated(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self._show()

    def _show(self):
        self.show()
        self.raise_()
        self.activateWindow()

    # ------------------------------------------------------------------ events
    def changeEvent(self, e):
        if e.type() == QtCore.QEvent.Type.ActivationChange and self.isActiveWindow():
            self.refresh()   # pick up apps installed in a terminal meanwhile
        super().changeEvent(e)

    def closeEvent(self, e):
        if self.tray_mode and self.tray:
            self.hide()
            e.ignore()
        else:
            super().closeEvent(e)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        files = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        pos = self.tree.viewport().mapFrom(self, e.position().toPoint())
        it = self.tree.itemAt(pos) or self.tree.currentItem()
        res = self.results.get(it.data(0, ROLE)) if it else None
        if files and res:
            self.launch(res, files)
            e.acceptProposedAction()
        else:
            self._status("Drop files onto an app in the list to open them there")


def run(argv: list[str]) -> int:
    tray = "--tray" in argv
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(["appbridge-gui"])
    app.setApplicationName("appbridge")
    app.setApplicationDisplayName("AppBridge")
    app.setOrganizationDomain("debpak.github.io")
    # Ties our windows to io.github.debpak.AppBridge.desktop: KDE's task manager
    # and Wayland compositors use this for the icon and grouping.
    app.setDesktopFileName(SELF_ID)
    app.setWindowIcon(theme_icon("preferences-desktop-default-applications"))
    win = MainWindow(Bridge(), tray_mode=tray)
    if tray and win.tray:
        app.setQuitOnLastWindowClosed(False)
    else:
        win.show()
    return app.exec()
