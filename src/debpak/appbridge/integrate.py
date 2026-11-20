"""Desktop integration through the freedesktop standards every Linux desktop
reads: .desktop entries (app menu, KRunner, GNOME search, Dolphin and Nautilus
"Open With"), MIME associations, StartupWMClass for task-manager grouping, and
right-click actions for the other ways an app can run. After writing, the
KDE (kbuildsycoca) and freedesktop caches are refreshed."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .core import READY, Bridge, Resolved
from .icons import PeError, extract_png

PREFIX = "appbridge-"
MARK = "X-AppBridge-Id"
SELF_ID = "io.github.debpak.AppBridge"


def _exec_quote(arg: str) -> str:
    """Quote one Exec= argument (Desktop Entry spec, "The Exec key")."""
    if arg and not any(c in arg for c in ' \t\n"\'\\><~|&;$*?#()`'):
        return arg
    return '"' + "".join("\\" + c if c in '"`$\\' else c for c in arg) + '"'


def _escape_value(v: str) -> str:
    """Escape a string value for a .desktop file (backslash first)."""
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def appbridge_argv() -> list[str]:
    """How a menu entry should call us: the installed script if there is one, else python -m."""
    exe = shutil.which("appbridge")
    if exe:
        return [os.path.realpath(exe)]
    return [sys.executable, "-m", "debpak.appbridge"]


def _exec(argv: list[str]) -> str:
    return _escape_value(" ".join(_exec_quote(a) for a in argv))


@dataclass
class Result:
    written: list[Path] = field(default_factory=list)
    removed: list[Path] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    defaults: list[str] = field(default_factory=list)
    refreshed: list[str] = field(default_factory=list)


class Integrator:
    def __init__(self, bridge: Bridge, dry_run: bool = False):
        self.b = bridge
        self.host = bridge.host
        self.dry = dry_run
        self.apps_dir = self.host.data_home / "applications"
        self.icon_dir = self.host.data_home / "appbridge/icons"

    def desktop_path(self, app_id: str) -> Path:
        return self.apps_dir / f"{PREFIX}{app_id}.desktop"

    def integrated(self, app_id: str) -> bool:
        return self.desktop_path(app_id).exists()

    # ------------------------------------------------------------------ icons
    def icon_for(self, res: Resolved) -> str:
        """Best icon: the app's own (from its .exe or the project), else a theme icon."""
        s = res.state
        if s:
            b, r = s.backend, s.route
            exe = b.exe_path(res.app, r, self.host)
            if exe and exe.is_file():
                dest = self.icon_dir / f"{res.app.id}.png"
                try:
                    if dest.exists() and dest.stat().st_mtime >= exe.stat().st_mtime:
                        return str(dest)
                    png = extract_png(exe)
                except (PeError, OSError, ValueError):
                    png = None
                if png:
                    if not self.dry:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(png)
                    return str(dest)
            f = b.icon_file(res.app, r, self.host)
            if f:
                return str(f)
            n = b.icon_name(res.app, r, self.host)
            if n:
                return n
        return res.app.icon

    # ------------------------------------------------------------------ entries
    def entry(self, res: Resolved, icon: str) -> str:
        a = res.app
        me = appbridge_argv()
        files = "%F" if a.mime else ""
        lines = [
            "[Desktop Entry]",
            "Type=Application",
            "Version=1.5",
            f"Name={_escape_value(a.name)}",
        ]
        if a.generic:
            lines.append(f"GenericName={_escape_value(a.generic)}")
        via = res.state.backend.label if res.state else ""
        lines += [
            f"Comment={_escape_value(f'{a.generic or a.name} ({via}, launched by appbridge)')}",
            f"Exec={_exec(me + ['launch', a.id]) + (' ' + files if files else '')}",
            f"TryExec={_escape_value(me[0])}",
            f"Icon={_escape_value(icon)}",
            "Terminal=false",
            "StartupNotify=true",
            f"Categories={';'.join(a.categories)};" if a.categories else "Categories=Utility;",
        ]
        if a.mime:
            lines.append(f"MimeType={';'.join(a.mime)};")
        kw = list(a.keywords) + [w for w in (a.suite.split()[0].lower(), "windows") if w]
        lines.append(f"Keywords={';'.join(dict.fromkeys(kw))};")
        if a.wm_class:
            lines.append(f"StartupWMClass={a.wm_class}")
        lines.append(f"{MARK}={a.id}")

        actions: list[tuple[str, str, list[str]]] = []
        for s in res.routes:
            if s is res.state or not s.usable:
                continue
            actions.append((f"via-{s.backend.name}", f"Open with {s.backend.label}",
                            me + ["launch", "--backend", s.backend.name, a.id]))
        if res.state and res.state.backend.stop(a, res.state.route, self.host):
            actions.append(("stop", "Stop" if a.kind == "service" else "Force close", me + ["stop", a.id]))
        if actions:
            lines.append(f"Actions={';'.join(k for k, _, _ in actions)};")
            for key, name, argv in actions:
                lines += ["", f"[Desktop Action {key}]", f"Name={_escape_value(name)}", f"Exec={_exec(argv)}"]
        return "\n".join(lines) + "\n"

    def self_entry(self) -> str:
        me = appbridge_argv()
        gui = shutil.which("appbridge-gui")
        argv = [os.path.realpath(gui)] if gui else me + ["gui"]
        return "\n".join([
            "[Desktop Entry]", "Type=Application", "Version=1.5", "Name=AppBridge",
            "GenericName=Windows App Launcher",
            "Comment=Run Microsoft 365, Adobe and other Windows apps through Wine or a Windows VM",
            f"Exec={_exec(argv)}", "Icon=preferences-desktop-default-applications", "Terminal=false",
            "Categories=Utility;System;", "Keywords=office;adobe;wine;windows;microsoft;",
            "StartupNotify=true", f"{MARK}=@self",
            "Actions=tray;", "", "[Desktop Action tray]", "Name=Start in system tray",
            f"Exec={_exec(argv + ['--tray'])}",
        ]) + "\n"

    def _foreign_duplicate(self, name: str) -> Path | None:
        """Another (non-appbridge) entry with the same name, e.g. one LinDobe or the flake made."""
        if not self.apps_dir.is_dir():
            return None
        for p in self.apps_dir.glob("*.desktop"):
            if p.name.startswith(PREFIX):
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            if f"\nName={name}\n" in "\n" + text and "NoDisplay=true" not in text:
                return p
        return None

    def add(self, app_ids: list[str] | None = None, force: bool = False, include_self: bool = True,
            set_default: bool = False) -> Result:
        out = Result()
        targets = [self.b.app(i) for i in app_ids] if app_ids else self.b.apps
        for a in targets:
            res = self.b.resolve(a)
            if res.status != READY and not force:
                if app_ids:
                    out.skipped.append((a.id, f"not ready: {res.summary}"))
                continue
            if res.state and res.state.backend.name in ("flatpak", "native") and not force:
                out.skipped.append((a.id, "it installs its own menu entry"))
                continue
            dup = self._foreign_duplicate(a.name)
            if dup and not force:
                out.skipped.append((a.id, f"{dup.name} already adds '{a.name}' (use --force to add ours too)"))
                continue
            text = self.entry(res, self.icon_for(res))
            p = self.desktop_path(a.id)
            if not self.dry:
                p.parent.mkdir(parents=True, exist_ok=True)
                tmp = p.with_suffix(".tmp")
                tmp.write_text(text)
                os.chmod(tmp, 0o755)   # KDE asks before running non-executable entries placed on the desktop
                tmp.replace(p)
            out.written.append(p)
            if set_default and a.mime:
                out.defaults += self._set_default(p.name, a.mime)
        if include_self:
            p = self.apps_dir / f"{SELF_ID}.desktop"
            if not self.dry:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(self.self_entry())
            out.written.append(p)
        if out.written:
            out.refreshed = self.refresh()
        return out

    def remove(self, app_ids: list[str] | None = None, include_self: bool = False) -> Result:
        out = Result()
        if not self.apps_dir.is_dir():
            return out
        for p in sorted(self.apps_dir.glob("*.desktop")):
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            ids = [l.split("=", 1)[1] for l in text.splitlines() if l.startswith(MARK + "=")]
            if not ids:
                continue
            if ids[0] == "@self":
                hit = include_self
            else:
                hit = app_ids is None or ids[0] in app_ids
            if hit:
                if not self.dry:
                    p.unlink()
                    icon = self.icon_dir / f"{ids[0]}.png"
                    if icon.exists():
                        icon.unlink()
                out.removed.append(p)
        if out.removed:
            out.refreshed = self.refresh()
        return out

    # ------------------------------------------------------------------ system hooks
    def _run(self, argv: list[str]) -> bool:
        if self.dry:
            return True
        try:
            return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env=self.host.env, timeout=60).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _set_default(self, desktop_name: str, mimes: tuple[str, ...]) -> list[str]:
        xm = self.host.which("xdg-mime")
        done = []
        for m in mimes:
            if xm and self._run([xm, "default", desktop_name, m]):
                done.append(m)
        return done

    def refresh(self) -> list[str]:
        """Tell the desktop the menu changed. KDE Plasma rebuilds its service cache
        (KRunner, Kickoff, Dolphin's Open With); others read the MIME cache."""
        done = []
        if udb := self.host.which("update-desktop-database"):
            if self._run([udb, "-q", str(self.apps_dir)]):
                done.append("update-desktop-database")
        for k in ("kbuildsycoca6", "kbuildsycoca5"):
            if p := self.host.which(k):
                if self._run([p]):
                    done.append(k)
                break
        if xdm := self.host.which("xdg-desktop-menu"):
            if self._run([xdm, "forceupdate"]):
                done.append("xdg-desktop-menu")
        return done


def shell_join(argv: list[str]) -> str:
    return shlex.join(argv)
