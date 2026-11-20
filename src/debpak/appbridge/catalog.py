"""Which apps appbridge knows about, and the routes that can run each one.

Routes are listed best-first. appbridge picks the first route whose backend is
set up and has the app installed, unless you set a preference.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .host import Host


@dataclass(frozen=True)
class Route:
    backend: str          # name in backends.BACKENDS
    target: str           # backend-specific: app key, Flatpak ID, binary, unit, or "a|b|c" candidates
    exe: str = ""         # Windows executable, relative to the backend's install root (for checks and icons)
    remote: str = ""      # Flatpak remote that carries the app ("" = not on a remote, install it yourself)


@dataclass
class App:
    id: str
    name: str
    suite: str
    generic: str = ""
    icon: str = "application-x-executable"   # freedesktop icon name, used until a real icon is extracted
    categories: tuple[str, ...] = ()
    mime: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    routes: tuple[Route, ...] = ()
    kind: str = "app"     # "app", or "service" for sync daemons that start and stop
    custom: dict = field(default_factory=dict)   # custom Wine apps: exe, prefix, runner, env, installer

    @property
    def wm_class(self) -> str:
        """What Wine names the app's windows (StartupWMClass), for task-manager grouping."""
        for r in self.routes:
            if r.exe:
                return r.exe.replace("\\", "/").rsplit("/", 1)[-1].lower()
        exe = self.custom.get("exe", "")
        return exe.replace("\\", "/").rsplit("/", 1)[-1].lower() if exe else ""


SUITES = ("Microsoft 365", "Adobe", "Communication & sync", "Windows VM", "Custom")

_DOCX = ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
         "application/msword", "application/vnd.ms-word.document.macroEnabled.12",
         "application/vnd.ms-word.template.macroEnabled.12", "application/rtf")
_XLSX = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
         "application/vnd.ms-excel", "application/vnd.ms-excel.sheet.macroEnabled.12",
         "application/vnd.ms-excel.sheet.binary.macroEnabled.12")
_PPTX = ("application/vnd.openxmlformats-officedocument.presentationml.presentation",
         "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
         "application/vnd.openxmlformats-officedocument.presentationml.template",
         "application/vnd.ms-powerpoint", "application/vnd.ms-powerpoint.presentation.macroEnabled.12")


def _office(id_, name, exe, generic, icon, cats, mime, winapps, linoffice=True, kw=()):
    routes = [Route("ms365", id_, exe)]
    if linoffice:
        routes.append(Route("linoffice", id_))
    routes.append(Route("winapps", winapps))
    return App(id_, name, "Microsoft 365", generic, icon, cats, mime, kw, tuple(routes))


def _adobe(id_, name, folder, exe, generic, icon, cats, mime, winapps, kw=()):
    return App(id_, name, "Adobe", generic, icon, cats, mime, kw,
               (Route("lindobe", id_, f"{folder}/{exe}"), Route("winapps", winapps)))


def _vm(id_, name, generic, icon, cats, mime, winapps, kw=()):
    return App(id_, name, "Windows VM", generic, icon, cats, mime, kw, (Route("winapps", winapps),))


BUILTIN: tuple[App, ...] = (
    # ---------------------------------------------------------------- Microsoft 365
    _office("word", "Microsoft Word", "WINWORD.EXE", "Word Processor", "x-office-document",
            ("Office", "WordProcessor"), _DOCX, "word-o365|word|word-o365-x86|word-x86", kw=("docx", "doc")),
    _office("excel", "Microsoft Excel", "EXCEL.EXE", "Spreadsheet", "x-office-spreadsheet",
            ("Office", "Spreadsheet"), _XLSX, "excel-o365|excel|excel-o365-x86|excel-x86", kw=("xlsx", "xls")),
    _office("powerpoint", "Microsoft PowerPoint", "POWERPNT.EXE", "Presentation", "x-office-presentation",
            ("Office", "Presentation"), _PPTX, "powerpoint-o365|powerpoint|powerpoint-o365-x86|powerpoint-x86",
            kw=("pptx", "slides")),
    App("outlook", "Microsoft Outlook", "Microsoft 365", "Mail and Calendar", "internet-mail",
        ("Office", "Network", "Email", "Calendar"), ("application/vnd.ms-outlook", "message/rfc822"), ("email", "calendar"),
        (Route("ms365", "outlook", "OUTLOOK.EXE"), Route("linoffice", "outlook"),
         Route("winapps", "outlook-o365|outlook|outlook-o365-x86|outlook-x86"),
         Route("flatpak", "io.github.julian-alarcon.prospect-mail"), Route("native", "prospect-mail"))),
    App("onenote", "Microsoft OneNote", "Microsoft 365", "Notebook", "accessories-text-editor",
        ("Office", "Utility"), ("application/onenote",), ("notes",),
        (Route("ms365", "onenote", "ONENOTE.EXE"), Route("linoffice", "onenote"),
         Route("winapps", "onenote-o365|onenote|onenote-o365-x86|onenote-x86"),
         Route("flatpak", "com.patrikx3.onenote"), Route("native", "p3x-onenote"))),
    _office("access", "Microsoft Access", "MSACCESS.EXE", "Database", "x-office-spreadsheet",
            ("Office", "Database"), ("application/vnd.ms-access", "application/x-msaccess"),
            "access-o365|access|access-o365-x86|access-x86", linoffice=False),
    _office("publisher", "Microsoft Publisher", "MSPUB.EXE", "Desktop Publishing", "x-office-drawing",
            ("Office", "Publishing"), ("application/vnd.ms-publisher", "application/x-mspublisher"),
            "publisher-o365|publisher|publisher-o365-x86|publisher-x86", linoffice=False),
    # ---------------------------------------------------------------- Communication & sync
    App("teams", "Microsoft Teams", "Communication & sync", "Chat and Meetings", "internet-group-chat",
        ("Network", "InstantMessaging", "Chat", "VideoConference"), ("x-scheme-handler/msteams",), ("chat", "meeting"),
        (Route("flatpak", "com.github.IsmaelMartinez.teams_for_linux", remote="flathub"),
         Route("native", "teams-for-linux"))),
    App("onedrive", "OneDrive Sync", "Communication & sync", "File Sync", "folder-remote",
        ("Network", "FileTransfer"), (), ("sharepoint", "sync"),
        (Route("service", "onedrive.service"),), kind="service"),
    # ---------------------------------------------------------------- Adobe (folders as in LinDobe's config/apps.txt)
    _adobe("cc", "Adobe Creative Cloud", "Adobe Creative Cloud", "ACC/Creative Cloud.exe", "App Manager",
           "applications-graphics", ("Graphics",), (), "adobe-cc"),
    _adobe("photoshop", "Adobe Photoshop", "Adobe Photoshop {year}", "Photoshop.exe", "Image Editor",
           "applications-graphics", ("Graphics", "2DGraphics", "RasterGraphics"),
           ("image/vnd.adobe.photoshop", "image/png", "image/jpeg", "image/tiff"),
           "photoshop-2026|photoshop-2025|photoshop-2024|photoshop-2022|photoshop-cc", kw=("psd",)),
    _adobe("illustrator", "Adobe Illustrator", "Adobe Illustrator {year}", "Support Files/Contents/Windows/Illustrator.exe",
           "Vector Graphics Editor", "x-office-drawing", ("Graphics", "2DGraphics", "VectorGraphics"),
           ("application/illustrator", "application/postscript", "image/svg+xml"),
           "illustrator-2026|illustrator-2024|illustrator-cc", kw=("ai", "vector")),
    _adobe("indesign", "Adobe InDesign", "Adobe InDesign {year}", "InDesign.exe", "Page Layout", "x-office-document",
           ("Graphics", "Publishing"), ("application/x-indesign",), "indesign-2024|indesign-cc"),
    _adobe("incopy", "Adobe InCopy", "Adobe InCopy {year}", "InCopy.exe", "Copy Editor", "x-office-document",
           ("Graphics", "Publishing"), ("application/x-incopy",), "incopy"),
    _adobe("premiere", "Adobe Premiere Pro", "Adobe Premiere Pro {year}", "Adobe Premiere Pro.exe", "Video Editor",
           "applications-multimedia", ("AudioVideo", "Video", "AudioVideoEditing"), ("application/x-premiere",),
           "premierepro-2024", kw=("video",)),
    _adobe("aftereffects", "Adobe After Effects", "Adobe After Effects {year}", "Support Files/AfterFX.exe",
           "Motion Graphics", "applications-multimedia", ("AudioVideo", "Video", "AudioVideoEditing"),
           ("application/x-aftereffects",), "aftereffects-2024|aftereffects-cc"),
    _adobe("encoder", "Adobe Media Encoder", "Adobe Media Encoder {year}", "Adobe Media Encoder.exe", "Video Encoder",
           "applications-multimedia", ("AudioVideo", "Video"), (), "mediaencoder-2024"),
    _adobe("audition", "Adobe Audition", "Adobe Audition {year}", "Adobe Audition.exe", "Audio Editor",
           "applications-multimedia", ("AudioVideo", "Audio", "AudioVideoEditing"),
           ("application/x-audition",), "audition-2024|audition-cc"),
    _adobe("animate", "Adobe Animate", "Adobe Animate {year}", "Animate.exe", "Animation", "applications-graphics",
           ("Graphics", "2DGraphics", "VectorGraphics"), ("application/x-animate",), "animate"),
    _adobe("bridge", "Adobe Bridge", "Adobe Bridge {year}", "Adobe Bridge.exe", "Asset Browser",
           "applications-graphics", ("Graphics", "Viewer"), (), "bridge-cc"),
    _adobe("lightroomclassic", "Adobe Lightroom Classic", "Adobe Lightroom Classic", "Lightroom.exe", "Photo Manager",
           "applications-graphics", ("Graphics", "Photography"), ("application/x-lightroom-catalog",),
           "lightroom-classic"),
    _adobe("lightroom", "Adobe Lightroom", "Adobe Lightroom CC", "lightroom.exe", "Photo Editor",
           "applications-graphics", ("Graphics", "Photography"), (), "lightroom-cc"),
    _adobe("acrobat", "Adobe Acrobat", "Acrobat DC", "Acrobat/Acrobat.exe", "PDF Editor", "x-office-document",
           ("Office", "Viewer"), ("application/pdf",), "acrobat-dc|acrobat-x-pro", kw=("pdf",)),
    # ---------------------------------------------------------------- Windows-only, via a Windows VM
    _vm("visio", "Microsoft Visio", "Diagram Editor", "x-office-drawing", ("Office", "Graphics"),
        ("application/vnd.visio", "application/vnd.ms-visio.drawing"), "visio|visio-x86", kw=("vsdx", "diagram")),
    _vm("project", "Microsoft Project", "Project Planner", "x-office-spreadsheet", ("Office", "ProjectManagement"),
        ("application/vnd.ms-project",), "project|project-x86", kw=("mpp", "gantt")),
    _vm("powerbi", "Power BI Desktop", "Business Intelligence", "x-office-spreadsheet", ("Office", "Development"),
        (), "powerbi|powerbi-store", kw=("pbix", "dashboard")),
    _vm("ssms", "SQL Server Management Studio", "Database Tool", "applications-development",
        ("Development", "Database"), (), "ssms20", kw=("sql",)),
    _vm("visualstudio", "Visual Studio", "IDE", "applications-development", ("Development", "IDE"), (),
        "visual-studio-ent|visual-studio-pro|visual-studio-comm"),
    _vm("windows", "Windows Desktop", "Full Windows session", "computer", ("System",), (), "windows",
        kw=("rdp", "vm")),
)


# ---------------------------------------------------------------- user config

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def valid_id(app_id: str) -> bool:
    return bool(_ID_RE.match(app_id))


class Config:
    """~/.config/appbridge/config.json (preferred backends) and apps.json (your own Windows apps)."""

    def __init__(self, host: Host):
        self.host = host
        self.dir = host.config_home / "appbridge"
        self.prefer: dict[str, str] = {}
        self.custom: list[dict] = []
        self._load()

    def _read(self, name: str) -> dict:
        p = self.dir / name
        try:
            return json.loads(p.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            raise ValueError(f"{p}: {e}") from e

    def _load(self) -> None:
        self.prefer = dict(self._read("config.json").get("prefer", {}))
        self.custom = [a for a in self._read("apps.json").get("apps", []) if valid_id(a.get("id", ""))]

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "config.json").write_text(json.dumps({"prefer": self.prefer}, indent=2) + "\n")
        (self.dir / "apps.json").write_text(json.dumps({"apps": self.custom}, indent=2) + "\n")

    def default_prefix(self, app_id: str) -> Path:
        return self.host.data_home / "appbridge" / "prefixes" / app_id


def custom_app(d: dict) -> App:
    return App(
        id=d["id"], name=d.get("name") or d["id"], suite="Custom", generic=d.get("generic", "Windows Application"),
        icon=d.get("icon", "wine"), categories=tuple(d.get("categories", ["Office"])),
        mime=tuple(d.get("mime", [])), keywords=tuple(d.get("keywords", [])),
        routes=(Route("wine", d["id"]),), custom=d)


def all_apps(config: Config) -> list[App]:
    apps = list(BUILTIN)
    taken = {a.id for a in apps}
    apps += [custom_app(d) for d in config.custom if d["id"] not in taken]
    return apps


def find(apps: list[App], app_id: str) -> App | None:
    return next((a for a in apps if a.id == app_id), None)


def to_json(app: App) -> dict:
    d = asdict(app)
    d["routes"] = [asdict(r) for r in app.routes]
    return d
