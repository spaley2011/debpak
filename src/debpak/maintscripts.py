"""Maintainer-script and host-integration analysis.

Flatpak has no root-run install hooks and a read-only /usr, so preinst /
postinst logic can't run. Most of it is cache refreshing that Flatpak does
itself; some of it (kernel modules, system services, udev rules) signals a
component that cannot work in a sandbox at all.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SCRIPTS = ("preinst", "postinst", "prerm", "postrm")

# (pattern, category, explanation)
#   ignore  -> handled by Flatpak or irrelevant in a sandbox
#   handled -> debpak replaces it with something equivalent
#   warn    -> app may misbehave; review manually
#   blocker -> needs host integration a Flatpak cannot provide
RULES: list[tuple[str, str, str]] = [
    (r"\bldconfig\b", "ignore", "linker cache; Flatpak builds its own"),
    (r"\bupdate-desktop-database\b", "ignore", "desktop DB refresh; Flatpak exports handle this"),
    (r"\bgtk-update-icon-cache\b|\bxdg-icon-resource\b", "ignore", "icon cache refresh; handled on export"),
    (r"\bupdate-mime-database\b|\bxdg-mime\b", "ignore", "MIME DB refresh; handled on export"),
    (r"\bglib-compile-schemas\b", "ignore", "schemas; compile at build time if the app ships any"),
    (r"\bupdate-alternatives\b", "ignore", "alternatives symlinks; the wrapper calls the binary directly"),
    (r"/etc/apt|apt-key|sources\.list", "ignore", "vendor adds an apt repository; irrelevant for Flatpak"),
    (r"chmod\s+4755|chmod\s+u\+s", "handled", "setuid helper (e.g. chrome-sandbox); zypak/sandbox replaces it"),
    (r"\bxdg-desktop-menu\b", "ignore", "menu registration; Flatpak exports the desktop file"),
    # Chromium-based debs on Ubuntu load an AppArmor profile so the browser sandbox may use user
    # namespaces (Cursor, VS Code): `systemctl is-active apparmor`, then apparmor_parser
    (r"\bapparmor_parser\b|/etc/apparmor\.d/|\bsystemctl\b.*\bapparmor\b", "ignore",
     "loads an AppArmor profile for Chromium's sandbox; Flatpak sandboxes the app itself"),
    # systemctl that changes something; read-only queries, user units and the apparmor unit
    # don't count, nor does checking whether systemctl exists (see _without_probes)
    (r"(?m)^(?!.*apparmor).*\bsystemctl\b(?!(?:\s+-\S+)*\s+(?:is-active|is-enabled|is-failed|"
     r"is-system-running|status|show|cat|list-\S+|--user|--global|--version)\b)"
     r"|\bdeb-systemd-(?!.*--user)|\bupdate-rc\.d\b|\binvoke-rc\.d\b",
     "blocker", "installs/starts a system service; Flatpaks cannot run system services"),
    (r"(?m)^(?!.*apparmor).*\bsystemctl\b(?:\s+-\S+)*?\s+--(?:user|global)\b|\bdeb-systemd-\S+.*--user",
     "warn", "manages a user service; it isn't started inside the Flatpak"),
    # the vendor's own service installer (`teamviewer daemon enable`), or a unit file copied
    # or linked into the system's unit folders by hand
    (r"(?m)^[^#\n]*?[\w./${}\"'-]+[\"']?\s+daemon\s+(?:enable|install|start|restart)\b"
     r"|\.service\b[^\n]*\s[\"']?/(?:etc|usr/lib|lib)/systemd/system\b"
     r"|\b(?:cp|install|ln|mv)\b[^\n]*\s[\"']?/(?:etc|usr/lib|lib)/systemd/system/\S*\.service\b",
     "blocker", "installs a system service of its own; Flatpaks cannot run system services"),
    (r"\bmodprobe\b|\bdkms\b|\bdepmod\b|\binsmod\b", "blocker", "loads a kernel module; impossible in a sandbox"),
    # the app runs without its udev rules; only the hardware they open up (a headset's buttons, a
    # USB gadget) stays unreachable until they're installed on the host, as the payload check reports
    (r"\budevadm\b", "warn", "reloads udev rules; until they're installed on the host, devices they "
     "cover may not be reachable"),
    (r"\b(useradd|adduser|groupadd|addgroup|usermod)\b", "warn", "creates users/groups on the host"),
    (r"\bsetcap\b", "warn", "grants file capabilities; not available inside Flatpak"),
    (r"/etc/(security|pam\.d)|\bpam-auth-update\b", "blocker", "modifies PAM/security config on the host"),
]

# payload paths that indicate host integration
HOST_PATHS: list[tuple[str, str, str]] = [
    (r"^(usr/)?lib/modules/|^usr/src/.+-dkms|^usr/src/[^/]+/dkms\.conf", "blocker", "kernel module sources/binaries"),
    (r"^(usr/)?lib/systemd/system/|^etc/systemd/system/|^etc/init\.d/", "blocker", "system service units"),
    (r"^(usr/)?lib/udev/rules\.d/|^etc/udev/", "warn", "udev rules (install on host for device access)"),
    (r"^etc/pam\.d/|^etc/security/", "blocker", "PAM configuration"),
    (r"^(usr/)?lib/systemd/user/", "warn", "user service units (not started inside Flatpak)"),
    (r"^etc/cron\.|^etc/apt/", "ignore", "vendor repo/cron updater (stripped)"),
    (r"^etc/apparmor\.d/", "ignore", "AppArmor profile for the host; Flatpak sandboxes the app itself (stripped)"),
    (r"^usr/lib/[^/]+/(modules|plugins)/.*nss|^(usr/)?lib/.*/libnss_", "warn", "NSS module for the host resolver"),
    (r"^usr/lib/mozilla/native-messaging|^etc/opt/chrome/native-messaging|^etc/chromium/native-messaging",
     "warn", "browser native-messaging host (host browsers can't reach sandboxed apps)"),
]

# stripped from bundle-mode staging (and in apply_extra)
STRIP_PREFIXES = ("etc/cron.daily", "etc/cron.weekly", "etc/cron.hourly", "etc/apt", "etc/apparmor.d",
                  "lib/systemd", "usr/lib/systemd", "etc/systemd", "etc/init.d",
                  "lib/udev", "usr/lib/udev", "etc/udev", "usr/share/lintian",
                  "usr/share/menu", "etc/X11/Xsession.d")


@dataclass
class Finding:
    """One result of the host-integration checks: category (ignore, handled, warn or blocker), where it was found and why."""
    category: str
    where: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.category}] {self.where}: {self.detail}"


@dataclass
class HostIntegrationReport:
    """A list of findings, grouped on request."""
    findings: list[Finding] = field(default_factory=list)

    def by_category(self, cat: str) -> list[Finding]:
        return [f for f in self.findings if f.category == cat]

    @property
    def blockers(self) -> list[Finding]:
        return self.by_category("blocker")


def _strip_comments(script: str) -> str:
    """Remove # comments and the shebang line from a shell script, so rules don't match commented-out code."""
    return "\n".join(line.split("#", 1)[0] if not line.lstrip().startswith("#!") else "" for line in script.splitlines())


# `command -v systemctl`, `which systemctl`, `[ -x /bin/systemctl ]`: asking whether
# systemd is there before reloading AppArmor or the like does nothing to services
_SYSTEMCTL_PROBE = re.compile(r"\b(command\s+-v|which|type|hash)(\s+)(\S*/)?systemctl\b"
                              r"|(-[xef]\s+[\"']?)(\S*/)?systemctl\b")


def _without_probes(body: str) -> str:
    """Join continued lines and blank out checks for whether systemctl exists, before RULES are applied."""
    body = re.sub(r"\\\n\s*", " ", body)
    return _SYSTEMCTL_PROBE.sub(lambda m: (m.group(1) or m.group(4)) + (m.group(2) or "") + "systemd-probe", body)


def analyze_scripts(scripts: dict[str, str]) -> list[Finding]:
    """Check maintainer scripts against RULES.

    A script that has commands but matches no rule gets a warning, because
    debpak can't tell what it does.

    Args:
        scripts: Script name (preinst, postinst, ...) -> its text.
    """
    out = []
    for name, text in scripts.items():
        body = _without_probes(_strip_comments(text))
        matched_any = False
        for pattern, cat, why in RULES:
            if re.search(pattern, body):
                out.append(Finding(cat, name, why))
                matched_any = True
        meaningful = [ln for ln in body.splitlines()
                      if ln.strip() and not re.match(r"^\s*(set -e|set -u|exit 0|fi|esac|;;|then|else|do|done|\{|\})\s*$", ln)
                      and not re.match(r"^\s*(case|if|elif|for|while)\b", ln)]
        if meaningful and not matched_any:
            out.append(Finding("warn", name, "unrecognized maintainer script logic; review it manually"))
    return _removal_only_warns(out)


INSTALL_SCRIPTS = ("preinst", "postinst")
REMOVAL_SCRIPTS = ("prerm", "postrm")


def _removal_only_warns(findings: list[Finding]) -> list[Finding]:
    """Turn a blocker found only in the scripts that run on removal into a warning.

    prerm and postrm undo what the install did: LieNetwork's RPM has only a
    %postun that stops and reloads services (`systemctl daemon-reload`), and
    was refused for "installs/starts a system service" though nothing in it
    installs one. What the removal scripts touch matters only when the install
    scripts do the same; units in the package are judged by analyze_payload.
    """
    at_install = {f.detail for f in findings if f.where in INSTALL_SCRIPTS and f.category == "blocker"}
    out = []
    for f in findings:
        if f.category == "blocker" and f.where in REMOVAL_SCRIPTS and f.detail not in at_install:
            f = Finding("warn", f.where, f"{f.detail}, but only on removal: nothing the install runs does it")
        out.append(f)
    return out


def analyze_payload(root: Path, units: bool = True) -> list[Finding]:
    """Check the package's files against HOST_PATHS (systemd units, udev rules, ...); report each kind once.

    systemd units kept elsewhere count too (see service_unit_kind): TeamViewer
    ships teamviewerd.service in /opt/teamviewer/tv_bin/script, and its scripts
    copy it into /etc/systemd/system. Without units, that search is skipped:
    an AppImage or a snap has no install scripts to copy a unit anywhere (a
    snap's services come from its snap.yaml), so units inside one are left
    over from the system image it was built from (RustDesk's, LocalSend's).
    """
    out: list[Finding] = []
    seen = set()

    def add(cat: str, rel: str, why: str) -> None:
        if (cat, why) not in seen:
            seen.add((cat, why))
            out.append(Finding(cat, rel, why))

    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        matched = False
        for pattern, cat, why in HOST_PATHS:
            if re.search(pattern, rel):
                matched = True
                add(cat, rel, why)
        if units and not matched and p.name.endswith(".service") and not rel.startswith("usr/share/doc/"):
            kind = service_unit_kind(p)
            if kind and (OS_UNIT.match(p.name) or not runs_own_program(p, root)):
                # left over from the system the package was built on: LocalSend's AppImage carries
                # console-getty.service, which runs /sbin/agetty, not anything of LocalSend's
                continue
            if kind == "system":
                add("blocker", rel, "system service unit kept outside the systemd folders, for the package to "
                    "install on the host; Flatpaks cannot run system services")
            elif kind == "user":
                add("warn", rel, "user service unit (not started inside Flatpak)")
    return out


# Units of the operating system itself, which AppImages built from a whole system image
# carry (RustDesk's has emergency.service, LocalSend's dbus.service): never the app's own
OS_UNIT = re.compile(r"^(systemd-.*|dbus(-broker)?|emergency|rescue|debug-shell|(console|serial|container)?-?getty@?.*"
                     r"|user@|user-runtime-dir@|initrd-.*|quotaon|kmod-static-nodes|ldconfig|"
                     r"modprobe@)\.service$")


def runs_own_program(unit: Path, root: Path) -> bool:
    """Return whether a service unit's ExecStart= runs a program the package ships.

    The program counts when it's at its path inside the package or, since an
    AppImage keeps its files under opt/<name>, anywhere in it under that name.
    A unit with no ExecStart= is given the benefit of the doubt.
    """
    try:
        text = unit.read_text("utf-8", "replace")
    except OSError:
        return True
    m = re.search(r"(?m)^\s*ExecStart\s*=\s*[-@+!:]*(\S+)", text)
    if not m:
        return True
    prog = m.group(1)
    if (root / prog.lstrip("/")).exists():
        return True
    name = Path(prog).name
    return any(True for _ in root.rglob(name)) if name else True


# targets only the user manager has: a unit wanted by them is started for a user's session
USER_TARGETS = {"default.target", "graphical-session.target", "graphical-session-pre.target",
                "xdg-desktop-autostart.target", "tray.target"}


def service_unit_kind(path: Path) -> str | None:
    """Return "system" or "user" for a systemd service unit file, None for anything else.

    A D-Bus service file is also named *.service, but has no [Service] section.
    A unit is a user unit when it's in a systemd/user folder, when it's only
    wanted by default.target or the graphical session's targets (which only
    the user manager has), when it is part of or bound to the graphical
    session, or when nothing enables it and it only starts for a D-Bus name
    (Slack's snap carries dconf's), and it doesn't name a User=. Wayle's
    tarball keeps wayle.service, its desktop shell started with the
    graphical session, beside its programs, and was refused for a system
    service it doesn't have.
    """
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
            return None
        text = path.read_text("utf-8", "replace")
    except OSError:
        return None
    if not re.search(r"(?m)^\s*\[Service\]\s*$", text):
        return None
    wanted = set()
    for m in re.finditer(r"(?m)^\s*(?:WantedBy|RequiredBy)\s*=\s*(.*)$", text):
        wanted.update(m.group(1).split())
    if re.search(r"(?m)^\s*User\s*=", text):
        return "system"
    in_user_folder = "/systemd/user/" in "/" + path.as_posix()
    bus_activated = not wanted and re.search(r"(?m)^\s*BusName\s*=", text)
    session = re.search(r"(?m)^\s*(?:PartOf|BindsTo|Requisite)\s*=.*\bgraphical-session\.target\b", text)
    if in_user_folder or (wanted and wanted <= USER_TARGETS) or bus_activated or session:
        return "user"
    return "system"


def keeps_chromium_sandbox(findings: list[Finding]) -> bool:
    """Return True if the maintainer scripts make Chromium's sandbox helper setuid or
    load an AppArmor profile that lets it use user namespaces: the app runs Chromium
    (or CEF) with its sandbox on."""
    return any(re.search(r"setuid helper|AppArmor profile for Chromium", f.detail) for f in findings
               if f.where in SCRIPTS)


def is_service_finding(f: Finding) -> bool:
    """Return True for a finding about a system service (a unit, an init script, or a script starting one)."""
    return "system service" in f.detail


def system_services(root: Path) -> dict[str, str]:
    """Return the package's system services: where each is defined -> the name of the program it runs.

    Units are read wherever the package keeps them (see service_unit_kind); a
    SysV init script under etc/init.d counts as a service running a program of
    its own name. Units of the operating system itself (OS_UNIT) are left out.
    """
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if rel.startswith("etc/init.d/") and p.is_file():
            out[rel] = p.name
            continue
        if not p.name.endswith(".service") or rel.startswith("usr/share/doc/") or OS_UNIT.match(p.name):
            continue
        if service_unit_kind(p) != "system":
            continue
        text = p.read_text("utf-8", "replace")
        m = re.search(r"(?m)^\s*ExecStart\s*=\s*[-@+!:]*(\S+)", text)
        out[rel] = Path(m.group(1)).name if m else ""
    return out


# what a front end adds to the name of the program it fronts (netbird-ui, foo-gtk), and what a
# daemon adds to the name of its app (teamviewerd, foo-daemon)
FRONT_END_SUFFIX = re.compile(r"(?i)[-_.](ui|gui|tray|client|desktop|app|qt|gtk|frontend)$")
DAEMON_SUFFIX = re.compile(r"(?i)(?:[-_.]?(daemon|service|svc|server|helper)|d)$")


def _stem(name: str, suffix: re.Pattern) -> str:
    return re.sub(r"[^a-z0-9]", "", suffix.sub("", name.lower()))


def fronts_daemon(gui: str, daemon: str) -> bool:
    """Return True if gui looks like the front end of the program daemon: teamviewer of teamviewerd,
    netbird-ui of netbird. The same program run as a service (rudesktop --service) isn't."""
    if not gui or not daemon or gui.lower() == daemon.lower():
        return False
    g = re.sub(r"[^a-z0-9]", "", gui.lower())
    d = re.sub(r"[^a-z0-9]", "", daemon.lower())
    return bool(g) and (_stem(daemon, DAEMON_SUFFIX) == g or _stem(gui, FRONT_END_SUFFIX) == d
                        or _stem(daemon, DAEMON_SUFFIX) == _stem(gui, FRONT_END_SUFFIX))
