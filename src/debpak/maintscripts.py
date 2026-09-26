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
    (r"\bsystemctl\b|\bdeb-systemd-|\bupdate-rc\.d\b|\binvoke-rc\.d\b", "blocker",
     "installs/starts a system service; Flatpaks cannot run system services"),
    (r"\bmodprobe\b|\bdkms\b|\bdepmod\b|\binsmod\b", "blocker", "loads a kernel module; impossible in a sandbox"),
    (r"\budevadm\b", "blocker", "reloads udev rules; device rules must be installed on the host"),
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
    (r"^usr/lib/[^/]+/(modules|plugins)/.*nss|^(usr/)?lib/.*/libnss_", "warn", "NSS module for the host resolver"),
    (r"^usr/lib/mozilla/native-messaging|^etc/opt/chrome/native-messaging|^etc/chromium/native-messaging",
     "warn", "browser native-messaging host (host browsers can't reach sandboxed apps)"),
]

# stripped from bundle-mode staging (and in apply_extra)
STRIP_PREFIXES = ("etc/cron.daily", "etc/cron.weekly", "etc/cron.hourly", "etc/apt",
                  "lib/systemd", "usr/lib/systemd", "etc/systemd", "etc/init.d",
                  "lib/udev", "usr/lib/udev", "etc/udev", "usr/share/lintian",
                  "usr/share/menu", "etc/X11/Xsession.d")


@dataclass
class Finding:
    category: str
    where: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.category}] {self.where}: {self.detail}"


@dataclass
class HostIntegrationReport:
    findings: list[Finding] = field(default_factory=list)

    def by_category(self, cat: str) -> list[Finding]:
        return [f for f in self.findings if f.category == cat]

    @property
    def blockers(self) -> list[Finding]:
        return self.by_category("blocker")


def _strip_comments(script: str) -> str:
    return "\n".join(line.split("#", 1)[0] if not line.lstrip().startswith("#!") else "" for line in script.splitlines())


def analyze_scripts(scripts: dict[str, str]) -> list[Finding]:
    out = []
    for name, text in scripts.items():
        body = _strip_comments(text)
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
    return out


def analyze_payload(root: Path) -> list[Finding]:
    out: list[Finding] = []
    seen = set()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        for pattern, cat, why in HOST_PATHS:
            if re.search(pattern, rel):
                key = (cat, why)
                if key not in seen:
                    seen.add(key)
                    out.append(Finding(cat, rel, why))
    return out
