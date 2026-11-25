"""HTTP requests with debpak's own User-Agent.

Some download hosts refuse Python's default User-Agent ("Python-urllib/3.x"):
Notion's desktop-release CDN answers it with 403 and serves curl normally.
Every download in debpak goes through urlopen() here, so they all identify
as debpak.
"""
from __future__ import annotations

import shutil
import urllib.parse
import urllib.request
from pathlib import Path

from . import __version__

USER_AGENT = f"debpak/{__version__} (+https://github.com/spaley2011/debpak)"


def urlopen(url: str | urllib.request.Request, timeout: float = 60):
    """urllib.request.urlopen, with debpak's User-Agent unless the request already sets one."""
    req = url if isinstance(url, urllib.request.Request) else urllib.request.Request(url)
    if not req.has_header("User-agent"):          # urllib stores header names capitalize()d
        req.add_header("User-Agent", USER_AGENT)
    return urllib.request.urlopen(req, timeout=timeout)


def download(url: str, dest: Path, timeout: float = 120, tries: int = 3) -> Path:
    """Download url to dest, checking it arrived whole, and return dest.

    A connection that drops can end a response early without an error: a
    Snipaste AppImage arrived as 28 of its 37 MB, and unsquashfs then found
    the filesystem cut short. When the server gives a Content-Length (and no
    Content-Encoding, which would change the length), the file must have
    exactly that many bytes, or it's downloaded again, up to tries times.

    Raises:
        OSError: Every try failed or came out short.
    """
    error: OSError | None = None
    for _ in range(tries):
        try:
            with urlopen(url, timeout=timeout) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f, 1 << 20)
                length = r.headers.get("Content-Length") if not r.headers.get("Content-Encoding") else None
            if length is None or not length.isdigit() or dest.stat().st_size == int(length):
                return dest
            error = OSError(f"{url}: the download stopped at {dest.stat().st_size} of {length} bytes")
        except OSError as e:
            error = e
    raise error or OSError(f"{url}: download failed")


def quote_url(url: str) -> str:
    """Percent-encode the characters a URL can't contain as written, such as spaces.

    Flatpak refuses an extra-data URL with a space in it ("URL using
    bad/illegal format"), and installers are often named like "Notion Setup
    7.44.1.exe". Existing %XX escapes and the URL's own punctuation are kept,
    so an already-encoded URL comes back unchanged.
    """
    return urllib.parse.quote(url, safe=":/?#[]@!$&'()*+,;=%~")
