"""HTTP requests with debpak's own User-Agent.

Some download hosts refuse Python's default User-Agent ("Python-urllib/3.x"):
Notion's desktop-release CDN answers it with 403 and serves curl normally.
Every download in debpak goes through urlopen() here, so they all identify
as debpak.
"""
from __future__ import annotations

import urllib.parse
import urllib.request

from . import __version__

USER_AGENT = f"debpak/{__version__} (+https://github.com/spaley2011/debpak)"


def urlopen(url: str | urllib.request.Request, timeout: float = 60):
    """urllib.request.urlopen, with debpak's User-Agent unless the request already sets one."""
    req = url if isinstance(url, urllib.request.Request) else urllib.request.Request(url)
    if not req.has_header("User-agent"):          # urllib stores header names capitalize()d
        req.add_header("User-Agent", USER_AGENT)
    return urllib.request.urlopen(req, timeout=timeout)      # noqa: S310 - callers pass https or file URLs


def quote_url(url: str) -> str:
    """Percent-encode the characters a URL can't contain as written, such as spaces.

    Flatpak refuses an extra-data URL with a space in it ("URL using
    bad/illegal format"), and installers are often named like "Notion Setup
    7.44.1.exe". Existing %XX escapes and the URL's own punctuation are kept,
    so an already-encoded URL comes back unchanged.
    """
    return urllib.parse.quote(url, safe=":/?#[]@!$&'()*+,;=%~")
