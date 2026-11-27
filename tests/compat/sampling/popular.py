"""Draw the popular suite: 45 well-known, demanding apps of each package type.

Usage: popular.py WORK OUT.json CATALOG... [--releases RELEASES.json...] [--winget-index index.db]
                  [--per 45] [--min-stars 500] [--low-stars 200] [--skip popular-skip.txt]

The random batches turned out to be mostly small hobby projects, half of them Electron or Tauri, so
they say little about the apps people use most. This suite is drawn the other way round: the most
starred GitHub repos whose latest release has a Linux x86-64 AppImage, .deb, .rpm or tarball, the
snaps the store lists first in its featured and topic sections, and the winget packages of big
vendors or of repos with many stars. Electron and Tauri (and other web view) apps are held to a
third of each type, so the rest are native programs: Qt, GTK, C++ and Rust programs, games,
creative tools, IDEs and the like. Each repo gives one app, to the route it can fill best.

No app any CATALOG has is drawn, by key, name, GitHub repo, snap name or winget id: pass every
earlier catalog (tests/compat/apps*.json, the PC's holdout-v.json, holdout-t.json and
batches/batch-*.json); a used.json of the batch scripts (names, repos, snaps, files) works too.
What the filters let through that is no app to test (a server, a widget set, a game engine that
needs the original game's files) is left out by name in popular-skip.txt, with the reason.

GitHub is asked through the gh CLI: topic searches sorted by stars (above --min-stars, then from
--low-stars up for routes that run short), each repo's latest release and its top folder. Where
the gh API refuses a repo (a sandbox whose proxy allows searches only), releases come from
--releases files instead, in releases_html.py's form ({repo: {tag, assets}}), and the repos still
unread are listed most starred first in WORK/unread-repos.txt, for releases_html.py to read where
github.com can be reached; the next run with its output then draws from them too. The snap store
is asked through its v2 API, winget through its index (source.msix's Public/index.db) and its
manifests on cdn.winget.microsoft.com. Each link drawn is checked (a HEAD request, or a short
ranged GET) before it is kept.

Everything fetched is cached in WORK (search results, releases, repo checks, snap and winget
records), so a second run is quick and draws the same apps, and a run that was cut off picks up
where it stopped. Delete a cache file to fetch that part again.
"""
import argparse
import collections
import json
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from classify import kind, names_app, fname          # the batches' Linux asset rules
import snap_gui
import winget_sample

ROUTES = ["appimage", "deb", "rpm", "tarball", "snap", "wine"]


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


# GitHub topics to search, sorted by stars: kinds of GUI program, toolkits and package formats. A
# search gives at most 1,000 repos, so it goes topic by topic.
TOPICS = ["gui", "desktop-app", "desktop-application", "desktop", "linux-app", "linux-desktop", "cross-platform", "qt", "qt5", "qt6", "qml", "gtk", "gtk3", "gtk4", "gtk-rs", "libadwaita", "gnome", "kde", "wxwidgets", "imgui", "sdl2", "opengl", "vulkan", "godot", "game", "games", "game-engine", "emulator", "video-editor", "image-editor", "photo-editor", "photography", "raw", "music-player", "audio", "daw", "synthesizer", "media-player", "video-player", "3d", "cad", "modeling", "drawing", "painting", "pixel-art", "animation", "ide", "code-editor", "text-editor", "editor", "markdown-editor", "note-taking", "notes", "knowledge-base", "office", "spreadsheet", "pdf", "pdf-viewer", "ebook", "epub", "reader", "science", "astronomy", "chemistry", "physics", "mathematics", "visualization", "data-visualization", "gis", "electronics", "simulation", "terminal-emulator", "file-manager", "browser", "web-browser", "email-client", "chat", "messenger", "download-manager", "torrent", "bittorrent-client", "screenshot", "screen-recorder", "streaming", "obs", "appimage", "flatpak", "electron", "tauri", "flutter", "password-manager", "database-gui", "git-client", "sdr", "ocr", "launcher", "minecraft-launcher", "retro", "roguelike", "rpg", "strategy-game", "puzzle-game", "music-production", "audio-plugin", "sound", "translation", "dictionary", "mindmap", "diagram", "whiteboard", "flashcards", "finance", "accounting", "productivity", "podcast", "youtube-downloader", "remote-desktop", "vnc", "file-sync", "backup", "diff-tool", "hex-editor", "api-client"]

# what a GUI suite has no use for, by the repo's name, description or topics
NOT_GUI = re.compile(r"(?i)\b(cli|command[- ]line|terminal (tool|app|client|ui)|tui|server|daemon|headless|library|"
                     r"framework|sdk|bindings?|driver|kernel module|theme|icon theme|cursor theme|font|wallpapers?|"
                     r"dotfiles|awesome|cheat ?sheet|bot|api wrapper|proxy|vpn core|plugin for|extension for|"
                     r"neovim plugin|vim plugin|language server|lsp|compiler|interpreter|runtime|toolchain|"
                     r"package manager|shell prompt|status ?bar|window manager|compositor|wayland compositor|"
                     r"benchmark|tutorial|course|book|example|boilerplate|template|starter)\b")
NOT_GUI_TOPICS = {"cli", "command-line", "command-line-tool", "terminal-based", "tui", "server", "library", "sdk",
                  "framework", "theme", "gtk-theme", "icon-theme", "font", "fonts", "dotfiles", "awesome-list",
                  "window-manager", "wayland-compositor", "compositor", "neovim-plugin", "vim-plugin", "cli-app",
                  "command-line-interface", "self-hosted", "selfhosted", "docker", "kubernetes", "status-bar"}
# kept although their text matches NOT_GUI: a browser is not a "runtime", a game engine's editor is a GUI
GUI_TOPICS = {"gui", "desktop-app", "desktop-application", "qt", "gtk", "gtk4", "gtk3", "libadwaita", "electron",
              "tauri", "game", "emulator", "video-editor", "image-editor", "ide", "web-browser", "browser"}

WEB_TOPICS = {"electron", "electron-app", "electronjs", "tauri", "tauri-app", "tauri2", "tauri-v2", "wails",
              "neutralino", "neutralinojs", "nwjs", "webview"}
WEB_LANGS = {"TypeScript", "JavaScript", "Vue", "Svelte", "HTML", "CSS", "Astro", "SCSS", "Less"}
# electron-builder publishes latest-linux.yml and .blockmap files; Tauri's updater publishes latest.json
# beside .sig files (a macOS .app.tar.gz alone says nothing: navop, a GPUI program, ships one)
ELECTRON_ASSETS = re.compile(r"(?i)(^latest-linux\.yml$|-linux\.yml$|\.blockmap$)")
TAURI_ASSETS = re.compile(r"(?i)(\.appimage\.tar\.gz|\.appimage\.sig)$")


REFUSED = object()


def gh(path, **params):
    """GET path from GitHub's API through the gh CLI; None if it isn't there, REFUSED if this
    machine may not ask (a sandbox whose proxy lets through searches but not a repo's own API)."""
    args = ["gh", "api", "-X", "GET", path] + [x for k, v in params.items() for x in ("-f", f"{k}={v}")]
    for t in range(5):
        p = subprocess.run(args, capture_output=True, text=True)
        if p.returncode == 0:
            return json.loads(p.stdout or "null")
        if "404" in p.stderr or "Not Found" in p.stderr or "409" in p.stderr:
            return None
        if "not enabled for this session" in p.stderr or "is not available" in p.stderr:
            return REFUSED
        if "rate limit" in p.stderr.lower() or "403" in p.stderr or "429" in p.stderr:
            time.sleep(30 * (t + 1))
        else:
            time.sleep(3 * (t + 1))
    print("gh failed:", path, p.stderr.strip()[:200], file=sys.stderr)
    return None


class Cache:
    """A JSON file in WORK, written as it fills."""
    def __init__(self, path):
        self.path = Path(path)
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {}

    def save(self):
        self.path.write_text(json.dumps(self.data, indent=0))


# ------------------------------------------------------------------ what earlier sets have

def used_from(catalogs):
    """Keys, names, repos, snaps, winget ids and installer files of every earlier set."""
    u = {k: set() for k in ("keys", "names", "repos", "snaps", "winget", "files")}
    for f in catalogs:
        d = json.loads(Path(f).read_text())
        if "apps" not in d:                   # a used.json of the batch scripts
            u["names"] |= {norm(n) for n in d.get("names", [])}
            u["repos"] |= {r.lower() for r in d.get("repos", [])}
            u["snaps"] |= set(d.get("snaps", []))
            u["files"] |= {x.lower() for x in d.get("files", [])}
            continue
        for a in d["apps"]:
            u["keys"].add(a["key"])
            u["names"].add(norm(a.get("name", "")))
            s, why = a.get("source", {}), a.get("why", "")
            if s.get("type") == "snap":
                u["snaps"].add(s["name"])
            if s.get("repo"):
                u["repos"].add(s["repo"].lower())
            for text in (why, s.get("url", "")):
                m = re.search(r"github\.com/([\w.-]+/[\w.-]+)", text)
                if m:
                    u["repos"].add(m.group(1).lower().removesuffix(".git"))
            m = re.match(r"winget sample (\S+)", why)
            if m:
                u["winget"].add(m.group(1).lower())
            if s.get("url"):
                u["files"].add(fname(s["url"]).lower())
    u["names"].discard("")
    return u


def skipped(skip, x):
    """True if x (a repo, snap or winget id) is in the skip list, or under an entry ending in *."""
    x = x.lower()
    return x in skip or any(s.endswith("*") and x.startswith(s[:-1]) for s in skip)


def is_used(u, key, name, repo=None, snap=None, winget=None):
    return (key in u["keys"] or norm(name) in u["names"] or (repo and repo.lower() in u["repos"])
            or (snap and snap in u["snaps"]) or (winget and winget.lower() in u["winget"]))


# ------------------------------------------------------------------ links

def link_ok(url):
    """True if url leads to a file: a HEAD request, or a short ranged GET where HEAD isn't allowed."""
    for method, headers in (("HEAD", {}), ("GET", {"Range": "bytes=0-1023"})):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "debpak-compat", **headers})
        for t in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip()
                    return r.status < 400 and ctype not in ("text/html", "application/xhtml+xml")
            except urllib.error.HTTPError as e:
                if e.code in (404, 410):
                    return False
                if e.code in (403, 405, 501) and method == "HEAD":
                    break                          # try a GET
                time.sleep(3 * (t + 1))
            except (OSError, ValueError):
                time.sleep(3 * (t + 1))
    return False


# ------------------------------------------------------------------ GitHub

def search_github(work, min_stars, pages, low_stars=None):
    """Repos found by topic searches, sorted by stars: {full_name: {stars, language, topics, ...}}.

    Each topic is searched for repos above min_stars and, with low_stars, again for those between
    low_stars and min_stars: a search gives at most 1,000 repos, so the lower band needs its own.
    They are drawn after the starred ones, where a route runs short.
    """
    c = Cache(work / "gh-search.json")
    done = set(c.data.get("_topics", []))
    bands = [("", f">{min_stars}")] + ([(f"@{low_stars}", f"{low_stars}..{min_stars}")] if low_stars else [])
    for topic, (tag, stars) in [(t, b) for b in bands for t in TOPICS]:
        if topic + tag in done:
            continue
        for page in range(1, pages + 1):
            r = gh("search/repositories", q=f"topic:{topic} stars:{stars} fork:false", sort="stars",
                   order="desc", per_page=100, page=page)
            time.sleep(2.2)                        # the search API allows 30 a minute
            items = (r or {}).get("items", [])
            for it in items:
                c.data.setdefault("repos", {})[it["full_name"]] = {
                    "stars": it["stargazers_count"], "language": it.get("language"), "topics": it.get("topics", []),
                    "description": (it.get("description") or "")[:300], "archived": it.get("archived", False)}
            if len(items) < 100:
                break
        c.data.setdefault("_topics", []).append(topic + tag)
        c.save()
        print(f"search {topic}{tag}: {len(c.data.get('repos', {}))} repos", file=sys.stderr, flush=True)
    return c.data.get("repos", {})


def looks_gui(repo, info):
    topics = set(info["topics"])
    text = repo.split("/")[1].replace("-", " ") + " " + info["description"]
    if topics & GUI_TOPICS and not topics & {"cli", "tui", "library", "theme", "gtk-theme", "icon-theme"}:
        return not re.search(r"(?i)\b(theme|icon pack|library|framework|sdk|bindings)\b", info["description"])
    return not (topics & NOT_GUI_TOPICS or NOT_GUI.search(text))


def latest_releases(work, repos, known):
    """The latest release's asset links of each repo: {repo: {tag, assets}} (None when it has none).

    known holds releases already read (releases_html.py's output, in the same form); the rest are
    asked of GitHub's API. Where the API is refused, the repos left unread are written to
    WORK/unread-repos.txt, most starred first, for releases_html.py to read where github.com can be
    reached; give its output with --releases on the next run.
    """
    c = Cache(work / "gh-releases.json")
    todo = [r for r in repos if r not in c.data and r not in known]
    refused = []

    def get(r):
        if refused:
            return r, REFUSED
        rel = gh(f"repos/{r}/releases/latest")
        if rel is REFUSED:
            refused.append(r)
            return r, REFUSED
        if not rel:
            return r, None
        return r, {"tag": rel.get("tag_name"), "published": rel.get("published_at"),
                   "assets": [a["browser_download_url"] for a in rel.get("assets", [])]}
    unread = []
    with ThreadPoolExecutor(6) as ex:
        for i, (r, v) in enumerate(ex.map(get, todo)):
            if v is REFUSED:
                unread.append(r)
                continue
            c.data[r] = v
            if i % 100 == 0:
                c.save()
                print(f"releases {i}/{len(todo)}", file=sys.stderr, flush=True)
    c.save()
    (work / "unread-repos.txt").write_text("".join(r + "\n" for r in unread))
    if unread:
        print(f"{len(unread)} repos' releases could not be read here (GitHub's API refused): "
              f"see {work / 'unread-repos.txt'}", file=sys.stderr)
    return {**known, **c.data}


def web_kind(work, repo, info, assets):
    """'electron', 'tauri' or 'web' if the app is a web page in a wrapper, else None (native).

    From the repo's topics, its top folder (src-tauri, a package.json that pulls in electron), its
    release files (electron-builder's latest-linux.yml and .blockmap, Tauri's latest.json) and, when
    nothing else says, a web language as the repo's main one.
    """
    c = web_kind.cache = getattr(web_kind, "cache", None) or Cache(work / "gh-web.json")
    if repo in c.data:
        return c.data[repo]
    topics = set(info["topics"])
    names = [fname(a) for a in assets]
    if topics & {"tauri", "tauri-app", "tauri2", "tauri-v2"}:
        k = "tauri"
    elif topics & {"electron", "electron-app", "electronjs"}:
        k = "electron"
    else:
        k = None
        top = gh(f"repos/{repo}/contents") if not web_kind.refused else REFUSED
        web_kind.refused = top is REFUSED          # then only the topics, files and language say
        top = {x["name"] for x in top} if isinstance(top, list) else set()
        if "src-tauri" in top:
            k = "tauri"
        elif "package.json" in top:
            pkg = gh(f"repos/{repo}/contents/package.json")
            import base64
            text = base64.b64decode(pkg.get("content", "")).decode("utf-8", "replace") \
                if isinstance(pkg, dict) else ""
            if re.search(r'"electron"\s*:', text):
                k = "electron"
            elif "@tauri-apps" in text:
                k = "tauri"
            elif "@neutralinojs" in text or "nw-builder" in text:
                k = "web"
        if k is None and "wails.json" in top:
            k = "web"
        # navop's says "built with Rust and GPUI. No WebView, no Electron"
        if k is None and re.search(r"(?i)\b(electron|tauri)\b", info["description"]) and not \
                re.search(r"(?i)\b(no|not|without|instead of)\s+(an?\s+)?(webview|electron|tauri)", info["description"]):
            k = "electron" if re.search(r"(?i)\belectron\b", info["description"]) else "tauri"
        if k is None and any(ELECTRON_ASSETS.search(n) for n in names):
            k = "electron"
        if k is None and (any(TAURI_ASSETS.search(n) for n in names)
                          or ("latest.json" in names and any(n.endswith(".sig") for n in names))):
            k = "tauri"
        if k is None and topics & WEB_TOPICS:
            k = "web"
        if k is None and info.get("language") in WEB_LANGS:
            k = "web"
    c.data[repo] = k
    c.save()
    return k


web_kind.refused = False      # set once GitHub refuses a repo's contents
web_kind.cache = None


def github_candidates(work, used, min_stars, pages, known, low_stars=None):
    """Per route, the GitHub apps that could be drawn, most starred first."""
    found = search_github(work, min_stars, pages, low_stars)
    gui = {r: i for r, i in found.items() if not i["archived"] and looks_gui(r, i)
           and r.lower() not in used["repos"] and norm(r.split("/")[1]) not in used["names"]}
    rels = latest_releases(work, sorted(gui, key=lambda r: -gui[r]["stars"]), known)
    out = []
    for r, info in sorted(gui.items(), key=lambda x: -x[1]["stars"]):
        rel = rels.get(r)
        if not rel:
            continue
        by = {}
        for u in rel["assets"]:
            k = kind(fname(u))
            if k and (k not in by or (names_app(u, r) and not names_app(by[k], r))):
                by[k] = u
        if by:
            out.append({"repo": r, "stars": info["stars"], "language": info["language"], "kinds": by,
                        "web": web_kind(work, r, info, rel["assets"]), "description": info["description"]})
    return out


def pick_github(cands, used, per, web_cap, skip):
    """Give each repo, most starred first, to the route it offers that is shortest of supply.

    A repo with an AppImage, a .deb and an .rpm counts for one route only (no app twice). Web
    wrappers stop being taken for a route once it has web_cap of them.
    """
    routes = ["appimage", "deb", "rpm", "tarball"]
    picked = {r: [] for r in routes}
    taken = set()
    supply = collections.Counter(k for c in cands for k in c["kinds"])
    for c in cands:
        for k in c["kinds"]:
            supply[k] -= 1                       # supply left after this one
        name = c["repo"].split("/")[1]
        if skipped(skip, c["repo"]) or norm(name) in taken:
            continue
        key0 = re.sub(r"[^a-z0-9]+", "-", c["repo"].lower()).strip("-")
        opts = [k for k in c["kinds"] if len(picked[k]) < per and not is_used(used, f"p-{k[:3]}-{key0}", name, c["repo"])
                and not (c["web"] and sum(1 for x in picked[k] if x["_web"]) >= web_cap)]
        if not opts:
            continue
        # the route whose remaining need is largest against what is left of it
        k = max(opts, key=lambda k: ((per - len(picked[k])) / (supply[k] + 1), -routes.index(k)))
        if not link_ok(c["kinds"][k]):
            print("dead link:", c["repo"], c["kinds"][k], file=sys.stderr)
            continue
        taken.add(norm(name))
        picked[k].append({"key": f"p-{k[:3]}-{key0}", "name": name, "route": k,
                          "why": f"popular: github.com/{c['repo']} ({c['stars']} stars, "
                                 f"{c['web'] or (c['language'] or 'native')})",
                          "source": {"type": "url", "url": c["kinds"][k]}, "_web": c["web"], "_stars": c["stars"]})
    return picked


# ------------------------------------------------------------------ snaps

# the store's sections, each listed best known first; education, personalisation and the like are left
# out: their first ones are small (KDE's flash-card and fraction programs, wallpaper pickers)
SNAP_SECTIONS = ["featured", "productivity", "development", "art-and-design", "photo-and-video", "music-and-audio",
                 "games", "science", "social", "entertainment", "utilities"]
# publishers whose snaps are big, well-known programs (the KDE and GNOME projects, Canonical, vendors)
SNAP_PUBLISHERS = ["kde", "gnome", "canonical", "mozilla", "libreoffice", "videolan", "blenderfoundation",
                   "jetbrains", "obsproject", "spotify", "slack", "microsoft-edge", "vscode", "onlyoffice",
                   "snapcrafters", "freecad", "krita", "inkscape", "gimp", "audacity", "darktable"]
# snaps that are tools, servers or parts of other snaps, by name
SNAP_NOT_GUI = re.compile(r"(?i)(^kde-.*(sdk|core\d)|-sdk$|^gnome-\d|^gtk-common|-themes?$|^core\d*$|^snapd|"
                          r"^lxd|^microk8s|^kubectl|^juju|^multipass|^charmcraft|^snapcraft|^powershell|^htop|"
                          r"^ruff|^node$|^go$|^dotnet|server|daemon|cli$|-cli|^aws|^gcloud|^google-cloud|^certbot|"
                          r"^docker|^helm|^terraform|^yq$|^jq$|^ffmpeg$|^youtube-dl|^yt-dlp|^tio$|^bw$|^slcli|"
                          r"^nextcloud$|^plexmediaserver|^ubuntu-|^mesa|^wine-platform|^bare$|^gnome-platform|"
                          r"insiders$|-(ds|beta|edge|nightly|daily|git)$|^miriway$|^wormhole$|printer-app$|^ufw$)")
# no publisher gives more than this many snaps, so the suite isn't one vendor's: two for a community
# packager the store stars (qiplex's and keshavnrj's small web apps fill the store's lists), four for a
# vendor it has verified, more for the big projects
SNAP_PUBLISHER_CAP = {"starred": 2, "verified": 4}
SNAP_BIG_PUBLISHERS = {"kde": 8, "canonical": 6, "gnome": 6, "snapcrafters": 6}


def snap_find(params):
    req = urllib.request.Request("https://api.snapcraft.io/v2/snaps/find?" + urllib.parse.urlencode(
        {**params, "fields": "title,publisher,summary"}), headers={"Snap-Device-Series": "16"})
    for t in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r).get("results", [])
        except (OSError, ValueError):
            time.sleep(5 * (t + 1))
    return []


def snap_candidates(work, used):
    """Snaps in the store's order (featured first, then each section's best known, then by publisher)."""
    c = Cache(work / "snaps.json")
    if c.data.get("lists") != SNAP_SECTIONS + SNAP_PUBLISHERS:
        lists = [snap_find({"category": s}) for s in SNAP_SECTIONS]
        lists += [[x for x in snap_find({"q": p}) if x["snap"].get("publisher", {}).get("username") == p]
                  for p in SNAP_PUBLISHERS]
        order, meta = [], {}
        # round robin, so each section and publisher gives its first ones before any gives its tenth
        for i in range(max(map(len, lists))):
            for lst in lists:
                if i < len(lst) and lst[i]["name"] not in meta:
                    x = lst[i]
                    order.append(x["name"])
                    meta[x["name"]] = {"title": x["snap"].get("title", x["name"]),
                                       "publisher": x["snap"].get("publisher", {}).get("username"),
                                       "validation": x["snap"].get("publisher", {}).get("validation"),
                                       "summary": x["snap"].get("summary", "")}
        c.data = {"order": order, "meta": meta, "info": c.data.get("info", {}),
                  "lists": SNAP_SECTIONS + SNAP_PUBLISHERS}
        c.save()
    todo = [n for n in c.data["order"] if n not in c.data["info"]]
    with ThreadPoolExecutor(8) as ex:
        for n, d in zip(todo, ex.map(snap_gui.store_info, todo), strict=True):
            c.data["info"][n] = bool(d and snap_gui.keep(d))
    c.save()
    return [(n, c.data["meta"][n]) for n in c.data["order"] if c.data["info"].get(n)]


def pick_snaps(cands, used, per, skip, taken_names):
    """GUI snaps of known publishers (the store's verified or starred ones), in the store's order."""
    out, by_pub = [], collections.Counter()
    for n, m in cands:
        if len(out) >= per:
            break
        if SNAP_NOT_GUI.search(n) or skipped(skip, n) or (m["validation"] not in ("verified", "starred") and \
                m["publisher"] not in SNAP_PUBLISHERS):
            continue
        if re.search(r"(?i)\b(command[- ]line|cli|terminal|server|daemon|theme|library|runtime|compositor|"
                     r"window manager|desktop environment)\b", m["summary"]):
            continue
        if by_pub[m["publisher"]] >= SNAP_BIG_PUBLISHERS.get(m["publisher"], SNAP_PUBLISHER_CAP.get(m["validation"], 2)):
            continue
        # by its title too: organize-my-files is "Easy File Organizer", which batch 10 had as easy-file-organizer
        if is_used(used, f"p-snap-{n}", n, snap=n) or is_used(used, "", m["title"]) or norm(n) in taken_names \
                or norm(m["title"]) in taken_names:
            continue
        # one of a publisher's editions: alfacast and alfacastx are the same screen mirror
        if any(x["source"]["name"].startswith(n) or n.startswith(x["source"]["name"]) for x in out
               if x["_publisher"] == m["publisher"]):
            continue
        taken_names.add(norm(n))
        by_pub[m["publisher"]] += 1
        out.append({"key": f"p-snap-{n}", "name": m["title"], "route": "snap",
                    "why": f"popular: snap store, by {m['publisher']}", "source": {"type": "snap", "name": n},
                    "_publisher": m["publisher"]})
    return out


# ------------------------------------------------------------------ Windows (winget)

# vendors whose programs are widely used: a winget id starting with one of these is well known
WINGET_VENDORS = ["Mozilla", "Google", "VideoLAN", "GIMP", "Inkscape", "Audacity", "OBSProject", "KDE", "BlenderFoundation", "Microsoft", "Adobe", "Valve", "Zoom", "SlackTechnologies", "Discord", "Spotify", "Notepad++", "7zip", "RARLab", "TheDocumentFoundation", "Apache", "Oracle", "JetBrains", "Python", "Git", "GitHub", "Docker", "Brave", "Opera", "Vivaldi", "Telegram", "OpenWhisperSystems", "WhatsApp", "Dropbox", "Nextcloud", "ownCloud", "KeePassXCTeam", "DominikReichl", "Bitwarden", "AgileBits", "Piriform", "IrfanSkiljan", "Greenshot", "ShareX", "HandBrake", "Gyan", "MKVToolNix", "CodecGuide", "PeterPawlowski", "Foobar2000", "Winamp", "DuongDieuPhap", "Daum", "PotPlayer", "calibre", "SumatraPDF", "TrackerSoftware", "Foxit", "Mendeley", "Zotero", "DigitalScholar", "Anki", "Obsidian", "Notion", "Evernote", "Joplin", "TeamViewer", "AnyDesk", "RealVNC", "TigerVNC", "PuTTY", "WinSCP", "FileZilla", "Wireshark", "WiresharkFoundation", "Insecure", "Nmap", "Postman", "Insomnia", "HeidiSQL", "DBeaver", "dbeaver", "MongoDB", "Logitech", "Corsair", "Elgato", "NVIDIA", "AMD", "Intel", "Canonical", "Unity", "Epic", "Godot", "GodotEngine", "Kitware", "OpenSCAD", "FreeCAD", "KiCad", "LibreCAD", "Autodesk", "SketchUp", "Ultimaker", "Prusa3D", "PrusaResearch", "Bambulab", "SoftFever", "Krita", "darktable", "RawTherapee", "Paint.NET", "dotPDN", "Audacity", "Ableton", "Cockos", "MuseScore", "LMMS", "Ardour", "Reaper", "Mixxx", "Sonic", "Image-Line", "Steinberg", "Avidemux", "Shotcut", "Meltytech", "OpenShot", "Kdenlive", "Natron", "Blackmagic", "BlackmagicDesign", "Calibre", "Tor", "TorProject", "qBittorrent", "Transmission", "Deluge", "Tixati", "Vuze", "Mullvad", "ProtonTechnologies", "Proton", "NordVPN", "Signal", "Element", "Mattermost", "RocketChat", "Zulip", "Thunderbird", "Mailbird", "eM", "Postbox", "Citrix", "VMware", "Oracle.VirtualBox", "Hashicorp", "CPUID", "TechPowerUp", "REALiX", "HWiNFO", "CrystalDewWorld", "Rufus", "Balena", "Ventoy", "AOMEI", "EaseUS", "Macrium", "Malwarebytes", "ESET", "Avast", "Kaspersky", "voidtools", "Everything", "WinMerge", "WinDirStat", "JAMSoftware", "Files-Community", "Flow-Launcher", "Ditto", "Espanso", "AutoHotkey", "PowerToys", "ScummVM", "DOSBox", "RetroArch", "Libretro", "PPSSPPTeam", "Dolphin", "DolphinEmu", "PCSX2Team", "Citra", "Ryujinx", "RPCS3", "Xemu", "DuckStation", "Stellarium", "Celestia", "GeoGebra", "Maxima", "Octave", "GNU", "QGIS", "OSGeo", "JOSM", "Gpg4win", "GnuPG", "Cryptomator", "VeraCrypt", "IDRIX", "Syncthing", "Resilio", "Mega", "MEGA", "Box", "pCloud", "Amazon", "Kindle", "Plex", "Kodi", "XBMC", "Jellyfin", "Emby", "Stremio", "Popcorn", "MediaMonkey", "AIMP", "MusicBee", "Clementine", "Strawberry", "Tidal", "Deezer", "Audible", "Sublime", "SublimeHQ", "Neovim", "Vim", "vim", "Emacs", "GNU.Emacs", "Geany", "Notepad3", "NotepadNext", "Atom", "Brackets", "Eclipse", "ApacheNetBeans", "Racket", "RStudio", "Posit", "Anaconda", "Jupyter", "Arduino", "ArduinoSA", "Espressif", "Fritzing", "Lightburn", "Inkscape", "Scribus", "Calligra", "Xournal", "Xournalpp", "Rnote", "Krita", "Pinta", "Darktable", "digiKam", "FastStone", "XnSoft", "Nomacs", "ImageGlass", "HoneyView", "Bandizip", "Bandisoft", "PeaZip", "Giorgiotani", "NanaZip", "M2Team"]
WINGET_PRERELEASE = re.compile(r"(?i)(alpha|beta|preview|nightly|canary|insider|(?<![a-z])rc\d*(?![a-z]))")
WINGET_KINDS = {"msi": "msi", "wix": "msi", "inno": "inno", "nullsoft": "nsis", "zip": "portable", "portable": "portable",
                "exe": "exe", "burn": "exe"}
WINGET_NOT_APP = re.compile(r"(?i)\b(driver|drivers|runtime|redistributable|redist|sdk|server|cli|font|fonts|plugin|"
                            r"plug-in|extension|add-?in|jdk|jre|toolkit|library|framework|webview2|vc\+\+|directx|"
                            r"codec|codecs|bootstrapper|beta|preview|nightly|insiders?|canary|dev|rc|eap|webdriver|daemon|service|agent|"
                            r"updater|uninstaller|helper|console|shell|powershell|terminal|python|git|node|nodejs|"
                            r"openjdk|java|dotnet|\.net|build ?tools|vpn|antivirus|firmware|bios|update)\b")


def winget_candidates(work, index, repos):
    """Latest winget manifests of the packages that might be well known.

    Those of the big vendors (WINGET_VENDORS, by the first part of the id) and those whose id ends
    in the name of a GitHub repo with many stars (repos: the topic searches' results), fetched from
    winget's CDN. Returns {"ids": {id: [version, manifest path, versions in winget]},
    "manifests": {id: text}}.
    """
    c = Cache(work / "winget.json")
    if "ids" not in c.data or "versions" not in c.data:
        db = sqlite3.connect(index)
        parts = {r: (p, s) for r, p, s in db.execute("select rowid, parent, pathpart from pathparts")}

        def path(r):
            out = []
            while r is not None:
                p, s = parts[r]
                out.append(s)
                r = p
            return "/".join(reversed(out))
        with_cmd = {m for (m,) in db.execute("select distinct manifest from commands_map")}

        def vkey(v):
            return [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", v)]
        latest, versions = {}, collections.Counter()
        for mid, pid, ver, pp in db.execute("select m.rowid, i.id, v.version, m.pathpart from manifest m "
                                            "join ids i on m.id=i.rowid join versions v on m.version=v.rowid"):
            versions[pid] += 1
            cur = latest.get(pid)
            cmd = mid in with_cmd or bool(cur and cur[2])
            if cur is None or vkey(ver) > vkey(cur[0]):
                latest[pid] = (ver, path(pp), cmd)
            elif cmd:
                latest[pid] = (cur[0], cur[1], True)
        vendors = {v.lower() for v in WINGET_VENDORS}
        starred = {norm(r.split("/")[1]) for r, i in repos.items() if i["stars"] >= 1000} - {""}
        ids = {pid: [v[0], v[1], versions[pid]] for pid, v in latest.items()
               if not v[2] and not WINGET_NOT_APP.search(pid.replace(".", " "))
               and (pid.split(".")[0].lower() in vendors or norm(pid.split(".")[-1]) in starred)}
        c.data = {"ids": ids, "manifests": c.data.get("manifests", {}), "versions": True}
        c.save()
    todo = [p for p in c.data["ids"] if p not in c.data["manifests"]]

    def fetch(pid):
        try:
            return pid, winget_sample.get("https://cdn.winget.microsoft.com/cache/" + c.data["ids"][pid][1])[2] \
                .decode("utf-8", "replace")
        except Exception:
            return pid, None
    with ThreadPoolExecutor(8) as ex:
        for i, (pid, text) in enumerate(ex.map(fetch, todo)):
            c.data["manifests"][pid] = text
            if i % 200 == 0:
                c.save()
    c.save()
    return c.data


def pick_winget(work, data, used, per, skip, taken_names, known, taken_repos=frozenset()):
    """Well-known GUI packages, a quarter or so of each installer kind (MSI, Inno, NSIS, portable).

    Two lists are drawn from in turn: the big vendors' programs (WINGET_VENDORS), the one with most
    versions in winget first (kept up longest), and the packages whose source is a repo the GUI topic
    searches found (known), most starred first; a repo those searches didn't find (protobuf,
    ninja, Z3) is no GUI program. Packages with a command (winget's commands list), a pre-release
    version or a description of a tool, server or library are left out.
    """
    import yaml
    cands = []
    for pid, text in data["manifests"].items():
        if not text or skipped(skip, pid):
            continue
        m = yaml.safe_load(text)
        name = m.get("PackageName") or pid
        tags = " ".join(map(str, m.get("Tags") or [])).lower()
        if WINGET_NOT_APP.search(name) or re.search(r"\b(cli|command-line|terminal|server|driver|library|sdk)\b", tags):
            continue
        if WINGET_PRERELEASE.search(data["ids"][pid][0]) or NOT_GUI.search(str(m.get("ShortDescription") or "")):
            continue
        inst = m.get("Installers") or []

        def ok(i, m=m):
            t = (i.get("InstallerType") or m.get("InstallerType") or "").lower()
            if t == "zip":
                t = (i.get("NestedInstallerType") or m.get("NestedInstallerType") or "").lower()
                t = "zip" if t in ("portable", "") else t
            return t in WINGET_KINDS and i.get("InstallerUrl") and "apps.microsoft.com" not in i["InstallerUrl"] \
                and (i.get("Scope") or "machine") in ("machine", "user")
        pick = [i for i in inst if ok(i) and i.get("Architecture") in ("x64", "neutral")] or \
               [i for i in inst if ok(i) and i.get("Architecture") == "x86"]
        if not pick:
            continue
        i = pick[0]
        t = (i.get("InstallerType") or m.get("InstallerType") or "").lower()
        if t == "zip":
            nt = (i.get("NestedInstallerType") or m.get("NestedInstallerType") or "portable").lower()
            t = "zip" if nt == "portable" else nt
        src = " ".join(str(m.get(k) or "") for k in ("PackageUrl", "PublisherUrl", "ReleaseNotesUrl")) + " " + i["InstallerUrl"]
        gm = re.search(r"github\.com/([\w.-]+/[\w.-]+)", src)
        repo = gm.group(1).removesuffix(".git") if gm else None
        cands.append({"id": pid, "ver": data["ids"][pid][0], "name": name, "kind": WINGET_KINDS[t],
                      "url": i["InstallerUrl"], "repo": repo})
    vendors = {v.lower() for v in WINGET_VENDORS}
    low = {k.lower(): (k, v) for k, v in known.items()}
    by_vendor, by_stars = [], []
    for cnd in cands:
        r = low.get((cnd["repo"] or "").lower())
        cnd["stars"] = r[1]["stars"] if r else 0
        if cnd["id"].split(".")[0].lower() in vendors:
            by_vendor.append(cnd)
        elif r and r[1]["stars"] >= 1000 and looks_gui(r[0], r[1]):
            by_stars.append(cnd)
    by_vendor.sort(key=lambda c: (-data["ids"][c["id"]][2], c["id"]))
    by_stars.sort(key=lambda c: (-c["stars"], c["id"]))
    cands = [c for pair in zip(by_vendor, by_stars, strict=False) for c in pair]
    cands += by_vendor[len(by_stars):] + by_stars[len(by_vendor):]
    quota = {"msi": per // 4, "inno": per // 4, "nsis": per // 4, "portable": per - 3 * (per // 4)}
    out, bases, overflow = [], set(), []
    for cnd in cands:
        base = ".".join(cnd["id"].split(".")[:2])
        key = "p-win-" + re.sub(r"[^a-z0-9]+", "-", cnd["id"].lower()).strip("-")
        if base in bases or is_used(used, key, cnd["name"], cnd["repo"], winget=cnd["id"]) \
                or norm(cnd["name"]) in taken_names or fname(cnd["url"]).lower() in used["files"] \
                or (cnd["repo"] or "").lower() in taken_repos:
            continue
        a = {"key": key, "name": cnd["name"], "route": "wine",
             "why": f"winget sample {cnd['id']} {cnd['ver']} (popular: {cnd['kind']}"
                    + (f", github.com/{cnd['repo']} {cnd['stars']} stars" if cnd["stars"] else "") + ")",
             "source": {"type": "url", "url": cnd["url"]}, "_kind": cnd["kind"]}
        full = quota.get(cnd["kind"], 0) <= sum(1 for x in out if x["_kind"] == cnd["kind"])
        if full:
            overflow.append((base, a))
            continue
        if winget_sample.link_dead(cnd["url"]) or not link_ok(cnd["url"]):
            print("dead link:", cnd["id"], cnd["url"], file=sys.stderr)
            continue
        bases.add(base)
        taken_names.add(norm(cnd["name"]))
        out.append(a)
        if len(out) >= per:
            break
    for base, a in overflow:                  # a kind that ran short leaves room for the others
        if len(out) >= per:
            break
        if base in bases or norm(a["name"]) in taken_names or not link_ok(a["source"]["url"]):
            continue
        bases.add(base)
        taken_names.add(norm(a["name"]))
        out.append(a)
    return out


# ------------------------------------------------------------------ the draw

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("work")
    ap.add_argument("out")
    ap.add_argument("catalogs", nargs="+")
    ap.add_argument("--winget-index", help="winget's index.db (from source.msix's Public/ folder)")
    ap.add_argument("--releases", nargs="*", default=[],
                    help="latest releases already read, as releases_html.py writes them ({repo: {tag, assets}})")
    ap.add_argument("--per", type=int, default=45)
    ap.add_argument("--min-stars", type=int, default=500)
    ap.add_argument("--low-stars", type=int, default=200,
                    help="also search repos with this many stars up to --min-stars, for routes that run short")
    ap.add_argument("--pages", type=int, default=3, help="pages of 100 per topic search")
    ap.add_argument("--skip", default=str(Path(__file__).with_name("popular-skip.txt")),
                    help="a file of repos, snaps and winget ids left out by hand (one per line, # comments)")
    a = ap.parse_args(argv)
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    used = used_from(a.catalogs)
    skip = set()
    if Path(a.skip).exists():
        skip = {l.split("#")[0].strip().lower() for l in open(a.skip)} - {""}
    web_cap = a.per // 3

    known = {}
    for f in a.releases:
        known.update(json.loads(Path(f).read_text()))
    cands = github_candidates(work, used, a.min_stars, a.pages, known, a.low_stars)
    picked = pick_github(cands, used, a.per, web_cap, skip)
    taken = {norm(x["name"]) for v in picked.values() for x in v}
    taken_repos = {x["why"].split("github.com/")[1].split()[0].lower() for v in picked.values() for x in v}
    picked["snap"] = pick_snaps(snap_candidates(work, used), used, a.per, skip, taken)
    if a.winget_index:
        repos = search_github(work, a.min_stars, a.pages, a.low_stars)
        picked["wine"] = pick_winget(work, winget_candidates(work, a.winget_index, repos), used, a.per, skip, taken,
                                     repos, taken_repos)

    apps = [{k: v for k, v in x.items() if not k.startswith("_")} for r in ROUTES for x in picked.get(r, [])]
    Path(a.out).write_text(json.dumps({"apps": apps}, indent=1) + "\n")
    for r in ROUTES:
        xs = picked.get(r, [])
        web = sum(1 for x in xs if x.get("_web"))
        extra = f", {web} web wrappers" if r in ("appimage", "deb", "rpm", "tarball") else ""
        kinds = dict(collections.Counter(x["_kind"] for x in xs)) if r == "wine" else ""
        print(f"{r}: {len(xs)}{extra} {kinds}")
    print(len(apps), "->", a.out)


if __name__ == "__main__":
    main()
