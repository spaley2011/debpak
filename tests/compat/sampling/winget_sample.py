"""Random sample of winget GUI apps for the wine route. Usage: winget_sample.py index.db USED.json N SEED OUT.json

A package whose installer link is dead when it's drawn is passed over: CuteCut Pro's link answered
404 and BomberClone's (www.bomberclone.de/stuff/...) now leads to an article about the game on
another site, and both came out of batch 1 as failed downloads that no conversion could fix. A
manifest or link check that times out is tried again.
"""
import json, random, re, sqlite3, sys, time, urllib.error, urllib.parse, urllib.request

PASSING = (408, 425, 429, 500, 502, 503, 504)


def get(url, tries=4, headers=None, limit=None):
    """urlopen url, trying again while it times out or the server is busy; return (final URL, headers, body).

    The body is read whole, or its first limit bytes.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "debpak-compat", **(headers or {})})
    for t in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.geturl(), r.headers, (r.read(limit) if limit else r.read())
        except urllib.error.HTTPError as e:
            if e.code not in PASSING or t == tries - 1:
                raise
        except (OSError, ValueError):
            if t == tries - 1:
                raise
        time.sleep(5 * (t + 1))


def link_dead(u, opener=get):
    """Why an installer link is dead (404, 410, or a web page in place of the file), or None if it isn't.

    A link that can't be checked at all (a timeout every time, a server that refuses robots) is
    taken as live: the compat run tries it again and reports it.
    """
    try:
        final, headers, head = opener(u, headers={"Range": "bytes=0-262143"}, limit=1 << 18)
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}" if e.code in (404, 410) else None
    except (OSError, ValueError):
        return None
    path = urllib.parse.unquote(urllib.parse.urlparse(u).path)
    page = (headers.get("Content-Type") or "").split(";")[0].strip() in ("text/html", "application/xhtml+xml") \
        or head.lstrip()[:15].lower().startswith((b"<!doctype html", b"<html"))
    if not page or path.lower().endswith((".htm", ".html")):
        return None
    # a landing page that links to the file (SourceForge's /download pages) is followed by the compat run
    parts = [p for p in path.split("/") if p and p != "download"]
    if parts and re.search(rb"""(href|content|url)=["']?[^"'>\s]*""" + re.escape(parts[-1].encode()), head, re.I):
        return None
    return f"a web page with no link to the file ({final})"


def main():
    import yaml
    db, used_f, n, seed, out_f = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
    used = json.load(open(used_f))
    used_names = {re.sub(r"[^a-z0-9]", "", x.lower()) for x in used["names"]}
    used_files = set(used["files"])
    c = sqlite3.connect(db)
    parts = {r: (p, s) for r, p, s in c.execute("select rowid, parent, pathpart from pathparts")}
    def path(r):
        out = []
        while r is not None:
            p, s = parts[r]; out.append(s); r = p
        return "/".join(reversed(out))
    with_cmd = {m for (m,) in c.execute("select distinct manifest from commands_map")}
    def vkey(v):
        return [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", v)]
    latest = {}
    for mid, pid, ver, pp in c.execute("select m.rowid, i.id, v.version, m.pathpart from manifest m join ids i on m.id=i.rowid join versions v on m.version=v.rowid"):
        cmd = mid in with_cmd
        cur = latest.get(pid)
        if cur is None or vkey(ver) > vkey(cur[0]):
            latest[pid] = (ver, pp, cmd or (cur[2] if cur else False))
        elif cmd:
            latest[pid] = (cur[0], cur[1], True)
    ids = sorted(latest)
    random.Random(seed).shuffle(ids)
    NOT_APP = re.compile(r"(?i)\b(driver|drivers|runtime|redistributable|redist|sdk|server|cli|font|fonts|plugin|plug-in|extension|add-?in|jdk|jre|toolkit|library|framework|webview2|vc\+\+|directx|codec|codecs|bootstrapper|beta|preview|nightly|insiders?|canary|dev)\b")
    OK_TYPES = {"exe", "inno", "nullsoft", "msi", "wix", "burn", "zip", "portable"}
    picked = []
    for pid in ids:
        if len(picked) >= n:
            break
        ver, pp, cmd = latest[pid]
        if cmd or NOT_APP.search(pid.replace(".", " ")):
            continue
        url = "https://cdn.winget.microsoft.com/cache/" + path(pp)
        try:
            m = yaml.safe_load(get(url)[2])
        except Exception as e:
            print("skip", pid, e, file=sys.stderr); continue
        name = m.get("PackageName") or pid
        if NOT_APP.search(name) or re.sub(r"[^a-z0-9]", "", name.lower()) in used_names:
            continue
        tags = " ".join(map(str, m.get("Tags") or [])).lower()
        if re.search(r"\b(cli|command-line|terminal-tool)\b", tags):
            continue
        inst = m.get("Installers") or []
        def ok(i):
            t = (i.get("InstallerType") or m.get("InstallerType") or "").lower()
            return t in OK_TYPES and i.get("InstallerUrl") and "apps.microsoft.com" not in i["InstallerUrl"]
        cands = [i for i in inst if ok(i) and i.get("Architecture") in ("x64", "neutral")] or \
                [i for i in inst if ok(i) and i.get("Architecture") == "x86"]
        if not cands:
            continue
        i = cands[0]
        u = i["InstallerUrl"]
        fname = urllib.parse.unquote(urllib.parse.urlparse(u).path.rsplit("/", 1)[-1]).lower()
        if fname in used_files:
            continue
        if (dead := link_dead(u)):
            print("skip", pid, "dead link:", dead, file=sys.stderr)
            continue
        key = re.sub(r"[^a-z0-9]+", "-", pid.lower()).strip("-")
        picked.append({"key": "w-" + key, "name": name, "route": "wine", "why": f"winget sample {pid} {ver}",
                       "source": {"type": "url", "url": u}})
        print(len(picked), pid, (i.get("InstallerType") or m.get("InstallerType")), file=sys.stderr, flush=True)
    json.dump({"apps": picked}, open(out_f, "w"), indent=1)


if __name__ == "__main__":
    main()
