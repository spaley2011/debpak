"""Assign each repo (latest release) to one route by its Linux x86-64 assets. Usage: classify.py releases.json used.json"""
import json, re, sys, collections, urllib.parse
rel = json.load(open(sys.argv[1])); used = json.load(open(sys.argv[2]))
used_repos = set(used["repos"]); used_names = {re.sub(r"[^a-z0-9]", "", n.lower()) for n in used["names"]}
OTHER_ARCH = re.compile(r"(?i)(arm64|aarch64|armhf|armv7|arm(?![a-z])|i[36]86|(?<![0-9])386|ia32|linux32|x86(?![_-]?64)|32-?bit|ppc64|s390x|riscv|loong|mips)")
# command-line tools, servers and daemons aren't what the compat suite tests (it looks for a window)
NOT_GUI = re.compile(r"(?i)(\b|[-_.])(cli|server|daemon|headless|tui|agent|bot|sdk|lib|api)(\b|[-_.])|tui(\b|[-_.])|^lazy")
def fname(u): return urllib.parse.unquote(u.rsplit("/", 1)[-1])
def kind(n):
    l = n.lower()
    if NOT_GUI.search(n) or OTHER_ARCH.search(l) or re.search(r"(?i)(\.sha\d+|\.sig|\.asc|\.zsync|\.blockmap|debug|dbg|src\.rpm|source)", l): return None
    if l.endswith(".appimage"): return "appimage"
    if l.endswith(".deb"): return "deb"
    if l.endswith(".rpm"): return "rpm"
    if ".pkg.tar" in l: return None          # an Arch Linux package, not a tarball
    if re.search(r"\.(tar\.(gz|xz|bz2|zst)|tgz)$", l) and re.search(r"linux", l) and not re.search(r"(?i)(mac|darwin|osx|windows|win(32|64)?[._-])", l): return "tarball"
    return None
by = collections.defaultdict(dict)
for repo, r in rel.items():
    if repo.lower() in used_repos: continue
    short = re.sub(r"[^a-z0-9]", "", repo.split("/")[1].lower())
    if short in used_names or NOT_GUI.search(repo.split("/")[1]): continue
    for u in r["assets"]:
        k = kind(fname(u))
        if k and k not in by[repo]: by[repo][k] = u
c = collections.Counter(k for v in by.values() for k in v)
print(len(rel), "repos with releases;", len(by), "with linux assets;", dict(c))
json.dump(by, open("linux-assets.json", "w"), indent=0)
