"""CLI paths the other tests don't reach: update's exit status, install's question, runtime-index and smoke errors."""
import contextlib
import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from debpak import cli, manage, recipes


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = cli.main(list(argv))
    return code, out.getvalue()


class TestUpdateStatus(unittest.TestCase):
    REG = {"a.a.a": {"output": "/o/a", "options": {"mirror": "m"}},
           "b.b.b": {"recipe": "B", "recipe_source": "src", "output": "/o/b"},
           "c.c.c": {"output": "/o/c"}}

    def update(self, *argv, checks, codes=()):
        ran, codes = [], iter(codes)
        real_main = cli.main

        def fake_main(av=None):
            if av and av[0] in ("install", "convert"):
                ran.append(av)
                return next(codes)
            return real_main(av)

        def check(app_id, entry, download, workdir):
            status, new_file = checks[app_id]
            return SimpleNamespace(status=status, detail="d", new_file=new_file)
        with mock.patch.object(manage, "load_registry", lambda: self.REG), \
                mock.patch.object(manage, "check_update", check), \
                mock.patch.object(manage, "update_workdir", lambda: Path("/nonexistent/debpak-update")), \
                mock.patch.object(cli, "main", fake_main):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                code = fake_main(["update", *argv])
        return code, ran, out.getvalue()

    def test_a_failed_conversion_outranks_cant_check(self):
        code, ran, _ = self.update(checks={"a.a.a": ("can't check", None), "b.b.b": ("update available", None),
                                           "c.c.c": ("update available", "/new.deb")}, codes=[5, 0])
        self.assertEqual(code, 5)
        self.assertEqual(ran[0], ["install", "B", "--recipes", "src", "--yes"])
        self.assertEqual(ran[1][:7], ["convert", "/new.deb", "--app-id", "c.c.c", "-o", "/o/c", "--anyway"])

    def test_cant_check_keeps_an_earlier_status(self):
        code, ran, _ = self.update("b.b.b", "a.a.a", checks={"a.a.a": ("can't check", None),
                                                             "b.b.b": ("update available", None)}, codes=[7])
        self.assertEqual((code, len(ran)), (7, 1))

    def test_unknown_app_then_check_only(self):
        code, ran, text = self.update("x.y.z", "a.a.a", "--check", checks={"a.a.a": ("update available", "/n.deb")})
        self.assertEqual((code, ran), (1, []))
        self.assertIn("x.y.z wasn't installed by debpak", text)
        self.assertIn("a.a.a: update available (d)", text)


class TestInstallQuestion(unittest.TestCase):
    def install(self, *argv, tty=True, answer="y"):
        entry = {"id": "com.a.B", "recipe_sha256": "abc"}
        with mock.patch.object(recipes, "load_index", lambda src: {}), \
                mock.patch.object(recipes, "find", lambda index, name: [entry]), \
                mock.patch.object(recipes, "recipes_dir", lambda: Path("/nonexistent/recipes")), \
                mock.patch.object(recipes, "download", lambda src, e, dest: {"id": e["id"]}), \
                mock.patch.object(recipes, "describe", lambda r: "recipe\n"), \
                mock.patch.object(cli.sys.stdin, "isatty", lambda: tty, create=True), \
                mock.patch("builtins.input", lambda prompt: answer), \
                mock.patch.object(cli.host, "which", lambda name: None):
            return run_cli("install", "B", "--recipes", "/nonexistent", *argv)

    def test_no_terminal(self):
        code, text = self.install(tty=False)
        self.assertEqual(code, 1)
        self.assertIn("not asking without a terminal", text)

    def test_answer_no(self):
        self.assertEqual(self.install(answer=" n "), (1, "recipe\nNot installed.\n"))

    def test_yes_without_builder(self):
        code, text = self.install("--yes", tty=False)
        self.assertEqual(code, 1)
        self.assertIn("flatpak-builder isn't installed", text)


class TestRuntimeIndexAndSmokeErrors(unittest.TestCase):
    def test_runtime_index_needs_a_ref(self):
        self.assertIn("--root needs --ref", run_cli("runtime-index", "--root", "/x")[1])
        self.assertIn("give a runtime ref", run_cli("runtime-index")[1])

    def test_runtime_index_error(self):
        with mock.patch.object(cli, "get_index", side_effect=RuntimeError("not installed")):
            self.assertEqual(run_cli("runtime-index", "org.a.P//1"), (1, "debpak: error: not installed\n"))

    def test_smoke_needs_something_to_run(self):
        self.assertEqual(run_cli("smoke"), (1, "debpak: error: give a Flatpak app ID, --exec COMMAND or --log FILE\n"))


class TestNewerRuntimeInstall(unittest.TestCase):
    def test_installs_the_newer_branch_when_the_build_would(self):
        old = SimpleNamespace(id="org.freedesktop.Platform", branch="25.08", glibc="2.42")
        new = SimpleNamespace(ref="org.freedesktop.Platform/x86_64/26.08", glibc="2.43")
        indexes = iter([RuntimeError("not installed"), new])

        def get_index(ref, arch):
            got = next(indexes)
            if isinstance(got, Exception):
                raise got
            return got
        args = SimpleNamespace(runtime=None, runtime_index=None, no_build=False)
        a = SimpleNamespace(max_glibc="GLIBC_2.43")
        with mock.patch.object(cli, "get_index", get_index), \
                mock.patch.object(cli.host, "which", lambda name: "/usr/bin/flatpak-builder"), \
                mock.patch.object(cli, "_install_runtime", lambda ref, arch: True):
            self.assertIs(cli._newer_runtime(args, old, a, "x86_64"), new)
        with mock.patch.object(cli, "get_index", side_effect=RuntimeError("not installed")):
            self.assertIsNone(cli._newer_runtime(SimpleNamespace(**{**vars(args), "no_build": True}), old, a, "x86_64"))


if __name__ == "__main__":
    unittest.main()
