"""Pins the snap.yaml parser's results on the YAML it handles, including its odd corners.

The expected values were taken from the parser before it was split into a class,
so a later change that alters any of them is a change in behavior.
"""
from __future__ import annotations

import unittest

from debpak.snap import parse_yaml


class ParseYamlPinnedTests(unittest.TestCase):
    def test_block_scalars(self):
        self.assertEqual(parse_yaml("a: |\n  one\n\n  two\n\nb: x\n"), {"a": "one\n\ntwo\n", "b": "x"})
        self.assertEqual(parse_yaml("s: >\n  folded\n  line\n\n  para\nn: 1\n"), {"s": "folded line\npara\n", "n": "1"})

    def test_continued_scalars_and_flow_collections(self):
        self.assertEqual(parse_yaml("d: \"quoted\n  over lines\"\ne: plain\n  continued\nf: [a, 'b, c', {k: v}]\n"),
                         {"d": "quoted over lines", "e": "plain continued", "f": ["a", "b, c", {"k": "v"}]})

    def test_quotes_escapes_and_comments(self):
        text = "g: {x: [1, 2], ' y': \"z#\"}  # comment\nh: 'it''s'\ni: \"\\u00e9\\n\\t\"\nj: a#b\n"
        self.assertEqual(parse_yaml(text), {"g": {"x": ["1", "2"], " y": "z#"}, "h": "it's", "i": "é\n\t", "j": "a#b"})

    def test_sequences(self):
        text = ("apps:\n  foo:\n    plugs:\n    - x11\n    - wayland\n"
                "list:\n- key: v\n  other: w\n- plain\n-\n  - nested\n")
        self.assertEqual(parse_yaml(text), {"apps": {"foo": {"plugs": ["x11", "wayland"]}},
                                            "list": [{"key": "v", "other": "w"}, "plain", ["nested"]]})
        self.assertEqual(parse_yaml("---\nk:\nm:\n  - \n"), {"k": None, "m": [None]})

    def test_empty_and_unhashable_keys(self):
        self.assertEqual(parse_yaml(""), {})
        self.assertEqual(parse_yaml("# only a comment\n---\n"), {})
        for text in ("x: {[a]: b}\n", "[a]: b\n"):
            with self.assertRaisesRegex(TypeError, "unhashable type: 'list'"):
                parse_yaml(text)


if __name__ == "__main__":
    unittest.main()
