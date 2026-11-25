"""Which runtime an app gets from the libraries it was built against."""
import unittest

from debpak.analyze import kde_runtime_for_qt


class TestQtRuntime(unittest.TestCase):
    def test_newer_qt_than_the_default(self):
        self.assertEqual(kde_runtime_for_qt({"libQt6Core.so.6": {"Qt_6", "Qt_6.11"}}), "org.kde.Platform//6.11")

    def test_private_api_needs_that_exact_qt(self):
        self.assertEqual(kde_runtime_for_qt({"libQt6Widgets.so.6": {"Qt_6", "Qt_6.6_PRIVATE_API"}}),
                         "org.kde.Platform//6.6")

    def test_default_is_enough(self):
        self.assertIsNone(kde_runtime_for_qt({"libQt6Core.so.6": {"Qt_6", "Qt_6.5"}}))
        self.assertIsNone(kde_runtime_for_qt({"libc.so.6": {"GLIBC_2.34"}}))

    def test_no_runtime_has_it(self):
        self.assertIsNone(kde_runtime_for_qt({"libQt6Core.so.6": {"Qt_6.40"}}))


if __name__ == "__main__":
    unittest.main()
