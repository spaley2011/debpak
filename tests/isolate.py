"""Keep CLI tests from depending on the machine they run on.

On a machine with flatpak-builder installed, `debpak convert` builds and
installs by default, and every conversion asks Flathub whether the app is
already there. Tests that check conversions run inside offline(), which hides
flatpak-builder and answers every Flathub search with nothing, so they behave
the same everywhere. Tests that want a builder or Flathub use stand-in tools
instead (test_snap, test_recipes).
"""
import contextlib
import shutil
from unittest import mock

_real_which = shutil.which


def _which(name, *args, **kwargs):
    if name == "flatpak-builder":
        return None
    return _real_which(name, *args, **kwargs)


@contextlib.contextmanager
def offline():
    with mock.patch("shutil.which", _which), mock.patch("debpak.manage.flathub_search", return_value=[]):
        yield
