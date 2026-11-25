# Drawing apps debpak has never seen

These scripts pick the apps for the holdout runs: a validation set, a final test set that nothing is
fixed from, and batches of 200 for the fix-and-retest loop. Each set is a random draw, the same number
of apps of each package type, with no app that any catalog in tests/compat or any earlier set has.

The GitHub repos come from topic searches (`gh search`) and the AppImage feed. `releases_html.py` reads
each repo's latest release from github.com's pages, `classify.py` sorts the Linux x86-64 downloads
into AppImage, .deb, .rpm and tarball, `winget_sample.py` draws Windows apps from winget's index, and
`snap_gui.py` keeps the snaps whose store page has a screenshot. `batches.py` then draws the final
test set (45 per type) and the batches; `assemble.py` drew the validation set. Command-line tools,
servers and libraries are left out by name, and the ones that slip through are counted apart.

`why.py` shows why the apps of a run failed, and `summary.py` gives each type's pass rate on the
first try and after the fixes.
