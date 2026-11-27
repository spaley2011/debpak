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

## The batch loop

Each batch is 200 apps debpak has never seen, about 33 of each type (AppImage, .deb, .rpm,
tarball, snap and Windows). No app is drawn twice, by name, by GitHub repo or in another format:
the 15 batches, the validation set and the final test set together hold 3,540 apps with no
repeats.

A batch's first pass gives its first-try rate, per type and overall, which is the honest measure
of how debpak does on apps it hasn't seen. After each first pass, `causes.py` ranks the first-try
failures of every batch so far by their cause, and the most common causes go to fix agents
first. Fixes are general rules, never special cases for one app.

A batch is then fixed and tested again until it clears the bar that `summary.py` prints: at
least 95% passing, 190 of 200, since these apps go into the Flatpak repo. For the bar an app
passes when it shows a working window with no error; a command-line program that converts and
runs passes too, and so does a refusal of a system service or a driver, which no Flatpak can be.
Apps that can't work outside their own OS are dropped from the batch with the user's say-so and
listed in the batch folder's `dropped.json`. A theme snap with no apps is no app at all. Failed
lookups and downloads count against the bar.

Batches overlap to keep the machine busy: the next batch's first pass can run while earlier ones
are being fixed, but each has to clear the bar.

After batches 5, 10 and 15 (and every fifth batch after that, however many there are), the
validation set, `holdout-v.json`, 270 apps, 45 of each type, is run again on the code of the
day. A batch holds about 33 apps of each type, too few to tell a few points from luck; the
validation set is larger and the same each time, so its first-try rate shows what the fixes did
for apps debpak hasn't seen. Its failures are not handed to fix agents, so that it stays a
measure and never becomes a training set; the final test set, `holdout-t.json`, stays untouched
until the very end.

The work stops only when two batches in a row have a first-try rate above 90% on every type, the
latest run of the validation set is above 90% on every type too, the results make sense, and not
before 3,000 apps.

The runs use as much of the machine as is safe: they back off when free memory drops below about
6 GB (with zram swap as a cushion), when the RAM disk passes about 85%, or when the SSD starts
timing out. At most three runs go at once: a fourth, started at 03:00 on the 27th with
the processor idle, brought a dozen SSD timeouts within ten minutes, because the disk, not the
processor, is what they share. Fix agents work in the cloud, never on the test machine, and every broad problem
group has one. They never use the web fetch or web search tools, which wait for the user to
approve each call; the shell's curl and git do instead. Each app is uninstalled after its test, and a cleanup job removes what stopped
runs leave behind. A status report goes out every 10 minutes and is kept in
`~/holdout/reports.log` on the test machine.

New code reaches the test machine only through `~/holdout-scripts/deploy.sh BUNDLE`. It checks
each version out into a folder of its own under `~/debpak-trees` and then points `~/debpak-latest`
at it in one rename. A run keeps the tree it started on, and the next run in a chain starts on the
newest. Checking a version out over a folder that live runs are reading gives them half of one
version and half of the next: on the night of the 27th, 17 conversions failed to import that way.
Apps whose attempt the test setup broke like this go in the batch folder's `torn.json`. Since they
were never really tried, `summary.py` counts their next attempt as their first try.
