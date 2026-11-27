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

## The popular suite

The random draws turned out to be mostly small hobby projects, and half of their Linux apps are
Electron or Tauri, so a high first-try rate on them says little about the programs people use most.
`tests/compat/popular.json` is a separate suite weighted the other way: 270 apps, 45 of each type,
chosen for demand and size. It is run like any catalog (`compat.py --catalog tests/compat/popular.json`),
and its numbers are reported apart from the batches'.

`popular.py` draws it. For the four Linux types it takes the most starred GitHub repos found by
topic searches (GUI toolkits, games, emulators, creative tools, IDEs, office, media, science and
the like, above 500 stars, then from 200 where a type runs short) whose latest release has a Linux
x86-64 file of that type, read with `classify.py`'s rules. Each repo gives one app, to the type it
can fill best. Electron, Tauri and other web view apps are held to a third of each type, told
apart by the repo's topics and language and by their release files (electron-builder's
latest-linux.yml, Tauri's signed AppImage updates). Snaps come from the store's featured section
and the head of its topic sections, with the KDE, GNOME, Canonical and big-vendor publishers'
snaps among them, GUI only (`snap_gui.py`'s test) and no more than a few per publisher. Windows
apps are winget packages of big vendors and of GitHub repos with many stars, taken in turn, with
about a quarter each of MSI, Inno Setup, NSIS and portable installers. Command-line tools, servers,
libraries, drivers and themes are left out by their descriptions, and what slips through is
listed by name in `popular-skip.txt` with the reason. No app any earlier set has is drawn (by key,
name, repo, snap or winget id), and every link is checked before it is kept.

The draw of the 27th was made in a sandbox whose GitHub access allowed searches but not a repo's
releases, so the GitHub apps were drawn from the repos whose releases the batch draws had already
read on the test machine (`releases.json`). The most starred repos still unread are in the work
folder's `unread-repos.txt`; reading them with `releases_html.py` and running `popular.py` again
with `--releases` adds them to the pool.

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
for apps debpak hasn't seen. Its first pass is the number that counts, and it is kept as it came out
(`results.firstpass.json` in its folder). Once that pass is in, its failures are fixed like any batch's,
at the user's direction (27th), so that no known failure ships; the numbers reported for it stay
those of the first pass. The final test set, `holdout-t.json`, stays untouched until the very end.

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

From 09:40 on the 27th the machine runs in lanes, at the user's direction. One lane runs first passes of new
batches, always on the newest code, so fixes show in first-try numbers as soon as they land. One lane runs
retries, one batch after another. One runs the validation set when it is due. Fix agents build and test
their fixes on the machine in a small lane of their own, one app at a time each (`-j 1 --ram-gb 1`), and
report what they saw rather than what they expect: fixes written from logs alone too often missed.

The bar is at least 189 passes in every batch, whatever is left out or dropped (the user, 10:36 on the
27th: "189+. full stop."). Ninety-five percent of the apps left still applies when it asks for more.
189 is a minimum, not a target (the user, 10:55 on the 27th): a batch that reaches it stays in the retry
rotation, and its failures keep going to fix agents, for as long as any of them has a general fix. Batches
under 189 get the retry lane first.
