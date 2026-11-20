# debpak

Import-gap analysis for running software outside its home platform. One engine has three backends:

| Tool      | Input                         | Target                    | What it answers |
|-----------|-------------------------------|---------------------------|-----------------|
| `debpak`  | Linux `.deb` (ELF)            | Flatpak runtime           | Which libraries are missing? Builds the Flatpak manifest. |
| `winegap` | Windows app (PE), or a Wine log | Wine / Proton           | Will it start? Which functions are stubs? What actually failed when it ran? Generates stub DLLs. |
| `machgap` | macOS `.app` (Mach-O)         | Darling                   | Will dyld load it? Which symbols and classes are missing or stubbed? |
| `gaprank` | reports from any of the above | the maintainers           | Which single fix unblocks the most apps? |

Static analysis predicts problems; `winegap trace` and `debpak smoke` confirm
them by running the app with Wine's or the Linux loader's logging on. Every gap
records how it was found (predicted, seen running, both, or a guess), and
`gaprank` ranks problems seen in real runs first.

Each backend parses what a binary imports (ELF `DT_NEEDED` and symbol versions,
PE import and delay-import tables, Mach-O linked dylibs and two-level
namespace bindings). It compares that against an index of what the target
environment provides, and classifies every gap by how the platform's loader
would react:

- **fatal**: the app won't start (a missing library, or a missing non-weak
  Mach-O symbol, since dyld binds at launch).
- **crash**: the app starts but aborts if it reaches the function (Wine stubs
  and missing exports).
- **degraded**: the app runs but a feature is missing: a stub that returns nil/0
  (Darling stubs, Wine `fixme ... stub`), or a library or COM object that failed
  to load at runtime.
- **optional**: the gap is in a weak or delay-loaded import, or in a plugin
  that nothing links statically.

All parsers (ELF, PE, Mach-O including universal binaries, and export tries)
are pure Python with no dependencies.

## Status

Early MVP (0.1). The Wine and Darling backends are tested against spec-conformant
synthetic binaries (and `objdump` for PE), not yet against a real app corpus. The analysis, gap resolution and manifest generation are
covered by an end-to-end test suite that builds real `.deb` fixtures. Real-world
builds with `flatpak-builder` have **not** been validated broadly yet, so treat
generated manifests as a strong first draft and review them.

## Install

```sh
pip install .            # installs debpak, winegap, machgap, gaprank; no runtime dependencies
pip install '.[zstd]'    # optional: pure-Python zstd (otherwise uses the zstd or dpkg-deb binary)
```

Requires Python 3.10+. Gap analysis needs the target runtime installed
(`flatpak install flathub org.freedesktop.Platform//25.08`) or a saved index file.

## debpak: .deb to Flatpak

```sh
# What would conversion involve? (no runtime needed for a basic report)
debpak inspect vendor-app_1.0_amd64.deb
debpak inspect vendor-app_1.0_amd64.deb --runtime org.freedesktop.Platform//25.08

# Convert, filling library gaps from a Debian mirror...
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mirror https://deb.debian.org/debian --suite stable -o out/

# ...or from .debs you downloaded yourself (e.g. with `apt download`)
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App --deps-dir ./debs -o out/

# Don't redistribute the vendor's binaries: download the .deb at install time
debpak convert vendor-app_1.0_amd64.deb --app-id com.vendor.App \
    --mode extra-data --url https://vendor.example/app_1.0_amd64.deb -o out/

# Build and install
flatpak-builder --user --install --force-clean --install-deps-from=flathub out/build-dir out/com.vendor.App.json
```

`convert` exits with status 2 and writes nothing if it finds blockers or
unresolvable required libraries. Use `--force` to write a manifest anyway.

### Output

```
out/
  com.vendor.App.json   flatpak-builder manifest (x-debpak block records reasons & provenance)
  app/                  staged /app tree (dir source of the manifest)
  report.txt            human-readable analysis
  report.json           machine-readable analysis
```

### How debpak works

1. **Extract**: pure-Python `ar` parsing; gz/xz/bz2/zstd data members.
2. **Analyze**: a built-in, dependency-free ELF reader collects `DT_NEEDED`,
   sonames, RPATH/RUNPATH, symbol-version requirements and imported symbols
   from every ELF in the package. Executables are dependency roots.
   Libraries needed only by plugins are tracked separately as optional.
3. **Classify**: Electron, Qt5/Qt6, GTK3/GTK4, Java or plain ELF. This drives the
   runtime suggestion and special handling (Electron → `zypak` + Electron BaseApp).
4. **Runtime index**: scans the installed runtime's `files/` tree on the host
   and caches the library names and symbol versions it provides in
   `~/.cache/debpak`. GL/Vulkan/driver libraries count as provided by the GL extension.
5. **Gap fill**: missing sonames are looked up in local `.deb`s or a mirror's
   `Contents-<arch>` index. Only the matching library files are copied into
   `/app/lib/debpak`, and their own dependencies are resolved iteratively.
   Core glibc libraries are never bundled.
6. **Version check**: every required symbol version (for example `GLIBC_2.38` or
   `GLIBCXX_3.4.32`) is checked against what the runtime or bundle defines. A
   glibc mismatch is a blocker, and the fix is a newer runtime branch.
7. **Host integration**: maintainer scripts and payload paths are classified.
   Cache refreshes are ignored, setuid sandboxes are handled, and systemd units,
   kernel modules, PAM, and udev are flagged as blockers or warnings.
8. **Paths**: the payload maps to `/app` (`usr/*` → `/app/*`, `opt/*` → `/app/opt/*`).
   Hardcoded `/opt/...` paths in shell scripts are rewritten, and paths hardcoded
   in binaries are reported.
9. **Desktop integration**: the `.desktop` file is renamed to the app ID and its
   `Exec=` points to a generated wrapper. `env VAR=...` prefixes move into the
   wrapper. Icons are exported under the app ID and an AppStream metainfo file
   is generated.
10. **Permissions**: inferred from linked libraries and imported symbols. Each
    permission's reason is recorded in the manifest and report. debpak never
    grants `--filesystem=home` unless you pass `--permissive`.


## winegap: Windows apps on Wine/Proton

```sh
# index a Wine or Proton-wine source tree (its .spec files mark stubs)
git clone --depth 1 https://gitlab.winehq.org/wine/wine.git
winegap index --wine-source wine --arch x86_64
winegap index --wine-source wine --arch i386

# scan an installed app (e.g. inside a prefix's drive_c)
winegap scan ~/.wine/drive_c/Program\ Files/Vendor/App --index ~/.cache/debpak/wine/11.8_x86_64.json \
    --index ~/.cache/debpak/wine/11.8_i386.json -o app.gap.json

# or index on the fly, and write loader-satisfying stub DLLs for DLLs Wine lacks
winegap scan ./App --wine-source wine --stubs ./stubs
```

The scanner models Wine's loader behavior:
- A statically imported DLL that exists neither in Wine nor next to the app
  prevents startup.
- A function that is stubbed or missing in an existing DLL gets an
  "unimplemented function" thunk that aborts only when called.
- Delay-loaded DLLs fail on first use.
- DLLs shipped in the app directory take precedence over builtins.

Forwarders (such as kernel32 to kernelbase) are followed, and imports by
ordinal are resolved. Each module is checked against the index for its own
architecture, so 32-bit helpers are handled.

**Stub DLLs.** The `--stubs` option writes a minimal PE DLL for each missing DLL,
exporting exactly the names and ordinals the app imports. This automates the
manual fix from the widely shared Lightroom-on-Linux recipe. Stubs return 0,
or trap with `--stub-mode trap`. 32-bit x86 stubs always trap, because a
stdcall stub can't know how many argument bytes to pop. Stub DLLs only get
the app past the loader; features that call them won't work.

**Runtime lookups (guesses).** `scan` also reads the text inside each binary:
a DLL name next to a function name (`LoadLibrary("dwmapi.dll")` +
`GetProcAddress(h, "DwmFlush")`) is a function looked up at runtime. Only those
Wine has as stubs are reported (they abort if called), tagged `[guess]` at the
`optional` tier so they never change the verdict. `--no-guess` turns this off.

### winegap trace: what actually failed

Import analysis can't see what an app does while it runs: functions looked up
with `GetProcAddress`, DLLs loaded on demand, COM objects, and Wine functions
that exist but are only partly implemented. Wine reports most of these itself
when they happen, if its debug logging is on. `winegap trace` runs the app that
way and turns the log into the same gap report:

```sh
# run it (in its prefix) for up to 5 minutes; use the features you care about meanwhile
winegap trace --prefix ~/.wine-app --timeout 300 \
    ~/.wine-app/drive_c/Program\ Files/Vendor/App.exe -- --some-arg

# add the static scan of the app's folder and merge the two (needs an index)
winegap trace --prefix ~/.wine-app --index ~/.cache/debpak/wine/11.8_x86_64.json App.exe -o app.gap.json

# or read a log you already have: Proton's steam-<appid>.log, a launcher's log, or
# WINEDEBUG=err+all,fixme+all,warn+module,+loaddll wine App.exe 2> app.log
winegap trace --log app.log --name "Vendor App" --index ...
```

| Seen in the log | Gap |
|---|---|
| `Call from ... to unimplemented function X.dll.Func, aborting` | **crash**, X.dll!Func |
| `err:module:import_dll Library X.dll (which is needed by ...) not found` | **fatal** if the .exe needs it, else **degraded** |
| `warn:module:load_dll Failed to load module "X.dll"` (LoadLibrary) | **degraded** |
| `fixme:<channel>:Func ... stub` | **degraded**; the Wine index names the DLL |
| `no instance created ... of class {CLSID}` / `class {CLSID} not registered` | **degraded**, com!{CLSID} |
| `wine: Unhandled page fault ...` + backtrace | **crash** in the module of frame 0 |
| other `fixme` lines | counted and listed in the notes (usually harmless) |

With an index, gaps the static scan predicted and the trace confirmed are marked
`both`; the rest are `runtime` only. Run counts show as `[seen running x3]`.
After the timeout the app is stopped, and with `--prefix` that prefix's
`wineserver` is shut down too. Launch scripts and Proton pass `WINEDEBUG`
through, so you can also trace through them and read their output with `--log`.

**Limitations.** A trace covers only what that run did, so open the documents
and use the features you need while it runs. Bugs Wine doesn't notice, such as a
function quietly returning a different result than Windows would, don't appear
in any log. Finding those means comparing the same task on Windows. .NET
assemblies are flagged, but their managed P/Invoke calls are not analyzed.
Kernel drivers (anti-cheat, DRM, hardware) are flagged. Installers must be
installed or extracted first.

## machgap: macOS apps on Darling

```sh
machgap index --darling-root /usr/local/libexec/darling --arch x86_64
machgap scan Some.app --index ~/.cache/debpak/darling/installed_x86_64.json -o some.gap.json
machgap scan Some.zip --index ...         # a .zip containing an .app works too
```

The scanner handles universal (fat) binaries, `@rpath`, `@loader_path` and
`@executable_path` resolution inside the bundle, re-exported libraries
(libSystem), weak linking, flat-namespace lookups, and platform checks. It
rejects iOS or Catalyst binaries, and apps without a slice for the index's
architecture.

**Stub detection.** Darling stubs are detected heuristically from
generated log strings of the form `STUB: <name> called`. Pass
`--stub-pattern REGEX` if a Darling version logs stubs differently.

**Limitations.** Objective-C methods are dispatched by selector at runtime,
so a class that exists can still lack methods the app calls. The report says
so whenever an app references ObjC classes. `.dmg` files must be extracted
first (for example with `7z x`).

## gaprank: what to fix first

```sh
gaprank reports/          # any mix of winegap / machgap / debpak report JSONs
```

`gaprank` ranks gaps by how many apps they affect. The **sole** column
counts apps for which a gap is the *only* fatal one, meaning fixing it alone
makes those apps start. The **seen** column counts apps where it happened in a
traced run (`winegap trace`, `debpak smoke`) rather than only being predicted;
within a tier those rank first. Run it across a corpus of popular apps to get a
prioritized to-do list for Wine or Darling developers.

## debpak limitations

- Static analysis can't see `dlopen()`. Smoke-test the result with
  `debpak smoke` (below).
- Paths hardcoded inside binaries can't be rewritten.
- Packages that need host integration (drivers, VPNs that manage interfaces,
  system daemons) can't be Flatpaks. debpak says so instead of guessing.
- The generated metainfo uses `LicenseRef-proprietary`; fix it before publishing.
- Default runtime branches in `analyze.py` need occasional bumping.

## debpak smoke: libraries loaded at runtime

Plugins, codecs and GPU libraries are loaded with `dlopen()` while the app runs,
so the import scan can't see them. `debpak smoke` runs the converted app with
the loader's own logging on (`LD_DEBUG=libs,files`) and reports every library it
asked for and didn't get:

```sh
debpak smoke com.vendor.App                  # the installed Flatpak, for 20 s (--timeout 0: until you close it)
debpak smoke com.vendor.App -- --open f.txt  # with arguments
debpak smoke --exec "out/app/bin/vendor-app" # an unpacked app, without Flatpak
debpak smoke --log ld-debug.log              # an existing LD_DEBUG=libs,files log
```

A library needed at startup that's missing is **fatal**. One the app loaded on
demand and didn't find is **degraded** (that feature won't work), except common
GPU and desktop probes (`libcuda`, `libnvidia-*`, `libappindicator`, ...) that
apps run fine without, which are **optional**. `undefined symbol` errors are
**crash** (a library is too old). Only what that run loaded is covered.

## Roadmap

- Build a corpus runner that scans many apps and publishes `gaprank` tables for Wine and Darling.
- Runtime confirmation for Darling (`DYLD_PRINT_*` logs), like `winegap trace` and `debpak smoke`.
- Name COM classes in traces (a CLSID table, or the prefix's registry).
- Drive apps through scripted UI actions while tracing, for better coverage.
- Emit `x-checker-data` for extra-data sources (flatpak-external-data-checker).
- Pick the runtime automatically by comparing gap sizes across installed runtimes.
- Translate more maintainer-script patterns; add GSettings schema compilation.
- AppImage input.

## Development

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

The Wine, Darling, ranking and trace tests need nothing extra (traces use
recorded Wine log lines and a stand-in `wine`). The `debpak smoke` tests compile
small C programs with `gcc` and check real glibc loader output. They generate PE and
Mach-O files with the built-in writers, and PE output is cross-checked with
`objdump` when it's available. The debpak integration tests need `gcc` and `dpkg-deb` on x86_64. They compile
small C programs and libraries, package them as real `.deb`s (xz and zstd), and
check the whole pipeline. The tests include running the converted binary
against the bundled libraries.

## License

MIT
