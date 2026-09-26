# debpak

Convert binary `.deb` packages into Flatpaks, with **runtime-aware dependency resolution**.

Many vendors ship Linux software only as a `.deb`. Converting one by hand means
unpacking it, working out which libraries the Flatpak runtime is missing,
fixing hardcoded `/opt` paths, renaming desktop files and icons, guessing
sandbox permissions, and writing a `flatpak-builder` manifest. debpak automates
that pipeline and tells you when a package *can't* work as a Flatpak (kernel
modules, system services, and similar).

The key idea is that debpak resolves dependencies by **shared-library soname**, not by
Debian package name. It computes exactly which `.so` files the app's ELF
binaries need that the chosen runtime doesn't provide, and bundles only those.
It does not pull in the full apt dependency closure.

## Status

Early MVP (0.1). The analysis, gap resolution and manifest generation are
covered by an end-to-end test suite that builds real `.deb` fixtures. Real-world
builds with `flatpak-builder` have **not** been validated broadly yet, so treat
generated manifests as a strong first draft and review them.

## Install

```sh
pip install .            # no runtime dependencies
pip install '.[zstd]'    # optional: pure-Python zstd (otherwise uses the zstd or dpkg-deb binary)
```

Requires Python 3.10+. Gap analysis needs the target runtime installed
(`flatpak install flathub org.freedesktop.Platform//25.08`) or a saved index file.

## Usage

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

## How it works

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

## Limitations

- Static analysis can't see `dlopen()`. Smoke-test the result
  (`flatpak run --env=LD_DEBUG=libs <app-id>` shows failed loads).
- Paths hardcoded inside binaries can't be rewritten.
- Packages that need host integration (drivers, VPNs that manage interfaces,
  system daemons) can't be Flatpaks. debpak says so instead of guessing.
- The generated metainfo uses `LicenseRef-proprietary`; fix it before publishing.
- Default runtime branches in `analyze.py` need occasional bumping.

## Roadmap

- `debpak smoke` command: run the built app under `LD_DEBUG` and report
  `dlopen` failures.
- Emit `x-checker-data` for extra-data sources (flatpak-external-data-checker).
- Pick the runtime automatically by comparing gap sizes across installed runtimes.
- Translate more maintainer-script patterns; add GSettings schema compilation.
- AppImage input.

## Development

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

The integration tests need `gcc` and `dpkg-deb` on x86_64. They compile
small C programs and libraries, package them as real `.deb`s (xz and zstd), and
check the whole pipeline. The tests include running the converted binary
against the bundled libraries.

## License

MIT
