# Submitting debpak to Flathub

This folder holds what goes into the Flathub pull request:
io.github.spaley2011.debpak.yml, the manifest. Its only difference from
packaging/io.github.spaley2011.debpak.yml is that debpak's own source is the
v0.1.0 tag on GitHub instead of the local checkout. No flathub.json is needed:
every module builds on both x86_64 and aarch64, and Flathub builds both by
default. If one of them fails, add a flathub.json beside the manifest with
`{"only-arches": ["x86_64"]}`.

The metainfo file and the license aren't part of the pull request. The
manifest installs them from debpak's source, packaging/ and LICENSE.

## Before you open the pull request

1. Push this work to https://github.com/spaley2011/debpak, tag it and push the
   tag:

   ```sh
   git tag v0.1.0
   git push origin main v0.1.0
   ```

2. Put the tag's commit in the manifest, in place of
   REPLACE_WITH_THE_COMMIT_OF_v0.1.0:

   ```sh
   sed -i "s/REPLACE_WITH_THE_COMMIT_OF_v0.1.0/$(git rev-parse 'v0.1.0^{commit}')/" \
       packaging/flathub/io.github.spaley2011.debpak.yml
   ```

3. Check that the release date in packaging/io.github.spaley2011.debpak.metainfo.xml
   isn't after the tag's date (Flathub refuses release dates in the future),
   and that the version there matches the tag. If you change it, move the tag
   and do step 2 again.

4. Build it the way Flathub will, with Flathub's own builder, and run the
   linter on the manifest and the build:

   ```sh
   flatpak install -y flathub org.flatpak.Builder
   cd packaging/flathub
   flatpak run org.flatpak.Builder --force-clean --sandbox --user --install \
       --install-deps-from=flathub --ccache --mirror-screenshots-url=https://dl.flathub.org/media/ \
       --repo=repo builddir io.github.spaley2011.debpak.yml
   flatpak run --command=flatpak-builder-lint org.flatpak.Builder manifest io.github.spaley2011.debpak.yml
   flatpak run --command=flatpak-builder-lint org.flatpak.Builder repo repo
   ```

   The manifest linter gives no errors and two warnings:
   finish-args-flatpak-spawn-access (the org.freedesktop.Flatpak talk-name,
   explained below) and runtime-update-available-to-org.freedesktop.Platform-26.08.
   The manifest is on 25.08 because that's debpak's default runtime and the one
   it was tested on; reviewers may ask for 26.08, which means changing
   runtime-version and checking that 7-Zip still builds (debpak's Electron
   manifests drop 7-Zip's -Werror on 26.08, see electron.seven_zip_module).
   The metainfo passes flatpak-builder-lint appstream.

5. Try the installed app: `flatpak run io.github.spaley2011.debpak --help`, and
   convert a small package from a folder in your home folder.

## Opening the pull request

1. Fork https://github.com/flathub/flathub on GitHub. Leave "Copy the master
   branch only" unticked, since the pull request goes against the new-pr
   branch.

2. Clone your fork's new-pr branch and make a branch for the submission:

   ```sh
   git clone --branch=new-pr git@github.com:YOUR_GITHUB_USER/flathub.git
   cd flathub
   git checkout -b io.github.spaley2011.debpak
   ```

3. Copy in the manifest (with the commit filled in), commit and push:

   ```sh
   cp ~/debpak/packaging/flathub/io.github.spaley2011.debpak.yml .
   git add io.github.spaley2011.debpak.yml
   git commit -m "Add io.github.spaley2011.debpak"
   git push origin io.github.spaley2011.debpak
   ```

4. Open a pull request from that branch against flathub/flathub's new-pr
   branch (not master), titled "Add io.github.spaley2011.debpak". Fill in the
   checklist in the template. In the description, explain the permissions as
   below, so reviewers don't have to ask.

5. A reviewer can start a test build by commenting "bot, build". When the pull
   request is merged, Flathub creates the repository
   flathub/io.github.spaley2011.debpak and invites you to it; later releases
   are pull requests there that update the tag and commit.

The app ID starts with io.github.spaley2011, so Flathub verifies it against the
GitHub account spaley2011 when you log in to flathub.org with that account. The
repository must stay public at https://github.com/spaley2011/debpak.

## What reviewers are likely to question

Flathub's requirements say console software isn't accepted, with exceptions
for Flatpak and Flathub related tooling. debpak is Flatpak tooling (it makes
Flatpak manifests and builds them with flatpak-builder), so ask for that
exception in the description, and expect the reviewers to decide it. The
metainfo already uses type="console-application" with
`<provides><binary>debpak</binary></provides>`, which is what Flathub wants
from a console app. Without an icon and screenshots it won't show up in
flathub.org's search; that's allowed for a console app, and nothing a
screenshot could show is worth adding.

Then the permissions, in the order reviewers usually raise them.

--talk-name=org.freedesktop.Flatpak lets the app run any command on the host,
through flatpak-spawn --host, so the sandbox no longer contains it. Reviewers
treat this as a full sandbox escape and ask why it's needed. The answer:
debpak's job is to build Flatpaks with flatpak-builder and install them with
flatpak, and neither works inside a sandbox (flatpak-builder needs to create
its own sandboxes and write to the user's installation). debpak only runs
flatpak, flatpak-builder and gpg (for recipe signing) on the host. The code
that decides this is src/debpak/host.py, and the list is HOST_PROGRAMS there.
Every extraction tool it needs (unsquashfs, dwarfsextract, 7z, innoextract,
msiextract, bsdtar) is bundled and runs inside the sandbox, so the host needs
nothing beyond flatpak and flatpak-builder. There is precedent on Flathub:
org.flatpak.Builder asks for this name along with --filesystem=host and
--share=network, and Warehouse (io.github.flattool.Warehouse), which manages
installed Flatpaks, asks for it too.

--filesystem=home is broader than Flathub likes, and the usual answer is the
file chooser portal. That doesn't work here for two reasons. debpak is a
command-line tool given paths as arguments, and there is no portal for those.
And flatpak-builder runs on the host, where it has to find the output folder
and everything in it at the same path debpak wrote it to. A portal's
/run/user/.../doc path doesn't exist on the host. Point out that a
narrower --filesystem=xdg-download wouldn't let people convert into a
project folder, which is the documented use (`debpak convert PKG -o out/`).

--filesystem=xdg-data/flatpak:ro and --filesystem=/var/lib/flatpak:ro are
read-only. debpak reads the installed runtime's libraries to find which ones a
package needs that the runtime lacks (runtime.get_index), and Flathub's
AppStream catalogue to check whether Flathub already has the app before it
converts anything (manage.flathub_homepages). Flatpak hides
~/.local/share/flatpak from apps even with --filesystem=home, so it has to be
named. Warehouse asks for exactly these two folders read-only, and Flatseal
for the app folders inside them.

--share=network: missing libraries come from Debian, Ubuntu and RPM mirrors,
Electron apps get Electron's Linux build from GitHub, and recipes and --url
conversions download the vendor's file.

Other things a reviewer may bring up:

- innoextract is built from a git commit on master instead of the 1.9 release,
  because 1.9 (from 2020) can't read installers made with Inno Setup 6.3 or
  later, which most current ones are.
- msitools needs the Vala SDK extension (org.freedesktop.Sdk.Extension.vala)
  at build time only.
- `debpak desnap` refuses to run in the Flatpak (it changes the host's
  packages with sudo). That's deliberate and the README says so.
- The bundled Boost, libgsf and gcab are only there for innoextract, dwarfs
  and msitools; the runtime has none of them.
