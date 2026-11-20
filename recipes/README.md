# Recipes

Each folder here is a conversion someone already did and checked, so other
people can install the app with `debpak install NAME` instead of converting it
themselves. There aren't any yet.

A recipe never contains the vendor's files. Its manifest is in extra-data
mode, so Flatpak downloads the app from the vendor's own URL at install time
and checks it against the SHA-256 in the recipe. What's in the folder is
debpak's part: the manifest, launchers, the desktop file, the icon, AppStream
metadata, and for Windows and Mac apps the plan for unpacking the download.

## Adding one

Convert the app in extra-data mode, using the vendor's permanent download URL
for that exact version:

```sh
debpak convert vendor-app_2.3.1_amd64.deb --app-id com.vendor.App \
    --mode extra-data --url https://vendor.example/app_2.3.1_amd64.deb -o out/
```

Install it, use it for a while, and check the permissions the report gives.
Then turn it into a recipe:

```sh
debpak recipe make out/ --to recipes/ --note "Tested on Fedora 43: login, sync, notifications"
```

That refuses conversions that would carry the vendor's files or other binaries
(libraries debpak had to bundle, for example), and it writes recipes/index.json
again. Open a pull request with the new folder and the index. Say what you
tested in the description. The pull request's checks build and install the
recipe, which also downloads the vendor's file and unpacks it.

Give the recipe a check block with `--check`, so new versions are found
without you. There are four kinds:

```json
{"type": "redirect", "url": "https://vendor.example/latest.deb", "version": "app_([0-9.]+)_amd64"}
{"type": "html", "url": "https://vendor.example/download", "pattern": "href=\"(?P<url>[^\"]*app_(?P<version>[0-9.]+)_amd64\\.deb)\""}
{"type": "json", "url": "https://vendor.example/api/latest", "url-key": "linux.url", "version-key": "linux.version"}
{"type": "github", "repo": "owner/name", "asset": "linux-x64\\.zip$"}
```

A redirect check follows the link and reads the version from where it ends
up. An html check takes the highest version among the pattern's matches. A
json check reads two dotted paths. A github check uses the newest release
that isn't a pre-release. Run `debpak recipe check recipes/ ID` to try one.

Once a week, a workflow in this repository runs
`debpak recipe check recipes --apply`. For each recipe with a new vendor
version, it converts that version with the recipe's own options and opens a
pull request. Updated recipes say they haven't been tested by hand. A recipe
converted with local files (`--native-dir`, `--deps-dir`) can't be updated
this way, and the pull request says so. People who installed a recipe get the
new version from `debpak update`.

## Reviewing one

Read the manifest's finish-args and the reasons in recipe.json, check that the
URL is the vendor's own, and read anything in app/bin, which runs on the
user's machine. The one exception is app/bin/debpak-unpack, a copy of
src/debpak/unpack.py: `debpak install` replaces it with its own copy, so only
the plan it reads (app/share/debpak/unpack.json) needs checking.
