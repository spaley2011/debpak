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
tested in the description.

When the vendor releases a new version, convert it the same way and run
`recipe make` again; the folder is replaced. People who installed the recipe
get the new version from `debpak update`.

## Reviewing one

Read the manifest's finish-args and the reasons in recipe.json, check that the
URL is the vendor's own, and read anything in app/bin, which runs on the
user's machine. The one exception is app/bin/debpak-unpack, a copy of
src/debpak/unpack.py: `debpak install` replaces it with its own copy, so only
the plan it reads (app/share/debpak/unpack.json) needs checking.
