# third_party

The projects that `appbridge` drives, kept as git submodules pinned to a
known-good commit. Nothing here is copied into debpak's own (MIT) code; each
project keeps its own license.

```sh
git submodule update --init --depth 1 third_party/office365_flake   # just the ones you need
git submodule update --init --depth 1                               # or all of them (wine-adobe-installers is a full Wine tree)
scripts/fork-upstreams.sh                                           # fork them all into your GitHub account and repoint
scripts/fork-upstreams.sh --sync                                    # later: pull upstream changes into your forks
```

| Submodule | Upstream | License | What appbridge uses it for |
|---|---|---|---|
| `office365_flake` | [Tombert/office365_flake](https://github.com/Tombert/office365_flake) | LGPL-2.1 | Microsoft 365 desktop apps (Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher) on GE-Proton through umu, no VM. Driven through its `ms365` command or `nix run`. |
| `umu-launcher` | [Open-Wine-Components/umu-launcher](https://github.com/Open-Wine-Components/umu-launcher) | GPL-3.0 | Proton runner for the Microsoft 365 flake, and the `umu` runner for custom apps. |
| `winapps` | [winapps-org/winapps](https://github.com/winapps-org/winapps) | mixed (see its COPYRIGHT.md) | Runs Windows apps from a Windows VM as seamless RemoteApp windows. Fallback for Office and Adobe, and the only route for Visio, Project, Power BI, SSMS and other apps Wine can't run. |
| `linoffice` | [eylenburg/linoffice](https://github.com/eylenburg/linoffice) | AGPL-3.0 | One-step WinApps setup aimed at Office (Word, Excel, PowerPoint, Outlook, OneNote). |
| `LinDobe` | [le-birnes/LinDobe](https://github.com/le-birnes/LinDobe) | LGPL-2.1 | Adobe Creative Cloud apps (Photoshop, Illustrator, Premiere Pro, After Effects, InDesign, Lightroom, Acrobat, ...) on a patched Wine. Driven through its `adobewine` command. |
| `wine-adobe-installers` | [PhialsBasement/wine-adobe-installers](https://github.com/PhialsBasement/wine-adobe-installers) | LGPL-2.1 | The Wine patch set that first made the Creative Cloud installer work. Reference and fallback runtime; LinDobe builds on it. |
| `teams-for-linux` | [IsmaelMartinez/teams-for-linux](https://github.com/IsmaelMartinez/teams-for-linux) | GPL-3.0 | Microsoft Teams (Microsoft dropped its Linux client). |
| `prospect-mail` | [julian-alarcon/prospect-mail](https://github.com/julian-alarcon/prospect-mail) | MIT | Outlook mail and calendar as a desktop app, for machines without the Wine/VM Outlook. |
| `onenote` | [patrikx3/onenote](https://github.com/patrikx3/onenote) | MIT | OneNote as a desktop app. |
| `onedrive` | [abraunegg/onedrive](https://github.com/abraunegg/onedrive) | GPL-3.0 | OneDrive and SharePoint file sync (Microsoft has no Linux client). Run as a user service. |

Considered and left out: Corbin Davenport's `creative-cloud-linux` (PlayOnLinux
script, last changed in 2020, superseded by the Wine patches above) and
`office365-pol` (its author says it no longer works with current Microsoft 365).
