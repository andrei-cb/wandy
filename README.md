# Python Wand patcher

This patches alocal Wand/WeMod installation on Windows with Python 3.11 or newer. 
It provides Pro activation, update-check suppression, and F12 DevTools. 
It uses the static strategy; it does not replace Wand's launcher, 
inject the remote panel, or automatically reapply patches after an update.
The included `LICENSE.md` covers this standalone copy.

## Setup

From a Windows terminal in this folder:

```powershell
python -m pip install -r requirements.txt
```

Close Wand completely before patching or restoring. The CLI checks for running
`Wand.exe` and `WeMod.exe` processes and stops if it finds either one. By default
it chooses the newest valid `app-*` folder under `%LOCALAPPDATA%\Wand` or
`%LOCALAPPDATA%\WeMod`. Pass `--install` with the versioned folder to choose a
different installation.

## Commands

```powershell
python wandy.py status
python wandy.py patch
python wandy.py patch --patch pro --patch disable-updates --patch devtools
python wandy.py restore --install "C:\Users\you\AppData\Local\Wand\app-1.2.3"
```

`patch` selects Pro by default. When `--patch` is present, only the listed
options are selected. Run `patch` again to change the selection; it rebuilds
from the pristine backups. `restore` restores both `resources/app.asar` and
`resources/app.asar.unpacked`, resets the Electron fuse, and removes the Python
backup and manifest. The Pro option includes the C# patcher's native mobile
pairing safeguard, which disables Wand's native pairing request.
Patch and restore commands print timestamped progress in the terminal, including
backups, individual JavaScript edits, archive writing, the auxiliary trust edit,
the fuse change, and rollback if an operation fails.

The Python tool requires an unmodified installation for its first patch. If
the C# patcher was used, restore with that tool first. An incomplete Python
patch leaves its backups and `.incomplete-patch` marker so `restore` can recover
the installation. If the Wand executable changed after patching, restore may
reject its fuse backup; restore the matching executable or reinstall Wand.
