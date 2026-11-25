# wandy

Standalone Windows CLI utility (Python 3.11+) for customizing local Wand
installations: removes client-side UI limitations, disables automatic update
checks, and enables F12 DevTools.

## Setup

```powershell
python -m pip install -r requirements.txt
```

Close the application completely before patching or restoring. Start from an
unmodified installation; if another patcher was used previously, restore with
that tool first.

## Commands

```powershell
python wandy.py status
python wandy.py patch
python wandy.py patch --patch pro --patch disable-updates --patch devtools
python wandy.py restore
```

`patch` defaults to removing client-side limitations (`pro`). Repeat `--patch`
to select the exact options you want, or run it again to change your selection.
Reapply patches after application updates.

The newest local installation is detected automatically. To target a specific
versioned folder, pass `--install "C:\Users\you\AppData\Local\Wand\app-1.2.3"`
to any command.

If a patch fails, run `restore`. If restoration rejects a modified executable,
restore the matching executable or reinstall the application.
