# Python Wand patcher

Patch Wand/WeMod on Windows with Python 3.11+: Pro activation, disabled update
checks, and F12 DevTools.

## Setup

```powershell
python -m pip install -r requirements.txt
```

Close Wand before patching or restoring. Start with an unmodified installation;
if you used the C# patcher, restore with that tool first.

## Commands

```powershell
python wandy.py status
python wandy.py patch
python wandy.py patch --patch pro --patch disable-updates --patch devtools
python wandy.py restore
```

`patch` defaults to Pro; repeat `--patch` to select exactly the options you want.
Run it again to change your selection. Reapply patches after Wand updates.

The newest local installation is detected automatically. To choose another,
add `--install "C:\Users\you\AppData\Local\Wand\app-1.2.3"` to any command.

If a patch fails, run `restore`. If restoration rejects a changed executable,
restore the matching executable or reinstall Wand.

Based on https://github.com/k1tbyte/Wand-Enhancer
