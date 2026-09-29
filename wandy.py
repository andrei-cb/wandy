"""Standalone Windows command-line patcher for local Wand installations."""

from __future__ import annotations

import argparse
import logging
import sys

from wandy_lib.core import describe_status, find_install, patch, restore
from wandy_lib.js import PatchError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("patch", "restore", "status"):
        command = commands.add_parser(name)
        command.add_argument("--install", metavar="APP_FOLDER",
                             help="versioned app-* folder; otherwise detect the newest local install")
        if name == "patch":
            command.add_argument("--patch", action="append", choices=("pro", "disable-updates", "devtools"),
                                 help="repeat to select patches; defaults to pro")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
    logger = logging.getLogger("wandy")
    try:
        install = find_install(args.install)
        logger.info("Install: %s", install.root)
        if args.command == "status":
            print(f"{install.root}: {describe_status(install)}")
        elif args.command == "patch":
            selected = set(args.patch or ["pro"])
            patch(install, selected)
            print(f"Patched {install.root} with {', '.join(sorted(selected))}")
        else:
            restore(install)
            print(f"Restored {install.root}")
    except (PatchError, OSError, UnicodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
