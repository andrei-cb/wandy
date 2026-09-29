"""Installation discovery and transactional patch/restore orchestration."""

from __future__ import annotations

import csv
import ctypes
import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .asar import ArchiveSlice, rewrite_archive
from .js import PatchError
from .pe_patch import apply_fuse, matches_original_executable, neutralize_auxiliary, restore_fuse


OWNER = "wand-enhancer-python"
SCHEMA = 1
BRANDS = ("Wand", "WeMod")
logger = logging.getLogger("wandy")


@dataclass(frozen=True)
class Install:
    root: Path
    brand: str

    @property
    def executable(self) -> Path:
        return self.root / f"{self.brand}.exe"

    @property
    def resources(self) -> Path:
        return self.root / "resources"

    @property
    def asar(self) -> Path:
        return self.resources / "app.asar"

    @property
    def unpacked(self) -> Path:
        return self.resources / "app.asar.unpacked"

    @property
    def asar_backup(self) -> Path:
        return self.resources / "app.asar.backup"

    @property
    def unpacked_backup(self) -> Path:
        return self.resources / "app.asar.unpacked.backup"

    @property
    def manifest(self) -> Path:
        return self.resources / ".wand-enhancer-python.json"

    @property
    def marker(self) -> Path:
        return self.resources / ".incomplete-patch"

    @property
    def fuse_backup(self) -> Path:
        return Path(str(self.executable) + ".fusebak")

    @property
    def stub_backup(self) -> Path:
        return self.root.parent / f"{self.brand}.exe.stub"


def _check_install(folder: Path) -> Install | None:
    for brand in BRANDS:
        if (folder / f"{brand}.exe").is_file() and (folder / "resources" / "app.asar").is_file():
            return Install(folder.resolve(), brand)
    return None


def find_install(explicit: str | None) -> Install:
    if explicit:
        install = _check_install(Path(explicit).expanduser())
        if not install:
            raise PatchError("--install must name a versioned Wand/WeMod folder with its executable and resources/app.asar")
        return install
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise PatchError("LOCALAPPDATA is unset; pass --install with a versioned installation folder")
    candidates: list[Install] = []
    for brand in BRANDS:
        parent = Path(local) / brand
        if not parent.is_dir():
            continue
        for folder in parent.glob("app-*"):
            if folder.is_dir() and (install := _check_install(folder)):
                candidates.append(install)
    if not candidates:
        raise PatchError("No Wand/WeMod installation found; pass --install")
    return max(candidates, key=lambda item: (item.root.stat().st_mtime, str(item.root).lower()))


def _require_windows() -> None:
    if platform.system() != "Windows":
        raise PatchError("The static patcher requires Windows")


def _require_closed() -> None:
    completed = subprocess.run(
        ["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, errors="replace", check=False
    )
    if completed.returncode != 0:
        raise PatchError("Could not check running processes; close Wand and retry from a normal Windows shell")
    names = {row[0].lower() for row in csv.reader(completed.stdout.splitlines()) if row}
    if names.intersection({"wand.exe", "wemod.exe"}):
        raise PatchError("Wand/WeMod is running. Close it completely, then rerun the command")


def _foreign_footprints(install: Install) -> list[Path]:
    return [path for path in (
        install.asar_backup, install.unpacked_backup, install.marker,
        install.fuse_backup, install.stub_backup,
        install.root.parent / "enhancer.json", install.root / "version.dll",
        Path(str(install.asar) + ".building"),
        Path(str(install.asar_backup) + ".building"),
        Path(str(install.unpacked_backup) + ".building"),
        Path(str(install.manifest) + ".building"),
        Path(str(install.asar) + ".restoring"),
        Path(str(install.unpacked) + ".restoring"),
        Path(str(install.unpacked) + ".restore-old"),
    ) if path.exists()]


def _read_manifest(install: Install) -> dict | None:
    if not install.manifest.exists():
        return None
    try:
        data = json.loads(install.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PatchError(f"Python patch manifest is unreadable: {error}") from error
    if not isinstance(data, dict) or data.get("owner") != OWNER or data.get("schema") != SCHEMA:
        raise PatchError("Patch manifest has an unknown owner or version")
    if data.get("executable") != install.executable.name:
        raise PatchError("Patch manifest belongs to another installation")
    if data.get("state") not in ("preparing", "patched", "failed", "restoring", "restored"):
        raise PatchError("Patch manifest has an invalid state")
    for key in ("original_asar_sha256", "original_exe_sha256"):
        value = data.get(key)
        if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise PatchError(f"Patch manifest has an invalid {key}")
    if not isinstance(data.get("patches"), list):
        raise PatchError("Patch manifest has an invalid patch selection")
    if data["state"] == "patched" and any(not isinstance(data.get(key), str)
                                           for key in ("patched_asar_sha256", "patched_exe_sha256")):
        raise PatchError("Patch manifest is missing the patched-file hashes")
    return data


def _write_manifest(install: Install, data: dict) -> None:
    staging = Path(str(install.manifest) + ".building")
    with staging.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(staging, install.manifest)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _stage_copy(source: Path, destination: Path) -> None:
    staging = Path(str(destination) + ".building")
    if staging.exists():
        raise PatchError(f"Stale staging path exists: {staging}")
    if source.is_dir():
        shutil.copytree(source, staging)
    else:
        shutil.copy2(source, staging)
    os.replace(staging, destination)


def _replace_file_from_backup(backup: Path, destination: Path) -> None:
    staging = Path(str(destination) + ".restoring")
    if staging.exists():
        staging.unlink()
    shutil.copy2(backup, staging)
    _clear_attributes(destination)
    os.replace(staging, destination)


def _clear_attributes(path: Path) -> None:
    if os.name != "nt" or not path.exists():
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    kernel.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.SetFileAttributesW.restype = ctypes.c_int
    attributes = kernel.GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF:
        raise OSError(ctypes.get_last_error(), f"Cannot read file attributes: {path}")
    if attributes & 0x7 and not kernel.SetFileAttributesW(str(path), 0x80):
        raise OSError(ctypes.get_last_error(), f"Cannot clear file attributes: {path}")


def _replace_directory_from_backup(backup: Path, destination: Path) -> None:
    staging = Path(str(destination) + ".restoring")
    old = Path(str(destination) + ".restore-old")
    # A prior interrupted swap is recoverable because the immutable backup is intact.
    if old.exists() and not destination.exists():
        os.replace(old, destination)
    elif old.exists():
        shutil.rmtree(old)
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(backup, staging)
    if destination.exists():
        os.replace(destination, old)
    try:
        os.replace(staging, destination)
    except Exception:
        if old.exists() and not destination.exists():
            os.replace(old, destination)
        raise
    if old.exists():
        shutil.rmtree(old)


def _restore_originals(install: Install, manifest: dict) -> None:
    if not install.asar_backup.is_file() or not install.unpacked_backup.is_dir():
        raise PatchError("Python backup is incomplete; original files were not changed by this operation")
    if not matches_original_executable(install.executable, manifest["original_exe_sha256"]):
        raise PatchError("Wand executable changed since backup; refusing to restore its fuse byte")
    logger.info("Restoring Electron fuse byte, if changed")
    restore_fuse(install.executable)
    logger.info("Restoring %s", install.asar)
    _replace_file_from_backup(install.asar_backup, install.asar)
    logger.info("Restoring %s", install.unpacked)
    _replace_directory_from_backup(install.unpacked_backup, install.unpacked)


def _delete_state(install: Install) -> None:
    for path in (Path(str(install.asar_backup) + ".building"),
                 Path(str(install.unpacked_backup) + ".building"),
                 Path(str(install.manifest) + ".building"),
                 Path(str(install.asar) + ".building")):
        if path.is_file():
            path.unlink()
    if install.unpacked_backup.is_dir():
        shutil.rmtree(install.unpacked_backup)
    staging_dir = Path(str(install.unpacked_backup) + ".building")
    if staging_dir.is_dir():
        shutil.rmtree(staging_dir)
    install.asar_backup.unlink(missing_ok=True)
    install.marker.unlink(missing_ok=True)
    install.manifest.unlink(missing_ok=True)


def describe_status(install: Install) -> str:
    manifest = _read_manifest(install)
    if manifest:
        selection = ", ".join(manifest.get("patches", [])) or "none"
        marker = " (incomplete marker present)" if install.marker.exists() else ""
        return f"Python {manifest['state']}{marker}; patches: {selection}"
    foreign = _foreign_footprints(install)
    if foreign:
        return "Existing or incomplete non-Python patch state: " + ", ".join(path.name for path in foreign)
    return "Unmodified installation"


def patch(install: Install, selected: set[str]) -> None:
    _require_windows()
    logger.info("Patches selected: %s", ", ".join(sorted(selected)))
    logger.info("Checking for running Wand/WeMod processes")
    _require_closed()
    logger.info("Checking existing patch state")
    previous = _read_manifest(install)
    if previous is None:
        foreign = _foreign_footprints(install)
        if foreign:
            raise PatchError("Installation has existing patch state. Restore it with the C# tool first: "
                             + ", ".join(path.name for path in foreign))
        if not install.unpacked.is_dir():
            raise PatchError("app.asar.unpacked is missing; patch a complete installation")
        manifest = {"owner": OWNER, "schema": SCHEMA, "executable": install.executable.name,
                    "state": "preparing", "patches": [], "original_asar_sha256": _hash_file(install.asar),
                    "original_exe_sha256": _hash_file(install.executable)}
    else:
        if install.marker.exists() or previous["state"] != "patched":
            raise PatchError("Previous Python patch is incomplete; run restore before patching again")
        if not install.asar_backup.is_file() or not install.unpacked_backup.is_dir():
            raise PatchError("Python backup is incomplete; cannot re-patch safely")
        if _hash_file(install.executable) != previous.get("patched_exe_sha256"):
            raise PatchError("Wand executable changed since Python patched it; restore or reinstall before re-patching")
        if _hash_file(install.asar) != previous.get("patched_asar_sha256"):
            raise PatchError("Wand archive changed since Python patched it; restore before re-patching")
        manifest = previous.copy()
    live_changed = False
    first_patch = previous is None
    logger.info("%s", "Preparing a fresh installation" if first_patch else "Re-patching from Python backups")
    try:
        if first_patch:
            _write_manifest(install, manifest)
        install.marker.write_text("", encoding="utf-8")
        if first_patch:
            logger.info("Backing up %s", install.asar)
            _stage_copy(install.asar, install.asar_backup)
            logger.info("Backing up %s", install.unpacked)
            _stage_copy(install.unpacked, install.unpacked_backup)
        logger.info("Verifying pristine ASAR backup")
        if _hash_file(install.asar_backup) != manifest["original_asar_sha256"]:
            raise PatchError("Pristine ASAR backup hash does not match Python patch manifest")

        staged = Path(str(install.asar) + ".building")
        if staged.exists():
            raise PatchError(f"Stale archive staging file exists: {staged}")
        logger.info("Applying JavaScript patches and rebuilding app.asar")
        external = rewrite_archive(install.asar_backup, staged, install.unpacked_backup, selected)
        manifest["state"] = "failed"
        _write_manifest(install, manifest)
        live_changed = True
        if not first_patch:
            logger.info("Restoring original fuse byte before re-patching")
        restore_fuse(install.executable)
        logger.info("Preparing app.asar.unpacked from its pristine backup")
        _replace_directory_from_backup(install.unpacked_backup, install.unpacked)
        if external:
            logger.info("Writing %d unpacked archive file(s)", len(external))
        for name, content in external.items():
            destination = install.unpacked.joinpath(*name.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, ArchiveSlice):
                with content.source.open("rb") as source, destination.open("wb") as output:
                    source.seek(content.offset)
                    remaining = content.size
                    while remaining:
                        block = source.read(min(remaining, 1024 * 1024))
                        if not block:
                            raise PatchError(f"Packed file was truncated: {name}")
                        output.write(block)
                        remaining -= len(block)
            else:
                destination.write_bytes(content)
        neutralize_auxiliary(install.unpacked)
        logger.info("Installing patched app.asar")
        _clear_attributes(install.asar)
        os.replace(staged, install.asar)
        logger.info("Clearing Electron ASAR integrity fuse")
        apply_fuse(install.executable)
        manifest["state"] = "patched"
        manifest["patches"] = sorted(selected)
        manifest["patched_exe_sha256"] = _hash_file(install.executable)
        manifest["patched_asar_sha256"] = _hash_file(install.asar)
        _write_manifest(install, manifest)
        install.marker.unlink()
        logger.info("Patch complete; pristine backups are retained for re-patching or restore")
    except Exception as error:
        if live_changed:
            logger.warning("Patch failed; rolling back modified files")
            try:
                _restore_originals(install, manifest)
                manifest["state"] = "failed"
                _write_manifest(install, manifest)
            except Exception as rollback_error:
                logger.error("Rollback failed; backups and incomplete marker were retained")
                raise PatchError(f"Patch failed: {error}; rollback also failed: {rollback_error}. "
                                 "Backups and incomplete marker were preserved") from error
            logger.warning("Original files restored; run restore to clear the incomplete state")
            raise PatchError(f"Patch failed: {error}. Originals restored; run restore to clear patch state") from error
        if first_patch:
            logger.warning("Patch stopped before changing live files; removing staged backups")
            _delete_state(install)
        else:
            logger.warning("Patch stopped before changing live files; previous patch remains active")
            _write_manifest(install, previous)
            install.marker.unlink(missing_ok=True)
            staged = Path(str(install.asar) + ".building")
            staged.unlink(missing_ok=True)
        raise


def restore(install: Install) -> None:
    _require_windows()
    logger.info("Checking for running Wand/WeMod processes")
    _require_closed()
    logger.info("Checking Python backup and patch state")
    manifest = _read_manifest(install)
    if manifest is None:
        raise PatchError("This installation has no Python patch manifest; cannot restore foreign backups")
    logger.info("Python patch state: %s", manifest["state"])
    if manifest["state"] not in ("preparing", "restored") \
            and not matches_original_executable(install.executable, manifest["original_exe_sha256"]):
        raise PatchError("Wand executable changed since Python patched it; fuse backup cannot be applied safely")
    if manifest["state"] in ("patched", "failed"):
        manifest["state"] = "restoring"
        _write_manifest(install, manifest)
    if manifest["state"] == "restoring":
        _restore_originals(install, manifest)
    elif manifest["state"] == "preparing":
        logger.info("Patch stopped before changing live files; originals are already intact")
    manifest["state"] = "restored"
    _write_manifest(install, manifest)
    logger.info("Removing Python backups and patch metadata")
    _delete_state(install)
    logger.info("Restore complete")
