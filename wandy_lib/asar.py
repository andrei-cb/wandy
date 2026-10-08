"""Streaming ASAR reader/writer for the subset used by Wand's app archive."""

from __future__ import annotations

import hashlib
import json
import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from .js import PatchError, patch_bundles


logger = logging.getLogger("wandy")


BLOCK_SIZE = 4 * 1024 * 1024
COPY_SIZE = 1024 * 1024
MAX_HEADER_SIZE = 128 * 1024 * 1024


def header_hash(path: Path) -> str:
    """Hash the raw ASAR JSON header, excluding pickle fields, padding and file data."""
    with path.open("rb") as stream:
        prefix = stream.read(16)
        if len(prefix) != 16:
            raise PatchError("ASAR header is truncated")
        sentinel, pickle_size, payload_size, json_size = struct.unpack("<IIII", prefix)
        if (sentinel != 4 or not 8 <= pickle_size <= MAX_HEADER_SIZE
                or payload_size != pickle_size - 4 or json_size > pickle_size - 8
                or 8 + pickle_size > path.stat().st_size):
            raise PatchError("ASAR header is invalid")
        header = stream.read(json_size)
        if len(header) != json_size:
            raise PatchError("ASAR JSON header is truncated")
    return hashlib.sha256(header).hexdigest()


@dataclass
class Archive:
    path: Path
    header: dict
    data_offset: int

    @classmethod
    def read(cls, path: Path) -> Archive:
        with path.open("rb") as stream:
            size_pickle = stream.read(8)
            if len(size_pickle) != 8:
                raise PatchError("ASAR size header is truncated")
            payload_size, header_size = struct.unpack("<II", size_pickle)
            if payload_size != 4 or not 8 <= header_size <= MAX_HEADER_SIZE:
                raise PatchError("ASAR size header is invalid")
            pickle = stream.read(header_size)
            if len(pickle) != header_size or header_size < 8:
                raise PatchError("ASAR JSON header is truncated")
            actual_payload, json_size = struct.unpack_from("<II", pickle)
            if actual_payload != header_size - 4 or json_size > header_size - 8:
                raise PatchError("ASAR JSON pickle is invalid")
            try:
                header = json.loads(pickle[8:8 + json_size].decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise PatchError(f"ASAR JSON header is invalid: {error}") from error
        if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
            raise PatchError("ASAR root has no files")
        return cls(path, header, 8 + header_size)

    def entries(self) -> Iterator[tuple[str, dict]]:
        def walk(files: dict, prefix: str) -> Iterator[tuple[str, dict]]:
            for name, node in files.items():
                if not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\\" in name:
                    raise PatchError(f"Unsafe ASAR path component: {name!r}")
                if not isinstance(node, dict):
                    raise PatchError(f"Invalid ASAR node at {prefix}{name}")
                path = prefix + name
                yield path, node
                if "files" in node:
                    if not isinstance(node["files"], dict):
                        raise PatchError(f"Invalid ASAR directory: {path}")
                    yield from walk(node["files"], path + "/")

        yield from walk(self.header["files"], "")

    def packed_entries(self) -> list[tuple[str, dict, int, int]]:
        result = []
        archive_size = self.path.stat().st_size
        for name, node in self.entries():
            if "size" not in node or self._is_unpacked(name, node):
                continue
            try:
                size = int(node["size"])
                offset = int(node["offset"])
            except (KeyError, TypeError, ValueError) as error:
                raise PatchError(f"Invalid ASAR file offset or size: {name}") from error
            if size < 0 or offset < 0 or self.data_offset + offset + size > archive_size:
                raise PatchError(f"ASAR file lies outside archive: {name}")
            result.append((name, node, offset, size))
        result.sort(key=lambda row: row[2])
        for before, after in zip(result, result[1:]):
            if before[2] + before[3] > after[2]:
                raise PatchError(f"Overlapping ASAR file data: {before[0]} and {after[0]}")
        return result

    def _is_unpacked(self, name: str, node: dict) -> bool:
        if node.get("unpacked"):
            return True
        current = self.header
        for component in name.split("/")[:-1]:
            current = current["files"][component]
            if current.get("unpacked"):
                return True
        return False

    def read_file(self, name: str, node: dict, unpacked_root: Path) -> bytes:
        if self._is_unpacked(name, node):
            path = unpacked_root.joinpath(*name.split("/"))
            if not path.resolve().is_relative_to(unpacked_root.resolve()):
                raise PatchError(f"Unpacked ASAR path escapes its root: {name}")
            if not path.is_file():
                raise PatchError(f"Unpacked bundle is missing: {path}")
            return path.read_bytes()
        try:
            offset, size = int(node["offset"]), int(node["size"])
        except (KeyError, TypeError, ValueError) as error:
            raise PatchError(f"Invalid ASAR bundle metadata: {name}") from error
        with self.path.open("rb") as stream:
            stream.seek(self.data_offset + offset)
            data = stream.read(size)
        if len(data) != size:
            raise PatchError(f"ASAR bundle is truncated: {name}")
        return data


@dataclass(frozen=True)
class ArchiveSlice:
    source: Path
    offset: int
    size: int


def _integrity(data: bytes) -> dict:
    return {
        "algorithm": "SHA256",
        "hash": hashlib.sha256(data).hexdigest(),
        "blockSize": BLOCK_SIZE,
        "blocks": [hashlib.sha256(data[i:i + BLOCK_SIZE]).hexdigest()
                   for i in range(0, len(data), BLOCK_SIZE)],
    }


def _pickle_header(header: dict) -> bytes:
    source = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    padded = source + b"\0" * (-len(source) % 4)
    header_pickle = struct.pack("<II", 4 + len(padded), len(source)) + padded
    return struct.pack("<II", 4, len(header_pickle)) + header_pickle


def _copy_exact(source: BinaryIO, destination: BinaryIO, length: int) -> None:
    while length:
        block = source.read(min(length, COPY_SIZE))
        if not block:
            raise PatchError("ASAR data was truncated while copying")
        destination.write(block)
        length -= len(block)


def rewrite_archive(source: Path, destination: Path, unpacked_root: Path,
                    selected: set[str]) -> dict[str, bytes | ArchiveSlice]:
    """Write the patched archive and return files to place under app.asar.unpacked."""
    archive = Archive.read(source)
    packed = archive.packed_entries()
    root_bundles = {
        name: archive.read_file(name, node, unpacked_root)
        for name, node in archive.header["files"].items()
        if isinstance(node, dict) and "size" in node and
        (name.lower() == "index.js" or
         (name.lower().startswith("app-") and name.lower().endswith(".bundle.js")))
    }
    logger.info("Scanning %d JavaScript bundle(s) in app.asar", len(root_bundles))
    changed = patch_bundles(root_bundles, selected)
    external_changes: dict[str, bytes | ArchiveSlice] = {}
    for name, data in changed.items():
        node = archive.header["files"][name]
        node["size"] = len(data)
        node["integrity"] = _integrity(data)
        if archive._is_unpacked(name, node):
            external_changes[name] = data

    # The C# static strategy unpacks this tree before editing the managed
    # auxiliary service. Preserve that behavior even if the input ASAR packed it.
    promoted: set[str] = set()
    for name, node, old_offset, old_size in packed:
        if name.lower().startswith("static/unpacked/"):
            node["unpacked"] = True
            node.pop("offset", None)
            external_changes[name] = ArchiveSlice(source, archive.data_offset + old_offset, old_size)
            promoted.add(name)

    next_offset = 0
    for name, node, _, _ in packed:
        if name in promoted:
            continue
        node["offset"] = str(next_offset)
        next_offset += len(changed[name]) if name in changed else int(node["size"])

    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as original, destination.open("wb") as output:
        output.write(_pickle_header(archive.header))
        for name, _, old_offset, old_size in packed:
            if name in promoted:
                continue
            if name in changed:
                output.write(changed[name])
            else:
                original.seek(archive.data_offset + old_offset)
                _copy_exact(original, output, old_size)
    # Parse the staged file before it can replace the live archive.
    Archive.read(destination).packed_entries()
    logger.info("Staged app.asar: %d changed bundle(s), %d file(s) moved to app.asar.unpacked",
                len(changed), len(promoted))
    return external_changes
