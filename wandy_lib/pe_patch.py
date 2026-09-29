"""Static Electron fuse and managed auxiliary trust-check edits."""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from .js import PatchError


logger = logging.getLogger("wandy")


SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
STATE_FROM_SENTINEL = len(SENTINEL) + 2 + 4
MATCH_LENGTH = STATE_FROM_SENTINEL + 1
REMOVED = ord("r")


def find_fuse_offset(path: Path) -> int:
    """Find the validated ASAR-integrity state byte without loading the whole PE."""
    chunk_size = 1024 * 1024
    carry = b""
    start = 0
    with path.open("rb") as stream:
        while block := stream.read(chunk_size):
            data = carry + block
            pos = 0
            while (found := data.find(SENTINEL, pos)) >= 0:
                if found + MATCH_LENGTH <= len(data):
                    if data[found + len(SENTINEL)] == 1 and data[found + len(SENTINEL) + 1] >= 5:
                        return start + found + STATE_FROM_SENTINEL
                pos = found + 1
            keep = min(len(data), MATCH_LENGTH - 1)
            carry = data[-keep:]
            start += len(data) - keep
    return -1


def apply_fuse(executable: Path) -> None:
    offset = find_fuse_offset(executable)
    if offset < 0:
        raise PatchError(f"No supported Electron fuse block in {executable.name}")
    backup = Path(str(executable) + ".fusebak")
    with executable.open("r+b") as stream:
        stream.seek(offset)
        original = stream.read(1)
        if len(original) != 1:
            raise PatchError("Electron fuse byte is unreadable")
        if original[0] == REMOVED:
            if not backup.is_file():
                raise PatchError("Electron fuse is already cleared without an original-byte backup")
            return
        if backup.exists():
            raise PatchError(f"Unrecognized fuse backup already exists: {backup}")
        staging = Path(str(backup) + ".building")
        with staging.open("wb") as target:
            target.write(original)
            target.flush()
            os.fsync(target.fileno())
        os.replace(staging, backup)
        stream.seek(offset)
        stream.write(bytes((REMOVED,)))
        stream.flush()
        os.fsync(stream.fileno())


def restore_fuse(executable: Path) -> None:
    backup = Path(str(executable) + ".fusebak")
    if not backup.exists():
        return
    original = backup.read_bytes()
    if len(original) != 1:
        raise PatchError(f"Fuse backup is invalid: {backup}")
    offset = find_fuse_offset(executable)
    if offset < 0:
        raise PatchError("Cannot locate Electron fuse for restoration; preserving its backup")
    with executable.open("r+b") as stream:
        stream.seek(offset)
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    backup.unlink()


def matches_original_executable(executable: Path, expected_hash: str) -> bool:
    """Check the PE against its original hash, virtually undoing our one-byte fuse edit."""
    backup = Path(str(executable) + ".fusebak")
    replacement = backup.read_bytes() if backup.exists() else None
    if replacement is not None and len(replacement) != 1:
        raise PatchError(f"Fuse backup is invalid: {backup}")
    offset = find_fuse_offset(executable) if replacement is not None else -1
    if replacement is not None and offset < 0:
        raise PatchError("Cannot locate Electron fuse to verify the executable")
    digest = hashlib.sha256()
    position = 0
    with executable.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            if replacement is not None and position <= offset < position + len(block):
                index = offset - position
                block = block[:index] + replacement + block[index + 1:]
            digest.update(block)
            position += len(block)
    return digest.hexdigest() == expected_hash


def neutralize_auxiliary(unpacked_root: Path) -> int:
    auxiliary = unpacked_root / "static" / "unpacked" / "auxiliary"
    if not auxiliary.is_dir():
        logger.info("Auxiliary trust patch: no auxiliary service directory; skipped")
        return 0
    candidates = sorted(auxiliary.glob("*AuxiliaryService.exe"))
    if not candidates:
        logger.info("Auxiliary trust patch: no auxiliary service executable; skipped")
        return 0
    target = candidates[0]
    logger.info("Inspecting auxiliary trust checks in %s", target.name)

    # Imports stay here so status/restore can report problems without requiring PE packages.
    try:
        import dnfile
        from dncil.cil.body import CilMethodBody
        from dncil.cil.body.reader import CilMethodBodyReaderBase
        from dncil.cil.error import MethodBodyFormatError
        from dncil.clr.token import Token
    except ImportError as error:
        raise PatchError("PE packages are missing; install python/requirements.txt") from error

    class MethodReader(CilMethodBodyReaderBase):
        def __init__(self, pe, row):
            self.pe = pe
            self.offset = pe.get_offset_from_rva(row.Rva)

        def read(self, count: int) -> bytes:
            data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), count)
            self.offset += count
            return data

        def tell(self) -> int:
            return self.offset

        def seek(self, offset: int) -> int:
            self.offset = offset
            return self.offset

    pe = dnfile.dnPE(str(target))
    try:
        if not pe.net or not pe.net.mdtables or not pe.net.mdtables.MethodDef:
            raise PatchError(f"{target.name} is not a readable managed image")
        rows = list(pe.net.mdtables.MethodDef)
        tokens = {0x06000000 | index for index, row in enumerate(rows, 1)
                  if str(row.Name) == "WinVerifyTrust"}
        if not tokens:
            raise PatchError(f"No WinVerifyTrust import found in {target.name}")
        offsets: list[int] = []
        for row in rows:
            if not row.Rva or not row.ImplFlags.miIL or row.Flags.mdAbstract or row.Flags.mdPinvokeImpl:
                continue
            try:
                body = CilMethodBody(MethodReader(pe, row))
            except (MethodBodyFormatError, ValueError):
                continue
            if any(instruction.mnemonic in ("call", "callvirt")
                   and isinstance(instruction.operand, Token)
                   and instruction.operand.value in tokens
                   for instruction in body.instructions):
                code = pe.get_offset_from_rva(row.Rva) + len(body.get_header_bytes())
                if len(body.get_instruction_bytes()) < 2:
                    raise PatchError(f"WinVerifyTrust caller has too little IL in {target.name}")
                offsets.append(code)
    finally:
        pe.close()

    if not offsets:
        raise PatchError(f"No WinVerifyTrust caller found in {target.name}; auxiliary layout may have changed")
    stubbed = 0
    with target.open("r+b") as stream:
        for offset in offsets:
            stream.seek(offset)
            if stream.read(2) == b"\x16\x2a":
                continue
            stream.seek(offset)
            stream.write(b"\x16\x2a")  # ldc.i4.0; ret
            stubbed += 1
        stream.flush()
        os.fsync(stream.fileno())
    logger.info("Auxiliary trust patch: updated %d WinVerifyTrust caller(s)", stubbed)
    return stubbed
