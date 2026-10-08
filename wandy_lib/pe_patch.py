"""Static Electron fuse, ASAR integrity resource and managed auxiliary edits."""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from .asar import header_hash
from .js import PatchError


logger = logging.getLogger("wandy")


SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
STATE_FROM_SENTINEL = len(SENTINEL) + 2 + 4
MATCH_LENGTH = STATE_FROM_SENTINEL + 1
REMOVED = ord("r")
ASAR_HASH_ANCHOR = b'"file":"resources\\\\app.asar","alg":"SHA256","value":"'
HASH_HEX_LENGTH = 64


def _is_hash(value: bytes) -> bool:
    return len(value) == HASH_HEX_LENGTH and all(byte in b"0123456789abcdef" for byte in value)


def find_asar_hash_offset(executable: Path) -> int:
    """Locate the sole resource anchor and validate its exact 64-character value."""
    found = -1
    carry = b""
    start = 0
    with executable.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            data = carry + block
            position = 0
            while (match := data.find(ASAR_HASH_ANCHOR, position)) >= 0:
                if found >= 0:
                    raise PatchError("More than one ASAR integrity resource match; executable layout is ambiguous")
                found = start + match + len(ASAR_HASH_ANCHOR)
                position = match + 1
            keep = min(len(data), len(ASAR_HASH_ANCHOR) - 1)
            carry = data[-keep:]
            start += len(data) - keep
        if found >= 0:
            stream.seek(found)
            value = stream.read(HASH_HEX_LENGTH + 1)
            if not _is_hash(value[:HASH_HEX_LENGTH]) or value[HASH_HEX_LENGTH:] != b'"':
                raise PatchError("ASAR integrity resource value must be exactly 64 lowercase hex characters")
    return found


def _read_asar_hash_backup(executable: Path) -> bytes | None:
    backup = Path(str(executable) + ".asarhashbak")
    if not backup.exists():
        return None
    original = backup.read_bytes()
    if not _is_hash(original):
        raise PatchError(f"ASAR integrity resource backup is invalid: {backup}")
    return original


def patch_asar_integrity_resource(executable: Path, asar: Path) -> bool:
    """Back up and replace only the embedded hash; older executables may omit it."""
    offset = find_asar_hash_offset(executable)
    if offset < 0:
        logger.info("ASAR integrity resource: no resource found; skipped (older build)")
        return False
    replacement = header_hash(asar).encode("ascii")
    backup = Path(str(executable) + ".asarhashbak")
    if backup.exists():
        raise PatchError(f"ASAR integrity resource backup already exists: {backup}")
    with executable.open("r+b") as stream:
        stream.seek(offset)
        original = stream.read(HASH_HEX_LENGTH)
        if original == replacement:
            logger.info("ASAR integrity resource: hash already matches app.asar")
            return True
        staging = Path(str(backup) + ".building")
        if staging.exists():
            raise PatchError(f"Stale ASAR integrity resource backup exists: {staging}")
        with staging.open("wb") as target:
            target.write(original)
            target.flush()
            os.fsync(target.fileno())
        os.replace(staging, backup)
        stream.seek(offset)
        stream.write(replacement)
        stream.flush()
        os.fsync(stream.fileno())
    logger.info("ASAR integrity resource: updated executable hash to match app.asar")
    return True


def restore_asar_integrity_resource(executable: Path) -> None:
    original = _read_asar_hash_backup(executable)
    if original is None:
        return
    offset = find_asar_hash_offset(executable)
    if offset < 0:
        raise PatchError("Cannot locate ASAR integrity resource for restoration; preserving its backup")
    with executable.open("r+b") as stream:
        stream.seek(offset)
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    Path(str(executable) + ".asarhashbak").unlink()
    logger.info("ASAR integrity resource: restored original executable hash")


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
    """Check the original PE hash, virtually undoing our fuse and resource edits."""
    backup = Path(str(executable) + ".fusebak")
    replacement = backup.read_bytes() if backup.exists() else None
    if replacement is not None and len(replacement) != 1:
        raise PatchError(f"Fuse backup is invalid: {backup}")
    offset = find_fuse_offset(executable) if replacement is not None else -1
    if replacement is not None and offset < 0:
        raise PatchError("Cannot locate Electron fuse to verify the executable")
    resource = _read_asar_hash_backup(executable)
    resource_offset = find_asar_hash_offset(executable) if resource is not None else -1
    if resource is not None and resource_offset < 0:
        raise PatchError("Cannot locate ASAR integrity resource to verify the executable")
    replacements = [(offset, replacement), (resource_offset, resource)]
    digest = hashlib.sha256()
    position = 0
    with executable.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            for edit_offset, original in replacements:
                if original is None:
                    continue
                start = max(position, edit_offset)
                end = min(position + len(block), edit_offset + len(original))
                if start < end:
                    block = (block[:start - position] + original[start - edit_offset:end - edit_offset]
                             + block[end - position:])
            digest.update(block)
            position += len(block)
    return digest.hexdigest() == expected_hash


def _is_no_arg_boolean(signature: bytes) -> bool:
    """Read the ECMA-335 method signature, including compressed generic counts."""
    def compressed_integer(position: int) -> tuple[int, int]:
        first = signature[position]
        if first < 0x80:
            return first, position + 1
        if first < 0xC0:
            return ((first & 0x3F) << 8) | signature[position + 1], position + 2
        if first < 0xE0:
            value = int.from_bytes(signature[position:position + 4], "big") & 0x1FFFFFFF
            if position + 4 > len(signature):
                raise ValueError("Truncated method signature")
            return value, position + 4
        raise ValueError("Invalid compressed signature integer")

    try:
        position = 1
        if signature[0] & 0x10:  # GENERIC
            _, position = compressed_integer(position)
        parameters, position = compressed_integer(position)
        return parameters == 0 and signature[position] == 0x02  # ELEMENT_TYPE_BOOLEAN
    except (IndexError, ValueError):
        return False


def _find_auxiliary_fuse_offset(pe, read_body) -> int:
    """Find the sole bool predicate on the type loading Electron's stable sentinel."""
    owner = None
    for type_row in pe.net.mdtables.TypeDef:
        references_anchor = False
        for method in type_row.MethodList:
            body = read_body(method.row)
            if body is None:
                continue
            for instruction in body.instructions:
                token = getattr(instruction.operand, "value", 0)
                if instruction.mnemonic != "ldstr" or token & 0xFF000000 != 0x70000000:
                    continue
                try:
                    literal = pe.net.user_strings.get(token & 0x00FFFFFF) if pe.net.user_strings else None
                except (IndexError, ValueError, UnicodeError):
                    continue
                if literal is not None and literal.value == SENTINEL.decode("ascii"):
                    references_anchor = True
                    break
            if references_anchor:
                break
        if references_anchor:
            if owner is not None:
                raise PatchError("More than one type references the Electron fuse sentinel; auxiliary layout is ambiguous")
            owner = type_row
    if owner is None:
        return -1
    predicates = [method.row for method in owner.MethodList
                  if method.row.Rva and _is_no_arg_boolean(method.row.Signature.value)]
    if len(predicates) != 1:
        raise PatchError("Expected exactly one no-arg bool method on the fuse-anchored auxiliary type; "
                         f"found {len(predicates)}")
    row = predicates[0]
    body = read_body(row)
    if body is None or len(body.get_instruction_bytes()) < 2:
        raise PatchError("Auxiliary ASAR-fuse predicate has no readable two-byte IL body")
    return pe.get_offset_from_rva(row.Rva) + len(body.get_header_bytes())


def neutralize_auxiliary(unpacked_root: Path) -> int:
    """Neutralize trust callers and the optional ASAR-fuse predicate; return edits made."""
    auxiliary = unpacked_root / "static" / "unpacked" / "auxiliary"
    if not auxiliary.is_dir():
        logger.info("Auxiliary trust patch: no auxiliary service directory; skipped")
        return 0
    candidates = sorted(auxiliary.glob("*AuxiliaryService.exe"))
    if not candidates:
        logger.info("Auxiliary trust patch: no auxiliary service executable; skipped")
        return 0
    target = candidates[0]
    logger.info("Inspecting auxiliary trust and ASAR-fuse checks in %s", target.name)

    # Imports stay here so status/restore can report problems without requiring PE packages.
    try:
        import dnfile
        from dncil.cil.body import CilMethodBody
        from dncil.cil.body.reader import CilMethodBodyReaderBase
        from dncil.cil.error import MethodBodyFormatError
        from dncil.clr.token import Token
    except ImportError as error:
        raise PatchError("PE packages are missing; install requirements.txt") from error

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
        if not pe.net or not pe.net.mdtables or not pe.net.mdtables.MethodDef or not pe.net.mdtables.TypeDef:
            raise PatchError(f"{target.name} is not a readable managed image")

        def read_body(row):
            if not row.Rva or not row.ImplFlags.miIL or row.Flags.mdAbstract or row.Flags.mdPinvokeImpl:
                return None
            try:
                return CilMethodBody(MethodReader(pe, row))
            except (MethodBodyFormatError, ValueError):
                return None

        rows = list(pe.net.mdtables.MethodDef)
        tokens = {0x06000000 | index for index, row in enumerate(rows, 1)
                  if str(row.Name) == "WinVerifyTrust"}
        if not tokens:
            raise PatchError(f"No WinVerifyTrust import found in {target.name}")
        offsets: list[int] = []
        for row in rows:
            body = read_body(row)
            if body is None:
                continue
            if any(instruction.mnemonic in ("call", "callvirt")
                   and isinstance(instruction.operand, Token)
                   and instruction.operand.value in tokens
                   for instruction in body.instructions):
                code = pe.get_offset_from_rva(row.Rva) + len(body.get_header_bytes())
                if len(body.get_instruction_bytes()) < 2:
                    raise PatchError(f"WinVerifyTrust caller has too little IL in {target.name}")
                offsets.append(code)
        fuse_offset = _find_auxiliary_fuse_offset(pe, read_body)
    finally:
        pe.close()

    if not offsets:
        raise PatchError(f"No WinVerifyTrust caller found in {target.name}; auxiliary layout may have changed")
    if fuse_offset in offsets:
        raise PatchError("Auxiliary trust and ASAR-fuse predicates overlap; refusing conflicting edits")
    stubbed = 0
    fuse_stubbed = 0
    with target.open("r+b") as stream:
        for offset in offsets:
            stream.seek(offset)
            if stream.read(2) == b"\x16\x2a":
                continue
            stream.seek(offset)
            stream.write(b"\x16\x2a")  # ldc.i4.0; ret
            stubbed += 1
        if fuse_offset >= 0:
            stream.seek(fuse_offset)
            if stream.read(2) != b"\x17\x2a":
                stream.seek(fuse_offset)
                stream.write(b"\x17\x2a")  # ldc.i4.1; ret
                fuse_stubbed = 1
        stream.flush()
        os.fsync(stream.fileno())
    logger.info("Auxiliary trust patch: updated %d WinVerifyTrust caller(s)", stubbed)
    if fuse_offset < 0:
        logger.info("Auxiliary ASAR-fuse patch: no anchored check found; skipped (older build)")
    else:
        logger.info("Auxiliary ASAR-fuse patch: updated %d predicate(s)", fuse_stubbed)
    return stubbed + fuse_stubbed
