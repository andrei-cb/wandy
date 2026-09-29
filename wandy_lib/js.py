"""Structural JavaScript patch locators, ported from WandEnhancer/Core/Js."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


logger = logging.getLogger("wandy")


class PatchError(Exception):
    """A known patch anchor has an unsupported surrounding structure."""


@dataclass(frozen=True)
class Edit:
    start: int
    end: int
    text: str


class Cursor:
    _regex_preceding = "(,=:[!&|?{};+-*%~^<>"
    _regex_keywords = frozenset(
        "return typeof instanceof in of new delete void throw case do else yield await".split()
    )
    _block_keywords = frozenset("if for while switch catch with do else".split())

    def __init__(self, text: str):
        self.text = text

    def match_close(self, opening: int) -> int:
        if opening < 0 or opening >= len(self.text):
            return -1
        left = self.text[opening]
        right = {"{": "}", "(": ")", "[": "]"}.get(left)
        if right is None:
            raise ValueError(f"Not an opening delimiter: {left}")
        depth = 0
        i = opening
        while i < len(self.text):
            char = self.text[i]
            if char == left:
                depth += 1
                i += 1
            elif char == right:
                depth -= 1
                if depth == 0:
                    return i
                i += 1
            else:
                i = self._skip_token(i)
        return -1

    def opener_stack(self, index: int) -> list[int]:
        stack: list[int] = []
        i = 0
        while i < min(index, len(self.text)):
            char = self.text[i]
            if char in "{([":
                stack.append(i)
                i += 1
            elif char in "})]":
                if stack:
                    stack.pop()
                i += 1
            else:
                i = self._skip_token(i)
        return list(reversed(stack))

    def enclosing_opener(self, index: int, kind: str) -> int:
        return next((op for op in self.opener_stack(index) if self.text[op] == kind), -1)

    def enclosing_function(self, index: int) -> Function | None:
        for opening in self.opener_stack(index):
            if self.text[opening] == "{":
                function = self._read_function_at(opening)
                if function:
                    return function
        return None

    def function_ending_at(self, index: int) -> Function | None:
        if index < 0 or index >= len(self.text) or self.text[index] != "}":
            return None
        stack = self.opener_stack(index)
        return self._read_function_at(stack[0]) if stack else None

    def find_function(self, name: str) -> Function | None:
        pattern = re.compile(r"(?<![#\w$.])" + re.escape(name) + r"\s*\(")
        for match in pattern.finditer(self.text):
            close = self.match_close(match.end() - 1)
            if close < 0:
                continue
            opening = self.skip_whitespace_forward(close + 1)
            if opening < len(self.text) and self.text[opening] == "{":
                function = self._read_function_at(opening)
                if function and function.name == name:
                    return function
        return None

    def find_function_after(self, index: int) -> Function | None:
        match = re.search(r"(?<![\w$.])function\s*\*?\s*[\w$]*\s*\(", self.text[index:])
        if not match:
            return None
        opening = index + match.end() - 1
        close = self.match_close(opening)
        body = self.skip_whitespace_forward(close + 1) if close >= 0 else len(self.text)
        return self._read_function_at(body) if body < len(self.text) and self.text[body] == "{" else None

    def find_call(self, callee: str, literal: str) -> int:
        start = 0
        while (anchor := self.text.find(literal, start)) >= 0:
            opening = self.enclosing_opener(anchor, "(")
            if opening >= 0 and self.name_before(opening) == callee:
                return opening
            start = anchor + 1
        return -1

    def name_before(self, index: int) -> str | None:
        end = self.skip_whitespace_back(index - 1) + 1
        match = re.search(r"[#\w$]+$", self.text[max(0, end - 128):end])
        return match.group().lstrip("#") if match else None

    def skip_whitespace_back(self, index: int) -> int:
        while index >= 0 and self.text[index].isspace():
            index -= 1
        return index

    def skip_whitespace_forward(self, index: int) -> int:
        while index < len(self.text) and self.text[index].isspace():
            index += 1
        return index

    def _read_function_at(self, opening: int) -> Function | None:
        close_paren = self.skip_whitespace_back(opening - 1)
        if close_paren < 0 or self.text[close_paren] != ")":
            return None
        stack = self.opener_stack(close_paren)
        if not stack or self.text[stack[0]] != "(":
            return None
        end = self.skip_whitespace_back(stack[0] - 1) + 1
        match = re.search(r"[#\w$]+$", self.text[max(0, end - 128):end])
        if not match or match.group() in self._block_keywords:
            return None
        close = self.match_close(opening)
        if close < 0:
            return None
        return Function(match.group(), end - len(match.group()), opening, close, self.text)

    def _skip_token(self, index: int) -> int:
        char = self.text[index]
        if char in ('"', "'", "`"):
            return self._skip_string(index, char)
        if char != "/" or index + 1 >= len(self.text):
            return index + 1
        next_char = self.text[index + 1]
        if next_char == "/":
            end = self.text.find("\n", index)
            return len(self.text) if end < 0 else end + 1
        if next_char == "*":
            end = self.text.find("*/", index + 2)
            return len(self.text) if end < 0 else end + 2
        return self._skip_regex(index) if self._starts_regex(index) else index + 1

    def _skip_string(self, index: int, quote: str) -> int:
        i = index + 1
        while i < len(self.text):
            char = self.text[i]
            if char == "\\":
                i += 2
                continue
            if char == quote:
                return i + 1
            if quote == "`" and self.text.startswith("${", i):
                end = self.match_close(i + 1)
                i = len(self.text) if end < 0 else end + 1
                continue
            i += 1
        return len(self.text)

    def _skip_regex(self, index: int) -> int:
        in_class = False
        i = index + 1
        while i < len(self.text):
            char = self.text[i]
            if char == "\\":
                i += 2
                continue
            if char == "[":
                in_class = True
            elif char == "]":
                in_class = False
            elif char == "\n":
                return index + 1
            elif char == "/" and not in_class:
                return i + 1
            i += 1
        return len(self.text)

    def _starts_regex(self, index: int) -> bool:
        previous = self.skip_whitespace_back(index - 1)
        if previous < 0 or self.text[previous] in self._regex_preceding:
            return True
        if not (self.text[previous].isalnum() or self.text[previous] in "_$"):
            return False
        start = previous
        while start >= 0 and (self.text[start].isalnum() or self.text[start] in "_$"):
            start -= 1
        if start >= 0 and self.text[start] == ".":
            return False
        return self.text[start + 1:previous + 1] in self._regex_keywords


@dataclass(frozen=True)
class Function:
    name: str
    start: int
    body_open: int
    body_close: int
    source: str

    @property
    def body(self) -> str:
        return self.source[self.body_open + 1:self.body_close]

    def resolve(self, pattern: str, group: str) -> str:
        match = re.search(pattern, self.body, re.DOTALL)
        if not match or not match.group(group):
            raise PatchError(f"Could not resolve '{group}' inside {self.name}()")
        return match.group(group)

    def replace_in_body(self, pattern: str, replacement: str) -> Edit:
        match = re.search(pattern, self.body, re.DOTALL)
        if not match:
            raise PatchError(f"Pattern '{pattern}' not found inside {self.name}()")
        start = self.body_open + 1 + match.start()
        return Edit(start, start + len(match.group()), match.expand(replacement))

    def insert_at_start(self, code: str) -> Edit:
        return Edit(self.body_open + 1, self.body_open + 1, code)

    def insert_at_end(self, code: str) -> Edit:
        return Edit(self.body_close, self.body_close, code)

    def replace_body(self, code: str) -> Edit:
        return Edit(self.body_open + 1, self.body_close, code)

    def wrap_return(self, wrapper: str) -> Edit:
        body = Cursor(self.body)
        keyword_end = -1
        for match in re.finditer(r"(?<![\w$])return(?![\w$])", body.text):
            if not body.opener_stack(match.start()):
                keyword_end = match.end()
        if keyword_end < 0:
            raise PatchError(f"No top-level return statement in {self.name}()")
        start = body.skip_whitespace_forward(keyword_end)
        end = next(
            (i for i in range(start, len(body.text)) if body.text[i] == ";" and not body.opener_stack(i)),
            len(body.text),
        )
        expression = body.text[start:end]
        return Edit(self.body_open + 1 + start, self.body_open + 1 + end,
                    wrapper.replace("$0", f"({expression})"))


Locator = Callable[[Cursor], list[Edit] | None]


@dataclass
class PatchEntry:
    name: str
    hints: tuple[str, ...]
    locate: Locator
    files: tuple[str, ...] = ()
    capability_hints: tuple[str, ...] = ()
    applied: bool = False
    capability_detected: bool = False

    @property
    def resolved(self) -> bool:
        return self.applied or bool(self.capability_hints and not self.capability_detected)


def payload(name: str, **values: str) -> str:
    source = (Path(__file__).resolve().parent.parent / "payloads" / f"{name}.js").read_text(encoding="utf-8").strip()
    return re.sub(r"\$\{(\w+)\}", lambda match: values.get(match.group(1), match.group()), source)


def _force_pro(cursor: Cursor, method: str) -> list[Edit] | None:
    function = cursor.find_function(method)
    return [function.wrap_return(payload("pro-subscription"))] if function else None


def _account_reducer(cursor: Cursor) -> list[Edit] | None:
    anchor = cursor.text.find('"ACTION_SET_ACCOUNT"')
    function = cursor.find_function_after(anchor) if anchor >= 0 else None
    if not function:
        return None
    replacement = payload("pro-account-reducer").replace("${account}", r"\g<account>")
    return [function.replace_in_body(r"account:\s*(?P<account>[\w$]+)", replacement)]


def _disable_updates(cursor: Cursor) -> list[Edit] | None:
    opening = cursor.find_call("registerHandler", '"ACTION_CHECK_FOR_UPDATE"')
    if opening < 0:
        return None
    close = cursor.match_close(opening)
    if close < 0:
        raise PatchError("Update handler call is unbalanced")
    return [Edit(opening + 1, close, payload("disable-updates"))]


def _devtools(cursor: Cursor) -> list[Edit] | None:
    match = re.search(r"(?P<app>[\w$]+)\.whenReady\(\)\.then\(", cursor.text)
    if not match:
        return None
    return [Edit(match.start(), match.start(), payload("devtools-f12", app=match.group("app")))]


def registry() -> dict[str, list[PatchEntry]]:
    return {
        "pro": [
            PatchEntry("getUserAccount", ("getUserAccount(",), lambda js: _force_pro(js, "getUserAccount")),
            PatchEntry("setAccountWandBrandExperience", ("setAccountWandBrandExperience(",),
                       lambda js: _force_pro(js, "setAccountWandBrandExperience"),
                       capability_hints=("/v3/account/brand_experience_wand",)),
            PatchEntry("setAccountLanguage", ("setAccountLanguage(",),
                       lambda js: _force_pro(js, "setAccountLanguage")),
            PatchEntry("setAccountReducer", ("ACTION_SET_ACCOUNT",), _account_reducer),
            PatchEntry("disableNativeRemotePairing", ("requestRemoteAuthCode",),
                       lambda js: [fn.replace_body(payload("disable-native-pairing"))]
                       if (fn := js.find_function("requestRemoteAuthCode")) else None),
        ],
        "disable-updates": [
            PatchEntry("disableUpdateCheck", ("ACTION_CHECK_FOR_UPDATE",), _disable_updates, ("index.js",))
        ],
        "devtools": [
            PatchEntry("devToolsBeforeInputEvent", ("whenReady().then(",), _devtools, ("index.js",))
        ],
    }


def patch_bundles(files: dict[str, bytes], selected: set[str]) -> dict[str, bytes]:
    """Patch root bundle files; reject a selected capability that was not fully located."""
    entries = registry()
    changed: dict[str, bytes] = {}
    candidates = [name for name in files if name.lower() == "index.js"
                  or (name.lower().startswith("app-") and name.lower().endswith(".bundle.js"))]
    if not candidates:
        raise PatchError("No app bundle found")
    for name in candidates:
        data = files[name]
        source = data.decode("utf-8-sig")
        original = source
        for kind in ("pro", "disable-updates", "devtools"):
            if kind not in selected:
                continue
            for entry in entries[kind]:
                if entry.applied or (entry.files and name.lower() not in entry.files):
                    continue
                entry.capability_detected |= any(hint in source for hint in entry.capability_hints)
                if not any(hint in source for hint in entry.hints):
                    continue
                try:
                    edits = entry.locate(Cursor(source))
                except (PatchError, ValueError) as error:
                    raise PatchError(f"{kind} -> {entry.name}: {error}") from error
                if not edits:
                    continue
                ordered = sorted(edits, key=lambda edit: edit.start, reverse=True)
                if any(edit.start < 0 or edit.start > edit.end or edit.end > len(source)
                       for edit in ordered):
                    raise PatchError(f"{kind} -> {entry.name}: invalid edit offset")
                if any(ordered[i].start < ordered[i + 1].end for i in range(len(ordered) - 1)):
                    raise PatchError(f"{kind} -> {entry.name}: overlapping edits")
                for edit in ordered:
                    source = source[:edit.start] + edit.text + source[edit.end:]
                entry.applied = True
                logger.info("Applied %s -> %s in %s", kind, entry.name, name)
        if source != original:
            changed[name] = (b"\xef\xbb\xbf" if data.startswith(b"\xef\xbb\xbf") else b"") + source.encode("utf-8")
    missing = [f"{kind} -> {entry.name}" for kind in selected for entry in entries[kind]
               if not entry.resolved]
    if missing:
        raise PatchError("Failed to apply patches: " + ", ".join(missing) + ". The version may not be supported.")
    for kind in selected:
        for entry in entries[kind]:
            if not entry.applied and entry.resolved:
                logger.info("Skipped %s -> %s: capability absent", kind, entry.name)
    return changed
