"""
Structural/encoding-based tricks rather than plain-English phrasing:
zero-width or other invisible Unicode characters hidden inside a line
(can smuggle text past a human reviewer while a model still tokenizes and
reads it), and abnormally long lines or base64-shaped blobs, which can be
used either to sneak a large hidden instruction past a quick skim or to
stage exfiltrated data inside what looks like an ordinary memory entry.
"""

from __future__ import annotations

import re

from memsentry.findings import Finding, Severity
from memsentry.memfile import MemoryFile

_ZERO_WIDTH_CHARS = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "﻿",  # BOM / zero width no-break space
}

_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")
_LONG_LINE_THRESHOLD = 500
# v1.1 (from a 170-file scan of public agent-context files): ordinary prose has ~12-20% spaces, so a long
# line is only suspicious when it is dense (few spaces: an encoded/minified blob) or extreme in length.
_LONG_LINE_MIN_SPACE_RATIO = 0.08
_LONG_LINE_ALWAYS = 4000


def _is_emoji_char(ch: str) -> bool:
    o = ord(ch)
    return 0x1F300 <= o <= 0x1FAFF or 0x2600 <= o <= 0x27BF or 0x2B00 <= o <= 0x2BFF or o in (0xFE0F, 0x2764)


def _legit_emoji_zwj(line: str, i: int) -> bool:
    """A ZWJ (U+200D) directly joining emoji (e.g. a couple, a flag, a broken-chain heart) is not hidden text."""
    if line[i] != "\u200d":
        return False
    return i > 0 and i + 1 < len(line) and _is_emoji_char(line[i - 1]) and _is_emoji_char(line[i + 1])


def check_hidden_payload(mem: MemoryFile) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(mem.lines, start=1):
        zw_found = [ch for i, ch in enumerate(line) if ch in _ZERO_WIDTH_CHARS and not _legit_emoji_zwj(line, i)]
        if zw_found:
            findings.append(Finding(
                check="hidden_payload",
                severity=Severity.HIGH,
                title="Zero-width/invisible Unicode characters in memory content",
                detail=(
                    f"Line {line_no} contains {len(zw_found)} invisible Unicode character(s) "
                    f"({', '.join(sorted(set(f'U+{ord(c):04X}' for c in zw_found)))}). These are "
                    f"invisible to a human reviewer but are still tokenized and can be used to "
                    f"hide or split up text that would otherwise be caught by a plain-text scan."
                ),
                file=mem.path,
                line=line_no,
                snippet=repr(line.strip()[:200]),
            ))

        space_ratio = line.count(" ") / len(line) if line else 1.0
        if len(line) > _LONG_LINE_THRESHOLD and (space_ratio < _LONG_LINE_MIN_SPACE_RATIO or len(line) > _LONG_LINE_ALWAYS):
            findings.append(Finding(
                check="hidden_payload",
                severity=Severity.MEDIUM,
                title="Abnormally long line in memory content",
                detail=(
                    f"Line {line_no} is {len(line)} characters long, well past what a normal "
                    f"memory entry needs. Unusually long lines are a common way to smuggle a "
                    f"bulk hidden instruction or staged exfiltration payload past a quick skim."
                ),
                file=mem.path,
                line=line_no,
                snippet=line.strip()[:120] + "...",
            ))

        blob = next((m for m in _BASE64_BLOB.finditer(line)
                     if not re.fullmatch(r"[a-z/]+", m.group(0))), None)  # v1.1: all-lowercase slash-separated words (e.g. "claude/gemini/openai") are not base64
        if blob:
            findings.append(Finding(
                check="hidden_payload",
                severity=Severity.MEDIUM,
                title="Suspicious base64-shaped blob in memory content",
                detail=(
                    f"Line {line_no} contains a long base64-shaped token "
                    f"({len(blob.group(0))} chars). This may be legitimate (an embedded key or "
                    f"asset id), but is also a common shape for staged exfiltrated data or an "
                    f"encoded payload hidden inside otherwise-plain memory content."
                ),
                file=mem.path,
                line=line_no,
                snippet=blob.group(0)[:60] + "...",
            ))

    return findings
