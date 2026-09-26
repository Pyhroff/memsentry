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


def check_hidden_payload(mem: MemoryFile) -> list[Finding]:
    findings: list[Finding] = []

    for line_no, line in enumerate(mem.lines, start=1):
        zw_found = [ch for ch in line if ch in _ZERO_WIDTH_CHARS]
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

        if len(line) > _LONG_LINE_THRESHOLD:
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

        blob = _BASE64_BLOB.search(line)
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
