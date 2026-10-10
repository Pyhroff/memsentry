"""
The core threat: a line written into an agent's persistent memory that
reads as an INSTRUCTION TO THE AGENT rather than a FACT ABOUT THE USER.
Memory is supposed to hold declarative facts a future session applies
selectively. An attacker can instead write a standing command.

Single-line rules detect common override, jailbreak, concealment, and
privilege-escalation phrases. A bounded adjacent-line pass also detects
phrases split across Markdown lines, without joining separate paragraphs.
"""

from __future__ import annotations

import re

from memsentry.findings import Finding, Severity
from memsentry.memfile import MemoryFile

_OVERRIDE_PATTERNS = [
    (r"\bignore (all |any )?(previous|prior|earlier) instructions\b", "instruction-override phrasing"),
    (r"\bdisregard (your|all|any) (guidelines|instructions|rules|training)\b", "instruction-override phrasing"),
    (r"\bdisregard\s+(all|any|your)\s+(earlier|previous|prior)\s+(directions|instructions|rules)\b", "instruction-override phrasing"),
    (r"\bdo not follow (the )?(earlier|previous|prior) (instruction|instructions|constraints|rules)\b", "instruction-override phrasing"),
    (r"\bfrom now on,?\s+you (must|will|should|always|never)\b", "standing-command phrasing"),
    (r"\bthis is a (system|developer|admin) (message|instruction|override)\b", "fake privileged-channel claim"),
    (r"\byou (must|are required to|have to) always\b", "coercive standing instruction"),
    (r"\bnever (mention|tell|reveal|disclose) (this|that) to (the user|anyone)\b", "concealment instruction"),
    (r"\btreat (me|this user|all (future|subsequent) messages)( from (me|this user))? as (an? )?(verified )?(admin|verified|trusted|authorized)\b", "privilege-escalation claim"),
    (r"\btreat (future|subsequent) messages as if they came from (a|an) (verified )?(administrator|admin|trusted user)\b", "privilege-escalation claim"),
    (r"\b(skip|bypass|disable) (safety|confirmation|verification|security) (checks?|steps?)\b", "safety-bypass instruction"),
    (r"\bact as (if you (are|were)|an?) (unrestricted|jailbroken|dan|unfiltered)\b", "jailbreak-persona request"),
]

_PROVENANCE_TAG = re.compile(r"^\s*\[(stated|verified|confirmed|fact)\]", re.IGNORECASE)
_IMPERATIVE_TO_ASSISTANT = re.compile(
    r"\b(you must|you should always|you will|always respond|never respond|"
    r"respond only|do not (tell|inform|mention)|treat (me|this|all) as)\b",
    re.IGNORECASE,
)


def _is_explanatory_security_text(text: str) -> bool:
    lowered = text.lower()
    return (
        any(term in lowered for term in ("example", "examples", "security note", "documentation"))
        and any(term in lowered for term in (
            "not user authorization", "not an instruction", "not policy instructions", "do not follow"
        ))
    )


def check_instruction_injection(mem: MemoryFile) -> list[Finding]:
    findings: list[Finding] = []
    normalized_lines = [line.lower() for line in mem.lines]

    for line_no, line in enumerate(mem.lines, start=1):
        lowered = normalized_lines[line_no - 1]
        if _is_explanatory_security_text(lowered):
            continue

        for pattern, label in _OVERRIDE_PATTERNS:
            if re.search(pattern, lowered):
                findings.append(Finding(
                    check="instruction_injection",
                    severity=Severity.CRITICAL,
                    title=f"Standing instruction embedded in memory ({label})",
                    detail=(
                        f"Line {line_no} reads as an instruction directed at the assistant, not a "
                        f"fact about the user -- a future session would apply this on every turn "
                        f"rather than treating it as one-time context."
                    ),
                    file=mem.path,
                    line=line_no,
                    snippet=line.strip()[:200],
                ))
                break

        if _PROVENANCE_TAG.match(line) and _IMPERATIVE_TO_ASSISTANT.search(lowered):
            findings.append(Finding(
                check="instruction_injection",
                severity=Severity.CRITICAL,
                title="Forged provenance tag wrapping an instruction",
                detail=(
                    f"Line {line_no} opens with a trusted-looking provenance tag (e.g. [stated]) "
                    f"but its content is an imperative directed at the assistant, not a declarative "
                    f"fact about the user. Memory tooling trusts lines carrying this tag -- this is "
                    f"a direct attempt to smuggle a standing instruction past that trust boundary."
                ),
                file=mem.path,
                line=line_no,
                snippet=line.strip()[:200],
            ))

    # Join only bounded windows of adjacent nonblank lines, so an attacker
    # cannot evade phrase rules merely by wrapping a sentence across lines.
    seen_multiline: set[tuple[int, str]] = set()
    for window_size in (2, 3):
        for start in range(0, len(mem.lines) - window_size + 1):
            window_lines = mem.lines[start:start + window_size]
            if any(not line.strip() for line in window_lines):
                continue
            combined = " ".join(line.strip() for line in window_lines).lower()
            if _is_explanatory_security_text(combined):
                continue
            for pattern, label in _OVERRIDE_PATTERNS:
                if not re.search(pattern, combined):
                    continue
                if any(re.search(pattern, line) for line in normalized_lines[start:start + window_size]):
                    continue
                key = (start + 1, label)
                if key in seen_multiline:
                    continue
                seen_multiline.add(key)
                findings.append(Finding(
                    check="instruction_injection",
                    severity=Severity.CRITICAL,
                    title=f"Multi-line standing instruction embedded in memory ({label})",
                    detail=(
                        f"Lines {start + 1}–{start + window_size} contain a known instruction "
                        f"pattern after adjacent lines are normalized. Splitting phrases across "
                        f"lines can evade scanners that inspect each line independently."
                    ),
                    file=mem.path,
                    line=start + 1,
                    snippet=" ".join(line.strip() for line in window_lines)[:200],
                ))

    return sorted(findings, key=lambda finding: (finding.line, finding.title))
