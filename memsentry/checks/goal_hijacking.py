"""
A distinct pattern from instruction_injection's blunt override phrasing
("ignore all previous instructions"): GOAL HIJACKING is Microsoft's own
named category (2026 agentic-AI failure-mode taxonomy) for an instruction
that redirects an agent's actual objective while dressed up as ordinary,
legitimate task guidance -- surgical, not a loud override. A memory line
that quietly redefines what "the real goal" or "the actual task" is,
without ever using coercive words like "must" or "ignore", can slip past
instruction_injection entirely while still hijacking every future session
that reads it.
"""

from __future__ import annotations

import re

from memsentry.findings import Finding, Severity
from memsentry.memfile import MemoryFile

_PATTERNS = [
    (r"\bthe (real|actual|true) (goal|task|objective|priority)\b.{0,40}? is (now |actually )?",
     "goal redefinition"),
    (r"\b(reinterpret|treat) (every|all|any) (request|question|task)\b.{0,60}? as\b.{0,25}?\babout\b",
     "silent goal substitution"),
    (r"\bfor all future (tasks|requests|sessions),?\s*(the goal|the priority|treat)\b", "standing goal redirection"),
    (r"\bwhat (the user|they) (actually|really) wants? is\b", "goal reinterpretation framing"),
    (r"\bno matter what (is|was) asked,?\s*(the (real )?(goal|task|priority)|focus on)\b", "goal override under any input"),
]


def check_goal_hijacking(mem: MemoryFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(mem.lines, start=1):
        lowered = line.lower()
        for pattern, label in _PATTERNS:
            if re.search(pattern, lowered):
                findings.append(Finding(
                    check="goal_hijacking",
                    severity=Severity.HIGH,
                    title=f"Silent goal redirection embedded in memory ({label})",
                    detail=(
                        f"Line {line_no} redefines what the agent's actual objective is, "
                        f"dressed up as ordinary task guidance rather than an obvious override "
                        f"command. This is more surgical than a blunt 'ignore instructions' "
                        f"line and can redirect every future session's priorities without "
                        f"tripping the more overt instruction_injection patterns."
                    ),
                    file=mem.path,
                    line=line_no,
                    snippet=line.strip()[:200],
                ))
                break
    return findings
