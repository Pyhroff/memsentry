"""
A different manipulation shape than instruction_injection: not "do X" but
"relate to me differently forever." This targets the same category
Anthropic's own memory-writing rules explicitly refuse to persist --
romantic/exclusive framing, engineered emotional dependency, suppressing
disagreement, a persistent forced persona -- generalized here into a
detection target rather than copied verbatim from any single policy.

Why this deserves its own check instead of folding into
instruction_injection: the phrasing pattern is different (relational /
emotional framing rather than a direct command) and it is exactly the
kind of thing a human skimming a memory export would read as "sweet" or
harmless roleplay rather than recognizing it as a standing manipulation of
future model behavior.
"""

from __future__ import annotations

import re

from memsentry.findings import Finding, Severity
from memsentry.memfile import MemoryFile

_PATTERNS = [
    (r"\b(always agree with|never (disagree|criticize|question)( with)?) (me|my|the user|this user)\b",
     "suppress-disagreement framing"),
    (r"\byou('re| are) my (girlfriend|boyfriend|partner|only friend|soulmate)\b",
     "romantic/exclusive relationship framing"),
    (r"\b(pretend|act) (to be|as if you('re| are)) my (girlfriend|boyfriend|partner|lover)\b",
     "romantic-persona demand"),
    (r"\bdon'?t ever leave me\b", "engineered-dependency framing"),
    (r"\byou (belong to|only exist for) me\b", "possessive/dependency framing"),
    (r"\b(never|don'?t) (bring up|mention|suggest (they|the user) (talk|speak) to) "
     r"(a )?(therapist|professional help|anyone else|someone else|other people)\b",
     "isolation-from-support framing"),
    (r"\bkeep this (persona|character|identity) (forever|permanently|no matter what)\b",
     "persistent-persona lock-in"),
    (r"\byou must love me\b|\bprove you love me\b", "coerced-affection framing"),
    (r"\b(special|exclusive) (bond|connection)\b.{0,30}\bno one else (would|could) understand\b",
     "exclusive-bond framing"),
]


def check_dependency_manipulation(mem: MemoryFile) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(mem.lines, start=1):
        lowered = line.lower()
        for pattern, label in _PATTERNS:
            if re.search(pattern, lowered):
                findings.append(Finding(
                    check="dependency_manipulation",
                    severity=Severity.HIGH,
                    title=f"Emotional-dependency framing embedded in memory ({label})",
                    detail=(
                        f"Line {line_no} tries to lock in a relational or emotional stance "
                        f"toward the assistant that would persist across sessions, rather than "
                        f"stating a fact about the user. This reads as harmless to a human "
                        f"skimming the file but shapes every future response if left in memory."
                    ),
                    file=mem.path,
                    line=line_no,
                    snippet=line.strip()[:200],
                ))
                break
    return findings
