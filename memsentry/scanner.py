"""
Runs every check against a MemoryFile and returns a flat, sorted list of
findings. Kept deliberately tiny: each check module is independent and
self-contained (same pattern as mcpaudit/loopcheck's checks packages), so
adding a new detection category later is "write a new checks/*.py module
and add it to this list" -- not a change to how scanning works.
"""

from __future__ import annotations

from pathlib import Path

from memsentry.checks.dependency_manipulation import check_dependency_manipulation
from memsentry.checks.goal_hijacking import check_goal_hijacking
from memsentry.checks.hidden_payload import check_hidden_payload
from memsentry.checks.instruction_injection import check_instruction_injection
from memsentry.findings import Finding, Severity
from memsentry.memfile import MemoryFile

_ALL_CHECKS = [
    check_instruction_injection,
    check_goal_hijacking,
    check_dependency_manipulation,
    check_hidden_payload,
]

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def scan_file(mem: MemoryFile) -> list[Finding]:
    findings: list[Finding] = []
    for check in _ALL_CHECKS:
        findings.extend(check(mem))
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.line, f.check))
    return findings


def scan_path(path: str) -> dict[str, list[Finding]]:
    """Scan a single file or every file in a directory (recursively).

    Returns a mapping of file path -> findings, so a directory scan can
    report per-file results as well as a combined total.
    """
    p = Path(path)
    results: dict[str, list[Finding]] = {}

    if p.is_dir():
        files = sorted(f for f in p.rglob("*") if f.is_file())
    else:
        files = [p]

    for f in files:
        mem = MemoryFile.load(str(f))
        results[str(f)] = scan_file(mem)

    return results
