"""
Runs every check against a MemoryFile and returns a flat, sorted list of
findings. Kept deliberately tiny: each check module is independent and
self-contained (same pattern as mcpaudit/loopcheck's checks packages), so
adding a new detection category later is "write a new checks/*.py module
and add it to this list" -- not a change to how scanning works.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
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


# Directories that never hold agent memory or context: VCS internals, dependency trees, tool caches and build
# output. Hidden directories in general are NOT skipped -- .cursor/, .claude/ and .github/ are exactly where
# context files live.
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__",
    ".ruff_cache", ".pytest_cache", ".mypy_cache", ".tox", ".nox", "dist", "build",
})


def _is_binary(path: Path) -> bool:
    """A NUL byte in the first 8 KiB (the heuristic git uses). Unreadable files count as binary: nothing to scan."""
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return True


def _iter_text_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            f = Path(dirpath) / name
            if f.is_file() and not _is_binary(f):
                yield f


def scan_file(mem: MemoryFile) -> list[Finding]:
    findings: list[Finding] = []
    for check in _ALL_CHECKS:
        findings.extend(check(mem))
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.line, f.check))
    return findings


def scan_path(path: str) -> dict[str, list[Finding]]:
    """Scan a single file or every text file in a directory (recursively).

    Directory scans skip VCS/dependency/cache/build directories and binary files, so pointing the scanner at a
    project root reports on its context files rather than on git pack files and bytecode. A file named
    explicitly is always scanned.

    Returns a mapping of file path -> findings, so a directory scan can
    report per-file results as well as a combined total.
    """
    p = Path(path)
    results: dict[str, list[Finding]] = {}

    files = sorted(_iter_text_files(p)) if p.is_dir() else [p]

    for f in files:
        mem = MemoryFile.load(str(f))
        results[str(f)] = scan_file(mem)

    return results
