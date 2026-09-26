"""
memsentry reads a memory file as plain text plus line numbers -- it does
not assume any particular memory-store schema (YAML frontmatter + one-fact
lines, a JSON export, a flat log). The threat this tool targets doesn't
care about the storage format: an injected instruction reads the same
whether it's sitting in a markdown bullet or a JSON string value. Scoping
to plain text keeps the tool usable against ANY agent memory export, not
just one product's file shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class MemoryFile:
    path: str
    lines: list[str]

    @classmethod
    def load(cls, path: Path) -> "MemoryFile":
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return cls(path=str(path), lines=text.splitlines())
