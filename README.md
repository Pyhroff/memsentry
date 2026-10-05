# 🧠 memsentry

<div align="center">

**Static scanner for poisoned AI-agent memory and context.**

[![CI](https://github.com/Pyhroff/memsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/Pyhroff/memsentry/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Overview

An agent's memory can persist instructions that were never part of the user's request.

`memsentry` scans memory/context artifacts and flags content that attempts to influence future agent behavior.

It is the **memory module inside [aisec-suite](https://github.com/Pyhroff/aisec-suite)**.

## Detection surface

- persistent instruction injection
- forged provenance or trust tags
- goal hijacking
- dependency/social manipulation patterns
- hidden or obfuscated payloads

Common agent-context entry points include `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, and `.cursor/rules/*`.

## Usage

```bash
memsentry path/to/memory.md
memsentry path/to/memory.md --fail-on high
```

## Umbrella integration

```bash
aisec scan .
```

The umbrella automatically discovers common agent-context files and folds memsentry results into the shared suite reporting flow.

## Design

The scanner is static by design. It reads the memory artifact as text and does not execute its contents.

## Limitations

Patterns are heuristic. A clean scan means no supported rule matched the supplied artifact, not that the memory is guaranteed trustworthy.

## Development

```bash
pytest -q
```

## License

MIT
