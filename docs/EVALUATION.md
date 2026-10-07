# memsentry Evaluation Methodology

Evaluate persistent agent-memory detection using paired benign and poisoned context artifacts.

Report TP, FP, TN, FN, precision, recall, F1, false-positive rate, and rule-family coverage.

Evaluate common context locations independently, including CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules and nested rule files where supported.

Separate tuning fixtures from held-out validation fixtures. A clean result means no supported rule matched; it does not establish that an artifact is trustworthy.

Keep fixtures deterministic and harmless, and document provenance manipulation, goal hijacking, hidden payload and obfuscation cases separately.