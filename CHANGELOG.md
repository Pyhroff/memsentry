# Changelog

memsentry shipped as a single v1.0.0. This file tracks changes after that release.

## Unreleased

- Phrase rules now match on a canonical form of each line (`memsentry/normalize.py`): NFKC, invisible format characters dropped, Cyrillic/Greek/Armenian look-alike letters folded to Latin, spaced-out letters re-joined, whitespace collapsed. Before this, doubling the spaces between words, swapping a few letters for Cyrillic look-alikes, or writing `i g n o r e` removed every high/critical finding from `samples/poisoned_memory.md`; now all of them survive.
- hidden_payload: new HIGH finding for words that mix Latin letters with look-alikes from another script (4+ characters, so maths notation like `Fβ` is not flagged).
- instruction_injection: text that labels itself as an example or disclaimer ("not an instruction") is now reported at MEDIUM instead of being dropped. The disclaimer is attacker-controllable, so it can no longer hide a real injection; use `--fail-on medium` to gate on it.
- No change in findings on 854 real README/CLAUDE.md/AGENTS.md/docs files used as a false-positive check.

## v1.2.0 (patch, from a 170-file scan of public agent-context files)

- hidden_payload: emoji ZWJ sequences (U+200D between emoji/variation selectors) are no longer reported as invisible characters.
- hidden_payload: "abnormally long line" now requires a dense line (< 8% spaces) or > 4000 characters; ordinary long prose no longer fires.
- hidden_payload: all-lowercase slash-separated word lists (e.g. "claude/gemini/openai") are not treated as base64 blobs.
- 4 regression tests added (real zero-width text, dense blobs and real base64 still fire).
- Known trade-off: an injected instruction written as ordinary prose on a single 500-4000 character line is no longer flagged by this check (the instruction_injection check still applies to its wording).

## [1.1.0] -- goal_hijacking check
- New `memsentry/checks/goal_hijacking.py`: detects memory lines that
  redefine an agent's actual objective while dressed up as ordinary task
  guidance, rather than an obvious override command ("ignore all previous
  instructions"). This is Microsoft's own named category from their 2026
  agentic-AI failure-mode taxonomy -- surgical goal redirection, distinct
  from instruction_injection's blunter override phrasing, and able to slip
  past it entirely since it never uses coercive words like "must" or
  "ignore".
- 5 new tests. 35 total, all passing.

## [1.0.0] -- initial release
- Static scanner for injected instructions in agent memory/context files:
  `instruction_injection` (override phrasing + forged provenance tags),
  `dependency_manipulation` (emotional-dependency framing), `hidden_payload`
  (zero-width Unicode, base64 blobs). CLI, 30 tests, clean/subtle/poisoned
  sample fixtures.
