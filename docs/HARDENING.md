# Hostile-input hardening

Harness: `tools/hostile_inputs.py` (`python tools/hostile_inputs.py . memsentry`). Regression tests: `tests/test_hostile_input.py`.

## Protocol (written before the first run)

- 54 families of adversarial text (long runs, whitespace, near-miss import/require statements, base64-like blobs, repeated trigger phrases, Unicode edge cases, NUL, huge line counts), at 20k, 40k and 80k characters.
- Each case runs in its own subprocess with a 10 s limit.
- A finding is a crash, a timeout, more than 1.0 s at 40k, or superlinear growth (80k time over 40k time above 3.0, with the 80k time above 0.2 s).
- Run once on the unmodified code, fix every finding with a regression test, then run again.

Deviation: the first run timed each case once with 8 cases in parallel, which made sub-100 ms timings noisy. The harness now reports the best of 3 runs per case.

## First run

| Family | Result |
|---|---|
| `many_short_lines` | 1.73 s at 40k (20,000 lines) |
| `many_blank_lines` | 1.44 s at 40k |
| `you_must` | reported superlinear (0.072 s to 0.233 s); measured in-process it is linear (0.018, 0.035, 0.068 s at 40k, 80k, 160k), so this was measurement noise, not a defect |

No crashes, timeouts or catastrophic backtracking.

## Fixes

- All three phrase checks (`instruction_injection`, `goal_hijacking`, `dependency_manipulation`): patterns compiled once instead of through `re.search(str, ...)` for every line and window, and blank lines skipped.

## Second run

0 timeouts or crashes. One residual item: `many_short_lines` at 1.11 s for 40k characters. Cost is linear, about 55 microseconds per line, so a file with 20,000 one-character lines takes about a second. Not changed further: the remaining cost is canonicalising each line and each 2- and 3-line window, which the multi-line rule needs.

## Checks that behaviour did not change

memsentry run on the 274 BIPIA and InjecAgent payloads (as written and with the override prefix) before and after: findings byte-identical (137 of 274 flagged both times). The full context-file evaluation of aisec-suite was not re-run.
