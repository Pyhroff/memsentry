from __future__ import annotations

import sys

import typer

from memsentry.findings import Severity
from memsentry.report import max_severity, render_text, to_json, to_sarif
from memsentry.scanner import scan_path

app = typer.Typer(name="memsentry", help="Static scanner for injected instructions in agent memory/context files.")

_FAIL_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@app.command()
def scan(
    path: str = typer.Argument(..., help="A memory file, or a directory to scan recursively."),
    json_out: str | None = typer.Option(None, "--json", help="Write JSON results to this path."),
    sarif_out: str | None = typer.Option(None, "--sarif", help="Write SARIF 2.1.0 results to this path."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero if any finding is at or above this severity (low/medium/high/critical)."
    ),
) -> None:
    """Scan a memory file or directory for injected-instruction patterns."""
    results = scan_path(path)

    print(render_text(results))

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            f.write(to_json(results))
        print(f"\nJSON written to {json_out}")

    if sarif_out:
        with open(sarif_out, "w", encoding="utf-8") as f:
            f.write(to_sarif(results))
        print(f"\nSARIF written to {sarif_out}")

    if fail_on:
        try:
            threshold = Severity(fail_on.lower())
        except ValueError:
            print(f"\nUnknown --fail-on severity: {fail_on!r}", file=sys.stderr)
            raise typer.Exit(code=2)

        worst = max_severity(results)
        if worst is not None and _FAIL_ORDER[worst] >= _FAIL_ORDER[threshold]:
            raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
