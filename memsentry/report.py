""""
Human-readable, JSON, and SARIF rendering for CI/security tooling.
"""

from __future__ import annotations

import json

from memsentry.findings import Finding, Severity

_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
}
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_RESET = "\033[0m"


def render_text(results: dict[str, list[Finding]]) -> str:
    lines: list[str] = []
    total = sum(len(f) for f in results.values())

    for path, findings in results.items():
        if not findings:
            continue
        lines.append(f"\n{path}")
        lines.append("-" * len(path))
        for finding in findings:
            color = _COLOR.get(finding.severity, "")
            lines.append(f"  [{color}{finding.severity.value}{_RESET}] line {finding.line}: {finding.title}")
            lines.append(f"      {finding.detail}")
            lines.append(f"      snippet: {finding.snippet}")

    if total == 0:
        lines.append("No findings. Memory content looks clean.")
    else:
        clean_files = sum(1 for f in results.values() if not f)
        flagged_files = len(results) - clean_files
        lines.append(f"\n{total} finding(s) across {flagged_files} file(s) ({clean_files} clean).")

    return "\n".join(lines).strip()


def to_json(results: dict[str, list[Finding]]) -> str:
    payload = {
        path: [
            {
                "check": f.check,
                "severity": f.severity.value,
                "title": f.title,
                "detail": f.detail,
                "file": f.file,
                "line": f.line,
                "snippet": f.snippet,
            }
            for f in findings
        ]
        for path, findings in results.items()
    }
    return json.dumps(payload, indent=2)


def to_sarif(results: dict[str, list[Finding]]) -> str:
    """Render findings as SARIF 2.1.0 for GitHub Code Scanning and CI tools."""
    rules_by_id: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for findings in results.values():
        for finding in findings:
            rule_id = f"memsentry/{finding.check}"
            rules_by_id.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding.check,
                    "shortDescription": {"text": finding.title},
                },
            )
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": _SARIF_LEVEL[finding.severity],
                    "message": {"text": finding.detail},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file},
                                "region": {"startLine": finding.line},
                            }
                        }
                    ],
                }
            )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "memsentry",
                        "version": "1.2.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def max_severity(results: dict[str, list[Finding]]) -> Severity | None:
    all_findings = [f for findings in results.values() for f in findings]
    if not all_findings:
        return None
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for sev in order:
        if any(f.severity == sev for f in all_findings):
            return sev
    return None
