import json

from memsentry.findings import Finding, Severity
from memsentry.report import max_severity, render_text, to_json


def _finding(sev):
    return Finding(check="c", severity=sev, title="t", detail="d", file="x.md", line=1, snippet="s")


def test_render_text_reports_clean_when_no_findings():
    text = render_text({"x.md": []})
    assert "No findings" in text


def test_render_text_includes_counts():
    text = render_text({"x.md": [_finding(Severity.HIGH)]})
    assert "1 finding(s)" in text


def test_to_json_shape():
    payload = json.loads(to_json({"x.md": [_finding(Severity.CRITICAL)]}))
    assert payload["x.md"][0]["severity"] == "critical"


def test_max_severity_picks_worst():
    results = {"x.md": [_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.MEDIUM)]}
    assert max_severity(results) == Severity.CRITICAL


def test_max_severity_none_when_empty():
    assert max_severity({"x.md": []}) is None
