import json

from memsentry.findings import Finding, Severity
from memsentry.report import max_severity, render_text, to_json, to_sarif


def _finding(sev):
    return Finding(check="instruction_injection", severity=sev, title="t", detail="d", file="x.md", line=7, snippet="s")


def test_render_text_reports_clean_when_no_findings():
    text = render_text({"x.md": []})
    assert "No findings" in text


def test_render_text_includes_counts():
    text = render_text({"x.md": [_finding(Severity.HIGH)]})
    assert "1 finding(s)" in text


def test_to_json_shape():
    payload = json.loads(to_json({"x.md": [_finding(Severity.CRITICAL)]}))
    assert payload["x.md"][0]["severity"] == "critical"


def test_to_sarif_shape_and_location():
    payload = json.loads(to_sarif({"x.md": [_finding(Severity.CRITICAL)]}))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "memsentry"
    result = payload["runs"][0]["results"][0]
    assert result["ruleId"] == "memsentry/instruction_injection"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "x.md"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7


def test_max_severity_picks_worst():
    results = {"x.md": [_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.MEDIUM)]}
    assert max_severity(results) == Severity.CRITICAL


def test_max_severity_none_when_empty():
    assert max_severity({"x.md": []}) is None
