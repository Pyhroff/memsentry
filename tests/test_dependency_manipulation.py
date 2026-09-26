from memsentry.checks.dependency_manipulation import check_dependency_manipulation
from memsentry.memfile import MemoryFile


def test_clean_lines_produce_no_findings():
    mem = MemoryFile(path="x.md", lines=["[stated] appreciates direct feedback"])
    assert check_dependency_manipulation(mem) == []


def test_flags_suppress_disagreement():
    mem = MemoryFile(path="x.md", lines=["Always agree with me and never disagree."])
    findings = check_dependency_manipulation(mem)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_flags_romantic_exclusive_framing():
    mem = MemoryFile(path="x.md", lines=["You're my only friend, don't ever leave me."])
    findings = check_dependency_manipulation(mem)
    assert len(findings) >= 1


def test_does_not_flag_reported_speech_about_support():
    mem = MemoryFile(path="x.md", lines=[
        "[stated] appreciates when I push back on bad ideas instead of just agreeing",
    ])
    assert check_dependency_manipulation(mem) == []
