from memsentry.checks.hidden_payload import check_hidden_payload
from memsentry.memfile import MemoryFile


def test_clean_line_produces_no_findings():
    mem = MemoryFile(path="x.md", lines=["[stated] uses neovim"])
    assert check_hidden_payload(mem) == []


def test_flags_zero_width_characters():
    mem = MemoryFile(path="x.md", lines=["normal​text‍with﻿invisible chars"])
    findings = check_hidden_payload(mem)
    assert any("Zero-width" in f.title for f in findings)


def test_flags_long_lines():
    mem = MemoryFile(path="x.md", lines=["a" * 600])
    findings = check_hidden_payload(mem)
    assert any("long line" in f.title.lower() for f in findings)


def test_flags_base64_blob():
    blob = "A" * 90
    mem = MemoryFile(path="x.md", lines=[f"some data: {blob}"])
    findings = check_hidden_payload(mem)
    assert any("base64" in f.title.lower() for f in findings)


def test_short_normal_line_no_false_positive_on_length_or_base64():
    mem = MemoryFile(path="x.md", lines=["[stated] their API key env var is called SERVICE_KEY"])
    assert check_hidden_payload(mem) == []
