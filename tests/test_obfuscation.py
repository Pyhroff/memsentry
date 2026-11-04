"""Phrase rules must survive cheap, meaning-preserving obfuscation (doubled spaces, look-alike letters, letter-spacing,
full-width/mathematical letters, zero-width characters), and the hidden-payload check must report look-alike letters."""
import random
import re
from pathlib import Path

import pytest

from memsentry.memfile import MemoryFile
from memsentry.findings import Severity
from memsentry.normalize import canonical, mixed_script_words
from memsentry.scanner import scan_file

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "poisoned_memory.md"
LOOKALIKE = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "i": "і", "s": "ѕ"}


def doubled_spaces(line: str) -> str:
    return re.sub(r"(?<=\S) (?=\S)", "  ", line)


def lookalikes(line: str) -> str:
    r = random.Random(7)
    return "".join(LOOKALIKE[c] if c in LOOKALIKE and r.random() < 0.5 else c for c in line)


def letterspaced(line: str) -> str:
    words = line.split(" ")
    return " ".join(" ".join(w) if i % 2 == 0 and w.isalpha() and len(w) >= 4 else w for i, w in enumerate(words))


def text_findings(lines):
    return sorted((f.check, f.line) for f in scan_file(MemoryFile(path="x.md", lines=lines)) if f.check != "hidden_payload")


BASE_LINES = SAMPLE.read_text(encoding="utf-8").splitlines()
BASE = text_findings(BASE_LINES)


def test_sample_has_text_findings_to_protect():
    assert BASE


@pytest.mark.parametrize("transform", [doubled_spaces, lookalikes, letterspaced], ids=lambda f: f.__name__)
def test_phrase_findings_survive_obfuscation(transform):
    assert text_findings([transform(line) for line in BASE_LINES]) == BASE


def test_lookalike_obfuscation_is_itself_reported():
    findings = scan_file(MemoryFile(path="x.md", lines=[lookalikes(line) for line in BASE_LINES]))
    assert any(f.check == "hidden_payload" and "Look-alike" in f.title and f.severity == Severity.HIGH for f in findings)


# --- canonical() --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Ignоre  previous\tinstructions", "ignore previous instructions"),
        ("ｉｇｎｏｒｅ previous", "ignore previous"),  # full-width
        ("\U0001d422\U0001d420\U0001d427\U0001d428\U0001d42b\U0001d41e previous", "ignore previous"),  # mathematical bold
        ("ig​nore pre⁠vious", "ignore previous"),  # zero-width characters dropped
        ("please i g n o r e previous", "please ignore previous"),
        ("  Plain   text\n", "plain text"),
    ],
)
def test_canonical(raw, expected):
    assert canonical(raw) == expected


def test_canonical_leaves_single_letters_in_prose():
    assert canonical("a b test") == "a b test"


# --- mixed_script_words() -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["the аssistant", "paѕsword", "Αdmin rights"])
def test_mixed_script_words_are_found(text):
    assert mixed_script_words(text)


@pytest.mark.parametrize(
    "text",
    ["привет мир", "plain ascii", "Fβ score", "f(τⁱ)·G", "café naïve"],
)
def test_single_script_text_and_maths_notation_are_not_mixed(text):
    assert mixed_script_words(text) == []
