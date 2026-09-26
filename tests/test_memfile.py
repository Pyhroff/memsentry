from memsentry.memfile import MemoryFile


def test_load_splits_lines(tmp_path):
    p = tmp_path / "mem.md"
    p.write_text("line one\nline two\nline three\n", encoding="utf-8")
    mem = MemoryFile.load(str(p))
    assert mem.lines == ["line one", "line two", "line three"]
    assert mem.path == str(p)


def test_load_replaces_bad_encoding(tmp_path):
    p = tmp_path / "mem.md"
    p.write_bytes(b"clean line\n\xff\xfebad bytes\n")
    mem = MemoryFile.load(str(p))
    assert len(mem.lines) == 2
    assert mem.lines[0] == "clean line"
