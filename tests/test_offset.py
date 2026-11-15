"""Tests for the cyclic pattern generator and the gdb-driven offset finder.

The gdb run itself is mocked (we patch `have`/`run`), so these tests need no
gdb and no target binary -- they exercise the pure-Python pipeline.
"""
import ctfkit.offset as O


def test_cyclic_unique_4grams():
    pat = O.cyclic(5000)
    grams = [bytes(pat[i:i + 4]) for i in range(len(pat) - 3)]
    assert len(grams) == len(set(grams))


def test_cyclic_is_pwntools_compatible():
    # byte-for-byte identical to pwntools cyclic() for the default alphabet/n
    assert O.cyclic(32) == b"aaaabaaacaaadaaaeaaafaaagaaahaaa"


def test_cyclic_find_roundtrip():
    pat = O.cyclic(300)
    assert O.cyclic_find(pat[100:104]) == 100


def test_cyclic_find_accepts_int():
    pat = O.cyclic(300)
    val = int.from_bytes(pat[40:44], "little")
    assert O.cyclic_find(val) == 40


def test_find_offset_via_pc(monkeypatch):
    pat = O.cyclic(200)
    off = 72
    rip = int.from_bytes(pat[off:off + 8], "little")
    monkeypatch.setattr(O, "have", lambda tool: True)
    monkeypatch.setattr(O, "run", lambda cmd, data=None: f"$1 = {hex(rip)}\n")
    got, meta = O.find_offset("dummy", length=200)
    assert got == off
    assert meta["method"] == "rip"


def test_find_offset_pc_not_in_pattern(monkeypatch):
    # a real libc address at crash -> honestly return None, no guessing
    monkeypatch.setattr(O, "have", lambda tool: True)
    monkeypatch.setattr(O, "run", lambda cmd, data=None: "$1 = 0x7ffff7a05def\n")
    got, meta = O.find_offset("dummy", length=200)
    assert got is None


def test_find_offset_no_crash(monkeypatch):
    monkeypatch.setattr(O, "have", lambda tool: True)
    monkeypatch.setattr(O, "run", lambda cmd, data=None: "Inferior exited normally\n")
    got, _ = O.find_offset("dummy")
    assert got is None


def test_find_offset_no_gdb(monkeypatch):
    monkeypatch.setattr(O, "have", lambda tool: False)
    got, meta = O.find_offset("dummy")
    assert got is None
    assert "gdb" in meta["error"]


def test_patch_offset_in(tmp_path):
    f = tmp_path / "exp.py"
    f.write_text("from pwn import *\nOFFSET = 0  # TODO: set\nprint(OFFSET)\n")
    ok, why = O.patch_offset_in(str(f), 136)
    assert ok, why
    assert "OFFSET = 136" in f.read_text()


def test_patch_offset_missing_line(tmp_path):
    f = tmp_path / "exp.py"
    f.write_text("print('no offset here')\n")
    ok, why = O.patch_offset_in(str(f), 10)
    assert ok is False
    assert why
