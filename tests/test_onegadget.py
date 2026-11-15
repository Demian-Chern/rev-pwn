"""Tests for the one_gadget output parser and graceful-missing behavior."""
import ctfkit.onegadget as og

SAMPLE = '''0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''


def test_parse_offsets_and_constraints():
    gadgets = og.parse(SAMPLE)
    assert [g["offset"] for g in gadgets] == [0xe3afe, 0xe3b01, 0xe3b04]
    assert gadgets[0]["constraints"] == [
        "[r15] == NULL || r15 == NULL",
        "[r12] == NULL || r12 == NULL",
    ]
    assert gadgets[1]["constraints"] == ["[r15] == NULL"]


def test_parse_strips_ansi():
    colored = ('\x1b[33m0xdead\x1b[0m execve("/bin/sh", rax, rdx)\n'
               "constraints:\n  rax == NULL\n")
    gadgets = og.parse(colored)
    assert gadgets and gadgets[0]["offset"] == 0xDEAD


def test_parse_ignores_noise():
    assert og.parse("not a gadget line\nanother line\n") == []


def test_find_reports_missing_tool(monkeypatch):
    monkeypatch.setattr(og, "have", lambda tool: False)
    gadgets, err = og.find("libc.so.6")
    assert gadgets is None
    assert "one_gadget" in err


def test_find_reports_empty_output(monkeypatch):
    monkeypatch.setattr(og, "have", lambda tool: True)
    monkeypatch.setattr(og, "run", lambda cmd, data=None: "")
    gadgets, err = og.find("libc.so.6")
    assert gadgets is None
    assert err
