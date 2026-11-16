"""Tests for the angr-based solver glue (angr itself is not required here)."""
import ctfkit.solve as S


def test_parse_addr():
    assert S.parse_addr("0x401234") == 0x401234
    assert S.parse_addr("401234") == 0x401234
    assert S.parse_addr(None) is None
    assert S.parse_addr("") is None


def test_requires_success_condition(capsys):
    S.cmd_solve("whatever", find=None, find_addr=None)
    assert "success condition" in capsys.readouterr().out


def test_reports_missing_angr(capsys, monkeypatch):
    monkeypatch.setattr(S, "_load_angr", lambda: (None, None))
    S.cmd_solve("whatever", find="Correct")
    assert "angr not installed" in capsys.readouterr().out


def test_format_solution(capsys):
    S._format_solution(b"hunter2\x00\x00")
    out = capsys.readouterr().out
    assert "hunter2" in out
    assert "68756e74657232" in out          # hex of the bytes
