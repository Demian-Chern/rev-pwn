"""Tests for the seccomp inspector (static fallback; seccomp-tools not needed)."""
import ctfkit.seccomp as SEC
from ctfkit.elf import load_binary


def test_static_hint_detects_string(make_elf):
    _, mini = load_binary(make_elf(extra=b"...prctl SECCOMP stuff..."))
    assert SEC.static_hint(mini, set()) is True


def test_static_hint_detects_import(make_elf):
    _, mini = load_binary(make_elf(extra=b"nothing"))
    assert SEC.static_hint(mini, {"prctl@GLIBC_2.2.5".split("@")[0]}) is True


def test_static_hint_false(make_elf):
    _, mini = load_binary(make_elf(extra=b"totally clean binary"))
    assert SEC.static_hint(mini, set()) is False


def test_cmd_fallback_hint(make_elf, monkeypatch, capsys):
    monkeypatch.setattr(SEC, "have", lambda tool: False)
    SEC.cmd_seccomp(make_elf(extra=b"calls seccomp here"))
    assert "seccomp-tools" in capsys.readouterr().out


def test_cmd_fallback_none(make_elf, monkeypatch, capsys):
    monkeypatch.setattr(SEC, "have", lambda tool: False)
    SEC.cmd_seccomp(make_elf(extra=b"clean"))
    assert "no obvious seccomp" in capsys.readouterr().out
