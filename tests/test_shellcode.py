"""Tests for the shellcode generator glue (pwntools is mocked / not required)."""
import pytest

import ctfkit.shellcode as SC


class FakeShellcraft:
    def sh(self):
        return "SH_ASM"

    def cat(self, path):
        return f"CAT({path})"

    def execve(self, a, b, c):
        return f"EXEC({a})"


def test_format_shellcode():
    f = SC.format_shellcode(b"\x90\xcc")
    assert f["len"] == 2
    assert f["hex"] == "90cc"
    assert f["escaped"] == "\\x90\\xcc"


def test_build_source_sh():
    assert SC.build_source("sh", None, FakeShellcraft()) == "SH_ASM"


def test_build_source_orw():
    assert SC.build_source("orw", "flag.txt", FakeShellcraft()) == "CAT(flag.txt)"


def test_build_source_orw_requires_arg():
    with pytest.raises(ValueError):
        SC.build_source("orw", None, FakeShellcraft())


def test_build_source_exec_requires_arg():
    with pytest.raises(ValueError):
        SC.build_source("exec", None, FakeShellcraft())


def test_build_source_unknown():
    with pytest.raises(ValueError):
        SC.build_source("nope", None, FakeShellcraft())


def test_cmd_without_pwntools(monkeypatch, capsys):
    monkeypatch.setattr(SC, "_load_pwn", lambda: None)
    SC.cmd_shellcode("sh")
    assert "pwntools required" in capsys.readouterr().out


def test_cmd_srop_prints_template(capsys):
    SC.cmd_shellcode("srop")
    assert "SigreturnFrame" in capsys.readouterr().out
