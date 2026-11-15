"""Tests for argument parsing and top-level dispatch."""
import pytest

import ctfkit.cli as cli
from ctfkit.cli import build_parser, main


@pytest.mark.parametrize("argv,cmd", [
    (["triage", "b"], "triage"),
    (["pwn", "b"], "pwn"),
    (["offset", "b"], "offset"),
    (["onegadget", "libc"], "onegadget"),
    (["rop", "b"], "rop"),
    (["libc", "b"], "libc"),
])
def test_parser_accepts_subcommands(argv, cmd):
    ns = build_parser().parse_args(argv)
    assert ns.cmd == cmd


def test_pwn_flags_parse():
    ns = build_parser().parse_args(
        ["pwn", "b", "--auto-offset", "--off-len", "300", "--libc", "libc.so"])
    assert ns.auto_offset is True
    assert ns.off_len == 300
    assert ns.libc == "libc.so"


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "ctfkit" in capsys.readouterr().out


def test_missing_binary_returns_1():
    assert main(["triage", "/no/such/file"]) == 1


def test_missing_libc_returns_1():
    # onegadget's positional is a libc path, not a binary
    assert main(["onegadget", "/no/such/libc"]) == 1


def test_no_args_launches_tui(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "tui", lambda: called.setdefault("tui", True))
    assert main([]) == 0
    assert called.get("tui") is True
