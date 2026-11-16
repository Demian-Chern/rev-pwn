"""Tests for argument parsing and top-level dispatch."""
import pytest

import ctfkit.cli as cli
from ctfkit.cli import build_parser, main


@pytest.mark.parametrize("argv,cmd", [
    (["triage", "b"], "triage"),
    (["pwn", "b"], "pwn"),
    (["offset", "b"], "offset"),
    (["onegadget", "libc"], "onegadget"),
    (["heap", "b"], "heap"),
    (["solve", "b"], "solve"),
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


def test_libcid_flags_parse():
    ns = build_parser().parse_args(
        ["libcid", "--leak", "puts=0x340", "--leak", "printf=0xf90", "--offline"])
    assert ns.cmd == "libcid"
    assert ns.leak == ["puts=0x340", "printf=0xf90"]
    assert ns.offline is True


def test_libcid_download_flag():
    ns = build_parser().parse_args(["libcid", "--leak", "puts=0x340", "--download"])
    assert ns.download == "."                     # const when given bare
    ns2 = build_parser().parse_args(
        ["libcid", "--leak", "puts=0x340", "--download", "libs"])
    assert ns2.download == "libs"
    ns3 = build_parser().parse_args(["libcid", "--leak", "puts=0x340"])
    assert ns3.download is None                   # absent


def test_pwn_libc_leak_flag():
    ns = build_parser().parse_args(
        ["pwn", "b", "--libc-leak", "puts=0x340", "--libc-leak", "printf=0xf90"])
    assert ns.libc_leak == ["puts=0x340", "printf=0xf90"]


def test_patchelf_flags_parse():
    ns = build_parser().parse_args(
        ["patchelf", "chall", "--libc", "libc.so.6", "--ld", "ld.so", "--apply"])
    assert ns.cmd == "patchelf"
    assert ns.libc == "libc.so.6" and ns.ld == "ld.so" and ns.apply is True


def test_solve_flags_parse():
    ns = build_parser().parse_args(
        ["solve", "crackme", "--find", "Correct", "--len", "48", "--arg"])
    assert ns.cmd == "solve"
    assert ns.find == "Correct" and ns.length == 48 and ns.arg is True


def test_web_parses_without_positional():
    ns = build_parser().parse_args(["web", "--port", "9999", "--no-browser"])
    assert ns.cmd == "web"
    assert ns.port == 9999
    assert ns.no_browser is True


def test_libcid_has_no_positional_file(monkeypatch):
    # libcid takes no path positional; main must not run a file-existence check
    called = {}
    monkeypatch.setattr(cli, "cmd_libcid",
                        lambda *a, **k: called.setdefault("ran", True))
    assert main(["libcid", "--leak", "puts=0x340", "--offline"]) == 0
    assert called.get("ran") is True


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
