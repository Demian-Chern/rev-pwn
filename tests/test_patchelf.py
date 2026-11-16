"""Tests for the patchelf helper (command generation + detection, no patchelf run)."""
import ctfkit.patchelf as P


def test_find_ld(tmp_path):
    (tmp_path / "libc.so.6").write_bytes(b"\x7fELF")
    (tmp_path / "ld-2.31.so").write_bytes(b"\x7fELF")
    assert P.find_ld(str(tmp_path)).endswith("ld-2.31.so")


def test_find_ld_linux_name(tmp_path):
    (tmp_path / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF")
    assert P.find_ld(str(tmp_path)).endswith("ld-linux-x86-64.so.2")


def test_find_ld_none(tmp_path):
    (tmp_path / "libc.so.6").write_bytes(b"\x7fELF")
    assert P.find_ld(str(tmp_path)) is None


def test_libc_version(tmp_path):
    f = tmp_path / "libc.so.6"
    f.write_bytes(b"xx GNU C Library (Ubuntu GLIBC) stable release version 2.31. yy")
    assert P.libc_version(str(f)) == "2.31"


def test_libc_version_unknown(tmp_path):
    f = tmp_path / "libc.so.6"
    f.write_bytes(b"no version string here")
    assert P.libc_version(str(f)) is None


def test_build_commands():
    cmds = P.build_commands("chall", "libc.so.6", "ld-2.31.so", "chall.patched")
    assert cmds[0].startswith("cp ")
    assert any("--set-interpreter" in c for c in cmds)
    assert any("--replace-needed libc.so.6" in c for c in cmds)


def test_build_commands_no_ld():
    cmds = P.build_commands("chall", "libc.so.6", None, "chall.patched")
    assert not any("--set-interpreter" in c for c in cmds)
    assert any("--replace-needed" in c for c in cmds)


def test_cmd_prints_commands(tmp_path, capsys):
    (tmp_path / "chall").write_bytes(b"\x7fELF")
    (tmp_path / "libc.so.6").write_bytes(
        b"stable release version 2.31. padding")
    (tmp_path / "ld-2.31.so").write_bytes(b"\x7fELF")
    P.cmd_patchelf(str(tmp_path / "chall"), str(tmp_path / "libc.so.6"))
    out = capsys.readouterr().out
    assert "--set-interpreter" in out and "--replace-needed" in out
    assert "glibc 2.31" in out


def test_cmd_missing_libc(tmp_path, capsys):
    (tmp_path / "chall").write_bytes(b"\x7fELF")
    P.cmd_patchelf(str(tmp_path / "chall"), str(tmp_path / "nope.so"))
    assert "existing libc" in capsys.readouterr().out
