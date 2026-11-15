"""Tests for the dependency-free MiniELF parser and binary loading."""
import pytest

from ctfkit.elf import MiniELF, load_binary


def test_minielf_amd64_exec(make_elf):
    e = MiniELF(make_elf())
    assert e.bits == 64
    assert e.arch == "amd64"
    assert e.endian == "little"
    assert e.pie is False          # ET_EXEC


def test_minielf_pie(make_elf):
    assert MiniELF(make_elf(e_type=3)).pie is True   # ET_DYN


def test_minielf_i386(make_elf):
    e = MiniELF(make_elf(machine=0x03, bits64=False))
    assert e.bits == 32
    assert e.arch == "i386"


def test_minielf_unknown_machine(make_elf):
    e = MiniELF(make_elf(machine=0x1234))
    assert e.arch == "0x1234"


def test_minielf_rejects_non_elf(tmp_path):
    p = tmp_path / "notelf"
    p.write_bytes(b"MZ\x00\x00 this is not an elf at all")
    with pytest.raises(ValueError):
        MiniELF(str(p))


def test_load_binary_rejects_non_elf(tmp_path):
    p = tmp_path / "x"
    p.write_bytes(b"hello world")
    with pytest.raises(ValueError):
        load_binary(str(p))


def test_load_binary_returns_mini(fake_elf):
    pelf, mini = load_binary(fake_elf)
    # pwntools may or may not be installed; mini is always present.
    assert mini is not None
    assert mini.arch == "amd64"
