"""Shared pytest fixtures: craft minimal ELF files without external tools."""
import struct

import pytest


def _write_elf(path, e_type=2, machine=0x3E, bits64=True, extra=b""):
    """Write a structurally valid ELF header (+ optional trailing bytes)."""
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2 if bits64 else 1          # EI_CLASS
    hdr[5] = 1                           # EI_DATA = little-endian
    hdr[6] = 1                           # EI_VERSION
    struct.pack_into("<H", hdr, 16, e_type)     # e_type (2=EXEC, 3=DYN)
    struct.pack_into("<H", hdr, 18, machine)    # e_machine (0x3E=amd64)
    path.write_bytes(bytes(hdr) + extra)
    return str(path)


@pytest.fixture
def make_elf(tmp_path):
    """Factory: make_elf(name=..., e_type=..., machine=..., extra=b'...')."""
    def _make(name="chall", e_type=2, machine=0x3E, bits64=True, extra=b""):
        return _write_elf(tmp_path / name, e_type=e_type, machine=machine,
                          bits64=bits64, extra=extra)
    return _make


@pytest.fixture
def fake_elf(make_elf):
    """A 64-bit EXEC with a few juicy strings/symbols baked in."""
    return make_elf(extra=b"\x00gets\x00puts\x00/bin/sh\x00give_shell\x00%s%n\x00")
