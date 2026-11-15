"""Tests for libc identification by leak (parsing, matching, online + offline).

The network call is mocked, so these tests never touch libc.rip.
"""
import json
import urllib.error

import pytest

import ctfkit.libcid as L


# --- leak parsing ------------------------------------------------------------
def test_parse_leaks_hex_with_and_without_prefix():
    leaks = L.parse_leaks(["puts=0x7f3b2c0a4340", "system=50d70"])
    assert leaks == {"puts": 0x7F3B2C0A4340, "system": 0x50D70}


def test_parse_leaks_rejects_no_equals():
    with pytest.raises(ValueError):
        L.parse_leaks(["puts0x1234"])


def test_parse_leaks_rejects_non_hex():
    with pytest.raises(ValueError):
        L.parse_leaks(["puts=hello"])


def test_parse_leaks_requires_at_least_one():
    with pytest.raises(ValueError):
        L.parse_leaks([])


# --- low-level math ----------------------------------------------------------
def test_low12():
    assert L.low12(0x7F3B2C0A4340) == 0x340


def test_symbol_matches():
    leaks = {"puts": 0x7F0000068340}
    assert L.symbol_matches(leaks, {"puts": 0x68340, "system": 0x50D70}) is True
    assert L.symbol_matches(leaks, {"puts": 0x68341}) is False   # low12 differs
    assert L.symbol_matches(leaks, {"printf": 0x60340}) is False  # symbol absent


def test_resolve_computes_base_and_absolutes():
    leaks = {"puts": 0x7F0000068340}
    base, resolved = L.resolve(leaks, {"puts": 0x68340, "system": 0x50D70})
    assert base == 0x7F0000000000
    assert resolved["system"] == 0x7F0000050D70


def test_resolve_no_matching_symbol():
    base, resolved = L.resolve({"puts": 0x1340}, {"system": 0x50D70})
    assert base is None
    assert resolved == {}


# --- online (libc.rip) with mocked network -----------------------------------
class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_query_libc_rip_parses_matches(monkeypatch):
    payload = json.dumps([
        {"id": "libc6_2.31-0ubuntu9.9_amd64",
         "symbols": {"puts": "0x84340", "system": "0x50d60"},
         "download_url": "https://libc.rip/download/x"},
    ]).encode()
    monkeypatch.setattr(L.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(payload))
    matches, err = L.query_libc_rip({"puts": 0x7F0000084340})
    assert err is None
    assert matches[0]["id"].startswith("libc6_2.31")


def test_query_libc_rip_handles_no_network(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(L.urllib.request, "urlopen", boom)
    matches, err = L.query_libc_rip({"puts": 0x1})
    assert matches is None
    assert "network" in err or "unreachable" in err


def test_match_symbols_to_ints():
    out = L._match_symbols_to_ints({"system": "0x50d60", "bad": None})
    assert out == {"system": 0x50D60}


# --- offline (folder of libc files) ------------------------------------------
def test_local_candidates(tmp_path, monkeypatch):
    good = tmp_path / "libc-good.so"
    bad = tmp_path / "libc-bad.so"
    good.write_bytes(b"\x7fELF")
    bad.write_bytes(b"\x7fELF")

    def fake_syms(path):
        if path.endswith("libc-good.so"):
            return {"puts": 0x68340, "system": 0x50D70}
        return {"puts": 0x68111, "system": 0x50D70}      # low12 won't match

    monkeypatch.setattr(L, "_libc_symbols", fake_syms)
    cands = L.local_candidates(str(tmp_path), {"puts": 0x7F0000068340})
    assert [name for name, _ in cands] == ["libc-good.so"]
