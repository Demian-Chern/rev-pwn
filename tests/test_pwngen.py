"""Tests for the exploit-skeleton generator.

Every generated skeleton must be syntactically valid Python and must never
reference a symbol it did not also define (the main footgun when branches and
auto-filled symbols are chosen independently).
"""
import pytest

import ctfkit.pwngen as pg


def _sec(**over):
    base = {"canary": False, "nx": True, "pie": False, "relro": "Partial",
            "arch": "amd64", "bits": 64}
    base.update(over)
    return base


class FakePELF:
    """Minimal stand-in exposing plt/got like pwntools' ELF."""
    def __init__(self, names):
        self.plt = {n: 0x401000 + i * 16 for i, n in enumerate(names)}
        self.got = {n: 0x404000 + i * 8 for i, n in enumerate(names)}


def _build(sec, hits, wins, pelf=None, libc=None, onegadgets=None):
    symbols, meta = pg.gen_symbols_block(pelf, {}, wins, hits, sec,
                                         libc_path=libc, onegadgets=onegadgets)
    body = pg.gen_body(sec, hits, wins, meta)
    script = pg.EXPLOIT_TEMPLATE.format(
        binname="x", binpath="x", outname="x.py", vulnhint="t", host="h", port=0,
        relro=sec["relro"], canary=sec["canary"], nx=sec["nx"], pie=sec["pie"],
        offset_block=pg.gen_offset_block(sec), symbols_block=symbols, body=body)
    return script, meta


@pytest.mark.parametrize("hits,wins,pelf_names,pie,canary", [
    (["gets"], [("give_shell", 0x401234)], [], False, False),   # ret2win
    (["read", "system"], [], ["system"], False, False),          # ret2system
    (["gets", "puts"], [], ["puts"], False, False),              # ret2libc leak
    (["printf"], [], ["printf"], True, True),                    # format string
    (["malloc", "free"], [], [], True, True),                    # heap
    (["read", "puts"], [], ["puts"], True, True),                # PIE + leak
    ([], [], [], True, True),                                    # nothing found
])
def test_every_branch_compiles(hits, wins, pelf_names, pie, canary):
    sec = _sec(pie=pie, canary=canary)
    pelf = FakePELF(pelf_names) if pelf_names else None
    script, _ = _build(sec, hits, wins, pelf=pelf)
    compile(script, "<gen>", "exec")      # raises SyntaxError on any dangling name


def test_offset_block_bakes_value():
    for canary in (False, True):
        blk = pg.gen_offset_block(_sec(canary=canary), offset=200)
        assert "OFFSET = 200" in blk


def test_offset_block_todo_when_unknown():
    assert "OFFSET = 0" in pg.gen_offset_block(_sec())


def test_libc_and_onegadgets_embedded():
    gad = [{"offset": 0xe3afe, "constraints": ["rax == NULL"]},
           {"offset": 0xe3b01, "constraints": []}]
    script, meta = _build(_sec(), ["gets", "puts"], [], pelf=FakePELF(["puts"]),
                          libc="libc.so.6", onegadgets=gad)
    assert 'libc = ELF("libc.so.6"' in script
    assert "ONE_GADGETS = [0xe3afe, 0xe3b01]" in script
    assert meta["onegadget"] is True
    compile(script, "<gen>", "exec")


def test_libc_without_onegadget_has_no_dangling_ref():
    script, meta = _build(_sec(), ["gets"], [], libc="libc.so.6", onegadgets=None)
    assert 'libc = ELF("libc.so.6"' in script
    assert "ONE_GADGETS" not in script          # must not reference the undefined list
    assert meta["onegadget"] is False
    compile(script, "<gen>", "exec")


def test_generate_exploit_writes_valid_file(tmp_path, fake_elf):
    out = tmp_path / "exp.py"
    pg.generate_exploit(fake_elf, str(out), "h", 0)   # no pwntools/gdb needed
    compile(out.read_text(), str(out), "exec")


def test_short_vulnhint():
    assert pg.short_vulnhint(_sec(), {"gets"}, []) == "stack BOF (gets)"
    assert pg.short_vulnhint(_sec(), {"malloc", "free"}, []) == "heap"
