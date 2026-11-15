"""Tests for the heap menu detector and skeleton generator."""
import ctfkit.heap as H

MENU = b"\n".join([
    b"=== Heap Menu ===",
    b"1. Allocate chunk",
    b"2) Free chunk",
    b"[3] Edit note",
    b"4 - Show content",
    b"5: Exit",
    b"Your choice: ",
    b"Size: ",
    b"Index: ",
    b"Content: ",
]) + b"\x00"


def test_extract_strings():
    s = H.extract_strings(b"abcd\x00ef\x00ghij")
    assert "abcd" in s and "ghij" in s
    assert "ef" not in s                     # shorter than minlen=4


def test_detect_menu_actions():
    menu = H.detect_menu(MENU)
    assert menu["actions"] == {"alloc": 1, "free": 2, "edit": 3, "show": 4, "exit": 5}


def test_detect_menu_prompts():
    menu = H.detect_menu(MENU)
    assert menu["choice"] == "Your choice: "
    assert menu["size"] == "Size: "
    assert menu["index"] == "Index: "
    assert menu["data"] == "Content: "


def test_detect_menu_varied_formats():
    blob = b"\n".join([b"[1] new item", b"2 : release", b"3) modify entry",
                        b"4. dump all"]) + b"\x00"
    actions = H.detect_menu(blob)["actions"]
    assert actions["alloc"] == 1
    assert actions["free"] == 2
    assert actions["edit"] == 3
    assert actions["show"] == 4


def test_detect_menu_ignores_non_menu_numbers():
    # "404 Not Found" / "200 OK" must not be read as menu entries
    actions = H.detect_menu(b"404 Not Found\x00200 OK here\x00")["actions"]
    assert actions == {}


def test_gen_heap_exploit_compiles_with_menu():
    menu = H.detect_menu(MENU)
    script = H.gen_heap_exploit("chall", None, menu, host="h", port=1337)
    assert "def alloc(" in script and "def free(" in script
    assert "def edit(" in script and "def show(" in script
    assert "io.sendlineafter(CHOICE, b'1')" in script      # detected alloc number
    assert "CHOICE = b'Your choice: '" in script
    assert 'HOST = "h"' in script and "PORT = 1337" in script
    compile(script, "<heap>", "exec")


def test_gen_heap_exploit_compiles_without_menu():
    menu = H.detect_menu(b"just some text with no menu at all here")
    script = H.gen_heap_exploit("chall", None, menu)
    assert "TODO" in script                 # placeholders where detection failed
    compile(script, "<heap>", "exec")


def test_gen_heap_exploit_with_libc():
    menu = H.detect_menu(MENU)
    script = H.gen_heap_exploit("chall", None, menu, libc="libc.so.6")
    assert 'libc = ELF("libc.so.6"' in script
    compile(script, "<heap>", "exec")


def test_const_rendering():
    assert H._const("Size: ", "b': '") == "b'Size: '"
    assert "TODO" in H._const(None, "b': '")
