"""Tests for the local web UI: ANSI->HTML, action dispatch, and the HTTP layer."""
import json
import threading
import urllib.error
import urllib.request

import ctfkit.web as web


# --- ANSI -> HTML ------------------------------------------------------------
def test_ansi_to_html_colors():
    out = web.ansi_to_html("\033[32m[+]\033[0m ok")
    assert "color:#98c379" in out
    assert "[+]" in out and "ok" in out


def test_ansi_to_html_escapes():
    out = web.ansi_to_html("a <b> & c")
    assert "<b>" not in out and "&lt;b&gt;" in out and "&amp;" in out


def test_ansi_to_html_plain():
    assert web.ansi_to_html("just text") == "just text"


# --- action dispatch ---------------------------------------------------------
def test_run_action_unknown():
    res = web.run_action({"action": "nope"})
    assert "unknown action" in res["output"]


def test_run_action_missing_binary():
    res = web.run_action({"action": "triage", "binary": ""})
    assert "no binary" in res["output"]


def test_run_action_triage(fake_elf):
    res = web.run_action({"action": "triage", "binary": fake_elf})
    assert "Target" in res["output"]          # cmd_triage prints a "== Target ==" header


def test_run_action_pwn_returns_file(tmp_path, fake_elf):
    out = tmp_path / "exp.py"
    res = web.run_action({"action": "pwn", "binary": fake_elf, "out": str(out)})
    assert res["file"] and res["file"]["name"] == str(out)
    assert "from pwn import *" in res["file"]["content"]


# --- HTTP layer --------------------------------------------------------------
def _serve():
    httpd, token = web.make_server("127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, token, port


def test_http_serves_page_with_token():
    httpd, token, port = _serve()
    try:
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read().decode()
        assert "ctfkit" in body.lower()
        assert token in body                 # token is baked into the page JS
        assert "__TOKEN__" not in body       # placeholder was replaced
    finally:
        httpd.shutdown()


def test_http_post_requires_token():
    httpd, token, port = _serve()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/run", data=b"{}",
            headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            assert False, "expected 403"
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        httpd.shutdown()


def test_http_post_with_token_runs():
    httpd, token, port = _serve()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/run",
            data=json.dumps({"action": "nope"}).encode(),
            headers={"Content-Type": "application/json", "X-CTFKit-Token": token})
        resp = urllib.request.urlopen(req, timeout=5)
        payload = json.loads(resp.read().decode())
        assert "output" in payload
    finally:
        httpd.shutdown()
