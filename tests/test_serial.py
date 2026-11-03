"""Serial terminal: page and vendored assets, the event stream (scrollback then live), the token
gate, control-only input, amt_sol sharing the live session, recording, scrollback trimming, the
shared HTTP server's lifetime and the confirmed gate. No network to AMT: the SOL session is a
fake; the viewer HTTP server is real (loopback, a free port)."""
import asyncio
import base64
import http.client
import json
import threading
import time
import urllib.error
import urllib.request

import pytest

import amt_mirror
import amt_redir
import amt_serial
import amt_server
import amt_tools
import amt_vault
import amt_write


class FakeSol:
    instances: list["FakeSol"] = []

    def __init__(self, *a, **k):
        self.rx = bytearray()
        self.last_keepalive = time.time()
        self.sent: list[bytes] = []
        self.frames: list[bytes] = []
        self.pending = bytearray()
        self.lock = threading.Lock()
        self.opened = self.closed = False
        self.in_pump = False
        self.overlap = False
        self.echo = True
        FakeSol.instances.append(self)

    def open_session(self, timeout=None):
        self.opened = True

    def seq(self):
        return b"\x00\x00\x00\x00"

    def send(self, data):
        self.frames.append(bytes(data))

    def pump_once(self, deadline):
        self.in_pump = True
        time.sleep(0.002)
        with self.lock:
            self.rx += self.pending
            self.pending.clear()
        self.in_pump = False
        return 0

    def send_text(self, data):
        if self.in_pump:
            self.overlap = True
        self.sent.append(bytes(data))
        if self.echo:
            self.host_prints(data)

    def host_prints(self, data: bytes):
        with self.lock:
            self.pending += data

    def close(self):
        self.closed = True


@pytest.fixture
def fake(monkeypatch, tmp_path):
    FakeSol.instances = []
    monkeypatch.setattr(amt_redir, "pinned", lambda cls, dev, pw: FakeSol())
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: "pw")
    monkeypatch.setattr(amt_mirror, "recording_dir", lambda: tmp_path / "rec")
    yield
    for key in list(amt_serial._TERMS):
        amt_serial.stop(key)
    for key in list(amt_mirror._MIRRORS):
        amt_mirror.stop(key)


def _wait(pred, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(0.02)
    raise AssertionError("condition not reached")


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.headers.get("Content-Type"), r.read()


def _post(url, body: bytes = b""):
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read()


def _start(**kw):
    out = amt_serial.start(port=0, **kw)
    return out, amt_serial._TERMS["my-server-1"], FakeSol.instances[-1]


def _events(url, want: bytes, timeout=5, last_id=None):
    """Read the event stream until the decoded output holds ``want``; returns (text, events)."""
    headers = {"Last-Event-ID": str(last_id)} if last_id is not None else {}
    req = urllib.request.Request(url + "events", headers=headers)
    got, events = b"", []
    end = time.time() + timeout
    with urllib.request.urlopen(req, timeout=timeout) as r:
        assert r.headers.get("Content-Type") == "text/event-stream"
        buf = b""
        while want not in got and time.time() < end:
            buf += r.read1(65536)
            while b"\n\n" in buf:
                block, buf = buf.split(b"\n\n", 1)
                fields = dict(line.split(": ", 1) for line in block.decode().splitlines()
                              if ": " in line and not line.startswith(":"))
                if fields.get("event") == "out":
                    msg = json.loads(fields["data"])
                    events.append({"id": int(fields["id"]), **msg})
                    got += base64.b64decode(msg["d"])
    return got, events


def test_page_assets_and_status_are_served_with_the_token(fake):
    out, term, sol = _start()
    url = out["urls"][0]
    assert url.startswith("http://127.0.0.1:") and f"/s/{term.token}/" in url
    code, ctype, body = _get(url)
    assert code == 200 and "text/html" in ctype and b"my-server-1" in body and b"const CONTROL=false" in body
    for name, marker in (("xterm.js", b"Terminal"), ("addon-fit.js", b"FitAddon"), ("xterm.css", b".xterm")):
        code, ctype, body = _get(url + name)
        assert code == 200 and marker in body, name
    _, _, body = _get(url + "status.json")
    assert json.loads(body)["live"] is True
    _, _, body = _get(out["control_urls"][0])
    assert b"const CONTROL=true" in body


def test_a_wrong_or_missing_token_serves_nothing(fake):
    out, term, sol = _start()
    base = out["urls"][0].split("/s/")[0]
    for path in ("/s/not-a-token/", "/s/", "/s/not-a-token/events", "/s/not-a-token/xterm.js"):
        with pytest.raises(urllib.error.HTTPError) as e:
            _get(base + path)
        assert e.value.code == 404, path
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(out["urls"][0] + "../../etc/passwd")
    assert e.value.code == 404


def test_the_stream_sends_scrollback_then_live_output(fake):
    out, term, sol = _start()
    sol.host_prints(b"my-server-1 login: ")
    _wait(lambda: term.total >= 19)
    got, events = _events(out["urls"][0], b"login: ")
    assert got == b"my-server-1 login: "
    threading.Timer(0.2, lambda: sol.host_prints(b"\r\nLast login")).start()
    got, events = _events(out["urls"][0], b"Last login")
    assert got == b"my-server-1 login: \r\nLast login"
    assert events[-1]["id"] == term.total


def test_a_reconnect_resumes_from_last_event_id(fake):
    out, term, sol = _start()
    sol.host_prints(b"first ")
    _wait(lambda: term.total == 6)
    sol.host_prints(b"second")
    _wait(lambda: term.total == 12)
    got, _ = _events(out["urls"][0], b"second", last_id=6)
    assert got == b"second"


def test_only_the_control_token_can_type(fake):
    out, term, sol = _start()
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(out["urls"][0] + "input", json.dumps({"data": "ls\r"}).encode())
    assert e.value.code == 404 and sol.sent == []
    code, body = _post(out["control_urls"][0] + "input", json.dumps({"data": "ls\r"}).encode())
    assert code == 200 and json.loads(body) == {"sent": 3} and sol.sent == [b"ls\r"]
    assert term.sent == 3


@pytest.mark.parametrize("body,code", [(b"not json", 400), (b'{"data": ""}', 400), (b'{"keys": "x"}', 400),
                                       (json.dumps({"data": "x" * 4097}).encode(), 413)])
def test_bad_input_is_refused_with_nothing_sent(fake, body, code):
    out, term, sol = _start()
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(out["control_urls"][0] + "input", body)
    assert e.value.code == code and sol.sent == []


def test_input_never_overlaps_a_socket_read(fake):
    out, term, sol = _start()
    for _ in range(40):
        term.send(b"x")
    assert len(sol.sent) == 40 and sol.overlap is False


def test_amt_sol_shares_the_live_terminal_and_opens_no_session(fake):
    out, term, sol = _start()
    assert len(FakeSol.instances) == 1
    result = amt_write.sol("whoami\n", read_seconds=0.5, max_bytes=4096, confirmed=True)
    assert len(FakeSol.instances) == 1, "amt_sol opened a second SOL session"
    assert result["shared_terminal"] is True and result["output"] == "whoami\n"
    assert sol.sent == [b"whoami\n"]


def test_amt_sol_opens_its_own_session_when_no_terminal_is_live(fake):
    calls = []

    class Own(FakeSol):
        def read_window(self, seconds, max_bytes):
            calls.append("read")
            return b"out", False

    amt_redir.pinned = lambda cls, dev, pw: Own()
    result = amt_write.sol("", read_seconds=0.1, confirmed=True)
    assert calls == ["read"] and "shared_terminal" not in result and FakeSol.instances[-1].closed


def test_scrollback_is_bounded_and_a_late_viewer_is_told_of_the_gap(fake, monkeypatch):
    monkeypatch.setattr(amt_serial, "SCROLLBACK_BYTES", 32)
    out, term, sol = _start()
    sol.host_prints(b"A" * 40 + b"tail")
    _wait(lambda: term.total == 44)
    assert len(term.buf) == 32 and term.base == 12
    got, events = _events(out["urls"][0], b"tail")
    assert events[0]["gap"] is True and got.endswith(b"tail") and len(got) == 32


def test_recording_writes_an_asciinema_cast(fake, tmp_path):
    out, term, sol = _start()
    code, body = _post(out["urls"][0] + "record?on=1")
    rec = json.loads(body)
    assert code == 200 and rec["path"].endswith(".cast")
    sol.host_prints("héllo\r\n".encode())
    _wait(lambda: term.total >= 8)
    time.sleep(0.05)
    _, body = _post(out["urls"][0] + "record")
    done = json.loads(body)
    assert done["ended"] is True
    lines = open(done["path"], encoding="utf-8").read().splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2 and header["width"] and header["height"]
    events = [json.loads(line) for line in lines[1:]]
    assert "".join(e[2] for e in events) == "héllo\r\n" and all(e[1] == "o" for e in events)


def test_stop_releases_the_session_and_the_server_stays_up_for_the_mirror_only_while_needed(fake):
    out, term, sol = _start()
    url = out["urls"][0]
    assert amt_mirror._SERVER.get("httpd") is not None
    done = amt_serial.stop("my-server-1")
    assert done["stopped"] is True and done["session_released"] is True and sol.closed
    assert amt_mirror._SERVER.get("httpd") is None
    with pytest.raises(urllib.error.URLError):
        _get(url)
    assert amt_serial.stop("my-server-1")["stopped"] is False


def test_a_dead_session_ends_the_stream_and_status_reports_it(fake):
    out, term, sol = _start()

    def boom(deadline):
        raise amt_tools.amt_kvm.AmtError("redir_socket_closed_by_amt")

    sol.pump_once = boom
    _wait(lambda: not term.alive())
    assert term.error == "AmtError:redir_socket_closed_by_amt" and sol.closed
    with urllib.request.urlopen(out["urls"][0] + "events", timeout=5) as r:
        assert b"event: end" in r.read()
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(out["control_urls"][0] + "input", b'{"data": "x"}')
    assert e.value.code == 409


def test_start_twice_returns_the_existing_terminal(fake):
    out, term, sol = _start()
    again = amt_serial.start(port=0)
    assert again["note"].startswith("already live") and len(FakeSol.instances) == 1


def test_the_tool_needs_confirmed_for_start_and_record_start(fake):
    with pytest.raises(Exception) as e:
        asyncio.run(amt_serial.amt_serial_link(action="start", port=0))
    assert "confirmed" in str(e.value).lower() and FakeSol.instances == []
    with pytest.raises(Exception):
        asyncio.run(amt_serial.amt_serial_link(action="record_start"))
    out = asyncio.run(amt_serial.amt_serial_link(action="start", port=0, confirmed=True))
    assert out["live"] is True
    assert asyncio.run(amt_serial.amt_serial_link(action="status"))["terminals"][0]["device"] == "my-server-1"
    assert asyncio.run(amt_serial.amt_serial_link(action="stop"))["stopped"] is True


def test_mirror_and_terminal_share_one_server(fake, monkeypatch):
    import test_mirror
    monkeypatch.setattr(amt_tools, "_pinned_kvm_session", lambda dev, pw: test_mirror.FakeSession())
    m = amt_mirror.start(port=0, fps=10)
    t = amt_serial.start(port=0)
    port = amt_mirror._SERVER["port"]
    assert f":{port}/m/" in m["urls"][0] and f":{port}/s/" in t["urls"][0]
    amt_mirror.stop("my-server-1")
    assert amt_mirror._SERVER.get("httpd") is not None, "stopping the mirror took the terminal's server down"
    assert _get(t["urls"][0])[0] == 200


# --- review fixes (adversarial review 2026-10-19) ------------------------------------------

def test_the_reader_sends_amts_keepalive_while_idle(fake, monkeypatch):
    monkeypatch.setattr(amt_redir, "SOL_KEEPALIVE_SECONDS", 0.05)
    out, term, sol = _start()
    _wait(lambda: sum(1 for f in sol.frames if f[:1] == b"\x2b") >= 2)


def test_a_recording_write_error_drops_the_recording_and_keeps_the_console(fake):
    out, term, sol = _start()
    term.record_start(amt_mirror.recording_dir())

    class Broken:
        def write(self, s):
            raise OSError(28, "No space left on device")

        def flush(self):
            pass

        def close(self):
            pass

    term.recording["fh"] = Broken()
    sol.host_prints(b"still here")
    _wait(lambda: term.total == 10)
    _wait(lambda: term.recording is None)
    assert term.alive() and not sol.closed
    assert "No space left" in term.last_recording["error"]


def test_a_split_utf8_character_is_recorded_whole(fake):
    out, term, sol = _start()
    path = term.record_start(amt_mirror.recording_dir())["path"]
    raw = "é→".encode()
    sol.host_prints(raw[:1])
    _wait(lambda: term.total == 1)
    sol.host_prints(raw[1:])
    _wait(lambda: term.total == len(raw))
    term.record_stop()
    events = [json.loads(line) for line in open(path, encoding="utf-8").read().splitlines()[1:]]
    assert "".join(e[2] for e in events) == "é→" and "�" not in "".join(e[2] for e in events)


def test_a_dead_terminal_is_not_shared_and_amt_sol_opens_its_own_session(fake):
    out, term, sol = _start()
    term.stop.set()
    term.thread.join(timeout=5)
    assert amt_serial.shared_terminal("my-server-1") is None
    assert amt_serial.live() is False, "a dead terminal kept the viewer server up"


def test_collect_reports_a_terminal_that_died_mid_window(fake):
    out, term, sol = _start()
    threading.Timer(0.2, term.stop.set).start()
    data, truncated, error = term.collect(term.total, 3.0, 4096)
    assert error == "terminal_ended_during_read"


def test_a_failed_record_on_start_releases_the_session(fake, monkeypatch, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setattr(amt_mirror, "recording_dir", lambda: blocker / "sub")
    with pytest.raises(OSError):
        amt_serial.start(port=0, record=True)
    assert "my-server-1" not in amt_serial._TERMS and FakeSol.instances[-1].closed


def test_two_recordings_in_one_second_get_distinct_files(fake):
    out, term, sol = _start()
    a = term.record_start(amt_mirror.recording_dir())["path"]
    term.record_stop()
    b = term.record_start(amt_mirror.recording_dir())["path"]
    term.record_stop()
    assert a != b


@pytest.mark.parametrize("body", [b'{"data": 5}', b"[]", b"[" * 5000 + b"]" * 5000])
def test_wrongly_shaped_input_is_refused(fake, body):
    out, term, sol = _start()
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(out["control_urls"][0] + "input", body)
    assert e.value.code == 400 and sol.sent == []


def test_a_different_port_while_a_terminal_is_live_is_refused_not_torn_down(fake, monkeypatch):
    import test_mirror
    monkeypatch.setattr(amt_tools, "_pinned_kvm_session", lambda dev, pw: test_mirror.FakeSession())
    out, term, sol = _start()
    with pytest.raises(ValueError, match="viewer_server_in_use"):
        amt_mirror.start(port=1, fps=10)
    assert _get(out["urls"][0])[0] == 200


def test_a_stopped_cast_is_offered_once_over_http(fake, monkeypatch):
    import amt_handoff
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, "https://nas.example.com:8443")
    out, term, sol = _start()
    path = term.record_start(amt_mirror.recording_dir())["path"]
    sol.host_prints(b"login: ")
    _wait(lambda: term.total == 7)
    stopped = term.record_stop()
    assert stopped["url"].startswith("https://nas.example.com:8443/handoffs/")
    import hashlib
    assert stopped["sha256"] == hashlib.sha256(open(path, "rb").read()).hexdigest()


# --- serial console logon / logoff (amt_remote_logon / amt_remote_logoff console="serial") ----

SERIAL_PW = "Serial-pw-Sentinel-7"


class Getty:
    """A scripted Debian serial getty on a FakeSol: echoes the account name, never the password,
    answers a right password with a shell prompt and a wrong one with Login incorrect."""

    def __init__(self, sol, state="login", greet=True):
        self.sol, self.state, self.inputs = sol, state, []
        sol.echo = False
        orig = sol.send_text

        def send_text(data):
            orig(data)
            self.on(bytes(data).decode())
        sol.send_text = send_text
        if greet:
            sol.host_prints({"login": b"\r\nmy-server-1 login: ", "password": b"\r\nPassword: ",
                             "shell": b"\r\nuser@my-server-1:~$ "}[state])

    def on(self, s):
        self.inputs.append(s)
        if self.state == "login":
            out = "\r\nmy-server-1 login: " if s == "\r" else s.replace("\r", "\r\n") + "Password: "
            self.state = "login" if s == "\r" else "password"
        elif self.state == "password":
            ok = s == SERIAL_PW + "\r"
            self.state = "shell" if ok else "login"
            out = ("\r\nLinux my-server-1\r\n\x1b[?2004huser@my-server-1:~$ " if ok
                   else "\r\n\r\nLogin incorrect\r\nmy-server-1 login: ")
        else:
            self.state = "login" if s == "exit\r" else "shell"
            out = ("exit\r\nlogout\r\n\x1b[!p\x1b]104\x07\r\nDebian GNU/Linux 13 my-server-1 ttyS0\r\n\r\nmy-server-1 login: "
                   if s == "exit\r" else "\r\nuser@my-server-1:~$ ")
        self.sol.host_prints(out.encode())


@pytest.fixture
def serial_host(fake, monkeypatch):
    monkeypatch.setattr(amt_serial, "SERIAL_READ_SECONDS", 0.15)
    monkeypatch.setattr(amt_tools, "_power_state", lambda device, pw: amt_tools.POWER_ON)
    monkeypatch.setattr(amt_tools, "_host_credential", lambda dev: ("jdoe", SERIAL_PW))


def _logon(**kw):
    return asyncio.run(amt_tools.amt_remote_logon(confirmed=True, console="serial", **kw))


def _logoff(**kw):
    return asyncio.run(amt_tools.amt_remote_logoff(confirmed=True, console="serial", **kw))


def test_serial_logon_then_logoff_through_the_live_terminal(serial_host):
    out, term, sol = _start()
    getty = Getty(sol)
    _wait(lambda: term.total > 0)
    res = _logon()
    assert res["logged_in"] is True and res["aborted"] is False and res["login_incorrect"] is False
    assert res["shared_terminal"] is True and res["enter_sent_to_find_prompt"] is False
    assert getty.inputs == ["jdoe\r", SERIAL_PW + "\r"], "account once, password once, nothing else"
    assert SERIAL_PW not in json.dumps(res)
    off = _logoff()
    assert off["logged_off"] is True and getty.inputs[-1] == "exit\r"


def test_serial_logon_never_answers_a_password_prompt_it_did_not_ask_for(serial_host):
    out, term, sol = _start()
    getty = Getty(sol, state="password")
    _wait(lambda: term.total > 0)
    res = _logon()
    assert res["aborted"] is True and res["reason"] == "console_not_at_login_prompt"
    assert res["typed_nothing"] is True and getty.inputs == []


def test_a_wrong_password_is_reported_once_and_never_retried(serial_host, monkeypatch):
    monkeypatch.setattr(amt_tools, "_host_credential", lambda dev: ("jdoe", "wrong-one"))
    out, term, sol = _start()
    getty = Getty(sol)
    _wait(lambda: term.total > 0)
    res = _logon()
    assert res["logged_in"] is False and res["login_incorrect"] is True
    assert getty.inputs == ["jdoe\r", "wrong-one\r"]
    assert "wrong-one" not in json.dumps(res)


def test_serial_logoff_refuses_anything_but_a_shell_prompt(serial_host):
    out, term, sol = _start()
    getty = Getty(sol, state="login")
    _wait(lambda: term.total > 0)
    res = _logoff()
    assert res["aborted"] is True and res["reason"] == "console_not_at_shell_prompt" and getty.inputs == []


def test_already_at_a_shell_is_the_no_op_success(serial_host):
    out, term, sol = _start()
    getty = Getty(sol, state="shell")
    _wait(lambda: term.total > 0)
    res = _logon()
    assert res["already_logged_in"] is True and res["typed_nothing"] is True and getty.inputs == []


def test_without_a_terminal_it_opens_its_own_session_and_sends_one_enter_to_find_the_prompt(serial_host, monkeypatch):
    made = []

    def pinned(cls, dev, pw):
        sol = FakeSol()

        def read_window(seconds, max_bytes):
            time.sleep(seconds)
            with sol.lock:
                data, sol.pending[:] = bytes(sol.pending), b""
            return data, False
        sol.read_window = read_window
        made.append(Getty(sol, greet=False))
        return sol
    monkeypatch.setattr(amt_redir, "pinned", pinned)
    res = _logon()
    assert res["logged_in"] is True and res["shared_terminal"] is False
    assert res["enter_sent_to_find_prompt"] is True
    (getty,) = made
    assert getty.inputs == ["\r", "jdoe\r", SERIAL_PW + "\r"]
    assert FakeSol.instances[-1].closed is True


def test_the_password_waits_for_a_password_prompt(serial_host):
    """A getty that never asks for the password (here: it just prints another login prompt)
    never receives it."""
    out, term, sol = _start()
    getty = Getty(sol)
    getty.on = lambda s: (getty.inputs.append(s), sol.host_prints(b"\r\nmy-server-1 login: "))
    _wait(lambda: term.total > 0)
    res = _logon()
    assert res["aborted"] is True and res["reason"] == "password_prompt_not_identified"
    assert res["account_typed"] is True and res["password_typed"] is False
    assert getty.inputs == ["jdoe\r"]


# --- embed mode, viewer headers and the in-flight call -----------------------------------------

@pytest.mark.parametrize("which", ["urls", "control_urls"])
def test_embed_serves_capture_view_and_control_only(fake, which):
    out, _, _ = _start()
    plain = _get(out[which][0])[2].decode()
    embed = _get(out[which][0] + "?embed=1")[2].decode()
    for marker in ("id=dl", "Download .txt", "dl.onclick", "Download .txt saves a copy"):
        assert marker in plain, marker
        assert marker not in embed, marker
    for marker in ("id=fontm", "id=fontp", "id=copy", "id=clr", "id=cgrp", "id=ctl", "fetch('input'",
                   "the terminal keeps what it printed."):
        assert marker in embed, marker
    for marker in ("id=rec", "id=rect", "rec.onclick", "fetch('record'"):      # Record is a tool action, offered from the console's chrome
        assert marker in plain, marker
    for marker in ("id=rec", "id=rect", "rec.onclick", "rec.classList", "fetch('record", "lbl>Capture"):
        assert marker not in embed, marker
    assert "standalone" not in plain + embed and "<!--" not in plain + embed


@pytest.mark.parametrize("which", ["urls", "control_urls"])
@pytest.mark.parametrize("query", ["?embed=1&on=1", "?on=1&embed=1", "?x=1&embed=1&on=1", "?embed=1"])
def test_an_embed_request_cannot_start_or_stop_a_recording(fake, tmp_path, which, query):
    """Recording is a tool action (record_start needs confirmed): the embedded viewer has no Record button and the route refuses it."""
    out, term, _ = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out[which][0] + "record" + query)
    assert ex.value.code == 403 and b"embed_mode" in ex.value.read()
    assert term.recording is None and term.last_recording is None
    term.record_start(amt_mirror.recording_dir())    # a recording the tool started cannot be stopped from an embedded viewer either
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out[which][0] + "record?embed=1")
    assert ex.value.code == 403 and term.recording is not None
    term.record_stop()


def test_the_slash_redirect_keeps_the_embed_query(fake):
    out, term, _ = _start()
    conn = http.client.HTTPConnection(out["urls"][0].split("/")[2], timeout=5)
    conn.request("GET", f"/s/{term.control_token}?embed=1")
    res = conn.getresponse()
    assert res.status == 301 and res.getheader("Location") == f"/s/{term.control_token}/?embed=1"
    conn.close()


def _headers(url):
    conn = http.client.HTTPConnection(url.split("/")[2], timeout=5)
    conn.request("GET", "/" + url.split("/", 3)[3])
    res = conn.getresponse()
    out = (res.status, {k.lower(): v for k, v in res.getheaders()})
    conn.close()
    return out


def test_every_serial_response_sends_no_referrer_and_the_frame_ancestor(fake, monkeypatch):
    out, term, _ = _start()
    base = out["urls"][0]
    urls = [base, out["control_urls"][0] + "?embed=1", base + "status.json", base + "events", base + "xterm.js",
            f"{base.split('/s/')[0]}/s/{term.token}", base + "nope", base.split("/s/")[0] + "/s/wrong-token/"]
    for origin, want in ((None, "frame-ancestors 'none'"),
                         ("https://amt-console.example.com", "frame-ancestors https://amt-console.example.com"),
                         ("https://a.test; script-src *", "frame-ancestors 'none'")):
        if origin is None:
            monkeypatch.delenv("AMT_CONSOLE_ORIGIN", raising=False)
        else:
            monkeypatch.setenv("AMT_CONSOLE_ORIGIN", origin)
        for url in urls:
            status, headers = _headers(url)
            assert headers.get("referrer-policy") == "no-referrer", (url, status)
            assert headers.get("content-security-policy") == want, (url, status)
    assert {_headers(u)[0] for u in urls} >= {200, 301, 404}


def _in_flight(out):
    return json.loads(_get(out["urls"][0] + "status.json")[2])["in_flight"]


def test_status_names_the_tool_call_sharing_the_terminal(fake, monkeypatch):
    monkeypatch.setenv("AMT_TRANSPORT", "stdio")
    out, term, sol = _start()
    assert _in_flight(out) is None
    marker = "zz-typed-marker-zz"
    t = threading.Thread(target=lambda: asyncio.run(amt_server.mcp.call_tool(
        "amt_sol", {"text": marker, "read_seconds": 1.5, "confirmed": True})))
    t.start()
    _wait(lambda: _in_flight(out) is not None)
    flight = _in_flight(out)
    assert set(flight) == {"tool", "started_at"} and flight["tool"] == "amt_sol"
    assert marker not in _get(out["urls"][0] + "status.json")[2].decode()
    t.join(10)
    assert not t.is_alive() and _in_flight(out) is None


def test_status_names_a_serial_logon_sharing_the_terminal_until_it_closes(fake):
    out, term, sol = _start()
    dev = amt_serial.amt_registry.get_device("my-server-1")
    con = amt_serial._SerialConsole(dev, "pw")
    flight = _in_flight(out)
    assert flight["tool"] == "unknown" and isinstance(flight["started_at"], float)
    con.close()
    assert _in_flight(out) is None


def test_a_serial_console_with_its_own_session_is_not_an_in_flight_call(fake):
    dev = amt_serial.amt_registry.get_device("my-server-1")
    con = amt_serial._SerialConsole(dev, "pw")       # no terminal is live: nothing to report on
    assert con.term is None
    con.close()


def test_the_serial_tool_hands_its_event_loop_to_the_routes(fake):
    async def check():
        await amt_serial.amt_serial_link(action="status")
        assert amt_mirror._TOOL_LOOP is asyncio.get_running_loop()
    amt_mirror._TOOL_LOOP = None
    asyncio.run(check())
