"""Regression tests for the QA 1.1 web findings: client aborts, absolute-form targets, CSV guard, meta fields."""
from __future__ import annotations

import ast
import csv
import http.client
import io
import json
import logging
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore  # noqa: E402
import test_web as TW  # noqa: E402  (module import: its TestCase classes are not collected twice)
from leasewatch.collector import Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.db import Database  # noqa: E402
from leasewatch import web  # noqa: E402

MAC = "02:00:00:00:00:01"
ENV = {**FW1_ENV, "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0", "POLL_SECONDS": "120",
       "PUBLIC_URL": "http://lw.example.lan"}


class FailingWriter:
    """wfile stand-in: the first `ok` writes succeed, then every write raises `exc` (a client that went away)."""

    def __init__(self, exc: BaseException, ok: int = 0) -> None:
        self.exc, self.ok, self.data = exc, ok, []

    def write(self, b: bytes) -> int:
        if self.ok <= 0:
            raise self.exc
        self.ok -= 1
        self.data.append(bytes(b))
        return len(b)

    def flush(self) -> None:
        pass


class FailingReader:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def read(self, n: int = -1) -> bytes:
        raise self.exc


class Base(unittest.TestCase):
    env: dict = {}

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = clean_env(dict(ENV, DATA_DIR=self.tmp.name, **self.env))
        self.cfg = Config()
        self.db = Database(self.cfg.db_path)
        self.H = web.make_handler(self.cfg, self.db, "9.9.9")

    def tearDown(self) -> None:
        self.db._conn.close()
        self.tmp.cleanup()
        restore(self._saved)

    def handler(self, command: str = "GET", path: str = "/", headers: bytes = b"Host: 127.0.0.1\r\n",
                wfile: object | None = None, rfile: object | None = None) -> object:
        """A Handler without a socket: the request line and headers are set as parse_request() would."""
        h = self.H.__new__(self.H)
        h.command, h.path, h.request_version = command, path, "HTTP/1.1"
        h.requestline = f"{command} {path} HTTP/1.1"
        h.client_address = ("127.0.0.1", 40000)
        h.close_connection = False
        h.headers = http.client.parse_headers(io.BytesIO(headers + b"\r\n"))
        h.wfile = wfile if wfile is not None else io.BytesIO()
        h.rfile = rfile if rfile is not None else io.BytesIO()
        return h

    def add_device(self, **cols: object) -> None:
        self.db.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,1)", (MAC,))
        for k, v in cols.items():
            self.db.q(f"UPDATE devices SET {k}=? WHERE mac=?", (v, MAC))

    def csv_row(self) -> list[str]:
        h = self.handler(path="/api/devices.csv")
        h._csv()
        body = h.wfile.getvalue().partition(b"\r\n\r\n")[2].decode("utf-8-sig")
        return body.splitlines()

    @staticmethod
    def status(raw: bytes) -> int:
        return int(raw.split(b" ", 2)[1])


class CsvTests(Base):
    def test_R06_formula_after_semicolon_is_neutralised(self) -> None:
        # Excel with ';' as list separator (sv-SE) splits an unquoted cell there: no piece may start a formula
        self.add_device()
        self.db.update_user_fields(MAC, None, "x;=cmd|' /C calc'!A0;", None)
        line = self.csv_row()[1]
        pieces = next(csv.reader([line], delimiter=";"))
        self.assertEqual([c for c in pieces if c[:1] in ("=", "+", "-", "@")], [], line)

    def test_S28x_switch_port_is_neutralised(self) -> None:
        self.add_device(sw_port='=HYPERLINK("http://x.example.com")', sw_via="=via")
        rows = list(csv.reader(self.csv_row()))
        port = rows[1][rows[0].index("switch_port")]
        self.assertTrue(port.startswith("'"), port)


class LogTests(Base):
    def test_R97_control_characters_are_escaped_in_the_access_log(self) -> None:
        h = self.handler()
        with self.assertLogs("leasewatch.web", "DEBUG") as cm:
            h.log_message('"%s" %s %s', "GET /\x1b[2J\x1b[31mFAKE\rINFO leasewatch: forged HTTP/1.1", "400", "-")
        out = "\n".join(cm.output)
        self.assertNotIn("\x1b", out); self.assertNotIn("\r", out)
        self.assertIn("\\x1b", out)


class ClientGoneTests(Base):
    def test_R98_R106_body_write_timeout_sends_no_second_response(self) -> None:
        w = FailingWriter(TimeoutError("timed out"), ok=1)  # the header write succeeds, the body write stalls out
        h = self.handler(path="/api/events", wfile=w)
        with self.assertNoLogs("leasewatch.web", "ERROR"):
            h.do_GET()
        self.assertEqual(len(w.data), 1); self.assertTrue(w.data[0].startswith(b"HTTP/1.0 200"))
        self.assertTrue(h.close_connection)

    def test_R103_reset_during_405_is_not_raised(self) -> None:
        h = self.handler(command="PUT", wfile=FailingWriter(ConnectionResetError()))
        h._method_not_allowed()
        self.assertTrue(h.close_connection)

    def test_R104_reset_during_421_is_not_raised(self) -> None:
        h = self.handler(headers=b"Host: evil.example\r\n", wfile=FailingWriter(BrokenPipeError()))
        h.do_GET()
        self.assertTrue(h.close_connection)

    def test_R107_R108_reset_while_reading_the_post_body_is_not_raised(self) -> None:
        h = self.handler(command="POST", path=f"/api/devices/{MAC}", rfile=FailingReader(ConnectionResetError()),
                         headers=b"Host: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n")
        h.do_POST()
        self.assertTrue(h.close_connection); self.assertEqual(h.wfile.getvalue(), b"")

    def test_R108_reset_while_writing_the_post_reply_is_not_raised(self) -> None:
        self.add_device()
        h = self.handler(command="POST", path=f"/api/devices/{MAC}", rfile=io.BytesIO(b'{"acked":true}'),
                         headers=b"Host: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 14\r\n",
                         wfile=FailingWriter(BrokenPipeError()))
        h.do_POST()
        self.assertEqual(self.db.device(MAC)["acked"], 1)

    def test_R107_reset_mid_body_over_a_real_socket_reaches_no_handle_error(self) -> None:
        errors = []

        class S(web.Server):
            def handle_error(self, request: object, client_address: object) -> None:
                errors.append(sys.exc_info()[0])

        srv = S(("127.0.0.1", 0), self.H)
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            s = socket.create_connection(srv.server_address, timeout=5)
            s.sendall(f"POST /api/devices/{MAC} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                      "Content-Length: 200\r\n\r\n{\"a\":".encode())
            time.sleep(0.3)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # RST instead of FIN
            s.close()
            time.sleep(0.5)
        finally:
            srv.shutdown(); srv.server_close(); t.join(timeout=5)
        self.assertEqual(errors, [])


class RequestTargetTests(Base):
    def test_R99_absolute_form_root_serves_the_page(self) -> None:
        for path in ("http://127.0.0.1:8080/", "http://127.0.0.1:8080/?x=1"):
            h = self.handler(path=path)
            h.do_GET()
            raw = h.wfile.getvalue()
            self.assertEqual(self.status(raw), 200, path); self.assertNotIn(b"{{VERSION}}", raw)

    def test_R100_dotted_static_index_is_404(self) -> None:
        for path in ("/static/./index.html", "/static/x/../index.html"):
            h = self.handler(path=path)
            h.do_GET()
            self.assertEqual(self.status(h.wfile.getvalue()), 404, path)

    def test_R105_malformed_absolute_target_is_400(self) -> None:
        for command in ("GET", "HEAD", "POST"):
            h = self.handler(command=command, path="http://[x/")
            getattr(h, f"do_{command}")()
            raw = h.wfile.getvalue()
            self.assertEqual(self.status(raw), 400, command); self.assertIn(b"X-Content-Type-Options: nosniff", raw)

    def test_S45x_duplicate_host_header_is_400(self) -> None:
        for hosts in (b"Host: lw.example.lan\r\nHost: evil.example\r\n", b"Host: evil.example\r\nHost: lw.example.lan\r\n"):
            h = self.handler(path="/api/status", headers=hosts)
            h.do_GET()
            self.assertEqual(self.status(h.wfile.getvalue()), 400, hosts)
        h = self.handler(path="/api/status", headers=b"Host: lw.example.lan\r\n")
        h.do_GET()
        self.assertEqual(self.status(h.wfile.getvalue()), 200)


class MetaTests(Base):
    def test_R101_future_last_poll_is_stale(self) -> None:
        self.db.set_meta("last_poll_ts", str(int(time.time()) + 86400)); self.db.set_meta("last_poll_ok", "1")
        self.assertTrue(self.handler()._meta()["stale"])
        self.db.set_meta("last_poll_ts", str(int(time.time())))
        self.assertFalse(self.handler()._meta()["stale"])


class LwConnectorsSwitchTests(Base):
    env = {"LW_CONNECTORS": "fw1,switch", "LW_CONNECTOR__FW1__TYPE": "opnsense", "LW_CONNECTOR__FW1__URL": "https://10.0.0.1",
           "LW_CONNECTOR__FW1__KEY": "kkkkk", "LW_CONNECTOR__FW1__SECRET": "sssss", "LW_CONNECTOR__SWITCH__TYPE": "snmp_switch",
           "LW_CONNECTOR__SWITCH__HOST": "10.0.0.2", "LW_CONNECTOR__SWITCH__NAME": "sw-rack", "LW_CONNECTOR__SWITCH__USER": "u",
           "LW_CONNECTOR__SWITCH__AUTH_KEY": "aaaaaaaa", "LW_CONNECTOR__SWITCH__PRIV_KEY": "pppppppp"}

    def test_R102_switch_status_is_in_connectors_only(self) -> None:
        self.db.set_meta("conn.switch.ok", "1"); self.db.set_meta("conn.switch.count", "12")
        m = self.handler()._meta()
        self.assertNotIn("switch", m); self.assertNotIn("unifi", m)
        sw = next(c for c in m["connectors"] if c["name"] == "switch")
        self.assertEqual((sw["enabled"], sw["label"], sw["ok"], sw["count"]), (True, "sw-rack", True, 12))


class TwoControllersTests(Base):
    env = {"LW_CONNECTORS": "fw1,home,office", "LW_CONNECTOR__FW1__TYPE": "opnsense", "LW_CONNECTOR__FW1__URL": "https://10.0.0.1",
           "LW_CONNECTOR__FW1__KEY": "kkkkk", "LW_CONNECTOR__FW1__SECRET": "sssss",
           **{f"LW_CONNECTOR__{n}__{k}": v for n in ("HOME", "OFFICE")
              for k, v in (("TYPE", "unifi"), ("URL", "https://10.0.0.3"), ("USER", "ro"), ("PASSWORD", "pppppp"))}}

    def test_S25x_two_controllers_get_distinct_labels(self) -> None:
        labels = [c["label"] for c in self.handler()._meta()["connectors"]]
        self.assertEqual(len(set(labels)), 3, labels)
        self.assertTrue(all("Wi-Fi" in x for x in labels[1:]), labels)


class DrawerConsistencyTests(Base):
    def test_S27x_drawer_reads_do_not_straddle_a_poll(self) -> None:
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        client = TW.FakeClient([TW.S(MAC, "10.0.0.5", "phone")])
        col = Collector(self.cfg, self.db, client)
        col.run_once()
        client.sightings_data = [TW.S(MAC, "10.0.0.6", "phone")]
        orig, poll = self.db.history, []

        def history(mac: str) -> list:
            if not poll:  # a poll that commits between db.device() and db.history()
                poll.append(threading.Thread(target=col.run_once, daemon=True))
                poll[0].start(); poll[0].join(timeout=0.5)
            return orig(mac)

        self.db.history = history
        h = self.handler(path=f"/api/devices/{MAC}")
        h.do_GET()
        poll[0].join(timeout=5)
        data = json.loads(h.wfile.getvalue().partition(b"\r\n\r\n")[2])
        self.assertEqual(data["device"]["ip"], data["history"][0]["ip"])
        self.assertEqual(self.db.device(MAC)["ip"], "10.0.0.6")


class Round2Tests(Base):
    def _csv_body(self) -> str:
        h = self.handler(path="/api/devices.csv")
        h._csv()
        return h.wfile.getvalue().partition(b"\r\n\r\n")[2].decode("utf-8-sig")

    def test_V41_V42_quote_between_semicolon_and_formula_is_neutralised(self) -> None:
        self.add_device()
        for name in ('x;"=1+1;', "x;\"=cmd|' /C calc'!A0\"", 'x; "=1+1;'):
            self.db.update_user_fields(MAC, None, name, None)
            body = self._csv_body()
            pieces = [c for row in csv.reader(io.StringIO(body, newline=""), delimiter=";") for c in row]
            self.assertEqual([c for c in pieces if c.lstrip(' "')[:1] in ("=", "+", "-", "@")], [], body)

    def test_V43_formula_after_a_newline_in_the_note_is_neutralised(self) -> None:
        self.add_device()
        for note in ("n;\n=1+1", "n\n@SUM(1)", "n\r\n=1"):
            self.db.q("UPDATE devices SET note=? WHERE mac=?", (note, MAC))
            body = self._csv_body()
            pieces = [c for row in csv.reader(io.StringIO(body, newline=""), delimiter=";") for c in row]
            self.assertEqual([c for c in pieces if c[:1] in ("=", "+", "-", "@")], [], body)

    def test_V39_backslash_is_escaped_so_real_and_typed_escapes_differ(self) -> None:
        h = self.handler()
        with self.assertLogs("leasewatch.web", "DEBUG") as cm:
            h.log_message("%s", "GET /\x1b[2J HTTP/1.1")
            h.log_message("%s", "GET /\\x1b[2J HTTP/1.1")
        self.assertNotEqual(cm.output[0], cm.output[1])

    def test_V96_V97_future_last_poll_age_is_not_negative(self) -> None:
        self.db.set_meta("last_poll_ts", str(int(time.time()) + 86400)); self.db.set_meta("last_poll_ok", "1")
        self.assertGreaterEqual(self.handler()._meta()["last_poll_age"], 86400 - 5)

    def test_V98_whitespace_before_the_colon_is_400(self) -> None:
        h = self.handler(path="/api/status", headers=b"Host : evil.example\r\n")
        h.do_GET()
        self.assertEqual(self.status(h.wfile.getvalue()), 400)

    def test_V99_absolute_form_with_empty_path_serves_the_page(self) -> None:
        for path in ("http://lw.example.lan", "http://lw.example.lan?x=1"):
            h = self.handler(path=path, headers=b"Host: lw.example.lan\r\n")
            h.do_GET()
            raw = h.wfile.getvalue()
            self.assertEqual(self.status(raw), 200, path); self.assertNotIn(b"{{VERSION}}", raw)


class OtherNameControllerTests(Base):
    env = {"LW_CONNECTORS": "fw1,home", "LW_CONNECTOR__FW1__TYPE": "opnsense", "LW_CONNECTOR__FW1__URL": "https://10.0.0.1",
           "LW_CONNECTOR__FW1__KEY": "kkkkk", "LW_CONNECTOR__FW1__SECRET": "sssss", "LW_CONNECTOR__HOME__TYPE": "unifi",
           "LW_CONNECTOR__HOME__URL": "https://10.0.0.3", "LW_CONNECTOR__HOME__USER": "ro", "LW_CONNECTOR__HOME__PASSWORD": "pppppp"}

    def test_V23_V24_controller_status_follows_its_instance(self) -> None:
        self.db.set_meta("conn.home.ok", "1")
        m = self.handler()._meta()
        self.assertNotIn("unifi", m)
        self.assertEqual([(c["name"], c["label"], c["ok"]) for c in m["connectors"] if c["type"] == "unifi"], [("home", "Wi-Fi", True)])


class TypeHintTests(unittest.TestCase):
    def test_R150_R158_every_web_function_is_annotated(self) -> None:
        with open(os.path.join(REPO, "leasewatch", "web.py"), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        missing = []
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                a = n.args
                args = [x for x in a.posonlyargs + a.args + a.kwonlyargs if x.arg != "self" and x.annotation is None]
                if n.returns is None or args or (a.vararg and a.vararg.annotation is None):
                    missing.append(n.name)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()


class Round3Tests(Base):
    def test_W15_multipart_content_type_is_not_a_malformed_header(self) -> None:
        # the email parser records body defects for a well-formed multipart type; only header-line defects mean 400
        ct = b"Host: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary=x\r\n"
        h = self.handler(path="/api/status", headers=ct)
        h.do_GET()
        self.assertEqual(self.status(h.wfile.getvalue()), 200)
        h = self.handler(command="POST", path=f"/api/devices/{MAC}", headers=ct + b"Content-Length: 2\r\n")
        h.do_POST()
        self.assertEqual(self.status(h.wfile.getvalue()), 415)

    def test_W16_crlf_before_a_formula_keeps_the_pair_together(self) -> None:
        self.add_device()
        self.db.q("UPDATE devices SET note=? WHERE mac=?", ("x\r\n=1", MAC))
        note = list(csv.reader(io.StringIO(self.csv_body(), newline="")))[1][-1]
        self.assertEqual(note, "x\r\n'=1")

    def csv_body(self) -> str:
        h = self.handler(path="/api/devices.csv")
        h._csv()
        return h.wfile.getvalue().partition(b"\r\n\r\n")[2].decode("utf-8-sig")

    def test_W26_W27_index_only_at_slash(self) -> None:
        # origin form starts with "/" and has no authority (RFC 9112 3.2.1); anything else that is not absolute form
        # names no resource
        for path in ("//evil.example/", "//x", "///", "?x=1", "#f", "\x00/", "*"):
            h = self.handler(path=path)
            h.do_GET()
            self.assertEqual(self.status(h.wfile.getvalue()), 404, repr(path))
        for path in ("/", "/?x=1", "http://127.0.0.1", "http://127.0.0.1/?x=1"):
            h = self.handler(path=path)
            h.do_GET()
            self.assertEqual(self.status(h.wfile.getvalue()), 200, path)
