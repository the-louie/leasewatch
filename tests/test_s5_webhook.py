"""S5 T-06: the webhook channel (formats json, ntfy and discord), its signature, redirects, timeouts and the secret
URL. A local HTTP server on port 0 records the requests. Synthetic data only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore  # noqa: E402
from leasewatch import notify  # noqa: E402
from leasewatch.config import Config  # noqa: E402

DEV = {"mac": "02:00:00:00:00:09", "ip": "10.0.0.9", "hostname": "Alex's iPad", "vendor": "Acme", "vlan": "HomeNet",
       "lease_type": "dynamic"}
TOKEN = "tok3n-in-the-url-abc"


class Hook(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, status: int = 204, headers: dict | None = None, delay: float = 0) -> None:
        self.status, self.headers, self.delay = status, headers or {}, delay
        self.requests: list[tuple[str, dict, bytes]] = []
        server = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                server.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                if server.delay:
                    time.sleep(server.delay)
                try:
                    self.send_response(server.status)
                    for k, v in server.headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                except OSError:
                    pass  # the client timed out and left

            def log_message(self, *a: object) -> None:
                pass
        super().__init__(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server_address[1]}"
        self._t = threading.Thread(target=self.serve_forever, daemon=True)
        self._t.start()

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self._t.join(5)


class WebhookBase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = clean_env({"no_proxy": "*", "NO_PROXY": "*"})
        self.addCleanup(restore, self.saved)

    def hook(self, **kw: object) -> Hook:
        h = Hook(**kw)
        self.addCleanup(h.close)
        return h

    def cfg(self, **env: str) -> Config:
        os.environ.update(env)
        return Config()

    def channel(self, cfg: Config):
        chans = [c for c in notify.channels(cfg) if c.name == "webhook"]
        self.assertEqual(len(chans), 1)
        return chans[0]

    def send(self, cfg: Config, devs: list[dict] | None = None) -> None:
        self.channel(cfg).send(notify.build_message(cfg, devs or [DEV]))

    def err(self, cfg: Config) -> str:
        with self.assertRaises(notify.WebhookError) as cm:
            self.send(cfg)
        self.assertIsInstance(cm.exception, notify.NotifyError)
        return str(cm.exception)


class JsonTests(WebhookBase):
    def test_body(self) -> None:
        h = self.hook()
        cfg = self.cfg(WEBHOOK_URL=h.url + "/api/webhook/abc", SITE_NAME="HomeNet", PUBLIC_URL="https://lw.example.lan")
        evil = {**DEV, "hostname": "evil\r\nline", "vlan": ""}
        self.send(cfg, [DEV, evil])
        path, headers, raw = h.requests[0]
        self.assertEqual(path, "/api/webhook/abc")
        self.assertEqual(headers["content-type"], "application/json")
        self.assertTrue(headers["user-agent"].startswith("leasewatch/"))
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(body["event"], "new_devices")
        self.assertEqual(body["site"], "HomeNet")
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["title"], "2 new devices on the network")
        self.assertIn("Alex's iPad", body["message"])
        self.assertEqual(body["url"], "https://lw.example.lan/?filter=unacked")
        self.assertEqual(body["devices"][0], DEV)
        self.assertEqual(body["devices"][1]["hostname"], "evil\r\nline")  # data, JSON-escaped
        self.assertNotIn("\r", body["message"])
        for k in ("webhook-id", "webhook-timestamp", "webhook-signature"):
            self.assertNotIn(k, headers)

    def test_url_null_without_public_url(self) -> None:
        h = self.hook()
        self.send(self.cfg(WEBHOOK_URL=h.url + "/x"))
        self.assertIsNone(json.loads(h.requests[0][2])["url"])

    def test_signature(self) -> None:
        for secret, key in (("plain-secret", b"plain-secret"),
                            ("whsec_" + base64.b64encode(b"\x01\x02key").decode(), b"\x01\x02key")):
            h = self.hook()
            self.send(self.cfg(WEBHOOK_URL=h.url + "/x", WEBHOOK_SECRET=secret))
            _, headers, raw = h.requests[0]
            self.assertTrue(headers["webhook-id"].startswith("msg_"))
            ts = int(headers["webhook-timestamp"])
            self.assertLess(abs(ts - time.time()), 60)
            want = base64.b64encode(hmac.new(key, f"{headers['webhook-id']}.{ts}.".encode() + raw, hashlib.sha256).digest()).decode()
            self.assertEqual(headers["webhook-signature"], "v1," + want)


class FormatTests(WebhookBase):
    def test_ntfy(self) -> None:
        h = self.hook(status=200)
        self.send(self.cfg(WEBHOOK_URL=h.url + "/ntfy/lw-alerts?auth=" + TOKEN, WEBHOOK_FORMAT="ntfy",
                           PUBLIC_URL="https://lw.example.lan"))
        path, headers, raw = h.requests[0]
        self.assertEqual(path, "/ntfy/?auth=" + TOKEN)  # JSON publishing goes to the root URL with the topic inside
        body = json.loads(raw)
        self.assertEqual(body["topic"], "lw-alerts")
        self.assertEqual(body["title"], "New device: Alex's iPad (10.0.0.9, HomeNet)")
        self.assertIn("Alex's iPad", body["message"])
        self.assertEqual(body["click"], "https://lw.example.lan/?filter=unacked")

    def test_discord(self) -> None:
        h = self.hook()
        self.send(self.cfg(WEBHOOK_URL=h.url + "/api/webhooks/1/" + TOKEN, WEBHOOK_FORMAT="discord",
                           PUBLIC_URL="https://lw.example.lan"), [{**DEV, "hostname": "@everyone [x](https://evil.example.com)"}])
        body = json.loads(h.requests[0][2])
        self.assertEqual(body["allowed_mentions"], {"parse": []})  # a hostname cannot ping anyone
        self.assertIn("```", body["content"])
        self.assertIn("https://lw.example.lan/?filter=unacked", body["content"])
        self.assertNotIn("[x](https://evil.example.com)", body["content"].split("```")[0])  # escaped outside the code block
        self.assertLessEqual(len(body["content"]), 2000)

    def test_discord_long_is_cut(self) -> None:
        h = self.hook()
        devs = [{**DEV, "mac": f"02:00:00:00:01:{i:02x}", "hostname": "h" * 25} for i in range(50)]
        self.send(self.cfg(WEBHOOK_URL=h.url + "/d", WEBHOOK_FORMAT="discord"), devs)
        content = json.loads(h.requests[0][2])["content"]
        self.assertLessEqual(len(content), 2000)
        self.assertIn("more", content)
        self.assertEqual(content.count("```"), 2)

    def test_ntfy_long_is_cut(self) -> None:
        # S5R15: ntfy refuses (or turns into an attachment) a message over 4096 bytes
        h = self.hook(status=200)
        devs = [{**DEV, "mac": f"02:00:00:00:01:{i:02x}", "hostname": "guest-phone-ä" * 2} for i in range(50)]
        self.send(self.cfg(WEBHOOK_URL=h.url + "/lw", WEBHOOK_FORMAT="ntfy", PUBLIC_URL="https://lw.example.lan"), devs)
        message = json.loads(h.requests[0][2])["message"]
        self.assertLessEqual(len(message.encode("utf-8")), 4096)
        self.assertRegex(message, r"… and \d+ more")
        self.assertTrue(message.startswith("50 new devices on the network:\n\n"))
        self.assertTrue(message.endswith("Review and acknowledge: https://lw.example.lan/?filter=unacked"))

    def test_ntfy_exactly_at_the_limit_is_cut(self) -> None:
        # ntfy takes a body that reaches its limit as an attachment
        h = self.hook(status=200)
        cfg = self.cfg(WEBHOOK_URL=h.url + "/lw", WEBHOOK_FORMAT="ntfy")
        devs = [{**DEV, "mac": f"02:00:00:00:01:{i:02x}", "hostname": "host-" + "x" * 300} for i in range(10)]
        devs[-1]["hostname"] += "x" * (notify.NTFY_MAX - len(notify.build_message(cfg, devs).text.encode()))
        self.assertEqual(len(notify.build_message(cfg, devs).text.encode()), notify.NTFY_MAX)
        self.send(cfg, devs)
        message = json.loads(h.requests[0][2])["message"]
        self.assertLess(len(message.encode("utf-8")), notify.NTFY_MAX)
        self.assertRegex(message, r"… and \d+ more")

    def test_bad_secret_is_named(self) -> None:
        # S5R29: a decode error of the secret is not a bad URL (a Config built without validate())
        h = self.hook()
        e = self.err(self.cfg(WEBHOOK_URL=h.url + "/x", WEBHOOK_SECRET="whsec_abc"))
        self.assertEqual(e, "webhook: bad WEBHOOK_SECRET")
        self.assertEqual(h.requests, [])


class ErrorTests(WebhookBase):
    def secret_url(self, h: Hook) -> str:
        return h.url + "/hook/" + TOKEN + "?token=" + TOKEN

    def test_http_error(self) -> None:
        h = self.hook(status=500)
        self.assertEqual(self.err(self.cfg(WEBHOOK_URL=self.secret_url(h))), "webhook: HTTP 500")

    def test_redirect_refused(self) -> None:
        target = self.hook()
        h = self.hook(status=302, headers={"Location": target.url + "/stolen"})
        e = self.err(self.cfg(WEBHOOK_URL=self.secret_url(h)))
        self.assertEqual(e, "webhook: HTTP 302 (redirect not followed)")
        self.assertEqual(target.requests, [])

    def test_timeout(self) -> None:
        h = self.hook(delay=2)
        cfg = self.cfg(WEBHOOK_URL=self.secret_url(h))
        ch = self.channel(cfg)
        ch.timeout = 0.3
        with self.assertRaises(notify.WebhookError) as cm:
            ch.send(notify.build_message(cfg, [DEV]))
        self.assertEqual(str(cm.exception), "webhook: timeout")

    def test_connection_refused(self) -> None:
        h = Hook()
        url = self.secret_url(h)
        h.close()
        e = self.err(self.cfg(WEBHOOK_URL=url))
        self.assertTrue(e.startswith("webhook: "), e)
        self.assertNotIn("127.0.0.1", e)

    def test_invalid_url_names_the_setting(self) -> None:
        # http.client.InvalidURL is an HTTPException, but the setting's fault (a Config that skipped validate())
        self.assertEqual(self.err(self.cfg(WEBHOOK_URL="http://127.0.0.1:9/a b")), "webhook: bad WEBHOOK_URL")

    def test_secret_url_never_leaks(self) -> None:
        h = self.hook(status=403)
        cfg = self.cfg(WEBHOOK_URL=self.secret_url(h), WEBHOOK_SECRET="sig-secret-value")
        with self.assertLogs("leasewatch", "DEBUG") as logs:
            with self.assertRaises(notify.NotifyError) as cm:
                notify.new_devices(cfg, [DEV])
            notify.log.debug("end")
        text = "\n".join(logs.output) + str(cm.exception) + repr(cfg) + "\n".join(cfg.validate())
        for leak in (TOKEN, "sig-secret-value", "127.0.0.1"):
            self.assertNotIn(leak, text)


class ConfigTests(WebhookBase):
    def problems(self, **env: str) -> list[str]:
        return [p for p in self.cfg(**env).validate() if "WEBHOOK" in p]

    def test_rules(self) -> None:
        self.assertEqual(self.problems(WEBHOOK_URL="https://hooks.example.com/x"), [])
        self.assertIn("WEBHOOK_URL must be a URL (https://<host>/<path>)", self.problems(WEBHOOK_URL="hooks.example.com/" + TOKEN))
        self.assertIn("WEBHOOK_URL must not contain credentials", self.problems(WEBHOOK_URL=f"https://u:{TOKEN}@hooks.example.com/"))
        self.assertIn("WEBHOOK_URL is not a valid URL", self.problems(WEBHOOK_URL="https://hooks.example.com:0/x"))
        self.assertIn("WEBHOOK_FORMAT must be json, ntfy or discord", self.problems(WEBHOOK_URL="https://hooks.example.com/x", WEBHOOK_FORMAT="slack"))
        self.assertIn("WEBHOOK_URL needs a topic (https://<host>/<topic>) with WEBHOOK_FORMAT=ntfy",
                      self.problems(WEBHOOK_URL="https://ntfy.example.com/", WEBHOOK_FORMAT="ntfy"))
        self.assertIn("WEBHOOK_SECRET: the whsec_ value is not valid base64",
                      self.problems(WEBHOOK_URL="https://hooks.example.com/x", WEBHOOK_FORMAT="json", WEBHOOK_SECRET="whsec_!!!"))
        for p in self.problems(WEBHOOK_URL=f"https://u:{TOKEN}@hooks.example.com/" + TOKEN):
            self.assertNotIn(TOKEN, p)

    def test_secret_and_url_validated_as_used(self) -> None:
        url = "https://hooks.example.com/x"
        # S5R10/S5R16: "whsec_" alone decodes to an empty HMAC key, which anyone can sign with
        self.assertIn("WEBHOOK_SECRET: the whsec_ value is empty", self.problems(WEBHOOK_URL=url, WEBHOOK_SECRET="whsec_"))
        # S5R17: os.environ keeps undecodable bytes as surrogates, which .encode() refuses
        self.assertIn("WEBHOOK_SECRET is not valid UTF-8", self.problems(WEBHOOK_URL=url, WEBHOOK_SECRET="caf\udce9"))
        # S5R18: http.client sends the path and query as ASCII; a non-ASCII host is IDNA-encoded and fine
        msg = "WEBHOOK_URL: the path and query must be ASCII (percent-encode other characters)"
        for bad in ("https://hooks.example.com/ä/topic", "https://hooks.example.com/t?auth=å"):
            self.assertIn(msg, self.problems(WEBHOOK_URL=bad), bad)
        self.assertEqual(self.problems(WEBHOOK_URL="https://hooks.exämple.com/t", WEBHOOK_SECRET=""), [])

    def test_enabled_by_url_only(self) -> None:
        self.assertFalse(self.cfg().mail_enabled)
        cfg = self.cfg(WEBHOOK_URL="https://hooks.example.com/" + TOKEN)
        self.assertTrue(cfg.mail_enabled)
        self.assertEqual([c.name for c in notify.channels(cfg)], ["webhook"])
        self.assertNotIn(TOKEN, repr(cfg))


if __name__ == "__main__":
    unittest.main()
