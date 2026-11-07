"""S5 T-05: the notification channel interface, the SMTP channel and the queue with several channels. A fake SMTP
server on port 0 (tests/_smtpfake.py); TLS with a certificate made at test time. Synthetic data only."""
from __future__ import annotations

import email
import email.policy
import os
import ssl
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore  # noqa: E402
from _smtpfake import FakeSmtp, make_cert, server_tls, silent_listener  # noqa: E402
from test_instances import FW1, MAC, Base, arp  # noqa: E402
from leasewatch import notify  # noqa: E402
from leasewatch.__main__ import startup_line  # noqa: E402
from leasewatch.config import Config  # noqa: E402

DEV = {"mac": "02:00:00:00:00:09", "ip": "10.0.0.9", "hostname": "Alex's iPad ✓", "vendor": "Acme", "vlan": "HomeNet",
       "lease_type": "dynamic"}
PASSWORD = "s3cret-smtp-pass"


class SmtpBase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = clean_env()
        self.addCleanup(restore, self.saved)

    def cfg(self, **env: str) -> Config:
        os.environ.update({"MAIL_TO": "ops@example.com", "SMTP_FROM": "leasewatch@example.com", **env})
        return Config()

    def fake(self, **kw: object) -> FakeSmtp:
        srv = FakeSmtp(**kw)
        self.addCleanup(srv.close)
        return srv

    def channel(self, cfg: Config) -> "notify.SmtpChannel":
        chans = [c for c in notify.channels(cfg) if c.name == "smtp"]
        self.assertEqual(len(chans), 1)
        return chans[0]

    def send(self, cfg: Config, devs: list[dict] | None = None) -> None:
        self.channel(cfg).send(notify.build_message(cfg, devs or [DEV]))

    def err(self, cfg: Config) -> str:
        with self.assertRaises(notify.SmtpError) as cm:
            self.send(cfg)
        self.assertIsInstance(cm.exception, notify.NotifyError)
        return str(cm.exception)


class SmtpPlainTests(SmtpBase):
    def test_plain_send(self) -> None:
        srv = self.fake()
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none", MAIL_FROM_NAME="Lease Watch",
                       MAIL_TO="ops@example.com, alex@example.com", PUBLIC_URL="https://lw.example.lan")
        self.send(cfg)
        self.assertEqual(len(srv.messages), 1)
        m = email.message_from_bytes(srv.messages[0], policy=email.policy.default)
        self.assertEqual(m["From"], "Lease Watch <leasewatch@example.com>")
        self.assertEqual(m["To"], "ops@example.com, alex@example.com")
        self.assertEqual(m["Subject"], "New device: Alex's iPad ✓ (10.0.0.9, HomeNet)")
        self.assertTrue(m["Date"])
        self.assertTrue(m["Message-ID"].endswith("@example.com>"), m["Message-ID"])
        body = m.get_content()
        self.assertIn("Alex's iPad ✓", body)
        self.assertIn("https://lw.example.lan/?filter=unacked", body)
        self.assertIn("<leasewatch@example.com>", srv.mail_from[0])
        self.assertEqual(len(srv.rcpts), 2)
        self.assertEqual(srv.ehlo_names, ["leasewatch"])  # no getfqdn(): the container name stays private
        self.assertNotIn("AUTH", srv.commands)  # no SMTP_USER: no login
        self.assertEqual(srv.commands[-1], "QUIT")

    def test_port_default_by_tls(self) -> None:
        for tls, port in (("starttls", 587), ("tls", 465), ("none", 25), ("", 587)):
            os.environ.pop("SMTP_PORT", None)
            self.assertEqual(self.cfg(SMTP_HOST="mail.example.com", SMTP_TLS=tls).smtp_port, port, tls)
        self.assertEqual(self.cfg(SMTP_HOST="mail.example.com", SMTP_TLS="tls", SMTP_PORT="2465").smtp_port, 2465)

    def test_starttls_required_never_downgraded(self) -> None:
        srv = self.fake()  # does not offer STARTTLS
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_USER="ro", SMTP_PASSWORD=PASSWORD)
        self.assertEqual(self.err(cfg), "smtp: server does not offer STARTTLS")
        for verb in ("AUTH", "MAIL", "RCPT", "DATA"):
            self.assertNotIn(verb, srv.commands)
        self.assertEqual(srv.auth, [])

    def test_starttls_context_verifies(self) -> None:
        srv = self.fake(extensions=("STARTTLS", "AUTH PLAIN"))
        seen = []

        def fake_starttls(smtp, context=None):
            seen.append(context)
            raise ssl.SSLCertVerificationError("certificate verify failed")
        with mock.patch("smtplib.SMTP.starttls", fake_starttls):
            self.assertEqual(self.err(self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port))),
                             "smtp: certificate verification failed")
            self.err(self.cfg(SMTP_VERIFY_TLS="0"))
        self.assertEqual(seen[0].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(seen[0].check_hostname)
        self.assertEqual((seen[1].verify_mode, seen[1].check_hostname), (ssl.CERT_NONE, False))

    def test_auth_success(self) -> None:
        srv = self.fake(extensions=("AUTH PLAIN LOGIN",))
        # validation refuses a password without TLS; the channel itself is tested on the plain fake here
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none")
        cfg.smtp_user, cfg.smtp_password = "ro", PASSWORD
        self.send(cfg)
        self.assertEqual(srv.auth, [("ro", PASSWORD)])
        self.assertEqual(len(srv.messages), 1)

    def test_auth_refused_hides_password(self) -> None:
        srv = self.fake(replies={"AUTH": "535 5.7.8 bad credentials for ro"})
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none")
        cfg.smtp_user, cfg.smtp_password = "ro", PASSWORD
        with self.assertLogs("leasewatch", "DEBUG") as logs:
            with self.assertRaises(notify.NotifyError) as cm:
                notify.new_devices(cfg, [DEV])
            notify.log.debug("end")
        self.assertEqual(str(cm.exception), "smtp: login refused (535)")
        text = "\n".join(logs.output) + str(cm.exception) + repr(cfg)
        for leak in (PASSWORD, "bad credentials"):
            self.assertNotIn(leak, text)
        self.assertNotIn("MAIL", srv.commands)

    def test_recipient_refused_hides_address(self) -> None:
        srv = self.fake(replies={"RCPT": "550 5.1.1 <ops@example.com> unknown"})
        e = self.err(self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none"))
        self.assertEqual(e, "smtp: recipient refused")
        self.assertEqual(srv.messages, [])

    def test_sender_and_data_codes(self) -> None:
        srv = self.fake(replies={"MAIL": "553 sender leasewatch@example.com not allowed"})
        self.assertEqual(self.err(self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none")),
                         "smtp: sender refused (553)")
        srv2 = self.fake(replies={"DATA": "554 5.7.1 spam detected for ops@example.com"})
        self.assertEqual(self.err(self.cfg(SMTP_PORT=str(srv2.port))), "smtp: 554")

    def test_greeting_refused(self) -> None:
        srv = self.fake()
        # a server that answers 554 instead of 220
        import _smtpfake
        orig = _smtpfake._Handler.out

        def out(h, line):
            orig(h, "554 no service for you" if line.startswith("220 mail") else line)
        with mock.patch.object(_smtpfake._Handler, "out", out):
            self.assertEqual(self.err(self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none")),
                             "smtp: 554")

    def test_timeout(self) -> None:
        s = silent_listener()
        self.addCleanup(s.close)
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(s.getsockname()[1]), SMTP_TLS="none")
        ch = self.channel(cfg)
        ch.timeout = 0.3
        t = time.monotonic()
        with self.assertRaises(notify.SmtpError) as cm:
            ch.send(notify.build_message(cfg, [DEV]))
        self.assertEqual(str(cm.exception), "smtp: timeout")
        self.assertLess(time.monotonic() - t, 5)

    def test_connection_refused(self) -> None:
        s = silent_listener()
        port = s.getsockname()[1]
        s.close()
        e = self.err(self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(port), SMTP_TLS="none"))
        self.assertTrue(e.startswith("smtp: "), e)
        self.assertNotIn("127.0.0.1", e)

    def test_subject_header_injection(self) -> None:
        srv = self.fake()
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none")
        self.send(cfg, [{**DEV, "hostname": "evil\r\nBcc: x@example.com"}])
        m = email.message_from_bytes(srv.messages[0], policy=email.policy.default)
        self.assertIsNone(m["Bcc"])
        self.assertEqual(m["Subject"], "New device: evil  Bcc: x@example.com (10.0.0.9, HomeNet)")
        self.assertEqual(len(srv.rcpts), 1)


class SmtpTlsTests(SmtpBase):
    """Real TLS on the wire, with a certificate made now (skipped without the openssl command)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pair = make_cert(cls.tmp.name)
        if not cls.pair:
            cls.tmp.cleanup()
            raise unittest.SkipTest("openssl not available")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def trusting(self):
        """ssl.create_default_context() that also trusts the test certificate (as an installed CA would)."""
        real = ssl.create_default_context
        return mock.patch("ssl.create_default_context", lambda *a, **k: real(cafile=self.pair[0]))

    def test_starttls_untrusted_cert_refused(self) -> None:
        srv = self.fake(extensions=("STARTTLS", "AUTH PLAIN"), tls=server_tls(*self.pair))
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_USER="ro", SMTP_PASSWORD=PASSWORD)
        self.assertEqual(self.err(cfg), "smtp: certificate verification failed")
        self.assertEqual(srv.auth, [])

    def test_starttls_trusted_cert_with_login(self) -> None:
        srv = self.fake(extensions=("STARTTLS", "AUTH PLAIN"), tls=server_tls(*self.pair))
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_USER="ro", SMTP_PASSWORD=PASSWORD)
        with self.trusting():
            self.send(cfg)
        self.assertTrue(srv.tls_used)
        self.assertEqual(srv.auth, [("ro", PASSWORD)])
        self.assertEqual(len(srv.messages), 1)
        self.assertEqual(srv.commands[:3], ["EHLO", "STARTTLS", "EHLO"])

    def test_starttls_verify_off_accepts_self_signed(self) -> None:
        srv = self.fake(extensions=("STARTTLS",), tls=server_tls(*self.pair))
        self.send(self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_VERIFY_TLS="0"))
        self.assertTrue(srv.tls_used)
        self.assertEqual(len(srv.messages), 1)

    def test_implicit_tls(self) -> None:
        srv = self.fake(extensions=("AUTH PLAIN",), tls=server_tls(*self.pair), implicit_tls=True)
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="tls", SMTP_USER="ro", SMTP_PASSWORD=PASSWORD)
        self.assertEqual(self.err(cfg), "smtp: certificate verification failed")
        with self.trusting():
            self.send(cfg)
        self.assertEqual(len(srv.messages), 1)
        self.assertNotIn("STARTTLS", srv.commands)


class SmtpConfigTests(SmtpBase):
    def problems(self, **env: str) -> list[str]:
        for k in [k for k in os.environ if k.startswith("SMTP_")]:
            del os.environ[k]  # each call stands alone
        return [p for p in self.cfg(**env).validate() if "SMTP" in p or "MAIL_TO" in p]

    def test_valid(self) -> None:
        self.assertEqual(self.problems(SMTP_HOST="mail.example.com", SMTP_USER="ro", SMTP_PASSWORD=PASSWORD), [])
        self.assertEqual(self.problems(SMTP_HOST="mail.example.com", SMTP_TLS="none"), [])

    def test_rules(self) -> None:
        h = {"SMTP_HOST": "mail.example.com"}
        self.assertIn("SMTP_TLS must be starttls, tls or none", self.problems(**h, SMTP_TLS="ssl"))
        self.assertIn("SMTP_PORT must be 1-65535", self.problems(**h, SMTP_PORT="0"))
        self.assertIn("SMTP_PORT must be 1-65535", self.problems(**h, SMTP_PORT="70000"))
        self.assertIn("SMTP_PASSWORD needs SMTP_TLS=starttls or tls",
                      self.problems(**h, SMTP_TLS="none", SMTP_USER="ro", SMTP_PASSWORD=PASSWORD))
        self.assertIn("SMTP_USER and SMTP_PASSWORD must be set together", self.problems(**h, SMTP_USER="ro"))
        self.assertIn("SMTP_USER and SMTP_PASSWORD must be set together", self.problems(**h, SMTP_PASSWORD=PASSWORD))
        self.assertIn("SMTP_VERIFY_TLS must be 1 or 0", self.problems(**h, SMTP_VERIFY_TLS="maybe"))
        self.assertIn("SMTP_FROM must be an e-mail address (required with SMTP_HOST)", self.problems(**h, SMTP_FROM=""))
        self.assertIn("SMTP_FROM must be an e-mail address (required with SMTP_HOST)", self.problems(**h, SMTP_FROM="a@example.com\r\nBcc: b@x"))
        self.assertIn("MAIL_TO must be one or more e-mail addresses, comma separated (required with SMTP_HOST)", self.problems(**h, SMTP_FROM="a@example.com", MAIL_TO=""))
        self.assertIn("MAIL_TO must be one or more e-mail addresses, comma separated (required with SMTP_HOST)", self.problems(**h, MAIL_TO="ops@example.com, nobody"))
        bad = self.problems(**h, MAIL_TO="ops", SMTP_FROM="x", SMTP_TLS="none", SMTP_USER="ro", SMTP_PASSWORD=PASSWORD)
        self.assertNotIn(PASSWORD, "\n".join(bad))  # values never echoed

    def test_off_without_host(self) -> None:
        self.assertEqual(self.problems(SMTP_TLS="bogus"), ["SMTP_TLS must be starttls, tls or none"])
        cfg = self.cfg()
        self.assertFalse(cfg.mail_enabled)
        self.assertEqual(notify.channels(cfg), [])

    def test_secret_not_in_repr(self) -> None:
        self.assertNotIn(PASSWORD, repr(self.cfg(SMTP_HOST="mail.example.com", SMTP_USER="ro", SMTP_PASSWORD=PASSWORD)))

    def test_mail_enabled_and_startup_line(self) -> None:
        os.environ.update(FW1)
        os.environ["LW_CONNECTORS"] = "fw1"
        cfg = self.cfg(SMTP_HOST="mail.example.com")
        self.assertTrue(cfg.mail_enabled)
        self.assertTrue(startup_line(cfg, "x").endswith("mail on (smtp); writes all"), startup_line(cfg, "x"))
        cfg = self.cfg(SMTP_HOST="mail.example.com", MAILGUN_KEY="k" * 16, MAILGUN_DOMAIN="mg.example.com",
                       WEBHOOK_URL="https://hooks.example.com/t/abc")
        self.assertEqual([c.name for c in notify.channels(cfg)], ["mailgun", "smtp", "webhook"])
        self.assertTrue(startup_line(cfg, "x").endswith("mail on (mailgun, smtp, webhook); writes all"))


def ok_channel(name: str, sent: list):
    class C:
        def send(self, msg):
            sent.append((name, [d["mac"] for d in msg.devices]))
    c = C()
    c.name = name
    return c


def bad_channel(name: str):
    class C:
        def send(self, msg):
            raise notify.NotifyError(f"{name}: HTTP 503")
    c = C()
    c.name = name
    return c


class NewDevicesTests(SmtpBase):
    def test_partial_failure_returns_names_and_logs(self) -> None:
        sent: list = []
        with mock.patch.object(notify, "channels", lambda cfg: [bad_channel("mailgun"), ok_channel("smtp", sent)]):
            with self.assertLogs("leasewatch.notify", "WARNING") as logs:
                names = notify.new_devices(self.cfg(), [DEV, DEV])
        self.assertEqual(names, ["smtp"])
        self.assertEqual(len(sent), 1)
        self.assertTrue(any("mailgun failed (2 device(s)): mailgun: HTTP 503" in m for m in logs.output), logs.output)

    def test_all_fail_raises(self) -> None:
        with mock.patch.object(notify, "channels", lambda cfg: [bad_channel("mailgun"), bad_channel("smtp")]):
            with self.assertRaises(notify.NotifyError) as cm:
                notify.new_devices(self.cfg(), [DEV])
        self.assertIn("mailgun: HTTP 503", str(cm.exception))
        self.assertIn("smtp: HTTP 503", str(cm.exception))

    def test_unexpected_exception_counts_as_failure(self) -> None:
        sent: list = []

        class Boom:
            name = "smtp"

            def send(self, msg):
                raise KeyError("x")
        with mock.patch.object(notify, "channels", lambda cfg: [Boom(), ok_channel("webhook", sent)]):
            with self.assertLogs("leasewatch.notify", "WARNING"):
                self.assertEqual(notify.new_devices(self.cfg(), [DEV]), ["webhook"])

    def test_build_message_is_pure_text(self) -> None:
        cfg = self.cfg(PUBLIC_URL="https://lw.example.lan")
        m = notify.build_message(cfg, [DEV])
        self.assertEqual(m.subject, "New device: Alex's iPad ✓ (10.0.0.9, HomeNet)")
        self.assertEqual(m.url, "https://lw.example.lan/?filter=unacked")
        self.assertEqual(m.devices, [DEV])
        self.assertEqual(notify.build_message(self.cfg(PUBLIC_URL=""), [DEV]).url, "")

    def test_unexpected_exception_logs_redacted_traceback(self) -> None:
        # S5R30: a bug in a channel must leave its stack in the log (once), without a secret from the exception text
        notify._logged_bugs.clear()

        class Boom:
            name = "smtp"

            def send(self, msg):
                raise KeyError(PASSWORD)
        cfg = self.cfg(SMTP_HOST="mail.example.com", SMTP_USER="ro", SMTP_PASSWORD=PASSWORD)
        with mock.patch.object(notify, "channels", lambda cfg: [Boom(), ok_channel("webhook", [])]):
            with self.assertLogs("leasewatch.notify", "WARNING") as logs:
                notify.new_devices(cfg, [DEV])
                notify.new_devices(cfg, [DEV])
        text = "\n".join(logs.output)
        self.assertEqual(text.count("Traceback"), 1, text)  # once per bug, not every poll
        self.assertIn("in send", text)
        self.assertNotIn(PASSWORD, text)

    def test_unexpected_exception_log_has_no_device_data(self) -> None:
        # the exception text and its context chain can carry hostnames and addresses: type and stack only
        notify._logged_bugs.clear()

        class Boom:
            name = "smtp"

            def send(self, msg):
                try:
                    raise ValueError("ops@example.com refused")
                except ValueError:
                    raise KeyError("Alex's iPad")
        with mock.patch.object(notify, "channels", lambda cfg: [Boom(), ok_channel("webhook", [])]):
            with self.assertLogs("leasewatch.notify", "WARNING") as logs:
                notify.new_devices(self.cfg(), [DEV])
        text = "\n".join(logs.output)
        self.assertIn("smtp failed unexpectedly: KeyError", text)
        self.assertIn("in send", text)
        for leak in ("iPad", "ops@example.com", "During handling", "ValueError"):
            self.assertNotIn(leak, text)

    def test_unicode_line_breaks_leave_the_subject(self) -> None:
        # S5R27: EmailMessage refuses U+0085/U+2028/U+2029 in a header as it does CR/LF
        for ch in ("\x85", " ", " "):
            m = notify.build_message(self.cfg(), [{**DEV, "hostname": f"evil{ch}X"}])
            self.assertEqual(m.subject, "New device: evil X (10.0.0.9, HomeNet)")


class S5FixSmtpTests(SmtpBase):
    """Review fixes: a setting that passes validation works when sent; a partial refusal is logged."""

    def problems(self, **env: str) -> list[str]:
        return [p for p in self.cfg(SMTP_HOST="mail.example.com", **env).validate() if "SMTP" in p or "MAIL_TO" in p]

    def test_from_address_rules(self) -> None:
        # S5R06/S5R12: brackets, a list or a non-ASCII sender passed, then every send failed or lost the address
        msg = "SMTP_FROM must be an e-mail address (required with SMTP_HOST)"
        for bad in ("<lw@example.com>", "a@example.com,b@example.com", "lw@exämple.se", "lö@example.se",
                    "a@example.com;b@example.com", "mailto:lw@example.com", "lw@a@example.com", 'a"@example.com',
                    "a(b)@example.com", "a[b]@example.com", "a\\b@example.com", "@example.com", "lw@"):
            self.assertIn(msg, self.problems(SMTP_FROM=bad), bad)
        for bad in ("<ops@example.com>", "ops@example.com;alex@example.com", "ops@a@example.com"):
            self.assertIn("MAIL_TO must be one or more e-mail addresses, comma separated (required with SMTP_HOST)",
                          self.problems(MAIL_TO=bad), bad)
        self.assertEqual(self.problems(SMTP_FROM="lw.alerts+x@example.com", MAIL_TO="ops@example.com, a-b@example.com"), [])

    def test_mail_to_trailing_comma(self) -> None:
        # S5R08: the sender drops empty pieces, so validation does too
        self.assertEqual(self.problems(MAIL_TO="ops@example.com,"), [])
        self.assertIn("MAIL_TO must be one or more e-mail addresses, comma separated (required with SMTP_HOST)",
                      self.problems(MAIL_TO=" , "))

    def test_empty_verify_tls_is_default(self) -> None:
        # S5R09: an empty global setting means its default
        cfg = self.cfg(SMTP_HOST="mail.example.com", SMTP_VERIFY_TLS="")
        self.assertEqual([p for p in cfg.validate() if "SMTP" in p], [])
        self.assertEqual(cfg.smtp_verify_tls, "1")

    def test_bad_port_warning_names_the_port_used(self) -> None:
        # S5R07: the warning said "using -1" while 465 was used
        with self.assertLogs("leasewatch.config", "WARNING") as logs:
            cfg = self.cfg(SMTP_TLS="tls", SMTP_PORT="abc")
        self.assertEqual(cfg.smtp_port, 465)
        self.assertIn("using 465", "\n".join(logs.output))
        self.assertEqual(self.cfg(SMTP_TLS="tls", SMTP_PORT="").smtp_port, 465)

    def test_port_minus_one_is_not_the_default(self) -> None:
        # -1 is the "use the default" marker inside Config; set by hand it is no port
        with self.assertLogs("leasewatch.config", "WARNING") as logs:
            cfg = self.cfg(SMTP_TLS="tls", SMTP_PORT="-1")
        self.assertEqual(cfg.smtp_port, 465)
        self.assertIn("SMTP_PORT", "\n".join(logs.output))
        self.assertIn("using 465", "\n".join(logs.output))

    def test_non_ascii_login_refused_at_startup(self) -> None:
        # S5R14: smtplib encodes the login as ASCII, so such a value can never log in
        for env in ({"SMTP_USER": "ü", "SMTP_PASSWORD": PASSWORD}, {"SMTP_USER": "ro", "SMTP_PASSWORD": "pässword"}):
            self.assertIn("SMTP_USER and SMTP_PASSWORD must be ASCII", self.problems(**env))

    def test_non_ascii_login_error_names_the_login(self) -> None:
        srv = self.fake(extensions=("AUTH PLAIN",))
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_USER="ro", SMTP_PASSWORD="pässword")
        cfg.smtp_tls = "none"  # past validation: only the runtime message is tested here
        self.assertEqual(self.err(cfg), "smtp: bad SMTP_USER or SMTP_PASSWORD")

    def test_partially_refused_recipients_logged(self) -> None:
        # S5R13: send_message returns the refused recipients instead of raising while one is accepted
        srv = self.fake()
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none",
                       MAIL_TO="a@example.com, b@example.com")
        with mock.patch("smtplib.SMTP.send_message", return_value={"b@example.com": (550, b"no")}):
            with self.assertLogs("leasewatch.notify", "WARNING") as logs:
                self.send(cfg)
        text = "\n".join(logs.output)
        self.assertIn("smtp: 1 of 2 recipient(s) refused", text)
        self.assertNotIn("b@example.com", text)  # an address is personal data


MAIL2 = {"LW_CONNECTORS": "fw1", **FW1, "MAILGUN_KEY": "k", "MAILGUN_DOMAIN": "mg.example.com", "MAIL_TO": "a@example.com",
         "SMTP_HOST": "mail.example.com", "SMTP_FROM": "lw@example.com"}
UA1 = "00:00:5e:00:53:01"


class QueueTests(Base):
    """Collector._notify with two channels: the queue is cleared when at least one delivered (owner answer Q3)."""

    def run_with(self, mailgun_ok: bool, smtp_ok: bool) -> tuple:
        col, db = self.collector(MAIL2, rows=[arp(MAC, "10.0.0.5")])
        col.run_once()  # the baseline
        self.client.rows.append(arp(UA1, "10.0.0.6"))
        sent = []

        def mg(cfg, subject, text):
            if not mailgun_ok:
                raise notify.MailgunError("mailgun: HTTP 503")
            sent.append("mailgun")

        def smtp(self, msg):
            if not smtp_ok:
                raise notify.SmtpError("smtp: timeout")
            sent.append("smtp")
        with mock.patch.object(notify, "_send", mg), mock.patch.object(notify.SmtpChannel, "send", smtp), \
                self.assertLogs("leasewatch", "WARNING") as logs:
            col.run_once()
        q = db.q("SELECT mail_queued FROM devices WHERE mac=?", (UA1,))[0]["mail_queued"]
        return sent, q, "\n".join(logs.output)

    def test_one_fails_queue_cleared(self) -> None:
        sent, q, logs = self.run_with(mailgun_ok=False, smtp_ok=True)
        self.assertEqual(sent, ["smtp"])
        self.assertIsNone(q)
        self.assertIn("mailgun failed (1 device(s)): mailgun: HTTP 503", logs)

    def test_other_fails_queue_cleared(self) -> None:
        sent, q, logs = self.run_with(mailgun_ok=True, smtp_ok=False)
        self.assertEqual(sent, ["mailgun"])
        self.assertIsNone(q)
        self.assertIn("smtp failed (1 device(s)): smtp: timeout", logs)

    def test_all_fail_queue_kept(self) -> None:
        sent, q, logs = self.run_with(mailgun_ok=False, smtp_ok=False)
        self.assertEqual(sent, [])
        self.assertIsNotNone(q)
        self.assertIn("mail failed (1 device(s) queued)", logs)


if __name__ == "__main__":
    unittest.main()
