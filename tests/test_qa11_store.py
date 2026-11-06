"""Regression tests for the QA 1.1 store/notify/UniFi parser fixes (db.py, notify.py, unifi.py)."""
from __future__ import annotations

import inspect
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from _env import clean_env, restore

from leasewatch import notify
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.unifi import parse_clients

MAC = "aa:bb:cc:dd:ee:01"


class DbBase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "t.db")
        self.db = Database(self.path)

    def tearDown(self) -> None:
        self.db._conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def reopen_with_version(self, value: str, drop_seen: bool = False) -> Database:
        self.db._conn.close()
        c = sqlite3.connect(self.path)
        if drop_seen:
            c.execute("DROP TABLE IF EXISTS seen")
        c.execute("UPDATE meta SET value=? WHERE key='schema_version'", (value,))
        c.commit()
        c.close()
        self.db = Database(self.path)
        return self.db

    def add_device(self) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,0,0)", (MAC,))


class SchemaVersionTest(DbBase):
    def test_r50_lenient_int_forms_are_damage(self) -> None:
        # int() accepts "1_0" (10), " 2 " and Arabic-Indic digits: none of them is a value this app writes
        for raw in ("1_0", " 2 ", "٢"):
            with self.subTest(raw=raw):
                with self.assertLogs("leasewatch.db", "WARNING") as cm:
                    db = self.reopen_with_version(raw, drop_seen=True)
                self.assertIn("not a number", "\n".join(cm.output))
                self.assertEqual(db.get_meta("schema_version"), "2")
                self.assertTrue(db.q("SELECT 1 FROM sqlite_master WHERE name='seen'"))

    def test_r132_below_one_is_not_called_not_a_number(self) -> None:
        for raw in ("0", "-1"):
            with self.subTest(raw=raw):
                with self.assertLogs("leasewatch.db", "WARNING") as cm:
                    db = self.reopen_with_version(raw)
                text = "\n".join(cm.output)
                self.assertNotIn("not a number", text)
                self.assertIn("below 1", text)
                self.assertEqual(db.get_meta("schema_version"), "2")

    def test_v08_blob_version_does_not_crash_startup(self) -> None:
        # b"2" is version 2 (nothing to do, the value stays as stored); b"x" is damage and repaired to "2"
        for blob, want in ((b"2", b"2"), (b"x", "2")):
            with self.subTest(blob=blob):
                self.db._conn.close()
                c = sqlite3.connect(self.path)
                c.execute("UPDATE meta SET value=? WHERE key='schema_version'", (blob,))
                c.commit()
                c.close()
                self.db = Database(self.path)
                self.assertEqual(self.db.get_meta("schema_version"), want)

    def test_v09_overlong_digit_run_is_damage(self) -> None:
        with self.assertLogs("leasewatch.db", "WARNING") as cm:
            db = self.reopen_with_version("9" * 5000, drop_seen=True)
        self.assertIn("not a number", "\n".join(cm.output))
        self.assertEqual(db.get_meta("schema_version"), "2")
        self.assertTrue(db.q("SELECT 1 FROM sqlite_master WHERE name='seen'"))


class MetaTest(DbBase):
    def test_r51_lone_surrogate_does_not_roll_back_the_transaction(self) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,0,0)", (MAC,))
            self.db.set_meta("conn.unifi.error", "unifi: \ud800", c)
        self.assertIsNotNone(self.db.device(MAC))
        self.assertEqual(self.db.get_meta("conn.unifi.error"), "unifi: ?")

    def test_r133_r134_signatures_are_annotated(self) -> None:
        self.assertIn("return", Database.tx.__wrapped__.__annotations__)
        conn = inspect.signature(Database.set_meta).parameters["conn"]
        self.assertIsNot(conn.annotation, inspect.Parameter.empty)


class UserFieldsTest(DbBase):
    def test_r52_leading_whitespace_does_not_use_the_name_limit(self) -> None:
        self.add_device()
        self.assertEqual(self.db.update_user_fields(MAC, None, " " * 85 + "Kitchen TV", None)["name"], "Kitchen TV")
        self.assertEqual(self.db.update_user_fields(MAC, None, "\n" * 75 + "Kitchen TV", None)["name"], "Kitchen TV")
        self.assertEqual(self.db.update_user_fields(MAC, None, "x" * 79 + " y", None)["name"], "x" * 79)

    def test_r53_cut_note_has_no_trailing_whitespace(self) -> None:
        self.add_device()
        note = self.db.update_user_fields(MAC, None, None, "x" * 999 + " y")["note"]
        self.assertEqual(note, "x" * 999)


class DeviceDetailTest(DbBase):
    def test_v40_device_detail_reads_all_four_under_one_lock_hold(self) -> None:
        self.assertIsNone(self.db.device_detail(MAC))
        self.add_device()
        with self.db.tx() as c:
            c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,1,'10.0.0.5','','LAN','')", (MAC,))
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(1,?,'new','')", (MAC,))
            c.execute("INSERT INTO seen(mac,source,last_seen,last_present) VALUES(?,'fw1',1,1)", (MAC,))
        owned = []
        orig = self.db.seen

        def seen(mac: str) -> list[dict]:  # the last of the four reads: the lock must still be held by this thread
            owned.append(self.db._lock._is_owned())
            return orig(mac)
        with mock.patch.object(self.db, "seen", seen):
            out = self.db.device_detail(MAC)
        self.assertEqual(owned, [True])
        self.assertEqual(out, {"device": self.db.device(MAC), "history": self.db.history(MAC),
                               "events": self.db.events(MAC), "seen": self.db.seen(MAC)})
        self.assertEqual((len(out["history"]), len(out["events"]), len(out["seen"])), (1, 1, 1))


class MailBase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = clean_env({"MAILGUN_KEY": "k" * 16, "MAILGUN_DOMAIN": "mg.example.com", "MAIL_TO": "ops@example.com",
                                "PUBLIC_URL": "https://lw.example.lan"})
        self.cfg = Config()

    def tearDown(self) -> None:
        restore(self.saved)

    def capture(self, devs: list[dict]) -> tuple[str, str]:
        sent: list[tuple[str, str]] = []
        with mock.patch.object(notify, "_send", lambda cfg, subject, text: sent.append((subject, text))):
            notify.new_devices(self.cfg, devs)
        return sent[-1]


class _Resp:
    def read(self, *a: object) -> bytes:
        return b"{}"

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *a: object) -> None:
        pass


class NotifyTest(MailBase):
    DEV = {"mac": "02:00:00:00:00:09", "ip": "10.0.0.9", "hostname": "Alex's iPad", "vendor": "Acme",
           "vlan": "HomeNet", "lease_type": "dynamic"}

    def test_s12x_sent_log_has_no_device_data(self) -> None:
        with mock.patch("urllib.request.urlopen", lambda req, timeout=None: _Resp()):
            with self.assertLogs("leasewatch.notify", "INFO") as cm:
                notify.new_devices(self.cfg, [self.DEV])
        text = "\n".join(cm.output)
        self.assertIn("mail sent", text)
        for leak in ("Alex", "10.0.0.9", "HomeNet", "02:00:00:00:00:09"):
            self.assertNotIn(leak, text)

    def test_s13x_hostname_cannot_forge_body_lines(self) -> None:
        evil = "x\r\n\r\nAll clear. 0 new devices.\r\n\r\nReview and acknowledge: https://evil.example.com/"
        _, body = self.capture([{**self.DEV, "hostname": evil}])
        self.assertNotIn("\r", body)
        lines = body.split("\n")
        self.assertFalse(any(ln.startswith("Review") and "evil" in ln for ln in lines))
        self.assertEqual(len(lines), 5)  # header, blank, one device line, blank, the real link

    def test_s40x_empty_network_leaves_no_empty_part(self) -> None:
        subject, body = self.capture([{**self.DEV, "hostname": "", "vlan": "", "lease_type": "static"}])
        self.assertEqual(subject, "New device: Acme (10.0.0.9)")
        self.assertIn("[static]", body)
        self.assertNotIn("[, ", body)
        subject, body = self.capture([{**self.DEV, "vlan": "", "lease_type": ""}])
        self.assertNotIn("[]", body)
        subject, body = self.capture([self.DEV])
        self.assertEqual(subject, "New device: Alex's iPad (10.0.0.9, HomeNet)")
        self.assertIn("[HomeNet, dynamic]", body)

    def test_v88_no_empty_parentheses_without_ip_and_network(self) -> None:
        subject, _ = self.capture([{**self.DEV, "ip": "", "vlan": ""}])
        self.assertEqual(subject, "New device: Alex's iPad")


class UnifiSignalTest(unittest.TestCase):
    def sig(self, v: object) -> int | None:
        return parse_clients([{"mac": "02:00:00:00:00:01", "signal": v, "essid": "HomeNet"}], [])["02:00:00:00:00:01"].signal

    def test_s44x_signal_parsed_like_the_merge(self) -> None:
        self.assertEqual(self.sig("-61.5"), -61)
        self.assertEqual(self.sig("−61"), -61)
        self.assertEqual(self.sig(" -61 "), -61)
        self.assertEqual(self.sig(-61.0), -61)
        self.assertIsNone(self.sig(True))
        self.assertIsNone(self.sig("1e400"))
        self.assertIsNone(self.sig("nan"))
        self.assertIsNone(self.sig("abc"))

    def test_v69_odd_channel_drops_only_that_field(self) -> None:
        for ch in ("\u00b2", "\u2460", "9" * 5000):
            with self.subTest(ch=ch[:5]):
                out = parse_clients([{"mac": "02:00:00:00:00:01", "channel": ch, "essid": "HomeNet"}], [])
                self.assertIsNone(out["02:00:00:00:00:01"].channel)
                self.assertEqual(out["02:00:00:00:00:01"].ssid, "HomeNet")
        out = parse_clients([{"mac": "02:00:00:00:00:01", "channel": 36}], [])
        self.assertEqual(out["02:00:00:00:00:01"].channel, 36)


if __name__ == "__main__":
    unittest.main()
