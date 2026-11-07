"""devices.label: the migration, the merge write, and the rows the API and the CSV read."""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from leasewatch.collector import Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.fw1 import Sighting  # noqa: E402
from leasewatch.db import Database  # noqa: E402
from leasewatch.web import _dev  # noqa: E402

MAC = "00:00:5e:00:53:41"


def sight(label: str = "", host: str = "") -> Sighting:
    return Sighting(mac=MAC, ip="10.0.1.41", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan", source="dhcp",
                    lease_type="static", online=True, label=label)


class Client:
    def __init__(self, sightings: list) -> None:
        self.data = sightings

    def arp_raw(self) -> list:
        return []

    def sightings(self, ignore: tuple = ()) -> tuple:
        return list(self.data), {"leases": len(self.data), "arp": 0}


class LabelStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        self.addCleanup(restore, self._env)
        self.cfg = Config()

    def open_db(self) -> Database:
        db = Database(self.cfg.db_path)
        self.addCleanup(db._conn.close)
        return db

    def test_migration_adds_the_column_to_an_older_file(self) -> None:
        db = self.open_db()
        db.q("INSERT INTO devices(mac, first_seen, last_seen) VALUES(?,1,1)", (MAC,))
        db._conn.close()
        con = sqlite3.connect(self.cfg.db_path)
        con.execute("ALTER TABLE devices DROP COLUMN label")
        con.commit()
        con.close()
        db = self.open_db()
        self.assertEqual(dict(db.q("SELECT label FROM devices")[0]), {"label": ""})

    def test_poll_stores_label_and_it_follows_the_source(self) -> None:
        db = self.open_db()
        client = Client([sight("")])
        col = Collector(self.cfg, db, client)
        col.run_once()
        self.assertEqual(db.device(MAC)["label"], "")
        client.data = [sight("Kitchen shelf plug")]
        col.run_once()
        self.assertEqual(db.device(MAC)["label"], "Kitchen shelf plug")
        # the label follows the source: a poll whose DHCP sighting has none clears it
        client.data = [sight("")]
        col.run_once()
        self.assertEqual(db.device(MAC)["label"], "")

    def test_label_change_makes_no_event(self) -> None:
        db = self.open_db()
        client = Client([sight("")])
        col = Collector(self.cfg, db, client)
        col.run_once()
        client.data = [sight("Plug")]
        col.run_once()
        self.assertEqual([e["kind"] for e in db.events(MAC)], [])

    def test_api_row_carries_label_(self) -> None:
        db = self.open_db()
        Collector(self.cfg, db, Client([sight("Plug")])).run_once()
        self.assertEqual(_dev(db.devices()[0])["label"], "Plug")


if __name__ == "__main__":
    unittest.main()
