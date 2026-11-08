"""devices.label: the migration, the merge write, and the rows the API and the CSV read."""
import sqlite3
import unittest

from _case import EnvTmpCase
from leasewatch.collector import Collector
from leasewatch.config import Config
from leasewatch.fw1 import Sighting
from leasewatch.db import Database
from leasewatch.web import _dev

MAC = "00:00:5e:00:53:41"


def sight(label: str = "", host: str = "") -> Sighting:
    return Sighting(mac=MAC, ip="10.0.1.41", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan", source="dhcp",
                    lease_type="static", online=True, label=label)


class Client:
    def __init__(self, sightings: list) -> None:
        self.data = sightings
        self.extra: dict = {}

    def arp_raw(self) -> list:
        return []

    def sightings(self, ignore: tuple = ()) -> tuple:
        return list(self.data), {"leases": len(self.data), "arp": 0, **self.extra}


class LabelStoreTests(EnvTmpCase):
    def setUp(self) -> None:
        super().setUp()
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

    def test_poll_with_reservations_unavailable_keeps_the_stored_label(self) -> None:
        db = self.open_db()
        client = Client([sight("Kitchen shelf plug")])
        col = Collector(self.cfg, db, client)
        col.run_once()
        client.data, client.extra = [sight("")], {"labels_unavailable": 1}
        col.run_once()
        self.assertEqual(db.device(MAC)["label"], "Kitchen shelf plug")
        client.extra = {}  # the search answers again and the description is gone
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
