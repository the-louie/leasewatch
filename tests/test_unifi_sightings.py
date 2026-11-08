"""The UniFi connector's client sightings: the controller's hostname and vendor per client (session rows only)."""
from __future__ import annotations

import unittest

import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from leasewatch.connectors import HostContext
from leasewatch.connectors.unifi import UnifiConnector, to_sightings
from leasewatch.unifi import UnifiKeyClient, WifiInfo, parse_clients

STA = [
    {"mac": "02:00:00:00:00:31", "hostname": " laptop-a ", "oui": " Example Corp ", "essid": "lan", "is_wired": False},
    {"mac": "02:00:00:00:00:32", "essid": "lan"},
    {"mac": "02:00:00:00:00:33", "hostname": "", "oui": None, "is_wired": True},
]
BASE = {"url": "https://unifi.example.lan", "user": "ro", "password": "pw"}


class StubClient:
    def clients(self):
        return parse_clients(STA, [])


class KeyStub(UnifiKeyClient):
    def __init__(self):
        pass

    def clients(self, parsed=None):
        return {"02:00:00:00:00:34": WifiInfo(alias="x")}


def conn(client, **kw):
    return UnifiConnector("unifi", {**BASE, **kw}, HostContext(now=lambda: 1700000000), client=client)


class Parse(unittest.TestCase):
    def test_hostname_and_oui_kept_stripped(self):
        out = parse_clients(STA, [])
        a = out["02:00:00:00:00:31"]
        self.assertEqual((a.hostname, a.oui), ("laptop-a", "Example Corp"))

    def test_absent_is_empty(self):
        out = parse_clients(STA, [])
        for mac in ("02:00:00:00:00:32", "02:00:00:00:00:33"):
            self.assertEqual((out[mac].hostname, out[mac].oui), ("", ""))


class Sightings(unittest.TestCase):
    def test_shape(self):
        out = to_sightings(parse_clients(STA, []), "ctl", 5)
        self.assertEqual(len(out), 1)
        s = out[0]
        self.assertEqual((s.mac, s.source, s.kind, s.presence, s.observed_at, s.ip, s.hostname, s.vendor),
                         ("02:00:00:00:00:31", "ctl", "client", False, 5, "", "laptop-a", "Example Corp"))

    def test_oui_alone_is_enough(self):
        out = to_sightings({"02:00:00:00:00:35": WifiInfo(oui="Example Corp")}, "ctl", 5)
        self.assertEqual([(s.hostname, s.vendor) for s in out], [("", "Example Corp")])


class Collect(unittest.TestCase):
    def test_session_mode_emits(self):
        b = conn(StubClient()).collect()
        self.assertEqual([s.mac for s in b.sightings], ["02:00:00:00:00:31"])
        self.assertEqual(len(b.attachments), 3)

    def test_hostnames_off_emits_none(self):
        b = conn(StubClient(), hostnames="0").collect()
        self.assertEqual(b.sightings, [])
        self.assertEqual(len(b.attachments), 3)

    def test_key_mode_emits_none(self):
        b = conn(KeyStub(), auth="apikey", api_key="k", user="", password="").collect()
        self.assertEqual(b.sightings, [])
        self.assertEqual(len(b.attachments), 1)

    def test_validate(self):
        self.assertEqual(conn(StubClient()).validate(), [])
        self.assertIn("hostnames must be a boolean (1/0, true/false, yes/no, on/off)",
                      [p.split(": ")[-1] for p in conn(StubClient(), hostnames="maybe").validate()])


if __name__ == "__main__":
    unittest.main()
