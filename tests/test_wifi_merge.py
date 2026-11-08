"""The merge returns this poll's Wi-Fi observations: (device key, ssid, ap), one per device, from answered controllers."""
import unittest
from _env import FW1_ENV, clean_env, restore
from _fixtures import row
from leasewatch.config import Config
from leasewatch.connectors import Attachment, Batch, Sighting
from leasewatch.connectors.merge import ConnectorFailure, MergeState, merge

NOW = 1_700_000_000
A = "02:00:00:00:20:01"
ALIAS = "06:00:00:00:20:02"
CTRL = frozenset({"unifi", "unifi2"})


def arp(mac=A, ip="10.0.0.5"):
    return Sighting(mac=mac, source="fw1", kind="arp", presence=True, observed_at=NOW, ip=ip, network="Clients", iface="opt3")


def att(mac=A, link="wifi", ssid="HomeNet", ap="ap-hall", source="unifi"):
    return Attachment(mac=mac, source=source, observed_at=NOW, link=link, ssid=ssid, ap=ap)


class WifiObservations(unittest.TestCase):
    def setUp(self):
        self._env = clean_env(FW1_ENV)

    def tearDown(self):
        restore(self._env)

    def run_merge(self, prev, batches, aliases=None):
        st = MergeState(controllers=CTRL, aliases=dict(aliases or {}))
        return merge({r["mac"]: r for r in prev}, batches, Config(), NOW, st)

    def test_client_on_an_ssid_gives_one_entry(self):
        res = self.run_merge([row(A)], {"fw1": Batch(sightings=[arp()]), "unifi": Batch(attachments=[att()])})
        self.assertEqual(res.wifi, [(A, "HomeNet", "ap-hall")])

    def test_wired_client_and_empty_ssid_give_none(self):
        res = self.run_merge([row(A)], {"fw1": Batch(sightings=[arp()]),
                                        "unifi": Batch(attachments=[att(link="wired", ssid="")])})
        self.assertEqual(res.wifi, [])
        res = self.run_merge([row(A, wifi_ssid="HomeNet", link="wifi")],
                             {"fw1": Batch(sightings=[arp()]), "unifi": Batch(attachments=[att(ssid="")])})
        self.assertEqual(res.wifi, [])
        self.assertEqual(res.rows[A]["wifi_ssid"], "HomeNet")

    def test_mac_without_a_device_row_gives_none(self):
        res = self.run_merge([], {"unifi": Batch(attachments=[att()])})
        self.assertEqual(res.wifi, [])

    def test_alias_mac_lands_on_the_device_key(self):
        res = self.run_merge([row(A, online=0)], {"fw1": Batch(sightings=[arp(ALIAS, "10.0.0.9")]),
                                                  "unifi": Batch(attachments=[att(ALIAS)])}, aliases={ALIAS: A})
        self.assertEqual(res.wifi, [(A, "HomeNet", "ap-hall")])

    def test_two_controllers_give_the_first_instance_only(self):
        res = self.run_merge([row(A)], {"fw1": Batch(sightings=[arp()]),
                                        "unifi": Batch(attachments=[att(ssid="One", ap="ap-1")]),
                                        "unifi2": Batch(attachments=[att(ssid="Two", ap="ap-2", source="unifi2")])})
        self.assertEqual(res.wifi, [(A, "One", "ap-1")])

    def test_blind_controller_keeps_the_stored_ssid_without_an_entry(self):
        prev = row(A, wifi_ssid="HomeNet", wifi_ap="ap-hall", link="wifi", loc_source="unifi")
        res = self.run_merge([prev], {"fw1": Batch(sightings=[arp()]), "unifi": ConnectorFailure("unifi", "TimeoutError", NOW)})
        self.assertEqual(res.rows[A]["wifi_ssid"], "HomeNet")
        self.assertEqual(res.wifi, [])

    def test_failed_second_controller_does_not_hide_the_first(self):
        res = self.run_merge([row(A)], {"fw1": Batch(sightings=[arp()]), "unifi": Batch(attachments=[att()]),
                                        "unifi2": ConnectorFailure("unifi2", "TimeoutError", NOW)})
        self.assertEqual(res.wifi, [(A, "HomeNet", "ap-hall")])

    def test_roam_carries_the_new_ap_and_no_event(self):
        prev = row(A, wifi_ssid="HomeNet", wifi_ap="ap-hall", link="wifi", loc_source="unifi")
        res = self.run_merge([prev], {"fw1": Batch(sightings=[arp()]),
                                      "unifi": Batch(attachments=[att(ap="ap-attic")])})
        self.assertEqual(res.wifi, [(A, "HomeNet", "ap-attic")])
        self.assertFalse([e for e in res.events if e[1] == "wifi"])

    def test_ssid_change_keeps_its_event_and_gives_the_new_ssid(self):
        prev = row(A, wifi_ssid="HomeNet", wifi_ap="ap-hall", link="wifi", loc_source="unifi")
        res = self.run_merge([prev], {"fw1": Batch(sightings=[arp()]), "unifi": Batch(attachments=[att(ssid="Guest")])})
        self.assertIn((A, "wifi", "HomeNet -> Guest"), res.events)
        self.assertEqual(res.wifi, [(A, "Guest", "ap-hall")])


if __name__ == "__main__":
    unittest.main()
