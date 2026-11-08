"""A controller that cannot report SSIDs (stats ssid_unavailable): the stored SSID, signal and radio are cleared."""
import unittest
from _env import FW1_ENV, clean_env, restore
from _fixtures import row
from leasewatch.config import Config
from leasewatch.connectors import Attachment, Batch, Sighting
from leasewatch.connectors.merge import MergeState, merge

NOW = 1_700_000_000
A = "02:00:00:00:20:01"


def arp():
    return Sighting(mac=A, source="fw1", kind="arp", presence=True, observed_at=NOW, ip="10.0.0.5", network="Clients", iface="opt3")


def att():
    return Attachment(mac=A, source="unifi", observed_at=NOW, link="wifi", ssid="", ap="ap-hall", present=True)


class SsidUnavailable(unittest.TestCase):
    def setUp(self):
        self._env = clean_env(FW1_ENV)

    def tearDown(self):
        restore(self._env)

    def run_merge(self, prev, stats):
        st = MergeState(controllers=frozenset({"unifi"}))
        batches = {"fw1": Batch(sightings=[arp()]), "unifi": Batch(attachments=[att()], stats=stats)}
        return merge({r["mac"]: r for r in prev}, batches, Config(), NOW, st)

    def stored(self):
        return row(A, link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-old", wifi_signal=-60, wifi_radio="5 GHz", loc_source="unifi")

    def wifi_events(self, res):
        return [e for e in res.events if e[1] == "wifi"]

    def test_stat_clears_stored_values_and_keeps_ap(self):
        res = self.run_merge([self.stored()], {"clients": 1, "ssid_unavailable": 1})
        r = res.rows[A]
        self.assertEqual((r["wifi_ssid"], r["wifi_signal"], r["wifi_radio"], r["wifi_ap"], r["link"]),
                         ("", None, "", "ap-hall", "wifi"))
        self.assertEqual(self.wifi_events(res), [(A, "wifi", "SSID unknown (controller reports none)")])
        self.assertEqual(res.wifi, [])

    def test_without_the_stat_the_stored_ssid_stays(self):
        res = self.run_merge([self.stored()], {"clients": 1})
        self.assertEqual(res.rows[A]["wifi_ssid"], "HomeNet")
        self.assertEqual(self.wifi_events(res), [])

    def test_second_poll_writes_no_event(self):
        first = self.run_merge([self.stored()], {"ssid_unavailable": 1})
        res = self.run_merge([first.rows[A]], {"ssid_unavailable": 1})
        self.assertEqual(self.wifi_events(res), [])
        self.assertEqual(res.rows[A]["wifi_ssid"], "")


if __name__ == "__main__":
    unittest.main()
