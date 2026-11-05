"""merge() called directly with Batch objects: (prev rows, batches, state) -> rows, events, history."""
import itertools, os, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
from leasewatch.config import Config
from leasewatch.connectors import Attachment, Batch, HostContext, Sighting
from leasewatch.connectors.merge import ROW_DEFAULTS, UPDATE_COLUMNS, ConnectorFailure, MergeState, merge
from leasewatch.connectors.snmp_switch import SnmpSwitchConnector
from leasewatch.switch import build_snapshot

NOW = 1_700_000_000
A, B = "02:00:00:00:00:01", "02:00:00:00:00:02"
CTRL = frozenset({"unifi"})


def S(mac, ip, host="", kind="dhcp", net="Clients", lt="dynamic", presence=True, vendor="Acme"):
    return Sighting(mac=mac, source="fw1", kind=kind, presence=presence, observed_at=NOW, ip=ip, hostname=host, vendor=vendor,
                    network=net, iface="opt3", lease_type=lt if kind == "dhcp" else "")


def arp(mac, ip="10.0.0.5", **kw):
    return S(mac, ip, kind="arp", **kw)


def row(mac, **kw):
    r = {"mac": mac, "first_seen": NOW - 5000, "last_seen": NOW - 60, "last_online": NOW - 60, "ip": "10.0.0.5", "hostname": "",
         "vendor": "Acme", "vlan": "Clients", "iface": "opt3", "lease_type": "", "sources": "arp", "online": 1, "baseline": 0,
         "acked": 0, "acked_at": None, "name": "", "note": "", **ROW_DEFAULTS}
    r.update(kw)
    return r


def port(mac, label, via="", uplink=False):
    return Attachment(mac=mac, source="switch", observed_at=NOW, link="wired", device="sw-rack", port=label, via=via, uplink=uplink)


def wifi(mac, ssid="HomeNet", ap="ap-hall", alias=""):
    return Attachment(mac=mac, source="unifi", observed_at=NOW, link="wifi", ssid=ssid, ap=ap, signal=-50, radio="5 GHz", alias=alias)


def ctl_wired(mac, alias=""):
    return Attachment(mac=mac, source="unifi", observed_at=NOW, link="wired", alias=alias)


def fw1(*sightings):
    return Batch(sightings=list(sightings), stats={"leases": 1, "arp": 1})


ON_WIFI = dict(link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall", wifi_signal=-50, wifi_radio="5 GHz")
FAILED = ConnectorFailure("unifi", "TimeoutError", NOW)

# name, prev rows, batches, state kwargs, expected row fields per mac (None = row not written), events, history macs
CASES = [
    ("dhcp gives hostname, arp gives online",
     [], {"fw1": fw1(S(A, "10.0.0.5", "phone", presence=False), arp(A))}, {},
     {A: dict(hostname="phone", online=1, sources="arp,dhcp", lease_type="dynamic", baseline=0, last_online=NOW)},
     [(A, "new", "10.0.0.5 phone Acme (Clients)")], [A]),
    ("first run is the baseline: no new event",
     [], {"fw1": fw1(arp(A))}, {"first_run": True},
     {A: dict(baseline=1, first_seen=NOW, online=1)}, [], [A]),
    ("new event text without hostname or vlan",
     [], {"fw1": fw1(S(A, "10.0.0.6", net="", vendor=""))}, {},
     {A: dict(ip="10.0.0.6", online=1)}, [(A, "new", "10.0.0.6")], [A]),
    ("ip change writes an event and a history row",
     [row(A)], {"fw1": fw1(arp(A, "10.0.0.6"))}, {},
     {A: dict(ip="10.0.0.6", last_seen=NOW, last_online=NOW)}, [(A, "ip", "10.0.0.5 -> 10.0.0.6")], [A]),
    ("missing device stays online within grace (row untouched)",
     [row(A)], {"fw1": fw1(arp(B, "10.0.0.9"))}, {},
     {A: None}, [(B, "new", "10.0.0.9 Acme (Clients)")], [B]),
    ("missing device goes offline after grace",
     [row(A, last_online=NOW - 700)], {"fw1": fw1(arp(B, "10.0.0.9"))}, {},
     {A: dict(online=0, last_online=NOW - 700, last_seen=NOW - 60)}, [(B, "new", "10.0.0.9 Acme (Clients)")], [B]),
    ("lease listed but gone from ARP: online in grace, last_online kept",
     [row(A, hostname="pc", lease_type="dynamic")], {"fw1": fw1(S(A, "10.0.0.5", "pc", presence=False))}, {},
     {A: dict(online=1, last_online=NOW - 60, last_seen=NOW)}, [], []),
    ("lease listed but gone from ARP: offline after grace",
     [row(A, hostname="pc", lease_type="dynamic", last_online=NOW - 700)], {"fw1": fw1(S(A, "10.0.0.5", "pc", presence=False))}, {},
     {A: dict(online=0)}, [], []),
    ("back after more than a day",
     [row(A, online=0, last_online=NOW - 86400 - 60)], {"fw1": fw1(arp(A))}, {},
     {A: dict(online=1, last_online=NOW)}, [(A, "back", "back after 1 day")], []),
    ("no back event after a failed poll",
     [row(A, online=0, last_online=NOW - 3 * 86400)], {"fw1": fw1(arp(A))}, {"prev_ok": False},
     {A: dict(online=1)}, [], []),
    ("keep: lease type stays without a lease",
     [row(A, lease_type="static")], {"fw1": fw1(arp(A))}, {},
     {A: dict(lease_type="static")}, [], []),
    ("wired -> wifi: the cable port is cleared",
     [row(A, sw_port="GE1/0/5", link="wired")], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/5")]),
                                                  "unifi": Batch(attachments=[wifi(A)])}, {"controllers": CTRL},
     {A: dict(sw_port="", sw_via="", link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall", wifi_signal=-50, wifi_radio="5 GHz")}, [], []),
    ("controller says wired: Wi-Fi details dropped, alias kept",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch(attachments=[ctl_wired(A, "laptop")])}, {"controllers": CTRL},
     {A: dict(link="wired", wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", wifi_alias="laptop")}, [], []),
    ("controller answered without the client: left Wi-Fi, cable port shown",
     [row(A, wifi_alias="laptop", **ON_WIFI)], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/5")]),
                                                "unifi": Batch()}, {"controllers": CTRL},
     {A: dict(link="wired", wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", wifi_alias="laptop", sw_port="GE1/0/5")}, [], []),
    ("controller answered without the client, not in the FDB: link unknown",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch()}, {"controllers": CTRL},
     {A: dict(link="", wifi_ssid="")}, [], []),
    ("controller failed (blind): no AP uplink port for a Wi-Fi device",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/5", "ap-hall", True)]), "unifi": FAILED},
     {"controllers": CTRL},
     {A: dict(sw_port="", link="wifi", wifi_ssid="HomeNet")}, [], []),
    ("controller failed: a wired device still gets its port",
     [row(A, link="wired", sw_port="GE1/0/3")], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/5")]), "unifi": FAILED},
     {"controllers": CTRL},
     {A: dict(sw_port="GE1/0/5", link="wired")}, [(A, "port", "GE1/0/3 -> GE1/0/5")], []),
    ("device in grace keeps its SSID and gets no FDB port",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(B, "10.0.0.9")), "switch": Batch(attachments=[port(A, "GE1/0/5", "ap-hall", True)]),
                           "unifi": Batch()}, {"controllers": CTRL},
     {A: None}, [(B, "new", "10.0.0.9 Acme (Clients)")], [B]),
    ("lease listed without ARP keeps its SSID",
     [row(A, lease_type="dynamic", **ON_WIFI)], {"fw1": fw1(S(A, "10.0.0.5", presence=False)), "unifi": Batch()},
     {"controllers": CTRL},
     {A: dict(online=1, link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall")}, [], []),
    ("port move event with via",
     [row(A, link="wired", sw_port="GE1/0/3")], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/9", "sw-2", True)])}, {},
     {A: dict(sw_port="GE1/0/9", sw_via="sw-2")}, [(A, "port", "GE1/0/3 -> GE1/0/9 via sw-2")], []),
    ("first port: no event, link wired",
     [row(A)], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/3")])}, {},
     {A: dict(sw_port="GE1/0/3", link="wired")}, [], []),
    ("switch failed: port and link kept",
     [row(A, link="wired", sw_port="GE1/0/3")], {"fw1": fw1(arp(A)), "switch": ConnectorFailure("switch", "x", NOW)}, {},
     {A: dict(sw_port="GE1/0/3", link="wired")}, [], []),
    ("roaming to another AP writes a wifi event",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch(attachments=[wifi(A, ap="ap-attic")])}, {"controllers": CTRL},
     {A: dict(wifi_ap="ap-attic", link="wifi")}, [(A, "wifi", "HomeNet @ ap-hall -> HomeNet @ ap-attic")], []),
]


class MergeTableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({"FW1_KEY": "k", "FW1_SECRET": "s", "DATA_DIR": self.tmp.name})

    def tearDown(self): self.tmp.cleanup(); restore(self._env)

    def run_merge(self, prev, batches, cfg=None, **state):
        return merge({r["mac"]: r for r in prev}, batches, cfg or Config(), NOW, MergeState(**state))

    def test_cases(self):
        for name, prev, batches, state, want, events, history in CASES:
            with self.subTest(name):
                res = self.run_merge(prev, batches, **state)
                for mac, fields in want.items():
                    if fields is None:
                        self.assertNotIn(mac, res.rows)
                    else:
                        self.assertEqual({k: res.rows[mac][k] for k in fields}, fields)
                self.assertEqual(res.events, events)
                self.assertEqual([m for m, _ in res.history], history)
                self.assertEqual(res.new, [m for m, k, _ in events if k == "new"])

    def test_stats_and_history_values(self):
        res = self.run_merge([row(A, hostname="pc", lease_type="dynamic")], {"fw1": fw1(S(A, "10.0.0.6", "pc"), arp(A, "10.0.0.6"), arp(B, "10.0.0.9"))})
        self.assertEqual(res.stats, {"devices": 2, "new": 1, "changed": 1})
        self.assertEqual(res.history[0], (A, {"ip": "10.0.0.6", "hostname": "pc", "vlan": "Clients", "lease_type": "dynamic"}))

    def test_user_fields_are_never_written(self):
        res = self.run_merge([row(A, name="Kitchen TV", note="n", acked=1)], {"fw1": fw1(arp(A, "10.0.0.6"))})
        self.assertEqual((res.rows[A]["name"], res.rows[A]["note"], res.rows[A]["acked"]), ("Kitchen TV", "n", 1))
        self.assertFalse({"name", "note", "acked", "acked_at", "baseline", "first_seen"} & set(UPDATE_COLUMNS))

    def test_lease_type_modes(self):
        for mode, nls, lt, events, left in [("immediate", {}, "", [(A, "lease_type", "static -> no DHCP")], {}),
                                            ("grace", {}, "static", [], {A: NOW}),
                                            ("grace", {A: NOW - 600}, "", [(A, "lease_type", "static -> no DHCP")], {})]:
            with self.subTest(mode=mode, nls=nls):
                os.environ["LEASE_TYPE_MODE"] = mode
                nls = dict(nls)
                res = self.run_merge([row(A, lease_type="static")], {"fw1": fw1(arp(A))}, no_lease_since=nls)
                self.assertEqual((res.rows[A]["lease_type"], res.events, nls), (lt, events, left))
        res = self.run_merge([row(A, lease_type="static")], {"fw1": fw1(S(A, "10.0.0.5", lt="static"), arp(A))}, no_lease_since=nls)
        self.assertEqual(nls, {})  # a lease again resets the grace clock

    def test_order_independent(self):
        rows = [S(A, "10.0.0.5", "pc", presence=False), arp(A, "10.0.0.5"), arp(A, "10.0.1.5", net="Servers"), S(B, "10.0.0.9", "tv")]
        results = {tuple(sorted((m, r["ip"], r["vlan"], r["hostname"]) for m, r in self.run_merge([], {"fw1": fw1(*p)}).rows.items()))
                   for p in itertools.permutations(rows)}
        self.assertEqual(results, {((A, "10.0.0.5", "Clients", "pc"), (B, "10.0.0.9", "Clients", "tv"))})

    def test_no_clock_and_prev_untouched(self):
        prev = {A: row(A)}
        snapshot = {A: dict(prev[A])}
        with mock.patch("time.time", side_effect=AssertionError("merge read the clock")):
            merge(prev, {"fw1": fw1(arp(A, "10.0.0.6"))}, Config(), NOW, MergeState())
        self.assertEqual(prev, snapshot)

    def test_infra_naming_of_an_unnamed_uplink(self):
        # port 9 has 7 MACs and no LLDP neighbour: an uplink; one of them is a device the host knows as "ap-hall"
        ap, phone = "02:00:00:00:00:0a", A
        fdb = [("1.2.0.0.0.0.10", 9), ("1.2.0.0.0.0.1", 9)] + [(f"1.2.0.0.0.1.{i}", 9) for i in range(5)]
        snap = lambda: build_snapshot(fdb, [("9", 9)], [("9", "GigabitEthernet1/0/9")], [])
        for names, via in [({ap: "ap-hall", phone: "Alex's iPad"}, "ap-hall"), ({ap: "Kitchen TV"}, "7 devices"), ({}, "7 devices")]:
            with self.subTest(names=names):
                ctx = HostContext(now=lambda: NOW, device_names=lambda names=names: names)
                b = SnmpSwitchConnector("switch", {"host": "10.0.0.2", "name": "sw-rack"}, ctx,
                                        client=type("W", (), {"snapshot": lambda self: snap()})()).collect()
                self.assertEqual({a.via for a in b.attachments}, {via})
                res = self.run_merge([row(phone, link="wired")], {"fw1": fw1(arp(phone)), "switch": b})
                self.assertEqual((res.rows[phone]["sw_port"], res.rows[phone]["sw_via"]), ("GE1/0/9", via))


if __name__ == "__main__":
    unittest.main()
