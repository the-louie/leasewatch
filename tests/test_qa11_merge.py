"""Regression tests for the QA 1.1 merge findings: normalise_batch coercion, lease and location fallbacks, attachments."""
import logging, os, sqlite3, sys, tempfile, unittest
from dataclasses import dataclass
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore
from leasewatch.config import Config
from leasewatch.connectors import Attachment, Batch, Sighting
from leasewatch.connectors.merge import (ROW_DEFAULTS, ConnectorFailure, MergeState, merge, merge_sightings,
                                         normalise_batch)
from leasewatch.fw1 import Sighting as Fw1Sighting

NOW = 1_700_000_000
A = "02:00:00:00:00:01"
CTRL = frozenset({"unifi"})


def row(mac, **kw):
    r = {"mac": mac, "first_seen": NOW - 5000, "last_seen": NOW - 60, "last_online": NOW - 60, "ip": "10.0.0.5", "hostname": "",
         "vendor": "Acme", "vlan": "Clients", "iface": "opt3", "lease_type": "", "sources": "arp", "online": 1, "baseline": 0,
         "acked": 0, "acked_at": None, "name": "", "note": "", **ROW_DEFAULTS}
    r.update(kw)
    return r


def sight(mac=A, ip="10.0.0.5", kind="arp", presence=True, **kw):
    return Sighting(mac=mac, source="fw1", kind=kind, presence=presence, observed_at=NOW, ip=ip, network=kw.pop("network", "Clients"),
                    iface=kw.pop("iface", "opt3"), **kw)


def wifi(mac=A, ssid="HomeNet", ap="ap-hall", **kw):
    return Attachment(mac=mac, source="unifi", observed_at=NOW, link="wifi", ssid=ssid, ap=ap, **kw)


def swp(mac, label, source, uplink=False, via=""):
    return Attachment(mac=mac, source=source, observed_at=NOW, link="wired", device=source, port=label, via=via, uplink=uplink)


class Base(unittest.TestCase):
    def setUp(self):
        self._env = clean_env(FW1_ENV)
        self.cfg = Config()

    def tearDown(self):
        restore(self._env)

    def merge(self, prev, batches, **st):
        return merge({r["mac"]: r for r in prev}, batches, self.cfg, NOW, MergeState(**st))


class Coerce(Base):
    def test_R01_R02_huge_numbers_become_none_and_the_row_writes(self):
        for sig in ("1e30", 1e30, 2 ** 63, -(2 ** 64)):
            b = normalise_batch("unifi", Batch(attachments=[wifi(signal=sig, vlan=sig)]))
            self.assertIsNone(b.attachments[0].signal, sig)
            self.assertIsNone(b.attachments[0].vlan, sig)
        b = normalise_batch("unifi", Batch(attachments=[wifi(signal=2 ** 62)]))
        self.assertEqual(b.attachments[0].signal, 2 ** 62)
        b = normalise_batch("x", Batch(sightings=[Sighting(mac=A, source="", kind="arp", presence=True, observed_at=1e30)]))
        self.assertEqual(b.sightings[0].observed_at, 0)
        res = self.merge([], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi(signal="1e30")])},
                         controllers=CTRL)
        with sqlite3.connect(":memory:") as c:
            c.execute("CREATE TABLE t (v INTEGER)")
            c.execute("INSERT INTO t VALUES (?)", (res.rows[A]["wifi_signal"],))  # raised OverflowError before
        c.close()

    def test_R127_subclass_records_are_coerced_not_raised(self):
        @dataclass(frozen=True)
        class MySighting(Sighting):
            pass
        b = normalise_batch("x", Batch(sightings=[MySighting(mac="AA:BB:CC:DD:EE:FF", source="", kind="arp", presence=True,
                                                             observed_at=0, hostname=None)]))
        self.assertEqual(len(b.sightings), 1)
        self.assertEqual(b.sightings[0].hostname, "")
        self.assertEqual(b.sightings[0].source, "x")

    def test_R128_field_whose_str_or_bool_raises_drops_the_record(self):
        class Amb:
            def __bool__(self):
                raise ValueError("ambiguous")
        logging.disable(logging.WARNING)
        try:
            for kw in (dict(hostname=10 ** 5000), dict(presence=Amb())):
                b = normalise_batch("x", Batch(sightings=[Sighting(**{**dict(mac=A, source="", kind="dhcp", presence=True,
                                                                             observed_at=0), **kw}),
                                                          sight(mac="02:00:00:00:00:02")]))
                self.assertEqual([s.mac for s in b.sightings], ["02:00:00:00:00:02"])
                self.assertEqual(b.stats["dropped"], 1)
        finally:
            logging.disable(logging.NOTSET)

    def test_S08x_lone_surrogate_is_replaced_and_the_row_writes(self):
        b = normalise_batch("fw1", Batch(sightings=[sight(kind="dhcp", hostname="phone-\ud83d", lease_type="dynamic")]))
        host = b.sightings[0].hostname
        host.encode("utf-8")  # raised UnicodeEncodeError before
        self.assertEqual(host, "phone-?")
        b = normalise_batch("unifi", Batch(attachments=[wifi(ssid="Home\udc00Net")]))
        b.attachments[0].ssid.encode("utf-8")

    def test_S09x_bidi_controls_removed_from_connector_strings(self):
        b = normalise_batch("fw1", Batch(sightings=[sight(kind="dhcp", hostname="bad‮", lease_type="dynamic")]))
        self.assertEqual(b.sightings[0].hostname, "bad")
        res = self.merge([row(A, hostname="sonos")], {"fw1": Batch(sightings=[sight(kind="dhcp", hostname="bad⁦x")])})
        self.assertIn((A, "hostname", "sonos -> badx"), res.events)

    def test_S33x_ssid_ap_alias_keep_edge_whitespace(self):
        b = normalise_batch("unifi", Batch(attachments=[wifi(ssid="Guest ", ap=" ap-hall", alias="laptop ")]))
        a = b.attachments[0]
        self.assertEqual((a.ssid, a.ap, a.alias), ("Guest ", " ap-hall", "laptop "))
        res = self.merge([row(A, link="wifi", wifi_ssid="Guest", wifi_ap="ap-hall", loc_source="unifi")],
                         {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi(ssid="Guest ")])},
                         controllers=CTRL)
        self.assertEqual(res.rows[A]["wifi_ssid"], "Guest ")
        self.assertEqual([e[1] for e in res.events], ["wifi"])

    def test_S34x_kind_is_case_folded(self):
        b = normalise_batch("x", Batch(sightings=[sight(kind="DHCP", hostname="h", lease_type="static")]))
        self.assertEqual(b.sightings[0].kind, "dhcp")
        res = self.merge([], {"x": b}, first_run=True)
        self.assertEqual(res.rows[A]["lease_type"], "static")

    def test_S35x_string_flags_are_parsed_not_truthy(self):
        b = normalise_batch("x", Batch(sightings=[sight(kind="dhcp", presence="false")],
                                       attachments=[Attachment(mac=A, source="", observed_at=NOW, link="wired", port="1",
                                                               uplink="no", present="0")]))
        self.assertIs(b.sightings[0].presence, False)
        self.assertIs(b.attachments[0].uplink, False)
        self.assertIs(b.attachments[0].present, False)
        b = normalise_batch("x", Batch(sightings=[sight(presence="yes"), sight(mac="02:00:00:00:00:02", presence=1)]))
        self.assertEqual([s.presence for s in b.sightings], [True, True])
        res = self.merge([], {"x": normalise_batch("x", Batch(sightings=[sight(kind="dhcp", presence="false")]))})
        self.assertEqual(res.rows[A]["online"], 0)


class Sightings(Base):
    def test_R34_empty_ip_lease_does_not_pick_an_empty_ip_arp_row(self):
        mk = lambda ip, vlan, iface, src, lt="", online=True: Fw1Sighting(mac=A, ip=ip, hostname="", vendor="", vlan=vlan,
                                                                          iface=iface, source=src, lease_type=lt, online=online)
        m = merge_sightings([mk("", "LAN", "opt1", "dhcp", "static", False), mk("10.0.0.5", "LAN", "opt1", "arp"),
                             mk("", "IOT", "opt2", "arp")])[A]
        self.assertEqual((m.ip, m.vlan, m.iface), ("10.0.0.5", "LAN", "opt1"))

    def test_R35_failed_instance_does_not_clear_lease_type(self):
        self._env2 = clean_env({**FW1_ENV, "LEASE_TYPE_MODE": "immediate"})
        try:
            self.cfg = Config()
        finally:
            restore(self._env2)
        prev = [row(A, lease_type="static", sources="arp,dhcp")]
        res = self.merge(prev, {"fwA": ConnectorFailure("fwA", "TimeoutError", NOW), "fwB": Batch(sightings=[sight()])})
        self.assertEqual(res.events, [])
        self.assertEqual(res.history, [])
        self.assertEqual(res.rows[A]["lease_type"], "static")
        # every instance answered and none has a lease: cleared as before
        res = self.merge(prev, {"fwA": Batch(), "fwB": Batch(sightings=[sight()])})
        self.assertEqual(res.rows[A]["lease_type"], "")
        # a failed Wi-Fi controller lists no leases: it does not hold the clearing back
        res = self.merge(prev, {"fwB": Batch(sightings=[sight()]), "unifi": ConnectorFailure("unifi", "TimeoutError", NOW)},
                         controllers=CTRL)
        self.assertEqual(res.rows[A]["lease_type"], "")

    def test_S10x_moved_location_is_taken_as_one_unit(self):
        prev = [row(A, ip="10.0.10.5", vlan="LAN", iface="opt1", lease_type="static")]
        res = self.merge(prev, {"fw1": Batch(sightings=[sight(ip="10.0.30.9", kind="dhcp", presence=False, network="", iface="",
                                                              lease_type="static")])})
        r = res.rows[A]
        self.assertEqual((r["ip"], r["vlan"], r["iface"]), ("10.0.30.9", "", ""))
        self.assertEqual(res.history[0][1]["vlan"], "")
        res = self.merge(prev, {"fw1": Batch(sightings=[sight(ip="10.0.30.9", kind="dhcp", presence=False, network="IOT", iface="",
                                                              lease_type="static")])})
        r = res.rows[A]
        self.assertEqual((r["ip"], r["vlan"], r["iface"]), ("10.0.30.9", "IOT", ""))
        # same place, a sighting without the network: the stored values stay
        res = self.merge(prev, {"fw1": Batch(sightings=[sight(ip="10.0.10.5", network="", iface="")])})
        r = res.rows[A]
        self.assertEqual((r["ip"], r["vlan"], r["iface"]), ("10.0.10.5", "LAN", "opt1"))


class Attachments(Base):
    def test_R36_move_to_same_label_on_another_switch_writes_a_port_event(self):
        prev = [row(A, link="wired", sw_port="GE1/0/14", loc_source="swA")]
        res = self.merge(prev, {"fw1": Batch(sightings=[sight()]), "swA": Batch(attachments=[swp("02:00:00:00:00:09", "GE1/0/2", "swA")]),
                                "swB": Batch(attachments=[swp(A, "GE1/0/14", "swB")])})
        self.assertEqual(res.rows[A]["loc_source"], "swB")
        self.assertEqual([e for e in res.events if e[0] == A], [(A, "port", "GE1/0/14 (swA) -> GE1/0/14 (swB)")])
        # held by the same switch: no event
        res = self.merge(prev, {"fw1": Batch(sightings=[sight()]), "swA": Batch(attachments=[swp(A, "GE1/0/14", "swA")])})
        self.assertEqual(res.events, [])

    def test_R37_empty_ssid_keeps_the_stored_ssid_and_the_next_ssid_change_is_logged(self):
        prev = row(A, link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall", loc_source="unifi")
        res = self.merge([prev], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi(ssid="")])},
                         controllers=CTRL)
        self.assertEqual(res.rows[A]["wifi_ssid"], "HomeNet")
        res = self.merge([res.rows[A]], {"fw1": Batch(sightings=[sight()]),
                                         "unifi": Batch(attachments=[wifi(ssid="GuestNet", ap="ap-office")])},
                         controllers=CTRL)
        self.assertEqual(res.events, [(A, "wifi", "HomeNet -> GuestNet")])

    def test_R38_device_in_grace_gets_no_wired_link_from_the_fdb(self):
        prev = [row(A, lease_type="dynamic")]
        for uplink in (True, False):
            res = self.merge(prev, {"fw1": Batch(sightings=[sight(kind="dhcp", presence=False, lease_type="dynamic")]),
                                    "sw1": Batch(attachments=[swp(A, "GE1/0/48", "sw1", uplink=uplink, via="core")])})
            r = res.rows[A]
            self.assertEqual((r["online"], r["link"], r["sw_port"]), (1, "", ""), uplink)

    def test_S11x_empty_port_label_does_not_win_the_ranking(self):
        res = self.merge([], {"fw1": Batch(sightings=[sight()]), "swA": Batch(attachments=[swp(A, "", "swA")]),
                              "swB": Batch(attachments=[swp(A, "GE1/0/7", "swB", uplink=True, via="7 devices")])})
        r = res.rows[A]
        self.assertEqual((r["sw_port"], r["sw_via"], r["link"], r["loc_source"]), ("GE1/0/7", "7 devices", "wired", "swB"))
        # only an empty label: still wired, no port
        res = self.merge([], {"fw1": Batch(sightings=[sight()]), "swA": Batch(attachments=[swp(A, "", "swA")])})
        self.assertEqual((res.rows[A]["link"], res.rows[A]["sw_port"]), ("wired", ""))

    def test_S36x_S37x_batch_with_dropped_records_is_not_a_complete_answer(self):
        logging.disable(logging.WARNING)
        try:
            prev = [row(A, link="wifi", wifi_ssid="Home", wifi_ap="ap-hall", loc_source="unifi")]
            for bad in (Batch(attachments=None), Batch(attachments=[{"mac": A}])):
                # the collector normalises first, merge again: the dropped count must survive both
                res = self.merge(prev, {"fw1": Batch(sightings=[sight()]),
                                        "unifi": normalise_batch("unifi", bad),
                                        "sw": Batch(attachments=[swp(A, "GE1/0/1", "sw", uplink=True, via="ap-hall")])},
                                 controllers=CTRL)
                r = res.rows[A]
                self.assertEqual((r["link"], r["wifi_ssid"], r["sw_port"], r["loc_source"]), ("wifi", "Home", "", "unifi"))
            prev = [row(A, link="wired", sw_port="GE1/0/14", loc_source="swA")]
            res = self.merge(prev, {"fw1": Batch(sightings=[sight()]), "swA": normalise_batch("swA", Batch(attachments=None)),
                                    "swB": Batch(attachments=[swp(A, "GE1/0/48", "swB", uplink=True, via="swA")])})
            self.assertEqual((res.rows[A]["sw_port"], res.rows[A]["loc_source"]), ("GE1/0/14", "swA"))
            self.assertEqual(res.events, [])
        finally:
            logging.disable(logging.NOTSET)


class Round2(Base):
    """QA 1.1 round 2 (V-rows): merge findings left after the round-1 fixes."""

    def _mode(self, mode):
        env = clean_env({**FW1_ENV, "LEASE_TYPE_MODE": mode})
        try:
            self.cfg = Config()
        finally:
            restore(env)

    def test_V05_failed_switch_does_not_hold_back_lease_type_clearing(self):
        self._mode("immediate")
        prev = [row(A, lease_type="static", sources="arp,dhcp")]
        batches = {"fw1": Batch(sightings=[sight()]), "sw": ConnectorFailure("sw", "SNMP timeout", NOW)}
        res = self.merge(prev, batches, producers=frozenset({"fw1"}))
        self.assertEqual(res.rows[A]["lease_type"], "")
        self.assertIn((A, "lease_type", "static -> no DHCP"), res.events)
        # a failed sighting producer still holds it back
        res = self.merge(prev, {**batches, "fw2": ConnectorFailure("fw2", "TimeoutError", NOW)},
                         producers=frozenset({"fw1", "fw2"}))
        self.assertEqual(res.rows[A]["lease_type"], "static")

    def test_V29_drop_warning_names_an_unconvertible_field(self):
        class Bad:
            def __str__(self):
                raise RuntimeError("str")
        with self.assertLogs("leasewatch.merge", logging.WARNING) as cm:
            normalise_batch("v29", Batch(sightings=[sight(kind="dhcp", hostname=Bad())]))
        self.assertIn("field", cm.output[0])

    def test_V54_empty_ip_lease_does_not_hide_a_client_ip(self):
        mk = lambda ip, vlan, iface, src, lt="", online=True: Fw1Sighting(mac=A, ip=ip, hostname="r" if src == "dhcp" else "",
                                                                          vendor="", vlan=vlan, iface=iface, source=src,
                                                                          lease_type=lt, online=online)
        ss = [mk("", "LAN", "opt1", "dhcp", "static", False), mk("10.0.0.7", "WIFI", "opt2", "client")]
        for order in (ss, ss[::-1]):
            m = merge_sightings(order)[A]
            self.assertEqual((m.ip, m.vlan, m.iface, m.hostname, m.lease_type), ("10.0.0.7", "WIFI", "opt2", "r", "static"))
        # the empty-IP lease alone is still the place
        m = merge_sightings(ss[:1])[A]
        self.assertEqual((m.ip, m.vlan, m.iface), ("", "LAN", "opt1"))

    def test_V55_moved_network_without_ip_does_not_keep_the_old_ip(self):
        prev = [row(A, ip="10.0.10.5", vlan="LAN", iface="opt1", lease_type="static")]
        res = self.merge(prev, {"fw1": Batch(sightings=[sight(ip="", kind="dhcp", presence=False, network="IOT", iface="opt3",
                                                              lease_type="static")])})
        r = res.rows[A]
        self.assertEqual((r["ip"], r["vlan"], r["iface"]), ("", "IOT", "opt3"))
        self.assertEqual(res.history[0][1]["ip"], "")

    def test_V80_int_keeps_full_int64_precision(self):
        from leasewatch.connectors.merge import _int
        self.assertEqual(_int(2 ** 63 - 1), 2 ** 63 - 1)
        self.assertEqual(_int("9223372036854775807"), 2 ** 63 - 1)
        self.assertEqual(_int(2 ** 53 + 1), 2 ** 53 + 1)
        self.assertEqual((_int("-61"), _int("\u221261"), _int("3.7"), _int("1e3")), (-61, -61, 3, 1000))
        self.assertIsNone(_int(2 ** 63))

    def test_V81_V82_tab_and_newline_become_spaces(self):
        from leasewatch.connectors.merge import _str
        self.assertEqual((_str("a\nb\tc", True), _str(" a\tb ", True), _str("\x00x\t", False)), ("a b c", "a b", "x "))

    def test_V83_bytes_flags_are_read_as_text(self):
        from leasewatch.connectors.merge import _flag
        self.assertEqual([_flag(b"false"), _flag(b"0"), _flag(b"yes"), _flag(bytearray(b"no"))], [False, False, True, False])

    def test_V84_V85_raising_mac_or_list_is_dropped_not_raised(self):
        class S(str):
            def strip(self, *a):
                raise RuntimeError("strip")

        class L(list):
            def __iter__(self):
                raise RuntimeError("iter")
        logging.disable(logging.WARNING)
        try:
            b = normalise_batch("x", Batch(sightings=[sight(mac=S(A)), sight(mac="02:00:00:00:00:02")]))
            self.assertEqual(([s.mac for s in b.sightings], b.stats["dropped"]), (["02:00:00:00:00:02"], 1))
            b = normalise_batch("x", Batch(sightings=L([sight()]), attachments=[wifi()]))
            self.assertEqual((b.sightings, len(b.attachments), b.stats["dropped"]), ([], 1, 1))
        finally:
            logging.disable(logging.NOTSET)

    def test_V86_negative_or_bool_dropped_stat_does_not_cancel_drops(self):
        logging.disable(logging.WARNING)
        try:
            for before in (-1, True):
                b = normalise_batch("unifi", Batch(attachments=[Attachment(mac="bad", source="", observed_at=NOW, link="wifi"),
                                                                wifi()], stats={"dropped": before}))
                self.assertEqual(b.stats["dropped"], 1, before)
        finally:
            logging.disable(logging.NOTSET)


class Round3(Base):
    @staticmethod
    def _mk(ip, vlan, iface, src, lt="", online=True):
        return Fw1Sighting(mac=A, ip=ip, hostname="r" if src == "dhcp" else "", vendor="", vlan=vlan, iface=iface,
                           source=src, lease_type=lt, online=online)

    def test_W09_empty_ip_lease_beats_a_sighting_with_neither_ip_nor_network(self):
        ss = [self._mk("", "LAN", "opt1", "dhcp", "static", False), self._mk("", "", "", "client")]
        for order in (ss, ss[::-1]):
            m = merge_sightings(order)[A]
            self.assertEqual((m.ip, m.vlan, m.iface, m.lease_type), ("", "LAN", "opt1", "static"))

    def test_W41_sighting_of_an_unlisted_kind_with_an_ip_beats_an_empty_ip_lease(self):
        ss = [self._mk("", "LAN", "opt1", "dhcp", "static", False), self._mk("10.0.0.9", "WIFI", "opt2", "other")]
        for order in (ss, ss[::-1]):
            m = merge_sightings(order)[A]
            self.assertEqual((m.ip, m.vlan, m.iface), ("10.0.0.9", "WIFI", "opt2"))

    def test_W10_unknown_network_becoming_known_keeps_the_stored_ip(self):
        prev = [row(A, ip="10.0.10.5", vlan="", iface="", lease_type="static")]
        res = self.merge(prev, {"fw1": Batch(sightings=[sight(ip="", kind="dhcp", presence=False, network="LAN", iface="opt1",
                                                              lease_type="static")])})
        r = res.rows[A]
        self.assertEqual((r["ip"], r["vlan"], r["iface"]), ("10.0.10.5", "LAN", "opt1"))
        self.assertEqual(res.history[0][1]["ip"], "10.0.10.5")

    def test_W42_every_line_break_becomes_one_space(self):
        from leasewatch.connectors.merge import _str
        for s in ("a\rb", "a\x0bb", "a\x0cb", "a\x85b", "a\u2028b", "a\u2029b", "a\r\nb", "a\nb"):
            self.assertEqual(_str(s, True), "a b", repr(s))

    def test_W43_stats_whose_get_raises_does_not_raise(self):
        class D(dict):
            def get(self, *a):
                raise RuntimeError("get")
        b = normalise_batch("x", Batch(sightings=[sight()], stats=D(dropped=2)))
        self.assertEqual(len(b.sightings), 1)
        self.assertEqual(type(b.stats), dict)


    def test_W11_W12_W13_ssidless_client_that_left_wifi_is_cleared_like_one_with_an_ssid(self):
        # poll 1: listed without an SSID; poll 2: on the wire, every controller answered and none lists it
        p1 = self.merge([], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi(ssid="")])}, controllers=CTRL)
        self.assertEqual((p1.rows[A]["link"], p1.rows[A]["wifi_ap"]), ("wifi", "ap-hall"))
        r = self.merge([p1.rows[A]], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[])},
                       controllers=CTRL).rows[A]
        self.assertEqual((r["link"], r["wifi_ssid"], r["wifi_ap"], r["loc_source"]), ("", "", "", ""))
        # a switch lists it in that poll: on the cable, as a row with an SSID would be
        r = self.merge([p1.rows[A]], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[]),
                                      "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")])}, controllers=CTRL).rows[A]
        self.assertEqual((r["link"], r["wifi_ap"], r["sw_port"], r["loc_source"]), ("wired", "", "GE1/0/3", "sw1"))
        # walked out (off ARP): it keeps its Wi-Fi details
        r = self.merge([p1.rows[A]], {"fw1": Batch(sightings=[]), "unifi": Batch(attachments=[])},
                       controllers=CTRL).rows.get(A, p1.rows[A])  # not in rows: the stored row is not touched
        self.assertEqual((r["link"], r["wifi_ap"]), ("wifi", "ap-hall"))


class WifiEvents(Base):
    """B-13: a wifi event only for an SSID change or a start/stop of Wi-Fi; an AP roam is silent."""
    ON = dict(link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall", wifi_signal=-50, wifi_radio="5 GHz", loc_source="unifi")

    def test_T07a_roam_on_the_same_ssid_writes_no_event_and_updates_the_row(self):
        res = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight()]),
                                               "unifi": Batch(attachments=[wifi(ap="ap-attic", signal=-70, radio="2.4 GHz")])},
                         controllers=CTRL)
        self.assertEqual(res.events, [])
        self.assertEqual(res.history, [])
        r = res.rows[A]
        self.assertEqual((r["wifi_ssid"], r["wifi_ap"], r["wifi_signal"], r["wifi_radio"]), ("HomeNet", "ap-attic", -70, "2.4 GHz"))

    def test_T07b_ssid_change_writes_an_event(self):
        res = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight()]),
                                               "unifi": Batch(attachments=[wifi(ssid="GuestNet", ap="ap-attic")])},
                         controllers=CTRL)
        self.assertEqual(res.events, [(A, "wifi", "HomeNet -> GuestNet")])

    def test_T07c_start_on_wifi_writes_an_event(self):
        res = self.merge([row(A, link="wired", sw_port="GE1/0/5")],
                         {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi()])}, controllers=CTRL)
        self.assertEqual(res.events, [(A, "wifi", "- -> HomeNet")])

    def test_T07d_new_device_on_wifi_writes_only_the_new_event(self):
        res = self.merge([], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi()])}, controllers=CTRL)
        self.assertEqual([e[1] for e in res.events], ["new"])

    def test_T07e_stop_through_controller_wired_writes_an_event(self):
        wired = Attachment(mac=A, source="unifi", observed_at=NOW, link="wired")
        res = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wired])},
                         controllers=CTRL)
        self.assertEqual(res.events, [(A, "wifi", "HomeNet -> wired")])

    def test_T07f_stop_through_left_wifi_writes_an_event(self):
        res = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(),
                                               "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")])}, controllers=CTRL)
        self.assertEqual(res.events, [(A, "wifi", "HomeNet -> off Wi-Fi")])

    def test_S4R09_walk_out_with_a_lingering_arp_entry_writes_no_events(self):
        # the controller drops the phone at once, the firewall's ARP entry stays ~20 min: without a cable shown this
        # cannot be told from a walk-out, so the stale Wi-Fi details are cleared silently, and the return is silent too
        out = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight()]), "unifi": Batch()}, controllers=CTRL)
        self.assertEqual(out.events, [])
        self.assertEqual((out.rows[A]["wifi_ssid"], out.rows[A]["link"]), ("", ""))
        back = self.merge([out.rows[A]], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi()])},
                          controllers=CTRL)
        self.assertEqual(back.events, [])
        self.assertEqual((back.rows[A]["wifi_ssid"], back.rows[A]["link"]), ("HomeNet", "wifi"))

    def test_walk_out_with_an_ap_uplink_fdb_entry_writes_no_events(self):
        # the FDB still holds the phone on the AP's uplink: that is no cable, so leaving and returning are silent,
        # also when the walk-out lasts more than one poll
        up = {"sw1": Batch(attachments=[swp(A, "GE1/0/24", "sw1", uplink=True, via="ap-hall")])}
        out = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(), **up},
                         controllers=CTRL)
        self.assertEqual(out.events, [])
        self.assertEqual((out.rows[A]["wifi_ssid"], out.rows[A]["link"]), ("", ""))
        out = self.merge([out.rows[A]], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(), **up}, controllers=CTRL)
        self.assertEqual(out.events, [])
        back = self.merge([out.rows[A]], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi()]), **up},
                          controllers=CTRL)
        self.assertEqual(back.events, [])
        self.assertEqual((back.rows[A]["wifi_ssid"], back.rows[A]["link"]), ("HomeNet", "wifi"))

    def test_leaving_wifi_to_an_edge_port_writes_the_event(self):
        res = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight()]), "unifi": Batch(),
                                               "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")])}, controllers=CTRL)
        self.assertEqual(res.events, [(A, "wifi", "HomeNet -> off Wi-Fi")])
        self.assertEqual(res.rows[A]["link"], "wired")

    def test_S4R08_first_ssid_of_a_client_already_on_wifi_writes_no_event(self):
        res = self.merge([row(A, link="wifi", wifi_ssid="", wifi_ap="ap-hall", loc_source="unifi")],
                         {"fw1": Batch(sightings=[sight()]), "unifi": Batch(attachments=[wifi()])}, controllers=CTRL)
        self.assertEqual(res.events, [])
        self.assertEqual(res.rows[A]["wifi_ssid"], "HomeNet")

    def test_T07g_walk_out_and_return_to_the_same_ssid_writes_no_event(self):
        res = self.merge([row(A, **self.ON)], {"fw1": Batch(sightings=[sight(mac="02:00:00:00:00:09", ip="10.0.0.9")]),
                                               "unifi": Batch()}, controllers=CTRL)
        self.assertEqual([e for e in res.events if e[0] == A], [])
        res = self.merge([res.rows.get(A, row(A, **self.ON))], {"fw1": Batch(sightings=[sight()]),
                                                                "unifi": Batch(attachments=[wifi(ap="ap-attic")])},
                         controllers=CTRL)
        self.assertEqual(res.events, [])


class S4Rekey(Base):
    """S4R05/S4R06: an alias and its device in one batch, and two leases that differ only in client-id."""
    D = "00:00:5e:00:53:01"   # the device (documentation range)
    AL = "02:aa:00:00:00:01"  # its known private alias

    def test_S4R05_alias_and_device_on_one_switch_edge_port_wins_in_either_order(self):
        stale = swp(self.D, "GE1/0/24", "sw1", uplink=True, via="sw2")
        edge = swp(self.AL, "GE1/0/9", "sw1")
        for order in ([stale, edge], [edge, stale]):
            with self.subTest([a.port for a in order]):
                res = self.merge([row(self.D, sw_port="GE1/0/7", link="wired", loc_source="sw1")],
                                 {"fw1": Batch(sightings=[sight(self.AL)]), "sw1": Batch(attachments=list(order))},
                                 aliases={self.AL: self.D})
                self.assertEqual(res.rows[self.D]["sw_port"], "GE1/0/9")
                self.assertEqual(res.events, [(self.D, "port", "GE1/0/7 -> GE1/0/9")])

    def test_S4R05_controller_lists_alias_and_device_the_active_client_wins(self):
        idle = wifi(self.D, ssid="OldNet", present=False)
        active = wifi(self.AL, ssid="HomeNet", present=True)
        for order in ([idle, active], [active, idle]):
            with self.subTest([a.ssid for a in order]):
                res = self.merge([row(self.D, link="wifi", wifi_ssid="HomeNet", loc_source="unifi")],
                                 {"fw1": Batch(sightings=[sight(self.AL)]), "unifi": Batch(attachments=list(order))},
                                 controllers=CTRL, aliases={self.AL: self.D})
                self.assertEqual(res.rows[self.D]["wifi_ssid"], "HomeNet")
                self.assertEqual(res.events, [])

    def test_S4R06_client_id_does_not_depend_on_row_order(self):
        mk = lambda c: Fw1Sighting(mac=A, ip="10.0.0.5", hostname="h", vendor="", vlan="lan", iface="igb0", source="dhcp",
                                   lease_type="dynamic", online=False, client_id=c)
        with_cid, without, other = mk("01aabbccddee01"), mk(""), mk("01ff")
        self.assertEqual(merge_sightings([with_cid, without])[A].client_id, "01aabbccddee01")
        self.assertEqual(merge_sightings([without, with_cid])[A].client_id, "01aabbccddee01")
        self.assertEqual(merge_sightings([with_cid, other])[A].client_id, merge_sightings([other, with_cid])[A].client_id)


    def test_lease_type_ranks_static_dynamic_empty_in_any_order(self):
        mk = lambda t: Fw1Sighting(mac=A, ip="10.0.0.5", hostname="h", vendor="v", vlan="lan", iface="igb0", source="dhcp",
                                   lease_type=t, online=False, client_id="")
        for rows, want in (([mk("dynamic"), mk("")], "dynamic"), ([mk("static"), mk("dynamic"), mk("")], "static")):
            for order in (rows, rows[::-1]):
                with self.subTest([s.lease_type for s in order]):
                    self.assertEqual(merge_sightings(list(order))[A].lease_type, want)

if __name__ == "__main__":
    unittest.main()
