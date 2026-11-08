"""merge() called directly with Batch objects: (prev rows, batches, state) -> rows, events, history."""
import itertools, os, sys, tempfile, unittest
from dataclasses import replace
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore
from _fixtures import row
from leasewatch.config import Config
from leasewatch.connectors import Attachment, Batch, HostContext, Sighting
from leasewatch.connectors import merge as merge_mod
from leasewatch.connectors.merge import UPDATE_COLUMNS, ConnectorFailure, MergeState, merge, normalise_batch
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


def port(mac, label, via="", uplink=False):
    return Attachment(mac=mac, source="switch", observed_at=NOW, link="wired", device="sw-rack", port=label, via=via, uplink=uplink)


def swp(mac, label, source, uplink=False, at=NOW, via=""):
    """A wired attachment from one of several switch instances (C6)."""
    return Attachment(mac=mac, source=source, observed_at=at, link="wired", device=source, port=label, via=via, uplink=uplink)


def wifi(mac, ssid="HomeNet", ap="ap-hall", alias=""):
    return Attachment(mac=mac, source="unifi", observed_at=NOW, link="wifi", ssid=ssid, ap=ap, signal=-50, radio="5 GHz", alias=alias)


def ctl_wired(mac, alias=""):
    return Attachment(mac=mac, source="unifi", observed_at=NOW, link="wired", alias=alias)


def K(mac, ip, kind, presence=True, host="", vendor="", net="HomeNet", src="ctl"):
    """A sighting of any kind from a non-firewall instance (controller client list, scanner)."""
    return Sighting(mac=mac, source=src, kind=kind, presence=presence, observed_at=NOW, ip=ip, hostname=host, vendor=vendor,
                    network=net, iface="wlan")


def att(mac, link, source="unifi"):
    return Attachment(mac=mac, source=source, observed_at=NOW, link=link, device="sw-rack", port="GE1/0/7", ssid="HomeNet", ap="ap-hall")


def fw1(*sightings):
    return Batch(sightings=list(sightings), stats={"leases": 1, "arp": 1})


ON_WIFI = dict(link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall", wifi_signal=-50, wifi_radio="5 GHz")
FAILED = ConnectorFailure("unifi", "TimeoutError", NOW)
CTRL2 = frozenset({"unifi", "unifi2"})

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
     {A: dict(sw_port="", sw_via="", link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall", wifi_signal=-50, wifi_radio="5 GHz")}, [(A, "wifi", "- -> HomeNet")], []),
    ("controller says wired: Wi-Fi details dropped, alias kept",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch(attachments=[ctl_wired(A, "laptop")])}, {"controllers": CTRL},
     {A: dict(link="wired", wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", wifi_alias="laptop")}, [(A, "wifi", "HomeNet -> wired")], []),
    ("controller answered without the client: left Wi-Fi, cable port shown",
     [row(A, wifi_alias="laptop", **ON_WIFI)], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/5")]),
                                                "unifi": Batch()}, {"controllers": CTRL},
     {A: dict(link="wired", wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", wifi_alias="laptop", sw_port="GE1/0/5")}, [(A, "wifi", "HomeNet -> off Wi-Fi")], []),
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
    ("roaming to another AP on the same SSID writes no event",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch(attachments=[wifi(A, ap="ap-attic")])}, {"controllers": CTRL},
     {A: dict(wifi_ap="ap-attic", link="wifi")}, [], []),
    # C2b item 1: kinds client/scan, one total order for identity, RANKING for hostname/vendor
    ("client sighting only: no crash, identity from it",
     [], {"ctl": Batch(sightings=[K(A, "10.0.0.7", "client", host="alex-ipad", vendor="Apple")])}, {},
     {A: dict(ip="10.0.0.7", vlan="HomeNet", iface="wlan", hostname="alex-ipad", vendor="Apple", online=1, sources="client")},
     [(A, "new", "10.0.0.7 alex-ipad Apple (HomeNet)")], [A]),
    ("scan sighting without presence: listed, not online",
     [], {"scan": Batch(sightings=[K(A, "10.0.0.8", "scan", presence=False)])}, {},
     {A: dict(ip="10.0.0.8", online=0, last_online=None, sources="scan")}, [(A, "new", "10.0.0.8 (HomeNet)")], [A]),
    # C2c item 1: identity as in 1.0/C2: a lease is placed by ARP; client/scan only when there is no dhcp/arp sighting
    ("a lease without ARP is shown at the lease, not at a client seen now",
     [], {"fw1": fw1(S(A, "10.0.0.5", "pc", presence=False)), "ctl": Batch(sightings=[K(A, "10.0.0.7", "client")])}, {},
     {A: dict(ip="10.0.0.5", vlan="Clients", hostname="pc", lease_type="dynamic", online=1)},
     [(A, "new", "10.0.0.5 pc Acme (Clients)")], [A]),
    ("arp places the device, also when a client confirms the lease IP",
     [], {"fw1": fw1(S(A, "10.0.0.5", "pc", presence=False), arp(A, "10.0.1.9", net="Servers")),
          "ctl": Batch(sightings=[K(A, "10.0.0.5", "client")])}, {},
     {A: dict(ip="10.0.1.9", vlan="Servers", iface="opt3", hostname="pc")}, [(A, "new", "10.0.1.9 pc Acme (Servers)")], [A]),
    ("an ISC-online lease does not override the ARP row; hostname from dhcp[0]",
     [], {"fw1": fw1(S(A, "10.0.0.5", "pc", lt="static", presence=False), S(A, "10.0.1.6", "tv", presence=True),
                     arp(A, "10.0.0.9"))}, {},
     {A: dict(ip="10.0.0.9", vlan="Clients", hostname="pc", lease_type="static", online=1)},
     [(A, "new", "10.0.0.9 pc Acme (Clients)")], [A]),
    ("an ISC-online lease and ARP: hostname from the lease matching the ARP IP",
     [], {"fw1": fw1(S(A, "10.0.0.5", "pc", lt="static", presence=False), S(A, "10.0.1.6", "tv", presence=True),
                     arp(A, "10.0.1.6"))}, {},
     {A: dict(ip="10.0.1.6", hostname="tv", lease_type="dynamic", online=1)},
     [(A, "new", "10.0.1.6 tv Acme (Clients)")], [A]),
    ("client and scan only: the client places it",
     [], {"ctl": Batch(sightings=[K(A, "10.0.0.7", "client", presence=False)]),
          "scan": Batch(sightings=[K(A, "10.0.0.8", "scan", src="scan")])}, {},
     {A: dict(ip="10.0.0.7", online=1, sources="client,scan")}, [(A, "new", "10.0.0.7 (HomeNet)")], [A]),
    ("hostname: client before arp; vendor: arp before client",
     [], {"fw1": fw1(arp(A, host="aa-arp", vendor="ArpCo")), "ctl": Batch(sightings=[K(A, "10.0.0.5", "client", host="zz-client",
                                                                                     vendor="Apple", net="Clients")])}, {},
     {A: dict(hostname="zz-client", vendor="ArpCo")}, [(A, "new", "10.0.0.5 zz-client ArpCo (Clients)")], [A]),
    # item 2: presence decides online for every kind, also arp
    ("arp without presence: not online",
     [], {"fw1": fw1(arp(A, presence=False))}, {},
     {A: dict(online=0, last_online=None)}, [(A, "new", "10.0.0.5 Acme (Clients)")], [A]),
    ("arp without presence: last_online does not move, offline after grace",
     [row(A, last_online=NOW - 700)], {"fw1": fw1(arp(A, presence=False))}, {},
     {A: dict(online=0, last_online=NOW - 700, last_seen=NOW)}, [], []),
    ("client with presence: online, last_online moves",
     [row(A, online=0, last_online=NOW - 700)], {"ctl": Batch(sightings=[K(A, "10.0.0.5", "client", net="Clients")])}, {},
     {A: dict(online=1, last_online=NOW)}, [], []),
    # item 3: link outside {wired, wifi} is ignored
    ("controller link 'wireless' ignored: as if not listed (left Wi-Fi), not 'wired'",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch(attachments=[att(A, "wireless")])}, {"controllers": CTRL},
     {A: dict(link="", wifi_ssid="", wifi_ap="")}, [], []),
    ("switch link 'Wired' ignored: no port",
     [row(A)], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[att(A, "Wired", "switch")])}, {},
     {A: dict(sw_port="", link="")}, [], []),
    # item 4: the host normalises MACs and drops records that fail
    ("MAC normalised, invalid MAC dropped",
     [], {"fw1": fw1(arp("02-00-00-00-00-0A"), arp("not-a-mac", "10.0.0.9"))}, {},
     {"02:00:00:00:00:0a": dict(ip="10.0.0.5"), "not-a-mac": None, "02-00-00-00-00-0A": None},
     [("02:00:00:00:00:0a", "new", "10.0.0.5 Acme (Clients)")], ["02:00:00:00:00:0a"]),
    # item 5: several controllers
    ("two controllers: listed by one of them, stays on Wi-Fi (roam, no event)",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch(), "unifi2": Batch(attachments=[wifi(A, ap="ap-attic")])},
     {"controllers": CTRL2},
     {A: dict(link="wifi", wifi_ap="ap-attic")}, [], []),
    ("two controllers: both answered, neither lists it: left Wi-Fi",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch(), "unifi2": Batch()}, {"controllers": CTRL2},
     {A: dict(link="", wifi_ssid="")}, [], []),
    ("two controllers: one failed: blind, keeps Wi-Fi and gets no AP uplink port",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/5", "ap-hall", True)]),
                           "unifi": Batch(), "unifi2": ConnectorFailure("unifi2", "TimeoutError", NOW)},
     {"controllers": CTRL2},
     {A: dict(sw_port="", link="wifi", wifi_ssid="HomeNet", wifi_ap="ap-hall")}, [], []),
    # C2c item 5: a controller that answered and lists the device is evidence, even while another failed
    ("two controllers: one says wired, one failed: not blind, port taken in this poll",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "switch": Batch(attachments=[port(A, "GE1/0/5")]),
                           "unifi": Batch(attachments=[ctl_wired(A)]), "unifi2": ConnectorFailure("unifi2", "TimeoutError", NOW)},
     {"controllers": CTRL2},
     {A: dict(link="wired", sw_port="GE1/0/5", wifi_ssid="", loc_source="switch")}, [(A, "wifi", "HomeNet -> wired")], []),
    # C6, rule 6: several switches see one MAC
    ("two switches: the edge port beats an uplink from an earlier instance",
     [row(A)], {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/48", "sw1", True, via="sw-2")]),
                "sw2": Batch(attachments=[swp(A, "GE1/0/7", "sw2")])}, {},
     {A: dict(sw_port="GE1/0/7", sw_via="", link="wired", loc_source="sw2")}, [], []),
    ("two switches, two edge ports: observed_at is ignored (C6b), instance order",
     [row(A)], {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1", at=NOW - 120)]),
                "sw2": Batch(attachments=[swp(A, "GE1/0/7", "sw2", at=NOW)])}, {},
     {A: dict(sw_port="GE1/0/3", loc_source="sw1")}, [], []),
    ("two switches, two edge ports, same time: instance order",
     [row(A)], {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]),
                "sw2": Batch(attachments=[swp(A, "GE1/0/7", "sw2")])}, {},
     {A: dict(sw_port="GE1/0/3", loc_source="sw1")}, [], []),
    ("two uplinks: instance order (not the newest), and shown via",
     [row(A)], {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/47", "sw1", True, NOW - 60, "sw-2")]),
                "sw2": Batch(attachments=[swp(A, "GE1/0/1", "sw2", True, NOW, "sw-1")])}, {},
     {A: dict(sw_port="GE1/0/47", sw_via="sw-2", loc_source="sw1")}, [], []),
    # C6b (1): the switch that holds a wired device failed this poll
    ("sw2 holds the device and fails while sw1 offers an uplink: port kept, no event",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/48", "sw1", True, via="sw-2")]),
      "sw2": ConnectorFailure("sw2", "TimeoutError", NOW)}, {},
     {A: dict(sw_port="GE1/0/7", sw_via="", link="wired", loc_source="sw2")}, [], []),
    ("sw2 holds the device and fails while sw1 offers an edge port: port kept, no event",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]),
      "sw2": ConnectorFailure("sw2", "TimeoutError", NOW)}, {},
     {A: dict(sw_port="GE1/0/7", link="wired", loc_source="sw2")}, [], []),
    ("a failed switch that does not hold the device protects nothing",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]),
      "sw3": ConnectorFailure("sw3", "TimeoutError", NOW)}, {},
     {A: dict(sw_port="GE1/0/3", loc_source="sw1")}, [(A, "port", "GE1/0/7 -> GE1/0/3")], []),
    # C6b (2): sticky between equal ranks
    ("two edge ports: the switch that already holds the device stays (sticky over instance order)",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1", at=NOW)]),
      "sw2": Batch(attachments=[swp(A, "GE1/0/7", "sw2", at=NOW - 30)])}, {},
     {A: dict(sw_port="GE1/0/7", loc_source="sw2")}, [], []),
    ("two uplinks: sticky too",
     [row(A, link="wired", sw_port="GE1/0/1", sw_via="sw-1", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/47", "sw1", True, via="sw-2")]),
      "sw2": Batch(attachments=[swp(A, "GE1/0/1", "sw2", True, via="sw-1")])}, {},
     {A: dict(sw_port="GE1/0/1", sw_via="sw-1", loc_source="sw2")}, [], []),
    ("sticky never beats an edge port: the holder now offers only an uplink",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]),
      "sw2": Batch(attachments=[swp(A, "GE1/0/48", "sw2", True, via="sw-1")])}, {},
     {A: dict(sw_port="GE1/0/3", loc_source="sw1")}, [(A, "port", "GE1/0/7 -> GE1/0/3")], []),
    ("the holder no longer lists the device: instance order",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]), "sw2": Batch(),
      "sw3": Batch(attachments=[swp(A, "GE1/0/9", "sw3")])}, {},
     {A: dict(sw_port="GE1/0/3", loc_source="sw1")}, [(A, "port", "GE1/0/7 -> GE1/0/3")], []),
    ("only the losing uplink moved: no port event, port kept",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2", last_online=NOW, last_seen=NOW, sources="arp,dhcp",
          hostname="pc", lease_type="dynamic")],
     {"fw1": fw1(S(A, "10.0.0.5", "pc", presence=False), arp(A)),
      "sw1": Batch(attachments=[swp(A, "GE1/0/46", "sw1", True, via="sw-2")]),
      "sw2": Batch(attachments=[swp(A, "GE1/0/7", "sw2", at=NOW - 30)])}, {},
     {A: dict(sw_port="GE1/0/7", sw_via="", loc_source="sw2")}, [], []),
    ("winning switch changes: port event, loc_source follows",
     [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")],
     {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]),
      "sw2": Batch(attachments=[swp(A, "GE1/0/48", "sw2", True, via="sw-1")])}, {},
     {A: dict(sw_port="GE1/0/3", sw_via="", loc_source="sw1")}, [(A, "port", "GE1/0/7 -> GE1/0/3")], []),
    ("Wi-Fi still beats an edge port; loc_source is the controller",
     [row(A)], {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]), "unifi": Batch(attachments=[wifi(A)])},
     {"controllers": CTRL},
     {A: dict(link="wifi", sw_port="", wifi_ssid="HomeNet", loc_source="unifi")}, [], []),
    ("one instance: its first attachment for a MAC stays its candidate",
     [row(A)], {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/48", "sw1", True, via="sw-2"),
                                                              swp(A, "GE1/0/3", "sw1")])}, {},
     {A: dict(sw_port="GE1/0/48", loc_source="sw1")}, [], []),
    ("left Wi-Fi, no switch port: loc_source cleared",
     [row(A, loc_source="unifi", **ON_WIFI)], {"fw1": fw1(arp(A)), "unifi": Batch()}, {"controllers": CTRL},
     {A: dict(link="", loc_source="")}, [], []),
    ("controller role, not the name: a controller called ctl-1",
     [row(A, **ON_WIFI)], {"fw1": fw1(arp(A)), "ctl-1": Batch()}, {"controllers": frozenset({"ctl-1"})},
     {A: dict(link="", wifi_ssid="")}, [], []),
]


class MergeTableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})

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

    def test_seen_per_instance(self):
        """Rule 2: one entry per (known MAC, instance that listed it); last_present only on a presence claim."""
        unknown = "02:00:00:00:00:0f"  # only in the FDB, never sighted: no device row, so no seen entry
        res = self.run_merge([row(B)], {"fw1": fw1(S(A, "10.0.0.5", presence=False), arp(A), S(B, "10.0.0.9", presence=False)),
                                        "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1"), swp(unknown, "GE1/0/4", "sw1")]),
                                        "unifi": Batch(attachments=[wifi(B)]), "sw2": ConnectorFailure("sw2", "x", NOW)},
                             controllers=CTRL)
        self.assertEqual(sorted(res.seen), [(A, "fw1", NOW, NOW), (A, "sw1", NOW, None), (B, "fw1", NOW, None), (B, "unifi", NOW, None)])

    def test_two_edge_ports_alternating_walk_order_stay_stable(self):
        """C6b (2): which switch's walk ends last alternates per poll; the winner must not flap (no port events)."""
        rows = [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")]
        for p in range(4):
            early, late = (NOW - 5, NOW) if p % 2 else (NOW, NOW - 5)
            res = self.run_merge(rows, {"fw1": fw1(arp(A)), "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1", at=early)]),
                                        "sw2": Batch(attachments=[swp(A, "GE1/0/7", "sw2", at=late)])})
            self.assertEqual((res.rows[A]["sw_port"], res.rows[A]["loc_source"], res.events), ("GE1/0/7", "sw2", []))
            rows = [res.rows[A]]

    def test_present_attachment_sets_last_present_not_online(self):
        """C6b (3): a controller's active client is "on the wire" for that instance; online stays sighting-only."""
        res = self.run_merge([row(B, online=0, last_online=None)],
                             {"fw1": fw1(S(B, "10.0.0.9", presence=False)),
                              "unifi": Batch(attachments=[replace(wifi(B), present=True)]),
                              "sw1": Batch(attachments=[swp(B, "GE1/0/3", "sw1")])}, controllers=CTRL)
        self.assertEqual(sorted(res.seen), [(B, "fw1", NOW, None), (B, "sw1", NOW, None), (B, "unifi", NOW, NOW)])
        self.assertEqual((res.rows[B]["online"], res.rows[B]["last_online"]), (0, None))

    def test_unifi_attachments_are_present(self):
        from leasewatch.connectors.unifi import to_attachments
        from leasewatch.unifi import WifiInfo
        out = to_attachments({A: WifiInfo(ssid="HomeNet"), B: WifiInfo(wired=True)}, "unifi", NOW)
        self.assertEqual([a.present for a in out], [True, True])  # stat/sta lists only active clients, wired or not
        self.assertFalse(swp(A, "GE1/0/3", "sw1").present)  # the default: an FDB entry is not present

    def test_normalise_batch(self):
        b = Batch(sightings=[Sighting(mac="02:00:00:00:00:0A", source="", kind="arp", presence=True, observed_at=NOW),
                             Sighting(mac="", source="", kind="arp", presence=True, observed_at=NOW)],
                  attachments=[Attachment(mac="bogus", source="", observed_at=NOW, link="wired")], stats={"arp": 2})
        with mock.patch.object(merge_mod, "_mac_warned", set()):
            with self.assertLogs("leasewatch.merge", "WARNING") as logs:
                out = normalise_batch("fw2", b)
            self.assertEqual(logs.output, ["WARNING:leasewatch.merge:connector fw2: 2 malformed records dropped (invalid MAC, wrong type or unconvertible field)"])
            with self.assertNoLogs("leasewatch.merge", "WARNING"):  # once per instance per process
                normalise_batch("fw2", b)
        self.assertEqual([(s.mac, s.source) for s in out.sightings], [("02:00:00:00:00:0a", "fw2")])  # host fills source
        self.assertEqual((out.attachments, out.stats), ([], {"arp": 2, "dropped": 2}))
        self.assertEqual(normalise_batch("fw2", out).stats["dropped"], 2)  # applying it again drops nothing more
        self.assertEqual(len(b.sightings), 2)  # the given batch is left as it is

    def test_unknown_link_logged_once_per_instance_and_value(self):
        batches = {"fw1": fw1(arp(A), arp(B, "10.0.0.9")),
                   "switch": Batch(attachments=[att(A, "fiber", "switch"), att(B, "fiber", "switch"), att(B, "", "switch")])}
        with mock.patch.object(merge_mod, "_link_warned", set()):
            with self.assertLogs("leasewatch.merge", "WARNING") as logs:
                self.run_merge([], batches)
            self.assertEqual(logs.output, ["WARNING:leasewatch.merge:connector switch: attachments with link 'fiber' ignored (allowed: wired, wifi)",
                                           "WARNING:leasewatch.merge:connector switch: attachments with link '' ignored (allowed: wired, wifi)"])
            with self.assertNoLogs("leasewatch.merge", "WARNING"):
                self.run_merge([], batches)

    def test_identity_is_order_independent_over_all_kinds(self):
        rows = [S(A, "10.0.0.5", "pc", presence=False), K(A, "10.0.0.7", "client", host="ipad"), K(A, "10.0.0.8", "scan"),
                arp(A, "10.0.1.9", presence=False, net="Servers")]
        results = {tuple((r["ip"], r["vlan"], r["hostname"], r["online"]) for r in self.run_merge([], {"x": Batch(sightings=list(p))}).rows.values())
                   for p in itertools.permutations(rows)}
        self.assertEqual(results, {(("10.0.1.9", "Servers", "pc", 1),)})

    def test_vendor_and_iface_are_order_independent(self):
        """C2c item 2: rows that tie on every other key and differ only in vendor/iface still give one result."""
        def R(kind, vendor, iface):
            return Sighting(mac=A, source="x", kind=kind, presence=True, observed_at=NOW, ip="10.0.0.5", network="Clients",
                            vendor=vendor, iface=iface)
        rows = [R("arp", "Zeta", "opt1"), R("arp", "Acme", "opt9"), R("arp", "Acme", "opt2"), R("client", "Apple", "wlan"),
                R("client", "", "wlan2")]
        results = {(r["vendor"], r["iface"]) for p in itertools.permutations(rows)
                   for r in self.run_merge([], {"x": Batch(sightings=list(p))}).rows.values()}
        self.assertEqual(results, {("Acme", "opt2")})
        client_only = rows[3:] + [R("client", "Apple", "wlan0")]
        results = {(r["vendor"], r["iface"]) for p in itertools.permutations(client_only)
                   for r in self.run_merge([], {"x": Batch(sightings=list(p))}).rows.values()}
        self.assertEqual(results, {("Apple", "wlan2")})  # the empty vendor sorts first and places it

    def test_malformed_batch_never_raises(self):
        """C2c item 3: wrong record types, a non-str MAC and sightings=None are dropped and counted, never raised."""
        with mock.patch.object(merge_mod, "_mac_warned", set()):
            with self.assertLogs("leasewatch.merge", "WARNING") as logs:
                out = normalise_batch("bad", Batch(sightings=None, attachments=[Attachment(mac=2, source="", observed_at=NOW, link="wired"),
                                                                                arp(A), "junk"]))
                normalise_batch("bad", Batch(sightings=[None]))
            self.assertEqual(len(logs.output), 1)  # once per instance per process
        self.assertEqual((out.sightings, out.attachments, out.stats), ([], [], {"dropped": 4}))
        with mock.patch.object(merge_mod, "_mac_warned", set()):
            with self.assertLogs("leasewatch.merge", "WARNING"):
                res = self.run_merge([], {"bad": Batch(sightings=None), "fw1": fw1(arp(A))})
        self.assertEqual(res.rows[A]["ip"], "10.0.0.5")

    def test_held_device_keeps_loc_source_when_controller_says_wired(self):
        """C2d: holder sw2 failed, the controller lists the device as wired, sw1 offers an edge port: over two polls the
        port and loc_source stay and no port event is written (the controller must not take over loc_source)."""
        prev = [row(A, link="wired", sw_port="GE1/0/7", loc_source="sw2")]
        batches = {"fw1": fw1(arp(A)), "unifi": Batch(attachments=[Attachment(mac=A, source="unifi", observed_at=NOW, link="wired")]),
                   "sw1": Batch(attachments=[swp(A, "GE1/0/3", "sw1")]), "sw2": ConnectorFailure("sw2", "TimeoutError", NOW)}
        for poll in (1, 2):
            with self.subTest(poll=poll):
                res = self.run_merge(prev, batches, controllers=CTRL)
                r = res.rows[A]
                self.assertEqual((r["sw_port"], r["loc_source"], r["link"]), ("GE1/0/7", "sw2", "wired"))
                self.assertEqual([e for e in res.events if e[1] == "port"], [])
                prev = list(res.rows.values())

    def test_wrong_typed_fields_are_coerced_not_fatal(self):
        """C2d item 1: a valid MAC with ip=None, vendor=5, presence="yes", signal="\u221261" merges with coerced values."""
        sig = Sighting(mac=A, source="", kind="arp", presence="yes", observed_at="x", ip=None, vendor=5, network=" Clients ")
        att = Attachment(mac=A, source="", observed_at=NOW, link="wifi", ssid="HomeNet", ap="ap-hall", signal="\u221261", vlan="20",
                         uplink=0, present=1)
        out = normalise_batch("weird", Batch(sightings=[sig], attachments=[att]))
        s, a = out.sightings[0], out.attachments[0]
        self.assertEqual((s.ip, s.vendor, s.presence, s.observed_at, s.network, s.hostname), ("", "5", True, 0, "Clients", ""))
        self.assertEqual((a.signal, a.vlan, a.uplink, a.present), (-61, 20, False, True))
        self.assertEqual(out.stats, {"dropped": 0})
        res = self.run_merge([], {"weird": Batch(sightings=[sig], attachments=[att])}, controllers=CTRL | {"weird"})
        r = res.rows[A]
        self.assertEqual((r["ip"], r["vendor"], r["online"], r["wifi_signal"], r["link"]), ("", "5", 1, -61, "wifi"))

    def test_empty_network_ranks_last_in_hostname_fallback(self):
        """C2d item 2: between two ARP rows, the one without a network gives way, whatever the firewall's row order."""
        for order in ([0, 1], [1, 0]):
            rows = [arp(A, "10.0.0.5", host="", net="", vendor=""), arp(A, "10.0.0.5", host="", net="Clients", vendor="Acme")]
            rows[0] = replace(rows[0], hostname="from-empty-net")
            rows[1] = replace(rows[1], hostname="from-clients")
            with self.subTest(order=order):
                res = self.run_merge([], {"fw1": fw1(*[rows[i] for i in order])})
                self.assertEqual((res.rows[A]["hostname"], res.rows[A]["vlan"]), ("from-clients", "Clients"))

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
