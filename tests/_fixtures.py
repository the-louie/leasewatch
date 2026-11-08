"""Builders shared by the tests: sightings and device rows."""
from leasewatch.connectors.merge import ROW_DEFAULTS
from leasewatch.fw1 import Sighting


def S(mac, ip, host="", src="dhcp", vlan="Clients", lt="dynamic", online=True, vendor="Acme"):
    return Sighting(mac=mac, ip=ip, hostname=host, vendor=vendor, vlan=vlan, iface="opt3", source=src, lease_type=lt if src == "dhcp" else "", online=online)


NOW = 1_700_000_000


def row(mac, **kw):
    r = {"mac": mac, "first_seen": NOW - 5000, "last_seen": NOW - 60, "last_online": NOW - 60, "ip": "10.0.0.5", "hostname": "",
         "vendor": "Acme", "vlan": "Clients", "iface": "opt3", "lease_type": "", "sources": "arp", "online": 1, "baseline": 0,
         "acked": 0, "acked_at": None, "name": "", "note": "", **ROW_DEFAULTS}
    r.update(kw)
    return r
