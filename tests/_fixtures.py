"""Builders shared by the tests: sightings, device rows and a fake fw1 client."""
from leasewatch.connectors.merge import ROW_DEFAULTS
from leasewatch.fw1 import Fw1Error, Sighting


def S(mac, ip, host="", src="dhcp", vlan="Clients", lt="dynamic", online=True, vendor="Acme"):
    return Sighting(mac=mac, ip=ip, hostname=host, vendor=vendor, vlan=vlan, iface="opt3", source=src, lease_type=lt if src == "dhcp" else "", online=online)


NOW = 1_700_000_000


def row(mac, **kw):
    r = {"mac": mac, "first_seen": NOW - 5000, "last_seen": NOW - 60, "last_online": NOW - 60, "ip": "10.0.0.5", "hostname": "",
         "vendor": "Acme", "vlan": "Clients", "iface": "opt3", "lease_type": "", "sources": "arp", "online": 1, "baseline": 0,
         "acked": 0, "acked_at": None, "name": "", "note": "", **ROW_DEFAULTS}
    r.update(kw)
    return r


def _one_each(data):
    return {"leases": 1, "arp": 1}


class FakeClient:
    """Stands in for the fw1 client. sightings_data is what each poll returns; fail=True makes collect() raise
    Fw1Error. stats maps sightings_data to the raw counts; the default is 1 lease, 1 arp, whose "1 leases, 1 arp"
    test_web asserts. test_instances.Base passes its own, and the tests on Base assert its "0 leases, N arp"."""
    def __init__(self, data=None, *, fail=False, stats=_one_each):
        self.sightings_data = [] if data is None else data
        self.fail = fail
        self.stats = stats

    @property
    def rows(self):  # the name the tests on test_instances.Base use (client.rows.append(...))
        return self.sightings_data

    @rows.setter
    def rows(self, value):
        self.sightings_data = value

    def arp_raw(self):
        return []  # what the opnsense connector's check() calls; `fail` breaks collect() only

    def sightings(self, ignore=()):
        if self.fail:
            raise Fw1Error("boom")
        return list(self.sightings_data), self.stats(self.sightings_data)
