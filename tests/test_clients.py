import json, os, socket, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock
from _env import clean_env, restore
from leasewatch import fw1, notify, unifi
from leasewatch.config import Config
from leasewatch.connectors.unifi import _UnifiCfg
from leasewatch.fw1 import Fw1Client, Fw1Error, kea_leases
from leasewatch.unifi import UnifiClient, parse_clients


class Stub:
    """A local HTTP server; `routes` maps a path to (status, headers, body bytes). Records every request."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requests = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def _answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                stub.requests.append((self.command, self.path, dict(self.headers), self.rfile.read(n)))
                status, headers, body = stub.routes.get(self.path.split("?")[0], (404, {}, b"{}"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = _answer

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


LEASES = "/api/dhcpv4/leases/searchLease"
ARP = "/api/diagnostics/interface/get_arp"


def js(o):
    return (200, {"Content-Type": "application/json"}, json.dumps(o).encode())


class StubCase(unittest.TestCase):
    def setUp(self):
        self.stubs = []
        # Config(...) still reads every field not passed explicitly from the environment
        self._env = clean_env()

    def tearDown(self):
        for s in self.stubs:
            s.close()
        restore(self._env)

    def stub(self, routes=None):
        s = Stub(routes)
        self.stubs.append(s)
        return s


class Fw1HttpTests(StubCase):
    def client(self, stub):
        return Fw1Client(stub.url, "k", "s", verify_tls=False, timeout=5)

    def test_redirect_is_not_followed(self):
        target = self.stub({LEASES: js({"rows": []})})
        fw = self.stub({LEASES: (302, {"Location": target.url + LEASES}, b"")})
        with self.assertRaises(Fw1Error) as cm:
            self.client(fw).leases_raw()
        self.assertIn("HTTP 302", str(cm.exception))
        self.assertEqual(target.requests, [])  # the auth header never left for the redirect target

    def test_bad_fw1_url_is_fw1error(self):
        with self.assertRaises(Fw1Error) as cm:
            Fw1Client("https://[fe80::1", "k", "s", verify_tls=False, timeout=5).arp_raw()
        self.assertIn("bad URL", str(cm.exception))

    def test_non_utf8_body_is_fw1error(self):
        fw = self.stub({ARP: (200, {}, b"\xff\xfe[]")})
        with self.assertRaises(Fw1Error):
            self.client(fw).arp_raw()

    def test_deeply_nested_json_is_fw1error(self):
        fw = self.stub({ARP: (200, {}, b"[" * 200_000)})
        with self.assertRaises(Fw1Error):
            self.client(fw).arp_raw()

    def test_oversized_body_is_fw1error(self):
        fw = self.stub({ARP: (200, {}, b"[" + b" " * 64 + b"]")})
        with mock.patch.object(fw1, "MAX_BODY", 32):
            with self.assertRaises(Fw1Error) as cm:
                self.client(fw).arp_raw()
        self.assertIn("too large", str(cm.exception))

    def test_odd_field_types_do_not_crash(self):
        leases = {"rows": [
            {"mac": "02:00:00:00:00:01", "address": "10.0.1.5", "hostname": None, "man": None, "if": "opt1", "if_descr": 123,
             "type": "dynamic", "status": "online"},
            "not-a-row",
            {"mac": "02:00:00:00:00:02", "address": "10.0.1.6", "hostname": "ap-hall", "if": "opt1", "if_descr": "HomeNet"},
        ]}
        arp = [42, {"mac": "02:00:00:00:00:03", "ip": "10.0.1.7", "intf": "igc1", "intf_description": None, "hostname": None}]
        fw = self.stub({LEASES: js(leases), ARP: js(arp)})
        out, stats = self.client(fw).sightings(ignore_interfaces=(7, "wan"))
        by = {s.mac: s for s in out}
        self.assertEqual(sorted(by), ["02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"])
        self.assertEqual(by["02:00:00:00:00:01"].vlan, "123")
        self.assertEqual(by["02:00:00:00:00:01"].hostname, "")
        self.assertEqual(by["02:00:00:00:00:02"].hostname, "ap-hall")
        self.assertEqual(by["02:00:00:00:00:03"].vlan, "igc1")
        self.assertEqual(stats, {"leases": 3, "arp": 2})

    def test_remaining_type_errors_become_fw1error(self):
        # _s covers the known fields; simulate a type error it does not cover to check the safety net
        fw = self.stub({LEASES: js({"rows": []}), ARP: js([{"mac": "02:00:00:00:00:09"}])})
        with mock.patch.object(fw1, "_s", side_effect=TypeError("boom")):
            with self.assertRaises(Fw1Error) as cm:
                self.client(fw).sightings()
        self.assertIn("unexpected field type", str(cm.exception))

    def test_lease_type_is_normalised(self):
        leases = {"rows": [
            {"mac": "02:00:00:00:00:0a", "address": "10.0.1.10", "if": "opt1", "if_descr": "HomeNet", "type": "Static"},
            {"mac": "02:00:00:00:00:0b", "address": "10.0.1.11", "if": "opt1", "if_descr": "HomeNet", "type": "weird"},
        ]}
        fw = self.stub({LEASES: js(leases), ARP: js([])})
        by = {s.mac: s for s in self.client(fw).sightings()[0]}
        self.assertEqual(by["02:00:00:00:00:0a"].lease_type, "static")
        self.assertEqual(by["02:00:00:00:00:0b"].lease_type, "dynamic")

    def test_kea_null_state_is_not_active(self):
        self.assertEqual(kea_leases([{"hwaddr": "02:00:00:00:00:04", "state": None}]), [])
        self.assertEqual(len(kea_leases([{"hwaddr": "02:00:00:00:00:04", "state": 0, "if_descr": 5}])), 1)


KEA_LEASES = "/api/kea/leases4/search"
KEA_RES = "/api/kea/dhcpv4/searchReservation"


class KeaTests(StubCase):
    LEASE = {"hwaddr": "02:00:00:00:01:01", "address": "10.0.110.5", "state": 0, "hostname": "ap-hall",
             "if": "vlan0110", "if_name": "opt3", "if_descr": "Clients", "mac_info": "Acme", "lease_type": "dynamic"}

    def run_kea(self, leases, reservations=(), arp=(), ignore=()):
        fw = self.stub({KEA_LEASES: js({"rows": leases}), KEA_RES: js({"rows": list(reservations)}), ARP: js(list(arp))})
        out, stats = Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="kea").sightings(ignore)
        return out, stats, fw

    def test_kea_interface_identifier_and_description(self):
        out, _, _ = self.run_kea([self.LEASE])
        self.assertEqual([(s.iface, s.vlan, s.vendor) for s in out], [("opt3", "Clients", "Acme")])

    def test_kea_ignore_matches_device_identifier_and_description(self):
        for ign in (("vlan0110",), ("opt3",), ("clients",)):
            out, _, _ = self.run_kea([self.LEASE], ignore=ign)
            self.assertEqual(out, [], ign)

    def test_kea_precomputed_lease_type_wins(self):
        out, _, _ = self.run_kea([{**self.LEASE, "lease_type": "static", "is_reserved": ""}])
        self.assertEqual(out[0].lease_type, "static")

    def test_kea_list_is_reserved_without_lease_type(self):
        # OPNsense 26.1.5-26.7.3 sends is_reserved as a list and no lease_type; "[]" used to read as reserved
        base = {k: v for k, v in self.LEASE.items() if k != "lease_type"}
        cases = [([], "dynamic"), (["hwaddr"], "static"), (["client_id"], "static"), (["hwaddr", "client_id"], "static"),
                 ("1", "static"), ("0", "dynamic"), ("", "dynamic"), ("true", "static"), ("yes", "static"),
                 ("false", "dynamic"), (None, "dynamic")]
        for value, want in cases:
            self.assertEqual(kea_leases([{**base, "is_reserved": value}])[0]["type"], want, value)
        self.assertEqual(kea_leases([base])[0]["type"], "dynamic")
        self.assertEqual(kea_leases([{**base, "is_reserved": [], "lease_type": "static"}])[0]["type"], "static")

    def test_kea_reservation_without_lease_is_listed(self):
        res = [{"subnet": "10.0.110.0/24", "ip_address": "10.0.110.20", "hw_address": "02:00:00:00:01:02", "hostname": "nas"},
               {"subnet": "10.0.110.0/24", "ip_address": "10.0.110.5", "hw_address": "02:00:00:00:01:01", "hostname": "x"}]
        out, stats, fw = self.run_kea([self.LEASE], res)
        by = {}
        for s in out:
            by.setdefault(s.mac, []).append(s)
        self.assertEqual(len(by["02:00:00:00:01:01"]), 1)  # leased reservation not duplicated
        self.assertEqual(by["02:00:00:00:01:01"][0].hostname, "ap-hall")
        r = by["02:00:00:00:01:02"][0]
        self.assertEqual((r.source, r.lease_type, r.online, r.ip, r.hostname, r.iface, r.vlan),
                         ("dhcp", "static", False, "10.0.110.20", "nas", "opt3", "Clients"))
        self.assertEqual(stats, {"leases": 1, "arp": 0, "reservations": 2})
        post = [(m, p) for m, p, _, _ in fw.requests if p == KEA_RES]
        self.assertEqual(post, [("POST", KEA_RES)])

    def test_kea_reservation_vlan_from_arp_and_ignore(self):
        res = [{"subnet": "10.0.120.0/24", "ip_address": "10.0.120.9", "hw_address": "02:00:00:00:01:03"},
               {"subnet": "10.0.130.0/24", "ip_address": "10.0.130.9", "hw_address": "02:00:00:00:01:04"}]
        arp = [{"mac": "02:00:00:00:01:05", "ip": "10.0.120.7", "intf": "vlan0120", "intf_description": "IOT"}]
        out, _, _ = self.run_kea([], res, arp)
        by = {s.mac: s for s in out if s.source == "dhcp"}
        self.assertEqual((by["02:00:00:00:01:03"].vlan, by["02:00:00:00:01:03"].iface), ("IOT", ""))
        self.assertEqual(by["02:00:00:00:01:04"].vlan, "")  # unknown subnet
        out, _, _ = self.run_kea([], res, arp, ignore=("vlan0120",))
        self.assertNotIn("02:00:00:00:01:03", {s.mac for s in out})

    def test_kea_reservation_failure_is_not_fatal(self):
        arp = [{"mac": "02:00:00:00:01:05", "ip": "10.0.110.7", "intf": "vlan0110", "intf_description": "Clients"}]
        fw = self.stub({KEA_LEASES: js({"rows": [self.LEASE]}), KEA_RES: (403, {}, b"{}"), ARP: js(arp)})
        with self.assertLogs("leasewatch.fw1", "WARNING") as logs:
            out, stats = Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="kea").sightings()
        self.assertEqual({s.mac for s in out}, {"02:00:00:00:01:01", "02:00:00:00:01:05"})
        self.assertNotIn("reservations", stats)
        self.assertEqual((stats["leases"], stats["arp"]), (1, 1))
        self.assertIn("reservations unavailable", logs.output[0])

    def test_isc_never_reads_reservations(self):
        fw = self.stub({LEASES: js({"rows": []}), ARP: js([])})
        _, stats = Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="isc").sightings()
        self.assertNotIn(KEA_RES, [p for _, p, _, _ in fw.requests])
        self.assertNotIn("reservations", stats)

    def test_isc_never_reads_dnsmasq_hosts(self):
        fw = self.stub({LEASES: js({"rows": []}), ARP: js([])})
        Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="isc").sightings()
        self.assertNotIn(DNSMASQ_HOSTS, [p for _, p, _, _ in fw.requests])


DNSMASQ_LEASES = "/api/dnsmasq/leases/search"
DNSMASQ_HOSTS = "/api/dnsmasq/settings/search_host"
NOW_DM = 1_800_000_000


class DnsmasqTests(StubCase):
    # shaped from /api/dnsmasq/leases/search: Kea key names, no "state", "*" for an empty hostname/client id
    LEASE = {"expire": 1900000000, "hwaddr": "02:00:00:00:02:01", "iaid": "", "address": "10.0.110.15",
             "hostname": "alexs-ipad", "client_id": "01:02:00:00:00:02:01", "if": "vlan0110", "if_name": "opt3",
             "if_descr": "Clients", "mac_info": "Acme", "is_reserved": [], "sort_address": "x"}
    V6 = {"expire": 0, "hwaddr": "", "iaid": "33554433", "address": "fd00::15", "hostname": "*", "client_id": "*",
          "if": "vlan0110", "if_name": "opt3", "if_descr": "Clients", "mac_info": "", "is_reserved": []}

    def run_dm(self, leases, arp=(), ignore=(), hosts=()):
        fw = self.stub({DNSMASQ_LEASES: js({"total": len(leases), "rowCount": len(leases), "current": 1, "rows": leases}),
                        DNSMASQ_HOSTS: js({"total": len(hosts), "rowCount": len(hosts), "current": 1, "rows": list(hosts)}),
                        ARP: js(list(arp))})
        out, stats = Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="dnsmasq").sightings(ignore)
        return out, stats, fw

    def test_dnsmasq_row_mapped(self):
        out, stats, _ = self.run_dm([self.LEASE])
        self.assertEqual([(s.mac, s.ip, s.hostname, s.vendor, s.iface, s.vlan, s.source, s.lease_type, s.online) for s in out],
                         [("02:00:00:00:02:01", "10.0.110.15", "alexs-ipad", "Acme", "opt3", "Clients", "dhcp", "dynamic", False)])
        self.assertEqual(stats, {"leases": 1, "arp": 0, "reservations": 0})

    def test_dnsmasq_ipv6_rows_dropped(self):
        v6_with_mac = {**self.V6, "hwaddr": "02:00:00:00:02:02"}  # a DUID-LL client id gives an IPv6 row a MAC
        out, _, _ = self.run_dm([self.LEASE, self.V6, v6_with_mac])
        self.assertEqual([s.ip for s in out], ["10.0.110.15"])

    def test_dnsmasq_star_is_empty(self):
        rows = fw1.dnsmasq_leases([{**self.LEASE, "hostname": "*", "client_id": "*"}], NOW_DM)
        self.assertEqual((rows[0]["hostname"], rows[0]["mac"]), ("", "02:00:00:00:02:01"))
        self.assertEqual(fw1.dnsmasq_leases([{**self.LEASE, "client_id": "*"}], NOW_DM)[0]["hostname"], "alexs-ipad")
        out, _, _ = self.run_dm([{**self.LEASE, "hostname": "*"}])
        self.assertEqual(out[0].hostname, "")

    def test_dnsmasq_type_prefixed_hwaddr_dropped(self):
        # "<type>-<bytes>" is a non-Ethernet or empty hardware address; norm_mac would turn "06-02:00:00:00:01"
        # (5 bytes) into a 6-byte MAC that does not exist
        rows = [{**self.LEASE, "hwaddr": h} for h in ("06-02:00:00:00:01", "20-02:00:00:00:02:02", "0-")]
        self.assertEqual(fw1.dnsmasq_leases(rows, NOW_DM), [])
        out, _, _ = self.run_dm(rows + [self.LEASE])
        self.assertEqual([s.mac for s in out], ["02:00:00:00:02:01"])

    def test_dnsmasq_expired_lease_skipped(self):
        # dnsmasq prunes a past lease only later; the contrib file connector skips it, so this backend does too
        rows = [{**self.LEASE, "expire": NOW_DM}, {**self.LEASE, "expire": NOW_DM - 1, "hwaddr": "02:00:00:00:02:03"},
                {**self.LEASE, "expire": NOW_DM + 1, "hwaddr": "02:00:00:00:02:04"},
                {**self.LEASE, "expire": 0, "hwaddr": "02:00:00:00:02:05"}]  # 0: an infinite lease
        self.assertEqual([r["mac"] for r in fw1.dnsmasq_leases(rows, NOW_DM)], ["02:00:00:00:02:04", "02:00:00:00:02:05"])
        out, _, _ = self.run_dm([{**self.LEASE, "expire": 1700000000}])  # the caller supplies the current time
        self.assertEqual(out, [])

    def test_dnsmasq_non_finite_expire_keeps_the_lease(self):
        # JSON allows 1e999/Infinity; int() of it raises OverflowError, which must not escape the client
        rows = [{**self.LEASE, "expire": v, "hwaddr": f"02:00:00:00:03:0{i}"} for i, v in enumerate((float("inf"), float("-inf"), float("nan")))]
        self.assertEqual(len(fw1.dnsmasq_leases(rows, NOW_DM)), 3)

    def test_dnsmasq_lease_type_and_list_is_reserved(self):
        for extra, want in (({"is_reserved": []}, "dynamic"), ({"is_reserved": ["hwaddr"]}, "static"),
                            ({"is_reserved": ["client_id"]}, "static"), ({"is_reserved": "1"}, "static"),
                            ({"is_reserved": "0"}, "dynamic"), ({}, "dynamic"),
                            ({"is_reserved": ["hwaddr"], "lease_type": "dynamic"}, "dynamic"),
                            ({"is_reserved": [], "lease_type": "static"}, "static")):
            row = {k: v for k, v in self.LEASE.items() if k != "is_reserved"}
            out, _, _ = self.run_dm([{**row, **extra}])
            self.assertEqual(out[0].lease_type, want, extra)

    def test_dnsmasq_ignore_matches_device_identifier_and_description(self):
        for ign in (("vlan0110",), ("opt3",), ("clients",)):
            out, _, _ = self.run_dm([self.LEASE], ignore=ign)
            self.assertEqual(out, [], ign)
        out, _, _ = self.run_dm([self.LEASE], ignore=("opt4",))
        self.assertEqual(len(out), 1)

    def test_dnsmasq_calls_lease_and_host_search_and_arp(self):
        arp = [{"mac": "02:00:00:00:02:05", "ip": "10.0.110.7", "intf": "vlan0110", "intf_description": "Clients"}]
        _, stats, fw = self.run_dm([self.LEASE], arp)
        self.assertEqual(sorted(p for _, p, _, _ in fw.requests), sorted([DNSMASQ_LEASES, DNSMASQ_HOSTS, ARP]))
        post = [(m, json.loads(b)) for m, p, _, b in fw.requests if p == DNSMASQ_HOSTS]
        self.assertEqual(post, [("POST", {"current": 1, "rowCount": fw1.LEASE_ROWS})])
        self.assertNotIn("labels_unavailable", stats)

    # shaped from the OPNsense Dnsmasq.xml <hosts> model as searchBase returns it; not seen from a live firewall
    HOSTS = [
        {"uuid": "u1", "host": "alexs-ipad", "domain": "lan", "ip": "10.0.110.15", "hwaddr": "02:00:00:00:02:01",
         "ignore": "0", "descr": "Alex iPad"},                                                   # leased: label copied
        {"uuid": "u2", "host": "nas", "domain": "", "ip": ["10.0.110.20"], "hwaddr": ["02:00:00:00:02:10"],
         "ignore": "0", "descr": "NAS\tbox"},                                                   # lease-less, list form
        {"uuid": "u3", "host": "printer", "ip": "10.0.110.30", "hwaddr": "", "descr": "DNS only"},  # skipped
        {"uuid": "u4", "host": "laptop", "ip": "10.0.120.40,10.0.120.41",
         "hwaddr": "02:00:00:00:02:11, 02-00-00-00-02-12", "descr": "Laptop"},                   # two MACs, string form
        {"uuid": "u5", "host": "banned", "ip": "10.0.110.50", "hwaddr": "02:00:00:00:02:13", "ignore": "1"},  # skipped
        {"uuid": "u6", "host": "v6only", "ip": "fd00::60", "hwaddr": "02:00:00:00:02:14"},       # IPv6 only: skipped
        {"uuid": "u7", "host": "odd", "ip": None, "hwaddr": 42, "ignore": None, "descr": None},  # no valid MAC: skipped
        {"uuid": "u8", "host": "dyn", "ip": "", "hwaddr": "02:00:00:00:02:15"},                  # MAC only: no address
        "not-a-row",
    ]

    def test_dnsmasq_host_without_lease_is_listed(self):
        arp = [{"mac": "02:00:00:00:02:05", "ip": "10.0.120.7", "intf": "vlan0120", "intf_description": "IOT"}]
        out, stats, _ = self.run_dm([self.LEASE], arp, hosts=self.HOSTS)
        by = {}
        for s in out:
            if s.source == "dhcp":
                by.setdefault(s.mac, []).append(s)
        self.assertEqual(sorted(by), ["02:00:00:00:02:01", "02:00:00:00:02:10", "02:00:00:00:02:11",
                                      "02:00:00:00:02:12", "02:00:00:00:02:15"])
        leased = by["02:00:00:00:02:01"]
        self.assertEqual(len(leased), 1)  # a leased host is not duplicated
        self.assertEqual((leased[0].hostname, leased[0].lease_type, leased[0].label), ("alexs-ipad", "dynamic", "Alex iPad"))
        nas = by["02:00:00:00:02:10"][0]
        self.assertEqual((nas.lease_type, nas.online, nas.ip, nas.hostname, nas.iface, nas.vlan, nas.label),
                         ("static", False, "10.0.110.20", "nas", "opt3", "Clients", "NAS\tbox"))  # interface: lease in the /24
        for mac in ("02:00:00:00:02:11", "02:00:00:00:02:12"):
            s = by[mac][0]
            self.assertEqual((s.ip, s.hostname, s.vlan, s.iface, s.label), ("10.0.120.40", "laptop", "IOT", "", "Laptop"))
        dyn = by["02:00:00:00:02:15"][0]
        self.assertEqual((dyn.ip, dyn.vlan, dyn.lease_type, dyn.online), ("", "", "static", False))
        self.assertEqual(stats, {"leases": 1, "arp": 1, "reservations": len(self.HOSTS)})

    def test_dnsmasq_host_interface_from_exact_address_first(self):
        # 10.0.130.0/24 split in two /25: the ARP entry with the host's own address names its interface, not the
        # lease in the same /24 on the other half
        lease = {**self.LEASE, "address": "10.0.130.10", "if": "vlan0131", "if_name": "opt5", "if_descr": "Low"}
        arp = [{"mac": "02:00:00:00:02:30", "ip": "10.0.130.200", "intf": "vlan0132", "intf_description": "High"}]
        hosts = [{"host": "cam", "ip": "10.0.130.200", "hwaddr": "02:00:00:00:02:31"},
                 {"host": "guess", "ip": "10.0.130.201", "hwaddr": "02:00:00:00:02:32"}]
        out, _, _ = self.run_dm([lease], arp, hosts=hosts)
        got = {s.mac: (s.vlan, s.iface) for s in out if s.source == "dhcp"}
        self.assertEqual(got["02:00:00:00:02:31"], ("High", ""))
        self.assertEqual(got["02:00:00:00:02:32"], ("Low", "opt5"))  # no exact match: the /24 guess

    def test_dnsmasq_hosts_parser(self):
        for v in ("1", 1, True, "true"):
            self.assertEqual(fw1.dnsmasq_hosts([{"hwaddr": "02:00:00:00:02:20", "ignore": v}], {}), [], v)
        for v in ("0", 0, False, "", None):
            self.assertEqual(len(fw1.dnsmasq_hosts([{"hwaddr": "02:00:00:00:02:20", "ignore": v}], {})), 1, v)
        rows = fw1.dnsmasq_hosts([{"hwaddr": "02:00:00:00:02:21,02:00:00:00:02:21", "ip": ["fd00::1", "10.0.1.9"],
                                   "descr": "x" * 200}], {})
        self.assertEqual([(r["mac"], r["address"], r["subnet"], len(r["label"])) for r in rows],
                         [("02:00:00:00:02:21", "10.0.1.9", "", fw1.LABEL_MAX)])
        self.assertEqual(fw1.dnsmasq_hosts([{"hwaddr": "02:00:00:00:02:22", "ip": ["fd00::2", "fe80::2"]}], {}), [])
        self.assertEqual([r["address"] for r in fw1.dnsmasq_hosts([{"hwaddr": "02:00:00:00:02:23", "ip": []}], {})], [""])

    def test_dnsmasq_host_failure_is_not_fatal(self):
        arp = [{"mac": "02:00:00:00:02:05", "ip": "10.0.110.7", "intf": "vlan0110", "intf_description": "Clients"}]
        fw = self.stub({DNSMASQ_LEASES: js({"rows": [self.LEASE]}), DNSMASQ_HOSTS: (403, {}, b"{}"), ARP: js(arp)})
        with self.assertLogs("leasewatch.fw1", "WARNING") as logs:
            out, stats = Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="dnsmasq").sightings()
        self.assertEqual({s.mac for s in out}, {"02:00:00:00:02:01", "02:00:00:00:02:05"})
        self.assertNotIn("reservations", stats)
        self.assertEqual(stats["labels_unavailable"], 1)
        self.assertIn("HTTP 403", logs.output[0])

    def test_dnsmasq_errors_are_fw1_errors(self):
        fw = self.stub({DNSMASQ_LEASES: (403, {}, b"{}"), ARP: js([])})
        with self.assertRaisesRegex(Fw1Error, "HTTP 403"):
            Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="dnsmasq").sightings()
        fw = self.stub({DNSMASQ_LEASES: js({"total": 1}), ARP: js([])})
        with self.assertRaisesRegex(Fw1Error, "unexpected response shape"):
            Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="dnsmasq").sightings()
        fw = self.stub({DNSMASQ_LEASES: (302, {"Location": "http://10.0.0.9/"}, b""), ARP: js([])})
        with self.assertRaisesRegex(Fw1Error, "HTTP 302"):
            Fw1Client(fw.url, "k", "s", timeout=5, dhcp_backend="dnsmasq").sightings()
        self.assertEqual([p for _, p, _, _ in fw.requests], [DNSMASQ_LEASES])


def unifi_cfg(url):
    return _UnifiCfg(unifi_url=url, unifi_site="default", unifi_user="ro", unifi_password="pw", unifi_verify_tls=False)


STA = "/api/s/default/stat/sta"
DEV = "/api/s/default/stat/device"
OK = {"meta": {"rc": "ok"}, "data": []}


class UnifiTests(StubCase):
    def test_login_redirect_is_not_followed(self):
        target = self.stub({"/api/login": js(OK)})
        ctl = self.stub({"/api/login": (302, {"Location": target.url + "/api/login"}, b"")})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: HTTP 302")
        self.assertEqual(target.requests, [])

    def test_device_without_mac_does_not_name_every_ap(self):
        sta = [{"mac": "02:00:00:00:00:05", "essid": "HomeNet", "ap_mac": ""}]
        devices = [{"mac": "", "name": "ap-hall"}, {"mac": "02:00:00:00:00:aa", "name": "ap-kitchen"}]
        self.assertEqual(parse_clients(sta, devices)["02:00:00:00:00:05"].ap, "")

    def test_api_error_rc(self):
        ctl = self.stub({"/api/login": js(OK), STA: js({"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}, "data": []})})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: api.err.NoSiteContext")

    def test_data_not_a_list(self):
        ctl = self.stub({"/api/login": js(OK), STA: js({"meta": {"rc": "ok"}, "data": {"x": 1}})})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: unexpected response shape")

    def test_odd_rows_become_runtimeerror(self):
        ctl = self.stub({"/api/login": js(OK), STA: js({"data": ["not-a-dict"]}), DEV: js(OK)})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: unexpected response")

    def test_invalid_url_does_not_echo_credentials(self):
        cfg = unifi_cfg("http://admin:hunter2@127.0.0.1:notaport")
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(cfg).clients()
        self.assertNotIn("hunter2", str(cm.exception))

    def test_deeply_nested_json_is_runtimeerror(self):
        ctl = self.stub({"/api/login": js(OK), STA: (200, {}, b"[" * 200_000)})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: unexpected response")

    def test_oversized_body_is_runtimeerror(self):
        ctl = self.stub({"/api/login": js(OK), STA: (200, {}, b'{"data": []' + b" " * 64 + b"}")})
        with mock.patch.object(unifi, "MAX_BODY", 32):
            with self.assertRaises(RuntimeError) as cm:
                UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: response too large")

    def test_happy_path(self):
        sta = {"data": [{"mac": "02:00:00:00:00:06", "essid": "HomeNet", "ap_mac": "02:00:00:00:00:aa", "signal": -60}]}
        ctl = self.stub({"/api/login": js(OK), STA: js(sta), DEV: js({"data": [{"mac": "02:00:00:00:00:aa", "name": "ap-hall"}]})})
        out = UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(out["02:00:00:00:00:06"].ap, "ap-hall")


DEVICE = {"ip": "10.0.1.8", "mac": "02:00:00:00:00:07", "hostname": "evil\r\nBcc: x@example.com", "vendor": "",
          "vlan": "HomeNet", "lease_type": "dynamic"}


def mail_cfg(base):
    return Config(mailgun_key="key", mailgun_domain="mg.example.com", mail_to="you@example.com", mailgun_api_base=base)


class NotifyTests(StubCase):
    def test_http_error_is_mailerror(self):
        mg = self.stub({"/v3/mg.example.com/messages": (401, {}, b"Forbidden")})
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(mail_cfg(mg.url), [DEVICE])
        self.assertEqual(str(cm.exception), "mailgun: HTTP 401")

    def test_connection_error_is_mailerror(self):
        mg = self.stub()
        url = mg.url
        mg.close(); self.stubs.remove(mg)
        with self.assertRaises(notify.MailError):
            notify.new_devices(mail_cfg(url), [DEVICE])

    def test_malformed_status_line_is_mailerror(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        self.addCleanup(srv.close)

        def answer():
            conn, _ = srv.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(b"garbage\r\n\r\n")
        t = threading.Thread(target=answer, daemon=True); t.start()
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(mail_cfg(f"http://127.0.0.1:{srv.getsockname()[1]}"), [DEVICE])
        t.join(5)
        self.assertEqual(str(cm.exception), "mailgun: bad response")

    def test_bad_api_base_is_mailerror_without_url(self):
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(mail_cfg("api.eu.mailgun.net"), [DEVICE])
        self.assertEqual(str(cm.exception), "mailgun: bad MAILGUN_API_BASE")

    def test_subject_is_sanitised_and_base_url_used(self):
        mg = self.stub({"/v3/mg.example.com/messages": js({"id": "x"})})
        notify.new_devices(mail_cfg(mg.url), [DEVICE])
        self.assertEqual(len(mg.requests), 1)
        from urllib.parse import parse_qs
        form = parse_qs(mg.requests[0][3].decode())
        subject = form["subject"][0]
        self.assertNotIn("\r", subject); self.assertNotIn("\n", subject)
        self.assertIn("evil  Bcc: x@example.com", subject)

    def test_redirect_is_not_followed(self):
        # a 3xx would resend the Authorization header (the API key) to the redirect target
        target = self.stub({"/v3/mg.example.com/messages": js({"id": "x"})})
        mg = self.stub({"/v3/mg.example.com/messages": (302, {"Location": target.url + "/v3/mg.example.com/messages"}, b"")})
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(mail_cfg(mg.url), [DEVICE])
        self.assertEqual(str(cm.exception), "mailgun: HTTP 302 (redirect not followed)")
        self.assertEqual(target.requests, [])

    def test_invalid_domain_names_the_settings(self):
        # http.client.InvalidURL is an HTTPException, not a server's bad response
        cfg = Config(mailgun_key="key", mailgun_domain="mg example", mail_to="you@example.com",
                     mailgun_api_base="http://127.0.0.1:1")
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(cfg, [DEVICE])
        self.assertEqual(str(cm.exception), "mailgun: bad MAILGUN_DOMAIN or MAILGUN_API_BASE")


class ProxyTests(StubCase):
    """LAN clients must not send the firewall/UniFi credentials through an http(s)_proxy unless the instance's proxy setting is set."""
    PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY")

    def setUp(self):
        super().setUp()
        for k in self.PROXY_VARS:
            os.environ.pop(k, None)
        self.fw = self.stub({LEASES: js({"rows": [], "total": 0})})
        self.proxy = self.stub()
        # urllib reads the proxy settings when the opener is built, so they are set before the client exists
        os.environ["http_proxy"] = os.environ["https_proxy"] = self.proxy.url

    def test_fw1_ignores_env_proxy_by_default(self):
        Fw1Client(self.fw.url, "k", "s", timeout=5).leases_raw()
        self.assertEqual(self.proxy.requests, [])
        self.assertEqual([r[1] for r in self.fw.requests], [LEASES])

    def test_fw1_uses_env_proxy_when_asked(self):
        with self.assertRaises(Fw1Error):  # the proxy stub answers 404
            Fw1Client(self.fw.url, "k", "s", timeout=5, use_env_proxy=True).leases_raw()
        self.assertEqual(self.fw.requests, [])
        self.assertEqual([r[1] for r in self.proxy.requests], [self.fw.url + LEASES])

    def test_unifi_ignores_env_proxy_by_default(self):
        ctl = self.stub({"/api/login": js(OK), STA: js(OK), DEV: js(OK)})
        self.assertEqual(UnifiClient(unifi_cfg(ctl.url)).clients(), {})
        self.assertEqual(self.proxy.requests, [])


if __name__ == "__main__":
    unittest.main()
