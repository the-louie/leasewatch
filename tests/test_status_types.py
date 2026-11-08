"""/api/status lists the loaded connector types, the refused plugins (a built-in name) and the broken ones; the same
payload is not in _meta(), so /healthz, /api/stats and the ETag of /api/devices stay as they were."""
import json
import os
import sys
import unittest
from unittest import mock

import test_web
from test_basic_auth import GOOD, HASH, USER
from test_loader import make_dir_dist
from test_web import WebTestCase
from leasewatch.connectors import _reset_registry, type_report

TYPE_KEYS = {"type", "origin", "dist", "version", "type_version", "instances"}


class StatusTypesBase(WebTestCase):
    def use_plugins(self, *dists):
        """dists: (dist, pkg, type) written into a LW_CONNECTORS_DIR for this test."""
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        before = set(sys.modules)
        for dist, pkg, type_ in dists:
            make_dir_dist(tmp.name, dist, pkg, type_)
        os.environ["LW_CONNECTORS_DIR"] = tmp.name  # restored with the rest of the environment at tearDown

        def undo():
            for n in set(sys.modules) - before:
                if n.split(".")[0].startswith("lwt_"):
                    del sys.modules[n]
            _reset_registry()
        self.addCleanup(undo)
        return tmp.name

    def status(self, headers=None):
        status, _, body = self.req("GET", "/api/status", headers=headers)
        self.assertEqual(status, 200, body[:300])
        return json.loads(body)


class TypesTests(StatusTypesBase):
    def tearDown(self):
        _reset_registry()
        super().tearDown()

    def test_built_ins_only(self):
        st = self.status()
        self.assertEqual(set(st), {"meta", "types", "refused", "broken"})
        self.assertEqual([t["type"] for t in st["types"]], ["opnsense", "snmp_switch", "unifi"])
        for t in st["types"]:
            self.assertEqual(set(t), TYPE_KEYS)
            self.assertEqual(t["origin"], "built-in")
            self.assertEqual((t["dist"], t["version"]), ("", ""))
            self.assertTrue(t["type_version"])
        self.assertEqual({t["type"]: t["instances"] for t in st["types"]},
                         {"opnsense": 1, "snmp_switch": 0, "unifi": 0})
        self.assertEqual((st["refused"], st["broken"]), ([], []))

    def test_dir_plugin_shows_dist_and_version_and_no_path(self):
        root = self.use_plugins(("lw-demo", "lwt_demo", "demotype"))
        st = self.status()
        self.assertEqual([t["type"] for t in st["types"]], ["opnsense", "snmp_switch", "unifi", "demotype"])
        demo = st["types"][-1]
        self.assertEqual(demo, {"type": "demotype", "origin": "LW_CONNECTORS_DIR lw-demo", "dist": "lw-demo",
                                "version": "0.3.0", "type_version": "0.3.0", "instances": 0})
        body = json.dumps(st)
        self.assertNotIn(root, body)
        for t in st["types"]:  # no value is a path
            self.assertFalse(any("/" in str(v) for v in t.values()), t)

    def test_plugin_with_a_built_in_name_is_refused(self):
        self.use_plugins(("lw-fake-fw", "lwt_fakefw", "opnsense"))
        st = self.status()
        self.assertEqual(st["refused"], [{"type": "opnsense", "reason": "conflicts with the built-in type opnsense; "
                                                                        "declared by LW_CONNECTORS_DIR lw-fake-fw"}])
        self.assertEqual(next(t for t in st["types"] if t["type"] == "opnsense")["origin"], "built-in")
        self.assertNotIn("lwt_fakefw", sys.modules)  # refused before any import

    def test_broken_plugin_is_listed_with_a_one_line_reason(self):
        self.use_plugins(("lw-a", "lwt_a", "twice"))
        # the same type from an entry point on sys.path
        import tempfile
        from test_loader import make_ep_dist
        site_dir = tempfile.TemporaryDirectory()  # its own directory: never next to LW_CONNECTORS_DIR
        self.addCleanup(site_dir.cleanup)
        site = site_dir.name
        make_ep_dist(site, "lw-b", "lwt_b", "twice")
        self.addCleanup(lambda: sys.path.remove(site))
        sys.path.append(site)
        st = self.status()
        self.assertEqual([b["type"] for b in st["broken"]], ["twice"])
        self.assertIn("provided twice", st["broken"][0]["reason"])
        self.assertNotIn("twice", [t["type"] for t in st["types"]])

    def test_reasons_are_cut_and_masked(self):
        from leasewatch.connectors import loader
        res = loader.LoadResult(refused={"x": "first " + "y" * 300 + "\nsecond line"},
                                broken={"z": "see fw1.example.lan\nmore"})
        with mock.patch("leasewatch.connectors._loaded", return_value=res):
            rep = type_report([], lambda s: s.replace("fw1.example.lan", "<host>"))
        self.assertEqual(len(rep["refused"][0]["reason"]), 200)
        self.assertNotIn("second", rep["refused"][0]["reason"])
        self.assertEqual(rep["broken"][0]["reason"], "see <host>")

    def test_a_secret_crossing_the_cut_is_masked_whole(self):
        from leasewatch.connectors import loader
        secret = "S3cr3tT0ken-ABCDE"[:16]
        res = loader.LoadResult(broken={"z": "x" * 190 + secret + " tail"})
        with mock.patch("leasewatch.connectors._loaded", return_value=res):
            rep = type_report([], lambda s: s.replace(secret, "<secret>"))
        r = rep["broken"][0]["reason"]
        self.assertNotIn(secret[:4], r)
        self.assertLessEqual(len(r), 200)

    def test_a_host_in_a_reason_is_masked_in_the_response(self):
        from leasewatch.connectors import loader
        res = loader.LoadResult(broken={"z": "cannot reach fw1.example.lan"})
        with mock.patch("leasewatch.connectors._loaded", return_value=res):
            st = self.status()
        self.assertEqual(st["broken"], [{"type": "z", "reason": "cannot reach <host>"}])

    def test_other_bodies_do_not_carry_the_types(self):
        self.use_plugins(("lw-demo", "lwt_demo", "demotype"))
        for path in ("/healthz", "/api/stats", "/api/devices"):
            body, _ = self.get_json(path)
            self.assertEqual(set(body) & {"types", "refused", "broken"}, set(), path)
        health, _ = self.get_json("/healthz")
        stats, _ = self.get_json("/api/stats")
        self.assertEqual(set(stats), {"meta", "stats"})
        self.assertEqual(set(health) - set(stats["meta"]), {"ok", "reason"})  # healthz = meta + ok + reason
        self.assertEqual(set(stats["meta"]), set(self.status()["meta"]))

    def test_devices_etag_ignores_the_loaded_types(self):
        _, h1 = self.get_json("/api/devices")
        self.use_plugins(("lw-demo", "lwt_demo", "demotype"))
        self.status()
        _, h2 = self.get_json("/api/devices")
        self.assertEqual(h1["ETag"], h2["ETag"])


class AuthTypesTests(StatusTypesBase):
    def setUp(self):
        with mock.patch.dict(test_web.ENV, AUTH_USER=USER, AUTH_PASSWORD_HASH=HASH):
            super().setUp()

    def test_needs_credentials(self):
        status, _, body = self.req("GET", "/api/status")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"error": "authentication required"})
        self.assertEqual(set(self.status({"Authorization": GOOD})), {"meta", "types", "refused", "broken"})


class ReadOnlyTypesTests(StatusTypesBase):
    def setUp(self):
        with mock.patch.dict(test_web.ENV, READ_ONLY="1"):
            super().setUp()

    def test_still_answers(self):
        st = self.status()
        self.assertEqual(len(st["types"]), 3)
        self.assertFalse(st["meta"]["can_write"])


if __name__ == "__main__":
    unittest.main()
