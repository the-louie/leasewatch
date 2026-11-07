"""Deep links in the notifications: every device links to its own page (`/?device=<mac>`) in the text mail, the
webhook JSON, ntfy and Discord. Synthetic data only."""
from __future__ import annotations

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore  # noqa: E402
from leasewatch import notify  # noqa: E402
from leasewatch.config import Config  # noqa: E402

PUB = "https://leases.example.lan"


def dev(i: int) -> dict:
    return {"mac": f"02:00:00:00:02:{i:02x}", "ip": f"10.0.2.{i + 10}", "hostname": f"host-{i}-" + "h" * 25,
            "vendor": "Acme", "vlan": "HomeNet", "lease_type": "dynamic"}


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        saved = clean_env({})
        self.addCleanup(restore, saved)

    def cfg(self, **env: str) -> Config:
        os.environ.update(env)
        return Config()

    def request(self, fmt: str, devs: list[dict], public: str = PUB) -> tuple[notify.Message, dict]:
        cfg = self.cfg(WEBHOOK_URL="http://127.0.0.1:9/hook/topic", WEBHOOK_FORMAT=fmt, PUBLIC_URL=public)
        msg = notify.build_message(cfg, devs)
        return msg, notify.WebhookChannel(cfg)._request(msg)[1]


class MailTextTests(_Base):
    def test_each_device_has_its_link_line(self) -> None:
        msg = notify.build_message(self.cfg(PUBLIC_URL=PUB), [dev(1), dev(2)])
        lines = msg.text.split("\n")
        links = [ln for ln in lines if "?device=" in ln]
        self.assertEqual(links, [f"    {PUB}/?device=02:00:00:00:02:01", f"    {PUB}/?device=02:00:00:00:02:02"])
        for i, ln in enumerate(lines):  # a link line follows the line of its own device
            if "?device=" in ln:
                self.assertIn(ln.rsplit("=", 1)[1], lines[i - 1])
        self.assertEqual(lines[-1], f"Review and acknowledge: {PUB}/?filter=unacked")
        self.assertEqual(msg.links, [ln.strip() for ln in links])

    def test_no_link_without_public_url(self) -> None:
        msg = notify.build_message(self.cfg(), [dev(1), dev(2)])
        self.assertNotIn("?device=", msg.text)
        self.assertNotIn("http", msg.text)
        self.assertEqual(msg.links, [])

    def test_trailing_slash_does_not_double(self) -> None:
        # Config strips it; a Config built by hand may not
        cfg = self.cfg(PUBLIC_URL=PUB)
        cfg.public_url = PUB + "/"
        msg = notify.build_message(cfg, [dev(1)])
        self.assertEqual(msg.links, [f"{PUB}/?device=02:00:00:00:02:01"])
        self.assertEqual(msg.url, f"{PUB}/?filter=unacked")
        self.assertNotIn("//?", msg.text)

    def test_hostname_with_newline_cannot_forge_a_link(self) -> None:
        d = {**dev(1), "hostname": f"x\n    {PUB}/?device=02:00:00:00:ff:ff"}
        msg = notify.build_message(self.cfg(PUBLIC_URL=PUB), [d])
        # the forged text stays inside the device line: only the real link has a line of its own
        own = [ln for ln in msg.text.split("\n") if ln.startswith("    http")]
        self.assertEqual(own, [f"    {PUB}/?device=02:00:00:00:02:01"])


class WebhookTests(_Base):
    def test_json_has_a_url_per_device(self) -> None:
        _, body = self.request("json", [dev(1), dev(2)])
        self.assertEqual([d["url"] for d in body["devices"]],
                         [f"{PUB}/?device=02:00:00:00:02:01", f"{PUB}/?device=02:00:00:00:02:02"])
        self.assertEqual(body["url"], f"{PUB}/?filter=unacked")

    def test_json_url_null_without_public_url(self) -> None:
        _, body = self.request("json", [dev(1)], public="")
        self.assertIsNone(body["devices"][0]["url"])

    def test_ntfy_one_device_clicks_to_it(self) -> None:
        _, body = self.request("ntfy", [dev(1)])
        self.assertEqual(body["click"], f"{PUB}/?device=02:00:00:00:02:01")

    def test_ntfy_several_devices_click_to_the_list(self) -> None:
        _, body = self.request("ntfy", [dev(1), dev(2)])
        self.assertEqual(body["click"], f"{PUB}/?filter=unacked")

    def test_ntfy_without_public_url_has_no_click(self) -> None:
        _, body = self.request("ntfy", [dev(1)], public="")
        self.assertNotIn("click", body)

    def test_ntfy_cut_keeps_each_line_with_its_link(self) -> None:
        devs = [dev(i) for i in range(60)]
        msg, body = self.request("ntfy", devs)
        self.assertGreaterEqual(len(msg.text.encode()), notify.NTFY_MAX)  # the cut applies
        text = body["message"]
        self.assertLess(len(text.encode()), notify.NTFY_MAX)
        lines = text.split("\n")
        shown = [ln for ln in lines if re.match(r"  10\.0\.2\.", ln)]
        links = [ln for ln in lines if ln.startswith("    https://")]
        self.assertTrue(0 < len(shown) < 60)
        self.assertEqual(len(shown), len(links))
        for i, ln in enumerate(lines):
            if re.match(r"  10\.0\.2\.", ln):  # every shown device line is followed by its own link
                self.assertEqual(lines[i + 1], f"    {PUB}/?device={ln.split()[1]}")
            if ln.startswith("    https://"):
                self.assertIn(ln.rsplit("=", 1)[1], lines[i - 1])
        self.assertIn(f"  … and {60 - len(shown)} more", lines)
        self.assertEqual(lines[-1], f"Review and acknowledge: {PUB}/?filter=unacked")

    def test_discord_one_device_links_to_it(self) -> None:
        _, body = self.request("discord", [dev(1)])
        self.assertTrue(body["content"].endswith(f"```\n{PUB}/?device=02:00:00:00:02:01"))

    def test_discord_several_devices_link_once_to_the_list(self) -> None:
        _, body = self.request("discord", [dev(i) for i in range(12)])
        self.assertEqual(body["content"].count("https://"), 1)
        self.assertTrue(body["content"].endswith(f"```\n{PUB}/?filter=unacked"))
        self.assertLessEqual(len(body["content"]), notify.DISCORD_MAX)


if __name__ == "__main__":
    unittest.main()
