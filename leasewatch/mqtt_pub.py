"""Device presence over MQTT: one state and one attributes topic per selected device, a stats topic and a status topic.
With discovery on, Home Assistant also gets a device_tracker config per device and four sensor configs; with discovery
off, the configs from an earlier run are cleared once. A birth message from Home Assistant sends everything again.

The collector calls publish_poll() after each good poll. Only what changed since the last publish goes out (all of it
after a (re)connect); a device that leaves the selection has its retained messages cleared. The ids that have retained
messages on the broker are kept in meta `mqtt.published` with the discovery node they were published under
({"node", "ids"}; a plain list is read as the current node), so a device that left the selection while the process was
down is still cleared after the restart, and a changed SITE_NAME clears the old node's configs. A change of
last_online alone sends no attributes.

Every MqttError propagates to the caller after the connection is closed (connected is False) and the next poll is
marked to publish everything again; the caller reconnects.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import ssl
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from .config import Config
from .db import Database
from .mqtt import Client, MqttError
from .notify import SmtpChannel, WebhookChannel, _tls_context

log = logging.getLogger("leasewatch.mqtt_pub")

# seconds the notifications after the MQTT step may take: the sum of the channels' own timeouts (Mailgun's request
# 20 s, SMTP 20 s, webhook 10 s; MQTT sends are traffic of their own). A failing channel waits in its backoff, so the
# alert and the new-device message do not each pay it
NOTIFY_SECONDS = 20 + int(SmtpChannel.timeout + WebhookChannel.timeout)

META_PUBLISHED = "mqtt.published"
META_CLEARED = "mqtt.discovery_cleared"
SUPPORT_URL = "https://github.com/the-louie/leasewatch"
SENSORS = {"devices": "Devices", "online": "Online", "unacked": "Not yet known", "new": "New"}  # stats key -> name


def node_id(cfg: Config) -> str:
    """The discovery node id: leasewatch_<site name as a slug> (lower case, other characters "_")."""
    slug = re.sub(r"[^a-z0-9]+", "_", cfg.site_name.lower()).strip("_")
    return f"leasewatch_{slug}" if slug else "leasewatch"


def device_id(mac: str) -> str:
    """The MAC without colons, lower case: the per-device topic level."""
    return mac.replace(":", "").lower()


def _json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _iso_utc(ts: int | None) -> str | None:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


class Publisher:
    timeout: float = 5.0  # seconds per broker operation

    def __init__(self, cfg: Config, db: Database, version: str, clock: Callable[[], float] = time.monotonic) -> None:
        self.cfg = cfg
        self.db = db
        self.version = version
        self.clock = clock
        self.base = cfg.mqtt_topic
        # two polls, each as long as the slowest connector may take plus the notifications sent after the MQTT step:
        # a slow poll must not let the broker fire the Will
        slowest = max((s.timeout for s in cfg.instances), default=60)
        self.keepalive = min(2 * (cfg.poll_seconds + slowest + NOTIFY_SECONDS), 0xFFFF)
        self.client: Client | None = None
        self.full = True
        self.birth_seen = False
        self.subscribe_warned = False  # the refused birth subscription was logged (once per process)
        # id -> (state, attributes JSON without last_online, config JSON) as last published
        self.last: dict[str, tuple[str, str, str]] = {}
        self.published: set[str] = set()  # ids that may have retained messages on the broker
        self.stored_node = node_id(cfg)  # the node whose configs the stored ids have on the broker

    @property
    def connected(self) -> bool:
        return self.client is not None and self.client.connected

    @contextmanager
    def _closing_on_error(self) -> Iterator[None]:
        try:
            yield
        except Exception:
            self.full = True
            if self.client is not None:
                self.client.close()
            raise

    def _tls(self) -> ssl.SSLContext | None:
        if not self.cfg.mqtt_endpoint[2]:
            return None
        verify = self.cfg.mqtt_verify_tls_on
        if not self.cfg.mqtt_ca_file:
            return _tls_context(verify)
        ctx = ssl.create_default_context(cafile=self.cfg.mqtt_ca_file)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def connect(self) -> None:
        if self.client is not None:
            self.client.close()
        host, port, _ = self.cfg.mqtt_endpoint
        status = f"{self.base}/status"
        self.client = Client(host, port, tls=self._tls(), client_id=self.cfg.mqtt_client_id_effective,
                             user=self.cfg.mqtt_user, password=self.cfg.mqtt_password, keepalive=self.keepalive,
                             will=(status, b"offline", 1, True), timeout=self.timeout, clock=self.clock)
        node = node_id(self.cfg)
        try:
            stored = json.loads(self.db.get_meta(META_PUBLISHED, "[]"))
        except ValueError:
            stored = []
        if isinstance(stored, list):  # the 1.5.0 form: a list of ids, under the current node
            stored = {"node": node, "ids": stored}
        if not isinstance(stored, dict):
            stored = {}
        ids = stored.get("ids")
        ids = ids if isinstance(ids, list) else []
        old = stored.get("node")
        self.stored_node = old if isinstance(old, str) and re.fullmatch(r"leasewatch(_[a-z0-9_]+)?", old) else node
        # leftovers: ids with retained messages that the first publish_poll clears when they are not selected
        self.published = {i for i in ids if isinstance(i, str) and re.fullmatch(r"[0-9a-f]{12}", i)} | set(self.last)
        with self._closing_on_error():
            self.client.connect()
            self.client.publish(status, "online", qos=1, retain=True)
            if self.cfg.mqtt_discovery_on:
                birth = f"{self.cfg.mqtt_discovery_prefix}/status"
                try:
                    self.client.subscribe(birth, qos=1)
                except MqttError:
                    if not self.client.connected:  # the connection failed, not the subscription
                        raise
                    if not self.subscribe_warned:  # e.g. a write-only ACL: publish without the birth feature
                        log.warning("mqtt: cannot subscribe to %s, discovery will not be re-sent when Home Assistant "
                                    "restarts", birth)
                        self.subscribe_warned = True
        self.full = True

    def selected(self, rows: list[dict]) -> list[dict]:
        mode = self.cfg.mqtt_devices
        out = []
        for r in rows:
            if r.get("archived_ts") is not None:
                continue
            if mode == "watched":
                keep = bool(r.get("watch"))
            elif mode == "named":
                keep = bool(r.get("name"))
            elif mode == "known":
                keep = bool(r.get("acked")) or bool(r.get("name"))
            else:
                keep = True
            if keep:
                out.append(r)
        return out

    def _attributes(self, r: dict, last_online: bool = True) -> str:
        """The attributes JSON; without last_online (which moves every poll for an online device) for the diff."""
        base = self.cfg.public_url.rstrip("/")
        mac = r["mac"].lower()
        tags = r.get("tags") or ""
        attrs = {
            "ip": r.get("ip") or "", "ip6": r.get("ip6") or "", "hostname": r.get("hostname") or "",
            "name": r.get("name") or "", "vlan": r.get("vlan") or "", "switch_port": r.get("sw_port") or "",
            "wifi_ssid": r.get("wifi_ssid") or "", "tags": [t for t in tags.split(",") if t],
            "url": f"{base}/?device={mac}" if base else None, "mac": mac,
        }
        if last_online:
            attrs["last_online"] = _iso_utc(r.get("last_online"))
        return _json(attrs)

    def _device_config(self, r: dict, i: str) -> str:
        b, node = self.base, node_id(self.cfg)
        mac = r["mac"].lower()
        name = r.get("name") or r.get("hostname") or mac
        device: dict = {"identifiers": [f"{node}_{i}"], "connections": [["mac", mac]], "name": name, "via_device": node}
        if r.get("vendor"):
            device["manufacturer"] = r["vendor"]
        return _json({
            "name": name, "unique_id": f"{node}_{i}",
            "state_topic": f"{b}/device/{i}/state", "json_attributes_topic": f"{b}/device/{i}/attributes",
            "payload_home": "home", "payload_not_home": "not_home", "source_type": "router",
            "availability_topic": f"{b}/status", "payload_available": "online", "payload_not_available": "offline",
            "device": device, "origin": self._origin(),
        })

    def _origin(self) -> dict:
        return {"name": "leasewatch", "sw_version": self.version, "support_url": SUPPORT_URL}

    def _sensor_topic(self, key: str) -> str:
        return f"{self.cfg.mqtt_discovery_prefix}/sensor/{node_id(self.cfg)}/{key}/config"

    def _sensor_config(self, key: str) -> str:
        node = node_id(self.cfg)
        device: dict = {"identifiers": [node], "name": f"leasewatch {self.cfg.site_name}", "manufacturer": "leasewatch",
                        "sw_version": self.version}
        if self.cfg.public_url:
            device["configuration_url"] = self.cfg.public_url
        return _json({
            "name": SENSORS[key], "unique_id": f"{node}_{key}", "state_topic": f"{self.base}/stats",
            "value_template": "{{ value_json." + key + " }}", "state_class": "measurement",
            "availability_topic": f"{self.base}/status", "device": device, "origin": self._origin(),
        })

    def _require(self) -> Client:
        if self.client is None:
            raise MqttError("mqtt: not connected")
        return self.client

    def publish_poll(self, rows: list[dict], stats: dict) -> None:
        client = self._require()
        b = self.base
        sent = removed = 0
        before = set(self.published)
        moved = False  # the old node's configs were cleared: the stored node changes
        try:
            with self._closing_on_error():
                birth = f"{self.cfg.mqtt_discovery_prefix}/status"
                for topic, payload in client.poll_incoming():
                    if topic == birth and payload == b"online":
                        self.birth_seen = True
                if self.birth_seen:  # Home Assistant (re)started: send everything again
                    self.full = True
                    self.birth_seen = False
                discovery = self.cfg.mqtt_discovery_on
                prefix, node = self.cfg.mqtt_discovery_prefix, node_id(self.cfg)
                config_base = f"{prefix}/device_tracker/{node}"
                if self.full and self.stored_node != node:  # SITE_NAME changed: the old node's configs go
                    old = self.stored_node
                    for i in sorted(self.published):
                        client.publish(f"{prefix}/device_tracker/{old}/{i}/config", b"", qos=1, retain=True)
                    for key in SENSORS:
                        client.publish(f"{prefix}/sensor/{old}/{key}/config", b"", qos=1, retain=True)
                    self.stored_node = node
                    moved = True
                want: dict[str, dict] = {device_id(r["mac"]): r for r in self.selected(rows)}
                cleared = self.db.get_meta(META_CLEARED, "0") == "1" if self.full else True
                if self.full and not discovery and not cleared:
                    for i in sorted(self.published & set(want)):
                        client.publish(f"{config_base}/{i}/config", b"", qos=1, retain=True)
                    for key in SENSORS:
                        client.publish(self._sensor_topic(key), b"", qos=1, retain=True)
                for i, r in want.items():
                    state = "home" if r.get("online") else "not_home"
                    attrs = self._attributes(r, last_online=False)
                    conf = self._device_config(r, i) if discovery else ""
                    prev = None if self.full else self.last.get(i)
                    if prev is not None and prev == (state, attrs, conf):
                        continue
                    self.published.add(i)
                    if conf and (prev is None or prev[2] != conf):
                        client.publish(f"{config_base}/{i}/config", conf, qos=1, retain=True)
                    if prev is None or prev[0] != state:
                        client.publish(f"{b}/device/{i}/state", state, qos=1, retain=True)
                    if prev is None or prev[0] != state or prev[1] != attrs:  # with the current last_online
                        client.publish(f"{b}/device/{i}/attributes", self._attributes(r), qos=1, retain=True)
                    self.last[i] = (state, attrs, conf)
                    sent += 1
                if self.full and discovery:
                    for key in SENSORS:
                        client.publish(self._sensor_topic(key), self._sensor_config(key), qos=1, retain=True)
                for i in sorted((self.published | set(self.last)) - set(want)):
                    for topic in (f"{b}/device/{i}/state", f"{b}/device/{i}/attributes", f"{config_base}/{i}/config"):
                        client.publish(topic, b"", qos=1, retain=True)
                    self.last.pop(i, None)
                    self.published.discard(i)
                    removed += 1
                client.publish(f"{b}/stats", _json({
                    "devices": stats.get("total", 0), "online": stats.get("online", 0),
                    "unacked": stats.get("unacked", 0), "new": stats.get("new", 0),
                }), qos=1, retain=True)
                if self.full and discovery == cleared:  # off and not yet cleared, or on after a cleared run
                    self.db.set_meta(META_CLEARED, "0" if discovery else "1")
        finally:
            if self.published != before or moved:
                try:
                    self.db.set_meta(META_PUBLISHED, _json({"node": self.stored_node, "ids": sorted(self.published)}))
                except sqlite3.Error as e:
                    log.warning("mqtt: could not store the published devices (%s)", e)
        self.full = False
        log.debug("mqtt: poll published %d device(s), removed %d", sent, removed)

    def publish_status(self, online: bool) -> None:
        client = self._require()
        with self._closing_on_error():
            client.publish(f"{self.base}/status", "online" if online else "offline", qos=1, retain=True)

    def ping_if_idle(self) -> None:
        client = self._require()
        if not client.connected or self.clock() - client.last_sent < self.keepalive / 2:
            return
        with self._closing_on_error():
            client.ping()

    def close(self, timeout: float | None = None) -> None:
        """Status offline, then DISCONNECT (so the broker drops the Will). Never raises. `timeout` caps each step."""
        if self.client is None:
            return
        if timeout is not None:
            self.client.timeout = min(self.client.timeout, timeout)
        if self.client.connected:
            try:
                self.publish_status(False)
            except (MqttError, ValueError, OSError):
                pass
        self.client.disconnect()
