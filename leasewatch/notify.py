"""Mail on new devices through the Mailgun HTTP API."""
from __future__ import annotations

import base64
import logging
import urllib.parse
import urllib.request

from .config import Config

log = logging.getLogger("leasewatch.notify")


def _send(cfg: Config, subject: str, text: str) -> None:
    url = f"https://api.mailgun.net/v3/{cfg.mailgun_domain}/messages"
    data = urllib.parse.urlencode({
        "from": f"{cfg.mail_from_name} <mailgun@{cfg.mailgun_domain}>",
        "to": cfg.mail_to, "subject": subject, "text": text,
    }).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"api:{cfg.mailgun_key}".encode()).decode())
    with urllib.request.urlopen(req, timeout=20) as resp:
        resp.read()
    log.info("mail sent: %s", subject)


def new_devices(cfg: Config, devices: list[dict]) -> None:
    n = len(devices)
    lines = [f"{n} new device{'s' if n != 1 else ''} on the network:", ""]
    for d in devices:
        lines.append(f"  {d['ip']:15}  {d['mac']}  {d['hostname'] or '(no hostname)':28}  {d['vendor'] or '?'}  [{d['vlan']}{', ' + d['lease_type'] if d['lease_type'] else ''}]")
    if cfg.public_url:
        lines += ["", f"Review and acknowledge: {cfg.public_url}/?filter=unacked"]
    first = devices[0]
    who = first["hostname"] or first["vendor"] or first["mac"]
    subject = f"New device: {who} ({first['ip']}, {first['vlan']})" if n == 1 else f"{n} new devices on the network"
    _send(cfg, subject, "\n".join(lines))
