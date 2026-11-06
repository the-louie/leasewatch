"""Mail on new devices through the Mailgun HTTP API."""
from __future__ import annotations

import base64
import http.client
import logging
import re
import urllib.error
import urllib.parse
import urllib.request

from .config import Config

log = logging.getLogger("leasewatch.notify")
# hostnames come from DHCP clients: a CR/LF (or other control char) in the subject would inject mail headers
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class MailError(Exception):
    pass


def _send(cfg: Config, subject: str, text: str) -> None:
    url = f"{cfg.mailgun_api_base}/v3/{cfg.mailgun_domain}/messages"
    data = urllib.parse.urlencode({
        "from": f"{cfg.mail_from_name} <mailgun@{cfg.mailgun_domain}>",
        "to": cfg.mail_to, "subject": subject, "text": text,
    }).encode()
    try:
        # inside the try: a base without a scheme raises ValueError here, not in urlopen
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Authorization", "Basic " + base64.b64encode(f"api:{cfg.mailgun_key}".encode()).decode())
        # urlopen honours http(s)_proxy on purpose: Mailgun is on the internet (the instances' proxy setting only covers LAN clients)
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        e.close()
        raise MailError(f"mailgun: HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise MailError(f"mailgun: {e.reason}") from e
    except (TimeoutError, OSError) as e:
        raise MailError(f"mailgun: {e}") from e
    except http.client.HTTPException as e:  # e.g. a malformed status line
        raise MailError("mailgun: bad response") from e
    except ValueError as e:
        # no exception text: an InvalidURL/ValueError can echo the URL
        raise MailError("mailgun: bad MAILGUN_API_BASE") from e


def new_devices(cfg: Config, devices: list[dict]) -> None:
    n = len(devices)
    lines = [f"{n} new device{'s' if n != 1 else ''} on the network:", ""]
    for d in devices:
        # empty network or lease type: leave the part out, as the "new" event does
        tags = ", ".join(filter(None, [d["vlan"], d["lease_type"]]))
        line = f"  {d['ip']:15}  {d['mac']}  {d['hostname'] or '(no hostname)':28}  {d['vendor'] or '?'}" + (f"  [{tags}]" if tags else "")
        # a CR/LF in a DHCP hostname would forge whole lines of the body (e.g. a fake review link)
        lines.append(_CTRL.sub(" ", line))
    if cfg.public_url:
        lines += ["", f"Review and acknowledge: {cfg.public_url}/?filter=unacked"]
    first = devices[0]
    who = first["hostname"] or first["vendor"] or first["mac"]
    where = ", ".join(filter(None, [first["ip"], first["vlan"]]))
    # no IP and no network: no "()" either
    subject = (f"New device: {who}" + (f" ({where})" if where else "")) if n == 1 else f"{n} new devices on the network"
    _send(cfg, _CTRL.sub(" ", subject), "\n".join(lines))
    # a count only: the subject carries hostname, IP and network, which do not belong in the logs
    log.info("mail sent: %d new device%s", n, "s" if n != 1 else "")
