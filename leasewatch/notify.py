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
    _send(cfg, _CTRL.sub(" ", subject), "\n".join(lines))
