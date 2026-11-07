"""Notify on new devices through every configured channel: Mailgun HTTP API, SMTP, webhook."""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import logging
import re
import smtplib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from typing import Protocol

from . import __version__
from .config import Config
from .connectors import build_opener, parse_bool

log = logging.getLogger("leasewatch.notify")
# hostnames come from DHCP clients: a CR/LF (or other control char) in the subject would inject mail headers
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
MAX_RESPONSE = 64 * 1024  # bytes of a webhook answer read (and discarded)
DISCORD_MAX = 2000  # characters of a Discord message


class NotifyError(Exception):
    """A channel failed. The text names the channel and a code; never a secret, URL, address or server reply."""


MailError = NotifyError  # the 1.1 name


class MailgunError(NotifyError):
    pass


class SmtpError(NotifyError):
    pass


class WebhookError(NotifyError):
    pass


@dataclass
class Message:
    subject: str  # control characters removed
    text: str  # control characters removed per line
    devices: list[dict] = field(default_factory=list)  # the rows as queued (raw values, for the webhook JSON)
    url: str = ""  # the review link, "" without PUBLIC_URL


class Channel(Protocol):
    name: str

    def send(self, msg: Message) -> None:
        """Deliver `msg`; raise the channel's own NotifyError subclass on failure."""


def _device_line(d: dict) -> str:
    # empty network or lease type: leave the part out, as the "new" event does
    tags = ", ".join(filter(None, [d["vlan"], d["lease_type"]]))
    line = f"  {d['ip']:15}  {d['mac']}  {d['hostname'] or '(no hostname)':28}  {d['vendor'] or '?'}" + (f"  [{tags}]" if tags else "")
    # a CR/LF in a DHCP hostname would forge whole lines of the body (e.g. a fake review link)
    return _CTRL.sub(" ", line)


def build_message(cfg: Config, devices: list[dict]) -> Message:
    n = len(devices)
    lines = [f"{n} new device{'s' if n != 1 else ''} on the network:", ""]
    lines += [_device_line(d) for d in devices]
    url = f"{cfg.public_url}/?filter=unacked" if cfg.public_url else ""
    if url:
        lines += ["", f"Review and acknowledge: {url}"]
    first = devices[0]
    who = first["hostname"] or first["vendor"] or first["mac"]
    where = ", ".join(filter(None, [first["ip"], first["vlan"]]))
    # no IP and no network: no "()" either
    subject = (f"New device: {who}" + (f" ({where})" if where else "")) if n == 1 else f"{n} new devices on the network"
    return Message(_CTRL.sub(" ", subject), "\n".join(lines), list(devices), url)


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
        raise MailgunError(f"mailgun: HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise MailgunError(f"mailgun: {e.reason}") from e
    except (TimeoutError, OSError) as e:
        raise MailgunError(f"mailgun: {e}") from e
    except http.client.HTTPException as e:  # e.g. a malformed status line
        raise MailgunError("mailgun: bad response") from e
    except ValueError as e:
        # no exception text: an InvalidURL/ValueError can echo the URL
        raise MailgunError("mailgun: bad MAILGUN_API_BASE") from e


class MailgunChannel:
    name = "mailgun"

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def send(self, msg: Message) -> None:
        _send(self.cfg, msg.subject, msg.text)  # looked up at call time: tests patch notify._send


def _tls_context(verify: bool) -> ssl.SSLContext:
    # always a verifying default context: smtplib's own default (context=None) checks neither certificate nor name
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class SmtpChannel:
    name = "smtp"
    timeout: float = 20  # seconds per socket operation

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def _email(self, msg: Message) -> EmailMessage:
        cfg = self.cfg
        em = EmailMessage()
        em["From"] = formataddr((cfg.mail_from_name, cfg.smtp_from))
        em["To"] = ", ".join(a.strip() for a in cfg.mail_to.split(",") if a.strip())
        em["Subject"] = msg.subject
        em["Date"] = formatdate(localtime=False)
        # with a domain: make_msgid() would otherwise call getfqdn() (a DNS lookup that can block)
        em["Message-ID"] = make_msgid(domain=cfg.smtp_from.rpartition("@")[2])
        em.set_content(msg.text)
        return em

    def send(self, msg: Message) -> None:
        cfg = self.cfg
        phase = "connect"
        smtp: smtplib.SMTP | None = None
        try:
            ctx = _tls_context(parse_bool(cfg.smtp_verify_tls) is not False)
            em = self._email(msg)
            to = [a.strip() for a in cfg.mail_to.split(",") if a.strip()]
            # local_hostname: EHLO would otherwise send getfqdn() (a DNS lookup, and the container's name). The
            # constructor connects (and closes its socket itself when the greeting is not 220)
            if cfg.smtp_tls == "tls":
                smtp = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, local_hostname="leasewatch", timeout=self.timeout,
                                        context=ctx)
            else:
                smtp = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, local_hostname="leasewatch", timeout=self.timeout)
            if cfg.smtp_tls == "starttls":
                smtp.ehlo()
                phase = "starttls"
                smtp.starttls(context=ctx)  # raises when not offered: never a silent plain-text fallback
                smtp.ehlo()
            if cfg.smtp_user:
                phase = "login"
                smtp.login(cfg.smtp_user, cfg.smtp_password)
            phase = "send"
            smtp.send_message(em, cfg.smtp_from, to)
            phase = "quit"
            try:
                smtp.quit()
            except (smtplib.SMTPException, OSError):
                pass  # the message is accepted; a failing QUIT changes nothing
        # the server's reply text and the addresses stay out of the error: both can carry personal data
        except ssl.SSLCertVerificationError as e:
            raise SmtpError("smtp: certificate verification failed") from e
        except smtplib.SMTPAuthenticationError as e:
            raise SmtpError(f"smtp: login refused ({e.smtp_code})") from e
        except smtplib.SMTPRecipientsRefused as e:
            raise SmtpError("smtp: recipient refused") from e
        except smtplib.SMTPSenderRefused as e:
            raise SmtpError(f"smtp: sender refused ({e.smtp_code})") from e
        except smtplib.SMTPResponseException as e:
            raise SmtpError(f"smtp: {e.smtp_code}") from e
        except smtplib.SMTPNotSupportedError as e:
            what = {"starttls": "STARTTLS", "login": "AUTH", "send": "SMTPUTF8"}.get(phase, "a needed extension")
            raise SmtpError(f"smtp: server does not offer {what}") from e
        except TimeoutError as e:
            raise SmtpError("smtp: timeout") from e
        except smtplib.SMTPServerDisconnected as e:
            # smtplib turns a timeout while it waits for a reply into "disconnected"
            raise SmtpError("smtp: timeout" if isinstance(e.__context__, TimeoutError) else "smtp: server disconnected") from e
        except smtplib.SMTPException as e:  # e.g. no common AUTH method
            raise SmtpError(f"smtp: {type(e).__name__}") from e
        except OSError as e:
            raise SmtpError(f"smtp: {e.strerror or type(e).__name__}") from e
        except ValueError as e:  # incl. UnicodeEncodeError: an address the server cannot take
            raise SmtpError("smtp: bad address") from e
        finally:
            if smtp is not None:
                smtp.close()


def _md_escape(text: str) -> str:
    """Discord markdown outside the code block: a hostname must not render as a link, heading or mention."""
    return re.sub(r"([\\*_~`|>\[\]()#@<:-])", r"\\\1", text)


class WebhookChannel:
    name = "webhook"
    timeout: float = 10

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def _request(self, msg: Message) -> tuple[str, dict]:
        """(URL, JSON body) for the configured format."""
        cfg, url = self.cfg, self.cfg.webhook_url
        if cfg.webhook_format == "ntfy":
            # JSON publishing goes to the server's root URL with the topic in the body (a JSON body POSTed to the
            # topic URL would show as raw text)
            parts = urllib.parse.urlsplit(url)
            root, _, topic = parts.path.rstrip("/").rpartition("/")
            body = {"topic": topic, "title": msg.subject, "message": msg.text}
            if msg.url:
                body["click"] = msg.url
            return urllib.parse.urlunsplit(parts._replace(path=root + "/")), body
        if cfg.webhook_format == "discord":
            head = _md_escape(msg.subject)
            tail = f"\n{msg.url}" if msg.url else ""
            # a code block keeps the columns and shows hostnames as plain text; a backtick cannot close it
            lines = [_device_line(d).replace("`", "'") for d in msg.devices]
            budget = DISCORD_MAX - len(head) - len(tail) - 40  # the fences and the "more" line
            shown: list[str] = []
            for ln in lines:
                if sum(len(x) + 1 for x in shown) + len(ln) + 1 > budget:
                    break
                shown.append(ln)
            if len(shown) < len(lines):
                shown.append(f"  … and {len(lines) - len(shown)} more")
            content = head + "\n```\n" + "\n".join(shown) + "\n```" + tail
            return url, {"content": content[:DISCORD_MAX], "allowed_mentions": {"parse": []}}
        return url, {"event": "new_devices", "site": cfg.site_name, "count": len(msg.devices), "title": msg.subject,
                     "message": msg.text, "url": msg.url or None,
                     "devices": [{k: d.get(k) or "" for k in ("mac", "ip", "hostname", "vendor", "vlan", "lease_type")}
                                 for d in msg.devices]}

    def _signature_headers(self, body: bytes) -> dict:
        """Standard Webhooks: v1 = HMAC-SHA256 over "<id>.<timestamp>.<body>"."""
        secret = self.cfg.webhook_secret
        key = base64.b64decode(secret[6:]) if secret.startswith("whsec_") else secret.encode()
        msg_id, ts = f"msg_{uuid.uuid4().hex}", str(int(time.time()))
        sig = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
        return {"webhook-id": msg_id, "webhook-timestamp": ts, "webhook-signature": f"v1,{sig}"}

    def send(self, msg: Message) -> None:
        # the URL is a secret (it often carries the token): no error text below contains it, its host or the answer
        try:
            url, payload = self._request(msg)
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(url, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", f"leasewatch/{__version__}")
            if self.cfg.webhook_secret:
                for k, v in self._signature_headers(body).items():
                    req.add_header(k, v)
            # never follows a redirect (it would resend the body elsewhere); honours http(s)_proxy and no_proxy,
            # as Mailgun does
            with build_opener(verify_tls=True, use_env_proxy=True).open(req, timeout=self.timeout) as resp:
                resp.read(MAX_RESPONSE)
        except urllib.error.HTTPError as e:
            e.close()
            note = " (redirect not followed)" if 300 <= e.code < 400 else ""
            raise WebhookError(f"webhook: HTTP {e.code}{note}") from e
        except urllib.error.URLError as e:
            r = e.reason
            if isinstance(r, ssl.SSLCertVerificationError):
                raise WebhookError("webhook: certificate verification failed") from e
            if isinstance(r, TimeoutError):
                raise WebhookError("webhook: timeout") from e
            raise WebhookError(f"webhook: {getattr(r, 'strerror', None) or type(r).__name__}") from e
        except TimeoutError as e:
            raise WebhookError("webhook: timeout") from e
        except OSError as e:
            raise WebhookError(f"webhook: {e.strerror or type(e).__name__}") from e
        except http.client.HTTPException as e:
            raise WebhookError("webhook: bad response") from e
        except ValueError as e:  # an invalid URL; its text would echo the URL
            raise WebhookError("webhook: bad WEBHOOK_URL") from e


_CHANNELS = {"mailgun": MailgunChannel, "smtp": SmtpChannel, "webhook": WebhookChannel}


def channels(cfg: Config) -> list[Channel]:
    """One channel per complete group of settings, in send order."""
    return [_CHANNELS[n](cfg) for n in cfg.mail_channels]


def new_devices(cfg: Config, devices: list[dict]) -> list[str]:
    """Send one message through every channel; return the names that delivered. Raises NotifyError when none did
    (the caller keeps the queue then); a channel that failed while another delivered is logged here."""
    msg = build_message(cfg, devices)
    chans = channels(cfg)
    if not chans:
        raise NotifyError("no notification channel configured")
    ok: list[str] = []
    errors: list[tuple[str, Exception]] = []
    for ch in chans:
        try:
            ch.send(msg)
            ok.append(ch.name)
        except NotifyError as e:
            errors.append((ch.name, e))
        except Exception as e:  # a bug in one channel must not cost the others their delivery
            errors.append((ch.name, NotifyError(f"{ch.name}: {type(e).__name__}")))
    if not ok:
        if len(errors) == 1:
            raise errors[0][1]
        raise NotifyError("; ".join(str(e) for _, e in errors))
    n = len(devices)
    for name, e in errors:
        log.warning("%s failed (%d device(s)): %s", name, n, e)
    # a count only: the subject carries hostname, IP and network, which do not belong in the logs
    log.info("mail sent: %d new device%s (%s)", n, "s" if n != 1 else "", ", ".join(ok))
    return ok
