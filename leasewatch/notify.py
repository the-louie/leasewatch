"""Notify on new devices (and, through send(), other alerts) through every configured channel: Mailgun HTTP API, SMTP, webhook."""
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
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from typing import Protocol

from . import __version__
from .config import Config
from .connectors import build_opener, make_redactor, parse_bool

log = logging.getLogger("leasewatch.notify")
# hostnames come from DHCP clients: a CR/LF (or other control char) in the subject would inject mail headers
# (and the Unicode line breaks U+0085, U+2028 and U+2029, which EmailMessage refuses in a header as it does CR/LF)
# line breaks and control characters that would forge a header or a line in a mail or webhook; replaced by a space
_LINE_UNSAFE = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")
MAX_RESPONSE = 64 * 1024  # bytes of a webhook answer read (and discarded)
DISCORD_MAX = 2000  # characters of a Discord message
# bytes of an ntfy message: ntfy's default message-size-limit; one that reaches it is refused or turns into an attachment
NTFY_MAX = 4096
_logged_bugs: set = set()  # (channel, file, line) of unexpected channel exceptions whose traceback was logged


class NotifyError(Exception):
    """A channel failed. The text names the channel and a code; never a secret, URL, address or server reply."""


MailError = NotifyError  # the 1.1 name


class NotifyDeferred(NotifyError):
    """Every channel is waiting out its backoff: nothing was called, the queue stays."""


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
    links: list[str] = field(default_factory=list)  # per device (aligned with `devices`) its page, [] without PUBLIC_URL
    blocks: list[str] = field(default_factory=list)  # per device its text lines (the device line, then its link line)
    event: str = "new_devices"  # the webhook JSON's "event": new_devices, or source_down, source_up, watch


class Channel(Protocol):
    name: str

    def send(self, msg: Message) -> None:
        """Deliver `msg`; raise the channel's own NotifyError subclass on failure."""


def _device_line(d: dict) -> str:
    # empty network or lease type: leave the part out, as the "new" event does
    tags = ", ".join(filter(None, [d["vlan"], d["lease_type"]]))
    line = f"  {d['ip']:15}  {d['mac']}  {d['hostname'] or '(no hostname)':28}  {d['vendor'] or '?'}" + (f"  [{tags}]" if tags else "")
    # a CR/LF in a DHCP hostname would forge whole lines of the body (e.g. a fake review link)
    return _LINE_UNSAFE.sub(" ", line)


def build_message(cfg: Config, devices: list[dict]) -> Message:
    n = len(devices)
    lines = [f"{n} new device{'s' if n != 1 else ''} on the network:", ""]
    base = cfg.public_url.rstrip("/")  # a trailing slash must not give "//?device="
    # the MAC is stored normalised (hex pairs and colons): it needs no quoting
    links = [f"{base}/?device={d['mac']}" for d in devices] if base else []
    blocks = [_device_line(d) + (f"\n    {_LINE_UNSAFE.sub(' ', links[i])}" if links else "") for i, d in enumerate(devices)]
    lines += blocks
    url = f"{base}/?filter=unacked" if base else ""
    if url:
        lines += ["", f"Review and acknowledge: {url}"]
    first = devices[0]
    who = first["hostname"] or first["vendor"] or first["mac"]
    where = ", ".join(filter(None, [first["ip"], first["vlan"]]))
    # no IP and no network: no "()" either
    subject = (f"New device: {who}" + (f" ({where})" if where else "")) if n == 1 else f"{n} new devices on the network"
    return Message(_LINE_UNSAFE.sub(" ", subject), "\n".join(lines), list(devices), url, links, blocks)


def build_alert(cfg: Config, subject: str, lines: list[str], event: str) -> Message:
    """A message without devices (no device blocks, links or review link): the subject, then one text line per entry.
    Control characters are replaced as in build_message; the subject carries no site prefix, as build_message's."""
    return Message(_LINE_UNSAFE.sub(" ", subject), "\n".join(_LINE_UNSAFE.sub(" ", ln) for ln in lines), event=event)


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
        # honours http(s)_proxy on purpose: Mailgun is on the internet (the instances' proxy setting only covers LAN
        # clients). Never follows a redirect: it would resend the Authorization header (the API key) elsewhere
        with build_opener(verify_tls=True, use_env_proxy=True).open(req, timeout=20) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        e.close()
        note = " (redirect not followed)" if 300 <= e.code < 400 else ""
        raise MailgunError(f"mailgun: HTTP {e.code}{note}") from e
    except urllib.error.URLError as e:
        raise MailgunError(f"mailgun: {e.reason}") from e
    except (TimeoutError, OSError) as e:
        raise MailgunError(f"mailgun: {e}") from e
    except http.client.InvalidURL as e:  # an HTTPException, but a setting's fault (e.g. a blank in the domain)
        raise MailgunError("mailgun: bad MAILGUN_DOMAIN or MAILGUN_API_BASE") from e
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
            # smtplib raises only when every recipient is refused; the others come back here
            refused = smtp.send_message(em, cfg.smtp_from, to)
            if refused:
                log.warning("smtp: %d of %d recipient(s) refused", len(refused), len(to))  # no address: personal data
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
        except ValueError as e:  # incl. UnicodeEncodeError: an address, or a login smtplib encodes as ASCII
            raise SmtpError("smtp: bad SMTP_USER or SMTP_PASSWORD" if phase == "login" else "smtp: bad address") from e
        finally:
            if smtp is not None:
                smtp.close()


def _fit_lines(lines: list[str], budget: int, size: Callable[[str], int]) -> list[str]:
    """The first lines that fit in `budget` (each measured by `size`, plus its newline), then "… and N more"."""
    shown: list[str] = []
    used = 0
    for ln in lines:
        if used + size(ln) + 1 > budget:
            break
        shown.append(ln)
        used += size(ln) + 1
    if len(shown) < len(lines):
        shown.append(f"  … and {len(lines) - len(shown)} more")
    return shown


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
            text = msg.text
            if len(text.encode()) >= NTFY_MAX and not msg.blocks:  # a message without devices: whole lines only
                text = "\n".join(_fit_lines(text.split("\n"), NTFY_MAX - 40, lambda s: len(s.encode())))
            elif len(text.encode()) >= NTFY_MAX:  # ntfy takes a body that reaches the limit as an attachment
                # build_message's layout: two head lines, one block per device (its line, then its link line), then
                # the review link (if any). A block is kept or cut whole, so no link is left without its device line
                rows = text.split("\n")
                k = 2 + sum(b.count("\n") + 1 for b in msg.blocks)
                head, tail = rows[:2], rows[k:]
                budget = NTFY_MAX - len("\n".join(head + tail).encode()) - 40  # the newlines and the "more" line
                text = "\n".join(head + _fit_lines(msg.blocks, budget, lambda s: len(s.encode())) + tail)
            body = {"topic": topic, "title": msg.subject, "message": text}
            # one new device: tapping the notification opens that device, else the list of unchecked ones
            click = msg.links[0] if len(msg.links) == 1 else msg.url
            if click:
                body["click"] = click
            return urllib.parse.urlunsplit(parts._replace(path=root + "/")), body
        if cfg.webhook_format == "discord":
            head = _md_escape(msg.subject)
            # one link, after the code block (a link inside it is not clickable): the device for one, else the list
            link = msg.links[0] if len(msg.links) == 1 else msg.url
            tail = f"\n{link}" if link else ""
            # a code block keeps the columns and shows hostnames as plain text; a backtick cannot close it
            # a message without devices shows its text lines in the code block instead
            lines = [_device_line(d).replace("`", "'") for d in msg.devices] if msg.devices else \
                [ln.replace("`", "'") for ln in msg.text.split("\n")]
            shown = _fit_lines(lines, DISCORD_MAX - len(head) - len(tail) - 40, len)  # the fences and the "more" line
            content = head + "\n```\n" + "\n".join(shown) + "\n```" + tail
            return url, {"content": content[:DISCORD_MAX], "allowed_mentions": {"parse": []}}
        return url, {"event": msg.event, "site": cfg.site_name, "count": len(msg.devices), "title": msg.subject,
                     "message": msg.text, "url": msg.url or None,
                     "devices": [{**{k: d.get(k) or "" for k in ("mac", "ip", "hostname", "vendor", "vlan", "lease_type")},
                                  "url": msg.links[i] if msg.links else None} for i, d in enumerate(msg.devices)]}

    def _signature_headers(self, body: bytes) -> dict:
        """Standard Webhooks: v1 = HMAC-SHA256 over "<id>.<timestamp>.<body>"."""
        secret = self.cfg.webhook_secret
        # validate=True: decoded exactly as Config.validate() checks it
        key = base64.b64decode(secret[6:], validate=True) if secret.startswith("whsec_") else secret.encode()
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
                try:
                    sig = self._signature_headers(body)
                except ValueError as e:  # not the URL's fault (a Config that skipped validate())
                    raise WebhookError("webhook: bad WEBHOOK_SECRET") from e
                for k, v in sig.items():
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
        except http.client.InvalidURL as e:  # an HTTPException, but the setting's fault (e.g. a blank in the path)
            raise WebhookError("webhook: bad WEBHOOK_URL") from e
        except http.client.HTTPException as e:
            raise WebhookError("webhook: bad response") from e
        except ValueError as e:  # an invalid URL; its text would echo the URL
            raise WebhookError("webhook: bad WEBHOOK_URL") from e


_CHANNELS = {"mailgun": MailgunChannel, "smtp": SmtpChannel, "webhook": WebhookChannel}


def channels(cfg: Config) -> list[Channel]:
    """One channel per complete group of settings, in send order."""
    return [_CHANNELS[n](cfg) for n in cfg.mail_channels]


BACKOFF_CAP = 1800  # seconds: the longest wait between two attempts on a failing channel


@dataclass
class _ChannelState:
    fails: int = 0  # consecutive failed attempts
    retry_at: float = 0.0  # monotonic time of the next attempt
    since: float | None = None  # wall time of the first failure of the spell
    last_error: str = ""
    ok: bool | None = None  # None until the channel was tried


class Backoff:
    """Per channel wait after a failure: base * 2^(k-1) seconds after the k-th failure in a row, at most BACKOFF_CAP.

    A channel that waits is not called, so a dead server costs no timeout on the collector thread. The state lives in
    one process: a restart tries every channel at once. Used from the collector thread only."""

    def __init__(self, base: float = 120, clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time):
        self.base = max(float(base), 1.0)
        self._clock = clock
        self._wall = wall
        self._state: dict[str, _ChannelState] = {}

    def _get(self, name: str) -> _ChannelState:
        return self._state.setdefault(name, _ChannelState())

    def due(self, name: str) -> bool:
        return self._clock() >= self._get(name).retry_at

    def failed(self, name: str, error: object) -> bool:
        """Record a failed attempt; True when it is the first of a spell (the one to log as a warning)."""
        st = self._get(name)
        st.fails += 1
        st.ok = False
        st.last_error = str(error)
        st.retry_at = self._clock() + min(self.base * 2 ** min(st.fails - 1, 30), BACKOFF_CAP)
        if st.fails == 1:
            st.since = self._wall()
        return st.fails == 1

    def delivered(self, name: str) -> int:
        """Record a delivery; return how many attempts of the spell that ends now had failed (0: no spell)."""
        st = self._get(name)
        n = st.fails
        st.fails, st.retry_at, st.since, st.last_error, st.ok = 0, 0.0, None, "", True
        return n

    def states(self) -> dict[str, bool]:
        """Channel -> last attempt delivered, for the channels tried so far."""
        return {n: st.ok for n, st in self._state.items() if st.ok is not None}


def send(cfg: Config, msg: Message, backoff: Backoff | None = None, what: str = "new devices") -> list[str]:
    """Send `msg` through every channel; return the names that delivered. Raises NotifyError when none did
    (the caller keeps the queue then); a channel that failed while another delivered is logged here. `what` names
    the message in the log lines ("new devices"; a message without devices is logged by `what` alone).

    With a backoff, a channel that waits out its backoff is not called and counts as failed for this batch (it misses
    it, as a channel that failed). When every channel waits, NotifyDeferred is raised and nothing was called. One
    backoff shared by every kind of message: a channel that failed for one waits for all."""
    chans = channels(cfg)
    if not chans:
        raise NotifyError("no notification channel configured")
    ok: list[str] = []
    errors: list[tuple[str, Exception]] = []
    for ch in chans:
        if backoff is not None and not backoff.due(ch.name):
            continue
        try:
            ch.send(msg)
            ok.append(ch.name)
            if backoff is not None:
                again = backoff.delivered(ch.name)
                if again:
                    log.info("%s delivers again after %d failed attempt(s)", ch.name, again)
        except NotifyError as e:
            errors.append((ch.name, e))
        except Exception as e:  # a bug in one channel must not cost the others their delivery
            errors.append((ch.name, NotifyError(f"{ch.name}: {type(e).__name__}")))
            # the stack once per bug (not every poll): file, line and function only. Not the exception text, the
            # source lines or the context chain: they can carry hostnames, addresses and server replies
            tb_last = traceback.extract_tb(e.__traceback__)[-1:]
            key = (ch.name, *((tb_last[0].filename, tb_last[0].lineno) if tb_last else ()))
            if key not in _logged_bugs:
                _logged_bugs.add(key)
                redact = make_redactor([cfg.mailgun_key, cfg.smtp_user, cfg.smtp_password, cfg.webhook_url,
                                        cfg.webhook_secret])
                stack = "".join(f'\n  File "{f.filename}", line {f.lineno}, in {f.name}'
                                for f in traceback.extract_tb(e.__traceback__))
                log.error("%s failed unexpectedly: %s\nTraceback (most recent call last):%s", ch.name,
                          type(e).__name__, redact(stack))
    n = len(msg.devices)
    # counts and `what` only: the subject carries hostname, IP and network, which do not belong in the logs
    failed_what = f"{n} device(s)" if n else what
    sent_what = (f"{n} {what[:-1] if n == 1 and what.endswith('s') else what}") if n else what
    if backoff is not None:
        for name, e in errors:
            if backoff.failed(name, e):
                log.warning("%s failed (%s): %s; retrying with backoff up to %d min", name, failed_what, e,
                            BACKOFF_CAP // 60)
            else:
                log.debug("%s failed again (%s): %s", name, failed_what, e)
    if not ok:
        if not errors:
            raise NotifyDeferred("every channel is waiting out its backoff")
        if len(errors) == 1:
            raise errors[0][1]
        raise NotifyError("; ".join(str(e) for _, e in errors))
    for name, e in errors if backoff is None else ():
        log.warning("%s failed (%s): %s", name, failed_what, e)
    log.info("mail sent: %s (%s)", sent_what, ", ".join(ok))
    return ok


def new_devices(cfg: Config, devices: list[dict], backoff: Backoff | None = None) -> list[str]:
    """Send one message on `devices` through every channel (see send); the collector's call."""
    return send(cfg, build_message(cfg, devices), backoff, "new devices")
