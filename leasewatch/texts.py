"""The texts of mails and webhooks, per language (MAIL_LANG).

TEXTS maps a language to flat dotted keys. `en` and `sv` are complete; `en` is the fallback for any other language and for any key
a language lacks. A plural value is {"one": ..., "other": ...}, picked by the parameter `n`. The page's own texts live
in static/i18n.js, not here.
"""
from __future__ import annotations

TEXTS: dict[str, dict[str, str | dict[str, str]]] = {
    "en": {
        "mail.head": {"one": "{n} new device on the network:", "other": "{n} new devices on the network:"},
        "mail.new_subject": "New device: {who}",
        "mail.new_subject_where": "New device: {who} ({where})",
        "mail.new_subject_many": {"one": "{n} new device on the network", "other": "{n} new devices on the network"},
        "mail.no_hostname": "(no hostname)",
        "mail.review_link": "Review and acknowledge: {url}",
        "mail.more": "  … and {n} more",
        "alert.source_down": "{name} is down: {text}",
        "alert.source_up_after": "{name} is back after {length}",
        "alert.source_up": "{name} is back {text}",
        "alert.count_source": {"one": "{n} source event", "other": "{n} source events"},
        "alert.count_watch": {"one": "{n} change on a watched device", "other": "{n} changes on watched devices"},
        "alert.count_mixed": {"one": "{n} alert", "other": "{n} alerts"},
        "kind.offline": "offline",
        "kind.online": "online",
        "kind.ip": "ip",
        "kind.vlan": "vlan",
        "kind.port": "port",
        "kind.wifi": "wifi",
        "kind.source_down": "source_down",
        "kind.source_up": "source_up",
    },
    "sv": {
        "mail.head": {"one": "{n} ny enhet på nätverket:", "other": "{n} nya enheter på nätverket:"},
        "mail.new_subject": "Ny enhet: {who}",
        "mail.new_subject_where": "Ny enhet: {who} ({where})",
        "mail.new_subject_many": {"one": "{n} ny enhet på nätverket", "other": "{n} nya enheter på nätverket"},
        "mail.no_hostname": "(inget värdnamn)",
        "mail.review_link": "Granska och markera som kända: {url}",
        "mail.more": "  … och {n} till",
        "alert.source_down": "{name} är nere: {text}",
        "alert.source_up_after": "{name} är uppe igen efter {length}",
        "alert.source_up": "{name} är uppe igen {text}",
        "alert.count_source": {"one": "{n} källhändelse", "other": "{n} källhändelser"},
        "alert.count_watch": {"one": "{n} ändring på en bevakad enhet", "other": "{n} ändringar på bevakade enheter"},
        "alert.count_mixed": {"one": "{n} larm", "other": "{n} larm"},
        "kind.offline": "offline",
        "kind.online": "online",
        "kind.ip": "ny IP",
        "kind.vlan": "nytt nätverk",
        "kind.port": "ny port",
        "kind.wifi": "nytt Wi-Fi",
        "kind.source_down": "källa nere",
        "kind.source_up": "källa uppe",
    },
}


class _Keep(dict):
    """format_map table that leaves an unknown {x} as it is."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def t(lang: str, key: str, **params: object) -> str:
    """The text for `key` in `lang`; en when the language or key is missing there; the key itself when en lacks it too.
    {name} is filled from params; an unknown one stays in place. Never raises on a missing parameter."""
    value = TEXTS.get(lang, {}).get(key)
    if value is None:
        value = TEXTS["en"].get(key)
    if value is None:
        return key
    if isinstance(value, dict):
        value = value["one"] if params.get("n") == 1 else value["other"]
    try:
        return value.format_map(_Keep(params))
    except (ValueError, IndexError, KeyError, AttributeError):
        return value
