# Changelog

All notable changes to leasewatch are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.2.0 (unreleased)

### Added
- UniFi connector keeps its login session between polls and logs in again only when the session expires; logout happens on close.
- UniFi OS consoles supported (new PLATFORM setting: auto, classic, unifi_os; untested on hardware). UniFi connector version 1.1.
- **Notification channels:** new devices can be sent through Mailgun, SMTP and a webhook, each on when its settings are complete (`/api/status` `meta.mail` and the start log line `mail on (mailgun, smtp, webhook)` mean any channel). Each batch goes to every channel; the queue is cleared when at least one delivered, and a channel that failed is logged and misses that batch. Mailgun behaves as before.
- **SMTP:** `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS` (`starttls` default and required, `tls`, `none`), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_VERIFY_TLS`. The certificate and host name are always checked unless `SMTP_VERIFY_TLS=0`; a password with `SMTP_TLS=none` is refused at startup; errors carry the SMTP code only.
- **Webhook:** `WEBHOOK_URL` (treated as a secret), `WEBHOOK_FORMAT` (`json` default, `ntfy`, `discord`), optional `WEBHOOK_SECRET` signature per Standard Webhooks. Redirects are not followed.

- **Third-party connectors:** connector types are loaded from installed packages (entry point group `leasewatch.connectors.v1`) and from `LW_CONNECTORS_DIR` (no default; one package per subdirectory with its `pyproject.toml`, mounted read-only). A duplicate type name is refused (a built-in type always stays); a package that fails to load stops the start only when an instance uses its type. The start log lists the loaded types and their origin. A `<KEY>_FILE` secret of a third-party type is now read like a built-in one.
- **docs/connectors.md:** how to write a connector for connector API 1: the lifecycle, the records and how they are merged, settings, errors and secrets, the public names, packaging, installing, loading and versioning rules, the contract tests, and a complete example package.
- **contrib/leasewatch-dnsmasq:** connector type `dnsmasq_leases` reads the DHCPv4 leases from a dnsmasq leases file (Pi-hole, OpenWrt, Linux), mounted read-only.
- **contrib/leasewatch-mikrotik:** connector type `mikrotik` reads the DHCPv4 leases and the ARP table from MikroTik RouterOS 7 through its REST API (read-only; untested on real hardware).
- **OPNsense dnsmasq:** `LW_CONNECTOR__<NAME>__DHCP_BACKEND=dnsmasq` reads the DHCPv4 leases of the dnsmasq DHCP server (`/api/dnsmasq/leases/search`, OPNsense 25.1.6+). IPv6 leases are skipped; reservations without an active lease are not listed. The privilege *Services: Dnsmasq DNS/DHCP: Settings* also grants write access: OPNsense has no read-only one.
- **Private MACs:** a new locally administered (private) MAC that matches exactly one known device, by DHCP client-id or else by a distinctive DHCP hostname of a device seen in the last 30 days, is merged into it: its IP, hostname, port, Wi-Fi and *Seen by* rows land on that device, the alias is stored in the `aliases` table, and a `merged` event is written. Never at the first poll, never between two hardware MACs, never into a device on the wire in the same poll. A new private MAC, merged or not, sends no new-device mail.
- **Private MACs in the page:** every device with a private (locally administered) MAC has a yellow-tinted border in the list and a 🕵️ next to its MAC with the hint "private address" (tooltip and screen-reader text); the device page says the address is private and lists the MACs merged into the device (*Merged addresses*: MAC, matched client-id or hostname, merged, last seen).
- **API:** `private` on every device in `/api/devices`, `/api/devices/<mac>` and the POST answer; `aliases` (the merged MACs) in `/api/devices/<mac>`. CSV: a `private` column (1/0) before `note`.
- **Archive:** "Archive" on the device page (POST `{"archived": true}`) takes a device out of the list; the status filter "Archived" shows archived devices and "Restore to list" puts one back. History, events, name, note and ack are kept; the cards and network chips do not count archived devices, and an archived device leaves the mail queue. A device that is online again after being offline returns to the list by itself with one `back` event, no `new` event and no mail; a static lease alone does not bring it back. Events `archived` and `restored`. `/api/devices` gives `archived_ts`; CSV: an `archived` column before `note`.
- **Login (optional):** `AUTH_USER` and `AUTH_PASSWORD_HASH` (both or neither, checked at startup) turn on HTTP basic auth for every path, including `/static/`, the CSV export and `/healthz`. The Host check still comes first (421/400), then 401 with `WWW-Authenticate: Basic realm="leasewatch", charset="UTF-8"`. The password is stored only as a PBKDF2-SHA256 hash (`pbkdf2_sha256:<iterations>:<salt>:<hash>`) and compared in constant time; a correct login is remembered for 10 minutes, at most two password checks run at once (else 503 with `Retry-After: 5`), and failed logins are logged at most once a minute with a count and the client address only.
- **`python -m leasewatch hash-password [--iterations N]`:** prints the `AUTH_PASSWORD_HASH` value; the password comes from a prompt (asked twice) or one line of stdin, never from the command line.
- **`PRUNE_DAYS`** (default 0 = off): devices not online for that many days, with no name and not marked known, are archived once per poll (never at the first poll or while the baseline waits).
- **SECURITY.md:** how to report a vulnerability, the supported versions and the security stance (login, Host check, CSP, what is never logged, what the notification channels send).

### Changed

- **Container user:** the image's user `app` has the fixed uid:gid `10001:10001` (was the next free system ids, uid 100, gid 101) and `USER` is numeric. An existing bind-mounted data directory needs `chown -R 10001:10001 data` before the upgrade, or the start fails on a read-only database.
- **docker-compose.yml:** the default publishes `8080:8080` and uses no external network, so it works on a clean host; the nginx-proxy setup (`VIRTUAL_HOST`, external network) is a commented variant.
- **Docker healthcheck:** a 401 (login on) counts as alive, as a 200 does; the command is in exec form.
- **Content-Security-Policy** on every response (page, static files, API, CSV and errors): `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. The page no longer uses inline style attributes (the network colours are set from `data-vc`).
- **Events:** a `merged` event shows as "merged address" in the event lists (it showed the raw kind).
- **Copy MAC and IP:** the whole MAC and the whole IP in the device list copy on click, Enter or Space (tooltip "Click to copy", a short "Copied" above the text). The copy icon that appeared on hover, and widened the MAC column, is gone.
- **Database:** schema 3 adds the device columns `client_id`, `archived_ts` and `mail_queued` and an `aliases` table; the first start migrates a 1.0 or 1.1 database automatically and changes no existing row. The migration is one-way: back up `DATA_DIR` before the upgrade if you may go back to 1.1.
- **Device table:** the Type column now shows from a 1280 px wide window (was 1601 px); the table width is the same at every width from 1280 px.
- **Search:** the table and the URL follow the search box 150 ms after the last key instead of on every key (a rebuild of 2000 rows takes about 100 ms); Enter and Escape in the box still apply at once (Enter with no search waiting does nothing).
- **Baseline:** while the baseline waits for a sighting producer, no change events (ip, hostname, network, lease type, port, Wi-Fi, back) and no history rows are written, so a late producer no longer logs its details as changes (e.g. "hostname - -> laptop"). Devices are still recorded and updated; the poll that takes the baseline writes one history row per device with its complete values.
- **Wi-Fi events:** a `wifi` event is written only when the SSID changes ("HomeNet -> GuestNet") or the device joins or leaves Wi-Fi ("- -> HomeNet", "HomeNet -> wired", "HomeNet -> off Wi-Fi"); roaming between access points on the same SSID no longer writes an event and only updates the AP, signal and radio. A device that is new this poll gets only its `new` event.

### Removed

- **API:** the deprecated 1.0 objects `meta.switch` and `meta.unifi` in `/api/status`, `/api/stats` and `/api/devices`, and the `switch` and `unifi` keys of the `/healthz` body; use `meta.connectors` (one entry per instance). The collector no longer writes the meta keys behind them (`switch_ok`, `switch_error`, `switch_macs`, `unifi_ok`, `unifi_error`, `unifi_clients`), and the page no longer falls back to them. Instance names `switch` and `unifi` have no special meaning any more.

### Fixed
- The hidden column labels of the device table ("online", "actions") use the standard visually-hidden pattern instead of being moved 9999 px off-screen.
- Closing the device drawer (Escape, the backdrop, ✕) or opening another device while Name or Note has unsaved text asks "Discard unsaved changes?" first; Cancel keeps the drawer and the text.
- Closing the device drawer while its Save is still running no longer asks "Discard unsaved changes?" for the text being saved; it asks only for text typed after Save.
- The device drawer is modal for the keyboard: Tab and Shift+Tab cycle through its controls, and the page behind it (header, table, footer) takes no focus until it closes.
- `check <name>`, `collect <name>` and `snmp-detect <name>` now exit 2 on a config problem that belongs to no instance (e.g. `LW_CONNECTOR__FW1_SECRET` with one underscore, an invalid name in `LW_CONNECTORS`) and on a load problem, as the server does.
- `check` and `collect` keep the instance name and the client's `fw1 <path>:` label when the instance is named like its host; only the error text is host-masked. `check` now masks the host in problem texts too.
- `collect` shows device data unmasked again (a switch's own redact no longer masks its host and user in records), and prints only the declared record fields.
- `collect --json` no longer crashes on stats keys that are not strings or values whose `str()` raises, and never prints NaN/Infinity.
- `check` and `collect` no longer hang on a `close()` that blocks after a timed-out probe, build each named instance only once, and tolerate a connector `redact()` that returns a non-string.
- The `connector types:` start-log line escapes control characters from package metadata.
- While the baseline waits, a producer whose check keeps failing is still collected every poll once 10 minutes have passed, so the baseline can be taken.
- A connector that calls sys.exit() while it is built only disables its instance; the service keeps running.
- A connector can call device_names() in its constructor.
- The 'changed' count in the poll log line is 0 while the baseline waits, which matches the events and history written.
- Connector loader: a plugin whose describe() has malformed settings (including a min or max that is not an int), produces or roles is now refused as a broken type; Config() no longer stops with a traceback.
- Connector loader: a deeply nested pyproject.toml or an oversized API group number is now reported against that one entry; it no longer drops every third-party type.
- Connector loader: after a loader failure or Ctrl-C during plugin import, only the built-ins stay registered and no half-imported LW_CONNECTORS_DIR package stays in sys.modules; any other BaseException from a plugin import is now a plugin failure.
- Connector loader: a type that is pip-installed and also mounted in LW_CONNECTORS_DIR is refused as 'provided twice … remove one', and the start stops (the mounted package would shadow the installed one); a shadowing or malformed declaration still counts in the duplicate check.
- Connector loader: the group must be exactly leasewatch.connectors.v<N> (ASCII, no leading zero); type names with a trailing newline are refused; spaces around ':' in a LW_CONNECTORS_DIR entry point are accepted as pip accepts them.
- Connector loader: clearer messages for a missing __init__.py, a package name repeated across LW_CONNECTORS_DIR entries, and unreadable distribution metadata (now names the distribution); the other-API warning is logged once per distribution, and dist names spelled 'lw_b'/'lw-b' count as one distribution.
- registry() now also rebuilds when the working directory changes, so a relative LW_CONNECTORS_DIR follows os.chdir; unload drops submodules a plugin imported after the load.
- Contract tests (`leasewatch.connectors.testing`): the no-network test also stops `socket.getnameinfo` and no longer errors on a platform without `socket.sendmsg` (Windows); a type name or setting key with a trailing newline now fails the describe test; an empty tuple for a record kind the type does not produce now passes the check-and-collect test.
- docs/connectors.md: `make_host_mask()` and the contract test's host check skip a host shorter than 3 characters; this is now stated.
- check and collect mask a URL or HOST host anywhere in an error or problem text, including before the first ": "; only the instance's own "connector <name> (<type>): " head stays readable.
- check and collect mask a config: line that belongs to one instance with that instance's host only; a line that belongs to no instance is masked with every instance's host.
- Device list: a refresh while a MAC or IP has keyboard focus keeps focus on it (it moved to the row, so Enter opened the drawer instead of copying).
- Device list: the row count leaves archived devices out of its total ("15 of 15", was "15 of 16"); under "Archived" it counts only archived devices.
- Copy MAC and IP: the "press Ctrl+C" hint of a keyboard copy goes when focus leaves the MAC or IP, not only when the pointer leaves; a second copy within 0.9 s shows "Copied" for its full 0.9 s.
- Device drawer: Archive and Restore to list no longer show "saved" next to Save; typed Name or Note text is not saved by them and stays an unsaved edit.
- Events: `archived`, `restored` and `merged` have a colour, like the other kinds.
- check and collect no longer disable an instance because of a global load problem whose path contains LW_CONNECTOR__<NAME>__.
- check and collect no longer crash with OverflowError on a disabled instance with a huge TIMEOUT.
- collect: an int stat with more than 4300 digits, or an int or str subclass with a raising __str__ or __format__, no longer gives a traceback; keys that turn into the same text are all kept, as "1" and "1#2".
- A connector plugin that calls sys.exit() in its constructor or validate() (also a generator validate()) now only disables its instance at server start and in `leasewatch check`; the process no longer exits with the plugin's code. The built connector is still closed, and its setting problems are still reported.
- Connector loader: a package in LW_CONNECTORS_DIR that would shadow another module now stops the start even when its type is a duplicate or a built-in name.
- Connector loader: a space inside a module name in an entry point value is refused instead of being removed.
- Connector loader: describe() produces/roles may be a tuple or list of str, as the contract test accepts; a Setting key that is not a str makes the type broken instead of crashing Config().
- Connector loader: a distribution name or LW_CONNECTORS_DIR entry with a newline can no longer forge a log line; two distributions without a Name are no longer merged into one.
- Connector loader: unloading plugins no longer fails when another thread imports a module at the same time.
- The new-device mail queue no longer drops a device after 24 h: it is kept until mailed, acknowledged or archived, so a clock step can no longer lose a mail.
- A DHCP hostname that starts with a brand or model stem (galaxy, pixel, chromecast, iphone, ipad, android, ...) is generic and never merges a private MAC, e.g. `Galaxy-S21` or `Pixel-7`.
- While a sighting producer has failed, no private-MAC merge is decided: a new private MAC is held back for up to 30 minutes and merges once its lease is back.
- A device and its merged MAC on one switch: the edge port wins over a stale uplink entry whatever the walk order; a controller listing both places the device at its active client.
- The merged DHCP client-id no longer depends on the order of otherwise equal lease rows.
- PRUNE_DAYS no longer re-archives a device restored by hand until it has been online again.
- Wi-Fi events: no 'joined' event for the first SSID of a client already on Wi-Fi, and no 'off Wi-Fi' or 'joined' events for a phone that walks out while the firewall's ARP still lists it; leaving to a shown cable is still an event. A switch that still holds the phone on an uplink (the access point's port) is no cable: the walk-out and the return write no `wifi` events.
- GET and POST /api/devices/<mac> with a merged private (alias) MAC now act on the device it was merged into, instead of returning 404.
- Auth: an Authorization header with non-ASCII bytes (for example a 0xA0 or 0x85 blank) now gets a 401 and counts as a failed attempt. Before, the server dropped the connection and printed a traceback.
- Auth: failed logins held back by the once-a-minute log limit are now reported when the minute ends, even if no later attempt arrives.
- hash-password: a password with a byte that is not UTF-8 now gives 'cannot read the password' under every locale (C.UTF-8 included), and a run with stdout closed exits 1 without a traceback.
- Mailgun no longer follows a redirect: it would resend the API key to another host ("mailgun: HTTP 3xx (redirect not followed)").
- SMTP_FROM must be a plain ASCII address without <>, and a list is refused. MAIL_TO entries must not use <>, and a trailing comma is accepted. SMTP_USER and SMTP_PASSWORD must be ASCII. All are checked at startup, not on every send.
- An empty SMTP_VERIFY_TLS= means the default (verify). A non-integer SMTP_PORT warning names the port actually used.
- WEBHOOK_SECRET=whsec_ with an empty key, or a secret that is not valid UTF-8, is refused at startup. A non-ASCII path or query in WEBHOOK_URL is refused at startup.
- SMTP: recipients refused while another is accepted are logged as a warning (a count, no address).
- ntfy messages are cut to 4096 bytes with "… and N more".
- Clearer errors: "smtp: bad SMTP_USER or SMTP_PASSWORD", "webhook: bad WEBHOOK_SECRET", "mailgun: bad MAILGUN_DOMAIN or MAILGUN_API_BASE".
- A bug in a notification channel is logged once with a redacted traceback. U+0085, U+2028 and U+2029 are removed from the mail subject and body lines.
- UniFi OS: a csrfToken claim in the TOKEN cookie that is not plain visible ASCII (1-512 characters) is ignored, so it can no longer make every poll fail on a session that is kept.
- UniFi: a 401 right after a fresh login is reported as 'unifi: HTTP 401' on every poll again. Such a login no longer triggers the 60 s re-login pacing or a false 'session expired' log line.
- Login: failed attempts still held back for the next log line are logged when the service stops.
- `SMTP_FROM` and `MAIL_TO` accept only plain `name@domain` addresses: a second `@`, `;`, `:`, quotes, parentheses, square brackets or a backslash (e.g. `a@example.com;b@example.com`, `mailto:…`) are refused at startup instead of failing every send.
- `SMTP_PORT=-1` is no longer taken silently as the default port; it is logged as not a port, and the default is used.
- ntfy: a message of exactly 4096 bytes is cut too (ntfy took it as an attachment).
- Webhook: an invalid character in `WEBHOOK_URL` is reported as "webhook: bad WEBHOOK_URL" instead of "webhook: bad response".
- A bug in a notification channel is logged with the exception type and the stack (file, line, function) only: no exception text, source lines or chained exceptions, which could carry device names or e-mail addresses.
- With stdout closed (`>&-`), a command keeps the exit code it set (e.g. 2 for a usage error) instead of 1.
- Device table: long "Connected via" text (Wi-Fi SSID @ AP with signal, switch port → device) is cut with an ellipsis and shown in full as a tooltip; the Type cell has a tooltip too, so the table no longer scrolls sideways at 1280–1920 px.

- **Kea:** on OPNsense 26.1.5 – 26.7.3, which send `is_reserved` as a list and no `lease_type`, every lease was marked static.

## 1.1.0 (2026-11-06)

### Added

- **Connector instances:** `LW_CONNECTORS` lists named instances, each configured with `LW_CONNECTOR__<NAME>__<KEY>` (`TYPE` required, `TIMEOUT` per instance, `<KEY>_FILE` for secrets such as Docker secrets). Several firewalls, switches or controllers can run side by side. A wrong setting stops the start with a message that names the instance and the key.
- Each instance collects in its own thread with its own timeout. A failing or slow instance greys only its own status dot and keeps its last values; a failed first probe is retried with a backoff up to 10 minutes. The poll fails only when every sighting-producing instance failed.
- **Per-instance status:** one status dot per instance in the page (the switch's `NAME`, "Wi-Fi" for the controller) and `GET /api/status` with a `connectors` list (`name`, `label`, `type`, `ok`, `error`, `ts`, `ms`, `count`, `strategy`, `enabled`).
- **SNMP profiles** for the switch lookup: `standard`, `comware`, `cisco_ios`, `routeros`, `jetstream`, `zynos`, `edgeswitch`, detected from sysObjectID/sysDescr or set with `PROFILE`; your own JSON profile with `PROFILE_FILE` (it may extend a built-in one); `MIN_MACS` for the uplink threshold.
- **Cisco IOS:** the forwarding table is read per VLAN through SNMPv3 `vlan-<N>` contexts, with a fallback to Q-BRIDGE (logged once per instance) when the contexts are unavailable.
- Commands `python -m leasewatch snmp-profiles` (list the built-in profiles) and `python -m leasewatch snmp-detect <instance>` (sysObjectID, sysDescr, chosen profile and the first rows of each walk).
- **Seen by** on the device page: one line per instance that listed the device, with when it last did and whether it was on the wire.
- **Several switches:** an edge port beats an uplink port, then the newest observation, then the order in `LW_CONNECTORS`. The instance that placed a device is stored as `loc_source` (also a CSV column).

### Changed (breaking)

- **Sources are configured only as connector instances.** `LW_CONNECTORS` is required (at least one instance that produces sightings, i.e. an `opnsense` one). The 1.0 source variables are removed: a start with any of them set (also with an empty value) stops with one message per group that names the variables to use instead, never their values. The global settings stay as they were (`POLL_SECONDS`, `NEW_DAYS`, `ONLINE_GRACE_MINUTES`, `LEASE_TYPE_MODE`, `SITE_NAME`, `PUBLIC_URL`, `ALLOWED_HOSTS`, `MAILGUN_*`, `MAIL_TO`, `MAIL_FROM_NAME`, `LOG_LEVEL`, `DATA_DIR`, `LISTEN_HOST`, `LISTEN_PORT`).
- Instance names are `a-z` and `0-9` only (no `-`), so every `LW_CONNECTOR__<NAME>__<KEY>` can be exported from a POSIX shell.
- `snmp-detect --host` has no default key variables any more: give `--auth-key-env` and `--priv-key-env` (the names of the environment variables that hold the keys). `snmp-detect <instance>` reads the instance's settings.
- An empty connector yes/no or choice setting (e.g. `LW_CONNECTOR__FW1__VERIFY_TLS=`) is refused; leave the line out to use the default.

Migration (keep the instance names `fw1`, `switch` and `unifi`: the deprecated `meta.switch`/`meta.unifi` API objects follow those names):

| 1.0 variable | 1.1 setting |
|---|---|
| — | `LW_CONNECTORS=fw1` (add `,switch` and `,unifi` for those sources), `LW_CONNECTOR__FW1__TYPE=opnsense` |
| `FW1_URL`, `FW1_KEY`, `FW1_SECRET`, `FW1_VERIFY_TLS` | `LW_CONNECTOR__FW1__URL`, `__KEY`, `__SECRET`, `__VERIFY_TLS` |
| `DHCP_BACKEND` | `LW_CONNECTOR__FW1__DHCP_BACKEND` |
| `IGNORE_INTERFACES` | `LW_CONNECTOR__FW1__IGNORE_INTERFACES` |
| `PROXY_FOR_LAN` | `LW_CONNECTOR__FW1__PROXY` and `LW_CONNECTOR__UNIFI__PROXY` (per instance) |
| `SNMP_HOST`, `SNMP_NAME`, `SNMP_USER`, `SNMP_AUTH`, `SNMP_AUTH_KEY`, `SNMP_PRIV_KEY` | `LW_CONNECTOR__SWITCH__TYPE=snmp_switch`, `LW_CONNECTOR__SWITCH__HOST`, `__NAME`, `__USER`, `__AUTH`, `__AUTH_KEY`, `__PRIV_KEY` |
| `UNIFI_URL`, `UNIFI_SITE`, `UNIFI_USER`, `UNIFI_PASSWORD`, `UNIFI_VERIFY_TLS` | `LW_CONNECTOR__UNIFI__TYPE=unifi`, `LW_CONNECTOR__UNIFI__URL`, `__SITE`, `__USER`, `__PASSWORD`, `__VERIFY_TLS` |

### Changed

- The database gets a `schema_version` and is migrated automatically at the first start (a `seen` table and the `loc_source` column). The migration is one-way: back up `DATA_DIR` before the upgrade if you may go back to 1.0.
- SNMP errors never contain the switch address; an error from a per-VLAN walk names the VLAN.
- The startup line names each instance and its type, without URLs.
- hostname/vendor fallback between several rows of one MAC is now deterministic (empty IP or network ranks last); 1.0 depended on the firewall's row order.

### Deprecated

- The `switch` and `unifi` objects in the API `meta` block. Use `meta.connectors`; the old objects go away in 1.2.

### Fixed

- **Baseline:** with several sighting producers, the baseline waits until each enabled one has answered at least once, so a firewall that fails at the first poll no longer has its devices mailed as new when it answers; the instance holding the baseline back is logged once as a warning.
- **Merge:** with `LEASE_TYPE_MODE` `grace` or `immediate`, a failed instance that produces sightings no longer clears lease types it may hold; a failed switch or Wi-Fi controller does not hold clearing back. A device that moves takes IP, network and interface from the new sighting instead of keeping the old ones, also when it has no IP at the new place; a network that was unknown and becomes known is not a move (the stored IP is kept). Without ARP or a lease IP, IP, network and interface come from a sighting with an IP first, then a lease without an IP, then a controller client, scan or other source, so a Kea reservation without an IP no longer hides the IP a controller reports. A port with an empty label ranks last; a move to the same port label on another switch writes a `port` event naming both instances. A controller or switch whose answer had malformed records dropped counts as failed for leaving Wi-Fi and for releasing a held port. A client listed without an SSID keeps its stored SSID; one without any SSID leaves Wi-Fi under the same rule. `link` is set to `wired` only for a device on the wire, not one in grace.
- **Connector records:** control and bidi characters are removed from text, tab and every line break (also CR, VT, FF, NEL, LS, PS) become spaces, and broken Unicode is replaced instead of failing the poll; SSID, AP and alias are no longer trimmed; `kind` is compared case-insensitively; text (or bytes) flags such as `"false"` read as false; out-of-range numbers are ignored; a record whose field cannot be converted is dropped instead of failing the poll, and the drop warning names that cause too. An odd UniFi channel value drops only that field; a `stats` object that raises no longer fails the poll. An unexpected connector exception logs its traceback once per failed spell for each distinct error and raise site, also when failures alternate.
- **Switch/SNMP:** a MAC learned on several ports of one switch is placed on the edge port. Cisco IOS fails the poll and names the context when only some VLAN contexts answer. Profile OIDs may have a leading dot, and a `no_bulk` entry (an OID or an `oids` key name, trimmed) covers the OIDs under it. LLDP names are read as UTF-8. Bridge port 0 and invalid MAC indexes are skipped; a port known only from the forwarding table keeps its LLDP neighbour. The missing-baseport warning starts with the instance name and is logged once per instance, also when the rows cannot be read. The per-instance `TIMEOUT` also caps the SNMP walk and the probe instead of a fixed 60 s. Detection errors from pysnmp fall back to `standard` instead of failing.
- **SNMP profiles:** a file may start with a UTF-8 BOM; `_` keys are comments inside sections too; `oids` values must be numeric OIDs; `port_name.short` keys must not be empty and are applied longest first; JSON errors give line and column; a too deeply nested file is reported; long values in messages are cut; an error lists at most 20 problems and then "N more"; a section key that is not a plain name is quoted; an empty `port_name.short` key is reported together with a bad value; `fdb.vlan_source` and `fdb.private_oids` cannot name a `_` key; a socket given as the file is reported as "not a regular file".
- **Web/security:** a request with more than one `Host` header gets 400; the CSV formula guard also covers a formula after `;` or a line break (also behind quotes or blanks; a CRLF counts as one line break) and the `switch_port` column; a header line with whitespace before the colon gets 400 (other header complaints, such as a multipart `Content-Type`, do not); `last_poll_age` is never negative; a client that hangs up is no longer logged as an error or sent a second response; an absolute-form request target for `/` (also `http://host` without a path) serves the page, and in origin form only `/` and `/?…` do (`//x`, `?x` and `*` get 404); `/healthz` is stale when the last poll lies in the future; the request log escapes control characters and backslashes. The firewall's and controller's host is masked as `<host>` in connector errors, also in its punycode spelling. `meta.switch` and `meta.unifi.enabled` follow the instances named `switch` and `unifi` (of those types) under `LW_CONNECTORS`; with several controllers the status label is "Wi-Fi <instance>". In `/api/status` a `strategy` the poll did not report is cleared, an instance fixed after being disabled no longer shows the old `disabled: …` error (also in `switch_error`/`unifi_error`) before its first poll, and a disabled `switch`/`unifi` instance resets `switch_ok`/`unifi_ok` at startup.
- **UI:** a failed instance's dot is red, and grey while polls fail for an instance not read since the last good poll. "Seen by" and the device page name instances by their status-dot label; the device page names the switch that placed the device. A Wi-Fi client without an SSID is still shown on Wi-Fi, and on its port (filtered as Wired) once a switch places it there; the device page no longer names a Wi-Fi controller after a switch port. An older reload no longer overwrites a newer one, an edit in progress survives refreshes, failed refreshes and saves, the device page shows the new Known state after an ack saved while typing, and keyboard focus is kept (without scrolling) when the list or drawer redraws. "On the wire" and the "Seen by" age are judged in server time. A failing instance stays red when the last good poll lies in the future. The 30-day chart no longer drops newcomers at its edges. A baseline device shows as known, with Save as the main button and "Save & mark checked" as the ack button. The status line reads "polled <age>" without the firewall's name. The hostname sub-line is not repeated when it equals the alias or name. Copying a MAC works without the clipboard API or when the write is refused (the MAC is selected). The address bar is updated after Safari throttles it. The unnamed network sorts last.
- **Mail:** a retried mail leaves out devices acknowledged in the meantime and shows their current IP and hostname; an empty network or lease type is left out, and the subject has no "()" without IP and network; line breaks in hostnames can no longer add lines; the log line no longer contains the subject. A database error while refreshing queued mails no longer loses this poll's new-device mail or fails the poll.
- **CLI:** `snmp-detect` escapes control characters from the switch, runs the same configuration checks as the server, names an empty, blank or missing key variable, prints every configuration problem when the instance is not configured and the problems behind a key set in two spellings, refuses an instance listed twice in `LW_CONNECTORS`, and caches the detected profile; it shows names as the poll stores them and the forwarding-table address column as a hex MAC. Output piped to `head` no longer ends with a traceback and keeps a failure exit code, and `--help` into a closed pipe exits 0; Ctrl-C exits with 130 without a traceback. A broken or too old pysnmp is named (`pysnmp cannot be imported: …`, as the connector says, which also tells a missing pysnmp from an older one or a missing dependency) instead of "not installed".
- **Config:** `LW_CONNECTOR__*` variables for an instance not in `LW_CONNECTORS`, or not of the form `LW_CONNECTOR__<NAME>__<KEY>`, stop the start. An explicitly empty connector `DHCP_BACKEND`, `AUTH` or `USER` is refused. A UTF-8 BOM in a `<KEY>_FILE` is ignored. Only the literal `ALLOWED_HOSTS=*` turns the host check off; an entry without a host name stops the start; non-ASCII names are matched in punycode. URLs with a bad port (also port 0), spaces or control characters, or credentials before a `#`/`/`/`?`, are refused; an `@` in a URL path or query (also after an IPv6 literal host such as `[::1]`) is not taken for credentials unless a `user:` comes before it, in connector `URL`s as in `PUBLIC_URL` (only a URL with a port and an `@` in its path is still refused: write `%40`). An empty user info (`https://@host`) is refused, and a `:` after the first `/`, `?` or `#` is not taken for a password; connector URLs, `PUBLIC_URL` and `MAILGUN_API_BASE` share one rule. A `TIMEOUT` with leading zeros is used as written (`0005` is 5 s). The URL scheme is case-insensitive. An empty global integer setting (e.g. `NEW_DAYS=`) means its default. `ALLOWED_HOSTS` keeps the deviation characters `ß`, `ς`, ZWNJ and ZWJ in punycode as browsers do, reads `Σ` as `σ` and removes invisible characters such as a soft hyphen.
- **Store:** a non-standard `schema_version` (e.g. `1_0`) is treated as 1; a `schema_version` stored as a BLOB or as an overlong number no longer stops the start; a clock jump ahead of any length no longer wipes the event log (the prune clock is stored and moves at most a day per start and twice real time while running); a hand-edited non-numeric `events_prune_ts` falls back to the last poll time; a clock that is behind (e.g. no RTC before NTP sync) no longer moves the prune clock back (a brand-new database whose first poll runs on a wrong clock still starts from that clock); history is capped by insertion order.

## 1.0.0

First release; see the git tag `v1.0.0`.
