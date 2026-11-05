# leasewatch

**Who is on the network, newest first.** A small self-hosted page that watches an [OPNsense](https://opnsense.org/) firewall's DHCP leases and ARP table, remembers every device it has ever seen, mails you when a new one appears, and lets you name and acknowledge devices so a newcomer is noticed once and then known.

![screenshot](docs/screenshot.png)

- One row per MAC with vendor, IP, hostname, network (VLAN), lease type, first seen / last online, a history of address changes and an event log.
- **Newest first**, a "not yet known" review queue, name + note per device, CSV export, search, filters, light/dark, phone layout.
- Optional **"Connected via"**: switch port over SNMPv3 (Q-BRIDGE / IF / LLDP MIBs — any managed switch; uplink ports are named after the AP or switch behind them; tested on Comware, LLDP port numbers are mapped through `lldpLocPortId`) and Wi-Fi SSID / AP / signal from a UniFi Network controller.
- Backend: Python 3.12 standard library (`urllib`, `sqlite3`, `http.server`); the only pip dependency is `pysnmp` for the optional switch lookup. Frontend: one HTML page, vanilla JS/CSS, no build step.
- Read-only towards the firewall: the API user needs just the DHCPv4 leases privilege (ISC or Kea, `DHCP_BACKEND`) and *Diagnostics: ARP Table*.

## Run

```sh
cp .env.example .env && chmod 600 .env      # set FW1_URL, FW1_KEY, FW1_SECRET (and the optional sources)
install -d -o 100 -g 101 data               # the container runs as uid 100 (alpine "app")
docker compose up -d --build                # without nginx-proxy: publish port 8080 instead, see docker-compose.yml
docker compose exec leasewatch wget -qO- http://127.0.0.1:8080/api/stats   # the meta block shows the last poll; /healthz is for monitors (503 + reason on failure, which busybox wget does not print)
```
Local development: `DATA_DIR=./data LISTEN_PORT=8089 FW1_URL=… FW1_KEY=… FW1_SECRET=… python3 -m leasewatch`.

### OPNsense API user

Create a user with only the privileges *Diagnostics: ARP Table* and the leases page of the DHCPv4 server you run — *Services: ISC DHCPv4: Leases* (`DHCP_BACKEND=isc`, the default) or the Kea DHCPv4 leases privilege (`DHCP_BACKEND=kea`, reads `/api/kea/leases4/search`) — generate an API key for it (System › Access › Users › the user › API keys) and put key and secret in `.env`. The ACL for the ARP table matches the snake_case endpoint (`get_arp`), which is what leasewatch calls.

### Optional sources

- **Switch port (SNMPv3):** a read-only v3 user on the switch with a view that includes `1.3.6.1.2.1` (mib-2) and `1.0.8802.1.1.2` (LLDP), authentication SHA or SHA-256, privacy AES-128. Set `SNMP_HOST` (a host name or IP without a port; UDP 161 is used), `SNMP_USER`, `SNMP_AUTH`, `SNMP_AUTH_KEY`, `SNMP_PRIV_KEY`. Ports with an LLDP neighbour or ≥ 6 MACs are shown as `port → what hangs there`.
- **Wi-Fi (UniFi Network):** a read-only admin on the controller; set `UNIFI_URL`, `UNIFI_USER`, `UNIFI_PASSWORD` (classic session API: `/api/login`, `/api/s/<site>/stat/sta`). The controller's device alias becomes the display name when no name or hostname exists.
- **Mail (Mailgun):** set `MAILGUN_KEY`, `MAILGUN_DOMAIN`, `MAIL_TO`; for an EU-region domain also `MAILGUN_API_BASE=https://api.eu.mailgun.net`.
- Either source failing only greys its dot in the status pill; the last values stay.

## API

| Method | Path | What |
|---|---|---|
| GET | `/api/devices` | all devices + collector meta |
| GET | `/api/devices/<mac>` | one device with history and events |
| POST | `/api/devices/<mac>` | `{"acked": bool, "name": str, "note": str}` (any subset) |
| GET | `/api/stats` | counts, per-network, first-seen times of the last 30 days' newcomers |
| GET | `/api/events` | last 300 events |
| GET | `/api/devices.csv` | CSV export (timestamps ISO 8601 in the container's `TZ`) |
| GET | `/healthz` | 200 when the last poll succeeded and is fresh, else 503 |

## Semantics

- **Baseline:** everything present at the very first poll is marked `baseline` — not "new", no mail, sorted after real newcomers. An empty first poll is not taken as the baseline.
- **New** = first seen within `NEW_DAYS` and not baseline. **Not yet known** = not marked known and not baseline.
- **Online** = in the ARP table now (or the lease says online), re-evaluated every poll. A device that leaves the ARP table (or is no longer listed) stays online for `ONLINE_GRACE_MINUTES` after it was last seen on the wire, then goes offline. `last_online` is the last time it was actually online; `last_seen` (CSV `last_listed`) the last time the firewall listed it at all — static mappings are always listed, so the UI shows *last online*.
- **History** rows are written only when IP, hostname, network or lease type change (capped at 200 per device). **Events:** new, ip, hostname, vlan, lease_type, port, wifi, back (online again after > 1 day), acked / unacked; kept for a year.
- A device keeps its last lease type after the lease is gone (a device seen only in ARP stays "DHCP" if it once had a lease); otherwise an expiring lease that is still in ARP would flap between types on every poll. `sources` shows what listed it last.
- A Wi-Fi device that leaves keeps its last SSID/AP for the record; the Wi-Fi details are dropped only when it is on the wire again without UniFi listing it.
- Interfaces in `IGNORE_INTERFACES` (default WAN and loopback) are skipped.

## Backup and reset

- Backup: `docker compose exec leasewatch python -c "import sqlite3; sqlite3.connect('/data/leasewatch.sqlite3').backup(sqlite3.connect('/data/backup.sqlite3'))"` then copy `data/backup.sqlite3` (WAL mode: do not copy the live file while the container runs).
- Reset the baseline: stop the container, delete `data/leasewatch.sqlite3*`, start again (names and notes are lost — export the CSV first).
- Mail on new devices is retried with the next poll if Mailgun fails (up to 50 queued devices, lost on restart).

## Security notes

The page has no login: it is meant for a trusted LAN behind a reverse proxy. Anyone who can reach it can read the device list and mark devices known; nothing can be changed on the firewall through it. POSTs require `Content-Type: application/json` and a same-origin `Sec-Fetch-Site`, so a page on another site cannot submit them. Requests whose `Host` header is neither an IP address, `localhost` nor a name in `ALLOWED_HOSTS` (default: the host of `PUBLIC_URL`) get 421, which blocks DNS rebinding; set `ALLOWED_HOSTS=*` to turn that off. The CSV export neutralises spreadsheet formula injection from untrusted hostnames.

## Tests

`python3 -m unittest discover -s tests -v` — collector, enrichers and a full HTTP API suite (fake firewall, no network).

## License

MIT — see `LICENSE`.
