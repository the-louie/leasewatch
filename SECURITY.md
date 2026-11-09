# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** ([private vulnerability report](../../security/advisories/new)). Do not open a public issue for them.

Include the leasewatch version, how it is deployed (container or `pip`, reverse proxy, login on or off) and the steps to reproduce. Answers come in the advisory thread; the details are made public once a fixed release is out.

## Supported versions

| Version | Supported |
|---|---|
| 1.6.x | yes |
| older | no |

Fixes go into the latest 1.6 release only.

## Security stance

leasewatch is a tool for a home or small-office LAN. It is meant to run behind a reverse proxy, not exposed to the internet.

- **Login is optional and off by default.** Without it, anyone who can reach the page can read the device list and mark devices known. `AUTH_USER` and `AUTH_PASSWORD_HASH` (a PBKDF2-SHA256 hash from `python -m leasewatch hash-password`) turn on HTTP basic auth for every path, `/healthz` included. Basic auth is safe only over HTTPS: put a TLS reverse proxy in front. API tokens (`AUTH_TOKENS`, `Authorization: Bearer`, from `python -m leasewatch make-token`) are read-only and need the login; the environment holds only each token's SHA-256, and a token is revoked by removing its entry and restarting.
- **Write protection.** `READ_ONLY=1` refuses every change through the page or API; `WRITE_ALLOW` limits changes to the listed addresses and networks. The address is the socket peer, never `X-Forwarded-For`, so behind a reverse proxy restrict writes at the proxy instead (README, *Security notes*). With login off, bind the port to the admin network and set `WRITE_ALLOW` to it.
- **Read-only towards the firewall.** Only the DHCPv4 lease search, the Kea reservation search, the dnsmasq static-host search and the ARP table are read; with `IPV6=1` also the NDP table (a read-only privilege) and, under Kea, the DHCPv6 lease search (its privilege allows writes, like the v4 one). No configuration endpoint is called; nothing on the firewall can be changed through leasewatch. The switch (SNMPv3) and UniFi connectors only read as well.
- **Requests:** a `Host` header that is not an IP address, `localhost` or in `ALLOWED_HOSTS` (default: the host of `PUBLIC_URL`) gets 421, which blocks DNS rebinding. POSTs need `Content-Type: application/json` and a same-origin `Sec-Fetch-Site`. Request bodies have a size limit. Static files are served path-traversal safe.
- **Responses:** every response, errors included, carries security headers and a strict `Content-Security-Policy` (own script and style only, no inline code, own origin only, no framing). The CSV export neutralises spreadsheet formula injection from untrusted fields such as DHCP hostnames.
- **Secrets are never sent or logged.** API keys, passwords, SNMP keys, the webhook URL and the login password never appear in logs, error responses, API output or the page; errors from connectors and notification channels are redacted and carry a code or short text only. Connector secrets can be read from files (`<KEY>_FILE`). Requests to the firewall and the UniFi controller ignore HTTP proxies unless the instance sets `PROXY=1`.
- **Container:** runs as the non-root user `10001:10001` with a read-only root file system; `/data` is the only writable volume (plus a tmpfs `/tmp`).
- **Not an intrusion detector.** A new private (locally administered) MAC never sends a new-device mail, and one that sends the DHCP client-id or a distinctive hostname of a known device is merged into it (README, *Private MACs*). A device on the LAN can therefore hide in the list by copying another device's client-id or hostname.
- **Third-party connectors** run with leasewatch's full privileges and see the whole environment. Load only code you trust.

## What the notifications send

When a notification channel is configured (Mailgun, SMTP or a webhook), leasewatch sends each new device's **name (DHCP hostname), IP address, MAC address, vendor, network (VLAN) and lease type** to that channel, with the site name and, when `PUBLIC_URL` is set, a link to the page. With `MAIL_ON_SOURCE` or `MAIL_ON_WATCH` on, the channels also get a source's error text and a watched device's events (its name, the kind and the detail). Nothing else is sent to a channel, and nothing is sent when no channel is configured. Pick a channel you trust with this information; a webhook URL is treated as a secret, and `WEBHOOK_SECRET` signs each request.

With `MQTT_URL` set, device names, hostnames, MAC addresses, addresses (IPv4 and IPv6), VLAN, port, SSID, tags and online state go to the broker as retained messages, and with `MQTT_EVENTS=1` the webhook's JSON body goes to the event topic. The broker is therefore part of the trust boundary: use a user and password, and `mqtts://` for any broker that is not on the same host.
