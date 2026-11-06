# leasewatch-mikrotik

A leasewatch connector (type `mikrotik`) that reads the DHCPv4 leases and the ARP table from a MikroTik router
running RouterOS 7 (7.1 or later), through the RouterOS REST API. It only reads: three `GET` requests per poll, and
one `GET /rest/system/resource` as the probe.

**Untested on real hardware.** This connector is built from the RouterOS 7 documentation, not against a real
router. Please report what you see (a working setup, a field that is named differently, an error), so it can be
confirmed or fixed.

## Settings

| Key | Required | Default | Meaning |
|---|---|---|---|
| `URL` | yes | | `https://<router>`; must be `https://` (the password is sent with every request). No `?query` or `#fragment`: the REST paths are appended to it. A path (`https://proxy.example.lan/mt`) is kept as a prefix |
| `USER` | yes | | RouterOS user (see below) |
| `PASSWORD` | yes | | That user's password (secret; `PASSWORD_FILE` also works) |
| `VERIFY_TLS` | no | `1` | Check the router's certificate. Set `0` for a self-signed certificate |
| `IGNORE_INTERFACES` | no | empty | Comma-separated interface names (e.g. `ether1` for the WAN port) or DHCP server names to skip, case-insensitive |
| `PROXY` | no | `0` | Use `http(s)_proxy` for this connection |

`TYPE` and `TIMEOUT` are host keys, as for every connector. Each request is capped at 30 seconds or `TIMEOUT`,
whichever is lower.

```
LW_CONNECTORS=mt1
LW_CONNECTOR__MT1__TYPE=mikrotik
LW_CONNECTOR__MT1__URL=https://router.example.lan
LW_CONNECTOR__MT1__USER=leasewatch
LW_CONNECTOR__MT1__PASSWORD_FILE=/run/secrets/mikrotik_password
LW_CONNECTOR__MT1__IGNORE_INTERFACES=ether1
```

`IGNORE_INTERFACES` is empty by default because the WAN port differs between models and configurations. On a
router with the default configuration the WAN port is `ether1`; without it, the ISP's gateway shows up as a
device.

## Router setup

- Enable the `www-ssl` service with a certificate (`/ip service`). The plain `www` service is not used.
- Make a user in a group with the policies **`read`** and **`rest-api`** only (the built-in `read` group has both):

  ```
  /user add name=leasewatch group=read password=...
  ```

## What it reads

| Request | Fields (`.proplist`) |
|---|---|
| `GET /rest/ip/dhcp-server` | `name`, `interface` |
| `GET /rest/ip/dhcp-server/lease` | `address`, `mac-address`, `active-address`, `active-mac-address`, `client-id`, `active-client-id`, `host-name`, `server`, `status`, `dynamic`, `disabled` |
| `GET /rest/ip/arp` | `address`, `mac-address`, `interface`, `complete`, `invalid`, `disabled`, `published`, `status` |

Redirects are never followed (a redirect would resend the password).

## What it maps

- **Leases:** one `dhcp` sighting per lease with status `bound` that is not disabled. MAC and IP are the active
  ones (`active-mac-address`, `active-address`) when present, else the configured ones. Hostname from `host-name`.
  Lease type `static` when `dynamic` is `false`, else `dynamic`. Network and interface are the interface of the
  lease's DHCP server (a relay server gives its own interface). A lease never marks a device online.
  Skipped: `waiting`, `offered`, `testing` and other states, and disabled leases.
- **ARP:** one `arp` sighting, online now, per entry that is complete and not invalid, disabled, published (proxy
  ARP) or `permanent` (a static entry says nothing about the wire). Network and interface are the ARP entry's
  interface.
- Dropped and counted in the status `dropped` count: a row that is not a JSON object, and a row with a yes/no
  value other than `"true"`/`"false"`.

### Fields not confirmed in the documentation

RouterOS's documented lease properties do not include `host-name`, `dynamic`, `disabled`, `active-address`,
`active-mac-address` or `active-client-id`, and RouterOS seems to leave out empty properties. The connector
therefore treats every field except the MAC as optional:

- no `host-name`: empty hostname;
- no `dynamic`: lease type `dynamic`;
- no `disabled` (lease or ARP), `invalid` or `published`: not set;
- no `active-*`: the configured value is used;
- no `complete` on an ARP entry: complete when `status` is `reachable`, `stale`, `delay` or `probe`;
- no `server`, or a server not in the server list: empty network and interface.

## Errors

Errors name the request path and the kind of problem: `HTTP 401 (wrong USER or PASSWORD)`, `HTTP 403 (the user's
group needs the read and rest-api policies)`, other HTTP codes with RouterOS's `message`/`detail`, `TLS certificate
not accepted (...)`, `timed out`, `connection refused (is the www-ssl service enabled?)`, `response is not JSON`.
The router's host name or address is shown as `<host>`; the password is never shown.

## Tests

```
cd contrib/leasewatch-mikrotik
PYTHONPATH=../.. python3 -W error::ResourceWarning -m unittest discover -s tests
```
