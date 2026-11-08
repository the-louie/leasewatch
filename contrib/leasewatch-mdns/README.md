# leasewatch-mdns

A leasewatch connector (type `mdns`) that listens for mDNS/DNS-SD announcements on the LAN (UDP 5353, group
224.0.0.251) and attaches the names and models it hears to devices leasewatch already knows by IP address. It is
listen-only: it binds the mDNS port, joins the multicast group and receives. It never sends a packet; the only
frames it causes are the IGMP group joins.

## A device must be known already

The connector attributes a name by address: it maps the source address of an announcement to a device through the
host's address map (the addresses leasewatch already holds for each device). A device that no other connector has
seen yet (for example from the firewall's DHCP leases or ARP table) cannot get a name; its announcements are
counted as `unmapped` and dropped. The record it produces has no address and no MAC of its own, and `presence` is
`False`: hearing a device announce itself never marks it online.

## Settings

| Key | Required | Default | Meaning |
|---|---|---|---|
| `INTERFACE` | no | empty | Join the group on this interface, given as its IPv4 address or its name (e.g. `eth0`). Empty joins on every interface |
| `MAX_AGE_DAYS` | no | `7` | How long a heard name is kept per device, 1 to 90 days |
| `MAX_ENTRIES` | no | `4096` | The most devices kept in the cache, 64 to 65536 |

`TYPE` and `TIMEOUT` are host keys, as for every connector.

```
LW_CONNECTORS=fw1,names
LW_CONNECTOR__NAMES__TYPE=mdns
# LW_CONNECTOR__NAMES__INTERFACE=192.168.10.5
```

The listener binds `0.0.0.0:5353` with `SO_REUSEADDR` and `SO_REUSEPORT`, so another mDNS responder on the same
host (for example avahi) can run next to it.

## Running in a container

The default `docker-compose.yml` uses a bridge network. Multicast from the LAN does not arrive on a bridge, so the
connector would hear nothing. Use one of these instead:

- **`network_mode: host`.** Remove the `ports:` block and set `LISTEN_HOST` to the address the page should listen
  on, because the web port is then bound on the host itself (with the image's default `0.0.0.0` it listens on
  every address of the host).
- **A macvlan network** on the VLAN to listen on, with the container attached to it.

Only the VLANs the host is attached to are heard. mDNS does not cross a router, so for devices on other VLANs (for
example an IoT VLAN) run an mDNS repeater on the firewall, such as os-mdns-repeater on OPNsense, and make sure the
repeated traffic reaches the VLAN the host is on.

## What it sees

- **Hostname:** from the `A` record of the announcement, the host label without `.local`.
- **Model:** from the text (TXT) record of a service, the first of the keys `fn`, `md`, `model`, `ty` and
  `product` that is present. For example a printer's `ty=`, a Chromecast's `fn=`, an Apple device's `model=`. It
  is stored as the sighting's `label`.

Devices announce on their own schedule, and the cache refresh cycle of most responders is about 75 minutes, so the
first names arrive within an hour or two after the start. They then stay for `MAX_AGE_DAYS`.

The connector keeps one entry per device for `MAX_AGE_DAYS`. An address that moves to another device drops the old
device's entry. A goodbye (TTL 0) does not remove the name: the name is kept for the full time.

The listener thread starts at the first `check()` or `collect()` and parses at most 200 packets a second; the rest
are counted as `dropped_rate`. The status counts, reset each poll, are `names`, `packets`, `malformed`,
`unmapped`, `dropped_rate` and `errors`.

## Privacy

The names and models of the devices on your LAN are stored like a DHCP hostname is. Nothing leaves the host.

## Limits

- IPv4 only: no `AAAA` records and no `ff02::fb` group.
- Responses only; the parser reads `A`, `PTR`, `SRV` and `TXT` records. Queries from other hosts are ignored.
- No SSDP/UPnP and no active probes: it never asks a device anything.
- A device whose address leasewatch does not know is counted as `unmapped`.
- Only what reaches the host's network segment is heard (see "Running in a container").

## Installing

The package declares the entry point `mdns` in the group `leasewatch.connectors.v1`. In the container, copy this
directory into a plugin directory and mount it read-only:

```
mkdir -p connectors && cp -r contrib/leasewatch-mdns connectors/
```

(then uncomment the `LW_CONNECTORS_DIR` and `./connectors` lines in `docker-compose.yml`, and switch to host
networking as described above). Outside a container, `pip install contrib/leasewatch-mdns` installs it instead.

## Tests

From the repository root:

```
python -m unittest discover -s contrib/leasewatch-mdns/tests
```

The fixtures are handcrafted packets and there is no network access.
