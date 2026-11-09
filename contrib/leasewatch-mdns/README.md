# leasewatch-mdns

A leasewatch connector (type `mdns`) that listens for mDNS/DNS-SD announcements on the LAN (UDP 5353, group
224.0.0.251) and attaches the names and models it hears to devices leasewatch already knows by IP address. It is
listen-only: it binds the mDNS port, joins the multicast group and receives. It never sends a packet; the only
frames it causes are the IGMP group joins.

Needs leasewatch 1.5 or later. On an older host the settings check reports "needs leasewatch 1.5 or later
(device_ips)" and the connector does not start. It is a secondary source of names: a failed listener never fails
a poll, and the host does not hold its baseline or a lease for it.

## A device must be known already

The connector attributes a name by address: it maps the address in the announcement's `A` record to a device
through the host's address map. It does not use the packet's source address, because a sleep proxy that answers
for another device names that device, not itself. The address map holds the addresses leasewatch already knows
for each device. A device that no other connector has seen yet (for example from the firewall's DHCP leases or ARP table) cannot get a name; its announcements are
counted as `unmapped` and dropped. The record it produces has no address and no MAC of its own, and `presence` is
`False`: hearing a device announce itself never marks it online.

## Settings

| Key | Required | Default | Meaning |
|---|---|---|---|
| `INTERFACE` | no | empty | Join the group on this interface only, given as its IPv4 address or its name (e.g. `eth0`). Empty joins on every non-loopback interface, by index. With avahi on the host, set it to hear one segment only |
| `MAX_AGE_DAYS` | no | `7` | How long a heard name is kept per device, 1 to 90 days |
| `MAX_ENTRIES` | no | `4096` | The most devices kept in the cache, 64 to 65536 |
| `RELAYS` | no | empty | Comma-separated IPv4 addresses of mDNS repeaters. A packet sent to the group from one of them is accepted at any TTL and counted as `relayed`. See "Running in a container" |

`TYPE` and `TIMEOUT` are host keys, as for every connector.

```
LW_CONNECTORS=fw1,names
LW_CONNECTOR__NAMES__TYPE=mdns
# LW_CONNECTOR__NAMES__INTERFACE=192.168.10.5
```

The listener binds `0.0.0.0:5353` with `SO_REUSEADDR` and `SO_REUSEPORT`, so another mDNS responder on the same
host (for example avahi) can run next to it. At the start it logs "mdns: listening on N interfaces"; an interface
that refuses the join (down, or without IPv4) is skipped, and the start fails only when no join succeeds. On Linux
a socket also hears the groups that other sockets joined on other interfaces, so with `INTERFACE` set the
connector clears `IP_MULTICAST_ALL` to hear that interface only. A response whose source port is not 5353 is not
mDNS (RFC 6762 section 6) and is counted as `wrong_port` without being read.

As RFC 6762 section 11 asks, the listener reads each packet's IP TTL and destination address (`IP_RECVTTL` and
`IP_PKTINFO`). It accepts only a packet sent to 224.0.0.251 with TTL 255, so a host off the link (a router lowers
the TTL) or a unicast packet to this host cannot name a device; these are counted as `off_link` and `unicast`. A
packet with another destination is always `unicast`; one with another TTL is accepted only from an address in
`RELAYS`. If
the OS refuses the two options, the connector logs "mdns: cannot check the sender's link; accepting any source"
once and accepts any source.

## Running in a container

The default `docker-compose.yml` uses a bridge network. Multicast from the LAN does not arrive on a bridge, so the
connector would hear nothing. Use one of these instead:

- **`network_mode: host`.** Remove the `ports:` block and set `LISTEN_HOST` to the address the page should listen
  on, because the web port is then bound on the host itself (with the image's default `0.0.0.0` it listens on
  every address of the host).
- **A macvlan network** on the VLAN to listen on, with the container attached to it.

Only the VLANs the host is attached to are heard. mDNS does not cross a router, so for devices on other VLANs (for
example an IoT VLAN) run an mDNS repeater on the firewall, such as os-mdns-repeater on OPNsense, and make sure the
repeated traffic reaches the VLAN the host is on. os-mdns-repeater 1.11 as packaged by OPNsense sends with the
system default TTL (1 on FreeBSD), so its repeated packets are refused as `off_link` unless the firewall's address
on that VLAN is listed in `RELAYS`; the upstream mdns-repeater and avahi's reflector send TTL 255 and need no entry.

## What it sees

- **Hostname:** from the `A` record of the announcement, the host label without `.local`.
- **Model:** from the text (TXT) record of a service, the first of the keys `fn`, `md`, `model`, `ty` and
  `product` that is present. For example a printer's `ty=`, a Chromecast's `fn=`, an Apple device's `model=`. It
  is stored as the sighting's `label`.

Devices announce on their own schedule, and the cache refresh cycle of most responders is about 75 minutes, so the
first names arrive within an hour or two after the start. They then stay for `MAX_AGE_DAYS`. The cache is not
saved, so after a restart the names return within one announcement cycle; while the cache is empty the connector
reports `labels_unavailable`, and leasewatch keeps the stored labels meanwhile.

The connector keeps one entry per device for `MAX_AGE_DAYS`. An address that moves to another device drops the old
device's entry. A goodbye (TTL 0) does not remove the name: the name is kept for the full time.

The listener thread starts at the first `check()` or `collect()` and parses at most 200 packets a second; the rest
are counted as `dropped_rate`. The status counts, reset each poll, are `names`, `packets`, `malformed`,
`unmapped`, `wrong_port`, `off_link`, `unicast`, `relayed` (accepted at a TTL other than 255 from a listed repeater),
`dropped_rate` and `errors`; `joined` is the number of interfaces
the group is joined on.

A malformed packet is logged as a WARNING at most once an hour per source address, and at most 10 times an hour in
total; after that, malformed packets are logged at DEBUG until the hour is over.

A packet with more than 32 questions, more than 16 compression pointers in one name or more than 16 KiB of names
in total is counted as `malformed`. A packet with an OPCODE or RCODE other than 0 is ignored.

## Privacy

The names and models of the devices on your LAN are stored like a DHCP hostname is. Nothing leaves the host.

## Limits

- IPv4 only: no `AAAA` records and no `ff02::fb` group.
- Responses only; the parser reads `A`, `PTR`, `SRV` and `TXT` records. Queries from other hosts are ignored.
- No SSDP/UPnP and no active probes: it never asks a device anything.
- A device whose address leasewatch does not know is counted as `unmapped`.
- Only what reaches the host's network segment is heard (see "Running in a container"), and only multicast
  packets with TTL 255, or from a repeater listed in `RELAYS`: a repeater that re-sends with a lower TTL and is
  not listed is not heard.

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
