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
| `SSDP` | no | `0` | `1` also listens to SSDP announcements (UDP 1900, group 239.255.255.250) and takes the product named in `SERVER:` as the device's label when mDNS gives none; the socket only receives |

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

With `SSDP=1` the SSDP socket needs the same: host networking or a macvlan, for the same reason.

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
`unmapped`, `wrong_port`, `off_link`, `unicast`, `relayed` (accepted at a TTL other than 255 from a listed repeater, and then handled: not counted when it fails the port check or the rate budget),
`dropped_rate` and `errors`; `joined` is the number of interfaces
the group is joined on.

### SSDP (`SSDP=1`)

SSDP is how UPnP devices announce themselves: every few minutes a device sends a NOTIFY to 239.255.255.250:1900.
Its `SERVER:` header names the OS, `UPnP/1.0` and the product, for example `Linux/4.9 UPnP/1.0 Sonos/70.3-35220`,
which gives the label `Sonos/70.3-35220`. The label is the tokens after `UPnP/`; a `DLNADOC/1.50` token (the DLNA
capability marker, not a product) is left out wherever it stands. There is no label when the first remaining token
names a UPnP library rather than a device; these names are generic: `Portable SDK for UPnP devices`,
`UPnP-Device-Host`, `MiniUPnPd`, `Platinum`, `Cling`, `Samsung UPnP SDK`, `libupnp`, `IntelUpnp` and
`WindowsMediaPlayer` (and `DLNADOC` when nothing follows it). The device is the one that holds the NOTIFY's source
address, found as for mDNS.

The mDNS label wins: SSDP fills the label only when mDNS gave none. A device known by SSDP alone gets a sighting
with a label and no hostname, because an SSDP announcement carries no host name. Once a label is stored for a source address, its
NOTIFYs are not read again for 10 minutes (`ssdp_repeat`), so a device's bursts cost one parse. SSDP has its own cache, with the same
`MAX_AGE_DAYS` and `MAX_ENTRIES`, and its own rate budget of 200 packets a second.

The SSDP status counts, reset each poll, are all there when `SSDP=1` and absent otherwise:
`ssdp_packets` (every datagram on the SSDP socket), `ssdp_dropped_rate` (over the rate budget), `ssdp_errors`
(receive failures and packets the handler could not process), `ssdp_unicast`, `ssdp_wrong_if`, `ssdp_ttl_gt4`
(counted, not dropped), `ssdp_not_notify` (an M-SEARCH, a response, or a NOTIFY that is neither `ssdp:alive` nor
`ssdp:byebye`, such as `ssdp:update`), `ssdp_byebye`, `ssdp_malformed`, `ssdp_oversized` (over 2048 bytes), `ssdp_repeat`,
`ssdp_unmapped` (no known device holds the address), `ssdp_mismatch`, `ssdp_generic` (a generic UPnP stack),
`ssdp_no_label` (no product after `UPnP/`); `ssdp_joined` is the number of interfaces the SSDP group is joined on,
and `ssdp_labels` the number of devices that hold an SSDP label.

A malformed packet is logged as a WARNING at most once an hour per source address, and at most 10 times an hour in
total; after that, malformed packets are logged at DEBUG until the hour is over.

A packet with more than 32 questions, more than 16 compression pointers in one name or more than 16 KiB of names
in total is counted as `malformed`. A packet with an OPCODE or RCODE other than 0 is ignored.

## Privacy

The names and models of the devices on your LAN are stored like a DHCP hostname is. Nothing leaves the host.

With `SSDP=1` the connector still never sends: it sends no M-SEARCH and only hears what devices announce anyway. It
never fetches the `LOCATION` URL of a NOTIFY; it reads the host in it and nothing else.

## Limits

- IPv4 only: no `AAAA` records and no `ff02::fb` group.
- Responses only; the parser reads `A`, `PTR`, `SRV` and `TXT` records. Queries from other hosts are ignored.
- No active probes: it never asks a device anything, with or without SSDP.
- SSDP: a unicast NOTIFY is dropped (`ssdp_unicast`). A NOTIFY whose `LOCATION` names another IPv4 address than its
  source is dropped (`ssdp_mismatch`): a relay re-sent it, and the label would land on the relay; a `LOCATION` with
  a name or an IPv6 address is not checked. With `INTERFACE` set to an interface name, a packet from another
  interface is dropped (`ssdp_wrong_if`); given as an address, the kernel picks the interface and that check is
  skipped (on Linux the socket still receives only the joined interface's group traffic). The TTL is counted
  (`ssdp_ttl_gt4`), not
  checked. More than 200 packets a second are dropped (`ssdp_dropped_rate`). SSDP labels are often generic, which
  is why the list of ten library names exists.
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
