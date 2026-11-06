# leasewatch-dnsmasq

A leasewatch connector (type `dnsmasq_leases`) that reads the DHCPv4 leases from a dnsmasq leases file: the file
dnsmasq writes with `--dhcp-leasefile` (Pi-hole, OpenWrt, a plain Linux dnsmasq). It only reads the file.

## Settings

| Key | Required | Default | Meaning |
|---|---|---|---|
| `PATH` | yes | | Absolute path of the leases file inside the leasewatch container |
| `NETWORK` | no | empty | Network name shown for these devices (e.g. `LAN`); dnsmasq's file does not say which network a lease is on |

`TYPE` and `TIMEOUT` are host keys, as for every connector.

```
LW_CONNECTORS=dhcp1
LW_CONNECTOR__DHCP1__TYPE=dnsmasq_leases
LW_CONNECTOR__DHCP1__PATH=/leases/dnsmasq.leases
LW_CONNECTOR__DHCP1__NETWORK=LAN
```

## What it sees

- One `dhcp` sighting per current DHCPv4 lease: MAC, IPv4 address, hostname (`*` in the file becomes empty) and
  client-id.
- **No online state.** The file holds leases, not an ARP table, so a device is never marked online by this
  connector (presence is always false). Pair it with a source that sees the wire if you need *Online*.
- **No static/dynamic distinction.** The file does not say whether a lease comes from a `dhcp-host` entry or a
  dynamic range, so every lease has lease type `dynamic`. An expiry of `0` means an infinite lease (dnsmasq writes
  0 for lease time `infinite`, and also when the expiry would overflow in 2038); it is kept, still as `dynamic`.
- Not read: DHCPv6 leases, the `duid` line, `vendorclass` and `agent-info` lines.
- Skipped: leases whose expiry has passed (dnsmasq removes them on its next prune).
- Dropped and counted in the status `dropped` count: lines that are not a lease, and leases whose hardware address
  is not Ethernet (written with a type prefix such as `20-` for InfiniBand); those have no MAC.
- A dnsmasq built with `HAVE_BROKEN_RTC` writes the lease *length* instead of the expiry time; such a file is not
  supported (most of its leases would look expired).

The file may be at most 4 MiB, and must be a regular file (a FIFO, socket or directory is refused without
blocking). Errors name only the kind of problem (`PATH: not found`, `PATH: permission denied`,
`PATH: not a regular file`, `PATH: larger than 4096 KiB`, `PATH: symbolic link loop`, `PATH: path too long`, and for
other errors the system's short error text), never the path.

dnsmasq rewrites the file in place, so a read can catch it empty or half written. Each poll reads the file, waits
50 ms and reads it again; the text is used only when both reads give the same bytes and the file's inode, size and
modification time did not change. Otherwise it reads once more and compares with the read before, up to 3 times.
If the file is still changing, the poll fails for this instance with `PATH: file changed while reading` instead of
reporting a short lease list. An empty file is used only when it reads empty both times.

Limit: if dnsmasq stalls in the middle of its rewrite for longer than both reads and the wait between them (for
example on a slow SD card under heavy write load), the half-written file reads the same twice and is used. The
leases missing from it are not listed for that poll (on the very first poll they show up as new on the next one).

## Where the file is

| Platform | Default path |
|---|---|
| dnsmasq on Linux | `/var/lib/misc/dnsmasq.leases` |
| dnsmasq on FreeBSD/OPNsense | `/var/db/dnsmasq.leases` |
| Pi-hole (v6) | `/etc/pihole/dhcp.leases` |
| OpenWrt | `/tmp/dhcp.leases` (`uci get dhcp.@dnsmasq[0].leasefile`) |

`--dhcp-leasefile=<path>` (or `dhcp-leasefile=` in the config) overrides it.

## Mounting the file into the container

The leasewatch container runs as non-root with a read-only root file system. Mount the file's **directory**
read-only (dnsmasq rewrites the file in place, and a directory mount also survives a file that is replaced):

```yaml
services:
  leasewatch:
    volumes:
      - /etc/pihole:/leases:ro
    environment:
      LW_CONNECTOR__DHCP1__PATH: /leases/dhcp.leases
```

The file must be readable by the container's user. For a file on another host (e.g. OpenWrt), copy it to the
leasewatch host on a schedule and point `PATH` at the copy.

## Installing

The package declares the entry point `dnsmasq_leases` in the group `leasewatch.connectors.v1`. In the container, copy this
directory into a plugin directory and mount it read-only:

```
mkdir -p connectors && cp -r contrib/leasewatch-dnsmasq connectors/
docker run ... -v ./connectors:/connectors:ro -e LW_CONNECTORS_DIR=/connectors leasewatch:local
```

(or uncomment the `LW_CONNECTORS_DIR` and `./connectors` lines in `docker-compose.yml`). Outside a container,
`pip install contrib/leasewatch-dnsmasq` installs it instead (the build needs `setuptools`). The start log lists the type
(`connector types: ...; dnsmasq_leases 0.1 (leasewatch-dnsmasq 0.1.0, LW_CONNECTORS_DIR /connectors)`).

## Tests

```
cd contrib/leasewatch-dnsmasq
PYTHONPATH=../.. python3 -W error::ResourceWarning -m unittest discover -s tests
```
