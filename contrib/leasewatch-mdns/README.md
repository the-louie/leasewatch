# leasewatch-mdns

A leasewatch connector (type `mdns`) that listens for mDNS/DNS-SD announcements on the LAN (UDP 5353, group
224.0.0.251) and attaches the names and models it hears to devices leasewatch already knows by IP address. It is
listen-only: it binds, joins the group and receives, and never transmits a packet.

Full documentation follows.
