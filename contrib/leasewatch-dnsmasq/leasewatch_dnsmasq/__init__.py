"""leasewatch connector for a dnsmasq leases file (type "dnsmasq_leases")."""
from __future__ import annotations

from .connector import DnsmasqLeasesConnector, parse_leases

__all__ = ["DnsmasqLeasesConnector", "parse_leases"]
