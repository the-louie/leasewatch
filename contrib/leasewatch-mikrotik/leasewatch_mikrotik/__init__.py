"""leasewatch connector for MikroTik RouterOS 7 through its REST API (type "mikrotik")."""
from __future__ import annotations

from .connector import MikrotikConnector, parse

__all__ = ["MikrotikConnector", "parse"]
