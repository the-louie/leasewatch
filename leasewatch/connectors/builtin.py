"""The connector types that ship with leasewatch, listed explicitly (no package scan)."""
from __future__ import annotations

from .opnsense import OpnsenseConnector
from .snmp_switch import SnmpSwitchConnector
from .unifi import UnifiConnector

BUILTIN = (OpnsenseConnector, SnmpSwitchConnector, UnifiConnector)
