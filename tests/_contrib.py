"""Test helper: make one contrib package importable for the duration of a test.

contrib/<dist>/ is not on sys.path by default (leasewatch itself never imports it), so a test that imports a
contrib connector calls use_contrib(self, "<dist>") first. The path entry and any modules imported from that
directory are removed again in the test's cleanup, so packages from different tests cannot see each other.
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRIB = os.path.join(ROOT, "contrib")


def contrib_dists() -> list[str]:
    """Names of the contrib packages: subdirectories of contrib/ that contain a pyproject.toml."""
    if not os.path.isdir(CONTRIB):
        return []
    return sorted(d for d in os.listdir(CONTRIB)
                  if not d.startswith((".", "_")) and os.path.isfile(os.path.join(CONTRIB, d, "pyproject.toml")))


def use_contrib(test: unittest.TestCase, dist: str) -> str:
    """Put contrib/<dist>/ first on sys.path until the test ends; returns that directory."""
    path = os.path.join(CONTRIB, dist)
    if not os.path.isdir(path):
        raise FileNotFoundError(f"no contrib package {dist!r}")
    before = set(sys.modules)
    # sys.path and sys.modules are process globals: both are restored in the cleanup below
    sys.path.insert(0, path)

    def _undo() -> None:
        if path in sys.path:
            sys.path.remove(path)
        prefix = path + os.sep
        for name in set(sys.modules) - before:
            origin = getattr(sys.modules[name], "__file__", None) or ""
            if origin.startswith(prefix):
                del sys.modules[name]

    test.addCleanup(_undo)
    return path
