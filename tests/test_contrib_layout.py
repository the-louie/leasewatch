"""Layout rules for contrib/: the core never imports it, contrib imports only the public connector names, and
each contrib package's own tests pass."""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import unittest

from _contrib import CONTRIB, ROOT, contrib_dists, use_contrib
import _netguard

README = os.path.join(CONTRIB, "README.md")
PUBLIC_MODULE = "leasewatch.connectors"
TESTING_MODULE = "leasewatch.connectors.testing"


def py_files(top: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(top):
        dirnames[:] = [d for d in dirnames if d != "__pycache__" and not d.startswith(".")]
        out.extend(os.path.join(dirpath, f) for f in filenames if f.endswith(".py"))
    return sorted(out)


def imports(path: str) -> list[tuple[int, str, list[str]]]:
    """(line, absolute module, imported names) for every absolute import in a file; names is [] for `import x`."""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend((node.lineno, a.name, []) for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.append((node.lineno, node.module, [a.name for a in node.names]))
    return out


def public_names(block_name: str = "public-names") -> list[str]:
    with open(README, encoding="utf-8") as f:
        text = f.read()
    block = re.search(rf"<!-- {block_name}: begin -->(.*?)<!-- {block_name}: end -->", text, re.S)
    if not block:
        raise AssertionError(f"contrib/README.md has no {block_name} block")
    return re.findall(r"^- `([A-Za-z_][A-Za-z0-9_]*)`$", block.group(1), re.M)


def is_under(module: str, top: str) -> bool:
    return module == top or module.startswith(top + ".")


class ContribLayoutTest(unittest.TestCase):
    def test_core_never_imports_contrib(self) -> None:
        bad = [f"{os.path.relpath(p, ROOT)}:{line} {mod}"
               for p in py_files(os.path.join(ROOT, "leasewatch"))
               for line, mod, _ in imports(p) if is_under(mod, "contrib")]
        self.assertEqual(bad, [])

    def test_readme_public_names_exist(self) -> None:
        import leasewatch.connectors as connectors
        names = public_names()
        self.assertEqual(len(names), 15)
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(sorted(names), sorted(connectors.__all__))
        self.assertEqual([n for n in names if not hasattr(connectors, n)], [])

    def test_readme_testing_names_exist(self) -> None:
        import leasewatch.connectors.testing as testing
        names = public_names("testing-names")
        self.assertEqual(names, ["ConnectorContractTests"])
        self.assertEqual(sorted(names), sorted(testing.__all__))

    def test_contrib_imports_only_public_names(self) -> None:
        self.assertTrue(contrib_dists(), "contrib/ has no packages")
        allowed = {PUBLIC_MODULE: set(public_names()), TESTING_MODULE: set(public_names("testing-names"))}
        bad = []
        for p in py_files(CONTRIB):
            for line, mod, names in imports(p):
                if not is_under(mod, "leasewatch"):
                    continue
                if mod not in allowed or not names or set(names) - allowed[mod]:
                    bad.append(f"{os.path.relpath(p, ROOT)}:{line} {mod} {names}")
        self.assertEqual(bad, [])

    def test_contrib_package_tests_pass(self) -> None:
        dists = [d for d in contrib_dists() if os.path.isdir(os.path.join(CONTRIB, d, "tests"))]
        self.assertTrue(dists, "no contrib package has a tests directory")
        env = {**os.environ, "PYTHONPATH": ROOT}
        for dist in dists:
            with self.subTest(dist=dist):
                # a separate process per package: its test module names cannot clash with ours or another package's
                # with the network guard installed, like our own suite
                run = subprocess.run(_netguard.child_argv("discover", "-s", "tests"), cwd=os.path.join(CONTRIB, dist),
                                     env=env, capture_output=True, text=True, timeout=300)
                self.assertEqual(run.returncode, 0, run.stderr[-4000:])


class ContribHelperTest(unittest.TestCase):
    def test_use_contrib_adds_and_removes_path(self) -> None:
        self.assertTrue(contrib_dists(), "contrib/ has no packages")
        dist =contrib_dists()[0]
        inner = unittest.FunctionTestCase(lambda: None)
        path = use_contrib(inner, dist)
        self.assertEqual(sys.path[0], path)
        inner.doCleanups()
        self.assertNotIn(path, sys.path)

    def test_use_contrib_unknown_dist(self) -> None:
        with self.assertRaises(FileNotFoundError):
            use_contrib(self, "no-such-dist")


if __name__ == "__main__":
    unittest.main()
