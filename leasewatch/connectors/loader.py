"""Finds the connector types besides the built-in ones and imports them, one failure at a time.

Two origins, read in this order after the built-ins: installed distributions with an entry point in the group
`leasewatch.connectors.v<API_VERSION>` (name = type, value = `module:Class`), and the packages in
`LW_CONNECTORS_DIR` (one subdirectory per distribution, declaring the same entry point in its pyproject.toml).
There is no precedence: a type declared twice is refused, and a built-in type is never replaced. Every declared
name is collected before any plugin code runs, so a conflict never imports anything.

A plugin that fails to import or describe itself is not registered and is reported against its type: the host
refuses to start only when an instance uses that type. Problems the operator made in LW_CONNECTORS_DIR itself (not
a directory, an unreadable pyproject.toml, a package that would shadow another module) always stop the start.
"""
from __future__ import annotations

import importlib
import importlib.machinery
import importlib.metadata
import importlib.util
import logging
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field, replace
from typing import Mapping

from . import API_VERSION, Connector, ConnectorInfo

log = logging.getLogger("leasewatch.connectors.loader")

GROUP = f"leasewatch.connectors.v{API_VERSION}"
TYPE_RE = re.compile(r"^[a-z0-9_]+$")
_GROUP_RE = re.compile(r"^leasewatch\.connectors\.v(\d+)$")
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_VALUE_RE = re.compile(rf"^({_IDENT}(?:\.{_IDENT})*):({_IDENT}(?:\.{_IDENT})*)$")

BUILTIN, ENTRY_POINT, DIR = "built-in", "entry point", "LW_CONNECTORS_DIR"


@dataclass(frozen=True)
class Origin:
    """Where a type comes from. dist/version: the distribution's name and version; location: the resolved
    LW_CONNECTORS_DIR and entry: the subdirectory in it (dir origin only); type_version: describe().version."""
    kind: str
    dist: str = ""
    version: str = ""
    location: str = ""
    entry: str = ""
    type_version: str = ""

    def label(self) -> str:
        if self.kind == ENTRY_POINT:
            return f"entry point {self.dist} {self.version}".rstrip()
        if self.kind == DIR:
            return f"LW_CONNECTORS_DIR {self.entry}"
        return BUILTIN


@dataclass
class LoadResult:
    """types: type -> class (built-ins included); broken: type -> why it is not loaded; problems: the ones that stop
    the start; modules: the sys.modules names imported from LW_CONNECTORS_DIR (dropped again by unload())."""
    types: dict[str, type] = field(default_factory=dict)
    origins: dict[str, Origin] = field(default_factory=dict)
    broken: dict[str, str] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)


@dataclass
class _Decl:
    type: str
    module: str
    attr: str
    origin: Origin
    ep: importlib.metadata.EntryPoint | None = None
    path: str = ""  # the distribution's directory (dir origin)


class _Refused(Exception):
    """A plugin refused by a rule, not by its own failure: the message is the whole reason."""


def load(environ: Mapping[str, str], path: list[str] | None = None) -> LoadResult:
    """Built-ins plus every third-party type found on `path` (default sys.path) and in LW_CONNECTORS_DIR."""
    from .builtin import BUILTIN as builtin_classes
    res = LoadResult()
    for cls in builtin_classes:
        info = cls.describe()
        res.types[info.type] = cls
        res.origins[info.type] = Origin(BUILTIN, type_version=info.version)
    # finders cache directory listings: a package written since the last scan (a test, a fresh mount) must be seen
    importlib.invalidate_caches()
    other: dict[str, str] = {}
    try:
        decls = _entry_point_decls(sys.path if path is None else path, other)
        raw = (environ.get("LW_CONNECTORS_DIR") or "").strip()
        if raw:
            decls += _dir_decls(raw, res, other)
        _import_all(_without_conflicts(decls, res), res)
    except Exception as e:  # a loader bug must not take the built-ins (and the firewall connector) with it
        log.error("connector loading failed, only the built-in types are available", exc_info=True)
        res.problems.append(f"connector loading failed ({type(e).__name__})")
    for type_, why in other.items():
        if type_ not in res.types and type_ not in res.broken:
            res.broken[type_] = why
    return res


def unload(result: LoadResult) -> None:
    """Drop the modules a previous load imported from LW_CONNECTORS_DIR, so the next load imports them afresh."""
    for name in result.modules:
        sys.modules.pop(name, None)  # sys.modules is process global: only the dir plugins' own entries go


def _scan_path(path: list) -> list[str]:
    # `python -m` puts the working directory first on sys.path ("" for -c): it must never supply plugins
    try:
        cwd = os.path.realpath(os.getcwd())
    except OSError:
        cwd = ""
    return [p for p in path if isinstance(p, str) and p and os.path.realpath(p) != cwd]


def _other_api(dist: str, group: str, api: str, type_: str, other: dict[str, str]) -> None:
    log.warning("%s declares connector type %s for connector API %s (group %s); this host has connector API %d, "
                "so it is not loaded", dist, type_, api, group, API_VERSION)
    other.setdefault(type_, f"provided by {dist} for connector API {api}; this host has {API_VERSION}")


def _entry_point_decls(path: list, other: dict[str, str]) -> list[_Decl]:
    decls: list[_Decl] = []
    seen: set[tuple[str, str, str]] = set()
    for dist in importlib.metadata.distributions(path=_scan_path(path)):
        try:
            name = str(dist.metadata.get("Name") or "?")
            version = str(dist.version or "")
            eps = list(dist.entry_points)
        except Exception as e:  # broken metadata of some unrelated distribution
            log.warning("an installed distribution's metadata cannot be read (%s)", type(e).__name__)
            continue
        for ep in eps:
            m = _GROUP_RE.match(ep.group)
            if not m:
                continue
            if int(m.group(1)) != API_VERSION:
                _other_api(name, ep.group, m.group(1), ep.name, other)
                continue
            # the same distribution reached twice (a path listed twice) is one declaration
            if (name, ep.name, ep.value) in seen:
                continue
            seen.add((name, ep.name, ep.value))
            vm = _VALUE_RE.match(ep.value.replace(" ", ""))
            if not TYPE_RE.match(ep.name) or not vm:
                log.warning("%s: entry point %r = %r is not <type> = module:Class with a type of a-z, 0-9 and _; "
                            "ignored", name, ep.name, ep.value)
                continue
            decls.append(_Decl(ep.name, vm.group(1), vm.group(2), Origin(ENTRY_POINT, name, version), ep=ep))
    return decls


def _inside(path: str, base: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(base)]) == os.path.realpath(base)
    except ValueError:
        return False


def _shadows(pkg: str, base: str) -> bool:
    """True when importing `pkg` from `base` would replace or hide a module the process can already import."""
    if pkg in sys.stdlib_module_names or pkg == "leasewatch" or pkg in sys.modules:
        return True
    try:
        spec = importlib.util.find_spec(pkg)  # top level: finds, never executes
    except (ImportError, ValueError):
        return True
    if spec is None:
        return False
    where = ([spec.origin] if spec.origin else []) + list(spec.submodule_search_locations or [])
    return not where or not all(_inside(w, base) for w in where)


def _dir_decls(raw: str, res: LoadResult, other: dict[str, str]) -> list[_Decl]:
    root = os.path.abspath(raw)
    log.info("LW_CONNECTORS_DIR %s", root)
    if not os.path.isdir(root):
        res.problems.append(f"LW_CONNECTORS_DIR {root} is not a directory")
        return []
    try:
        entries = sorted(os.listdir(root))
    except OSError as e:
        res.problems.append(f"LW_CONNECTORS_DIR {root} cannot be read ({type(e).__name__})")
        return []
    decls: list[_Decl] = []
    for entry in entries:
        base = os.path.join(root, entry)
        pyproject = os.path.join(base, "pyproject.toml")
        # packages only: a loose .py file (or a hidden or "_" entry) is never run
        if entry.startswith((".", "_")) or not os.path.isdir(base) or not os.path.isfile(pyproject):
            continue
        bad = f"LW_CONNECTORS_DIR {entry}: pyproject.toml cannot be read"
        try:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            res.problems.append(f"{bad} ({type(e).__name__})")
            continue
        project = data.get("project")
        project = project if isinstance(project, dict) else {}
        groups = project.get("entry-points", {})
        if not isinstance(groups, dict):
            res.problems.append(f"{bad} (project.entry-points is not a table)")
            continue
        dist, version = str(project.get("name") or entry), str(project.get("version") or "")
        origin = Origin(DIR, dist, version, root, entry)
        found: list[_Decl] = []
        for group, table in groups.items():
            m = _GROUP_RE.match(str(group))
            if not m:
                continue
            if not isinstance(table, dict):
                res.problems.append(f"{bad} ({group} is not a table)")
                continue
            for type_, value in table.items():
                if int(m.group(1)) != API_VERSION:
                    _other_api(f"LW_CONNECTORS_DIR {entry}", group, m.group(1), type_, other)
                    continue
                vm = _VALUE_RE.match(value) if isinstance(value, str) else None
                if not TYPE_RE.match(type_) or not vm:
                    res.problems.append(f"LW_CONNECTORS_DIR {entry}: entry point {type_!r} is not <type> = "
                                        "\"module:Class\" with a type of a-z, 0-9 and _")
                    continue
                found.append(_Decl(type_, vm.group(1), vm.group(2), origin, path=base))
        for pkg in sorted({d.module.split(".")[0] for d in found}):
            if _shadows(pkg, base):
                res.problems.append(f"LW_CONNECTORS_DIR {entry}: package {pkg} would shadow another module")
                for d in found:
                    if d.module.split(".")[0] == pkg:
                        res.broken[d.type] = f"package {pkg} would shadow another module (from {origin.label()})"
                found = [d for d in found if d.module.split(".")[0] != pkg]
        decls += found
    for p in res.problems:
        log.warning("%s", p)
    return decls


def _without_conflicts(decls: list[_Decl], res: LoadResult) -> list[_Decl]:
    """The declarations whose type no other origin declares; checked on names only, before any import."""
    by_type: dict[str, list[_Decl]] = {}
    for d in decls:
        by_type.setdefault(d.type, []).append(d)
    out = []
    for type_, ds in by_type.items():
        if type_ in res.types:
            # the built-in stays: a stray package must never take the firewall connector away
            for d in ds:
                log.error("%s declares type %s, which conflicts with the built-in type %s; give the connector another "
                          "type name", d.origin.label(), type_, type_)
        elif len(ds) > 1:
            times = "twice" if len(ds) == 2 else f"{len(ds)} times"
            res.broken[type_] = f"type {type_} is provided {times}: {' and '.join(d.origin.label() for d in ds)}; remove one"
            log.warning("connector %s", res.broken[type_])
        else:
            out.append(ds[0])
    return out


def _class_problem(type_: str, obj: object) -> tuple[str, ConnectorInfo | None]:
    try:
        ok = isinstance(obj, type) and issubclass(obj, Connector)
    except TypeError:
        ok = False
    if not ok:
        return "not a connector class", None
    try:
        info = obj.describe()
    except (Exception, SystemExit) as e:
        return f"describe() failed ({type(e).__name__})", None
    if not isinstance(info, ConnectorInfo):
        return "describe() does not return a ConnectorInfo", None
    if info.type != type_:
        return f"describe() names type {info.type!r}, not {type_!r}", None
    if info.api_version != API_VERSION:
        return f"written for connector API {info.api_version}, this host has {API_VERSION}", None
    return "", info


def _import_dir(d: _Decl, packages: dict[str, str]) -> object:
    pkg = d.module.split(".")[0]
    if pkg not in packages:
        spec = importlib.machinery.PathFinder.find_spec(pkg, [d.path])  # the dist dir only: never cwd or sys.path
        if spec is None or spec.loader is None:
            raise _Refused(f"package {pkg} not found")
        module = importlib.util.module_from_spec(spec)
        # registered before it runs, so the package's own absolute and relative imports find it (the import system
        # does the same); a failure removes it again below
        sys.modules[pkg] = module
        packages[pkg] = d.path
        try:
            spec.loader.exec_module(module)
        except BaseException:
            packages[pkg] = ""  # a second type from the same package must not use it half-initialised
            raise
    elif not packages[pkg]:
        raise _Refused(f"package {pkg} failed to import")
    elif packages[pkg] != d.path:
        raise _Refused(f"package {pkg} is already loaded from another LW_CONNECTORS_DIR entry")
    obj: object = importlib.import_module(d.module)
    for part in d.attr.split("."):
        obj = getattr(obj, part)
    return obj


def _import_all(decls: list[_Decl], res: LoadResult) -> None:
    packages: dict[str, str] = {}  # dir package -> the dist dir it was imported from in this load
    used: set[str] = set()
    for d in decls:
        err: BaseException | None = None
        try:
            obj = d.ep.load() if d.ep is not None else _import_dir(d, packages)
            why, info = _class_problem(d.type, obj)
        except _Refused as e:
            why = str(e)
        except (Exception, SystemExit) as e:  # a plugin's import must never stop the host; Ctrl-C still does
            why, err = f"{type(e).__name__} in {d.module}", e
        if why:
            res.broken[d.type] = f"{why} (from {d.origin.label()})"
            # the traceback is the plugin's import code; no instance setting has been read at this point
            log.warning("connector type %s cannot be loaded: %s", d.type, res.broken[d.type], exc_info=err)
            continue
        res.types[d.type] = obj
        res.origins[d.type] = replace(d.origin, type_version=info.version)
        if d.ep is None:
            used.add(d.module.split(".")[0])
    for pkg in packages:
        names = [n for n in sys.modules if n == pkg or n.startswith(pkg + ".")]
        if pkg in used:
            res.modules += names
        else:  # nothing registered from it: no half-imported package stays behind
            for n in names:
                del sys.modules[n]
