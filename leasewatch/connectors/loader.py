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

from . import API_VERSION, Connector, ConnectorInfo, Setting

log = logging.getLogger("leasewatch.connectors.loader")

GROUP = f"leasewatch.connectors.v{API_VERSION}"
# \Z, not $: "$" also matches before a trailing newline, and such a name would reach the log lines
TYPE_RE = re.compile(r"\A[a-z0-9_]+\Z")
# ASCII digits without a leading zero and at most 9 of them: "v01" or "v\u0661" is not API 1, and int() of a
# 5000-digit number raises; a group that does not match is simply not a leasewatch group
_GROUP_RE = re.compile(r"\Aleasewatch\.connectors\.v([1-9][0-9]{0,8})\Z", re.ASCII)
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_VALUE_RE = re.compile(rf"\A({_IDENT}(?:\.{_IDENT})*):({_IDENT}(?:\.{_IDENT})*)\Z")

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
    # set when a rule refuses it before import: it still counts as a declaration in the duplicate check
    refused: str = ""


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
    packages: dict[str, tuple[str, bool]] = {}  # dir package -> (dist dir, imported) in this load
    try:
        decls = _entry_point_decls(sys.path if path is None else path, other)
        raw = (environ.get("LW_CONNECTORS_DIR") or "").strip()
        if raw:
            decls += _dir_decls(raw, res, other)
        _import_all(_unshadowed(_without_conflicts(decls, res), res), res, packages)
    except BaseException as e:
        # what was registered or imported before the failure must not stay: the log promises built-ins only, and a
        # dir package left in sys.modules would be refused as a shadow by every later load
        _drop(packages)
        for t in [t for t in res.types if t not in res.origins or res.origins[t].kind != BUILTIN]:
            res.types.pop(t)
            res.origins.pop(t, None)
        res.modules = []
        if not isinstance(e, Exception):  # Ctrl-C still stops the host
            raise
        # a loader bug must not take the built-ins (and the firewall connector) with it
        log.error("connector loading failed, only the built-in types are available", exc_info=True)
        res.problems.append(f"connector loading failed ({type(e).__name__})")
    for type_, why in other.items():
        if type_ not in res.types and type_ not in res.broken:
            res.broken[type_] = why
    return res


def unload(result: LoadResult) -> None:
    """Drop the modules a previous load imported from LW_CONNECTORS_DIR, so the next load imports them afresh."""
    # by package, not by the list: a submodule the plugin imported after the load (e.g. in collect()) goes too
    _drop({n.split(".")[0] for n in result.modules})


def _drop(packages) -> None:
    """Remove every sys.modules entry of these dir packages (process global: only the dir plugins' own entries)."""
    for name in [n for n in sys.modules if n.split(".")[0] in packages]:
        del sys.modules[name]


def _scan_path(path: list) -> list[str]:
    # `python -m` puts the working directory first on sys.path ("" for -c): it must never supply plugins
    try:
        cwd = os.path.realpath(os.getcwd())
    except OSError:
        cwd = ""
    return [p for p in path if isinstance(p, str) and p and os.path.realpath(p) != cwd]


def _other_api(dist: str, group: str, api: str, type_: str, other: dict[str, str]) -> None:
    # %r: the name is not checked against TYPE_RE here, and a newline in it would forge a log line
    log.warning("%s declares connector type %r for connector API %s (group %s); this host has connector API %d, "
                "so it is not loaded", dist, type_, api, group, API_VERSION)
    if TYPE_RE.match(type_):  # no instance can use any other name
        other.setdefault(type_, f"provided by {dist} for connector API {api}; this host has {API_VERSION}")


def _entry_point_decls(path: list, other: dict[str, str]) -> list[_Decl]:
    decls: list[_Decl] = []
    seen: set[tuple[str, str, str, str]] = set()
    for dist in importlib.metadata.distributions(path=_scan_path(path)):
        name = "?"
        try:
            name = str(dist.metadata.get("Name") or "?")
            version = str(dist.version or "")
            eps = list(dist.entry_points)
        except Exception as e:  # broken metadata of some unrelated distribution
            log.warning("installed distribution %r: metadata cannot be read (%s)", name, type(e).__name__)
            continue
        for ep in eps:
            m = _GROUP_RE.match(ep.group)
            if not m:
                continue
            # the same distribution reached twice (a path listed twice, or one name spelled "lw_b" and "lw-b" by two
            # build backends) is one declaration; checked first, so the other-API warning is logged once too
            key = (re.sub(r"[-_.]+", "-", name).lower(), ep.group, ep.name, ep.value)
            if key in seen:
                continue
            seen.add(key)
            if m.group(1) != str(API_VERSION):
                _other_api(name, ep.group, m.group(1), ep.name, other)
                continue
            vm = _VALUE_RE.match(ep.value.replace(" ", ""))
            if not TYPE_RE.match(ep.name):
                log.warning("%s: entry point %r = %r is not <type> = module:Class with a type of a-z, 0-9 and _; "
                            "ignored", name, ep.name, ep.value)
                continue
            origin = Origin(ENTRY_POINT, name, version)
            if not vm:  # a valid name still claims the type: it must count in the duplicate check
                why = f"entry point value {ep.value!r} is not module:Class"
                decls.append(_Decl(ep.name, "", "", origin, refused=why))
                continue
            decls.append(_Decl(ep.name, vm.group(1), vm.group(2), origin, ep=ep))
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
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError, RecursionError) as e:  # deep nesting
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
        for group, table in groups.items():
            m = _GROUP_RE.match(str(group))
            if not m:
                continue
            if not isinstance(table, dict):
                res.problems.append(f"{bad} ({group} is not a table)")
                continue
            for type_, value in table.items():
                if m.group(1) != str(API_VERSION):
                    _other_api(f"LW_CONNECTORS_DIR {entry}", group, m.group(1), type_, other)
                    continue
                # spaces around ":" as the entry-point path (and pip) accept them: one declaration serves both
                vm = _VALUE_RE.match(value.replace(" ", "")) if isinstance(value, str) else None
                if not TYPE_RE.match(type_) or not vm:
                    res.problems.append(f"LW_CONNECTORS_DIR {entry}: entry point {type_!r} is not <type> = "
                                        "\"module:Class\" with a type of a-z, 0-9 and _")
                    continue
                decls.append(_Decl(type_, vm.group(1), vm.group(2), origin, path=base))
    for p in res.problems:
        log.warning("%s", p)
    return decls


def _unshadowed(decls: list[_Decl], res: LoadResult) -> list[_Decl]:
    """Refuses the dir declarations whose package would shadow another module. Run after the duplicate check: a type
    also declared elsewhere (e.g. the same package installed with pip and mounted) is refused as "provided twice",
    which says what to remove, and its declaration never reaches this check."""
    out = []
    shadows: dict[tuple[str, str], bool] = {}
    for d in decls:
        pkg = d.module.split(".")[0]
        if d.path and not d.refused:
            if (d.path, pkg) not in shadows:
                shadows[(d.path, pkg)] = _shadows(pkg, d.path)
                if shadows[(d.path, pkg)]:
                    res.problems.append(f"LW_CONNECTORS_DIR {d.origin.entry}: package {pkg} would shadow another "
                                        "module")
                    log.warning("%s", res.problems[-1])
            if shadows[(d.path, pkg)]:
                d = replace(d, refused=f"package {pkg} would shadow another module")
        out.append(d)
    return out


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
    # the host iterates these (secret keys, known settings, "sighting" check): a wrong shape would be a traceback in
    # Config() instead of this type-level problem
    if not isinstance(info.settings, (tuple, list)) or not all(isinstance(s, Setting) for s in info.settings):
        return "describe() settings is not a tuple of Setting", None
    for name in ("produces", "roles"):
        value = getattr(info, name)
        if not isinstance(value, (set, frozenset)) or not all(isinstance(v, str) for v in value):
            return f"describe() {name} is not a set of str", None
    return "", info


def _import_dir(d: _Decl, packages: dict[str, tuple[str, bool]]) -> object:
    pkg = d.module.split(".")[0]
    if pkg not in packages:
        spec = importlib.machinery.PathFinder.find_spec(pkg, [d.path])  # the dist dir only: never cwd or sys.path
        if spec is None:
            raise _Refused(f"package {pkg} not found")
        if spec.loader is None:  # a directory without __init__.py is found as a namespace package
            raise _Refused(f"package {pkg} has no __init__.py")
        module = importlib.util.module_from_spec(spec)
        # registered before it runs, so the package's own absolute and relative imports find it (the import system
        # does the same); a failure removes it again below
        sys.modules[pkg] = module
        packages[pkg] = (d.path, True)
        try:
            spec.loader.exec_module(module)
        except BaseException:
            # a second type from the same package must not use it half-initialised
            packages[pkg] = (d.path, False)
            raise
    # the path first: a clash between two entries is what the operator must fix, even when the first one failed
    elif packages[pkg][0] != d.path:
        raise _Refused(f"package {pkg} is already loaded from another LW_CONNECTORS_DIR entry" if packages[pkg][1] else
                       f"package {pkg} is also in another LW_CONNECTORS_DIR entry, where it failed to import")
    elif not packages[pkg][1]:
        raise _Refused(f"package {pkg} failed to import")
    obj: object = importlib.import_module(d.module)
    for part in d.attr.split("."):
        obj = getattr(obj, part)
    return obj


def _import_all(decls: list[_Decl], res: LoadResult, packages: dict[str, tuple[str, bool]]) -> None:
    """packages: filled with the dir packages imported in this load, so load() can drop them after a failure."""
    used: set[str] = set()
    for d in decls:
        err: BaseException | None = None
        try:
            if d.refused:
                raise _Refused(d.refused)
            obj = d.ep.load() if d.ep is not None else _import_dir(d, packages)
            why, info = _class_problem(d.type, obj)
        except _Refused as e:
            why = str(e)
        except KeyboardInterrupt:  # Ctrl-C still stops the host (load() drops what was imported)
            raise
        except BaseException as e:  # a plugin's import must never stop the host: SystemExit, CancelledError, ...
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
    res.modules += [n for n in sys.modules if n.split(".")[0] in used]
    _drop(set(packages) - used)  # nothing registered from it: no half-imported package stays behind
