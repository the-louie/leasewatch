# contrib: connectors outside the core

`contrib/` holds connectors that are not built into leasewatch. Each one reads a source the core does not ship
(for example a dnsmasq leases file or a RouterOS REST API) and speaks the same connector contract as the built-in
connectors in `leasewatch/connectors/` (connector API version 1).

How to write, package, install and test a connector: [docs/connectors.md](../docs/connectors.md).

The leasewatch image does not contain `contrib/`, and nothing under `leasewatch/` imports from it. A test
(`tests/test_contrib_layout.py`) checks this.

## Layout

Each subdirectory is an independent package with its own distribution name:

```
contrib/<dist-name>/
    pyproject.toml        # metadata, plus the connector entry point
    <package>/            # the connector code, e.g. leasewatch_dnsmasq/
        __init__.py
    README.md             # what it reads, its settings, an example LW_CONNECTOR__<NAME>__<KEY> block
    tests/                # unittest files (test_*.py); synthetic data only, no network
```

`pyproject.toml` declares the connector type as an entry point; leasewatch's loader reads it both from an
installed distribution and from `LW_CONNECTORS_DIR`:

```toml
[project.entry-points."leasewatch.connectors.v1"]
<type> = "<package>.connector:<ClassName>"
```

## Using a package

In the container, copy the package directory into a directory on the host, mount that read-only and point
`LW_CONNECTORS_DIR` at it (one subdirectory per package, as here):

```
mkdir -p connectors && cp -r contrib/leasewatch-dnsmasq connectors/
docker run ... -v ./connectors:/connectors:ro -e LW_CONNECTORS_DIR=/connectors leasewatch:local
```

`docker-compose.yml` has the same two lines, commented out. Outside a container, `pip install contrib/<dist-name>`
installs it as a distribution instead (the build needs `setuptools`). Use one way per package: a type declared
twice is refused.

## What a connector may import from leasewatch

Only these names, and only as `from leasewatch.connectors import ...`:

<!-- public-names: begin -->
- `API_VERSION`
- `ConnectorInfo`
- `Setting`
- `Sighting`
- `Attachment`
- `Batch`
- `ConnectorError`
- `HostContext`
- `SettingsMixin`
- `build_opener`
- `make_redactor`
- `url_problems`
- `parse_bool`
- `Connector`
- `make_host_mask`
<!-- public-names: end -->

A package's own tests may also import, only as `from leasewatch.connectors.testing import ...`:

<!-- testing-names: begin -->
- `ConnectorContractTests`
<!-- testing-names: end -->

`ConnectorContractTests` is a mixin with the connector contract as tests (describe(), no I/O in `__init__` or
`validate()`, required settings, secrets kept out of the repr and of error texts, the Batch shape, `close()`). Mix
it into a `unittest.TestCase` and fill in its hooks; its module docstring lists them.

Every other name in `leasewatch` (other modules, `leasewatch.connectors` helpers not listed above, names that
start with `_`) is private and can change in any release. `import leasewatch...` as a module is not allowed
either. `tests/test_contrib_layout.py` checks every `.py` file under `contrib/` against this list.

A connector must also follow the rules of the built-in ones: Python stdlib only, no I/O in `__init__` or
`validate()`, every error from the source wrapped in `ConnectorError`, and no secrets in logs or error texts
(use `make_redactor`).

## Running a contrib package's tests

From the package directory, with the repository root on the import path:

```
cd contrib/<dist-name>
PYTHONPATH=../.. python3 -W error::ResourceWarning -m unittest discover -s tests
```

The core test run (`python3 -m unittest discover -s tests` from the repository root) also runs each package's
`tests/` directory, in a separate process per package.
