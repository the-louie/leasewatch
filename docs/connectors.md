# Writing a connector

This page tells you how to write a connector for leasewatch's connector API version 1 (`API_VERSION = 1`, host
1.2 and later). A connector reads one kind of source (a DHCP server, a router, a switch, a Wi-Fi controller) and
hands leasewatch plain records. Everything here is taken from the code: the contract and its docstrings are in
`leasewatch/connectors/__init__.py`, loading in `leasewatch/connectors/loader.py`, the reusable tests in
`leasewatch/connectors/testing.py` and the merge rules in `leasewatch/connectors/merge.py`.

Two complete connectors serve as worked examples:

- [contrib/leasewatch-dnsmasq](../contrib/leasewatch-dnsmasq/): reads a local file, `dhcp` sightings only.
- [contrib/leasewatch-mikrotik](../contrib/leasewatch-mikrotik/): talks HTTPS to a device with a password,
  `dhcp` and `arp` sightings, host masking and secret redaction.

Contents: [1 What a connector is](#1-what-a-connector-is) ·
[2 Records](#2-records) · [3 Settings](#3-settings) · [4 Errors and secrets](#4-errors-and-secrets) ·
[5 The public surface](#5-the-public-surface) · [6 Packaging](#6-packaging) · [7 Installing](#7-installing) ·
[8 Loading rules](#8-loading-rules) · [9 Versioning](#9-versioning) · [10 Testing](#10-testing) ·
[11 A minimal complete example](#11-a-minimal-complete-example) ·
[12 README template](#12-readme-template-for-a-connector-package)

## 1. What a connector is

A *connector type* is a class (for example `dnsmasq_leases`). A *connector instance* is one configured copy of it,
named in `LW_CONNECTORS` and configured with `LW_CONNECTOR__<NAME>__<KEY>` variables. The connector reads its
source and returns records; it never writes to the database or to the device it reads from.

The class does not need to inherit from anything: the host checks it against the `Connector` protocol (it must
have `describe`, `__init__`, `validate`, `check`, `collect` and `close`). Inheriting `SettingsMixin` gives you
`describe()`, the settings lookup, the generic checks and a repr that hides secrets.

### Lifecycle

```
describe()  ->  __init__(name, settings, ctx)  ->  validate()  ->  check()  ->  collect() once per poll  ->  close()
```

| Step | Who calls it, when | Rules |
|---|---|---|
| `describe()` | Class method. The loader calls it once at load; the host calls it again to read settings and roles. | Returns a `ConnectorInfo`. No I/O. |
| `__init__(name, settings, ctx)` | At start, once per instance. `settings` holds the instance's keys in lower case, as strings, without the host keys `TYPE` and `TIMEOUT`. | No I/O. Do not raise for a bad value: report it from `validate()`. If it raises anyway, the instance gets `cannot be set up (<ExceptionType>)` and is not used. |
| `validate()` | At start, right after `__init__`. | No I/O. Returns a list of problem strings; an empty list means the settings are fine. |
| `check()` | Once before the first `collect()`. | One cheap probe of the source (open the file, one request). Returns `None` or raises `ConnectorError`. |
| `collect()` | Once per poll. | Returns a `Batch`, or raises `ConnectorError`. |
| `close()` | By the `check` and `collect` commands and by the contract tests. The running server does not call it today; the instance lives until the process ends. | Never raises. May be called twice. Do not keep a connection open across polls in a way that needs `close()` to clean up. |

How the host runs it (`leasewatch/collector.py`):

- **Threads and `TIMEOUT`.** Each instance collects in its own thread. The host waits `TIMEOUT` seconds (a host key,
  default 60, 1–3600) for `check()` + `collect()`. A thread still running at the deadline is abandoned: its result
  is dropped, the instance shows `timed out after N s`, and it is skipped (`previous collection has not completed;
  skipped`) until the thread ends. The value is in `ctx.timeout`; use it to cap your own I/O (for example
  `min(ctx.timeout, 30)` as a socket timeout) so that your thread ends.
- **Order.** Instances whose `produces` has `"sighting"` run first, in parallel. Then all other instances run, in
  parallel. The poll fails only when every sighting producer failed.
- **Check backoff.** If `check()` fails or hangs, it is tried again after `POLL_SECONDS`, then after double that time,
  and so on up to 600 s. After that wait, the host stops calling `check()` and calls `collect()` every poll. Once
  `check()` has passed, a failing `collect()` does not run `check()` again. Exception: while the first baseline is
  held back, a sighting producer that has not yet answered is retried every `POLL_SECONDS`, without the backoff, so a
  source that comes up late does not delay the baseline by minutes. Once the baseline is taken, the backoff applies.
- **Log on change.** A failure is logged once when the instance goes from ok to failed (WARNING for a
  `ConnectorError` or a timeout; ERROR with a redacted traceback for any other exception), and once more when it
  recovers. Do not log every failed poll yourself.
- **A failed instance claims nothing.** Its devices keep their last values. Devices it held do not go offline
  because of the failure.

### Imports

Use the Python 3.12 standard library where you can. If you need a third-party library, import it inside `check()`
or `collect()`, never at module level, so that the type still loads (and `check` can say what is missing) when the
library is absent. The built-in `snmp_switch` does this with `pysnmp`.

## 2. Records

`collect()` returns a `Batch` of two kinds of record. Both are frozen dataclasses.

### Sighting: who a device is

One device as one source saw it (an IP, a hostname, a network).

| Field | Type | Meaning |
|---|---|---|
| `mac` | `str` | As the source gives it. The host normalises it to `aa:bb:cc:dd:ee:ff` and drops the record if it is not a MAC. |
| `source` | `str` | Leave it `""`. The host sets it to the instance name. |
| `kind` | `str` | What the evidence is: `"dhcp"`, `"arp"`, `"client"` or `"scan"`. See the ranking below. |
| `presence` | `bool` | `True` only if the source saw the device on the wire **now** (an ARP entry, a lease the DHCP server marks online, an active controller client). A lease or a reservation alone is `False`. |
| `observed_at` | `int` | Epoch seconds when you collected it (use `ctx.now()`). Informational in API 1; the merge does not rank by it. |
| `ip` | `str` | IPv4 address, or `""`. |
| `hostname` | `str` | Or `""`. |
| `vendor` | `str` | Or `""`. |
| `network` | `str` | Human interface name (`LAN`, `IOT`); shown as the device's network (the `vlan` column). |
| `iface` | `str` | Source-specific interface id (`opt3`). |
| `lease_type` | `str` | `"static"`, `"dynamic"` or `""`. Only kind `"dhcp"` sets it. |
| `client_id` | `str` | DHCP client-id or DUID if known. Reserved; not used yet. |

### Attachment: where a device hangs

A switch port, a Wi-Fi AP, or a port behind a controller-managed switch.

| Field | Type | Meaning |
|---|---|---|
| `mac`, `source`, `observed_at` | | As for `Sighting`. A walk may stamp all its rows with one time. |
| `link` | `str` | Exactly `"wired"` or `"wifi"`. Any other value is ignored (logged once). |
| `device` | `str` | The switch or AP name as the operator knows it. |
| `port` | `str` | Short port label (`GE1/0/14`); `""` for Wi-Fi. |
| `uplink` | `bool` | The port leads to more infrastructure, so the device is not really there. |
| `via` | `str` | What sits behind that port (an LLDP neighbour, `7 devices`). |
| `vlan` | `int \| None` | VLAN id, if known. |
| `ssid`, `ap`, `signal`, `alias` | | Wi-Fi details: SSID, AP name, signal in dBm (`int \| None`), the name set in the controller. |
| `radio` | `str` | Free text, shown as given (`"2.4 GHz"`, `"5 GHz"`, `"6 GHz"` suggested). |
| `present` | `bool` | The source vouches that the device is connected now (a controller's active client). It feeds the per-source "on the wire" line on the device page (`seen.last_present`), **never** *Online*. An FDB entry is not present (it ages out more slowly than the device leaves). |

### Batch

```python
Batch(sightings=[...], attachments=[...], stats={"leases": 12, "dropped": 0})
```

`stats` holds raw counts for the status. All keys are optional; a missing key reads as 0. Values are ints, except
the documented string key `"strategy"`.

| Key | Who sets it | What the host does with it |
|---|---|---|
| `leases`, `arp`, `reservations` | sighting producers | Summed over all producers and shown as the last poll's raw counts. |
| `macs` | switch | Accepted and not shown (the 1.0 status alias was removed in 1.2). |
| `clients` | controller | Accepted and not shown (the 1.0 status alias was removed in 1.2). |
| `strategy` (`str`) | switch | Copied to the instance's status (`conn.<name>.strategy`). |
| `dropped` | you and the host | Records you skipped as unusable. The host adds the records it dropped itself. **A batch with `dropped > 0` is not a complete list**: for a controller, and for the switch that holds a device, it counts as failed in the merge (see below). |

The status count of an instance is always `len(sightings) + len(attachments)`, whatever `stats` says.

### What the host does with a batch

Before anything reads it, the host runs `merge.normalise_batch(name, batch)`. It never raises, and it:

- sets `source` to the instance name;
- normalises `mac` and drops a record whose MAC fails (also a record of the wrong type, a MAC that is not a `str`,
  or a field that cannot be converted). It counts them in `stats["dropped"]` and logs one WARNING per instance per
  process;
- coerces fields of the wrong type: a `str` field `None` becomes `""`, other values `str()`; control and bidi
  characters are removed, tab and line breaks become spaces, and the text is stripped (except `ssid`, `ap`,
  `alias`); `kind` is lower-cased; flags given as text are read with the setting words (`"false"` is `False`);
  `observed_at` becomes an int or 0; `vlan`/`signal` an int in 64-bit range or `None`.

Return correct types anyway: the contract tests check them.

### How records are merged (what you must know)

The full rules are in the docstring of `leasewatch/connectors/merge.py`. The parts that affect a connector:

- **Only sightings create devices.** An attachment for a MAC that no sighting has ever listed does nothing.
- **Online.** A device is online when any sighting has `presence=True` this poll, of any kind. Only that moves
  `last_online`. After it is no longer seen, it stays online for `ONLINE_GRACE_MINUTES`.
- **Ranking by `kind`.** A kind not in a list ranks after all listed ones (the contract tests allow only the four).

  | Field | Order |
  |---|---|
  | `ip`, `network`, `iface` | Taken together from one sighting: the `dhcp` lease whose IP is in an `arp` sighting, shown where ARP saw it; else the first `arp`, else the lease if it has an IP. Only without any `arp` sighting and lease with an IP: a sighting with an IP first, then `client`, then `scan`. |
  | `hostname` | the lease's hostname, then the first non-empty in `dhcp`, `client`, `arp`, `scan` |
  | `vendor` | first non-empty in `dhcp`, `arp`, `client`, `scan` |
  | `lease_type` | the chosen `dhcp` lease only |

  "First" follows fixed sort keys (empty IP last, network, IP, static before dynamic, …), so the order in which you
  return rows never changes the result.
- **Which kind to use.** A DHCP lease or reservation: `dhcp`, `presence=False` unless the server says the client
  is online. An ARP/neighbour table entry: `arp`, `presence=True`. A device a controller or access point reports as
  connected: `client`. A result of an active scan: `scan`.
- **Switch ports** (`link="wired"` from an instance without the controller role): each instance's first wired
  attachment for a MAC is its candidate. An edge (non-uplink) port beats an uplink port; then the instance that
  already holds the device; then the order in `LW_CONNECTORS`. A port with an empty label ranks last. A port is
  only taken while the device is on the wire this poll. If the switch that holds a device fails (or its batch has
  `dropped > 0`), the device keeps its port.
- **The `controller` role** (`ConnectorInfo.roles = frozenset({"controller"})`). Set it only if your attachments are
  a Wi-Fi controller's **complete** client list. Then `"wifi"` puts a device on Wi-Fi (this beats any switch port),
  and `"wired"` means the controller sees it on a cable, so its Wi-Fi details are cleared. A device missing from an
  answered list has left Wi-Fi. While a controller has failed (or its batch has `dropped > 0`), its Wi-Fi devices are
  "blind" and keep their last values. A `"wifi"` attachment from an instance **without** the role is ignored.

## 3. Settings

Declare every key your type accepts in `ConnectorInfo.settings` as a `Setting`:

| Field | Default | Meaning |
|---|---|---|
| `key` | | Lower case; the operator writes it upper-cased in the variable. Must not be `type` or `timeout` (host keys). |
| `required` | `False` | An empty or missing value is reported as `<KEY> is required`. |
| `default` | `""` | A string, used when the key is absent. |
| `secret` | `False` | Never logged, shown in status or repr; accepts `<KEY>_FILE`. |
| `choices` | `()` | Allowed values; anything else is `<KEY> must be one of a, b`. An explicitly empty value is refused too when the setting has a default. |
| `help` | `""` | One line for your README. |
| `kind` | `"str"` | `"int"`: the value must be an integer within `min`..`max` (either bound optional). |
| `min`, `max` | `None` | Bounds for `kind="int"`. |

The operator sets them as `LW_CONNECTOR__<NAME>__<KEY>`, with the instance name and the key in upper case. Your
`__init__` gets them in lower case and always as strings. `SettingsMixin._init_settings()` fills in the defaults.

- **Host keys.** `TYPE` (required, your type name) and `TIMEOUT` (seconds, default 60, 1–3600) are read by the host.
  Your connector never sees them in `settings`; the timeout is in `ctx.timeout`.
- **Secrets.** With `secret=True`, the operator may set `<KEY>_FILE` instead of `<KEY>` (for example a Docker
  secret). The host reads the file (at most 64 KiB, stripped, a UTF-8 BOM ignored) and passes the value as `<KEY>`.
  Setting both is an error. The value is masked in the host's log and status lines (all instances' secrets are in
  `ctx.redact`) and in the `SettingsMixin` repr. The repr also hides any key that ends in `_file` or contains `key`,
  `secret`, `pass`, `token`, `community` or `credential`.
- **Generic checks.** `self._generic_problems()` (from `SettingsMixin`) runs the required, choices and int-range
  checks and never echoes a value. Call it from `validate()` and add your own checks.
- **Unknown keys.** A `LW_CONNECTOR__<NAME>__<KEY>` that is not in your settings is reported as
  `unknown setting <KEY>`.
- **Problem texts.** Return plain texts such as `"path must be an absolute path"`. The host adds
  `connector <name> (<type>): ` in front (unless the text already starts with `connector `) and drops duplicates of
  the generic checks. Any problem stops the server at start (exit 2, one `config:` line each); `check` shows the
  instance as `disabled: …`.
- **Helpers.** `parse_bool(value)` reads `1/0`, `true/false`, `yes/no`, `on/off` (case-insensitive) and returns
  `None` for anything else. `url_problems(key, url, hint)` checks a URL setting: an `http://` or `https://` scheme,
  a host, a valid port, no spaces or control characters, and no credentials in it.

`TYPE` names the type: it must be a type that is loaded. `python -m leasewatch check` prints them on its first line,
and an unknown type is reported with the list of loaded types (built-in and third-party).

## 4. Errors and secrets

- Raise only `ConnectorError` from `check()` and `collect()`. Its text is shown in the UI, the status API and the
  log (redacted and cut to 200 characters). Any other exception is shown as its type name only (its traceback goes
  to the log), so wrap every error from your source: `urllib`, `socket`, `ssl`, `json`, `OSError`.
- The text must never contain a secret, a URL, a host name or address, a credential, a file path, or a response body.
  Write what kind of problem it is: `PATH: not found`, `HTTP 401`, `response is not JSON`.
- `raise ConnectorError("...") from None` keeps the original exception (which may hold the URL or path) out of the
  traceback.
- Tools:
  - `make_redactor([secret, ...])` returns a function that replaces each secret with `***`, also in its `repr()` and
    JSON-escaped forms. Values shorter than 4 characters are not masked.
  - `ctx.redact` masks the secrets of **every** configured instance.
  - `make_host_mask(url_or_host)` returns a function that replaces whole occurrences of the host with `<host>`
    (lower case, without a trailing dot, the IDNA form, IPv6 compressed and exploded; `10.0.0.1` is not masked
    inside `10.0.0.15`). TLS and resolver errors echo the host, so mask before you raise.
  - The order the mikrotik connector uses: redact the secrets first, then mask the host, then cut the text (a secret
    that contains the host name would no longer match after masking; a cut can split a secret).
- HTTP: get an opener from `ctx.opener_factory(verify_tls=..., use_env_proxy=...)` (by default `build_opener`).
  It never follows redirects (a 3xx would resend credentials) and ignores `http(s)_proxy` unless asked. Tests
  replace the factory to reach a local fake server.
- Log with your own logger (for example `logging.getLogger("leasewatch.contrib.<name>")`) or `ctx.log`. Never log a
  secret, a URL with credentials, or a response body.

## 5. The public surface

A connector may import only these 15 names, and only as `from leasewatch.connectors import ...`:

| Name | What it is |
|---|---|
| `API_VERSION` | `1`. Put it in `ConnectorInfo.api_version`. |
| `ConnectorInfo` | What your type is: `type` (`[a-z0-9_]+`), `version` (your own), `api_version`, `produces` (`frozenset` of `"sighting"`/`"attachment"`), `settings`, `roles` (`frozenset()` or `{"controller"}`). |
| `Setting` | One setting key (section 3). |
| `Sighting`, `Attachment`, `Batch` | The records (section 2). |
| `ConnectorError` | The one exception to raise. |
| `HostContext` | What the host lends you: `log`, `now()` (epoch seconds), `norm_mac(text)`, `redact(text)`, `opener_factory(...)`, `device_names()` (MAC to the device's name or hostname, read-only; lets a switch name an uplink after the device behind it), `timeout` (the instance's `TIMEOUT`). |
| `SettingsMixin` | `_init_settings(name, settings, ctx)`, `describe()`, `_generic_problems()`, a repr without secrets. Set the class attribute `INFO`. |
| `build_opener` | The default HTTP(S) opener (section 4). |
| `make_redactor`, `make_host_mask` | Masking helpers (section 4). |
| `url_problems`, `parse_bool` | Setting helpers (section 3). |
| `Connector` | The protocol (for type hints; you do not need to inherit it). |

A package's own tests may also import `ConnectorContractTests` from `leasewatch.connectors.testing`.

Every other name in `leasewatch` is private and can change in any release: other modules, other names in
`leasewatch.connectors`, names that start with `_` (except the `SettingsMixin` methods above). The checked list is
the `public-names` block in [contrib/README.md](../contrib/README.md); `tests/test_contrib_layout.py` keeps it equal
to `leasewatch.connectors.__all__` and checks every file under `contrib/` against it.

## 6. Packaging

A connector is a Python distribution with an entry point in the group `leasewatch.connectors.v1`. The entry point
name is the type name; the value is `module:Class`.

```toml
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "leasewatch-<name>"
version = "0.1.0"
description = "leasewatch connector: <what it reads>"
readme = "README.md"
requires-python = ">=3.12"
dependencies = []

[tool.setuptools]
packages = ["leasewatch_<name>"]

[project.entry-points."leasewatch.connectors.v1"]
<type> = "leasewatch_<name>.connector:<ClassName>"
```

- `requires-python = ">=3.12"`, as leasewatch.
- Do not list `leasewatch` in `dependencies`: the leasewatch image copies the application and does not install it
  as a distribution, so pip cannot satisfy a `leasewatch>=1.2` requirement and the install fails. Write the minimum
  leasewatch version (1.2) in your README instead. The host refuses a package written for another connector API on
  its own (section 9).
- Prefer the standard library. Each dependency must also be installed into the leasewatch image.
- Give the top-level package a name no other module uses (`leasewatch_<name>`): a package in `LW_CONNECTORS_DIR`
  that would shadow another module is refused.
- Layout (the same as `contrib/<dist-name>/`):

  ```
  leasewatch-<name>/
      pyproject.toml
      README.md
      leasewatch_<name>/
          __init__.py
          connector.py
      tests/
          test_contract.py
          fixtures/
  ```

## 7. Installing

Use **one** of the two ways per package. A type declared twice is refused.

**(a) Install it into leasewatch's Python environment.** Outside a container: `pip install ./leasewatch-<name>`
(the build needs `setuptools`). For the container, build a derived image:

```dockerfile
FROM leasewatch:local
USER root
COPY leasewatch-<name>/ /tmp/leasewatch-<name>/
RUN pip install --no-cache-dir --root-user-action=ignore /tmp/leasewatch-<name> && rm -rf /tmp/leasewatch-<name>
USER app
```

**(b) `LW_CONNECTORS_DIR`.** A directory with one subdirectory per distribution, each with its `pyproject.toml`
(the entry point is read from there) and its package directory. Nothing is installed; no build step runs.

```
connectors/
    leasewatch-dnsmasq/
        pyproject.toml
        leasewatch_dnsmasq/...
    leasewatch-<name>/
        pyproject.toml
        leasewatch_<name>/...
```

```yaml
services:
  leasewatch:
    environment:
      LW_CONNECTORS_DIR: /connectors
    volumes:
      - ./connectors:/connectors:ro
```

- There is no default: without `LW_CONNECTORS_DIR` no directory is scanned. Mount it read-only, outside `/data`.
- Only packages are loaded. A loose `.py` file, and an entry whose name starts with `.` or `_`, are skipped.
- The package is imported from its own subdirectory only (not from the working directory or `sys.path`), so it can
  use only the standard library and what is installed in the image.
- The files must be readable by the container's user.
- **Trust.** A connector runs inside leasewatch with its full privileges. It sees the whole environment, including
  the secrets of other instances. Load only code you trust.

## 8. Loading rules

- **Origins**, read in this order: the built-in types (`opnsense`, `snmp_switch`, `unifi`), then installed
  distributions with an entry point in `leasewatch.connectors.v1`, then the packages in `LW_CONNECTORS_DIR`. The
  working directory is never scanned for entry points.
- **No precedence.** A type name declared twice (two packages, or one package installed both ways) is refused from
  every origin: `type <t> is provided twice: … ; remove one`. A package that declares a built-in type name is
  refused and the built-in stays. All names are compared before any plugin code runs.
- **All declared types are imported at load**, not only the ones `LW_CONNECTORS` uses.
- **A broken or incompatible plugin** (an import error, `describe()` fails or names another type, not a connector
  class, another `api_version`) is not registered. It is logged as a WARNING.
  - If no instance uses its type, the start goes on. `check` prints `plugin: <type> not loaded: <why>`.
  - If an instance uses it, the start stops:
    `connector dhcp1 (dnsmasq_leases): cannot be loaded: <why>`.
- **Problems with `LW_CONNECTORS_DIR` itself always stop the start:** it is not a directory or cannot be read, a
  `pyproject.toml` cannot be parsed, an entry point is not `<type> = "module:Class"`, or a package would shadow
  another module.
- **The types line.** The start log and the first line of `python -m leasewatch check` list every loaded type and
  where it came from:

  ```
  connector types: opnsense, snmp_switch, unifi (built-in); ethers 0.1.0 (leasewatch-ethers 0.1.0, LW_CONNECTORS_DIR /connectors)
  ```

  An installed package shows `(<dist> <version>, entry point)` instead.

## 9. Versioning

- `API_VERSION` is an integer and is part of the entry point group (`leasewatch.connectors.v1`).
- **Compatibility is exact equality, checked twice:** the host reads only the group of its own version, and
  `describe().api_version` must equal `API_VERSION`. A package that declares a type in another group
  (`leasewatch.connectors.v2`) is not imported; it is logged, and an instance that uses the type is told
  `provided by <dist> for connector API 2; this host has 1`.
- **The promise for API 1:** inside API 1 the host only adds things:
  - new optional record fields, with defaults;
  - new optional connector methods (the host looks for them and works without them);
  - new `HostContext` members.

  Removing or renaming any of the 15 public names, a record field, a `HostContext` member, a lifecycle method or the
  meaning of a value (`kind`, `link`, `presence`, `present`, the `controller` role), or making something optional
  required, needs API 2 and the group `leasewatch.connectors.v2`. A connector written for API 1 then keeps loading
  on every 1.x host.
- **Deprecations** inside API 1 come with a `DeprecationWarning` and a log line for at least one minor release
  before the next API version drops the item.
- Your own `ConnectorInfo.version` is free text; it appears in the types line.

## 10. Testing

Mix `ConnectorContractTests` into a `unittest.TestCase` and fill in its hooks:

| Hook | Required | Meaning |
|---|---|---|
| `connector_class` | yes | The class under test (class attribute). |
| `valid_settings()` | yes | Settings that work against a fake (a fixture file, a local server on port 0). Never the network. |
| `failing_settings()` | no | Settings for which `check()` or `collect()` raises `ConnectorError` (a missing file, a wrong password). `None` (the default) skips that test. |
| `make_context()` | no | The `HostContext` to lend; default `HostContext()`. Set `now=` for fixed times, `opener_factory=` to send requests to a fake server. |
| `make_connector(settings)` | no | How an instance is built; default as the host builds it: `connector_class(instance_name, settings without TYPE and TIMEOUT, make_context())` with `ctx.timeout` set from `TIMEOUT`. |
| `instance_name` | no | Default `"contract"`. |

What it checks (all tests are named `test_contract_*`):

- `describe()`: the type matches `[a-z0-9_]+`, `api_version == API_VERSION`, `produces` is a non-empty subset of
  `{"sighting", "attachment"}`, `roles` a subset of `{"controller"}`, the setting keys are unique, match
  `[a-z0-9_]+` and are not host keys, every `kind` is `str` or `int`, and no key is `<secret key>_file`.
- `__init__` and `validate()` open no network connection, send no datagram and look up no name (also when your code
  catches the error the test raises). `valid_settings()` runs before that guard.
- `validate()` accepts the valid settings, and the host's own `instance_problems()` names every required key when it
  is missing.
- The repr shows no secret value, also not in its repr or JSON escaped form.
- `check()` returns `None`; `collect()` returns a `Batch` whose `sightings` and `attachments` are lists, with at
  least one record, only of the declared kinds, `kind` in `dhcp/arp/client/scan`, `link` in `wired/wifi`, a MAC
  that `norm_mac` accepts and an int (not bool) `observed_at > 0`.
- With `failing_settings()`: a `ConnectorError` whose text holds no secret value (escaped forms included) and no
  host of a URL setting, in any spelling `make_host_mask()` masks (whole occurrences only: `10.0.0.15` is not
  `10.0.0.1`). Give the fixture a host that is no word of your messages: a host `fw1` would match a `fw1` label.
- `close()` never raises, also twice and after `collect()` (a `check()` or `collect()` failure there is left to the
  check-and-collect test).

Also test your parser on its own: keep it a pure function (text in, records out), as `parse_leases()` in
leasewatch-dnsmasq and `parse()` in leasewatch-mikrotik. Use synthetic data only in fixtures: locally administered
MACs (`02:…`), `10.0.x.x` addresses, `example.lan` names. Tests must not reach the network; fake the source.

Run the tests from the package directory with leasewatch on the import path:

```
PYTHONPATH=/path/to/leasewatch python3 -W error::ResourceWarning -m unittest discover -s tests
```

### Debug loop: `check` and `collect`

Both commands read the same environment as the server, run the loader, never start the server and never open the
database.

- `python -m leasewatch check [instance ...]` prints the types line, any plugin that failed to load, the config
  problems, and one line per instance: `ok (<ms> ms)`, `disabled: <problems>` or `check failed: <error>`. Only
  `validate()` and `check()` run. Exit code 0 when all are ok, 1 when a check failed or timed out, 2 on a config or
  load problem or an unknown name.
- `python -m leasewatch collect <instance> [--json]` runs `validate()`, `check()` and `collect()` once and prints the
  batch after `normalise_batch` (as the host would merge it: `source` filled, MACs normalised, `dropped` counted).
  `--json` prints exactly one JSON object, also on failure. Exit code 0 on success, 1 when check or collect failed,
  2 on a config problem. Error and problem texts are redacted and the host of a `url`/`host` setting is masked.

Example output of the connector in section 11 (`observed_at` is the time of the run):

```
$ python -m leasewatch collect lan --json
{
  "instance": "lan",
  "type": "ethers",
  "ok": true,
  "phase": "collect",
  "error": "",
  "ms": 0,
  "problems": [],
  "stats": {
    "leases": 2,
    "dropped": 1
  },
  "sightings": [
    {
      "mac": "02:00:00:00:00:01",
      "source": "lan",
      "kind": "dhcp",
      "presence": false,
      "observed_at": 1800000000,
      "ip": "10.0.0.10",
      "hostname": "printer",
      "vendor": "",
      "network": "LAN",
      "iface": "",
      "lease_type": "static",
      "client_id": ""
    },
    {
      "mac": "02:00:00:00:00:02",
      "source": "lan",
      "kind": "dhcp",
      "presence": false,
      "observed_at": 1800000000,
      "ip": "10.0.0.11",
      "hostname": "",
      "vendor": "",
      "network": "LAN",
      "iface": "",
      "lease_type": "static",
      "client_id": ""
    }
  ],
  "attachments": []
}
```

Without `--json`:

```
lan (ethers): 2 sightings, 0 attachments, 0 ms
stats: dropped=1 leases=2
sighting mac=02:00:00:00:00:01 source=lan kind=dhcp presence=False observed_at=1800000000 ip=10.0.0.10 hostname=printer network=LAN lease_type=static
sighting mac=02:00:00:00:00:02 source=lan kind=dhcp presence=False observed_at=1800000000 ip=10.0.0.11 network=LAN lease_type=static
```

A failure:

```
lan (ethers): check failed: PATH: No such file or directory
```

## 11. A minimal complete example

A connector of type `ethers` that reads a file of `<mac> <ipv4> [hostname]` lines (static mappings) and reports one
`dhcp` sighting per line. It has two settings, does no I/O in `__init__`/`validate()`, wraps every error and keeps
the path out of error texts.

`leasewatch-ethers/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "leasewatch-ethers"
version = "0.1.0"
description = "leasewatch connector: static MAC to IP mappings from an ethers-style file"
requires-python = ">=3.12"
dependencies = []

[tool.setuptools]
packages = ["leasewatch_ethers"]

[project.entry-points."leasewatch.connectors.v1"]
ethers = "leasewatch_ethers.connector:EthersConnector"
```

`leasewatch-ethers/leasewatch_ethers/__init__.py`:

```python
"""leasewatch connector for an ethers-style file (type "ethers")."""
```

`leasewatch-ethers/leasewatch_ethers/connector.py`:

```python
"""An ethers-style file as a connector: one "dhcp" sighting per line `<mac> <ipv4> [hostname]`."""
from __future__ import annotations

import ipaddress
import os
from typing import Mapping

from leasewatch.connectors import (API_VERSION, Batch, ConnectorError, ConnectorInfo, HostContext, Setting,
                                   SettingsMixin, Sighting)

MAX_BYTES = 1024 * 1024


def parse(text: str, now: int, network: str) -> tuple[list[Sighting], int]:
    """The sightings in the file and how many lines were dropped. Pure: no I/O, never raises."""
    out, dropped = [], 0
    for line in text.splitlines():
        tok = line.split("#", 1)[0].split()
        if not tok:
            continue
        try:
            mac, ip = tok[0], str(ipaddress.IPv4Address(tok[1]))
        except (IndexError, ValueError):
            dropped += 1
            continue
        out.append(Sighting(mac=mac, source="", kind="dhcp", presence=False, observed_at=now, ip=ip,
                            hostname=tok[2] if len(tok) > 2 else "", network=network, lease_type="static"))
    return out, dropped


class EthersConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="ethers", version="0.1.0", api_version=API_VERSION, produces=frozenset({"sighting"}),
        settings=(
            Setting("path", required=True, help="absolute path of the file"),
            Setting("network", help="network name shown for these devices (e.g. LAN)"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None) -> None:
        self._init_settings(name, settings, ctx)  # no I/O here

    def validate(self) -> list[str]:
        problems = self._generic_problems()
        if self.settings["path"] and not os.path.isabs(self.settings["path"]):
            problems.append("path must be an absolute path")
        return problems

    def _read(self) -> str:
        try:
            with open(self.settings["path"], "rb") as f:
                raw = f.read(MAX_BYTES + 1)
        except OSError as e:
            # the reason only: an OSError's text holds the path
            raise ConnectorError(f"PATH: {e.strerror or type(e).__name__}") from None
        if len(raw) > MAX_BYTES:
            raise ConnectorError("PATH: file too large")
        return raw.decode("utf-8", errors="replace")

    def check(self) -> None:
        self._read()

    def collect(self) -> Batch:
        sightings, dropped = parse(self._read(), self.ctx.now(), self.settings["network"])
        return Batch(sightings=sightings, stats={"leases": len(sightings), "dropped": dropped})

    def close(self) -> None:
        pass  # nothing is kept open
```

`leasewatch-ethers/tests/fixtures/ethers`:

```
# synthetic data only
02:00:00:00:00:01 10.0.0.10 printer
02:00:00:00:00:02 10.0.0.11
not-a-line
```

`leasewatch-ethers/tests/test_contract.py`:

```python
"""The connector contract applied to the ethers connector, against a fixture file."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import HostContext  # noqa: E402
from leasewatch.connectors.testing import ConnectorContractTests  # noqa: E402
from leasewatch_ethers.connector import EthersConnector  # noqa: E402


class EthersContract(ConnectorContractTests, unittest.TestCase):
    connector_class = EthersConnector

    def valid_settings(self) -> dict[str, str]:
        return {"path": os.path.join(HERE, "fixtures", "ethers"), "network": "LAN"}

    def failing_settings(self) -> dict[str, str]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return {"path": os.path.join(tmp.name, "missing")}

    def make_context(self) -> HostContext:
        return HostContext(now=lambda: 1_800_000_000)


if __name__ == "__main__":
    unittest.main()
```

Try it:

```
cd leasewatch-ethers
PYTHONPATH=/path/to/leasewatch python3 -W error::ResourceWarning -m unittest discover -s tests

mkdir -p /srv/connectors && cp -r leasewatch-ethers /srv/connectors/
export LW_CONNECTORS_DIR=/srv/connectors LW_CONNECTORS=lan
export LW_CONNECTOR__LAN__TYPE=ethers LW_CONNECTOR__LAN__PATH=/srv/connectors/leasewatch-ethers/tests/fixtures/ethers
export LW_CONNECTOR__LAN__NETWORK=LAN
python -m leasewatch check
python -m leasewatch collect lan --json
```

Here `check` prints the types line (with `ethers 0.1.0 (leasewatch-ethers 0.1.0, LW_CONNECTORS_DIR /srv/connectors)`)
and `lan (ethers): ok (0 ms)`; `collect` prints the output shown in section 10. The 7 contract tests pass.

## 12. README template for a connector package

Each package has a `README.md` with these parts (see the two contrib READMEs):

````markdown
# leasewatch-<name>

A leasewatch connector (type `<type>`, connector API 1, leasewatch 1.2 or later) that reads <what> from <source>.
It only reads; it never changes the source.

## Settings

| Key | Required | Default | Meaning |
|---|---|---|---|
| `PATH` | yes | | ... |
| `PASSWORD` | yes | | Secret; `PASSWORD_FILE` also works |

`TYPE` and `TIMEOUT` are host keys, as for every connector.

```
LW_CONNECTORS=fw1,dhcp1
LW_CONNECTOR__DHCP1__TYPE=<type>
LW_CONNECTOR__DHCP1__PATH=/leases/example.leases
```

## What it sees

- Which records (`dhcp`/`arp`/`client`/`scan` sightings, `wired`/`wifi` attachments) and which fields are filled.
- Whether it sets presence (can it make a device *Online*?) and the lease type.
- What is skipped, and what is counted as `dropped`.

## Example output

The `python -m leasewatch collect <instance>` output for a small synthetic source.

## Limits

What it cannot see, versions tested, known edge cases, and the error texts it shows.

## Installing

`LW_CONNECTORS_DIR` (copy this directory, mount read-only) or `pip install` (one of the two).

## Tests

```
PYTHONPATH=/path/to/leasewatch python3 -W error::ResourceWarning -m unittest discover -s tests
```
````
