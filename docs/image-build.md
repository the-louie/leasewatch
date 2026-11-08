# Image build: pinned base and hash-locked packages

Two builds of the same commit install the same bytes. The base image `python:3.12-alpine` is pinned by its index digest in the `Dockerfile`: a tag such as `3.12-alpine` moves when upstream rebuilds it, a digest does not. The index digest covers every platform, so the same line serves linux/amd64 and linux/arm64. The Python packages are installed from `requirements.lock` with `pip install --require-hashes`: every package, the dependencies included, has an exact version and the SHA-256 of each wheel the image may install. A wheel that was replaced on the index, or a version that was not locked, stops the build.

`requirements.txt` stays the source of the version ranges (`pysnmp>=7,<8`, `cryptography`); `pyproject.toml`'s `snmp` extra mirrors it. Only the image uses the lock.

The lock holds wheels only: `musllinux_1_2_x86_64` and `musllinux_1_2_aarch64` for the platform packages (cffi, cryptography), `py3-none-any` for the others. It holds no sdist hash, so a version without a musllinux wheel cannot be built from source by accident.

## Refresh

- Base image: Dependabot opens a pull request with the new digest. To check by hand: `docker buildx imagetools inspect python:3.12-alpine`.
- Packages: for each package and version that `requirements.txt` resolves to (the newest that satisfies the ranges), download the wheels of both platforms and hash them:

```sh
for p in x86_64 aarch64; do
  pip download -r requirements.txt --only-binary=:all: --python-version 3.12 \
    --implementation cp --abi cp312 --platform musllinux_1_2_$p -d wheels-$p
done
pip hash wheels-*/*.whl
```

  Write one line per package, sorted by name, with one `--hash=sha256:` per distinct wheel, and update the date in the header. If `pip download` fails for a platform, a package has no musllinux wheel for that version: lock the newest version that has both. `uv pip compile --generate-hashes` also works, but it writes the hashes of every wheel and the sdist, not only the two platforms.
- Check without Docker (both must print `Would install …` with no error):

```sh
for p in x86_64 aarch64; do
  pip install --dry-run --require-hashes --only-binary=:all: --python-version 3.12 \
    --implementation cp --abi cp312 --platform musllinux_1_2_$p --target /tmp/lockcheck-$p -r requirements.lock
done
```
