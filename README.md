# AntiCNSpy

AntiCNSpy signs and verifies software releases using RSA-PSS, ECDSA P-256,
and Ed25519. It signs the exact bytes of a canonical release manifest and
checks a separately managed, package-scoped public-key trust store.

Version **1.0.0**. Requires Python 3.11+; tested with Python 3.13.3 and a
Linux/amd64 Python 3.13 container. Runtime dependencies are pinned with hashes
in `requirements.txt`; development dependencies are in `requirements-dev.txt`.
`uv.lock` records the complete dependency resolution.

## Install

```sh
uv sync --frozen --extra dev
uv run --frozen anticnspy --help
uv run --frozen anticnspy --version
```

Or use Python directly:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements.txt
python -m pip install --no-deps .
anticnspy --help
```

`python -m anticnspy` is equivalent to the console command. On this prepared
Windows workspace, `.venv\Scripts\anticnspy.exe` works without activation.
The CLI requires no GUI, TTY, prompt, or runtime network access.

## All required commands

Prepare a file named `app.bin`, then run:

```sh
anticnspy keygen --algorithm ed25519 --out local-keys/publisher
# Check the printed fingerprint through a trusted channel before trusting it.
anticnspy trust add --key local-keys/publisher.pub.pem --package app --store trust.json
anticnspy trust list --store trust.json
anticnspy sign --file app.bin --package app --version 1.0.0 \
  --key local-keys/publisher.key.pem --out release.json
anticnspy verify --file app.bin --bundle release.json --trust-store trust.json \
  --package app --version 1.0.0 --json
anticnspy trust remove --keyid <64-lowercase-hex-fingerprint> --store trust.json
```

PowerShell users should put each command on one line or use PowerShell's
backtick continuation in place of the POSIX backslash. Select the other
profiles with `keygen --algorithm rsa-pss-sha256` or `ecdsa-p256-sha256`.
Signing infers the profile from the private key. Expected package/version are
required independent inputs to verification. Renaming an artifact requires a
new manifest and signature.

Every command supports `--help`; the root command supports `--version`.
`keygen` writes `<prefix>.key.pem` and `<prefix>.pub.pem` and prints the fingerprint.
Output conflicts fail with exit 2. `keygen --force` explicitly permits key
overwrites; `sign --force` permits bundle overwrites. Signing cannot overwrite
an artifact or input key even with `--force`. Parent output directories are
created as needed. Trust add merges permissions idempotently; remove deletes
the entire key entry and fails with exit 2 if it is absent. Atomic trust writes
preserve the prior store on failure. Concurrent writers need external locking.

## Algorithms, keys, and dependencies

| Profile | Parameters / library API | Raw signature |
| --- | --- | --- |
| `rsa-pss-sha256` | RSA 3072, e=65537; `padding.PSS` with SHA-256, MGF1-SHA-256, exactly 32-byte salt | 384 bytes |
| `ecdsa-p256-sha256` | `ec.SECP256R1`, `ec.ECDSA(hashes.SHA256())`; CSPRNG nonce; DER/raw conversion via `utils` | 32-byte big-endian r followed by 32-byte big-endian s |
| `ed25519` | `Ed25519PrivateKey.generate`, direct `sign/verify` of original message; no external prehash/context | 64 bytes |

RSA/ECDSA receive original manifest bytes and apply SHA-256 exactly once inside
the configured operation. RSA salt and ECDSA nonce are randomized; Ed25519 is
deterministic. Both valid low-S and non-low-S ECDSA signatures are accepted.

Private keys: unencrypted PKCS8 PEM (`PRIVATE KEY`). Public keys: SPKI PEM
(`PUBLIC KEY`). Encrypted PKCS8 is not supported. Private files use mode 0600
on Unix; Windows users must protect their containing directory with account
ACLs. Key envelopes/parameters are validated, including RSA `rsaEncryption`,
P-256 named curve/uncompressed point, and absent Ed25519 parameters.
`keyid` is lowercase SHA-256 of re-exported DER SPKI, independent of PEM wrapping.

Pinned runtime: `cryptography==50.0.2`, `cffi==2.1.1`, `pycparser==3.12` on
CPython. All other application functions use the standard library (`argparse`,
`json`, `base64`, `hashlib`, `pathlib`, `tempfile`, `os`, dataclasses/enums).
Development uses `pytest`, `ruff`, and `PyYAML`. OpenSSL CLI is used only for
external interoperability tests, never as the signing application.

Official API references: [RSA](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/),
[ECDSA](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ec/),
[Ed25519](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/),
[serialization](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/serialization/),
[Python JSON](https://docs.python.org/3/library/json.html).

## Formats and verification

See [file contracts](docs/formats.md). The assignment schema strings remain
`minisign-manifest/v1`, `minisign-bundle/v1`, and `minisign-trust/v1`.
Verification rejects at the first failed stage, without trying another key,
profile, or store:

| Stage | Failure status | Exit |
| --- | --- | ---: |
| Arguments, readability, I/O, environment | `INPUT_ERROR` | 2 |
| JSON/schema/types, sizes, Base64, canonical manifest, trust-key format | `FORMAT_ERROR` | 1 |
| Supported manifest profile | `UNSUPPORTED_ALGORITHM` | 1 |
| Key ID/profile and expected-package permission | `KEY_NOT_TRUSTED` | 1 |
| Signature over stored manifest bytes | `INVALID_SIGNATURE` | 1 |
| Expected package/version and artifact basename | `METADATA_MISMATCH` | 1 |
| Artifact size and SHA-256 | `ARTIFACT_MISMATCH` | 1 |
| All checks pass | `OK` | 0 |

Malformed Base64 is a format error. Decoded signature length/encoding/range
errors are signature failures. Unknown string-valued manifest algorithms
reach stage 3. Every trust-store key is validated before lookup.

`verify --json` writes exactly one object plus one newline to stdout:

```json
{"valid":true,"status":"OK","message":"Signature, trust, metadata, and artifact are valid.","algorithm":"ed25519","keyid":"<64 lowercase hex>","package":"app","version":"1.0.0"}
```

Unavailable manifest metadata is null. Diagnostics go to stderr. Usage/I/O
errors also follow this JSON contract when `verify --json` is requested.
All failures of non-verification commands use exit 2.

## Container

```sh
docker build --platform linux/amd64 -t anticnspy:local .
docker run --rm --network none anticnspy:local --help
docker run --rm --network none anticnspy:local --version
```

The image directly invokes the CLI. Default identity is 65532:65532; it supports
runner-supplied `--user`. The allowlisted build context excludes keys, fixtures,
PDFs, local environments, and private files. Dependencies are already inside.

Example Linux runner commands, with absolute `SIGNING_KEY_FILE` and a public
digest-pinned image reference in `IMAGE`:

```sh
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/dist,dst=/input,readonly" \
  --mount "type=bind,src=$PWD/out,dst=/output" \
  --mount "type=bind,src=$SIGNING_KEY_FILE,dst=/run/publisher.key.pem,readonly" \
  "$IMAGE" sign --file /input/app.bin --package app --version 1.0.0 \
  --key /run/publisher.key.pem --out /output/release.json
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/dist,dst=/input,readonly" \
  --mount "type=bind,src=$PWD/out,dst=/output,readonly" \
  --mount "type=bind,src=$PWD/trust.json,dst=/trust.json,readonly" \
  "$IMAGE" verify --file /input/app.bin --bundle /output/release.json \
  --trust-store /trust.json --package app --version 1.0.0 --json
```

Windows Docker Desktop uses the same CLI with quoted Windows absolute mount
paths. Outputs persist in the mounted host directory. Docker forwards CLI
stdout/stderr/exit codes; infrastructure failures can have other nonzero codes.

## Tests and benchmarks

```sh
uv run --frozen pytest --junitxml=test_cases/results/pytest.xml
uv run --frozen ruff check src tests scripts benchmarks ci
uv run --frozen ruff format --check src tests scripts benchmarks ci
uv run --frozen python scripts/run_evidence.py
uv run --frozen python benchmarks/run.py
```

Install external OpenSSL for bidirectional interoperability tests on all profiles;
three cases explicitly skip if it is absent. ECDSA interop converts DER/raw.
JUnit records actual outcomes. `scripts/run_evidence.py` generates 29 reusable
scenarios covering U01-U14 with separate malformed-input cases and repeat-sign
results. Inputs, expected/actual results, commands, stdout/stderr, and bundles
are retained under `test_cases/fixtures`.

**Private keys under `test_cases/keys` are deliberately PUBLIC test fixtures.**
Never use them for real releases or CI secrets. Regeneration replaces test
fixtures and their fingerprints; use `--out` to preserve an existing snapshot.

Benchmarks use identical deterministic 1 KiB, 1 MiB, and 16 MiB artifacts across
profiles, at least 5 key generations each, and 5 warm-ups plus 30 measured runs.
Crypto timings exclude artifact I/O/hash; full-CLI timings include startup,
parsing, I/O, hashing, and output. A monotonic clock and nearest-rank P95 are
used. Raw samples, sizes, environment, median/P95 are in `test_cases/benchmarks`.

## Public image and CI/CD

The intended repository is `ghcr.io/adharidwan/if4020-20-tugas3-kriptografi`.
Source tag: `v1.0.0`; image version tag: `1.0.0`. **Publication is pending.**
No public image digest or hosted workflow success is claimed. See
[release status](docs/release-status.json) and [release steps](docs/releasing.md).

After publication:

```sh
docker pull ghcr.io/adharidwan/if4020-20-tugas3-kriptografi:1.0.0
# IMAGE must contain the actual repository@sha256:digest from the publish job.
docker pull "$IMAGE"
docker run --rm --network none "$IMAGE" --version
```

The tag-triggered publisher checks version/source consistency and records the
actual digest. Make the GHCR package public, then dispatch **Registry consumer
C01-C05** on `main` with that reference. The consumer pulls the published tool
without building source or installing application/runtime dependencies.

Explicit one-time demo provisioning, outside the consumer:

```sh
python ci/provision_demo.py --keys-dir local-keys/ci-demo
```

This workspace already has ignored private demo keys there and matching public
stores in `ci/trust`. Configure their PEM contents as repository secrets
`DEMO_RSA_PRIVATE_KEY`, `DEMO_ECDSA_PRIVATE_KEY`, `DEMO_ED25519_PRIVATE_KEY`.
Check fingerprints independently. Do not regenerate unless rotating identity.

The consumer mounts CI secrets read-only for signing, cleans them up, and
verifies with independent public trust and no private key. C01 covers all
profiles; C02 corruption, C03 untrusted signer and C04 missing artifact block
deployment. C05 exercises offline/no-TTY operation with runner UID/GID.
Outputs include original exit codes, JSON, logs, and deployment-marker evidence.

Local-image regression, using a clean output directory:

```sh
python ci/container_cases.py --image anticnspy:local --allow-local-image \
  --keys-dir local-keys/ci-demo --trust-dir ci/trust --out test_cases/container-local
```

This is marked `registry_pull=false` and does not establish registry distribution.
Regular CI also runs local-image regressions with public test-only keys, separate
from CI publisher secrets. It passes `--package app` to match those fixtures'
permissions; the registry consumer uses the default `anticnspy-demo` package.
Workflow actions are pinned to verified commit IDs.

## Design and report

See [architecture](docs/architecture.md), [security analysis](docs/security.md),
[Python API](docs/api.md), and [technical report draft](docs/report.md).
Member identities/photos and final task division will be supplied later.
The rendered draft is `output/pdf/AntiCNSpy-technical-report-draft.pdf`.
Rebuild it from actual evidence with
`uv run --frozen --extra report python scripts/build_report.py`.

A valid signature establishes integrity and possession of an authorized key;
it does not establish absence of malware or signer honesty. There is no
timestamping, certificate identity, automatic revocation or rollback state.
Fresh expected versions must come from trusted caller policy. Keep inputs
immutable through verification and deployment. Artifacts are never executed,
extracted, normalized, or changed by the application.
