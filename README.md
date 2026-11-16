# AntiCNSpy

AntiCNSpy is a CLI that signs and verifies software releases. It supports
RSA-PSS, ECDSA P-256 and Ed25519. The signature covers a canonical manifest
that holds the package, the version and the SHA-256 of the artifact. The
verifier accepts only keys that a trust store allows for that package.

Version 1.0.0.

## Tech stack

- Python 3.13 (3.11 or later works)
- [`cryptography`](https://cryptography.io/) for all signature operations
- Python standard library for the CLI (`argparse`), JSON, Base64 and hashing
- Docker for the container image, GitHub Actions for CI, GHCR for the registry
- pytest, ruff and PyYAML for development

## Dependencies

| Package | Version | Use |
| --- | --- | --- |
| `cryptography` | 50.0.2 | Runtime |
| `cffi`, `pycparser` | 2.1.1, 3.12 | Runtime (needed by `cryptography`) |
| `pytest`, `ruff`, `PyYAML` | 9.2.0, 0.17.5, 6.0.3 | Development |

`requirements.txt` and `requirements-dev.txt` pin all versions with hashes.
The OpenSSL CLI is needed only for the interoperability tests.

## Run with the container image (CI)

```sh
IMAGE=ghcr.io/adharidwan/if4020-20-tugas3-kriptografi@sha256:a7d0945841d0e1bb3d7052e0cf402a59eda18f1d7afad4f544ec55a5265d9426
docker pull "$IMAGE"
docker run --rm --network none "$IMAGE" --version
```

The image runs the CLI directly. It needs no network. Mount the input files
and the output directory:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" \
  -v "$SIGNING_KEY_FILE:/run/publisher.key.pem:ro" \
  "$IMAGE" sign --file /input/app.bin --package app --version 1.0.0 \
  --key /run/publisher.key.pem --out /output/release.json

docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output:ro" \
  -v "$PWD/trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/app.bin --bundle /output/release.json \
  --trust-store /trust.json --package app --version 1.0.0 --json
```

The workflow `.github/workflows/consumer.yml` pulls this image and runs cases
C01–C05. The private signing keys are GitHub Actions secrets. The public trust
stores are in `ci/trust/`. Results of the hosted run are in
[`test_cases/container-registry`](test_cases/container-registry/README.md).

- Publisher run: <https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43689592719>
- Consumer run (C01–C05): <https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43690090640>

## Run without the container

```sh
uv sync --frozen --extra dev
uv run anticnspy --help
```

Or with pip:

```sh
python -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.txt
pip install --no-deps .
anticnspy --help
```

## Commands

```sh
# 1. Make a key pair (ed25519, rsa-pss-sha256 or ecdsa-p256-sha256)
anticnspy keygen --algorithm ed25519 --out keys/publisher

# 2. Allow the public key to sign package "app"
anticnspy trust add --key keys/publisher.pub.pem --package app --store trust.json
anticnspy trust list --store trust.json

# 3. Sign
anticnspy sign --file app.bin --package app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json

# 4. Verify
anticnspy verify --file app.bin --bundle release.json --trust-store trust.json \
  --package app --version 1.0.0 --json

# 5. Remove a key
anticnspy trust remove --keyid <keyid> --store trust.json
```

`sign` gets the algorithm from the private key. `keygen --force` and
`sign --force` overwrite existing output files.

Example `verify --json` output:

```json
{"valid":true,"status":"OK","message":"Signature, trust, metadata, and artifact are valid.","algorithm":"ed25519","keyid":"<64 hex>","package":"app","version":"1.0.0"}
```

Verification stops at the first failed check:

| Order | Check | Status | Exit |
| ---: | --- | --- | ---: |
| 1 | Arguments and file read | `INPUT_ERROR` | 2 |
| 2 | JSON, schema, Base64, canonical manifest | `FORMAT_ERROR` | 1 |
| 3 | Algorithm is supported | `UNSUPPORTED_ALGORITHM` | 1 |
| 4 | Key is in the store and allowed for the package | `KEY_NOT_TRUSTED` | 1 |
| 5 | Signature | `INVALID_SIGNATURE` | 1 |
| 6 | Package, version and file name | `METADATA_MISMATCH` | 1 |
| 7 | Artifact size and SHA-256 | `ARTIFACT_MISMATCH` | 1 |
| – | All checks pass | `OK` | 0 |

Other commands return exit 2 on error.

## Signed SBOM

The SBOM is a CycloneDX 1.6 JSON file. It records the package, the version,
the file name, the size and the SHA-256 of the release artifact. The SBOM is
signed as a separate bundle in the same `minisign-bundle/v1` format, with the
same keys and trust store as the release.

| Command | What it does | Fails with |
| --- | --- | --- |
| `sbom create --file F --package P --version V --out sbom.json [--dependency NAME==VER ...]` | Writes the SBOM for artifact `F` | exit 2 |
| `sbom sign --sbom sbom.json --package P --version V --key K --out sbom.bundle.json` | Signs the SBOM | exit 2 |
| `sbom verify --sbom sbom.json --bundle sbom.bundle.json --trust-store T --package P --version V [--json]` | Checks the SBOM signature, signer trust and release metadata | `KEY_NOT_TRUSTED`, `INVALID_SIGNATURE`, `METADATA_MISMATCH`, `ARTIFACT_MISMATCH` (SBOM changed) |
| `sbom check --sbom sbom.json --file F [--json]` | Checks that `F` has the name, size and SHA-256 in the SBOM | `METADATA_MISMATCH`, `ARTIFACT_MISMATCH` (artifact replaced) |

```sh
anticnspy sbom create --file app.bin --package app --version 1.0.0 \
  --dependency cryptography==50.0.2 --out sbom.json
anticnspy sbom sign --sbom sbom.json --package app --version 1.0.0 \
  --key keys/publisher.key.pem --out sbom.bundle.json
anticnspy sbom verify --sbom sbom.json --bundle sbom.bundle.json \
  --trust-store trust.json --package app --version 1.0.0
anticnspy sbom check --sbom sbom.json --file app.bin
```

`sbom verify` and `sbom check` use the same statuses and exit codes as `verify`.

## Run the tests

```sh
uv run pytest
uv run ruff check src tests scripts benchmarks ci
uv run python scripts/run_evidence.py   # makes test_cases/fixtures (U01–U14)
uv run python benchmarks/run.py         # makes test_cases/benchmarks
```

The private keys in `test_cases/keys` are test keys only. They are public on
purpose. Do not use them for real releases.

## Algorithms and library API

| Profile | Library API (`cryptography`) | Signature |
| --- | --- | --- |
| `rsa-pss-sha256` | `rsa.generate_private_key(public_exponent=65537, key_size=3072)`, `padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)`, `hashes.SHA256()` | 384 bytes |
| `ecdsa-p256-sha256` | `ec.generate_private_key(ec.SECP256R1())`, `ec.ECDSA(hashes.SHA256())`, `utils.decode_dss_signature` / `encode_dss_signature` for raw `r‖s` | 64 bytes |
| `ed25519` | `Ed25519PrivateKey.generate()`, `.sign()`, `.verify()` | 64 bytes |

- Private key: PKCS8 PEM, not encrypted. Public key: SPKI PEM.
- `keyid`: lowercase hex of SHA-256 over the DER SPKI.

## File formats

**Manifest** (`minisign-manifest/v1`). This is the signed message. It is
compact JSON in this exact field order, UTF-8 without BOM, 16 KiB maximum:

```json
{"schema":"minisign-manifest/v1","package":"app","version":"1.0.0","algorithm":"ed25519","keyid":"<64 hex>","artifact":{"name":"app.bin","size":256,"sha256":"<64 hex>"}}
```

| Field | Rule |
| --- | --- |
| `package` | `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `artifact.name` | File name only, `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` |
| `artifact.size` | Integer, 0 to 2^53−1 |
| `keyid`, `artifact.sha256` | 64 lowercase hex characters |

The verifier rejects extra fields, missing fields and any byte that is
different from the canonical form.

**Bundle** (`minisign-bundle/v1`), 64 KiB maximum:

```json
{
  "schema": "minisign-bundle/v1",
  "manifest_b64": "<Base64 of the manifest bytes>",
  "signature_b64": "<Base64 of the raw signature>"
}
```

Base64 is the standard RFC 4648 alphabet with padding.

**Trust store** (`minisign-trust/v1`):

```json
{
  "schema": "minisign-trust/v1",
  "keys": [{
    "keyid": "<64 hex>",
    "algorithm": "ed25519",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "packages": ["app"]
  }]
}
```

## API documentation

<https://adharidwan.github.io/IF4020-20-Tugas3-Kriptografi/api.html>
(source: [docs/api.md](docs/api.md))
