# AntiCNSpy Python API

The CLI uses these functions. You can also import them from Python.

```sh
pip install .
```

Path arguments accept `str` or `pathlib.Path`.

## Key generation

### `anticnspy.keys.keygen(algorithm, prefix, *, force=False) -> dict`

Makes a key pair and writes `<prefix>.key.pem` and `<prefix>.pub.pem`.

| Parameter | Type | Description |
| --- | --- | --- |
| `algorithm` | `str` | `rsa-pss-sha256`, `ecdsa-p256-sha256` or `ed25519` |
| `prefix` | `str \| Path` | Output path without the `.key.pem` / `.pub.pem` suffix |
| `force` | `bool` | Overwrite existing key files |

Returns `{"algorithm": str, "keyid": str, "private_key": str, "public_key": str}`.

### `anticnspy.keys.fingerprint(public_key) -> str`

Returns the key ID: lowercase hex of SHA-256 over the DER SPKI bytes.

## Trust store

### `anticnspy.trust.add(key_path, package, store_path) -> dict`

Gives a public key permission to sign `package`. Creates the store if it does
not exist. Running it again with the same key and package changes nothing.

Returns the entry: `{"keyid", "algorithm", "public_key_pem", "packages"}`.

### `anticnspy.trust.list_keys(store_path) -> list[dict]`

Returns all entries in the store.

### `anticnspy.trust.remove(keyid, store_path) -> None`

Removes the entry. Raises `InputError` if the key ID is not in the store.

## Sign

### `anticnspy.signing.sign_file(file, package, version, key, out, *, force=False) -> dict`

| Parameter | Type | Description |
| --- | --- | --- |
| `file` | `str \| Path` | Artifact to sign |
| `package` | `str` | Package name, pattern `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | `str` | Version, pattern `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `key` | `str \| Path` | Private key, PKCS8 PEM. The key type selects the algorithm |
| `out` | `str \| Path` | Bundle output path |
| `force` | `bool` | Overwrite an existing bundle |

Writes the bundle and returns the manifest as a `dict`.

## Verify

### `anticnspy.verification.verify_file(file, bundle, trust_store, package, version) -> VerificationResult`

| Parameter | Type | Description |
| --- | --- | --- |
| `file` | `str \| Path` | Artifact to check |
| `bundle` | `str \| Path` | Bundle JSON |
| `trust_store` | `str \| Path` | Trust store JSON |
| `package` | `str` | Expected package |
| `version` | `str` | Expected version |

This function does not raise on a failed check. It returns a result.

`VerificationResult` fields:

| Field | Type | Description |
| --- | --- | --- |
| `valid` | `bool` | `True` only when `status` is `OK` |
| `status` | `str` | `OK`, `INPUT_ERROR`, `FORMAT_ERROR`, `UNSUPPORTED_ALGORITHM`, `KEY_NOT_TRUSTED`, `INVALID_SIGNATURE`, `METADATA_MISMATCH` or `ARTIFACT_MISMATCH` |
| `message` | `str` | Short reason |
| `algorithm`, `keyid`, `package`, `version` | `str \| None` | Values from the manifest, or `None` if not read |
| `exit_code` | `int` (property) | `0` for `OK`, `2` for `INPUT_ERROR`, else `1` |

`to_dict()` returns the same fields as the `verify --json` output.

## Manifest helpers

| Function | Description |
| --- | --- |
| `anticnspy.formats.serialize_manifest(manifest: dict) -> bytes` | Canonical manifest bytes |
| `anticnspy.formats.parse_manifest(raw: bytes) -> dict` | Strict parse. Raises `FormatError` if `raw` is not canonical |

## Errors

`anticnspy.errors.InputError` and `anticnspy.errors.FormatError` are subclasses
of `ValueError`. All functions except `verify_file` can raise them, or `OSError`.

## Example

```python
from anticnspy.keys import keygen
from anticnspy.signing import sign_file
from anticnspy.trust import add
from anticnspy.verification import verify_file

keys = keygen("ed25519", "keys/publisher")
add(keys["public_key"], "app", "trust.json")
sign_file("app.bin", "app", "1.0.0", keys["private_key"], "release.json")

checked = verify_file("app.bin", "release.json", "trust.json", "app", "1.0.0")
print(checked.to_dict())
if not checked.valid:
    raise SystemExit(checked.exit_code)
```
