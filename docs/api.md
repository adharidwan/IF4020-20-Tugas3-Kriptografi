# Python API

Install the package before import. File arguments accept strings or `Path`.

| Function | Inputs | Output |
| --- | --- | --- |
| `keys.keygen(algorithm, prefix, force=False)` | Profile, path prefix, explicit overwrite bool | Dictionary of algorithm, fingerprint and PEM output paths |
| `trust.add(key_path, package, store_path)` | Public PEM path, package, store path | Validated entry; creates/updates store idempotently |
| `trust.list_keys(store_path)` | Trust path | Validated entry list |
| `trust.remove(keyid, store_path)` | Fingerprint, trust path | `None`; absent key raises `InputError` |
| `signing.sign_file(file, package, version, key, out, force=False)` | Artifact, metadata, private PEM, output | Manifest dictionary; writes bundle |
| `verification.verify_file(file, bundle, trust_store, package, version)` | Input paths and independent metadata | `VerificationResult` with `.to_dict()` and `.exit_code` |
| `formats.serialize_manifest(manifest)` | Dictionary | Canonical bytes |
| `formats.parse_manifest(raw)` | Original bytes | Validated canonical dictionary |
| `keys.fingerprint(public_key)` | Loaded public-key object | Lowercase SHA-256 hex of DER SPKI |

Non-verification operations raise `FormatError`, `InputError`, or `OSError`;
CLI maps failures to exit 2. Verification returns an ordered result with null
metadata when unavailable.

```python
from anticnspy.verification import verify_file
checked = verify_file("app.bin", "release.json", "trust.json", "app", "1.0.0")
if not checked.valid:
    raise SystemExit(checked.exit_code)
print(checked.to_dict())
```

These internal APIs are documented locally; public hosting for the optional
documentation bonus is not yet configured or claimed.
