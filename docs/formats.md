# File contracts

## Manifest

UTF-8 without BOM; at most 16384 bytes; no newline or whitespace outside strings.
Use this exact field order and ordinary decimal integer representation:

```json
{"schema":"minisign-manifest/v1","package":"app","version":"1.0.0","algorithm":"ed25519","keyid":"<64 lowercase hex>","artifact":{"name":"app.bin","size":256,"sha256":"<64 lowercase hex>"}}
```

| Field | Type / restriction |
| --- | --- |
| `schema` | Exactly `minisign-manifest/v1` |
| `package` | ASCII `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | ASCII `[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}`; SemVer optional |
| `algorithm` | Required profile; unknown string rejected at verification stage 3 |
| `keyid` | Lowercase 64-character SHA-256 hex of DER SPKI |
| `artifact` | Exactly `name`, `size`, `sha256`, in that order |
| `artifact.name` | Basename; ASCII `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` |
| `artifact.size` | Integer 0 through 9007199254740991; boolean/float rejected |
| `artifact.sha256` | Lowercase 64-character SHA-256 hex of unchanged artifact bytes |

All fields are mandatory; reject extra/duplicate names, nulls and wrong types.
Canonical bytes use ASCII strings written literally, not Unicode escapes.
Strictly parse, rebuild the specified representation, and compare byte-for-byte.
Verify the original bytes. This is assignment-specific serialization, not
RFC 8785 or `sort_keys=True`.

## Bundle

UTF-8 without BOM; at most 65536 bytes; exactly these three fields:

```json
{
  "schema": "minisign-bundle/v1",
  "manifest_b64": "<Base64 of original manifest bytes>",
  "signature_b64": "<Base64 of raw signature>"
}
```

Standard RFC 4648 Base64 alphabet and required padding; reject whitespace,
URL-safe alphabet, surplus/omitted padding and nonzero pad bits. Outer JSON
whitespace/order may vary; extra/duplicate fields and wrong types are rejected.
Private/public keys are not part of the bundle.

## Trust store

```json
{
  "schema": "minisign-trust/v1",
  "keys": [{
    "keyid": "<64 lowercase hex>",
    "algorithm": "ed25519",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "packages": ["app"]
  }]
}
```

All fields mandatory; no extras/duplicates. `keys` may be empty. Key IDs must
be unique and match the stored SPKI fingerprint. Algorithm/type/parameters must
agree. Packages use the manifest package pattern and must be nonempty, unique,
and explicit; no wildcards. PEM is inline text, not a path. Validate every key
before lookup. PEM inputs have an implementation bound of 64 KiB.
