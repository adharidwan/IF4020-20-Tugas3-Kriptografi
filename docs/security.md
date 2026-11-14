# Security analysis

An attacker may replace artifacts/bundles or supply malformed metadata and
encodings. Trusted boundaries are the user's expected package/version,
independent trust store, signing key, host and cryptographic backend.

| Risk | Implemented control | Remaining limitation |
| --- | --- | --- |
| Artifact substitution | Signed size, basename and SHA-256 | Deploy the same immutable verified bytes |
| Metadata/profile substitution | Original canonical manifest is signed; explicit profile and permissions | Expected metadata needs trusted caller configuration |
| Ambiguous JSON/encodings | Duplicate-aware parser, exact fields/types, strict Base64, canonical byte comparison | Trust-store document size is not bounded; control local file access |
| Signature format confusion | Fixed lengths; DER/raw ECDSA conversion; explicit r/s range | Crypto backend remains trusted |
| Incorrect RSA parameters | Explicit PSS, SHA-256, MGF1-SHA-256, 32-byte salt | Other RSA profiles intentionally rejected |
| Nonce/randomness failures | Backend CSPRNG for key generation, RSA salt and ECDSA nonce | Relies on operating-system entropy and backend |
| Untrusted signer | Exact key ID/profile and expected-package permission | Fingerprint approval is out-of-band |
| Malformed trust key | All envelopes/parameters and recomputed fingerprints checked | Authorized local writers can change trust |
| Private-key leakage | No keys in bundle/image/logs; Unix 0600; explicit overwrite; CI secret/read-only mount/cleanup | No encrypted PKCS8; protect Windows ACLs |
| Interrupted trust update | Flush/fsync staged file and atomic replacement | External locking needed for concurrent writers; no directory fsync guarantee |
| Rollback | Independently expected version checked | Automatic freshness needs additional trusted state |
| CI tool replacement | Exact image digest; action commit pins | Tool identity does not establish signer trust/source correctness |

U02/U03 reject same-size corruption and insertion/deletion. U04/U05 reject
modified signed content/signatures before metadata checks. U06/U07/U12 reject
missing/unauthorized keys. U08/U09 establish version and basename binding.
U10 rejects malformed inputs; U11 checks algorithm precedence; U13 allows outer
bundle reformatting. U14 demonstrates randomized RSA-PSS/ECDSA and deterministic
Ed25519. Actual fixtures and results are retained under `test_cases`.

Signatures do not assess malware, vulnerabilities, timestamps, certificate
identity or historical key validity. Removal rejects a key under the current
store. A trusted caller asking for an old signed version will still accept it;
automatic rollback prevention requires a trusted monotonic release policy.
