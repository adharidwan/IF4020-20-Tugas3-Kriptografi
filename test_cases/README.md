# Test cases

| Folder | Content |
| --- | --- |
| `fixtures/` | 29 scenarios for U01–U14: inputs, bundles, commands, expected and actual results |
| `keys/` | Test keys. They are public on purpose. Do not use them for real releases |
| `results/` | `scenarios.json` (all outcomes) and `pytest.xml` (JUnit, includes OpenSSL interop) |
| `benchmarks/` | Raw timings, median and P95, environment |
| `container-local/` | C01–C05 with a locally built image |
| `container-registry/` | C01–C05 from the hosted GitHub Actions run with the GHCR image |

Unit scenarios in `fixtures/`:

| ID | Change | Expected result |
| --- | --- | --- |
| U01 | None (empty, text and binary file, each algorithm) | `OK` |
| U02 | One artifact byte changed, same size | `ARTIFACT_MISMATCH` |
| U03 | One artifact byte inserted or deleted | `ARTIFACT_MISMATCH` |
| U04 | Version changed in the manifest, old signature | `INVALID_SIGNATURE` |
| U05 | One signature bit changed | `INVALID_SIGNATURE` |
| U06 | Empty trust store, or publisher key removed | `KEY_NOT_TRUSTED` |
| U07 | Key trusted only for another package | `KEY_NOT_TRUSTED` |
| U08 | Different expected version | `METADATA_MISMATCH` |
| U09 | Artifact renamed | `METADATA_MISMATCH` |
| U10 | Bad Base64, duplicate key, wrong type, oversize bundle | `FORMAT_ERROR` |
| U11 | Unknown algorithm name | `UNSUPPORTED_ALGORITHM` |
| U12 | Signed with a different, untrusted key | `KEY_NOT_TRUSTED` |
| U13 | Bundle JSON reformatted and keys reordered | `OK` |
| U14 | Same manifest signed two times | `OK` (signatures compared) |

Run again from the repository root:

```sh
uv run pytest --junitxml=test_cases/results/pytest.xml
uv run python scripts/run_evidence.py
uv run python benchmarks/run.py
```
