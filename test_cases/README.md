# Test cases

| Folder | Content |
| --- | --- |
| `fixtures/` | 29 scenarios for U01–U14: inputs, bundles, commands, expected and actual results |
| `keys/` | Test keys. They are public on purpose. Do not use them for real releases |
| `results/` | `scenarios.json` (all outcomes) and `pytest.xml` (JUnit, includes OpenSSL interop) |
| `benchmarks/` | Raw timings, median and P95, environment |
| `container-local/` | C01–C05 with a locally built image |
| `container-registry/` | C01–C05 from the hosted GitHub Actions run with the GHCR image |

Run again from the repository root:

```sh
uv run pytest --junitxml=test_cases/results/pytest.xml
uv run python scripts/run_evidence.py
uv run python benchmarks/run.py
```
