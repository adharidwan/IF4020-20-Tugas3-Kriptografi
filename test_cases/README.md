# Reproducible evidence

- `fixtures/`: 29 U01-U14 scenarios: inputs, bundles, trust, manifest bytes,
  expected/actual results, commands, stdout/stderr. U14 retains `second.json`.
- `keys/`: deliberately PUBLIC test private/public keys. Never use for real
  releases or CI secrets. These differ from the private CI demo publisher.
- `results/scenarios.json`: all outcomes and repeated-signature comparisons.
- `results/pytest.xml`: actual JUnit results, including bidirectional OpenSSL
  interoperability for all three profiles.
- `benchmarks/`: raw measurements, summaries, sizes and environment.
- `container-local/`: actual Linux/amd64 C01-C05 local-image regression results,
  marked `registry_pull=false`; these are not hosted registry evidence.

Reproduce from repository root after installing development dependencies:

```sh
python -m pytest --junitxml=test_cases/results/pytest.xml
python scripts/run_evidence.py
python benchmarks/run.py
python ci/container_cases.py --image anticnspy:local --allow-local-image \
  --keys-dir local-keys/ci-demo --trust-dir ci/trust --out <new-clean-directory>
```

The generator replaces test keys/fixtures. Use `--out` for a separate snapshot.
Recorded scenario commands assume the repository root as working directory.
