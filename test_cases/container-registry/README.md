# Registry consumer results

Hosted run: <https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43690090640>
(15 November 2026). Publisher run:
<https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43689592719>.

The runner pulled this image from GHCR. It did not build from source.

```text
ghcr.io/adharidwan/if4020-20-tugas3-kriptografi@sha256:a7d0945841d0e1bb3d7052e0cf402a59eda18f1d7afad4f544ec55a5265d9426
```

Source: tag `v1.0.0`, commit `6061a93765e35a91724ad0def89d16a744be3d75`.

| Case | Check | Result | Exit | Deploy marker |
| --- | --- | --- | ---: | --- |
| C01 | RSA-PSS-SHA256 | OK | 0 | present |
| C01 | ECDSA-P256-SHA256 | OK | 0 | present |
| C01 | Ed25519 | OK | 0 | present |
| C02 | Changed artifact (same size) | ARTIFACT_MISMATCH | 1 | absent |
| C03 | Empty trust store | KEY_NOT_TRUSTED | 1 | absent |
| C04 | Missing artifact | INPUT_ERROR | 2 | absent |
| C05 | Offline, no TTY, UID/GID 1001 (see `summary.json`) | all commands passed | 0 | - |

All runs used `--network none`. Files: `summary.json` (all cases), `pull.log`,
one folder per case, `C05.log.json`, `release-image.json` and `workflow.json`.
