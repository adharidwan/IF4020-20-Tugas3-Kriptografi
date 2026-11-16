# Registry consumer results

Hosted run: <https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43831293474>
(16 November 2026). Publisher run:
<https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43831076331>.

The runner pulled this image from GHCR. It did not build from source.

```text
ghcr.io/adharidwan/if4020-20-tugas3-kriptografi@sha256:1207bc792dd866767a20e487f5309b82b2e007f14f8cd08f09f986018cde77b6
```

Source: tag `v1.1.0`, commit `e3ed85bfc387fd385380f5e3a6bd7390370b5581`.

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
