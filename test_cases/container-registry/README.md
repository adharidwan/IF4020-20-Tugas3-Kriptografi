# Hosted registry consumer evidence

Captured from the successful [Registry consumer C01-C05 run](https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43690090640),
completed on 15 November 2026 at 07:28:46 UTC. The runner pulled the public
Linux/amd64 tool image without building or installing the application from
source. No registry login step was used. Anonymous manifest access was also
verified independently.

Source tag: `v1.0.0`, commit `6061a93765e35a91724ad0def89d16a744be3d75`.
[Publisher run](https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43689592719).

```text
ghcr.io/adharidwan/if4020-20-tugas3-kriptografi@sha256:a7d0945841d0e1bb3d7052e0cf402a59eda18f1d7afad4f544ec55a5265d9426
```

| Case | Profile / check | Actual result | Exit | Deployment marker |
| --- | --- | --- | ---: | --- |
| C01 | RSA-PSS-SHA256 | OK | 0 | present |
| C01 | ECDSA-P256-SHA256 | OK | 0 | present |
| C01 | Ed25519 | OK | 0 | present |
| C02 | Same-size artifact corruption | ARTIFACT_MISMATCH | 1 | absent |
| C03 | Empty independent trust store | KEY_NOT_TRUSTED | 1 | absent |
| C04 | Missing artifact | INPUT_ERROR | 2 | absent |
| C05 | Offline CLI and persisted outputs | all commands passed | 0 | not applicable |

Every tool invocation used `--network none`, no TTY, and UID/GID `1001:1001`.
Signing used pre-provisioned private keys supplied through GitHub Actions
secrets. Verification used separate public stores under `ci/trust`. Private
keys were removed by the workflow and are absent from this evidence.

`summary.json` records the image, registry pull, cases, exit codes, and marker
state. `pull.log` records the registry download. Each case retains its artifact,
bundle, signing log, verification JSON, stderr, and any deployment marker.
`C05.log.json` retains offline command results. `release-image.json` is the
publisher's exact identity record; `workflow.json` records source/run/artifact
metadata. The original hosted artifact is named `registry-consumer-evidence`.
