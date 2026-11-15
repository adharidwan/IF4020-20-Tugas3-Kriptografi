# Publish and collect hosted evidence

1. Review code, tests and report identities. Include lockfiles, public test
   fixtures and CI public trust stores. Exclude private `local-keys` and `.venv`.
2. Independently verify CI demo fingerprints. Install the three secrets listed
   in `ci/trust/README.md` from `local-keys/ci-demo`. Provisioning occurs before
   the consumer workflow and never derives trust from a bundle.
3. Push reviewed source, then source tag `v1.0.0`, matching project version
   `1.0.0`. The publisher tests and builds/pushes the Linux/amd64 release image.
4. Make the GHCR package public and check anonymous pull. Download the publish
   artifact `release-image.json`, which records the real registry digest.
5. Record that source-tag/image mapping and digest in README and
   `docs/release-status.json`. Never substitute a local Docker image ID for
   a registry manifest digest. Documentation-only updates may follow the tag.
6. Dispatch **Registry consumer C01-C05** on `main`, passing the exact
   `ghcr.io/...@sha256:...` reference. No application/runtime dependencies are
   installed and the tool is not built from source by the consumer.
7. Download evidence: sanitized JSON/logs, real exit codes, marker presence/
   absence, and hosted workflow run URL. C01 covers all profiles. C02-C04 must
   reject and leave protected deployment markers absent.
8. Complete/visually verify the final report PDF with member photos, truthful
   declaration and task division. Create the GitHub release and submit its URL.

Local runs are explicitly marked `registry_pull=false`; they do not establish
public registry distribution or hosted integration evidence.

## Recorded release 1.0.0

The source tag `v1.0.0` points to
`6061a93765e35a91724ad0def89d16a744be3d75`.
The [publisher run](https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43689592719)
published the public Linux/amd64 image on 15 November 2026. The
[consumer run](https://github.com/adharidwan/IF4020-20-Tugas3-Kriptografi/actions/runs/43690090640)
passed C01-C05 using the exact digest in [release status](release-status.json).
The three CI secrets are configured and match the independently provisioned
public trust stores. [Retained evidence](../test_cases/container-registry/README.md)
includes the registry pull, signature bundles, verification results, and markers.

Final report identities/photos, the final PDF, and the GitHub Release remain
separate submission work.
