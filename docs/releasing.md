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
