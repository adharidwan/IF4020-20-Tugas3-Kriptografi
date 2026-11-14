# Architecture

```mermaid
flowchart LR
  A[Artifact bytes] --> H[SHA-256 and size]
  H --> M[Canonical manifest]
  P[Package and version] --> M
  K[Private key] --> S[Profile sign operation]
  M --> S
  M --> B[Bundle: Base64 manifest and signature]
  S --> B
```

```mermaid
flowchart TD
  I[Inputs and expected metadata] --> R[Readability and usage]
  R --> F[Strict formats and canonical manifest]
  T[Independent trust store] --> F
  F --> A[Supported profile]
  A --> K[Key ID, profile, expected-package permission]
  K --> S[Verify stored manifest bytes]
  S --> M[Expected metadata and basename]
  M --> H[Artifact size and SHA-256]
  H --> OK[OK / exit 0]
```

Every failed stage returns immediately. I/O/usage errors use exit 2; rejections
use exit 1; only `OK` sets `valid=true`. No alternative keys/profiles are tried.

The CLI handles arguments/output. Formats enforce strict JSON and encoding.
Keys validate standard envelopes and profiles; crypto selects exact signature
parameters. Trust owns explicit package permissions. Artifacts stream read-only
bytes. Signing/verifying orchestrate these modules. Storage stages/fsyncs output
and publishes by hard link or atomic replacement.

```mermaid
flowchart LR
  P[Pull public image by digest] --> B[Build artifact]
  B --> S[Sign with CI secret]
  S --> V[Verify with independent public trust]
  V -->|exit 0| D[Deploy same bytes / marker]
  V -->|nonzero| X[Stop deployment]
```

The image has an allowlisted build context and nonroot default user. Inputs and
keys mount read-only; outputs persist on the runner. Verification receives no
private key. The harness captures original exit codes and marker evidence.
Registry-pull evidence is recorded separately from local image regressions.
