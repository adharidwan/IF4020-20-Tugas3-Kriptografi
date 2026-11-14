# Benchmark results

Timings are milliseconds. P95 uses nearest rank.

| Algorithm | Artifact bytes | Operation | Median ms | P95 ms |
| --- | ---: | --- | ---: | ---: |
| rsa-pss-sha256 | None | keygen | 130.713600 | 456.056000 |
| rsa-pss-sha256 | 1024 | artifact_sha256_memory | 0.001050 | 0.001300 |
| rsa-pss-sha256 | 1024 | crypto_sign | 0.593850 | 0.731800 |
| rsa-pss-sha256 | 1024 | crypto_verify | 0.038800 | 0.059700 |
| rsa-pss-sha256 | 1024 | cli_sign | 271.973950 | 338.275500 |
| rsa-pss-sha256 | 1024 | cli_verify | 160.599200 | 246.723300 |
| rsa-pss-sha256 | 1048576 | artifact_sha256_memory | 0.476800 | 0.678800 |
| rsa-pss-sha256 | 1048576 | crypto_sign | 0.610900 | 1.076800 |
| rsa-pss-sha256 | 1048576 | crypto_verify | 0.057350 | 0.065900 |
| rsa-pss-sha256 | 1048576 | cli_sign | 251.509000 | 366.798400 |
| rsa-pss-sha256 | 1048576 | cli_verify | 155.955550 | 216.523000 |
| rsa-pss-sha256 | 16777216 | artifact_sha256_memory | 7.426100 | 9.642600 |
| rsa-pss-sha256 | 16777216 | crypto_sign | 0.595550 | 1.047900 |
| rsa-pss-sha256 | 16777216 | crypto_verify | 0.040400 | 0.076600 |
| rsa-pss-sha256 | 16777216 | cli_sign | 265.579200 | 301.013700 |
| rsa-pss-sha256 | 16777216 | cli_verify | 163.164550 | 200.684300 |
| ecdsa-p256-sha256 | None | keygen | 0.020400 | 36.375700 |
| ecdsa-p256-sha256 | 1024 | artifact_sha256_memory | 0.001050 | 0.001400 |
| ecdsa-p256-sha256 | 1024 | crypto_sign | 0.020050 | 0.020700 |
| ecdsa-p256-sha256 | 1024 | crypto_verify | 0.050450 | 0.066000 |
| ecdsa-p256-sha256 | 1024 | cli_sign | 174.558250 | 196.383700 |
| ecdsa-p256-sha256 | 1024 | cli_verify | 233.736400 | 387.694200 |
| ecdsa-p256-sha256 | 1048576 | artifact_sha256_memory | 0.650100 | 0.730900 |
| ecdsa-p256-sha256 | 1048576 | crypto_sign | 0.038250 | 0.080500 |
| ecdsa-p256-sha256 | 1048576 | crypto_verify | 0.095700 | 0.104800 |
| ecdsa-p256-sha256 | 1048576 | cli_sign | 194.561950 | 315.175100 |
| ecdsa-p256-sha256 | 1048576 | cli_verify | 236.868650 | 292.325700 |
| ecdsa-p256-sha256 | 16777216 | artifact_sha256_memory | 11.448550 | 13.470800 |
| ecdsa-p256-sha256 | 16777216 | crypto_sign | 0.029650 | 0.062800 |
| ecdsa-p256-sha256 | 16777216 | crypto_verify | 0.084800 | 0.270500 |
| ecdsa-p256-sha256 | 16777216 | cli_sign | 276.341900 | 343.313400 |
| ecdsa-p256-sha256 | 16777216 | cli_verify | 247.936300 | 319.596200 |
| ed25519 | None | keygen | 0.068600 | 1.458700 |
| ed25519 | 1024 | artifact_sha256_memory | 0.001500 | 0.003100 |
| ed25519 | 1024 | crypto_sign | 0.045900 | 0.210000 |
| ed25519 | 1024 | crypto_verify | 0.117400 | 0.203100 |
| ed25519 | 1024 | cli_sign | 241.233850 | 313.360500 |
| ed25519 | 1024 | cli_verify | 186.451450 | 251.147300 |
| ed25519 | 1048576 | artifact_sha256_memory | 0.660950 | 0.729900 |
| ed25519 | 1048576 | crypto_sign | 0.061100 | 0.067800 |
| ed25519 | 1048576 | crypto_verify | 0.156600 | 0.171400 |
| ed25519 | 1048576 | cli_sign | 191.308100 | 284.747200 |
| ed25519 | 1048576 | cli_verify | 147.888650 | 264.946500 |
| ed25519 | 16777216 | artifact_sha256_memory | 11.471850 | 12.600300 |
| ed25519 | 16777216 | crypto_sign | 0.049700 | 0.105900 |
| ed25519 | 16777216 | crypto_verify | 0.113400 | 0.253200 |
| ed25519 | 16777216 | cli_sign | 199.792350 | 320.969200 |
| ed25519 | 16777216 | cli_verify | 196.041250 | 338.216200 |

Environment:

```json
{
  "platform": "Windows-11-10.0.26200-SP0",
  "machine": "AMD64",
  "cpu": "AMD64 Family 25 Model 116 Stepping 1, AuthenticAMD",
  "logical_cpus": 12,
  "python": "3.13.3 (main, May 30 2025, 05:37:00) [MSC v.1943 64 bit (AMD64)]",
  "anticnspy": "1.0.0",
  "cryptography": "50.0.2",
  "openssl_backend": "OpenSSL 4.0.3 29 Sep 2026",
  "clock": "time.perf_counter_ns (monotonic)",
  "percentile": "nearest-rank: sorted_samples[ceil(0.95*n)-1]",
  "iterations": 30,
  "warmups": 5,
  "artifact_generation": "repeat bytes 0..255 and truncate to requested length",
  "crypto_timing": "Profile operations on original manifest bytes; internal hash included; artifact I/O/hash excluded",
  "cli_timing": "Full new Python process including startup, I/O, hashing, validation and output"
}
```
