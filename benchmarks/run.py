import argparse
import csv
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import serialization

from anticnspy import __version__, crypto, trust
from anticnspy.formats import PROFILES, document_bytes, parse_bundle
from anticnspy.keys import generate, keygen, private_bytes, public_bytes
from anticnspy.signing import sign_file


def main():
    parser = argparse.ArgumentParser(
        description="Reproducible crypto, hashing, key generation and full-CLI benchmarks."
    )
    parser.add_argument("--out", type=Path, default=Path("test_cases/benchmarks"))
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1024, 1048576, 16777216])
    args = parser.parse_args()
    if args.iterations < 30 or args.warmups < 5 or len(set(args.sizes)) < 3 or min(args.sizes) < 0:
        parser.error("Use >=30 iterations, >=5 warm-ups and >=3 distinct nonnegative sizes.")
    args.out.mkdir(parents=True, exist_ok=True)
    rows, summaries, sizes = [], [], []

    def measure(algorithm, size, metric, operation, *, count=None, warmups=None):
        count = args.iterations if count is None else count
        warmups = args.warmups if warmups is None else warmups
        for _ in range(warmups):
            operation()
        samples = []
        for i in range(count):
            start = time.perf_counter_ns()
            operation()
            elapsed = time.perf_counter_ns() - start
            samples.append(elapsed)
            rows.append(
                {
                    "algorithm": algorithm,
                    "artifact_bytes": size,
                    "metric": metric,
                    "iteration": i + 1,
                    "nanoseconds": elapsed,
                }
            )
        ordered = sorted(samples)
        summaries.append(
            {
                "algorithm": algorithm,
                "artifact_bytes": size,
                "metric": metric,
                "samples": count,
                "median_ns": statistics.median(samples),
                "p95_ns": ordered[math.ceil(0.95 * count) - 1],
            }
        )

    def command(arguments):
        completed = subprocess.run(
            [sys.executable, "-m", "anticnspy", *arguments],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.decode(errors="replace"))

    with tempfile.TemporaryDirectory(prefix="anticnspy-benchmark-") as temporary:
        root = Path(temporary)
        for algorithm in PROFILES:
            measure(algorithm, None, "keygen", lambda a=algorithm: generate(a), count=5, warmups=0)
            key = generate(algorithm)
            prefix = root / algorithm
            keygen(algorithm, prefix)
            store = root / f"{algorithm}-trust.json"
            trust.add(f"{prefix}.pub.pem", "app", store)
            for size in args.sizes:
                data = (bytes(range(256)) * ((size + 255) // 256))[:size]
                file = root / f"artifact-{size}.bin"
                file.write_bytes(data)
                bundle = root / f"{algorithm}-{size}.json"
                sign_file(file, "app", "1.0.0", f"{prefix}.key.pem", bundle)
                message, _ = parse_bundle(bundle.read_bytes())
                signature = crypto.sign(key, message)
                public = key.public_key()
                measure(
                    algorithm,
                    size,
                    "artifact_sha256_memory",
                    lambda d=data: hashlib.sha256(d).digest(),
                )
                measure(algorithm, size, "crypto_sign", lambda k=key, m=message: crypto.sign(k, m))
                measure(
                    algorithm,
                    size,
                    "crypto_verify",
                    lambda k=public, m=message, s=signature: crypto.verify(k, m, s),
                )
                sign_args = [
                    "sign",
                    "--file",
                    str(file),
                    "--package",
                    "app",
                    "--version",
                    "1.0.0",
                    "--key",
                    f"{prefix}.key.pem",
                    "--out",
                    str(bundle),
                    "--force",
                ]
                verify_args = [
                    "verify",
                    "--file",
                    str(file),
                    "--bundle",
                    str(bundle),
                    "--trust-store",
                    str(store),
                    "--package",
                    "app",
                    "--version",
                    "1.0.0",
                    "--json",
                ]
                measure(algorithm, size, "cli_sign", lambda a=sign_args: command(a))
                measure(algorithm, size, "cli_verify", lambda a=verify_args: command(a))
                sizes.append(
                    {
                        "algorithm": algorithm,
                        "artifact_bytes": size,
                        "artifact_sha256": hashlib.sha256(data).hexdigest(),
                        "public_key_der_bytes": len(
                            public_bytes(public, serialization.Encoding.DER)
                        ),
                        "private_key_der_bytes": len(
                            private_bytes(key, serialization.Encoding.DER)
                        ),
                        "signature_bytes": len(signature),
                        "manifest_bytes": len(message),
                        "bundle_bytes": bundle.stat().st_size,
                    }
                )
                print(f"Measured {algorithm}: {size} bytes", flush=True)
    environment = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "unknown"),
        "logical_cpus": os.cpu_count(),
        "python": sys.version,
        "anticnspy": __version__,
        "cryptography": cryptography.__version__,
        "openssl_backend": backend.openssl_version_text(),
        "clock": "time.perf_counter_ns (monotonic)",
        "percentile": "nearest-rank: sorted_samples[ceil(0.95*n)-1]",
        "iterations": args.iterations,
        "warmups": args.warmups,
        "artifact_generation": "repeat bytes 0..255 and truncate to requested length",
        "crypto_timing": (
            "Profile operations on original manifest bytes; internal hash included; "
            "artifact I/O/hash excluded"
        ),
        "cli_timing": (
            "Full new Python process including startup, I/O, hashing, validation and output"
        ),
    }
    with (args.out / "raw.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["algorithm", "artifact_bytes", "metric", "iteration", "nanoseconds"]
        )
        writer.writeheader()
        writer.writerows(rows)
    (args.out / "summary.json").write_bytes(
        document_bytes({"environment": environment, "timings": summaries, "sizes": sizes})
    )
    lines = [
        "# Benchmark results",
        "",
        "Timings are milliseconds. P95 uses nearest rank.",
        "",
        "| Algorithm | Artifact bytes | Operation | Median ms | P95 ms |",
        "| --- | ---: | --- | ---: | ---: |",
    ]
    for row in summaries:
        lines.append(
            f"| {row['algorithm']} | {row['artifact_bytes']} | {row['metric']} | "
            f"{row['median_ns'] / 1e6:.6f} | {row['p95_ns'] / 1e6:.6f} |"
        )
    lines.extend(["", "Environment:", "", "```json", json.dumps(environment, indent=2), "```", ""])
    (args.out / "README.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
