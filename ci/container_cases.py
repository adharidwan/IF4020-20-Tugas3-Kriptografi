import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "C01-C05 consumer harness. Requires only Python stdlib and Docker on the runner.\n\n"
            "Uses pre-provisioned private keys and independent public trust configuration.\n"
            "It never automatically trusts a key supplied by a bundle or newly signed release.\n"
        )
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--keys-dir", type=Path, required=True)
    parser.add_argument("--trust-dir", type=Path, default=Path("ci/trust"))
    parser.add_argument("--out", type=Path, default=Path("test_cases/ci"))
    parser.add_argument(
        "--allow-local-image",
        action="store_true",
        help="Development only: skip registry pull/digest requirement",
    )
    args = parser.parse_args()
    if not args.allow_local_image and not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.image):
        parser.error("Consumer image must be pinned by its published SHA-256 digest.")
    for algorithm in PROFILES:
        for required in (
            args.keys_dir / f"{algorithm}.key.pem",
            args.trust_dir / f"{algorithm}.json",
        ):
            if not required.is_file():
                parser.error(f"Missing pre-provisioned input: {required}")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("Use a clean output directory to avoid stale deployment markers.")
    args.out.mkdir(parents=True, exist_ok=True)
    records = []

    def process(command):
        return subprocess.run(command, capture_output=True, text=True, timeout=180)

    if not args.allow_local_image:
        pulled = process(["docker", "pull", args.image])
        (args.out / "pull.log").write_text(pulled.stdout + pulled.stderr, encoding="utf-8")
        if pulled.returncode:
            raise RuntimeError("Published image pull failed; deployment is blocked.")

    inspected = process(["docker", "image", "inspect", args.image])
    if inspected.returncode:
        raise RuntimeError("Cannot inspect the tool image.")
    image_metadata = json.loads(inspected.stdout)[0]

    uid = (
        ["--user", f"{os.getuid()}:{os.getgid()}"]
        if hasattr(os, "getuid")
        else ["--user", "65532:65532"]
    )

    def docker(arguments, mounts):
        command = ["docker", "run", "--rm", "--network", "none", *uid]
        for source, destination, writable in mounts:
            spec = f"type=bind,src={Path(source).resolve()},dst={destination}"
            if not writable:
                spec += ",readonly"
            command.extend(["--mount", spec])
        return process([*command, args.image, *arguments])

    def scenario(identifier, algorithm, mutation=None, expected="OK", expected_code=0):
        directory = args.out / f"{identifier}-{algorithm}"
        directory.mkdir()
        inputs, output = directory / "input", directory / "output"
        inputs.mkdir()
        output.mkdir()
        artifact = inputs / "app.bin"
        artifact.write_bytes(b"AntiCNSpy demo build\n" + bytes(range(256)))
        expected_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        signed = docker(
            [
                "sign",
                "--file",
                "/input/app.bin",
                "--package",
                "anticnspy-demo",
                "--version",
                "1.0.0",
                "--key",
                "/run/publisher.key.pem",
                "--out",
                "/output/release.json",
            ],
            [
                (inputs, "/input", False),
                (output, "/output", True),
                (args.keys_dir / f"{algorithm}.key.pem", "/run/publisher.key.pem", False),
            ],
        )
        (directory / "sign.log").write_text(signed.stdout + signed.stderr, encoding="utf-8")
        if signed.returncode:
            raise RuntimeError(f"{identifier}: signing failed: {signed.stderr}")
        store = args.trust_dir / f"{algorithm}.json"
        file_argument = "/input/app.bin"
        if mutation == "tamper":
            data = bytearray(artifact.read_bytes())
            data[0] ^= 1
            artifact.write_bytes(data)
        elif mutation == "empty_trust":
            store = inputs / "empty-trust.json"
            store.write_text('{"schema":"minisign-trust/v1","keys":[]}', encoding="utf-8")
        elif mutation == "missing":
            file_argument = "/input/missing.bin"
        checked = docker(
            [
                "verify",
                "--file",
                file_argument,
                "--bundle",
                "/output/release.json",
                "--trust-store",
                "/trust.json",
                "--package",
                "anticnspy-demo",
                "--version",
                "1.0.0",
                "--json",
            ],
            [(inputs, "/input", False), (output, "/output", False), (store, "/trust.json", False)],
        )

        marker = output / "deployed.marker"
        if checked.returncode == 0:
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != expected_digest:
                raise RuntimeError("Verified artifact changed before deployment.")
            marker.write_text(expected_digest + "\n", encoding="ascii")
        (directory / "verification.json").write_text(checked.stdout, encoding="utf-8")
        (directory / "verify.stderr.txt").write_text(checked.stderr, encoding="utf-8")
        result = json.loads(checked.stdout)
        passed = (
            checked.returncode == expected_code
            and result["status"] == expected
            and result["valid"] == (expected_code == 0)
            and marker.exists() == (expected_code == 0)
        )
        record = {
            "id": identifier,
            "algorithm": algorithm,
            "expected_status": expected,
            "actual_status": result["status"],
            "expected_exit_code": expected_code,
            "actual_exit_code": checked.returncode,
            "deployment_marker_exists": marker.exists(),
            "passed": passed,
        }
        records.append(record)
        print(json.dumps(record), flush=True)
        if not passed:
            raise RuntimeError(f"{identifier} did not satisfy its acceptance criteria.")

    for algorithm in PROFILES:
        scenario("C01", algorithm)
    scenario("C02", "ed25519", "tamper", "ARTIFACT_MISMATCH", 1)
    scenario("C03", "ed25519", "empty_trust", "KEY_NOT_TRUSTED", 1)
    scenario("C04", "ed25519", "missing", "INPUT_ERROR", 2)

    with tempfile.TemporaryDirectory(prefix="anticnspy-c05-") as temporary:
        scratch = Path(temporary)
        if os.name == "posix":
            scratch.chmod(0o700)
        commands = [
            ["--help"],
            ["--version"],
            ["keygen", "--algorithm", "ed25519", "--out", "/scratch/key"],
            [
                "trust",
                "add",
                "--key",
                "/scratch/key.pub.pem",
                "--package",
                "scratch",
                "--store",
                "/scratch/trust.json",
            ],
            ["trust", "list", "--store", "/scratch/trust.json"],
        ]
        offline_results = []
        for command in commands:
            completed = docker(command, [(scratch, "/scratch", True)])
            offline_results.append(
                {
                    "arguments": command,
                    "exit_code": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                }
            )
            if completed.returncode:
                raise RuntimeError(f"C05 command failed: {completed.stderr}")

        keyid = json.loads((scratch / "trust.json").read_text())["keys"][0]["keyid"]
        completed = docker(
            ["trust", "remove", "--keyid", keyid, "--store", "/scratch/trust.json"],
            [(scratch, "/scratch", True)],
        )
        if completed.returncode or json.loads((scratch / "trust.json").read_text())["keys"]:
            raise RuntimeError("C05 offline trust removal failed.")
        offline_results.append(
            {
                "arguments": ["trust", "remove"],
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        )
        (args.out / "C05.log.json").write_text(
            json.dumps(offline_results, indent=2) + "\n", encoding="utf-8"
        )
    records.append(
        {
            "id": "C05",
            "network": "none",
            "tty": False,
            "caller_identity": uid[-1],
            "persistent_outputs": True,
            "passed": True,
        }
    )
    summary = {
        "image": args.image,
        "local_image_id": image_metadata["Id"],
        "image_platform": image_metadata["Os"] + "/" + image_metadata["Architecture"],
        "repo_digests": image_metadata.get("RepoDigests", []),
        "registry_pull": not args.allow_local_image,
        "workflow_run": os.environ.get("GITHUB_RUN_ID"),
        "cases": records,
        "passed": all(r["passed"] for r in records),
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
