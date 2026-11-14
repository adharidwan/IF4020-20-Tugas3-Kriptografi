import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path

from anticnspy import trust
from anticnspy.formats import PROFILES, document_bytes, encode_b64, serialize_manifest
from anticnspy.keys import keygen
from anticnspy.signing import sign_file


def main():
    parser = argparse.ArgumentParser(
        description="Generate explicitly public test-only fixtures and execute U01-U14 via the CLI."
    )
    parser.add_argument("--out", type=Path, default=Path("test_cases"))
    args = parser.parse_args()
    root = args.out
    keys = root / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    for algorithm in PROFILES:
        keygen(algorithm, keys / algorithm, force=True)
    (keys / "README.md").write_text(
        "# PUBLIC TEST KEYS\n\nThese private keys are intentionally public test fixtures. "
        "Never use them for real releases or as CI signing secrets. "
        "Regeneration changes all fingerprints and bundles.\n",
        encoding="utf-8",
    )
    results = []

    def case(
        case_id,
        description,
        expected="OK",
        *,
        algorithm="ed25519",
        data=b"abc\x00\xff\n",
        filename="app.bin",
        mutate=None,
        expected_version="1.0.0",
    ):
        directory = root / "fixtures" / case_id
        directory.mkdir(parents=True, exist_ok=True)
        file = directory / filename
        bundle = directory / "release.json"
        store = directory / "trust.json"
        file.write_bytes(data)
        store.write_bytes(document_bytes(trust.empty_store()))
        trust.add(keys / f"{algorithm}.pub.pem", "app", store)
        sign_file(file, "app", "1.0.0", keys / f"{algorithm}.key.pem", bundle, force=True)
        document = json.loads(bundle.read_bytes())
        context = {"file": file, "bundle": bundle, "store": store, "document": document}
        if mutate:
            mutate(context)
        file = context["file"]
        manifest = base64.b64decode(json.loads(bundle.read_bytes())["manifest_b64"])
        (directory / "manifest.bin").write_bytes(manifest)
        command = [
            "verify",
            "--file",
            file.as_posix(),
            "--bundle",
            bundle.as_posix(),
            "--trust-store",
            store.as_posix(),
            "--package",
            "app",
            "--version",
            expected_version,
            "--json",
        ]
        completed = subprocess.run(
            [sys.executable, "-m", "anticnspy", *command],
            capture_output=True,
            text=True,
            timeout=30,
        )
        checked = json.loads(completed.stdout)
        expected_code = 0 if expected == "OK" else 1
        record = {
            "id": case_id,
            "description": description,
            "algorithm": algorithm,
            "command": ["python", "-m", "anticnspy", *command],
            "expected_status": expected,
            "expected_exit_code": expected_code,
            "actual_exit_code": completed.returncode,
            "result": checked,
            "passed": checked["status"] == expected and completed.returncode == expected_code,
        }
        (directory / "case.json").write_bytes(document_bytes(record))
        (directory / "stdout.json").write_text(completed.stdout, encoding="utf-8")
        (directory / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
        results.append(record)
        return context

    def save(context):
        context["bundle"].write_bytes(document_bytes(context["document"]))

    def manifest_change(context, **changes):
        manifest = json.loads(base64.b64decode(context["document"]["manifest_b64"]))
        manifest.update(changes)
        context["document"]["manifest_b64"] = encode_b64(serialize_manifest(manifest))
        save(context)

    for algorithm in PROFILES:
        for kind, content in (
            ("text", b"hello\r\nworld\n"),
            ("binary", bytes(range(256))),
            ("empty", b""),
        ):
            case(
                f"U01-{algorithm}-{kind}",
                f"Correct {kind} artifact",
                algorithm=algorithm,
                data=content,
            )
    case(
        "U02",
        "Same-size single-byte mutation",
        "ARTIFACT_MISMATCH",
        mutate=lambda c: c["file"].write_bytes(b"z" + c["file"].read_bytes()[1:]),
    )
    case(
        "U03-insert",
        "Insert an artifact byte",
        "ARTIFACT_MISMATCH",
        mutate=lambda c: c["file"].write_bytes(c["file"].read_bytes() + b"x"),
    )
    case(
        "U03-delete",
        "Delete an artifact byte",
        "ARTIFACT_MISMATCH",
        mutate=lambda c: c["file"].write_bytes(c["file"].read_bytes()[:-1]),
    )
    case(
        "U04",
        "Changed canonical version, original signature",
        "INVALID_SIGNATURE",
        mutate=lambda c: manifest_change(c, version="2.0.0"),
    )

    def flip_signature(c):
        signature = bytearray(base64.b64decode(c["document"]["signature_b64"]))
        signature[0] ^= 1
        c["document"]["signature_b64"] = encode_b64(signature)
        save(c)

    case("U05", "One signature bit changed", "INVALID_SIGNATURE", mutate=flip_signature)
    case(
        "U06-empty",
        "Empty store",
        "KEY_NOT_TRUSTED",
        mutate=lambda c: c["store"].write_bytes(document_bytes(trust.empty_store())),
    )
    case(
        "U06-remove",
        "Removed publisher key",
        "KEY_NOT_TRUSTED",
        mutate=lambda c: trust.remove(trust.list_keys(c["store"])[0]["keyid"], c["store"]),
    )

    def other_permission(c):
        store = json.loads(c["store"].read_bytes())
        store["keys"][0]["packages"] = ["other"]
        c["store"].write_bytes(document_bytes(store))

    case("U07", "Key permitted only for other package", "KEY_NOT_TRUSTED", mutate=other_permission)
    case("U08", "Different expected version", "METADATA_MISMATCH", expected_version="2.0.0")

    def rename(c):
        renamed = c["file"].with_name("renamed.bin")
        renamed.write_bytes(c["file"].read_bytes())
        c["file"].unlink()
        c["file"] = renamed

    case("U09", "Renamed artifact", "METADATA_MISMATCH", mutate=rename)

    def malformed(c, kind):
        if kind == "duplicate":
            c["bundle"].write_bytes(
                c["bundle"].read_bytes().replace(b'"schema":', b'"schema":"duplicate","schema":')
            )
        else:
            field = "signature_b64" if kind == "base64" else "manifest_b64"
            value = {"type": 7, "base64": "@@@=", "oversize": encode_b64(b" " * 16385)}[kind]
            c["document"][field] = value
            save(c)

    for kind in ("duplicate", "type", "base64", "oversize"):
        if kind == "type":

            def wrong_signature_type(c):
                c["document"]["signature_b64"] = 7
                save(c)

            mutation = wrong_signature_type
        else:

            def mutation(c, k=kind):
                return malformed(c, k)

        case(f"U10-{kind}", f"Malformed {kind}", "FORMAT_ERROR", mutate=mutation)
    case(
        "U11",
        "Unsupported algorithm string",
        "UNSUPPORTED_ALGORITHM",
        mutate=lambda c: manifest_change(c, algorithm="unknown-profile"),
    )

    keygen("ed25519", keys / "untrusted", force=True)

    def untrusted(c):
        sign_file(c["file"], "app", "1.0.0", keys / "untrusted.key.pem", c["bundle"], force=True)

    case("U12", "Different untrusted key of same profile", "KEY_NOT_TRUSTED", mutate=untrusted)
    case(
        "U13",
        "Reformatted and reordered outer bundle",
        mutate=lambda c: c["bundle"].write_text(
            json.dumps(dict(reversed(list(c["document"].items()))), indent=5), encoding="utf-8"
        ),
    )
    for algorithm in PROFILES:
        context = case(
            f"U14-{algorithm}-first", "First signature of identical manifest", algorithm=algorithm
        )
        first = json.loads(context["bundle"].read_bytes())
        second_path = context["bundle"].with_name("second.json")
        sign_file(
            context["file"], "app", "1.0.0", keys / f"{algorithm}.key.pem", second_path, force=True
        )
        second = json.loads(second_path.read_bytes())
        repeat_command = results[-1]["command"].copy()
        repeat_command[repeat_command.index("--bundle") + 1] = second_path.as_posix()
        completed = subprocess.run(
            [sys.executable, *repeat_command[1:]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        identical = first["signature_b64"] == second["signature_b64"]
        results[-1]["repeat"] = {
            "command": repeat_command,
            "result": json.loads(completed.stdout),
            "exit_code": completed.returncode,
            "signature_identical": identical,
            "manifest_identical": first["manifest_b64"] == second["manifest_b64"],
        }
        results[-1]["passed"] &= (
            completed.returncode == 0
            and identical == (algorithm == "ed25519")
            and first["manifest_b64"] == second["manifest_b64"]
        )
        directory = context["bundle"].parent
        (directory / "case.json").write_bytes(document_bytes(results[-1]))
        (directory / "second.stdout.json").write_text(completed.stdout, encoding="utf-8")
        (directory / "second.stderr.txt").write_text(completed.stderr, encoding="utf-8")
    summary = {
        "test_only_keys": True,
        "cases": results,
        "passed": all(r["passed"] for r in results),
    }
    (root / "results").mkdir(exist_ok=True)
    (root / "results" / "scenarios.json").write_bytes(document_bytes(summary))
    print(f"{sum(r['passed'] for r in results)}/{len(results)} evidence scenarios passed.")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
