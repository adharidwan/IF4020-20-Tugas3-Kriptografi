import json
import subprocess
import sys

import pytest


def run(*args):
    return subprocess.run(
        [sys.executable, "-m", "anticnspy", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    "args",
    [
        ("--help",),
        ("--version",),
        ("keygen", "--help"),
        ("sign", "--help"),
        ("verify", "--help"),
        ("trust", "add", "--help"),
        ("trust", "list", "--help"),
        ("trust", "remove", "--help"),
    ],
)
def test_help_and_version(args):
    completed = run(*args)
    assert completed.returncode == 0
    assert completed.stdout


def test_json_usage_failure():
    completed = run("verify", "--json")
    assert completed.returncode == 2
    checked = json.loads(completed.stdout)
    assert checked == {
        "valid": False,
        "status": "INPUT_ERROR",
        "message": checked["message"],
        "algorithm": None,
        "keyid": None,
        "package": None,
        "version": None,
    }
    assert completed.stdout.endswith("\n") and len(completed.stdout.splitlines()) == 1
    assert completed.stderr


@pytest.mark.parametrize(
    "case,code,status",
    [("ok", 0, "OK"), ("tamper", 1, "ARTIFACT_MISMATCH"), ("missing", 2, "INPUT_ERROR")],
)
def test_verify_process_contract(release, case, code, status):
    item = release()
    if case == "tamper":
        item["file"].write_bytes(b"bad")
    elif case == "missing":
        item["file"].unlink()
    completed = run(
        "verify",
        "--file",
        item["file"],
        "--bundle",
        item["bundle"],
        "--trust-store",
        item["store"],
        "--package",
        "app",
        "--version",
        "1.0.0",
        "--json",
    )
    assert completed.returncode == code
    checked = json.loads(completed.stdout)
    assert checked["status"] == status and checked["valid"] == (code == 0)
    assert len(completed.stdout.splitlines()) == 1
    assert set(checked) == {
        "valid",
        "status",
        "message",
        "algorithm",
        "keyid",
        "package",
        "version",
    }


def test_full_cli_lifecycle(tmp_path):
    prefix = tmp_path / "publisher"
    generated = run("keygen", "--algorithm", "ed25519", "--out", prefix)
    assert generated.returncode == 0, generated.stderr
    keyid = json.loads(generated.stdout)["keyid"]
    store = tmp_path / "trust.json"
    assert (
        run(
            "trust", "add", "--key", f"{prefix}.pub.pem", "--package", "app", "--store", store
        ).returncode
        == 0
    )
    assert keyid in run("trust", "list", "--store", store).stdout
    file = tmp_path / "app.txt"
    file.write_bytes(b"hello\n")
    bundle = tmp_path / "bundle.json"
    signed = run(
        "sign",
        "--file",
        file,
        "--package",
        "app",
        "--version",
        "1.0.0",
        "--key",
        f"{prefix}.key.pem",
        "--out",
        bundle,
    )
    assert signed.returncode == 0, signed.stderr
    assert run("trust", "remove", "--keyid", keyid, "--store", store).returncode == 0
    assert run("trust", "remove", "--keyid", keyid, "--store", store).returncode == 2


def test_abbreviated_options_rejected():
    assert run("keygen", "--alg", "ed25519", "--out", "unused").returncode == 2
