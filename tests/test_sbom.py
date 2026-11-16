import json

import pytest

from anticnspy import sbom
from anticnspy.cli import main
from anticnspy.errors import FormatError, InputError
from anticnspy.formats import PROFILES


@pytest.fixture
def signed_sbom(release):
    def make(algorithm="ed25519"):
        case = release(algorithm)
        case["sbom"] = case["file"].with_name("sbom.json")
        case["sbom_bundle"] = case["file"].with_name("sbom.bundle.json")
        sbom.create(
            case["file"], "app", "1.0.0", case["sbom"], dependencies=["cryptography==50.0.2"]
        )
        sbom.sign(case["sbom"], "app", "1.0.0", case["key"], case["sbom_bundle"])
        return case

    return make


def verify(case, package="app", version="1.0.0"):
    return sbom.verify(case["sbom"], case["sbom_bundle"], case["store"], package, version)


@pytest.mark.parametrize("algorithm", PROFILES)
def test_signed_sbom_roundtrip(signed_sbom, algorithm):
    case = signed_sbom(algorithm)
    checked = verify(case)
    assert checked.valid and checked.algorithm == algorithm
    assert sbom.check(case["sbom"], case["file"]).status == "OK"


def test_sbom_records_artifact_hash(signed_sbom):
    case = signed_sbom()
    document = json.loads(case["sbom"].read_bytes())
    component = document["metadata"]["component"]
    assert component["hashes"] == [
        {"alg": "SHA-256", "content": case["manifest"]["artifact"]["sha256"]}
    ]
    assert document["components"] == [
        {"type": "library", "name": "cryptography", "version": "50.0.2"}
    ]


def test_sbom_bundle_uses_release_bundle_format(signed_sbom):
    case = signed_sbom()
    bundle = json.loads(case["sbom_bundle"].read_bytes())
    assert set(bundle) == {"schema", "manifest_b64", "signature_b64"}
    assert bundle["schema"] == "minisign-bundle/v1"


def test_changed_sbom_is_rejected(signed_sbom):
    case = signed_sbom()
    raw = case["sbom"].read_bytes()
    case["sbom"].write_bytes(
        raw.replace(case["manifest"]["artifact"]["sha256"].encode(), b"0" * 64)
    )
    checked = verify(case)
    assert checked.status == "ARTIFACT_MISMATCH" and checked.exit_code == 1


def test_changed_sbom_version_is_rejected(signed_sbom):
    case = signed_sbom()
    raw = case["sbom"].read_bytes()
    case["sbom"].write_bytes(raw.replace(b'"version": "1.0.0"', b'"version": "9.9.9"'))
    assert verify(case).status == "ARTIFACT_MISMATCH"


def test_replaced_artifact_is_rejected(signed_sbom):
    case = signed_sbom()
    case["file"].write_bytes(b"replaced artifact with other content")
    checked = sbom.check(case["sbom"], case["file"])
    assert checked.status == "ARTIFACT_MISMATCH" and checked.exit_code == 1
    assert verify(case).valid


def test_same_size_replaced_artifact_is_rejected(signed_sbom):
    case = signed_sbom()
    raw = bytearray(case["file"].read_bytes())
    raw[0] ^= 1
    case["file"].write_bytes(bytes(raw))
    assert sbom.check(case["sbom"], case["file"]).status == "ARTIFACT_MISMATCH"


def test_renamed_artifact_is_rejected(signed_sbom):
    case = signed_sbom()
    renamed = case["file"].rename(case["file"].with_name("other.bin"))
    assert sbom.check(case["sbom"], renamed).status == "METADATA_MISMATCH"


def test_untrusted_sbom_signer(signed_sbom, tmp_path):
    case = signed_sbom()
    empty = tmp_path / "empty.json"
    empty.write_text('{"schema":"minisign-trust/v1","keys":[]}')
    checked = sbom.verify(case["sbom"], case["sbom_bundle"], empty, "app", "1.0.0")
    assert checked.status == "KEY_NOT_TRUSTED"


def test_release_bundle_does_not_verify_sbom(signed_sbom):
    case = signed_sbom()
    checked = sbom.verify(case["sbom"], case["bundle"], case["store"], "app", "1.0.0")
    assert checked.status == "METADATA_MISMATCH"


def test_wrong_expected_version(signed_sbom):
    assert verify(signed_sbom(), version="2.0.0").status == "METADATA_MISMATCH"


def test_sign_rejects_sbom_for_other_release(signed_sbom):
    case = signed_sbom()
    with pytest.raises(InputError):
        sbom.sign(case["sbom"], "app", "2.0.0", case["key"], case["sbom_bundle"], force=True)


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b'{"bomFormat":"SPDX"}',
        b'{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{}}',
        b'{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":'
        b'{"name":"app","version":"1.0.0","hashes":[],"properties":[]}}}',
    ],
)
def test_malformed_sbom(raw):
    with pytest.raises(FormatError):
        sbom.parse(raw)


def test_malformed_sbom_check(signed_sbom):
    case = signed_sbom()
    case["sbom"].write_bytes(b"not json")
    assert sbom.check(case["sbom"], case["file"]).status == "FORMAT_ERROR"


def test_missing_artifact_check(signed_sbom):
    case = signed_sbom()
    case["file"].unlink()
    checked = sbom.check(case["sbom"], case["file"])
    assert checked.status == "INPUT_ERROR" and checked.exit_code == 2


def test_bad_dependency(release, tmp_path):
    case = release()
    with pytest.raises(InputError):
        sbom.create(case["file"], "app", "1.0.0", tmp_path / "s.json", dependencies=["nover"])


def test_cli_sbom_flow(signed_sbom, capsys):
    case = signed_sbom()
    common = ["--sbom", str(case["sbom"])]
    code = main(
        [
            "sbom",
            "verify",
            *common,
            "--bundle",
            str(case["sbom_bundle"]),
            "--trust-store",
            str(case["store"]),
            "--package",
            "app",
            "--version",
            "1.0.0",
            "--json",
        ]
    )
    assert code == 0 and json.loads(capsys.readouterr().out)["status"] == "OK"
    assert main(["sbom", "check", *common, "--file", str(case["file"])]) == 0
    case["file"].write_bytes(b"other")
    assert main(["sbom", "check", *common, "--file", str(case["file"]), "--json"]) == 1
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["status"] == "ARTIFACT_MISMATCH"


def test_cli_sbom_usage_error_json(capsys):
    assert main(["sbom", "check", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "INPUT_ERROR"
