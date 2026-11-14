import base64
import json

import pytest

from anticnspy import crypto
from anticnspy.formats import (
    BUNDLE_LIMIT,
    MANIFEST_LIMIT,
    PROFILES,
    TRUST_SCHEMA,
    document_bytes,
    encode_b64,
    serialize_manifest,
)
from anticnspy.keys import fingerprint, generate, load_private, private_bytes
from anticnspy.results import Status
from anticnspy.signing import sign_file
from anticnspy.trust import remove
from anticnspy.verification import verify_file


def check(release, *, package="app", version="1.0.0"):
    return verify_file(release["file"], release["bundle"], release["store"], package, version)


def save_bundle(release):
    release["bundle"].write_bytes(document_bytes(release["document"]))


def mutate_manifest(release, change, *, resign=False):
    manifest = json.loads(base64.b64decode(release["document"]["manifest_b64"]))
    change(manifest)
    message = serialize_manifest(manifest)
    release["document"]["manifest_b64"] = encode_b64(message)
    if resign:
        key = load_private(release["key"].read_bytes())
        release["document"]["signature_b64"] = encode_b64(crypto.sign(key, message))
    save_bundle(release)


@pytest.mark.parametrize("algorithm", PROFILES)
@pytest.mark.parametrize("content", [b"hello\r\nworld\n", bytes(range(256)), b""])
def test_U01_valid_text_binary_empty(release, algorithm, content):
    item = release(algorithm, content)
    assert check(item).status == Status.OK
    assert item["file"].read_bytes() == content


def test_U02_same_size_artifact_mutation(release):
    item = release()
    data = bytearray(item["file"].read_bytes())
    data[0] ^= 1
    item["file"].write_bytes(data)
    assert check(item).status == Status.ARTIFACT_MISMATCH


@pytest.mark.parametrize("change", [lambda b: b + b"x", lambda b: b[:-1]])
def test_U03_insert_delete(release, change):
    item = release()
    item["file"].write_bytes(change(item["file"].read_bytes()))
    assert check(item).status == Status.ARTIFACT_MISMATCH


def test_U04_changed_canonical_version(release):
    item = release()
    mutate_manifest(item, lambda m: m.update(version="2.0.0"))
    assert check(item).status == Status.INVALID_SIGNATURE


@pytest.mark.parametrize("algorithm", PROFILES)
def test_U05_signature_bit_flip(release, algorithm):
    item = release(algorithm)
    signature = bytearray(base64.b64decode(item["document"]["signature_b64"]))
    signature[0] ^= 1
    item["document"]["signature_b64"] = encode_b64(signature)
    save_bundle(item)
    assert check(item).status == Status.INVALID_SIGNATURE


@pytest.mark.parametrize("empty", [True, False])
def test_U06_empty_or_removed_trust(release, empty):
    item = release()
    if empty:
        item["store"].write_bytes(document_bytes({"schema": TRUST_SCHEMA, "keys": []}))
    else:
        remove(item["entry"]["keyid"], item["store"])
    assert check(item).status == Status.KEY_NOT_TRUSTED


def test_U07_permission_for_other_package(release):
    item = release()
    store = json.loads(item["store"].read_bytes())
    store["keys"][0]["packages"] = ["other"]
    item["store"].write_bytes(document_bytes(store))
    assert check(item).status == Status.KEY_NOT_TRUSTED


def test_U08_wrong_expected_version(release):
    assert check(release(), version="2.0.0").status == Status.METADATA_MISMATCH


def test_U09_renamed_artifact(release):
    item = release()
    renamed = item["file"].with_name("renamed.bin")
    item["file"].rename(renamed)
    item["file"] = renamed
    assert check(item).status == Status.METADATA_MISMATCH


@pytest.mark.parametrize("case", ["duplicate", "wrong_type", "base64", "oversized_manifest"])
def test_U10_malformed_documents(release, case):
    item = release()
    if case == "duplicate":
        raw = item["bundle"].read_bytes().replace(b'"schema":', b'"schema":"duplicate","schema":')
        item["bundle"].write_bytes(raw)
    elif case == "wrong_type":
        item["document"]["manifest_b64"] = 17
        save_bundle(item)
    elif case == "base64":
        item["document"]["signature_b64"] = "@@@="
        save_bundle(item)
    else:
        item["document"]["manifest_b64"] = encode_b64(b" " * (MANIFEST_LIMIT + 1))
        save_bundle(item)
    assert check(item).status == Status.FORMAT_ERROR


def test_U11_unknown_algorithm_before_signature(release):
    item = release()
    mutate_manifest(item, lambda m: m.update(algorithm="unknown-profile"))
    assert check(item).status == Status.UNSUPPORTED_ALGORITHM


def test_U12_other_key_same_profile(release):
    item = release()
    other = generate("ed25519")
    item["key"].write_bytes(private_bytes(other))
    sign_file(item["file"], "app", "1.0.0", item["key"], item["bundle"], force=True)
    checked = check(item)
    assert checked.keyid == fingerprint(other.public_key())
    assert checked.status == Status.KEY_NOT_TRUSTED


def test_U13_outer_bundle_whitespace_and_order(release):
    item = release()
    item["bundle"].write_text(json.dumps(dict(reversed(list(item["document"].items()))), indent=5))
    assert check(item).status == Status.OK


@pytest.mark.parametrize("algorithm", PROFILES)
def test_U14_repeated_signatures(release, algorithm):
    item = release(algorithm)
    first = item["document"]
    sign_file(item["file"], "app", "1.0.0", item["key"], item["bundle"], force=True)
    second = json.loads(item["bundle"].read_bytes())
    assert first["manifest_b64"] == second["manifest_b64"]
    assert (first["signature_b64"] == second["signature_b64"]) == (algorithm == "ed25519")
    assert check(item).status == Status.OK
    item["bundle"].write_bytes(document_bytes(first))
    assert check(item).status == Status.OK


@pytest.mark.parametrize("algorithm", PROFILES)
@pytest.mark.parametrize("signature", [b"", b"x", b"\x00" * 64, b"\xff" * 64])
def test_signature_length_or_value_is_signature_failure(release, algorithm, signature):
    item = release(algorithm)
    item["document"]["signature_b64"] = encode_b64(signature)
    save_bundle(item)
    assert check(item).status == Status.INVALID_SIGNATURE


@pytest.mark.parametrize("suffix", [b"\n", b" "])
def test_noncanonical_manifest(release, suffix):
    item = release()
    raw = base64.b64decode(item["document"]["manifest_b64"]) + suffix
    item["document"]["manifest_b64"] = encode_b64(raw)
    save_bundle(item)
    assert check(item).status == Status.FORMAT_ERROR


def test_input_error_precedes_format(release):
    item = release()
    item["bundle"].write_bytes(b"invalid JSON")
    item["store"].unlink()
    assert check(item).status == Status.INPUT_ERROR


def test_malformed_store_precedes_unknown_algorithm(release):
    item = release()
    mutate_manifest(item, lambda m: m.update(algorithm="unknown"))
    item["store"].write_bytes(b"{}")
    assert check(item).status == Status.FORMAT_ERROR


def test_trust_precedes_signature_metadata_and_artifact(release):
    item = release()
    item["store"].write_bytes(document_bytes({"schema": TRUST_SCHEMA, "keys": []}))
    item["document"]["signature_b64"] = encode_b64(b"bad")
    save_bundle(item)
    item["file"].write_bytes(b"changed")
    assert check(item, version="2.0.0").status == Status.KEY_NOT_TRUSTED


def test_metadata_precedes_artifact(release):
    item = release()
    item["file"].write_bytes(b"changed")
    assert check(item, version="2.0.0").status == Status.METADATA_MISMATCH


def test_valid_trust_key_profile_different_from_manifest(release):
    item = release()
    mutate_manifest(item, lambda m: m.update(algorithm="ecdsa-p256-sha256"))
    assert check(item).status == Status.KEY_NOT_TRUSTED


def test_expected_package_controls_permission_check(release):
    assert check(release(), package="other").status == Status.KEY_NOT_TRUSTED


def test_oversized_bundle(release):
    item = release()
    item["bundle"].write_bytes(b" " * (BUNDLE_LIMIT + 1))
    assert check(item).status == Status.FORMAT_ERROR


def test_invalid_expected_metadata_is_input_error(release):
    assert check(release(), package="Invalid/Name").status == Status.INPUT_ERROR
