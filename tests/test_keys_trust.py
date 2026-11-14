import base64
import json
import os
import textwrap

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from anticnspy import storage, trust
from anticnspy.errors import FormatError, InputError
from anticnspy.formats import PROFILES, document_bytes
from anticnspy.keys import (
    fingerprint,
    keygen,
    load_private,
    load_public,
    private_bytes,
    profile,
    public_bytes,
)
from anticnspy.signing import sign_file
from anticnspy.verification import verify_file


@pytest.mark.parametrize("algorithm", PROFILES)
def test_key_roundtrip_and_fingerprint_line_endings(key_material, algorithm):
    secret, public = key_material[algorithm]
    private_key = load_private(secret)
    public_key = load_public(public)
    assert profile(private_key) == algorithm
    assert fingerprint(public_key) == fingerprint(private_key.public_key())
    assert fingerprint(load_public(public.replace(b"\n", b"\r\n"))) == fingerprint(public_key)
    body = b"".join(public.splitlines()[1:-1]).decode()
    rewrapped = (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(textwrap.wrap(body, 19))
        + "\n-----END PUBLIC KEY-----\n"
    ).encode()
    assert fingerprint(load_public(rewrapped)) == fingerprint(public_key)


@pytest.mark.parametrize(
    "key",
    [
        lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        lambda: ec.generate_private_key(ec.SECP384R1()),
    ],
)
def test_wrong_key_parameters(key):
    with pytest.raises(FormatError):
        load_public(public_bytes(key().public_key()))


def test_reject_non_pkcs8_private():
    key = ec.generate_private_key(ec.SECP256R1())
    raw = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with pytest.raises(FormatError):
        load_private(raw)


def test_reject_compressed_p256_spki():
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    point = key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    alg = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    content = alg + b"\x03\x22\x00" + point
    der = b"\x30" + bytes([len(content)]) + content
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der) + b"\n-----END PUBLIC KEY-----\n"
    with pytest.raises(FormatError):
        load_public(pem)


def test_ed25519_null_algorithm_parameter_rejected():
    der = public_bytes(
        ed25519.Ed25519PrivateKey.generate().public_key(), serialization.Encoding.DER
    )
    mutated = b"\x30\x2c\x30\x07\x06\x03\x2b\x65\x70\x05\x00" + der[9:]
    pem = (
        b"-----BEGIN PUBLIC KEY-----\n"
        + base64.b64encode(mutated)
        + b"\n-----END PUBLIC KEY-----\n"
    )
    with pytest.raises(FormatError):
        load_public(pem)


def test_add_merges_idempotently_and_remove(release):
    item = release()
    before = item["store"].read_bytes()
    trust.add(item["public"], "app", item["store"])
    assert item["store"].read_bytes() == before
    trust.add(item["public"], "another", item["store"])
    entries = trust.list_keys(item["store"])
    assert len(entries) == 1 and entries[0]["packages"] == ["app", "another"]
    trust.remove(entries[0]["keyid"], item["store"])
    assert trust.list_keys(item["store"]) == []
    with pytest.raises(InputError):
        trust.remove(entries[0]["keyid"], item["store"])


@pytest.mark.parametrize(
    "mutation",
    [
        "fingerprint",
        "profile",
        "wildcard",
        "duplicate_package",
        "empty_packages",
        "duplicate_key",
        "extra_field",
        "invalid_pem",
    ],
)
def test_bad_trust_store_is_format_error(release, mutation):
    item = release()
    store = json.loads(item["store"].read_bytes())
    entry = store["keys"][0]
    if mutation == "fingerprint":
        entry["keyid"] = "0" * 64
    elif mutation == "profile":
        entry["algorithm"] = "ecdsa-p256-sha256"
    elif mutation == "wildcard":
        entry["packages"] = ["*"]
    elif mutation == "duplicate_package":
        entry["packages"] = ["app", "app"]
    elif mutation == "empty_packages":
        entry["packages"] = []
    elif mutation == "duplicate_key":
        store["keys"].append(dict(entry))
    elif mutation == "extra_field":
        entry["extra"] = "no"
    else:
        entry["public_key_pem"] = "invalid"
    item["store"].write_bytes(document_bytes(store))
    assert (
        verify_file(item["file"], item["bundle"], item["store"], "app", "1.0.0").status
        == "FORMAT_ERROR"
    )


def test_atomic_trust_failure_preserves_previous_file(release, monkeypatch):
    item = release()
    before = item["store"].read_bytes()

    def fail_replace(*args):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(storage.os, "replace", fail_replace)
    with pytest.raises(OSError):
        trust.add(item["public"], "other", item["store"])
    assert item["store"].read_bytes() == before
    assert not list(item["store"].parent.glob(".trust.json.*"))


def test_key_overwrite_requires_force(tmp_path):
    prefix = tmp_path / "key"
    keygen("ed25519", prefix)
    before = prefix.with_suffix(".key.pem").read_bytes()
    with pytest.raises(InputError):
        keygen("ed25519", prefix)
    assert prefix.with_suffix(".key.pem").read_bytes() == before
    keygen("ed25519", prefix, force=True)
    assert prefix.with_suffix(".key.pem").read_bytes() != before
    if os.name == "posix":
        assert prefix.with_suffix(".key.pem").stat().st_mode & 0o777 == 0o600


def test_sign_does_not_overwrite_inputs_even_with_force(release):
    item = release()
    original = item["file"].read_bytes()
    with pytest.raises(InputError):
        sign_file(item["file"], "app", "1.0.0", item["key"], item["file"], force=True)
    assert item["file"].read_bytes() == original


def test_key_material_not_in_bundle(release):
    item = release()
    assert b"PRIVATE KEY" not in item["bundle"].read_bytes()
    assert private_bytes(load_private(item["key"].read_bytes())) == item["key"].read_bytes()
