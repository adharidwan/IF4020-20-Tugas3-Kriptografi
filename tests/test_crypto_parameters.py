import base64

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from anticnspy import crypto
from anticnspy.formats import document_bytes, encode_b64
from anticnspy.keys import load_private
from anticnspy.trust import add
from anticnspy.verification import verify_file


@pytest.mark.parametrize("salt_length", [0, 20, 33, padding.PSS.MAX_LENGTH])
def test_rsa_rejects_wrong_pss_salt_length(release, salt_length):
    item = release("rsa-pss-sha256")
    key = load_private(item["key"].read_bytes())
    message = base64.b64decode(item["document"]["manifest_b64"])
    signature = key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length),
        hashes.SHA256(),
    )
    item["document"]["signature_b64"] = encode_b64(signature)
    item["bundle"].write_bytes(document_bytes(item["document"]))
    assert (
        verify_file(item["file"], item["bundle"], item["store"], "app", "1.0.0").status
        == "INVALID_SIGNATURE"
    )


def test_ecdsa_accepts_both_s_forms(release):
    item = release("ecdsa-p256-sha256")
    key = load_private(item["key"].read_bytes()).public_key()
    message = base64.b64decode(item["document"]["manifest_b64"])
    signature = base64.b64decode(item["document"]["signature_b64"])
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    for value in (s, crypto.P256_ORDER - s):
        assert crypto.verify(key, message, r.to_bytes(32, "big") + value.to_bytes(32, "big"))
    assert not crypto.verify(key, message, utils.encode_dss_signature(r, s))


def test_authorized_other_expected_package_reaches_metadata_check(release):
    item = release()
    add(item["public"], "other", item["store"])
    assert (
        verify_file(item["file"], item["bundle"], item["store"], "other", "1.0.0").status
        == "METADATA_MISMATCH"
    )
