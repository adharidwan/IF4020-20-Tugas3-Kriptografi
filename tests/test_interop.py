import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric import utils

from anticnspy import crypto
from anticnspy.formats import PROFILES
from anticnspy.keys import load_private, load_public

OPENSSL = shutil.which("openssl")


@pytest.mark.skipif(OPENSSL is None, reason="External OpenSSL executable is not installed")
@pytest.mark.parametrize("algorithm", PROFILES)
def test_openssl_bidirectional(release, algorithm):
    item = release(algorithm)
    message = b"AntiCNSpy interoperability message\n"
    directory = item["file"].parent
    message_path = directory / "message.bin"
    signature_path = directory / "signature.bin"
    external_path = directory / "external.bin"
    message_path.write_bytes(message)
    key = load_private(item["key"].read_bytes())
    public = load_public(item["public"].read_bytes())
    signature = crypto.sign(key, message)
    options = []
    if algorithm == PROFILES[0]:
        options = [
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:32",
            "-sigopt",
            "rsa_mgf1_md:sha256",
        ]
    elif algorithm == PROFILES[1]:
        signature = utils.encode_dss_signature(
            int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        )
    signature_path.write_bytes(signature)
    if algorithm == "ed25519":
        verify_args = [
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(item["public"]),
            "-sigfile",
            str(signature_path),
            "-in",
            str(message_path),
        ]
        sign_args = [
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(item["key"]),
            "-in",
            str(message_path),
            "-out",
            str(external_path),
        ]
    else:
        verify_args = [
            "dgst",
            "-sha256",
            "-verify",
            str(item["public"]),
            "-signature",
            str(signature_path),
            *options,
            str(message_path),
        ]
        sign_args = [
            "dgst",
            "-sha256",
            "-sign",
            str(item["key"]),
            *options,
            "-out",
            str(external_path),
            str(message_path),
        ]
    for args in (verify_args, sign_args):
        completed = subprocess.run([OPENSSL, *args], capture_output=True, timeout=30)
        assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    external = external_path.read_bytes()
    if algorithm == PROFILES[1]:
        r, s = utils.decode_dss_signature(external)
        external = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert crypto.verify(public, message, external)
