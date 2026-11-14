import base64
import hashlib
import re
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .errors import FormatError, InputError
from .formats import PROFILES
from .storage import atomic_write

ALGORITHM_IDENTIFIERS = {
    "rsa-pss-sha256": bytes.fromhex("300d06092a864886f70d0101010500"),
    "ecdsa-p256-sha256": bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107"),
    "ed25519": bytes.fromhex("300506032b6570"),
}
KEY_LIMIT = 64 * 1024


def profile(key) -> str:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        pub = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
        if pub.key_size != 3072 or pub.public_numbers().e != 65537:
            raise FormatError("RSA requires exactly 3072 bits and exponent 65537.")
        return PROFILES[0]
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if not isinstance(key.curve, ec.SECP256R1):
            raise FormatError("ECDSA requires the named P-256 curve.")
        return PROFILES[1]
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return PROFILES[2]
    raise FormatError("Unsupported key type.")


def generate(algorithm: str):
    if algorithm == PROFILES[0]:
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if algorithm == PROFILES[1]:
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == PROFILES[2]:
        return ed25519.Ed25519PrivateKey.generate()
    raise InputError("Unsupported key-generation algorithm.")


def private_bytes(key, encoding=serialization.Encoding.PEM) -> bytes:
    return key.private_bytes(
        encoding, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def public_bytes(key, encoding=serialization.Encoding.PEM) -> bytes:
    return key.public_bytes(encoding, serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(public_key) -> str:
    return hashlib.sha256(public_bytes(public_key, serialization.Encoding.DER)).hexdigest()


def _unarmor(raw: bytes, label: bytes) -> bytes:
    if len(raw) > KEY_LIMIT:
        raise FormatError("PEM key exceeds 64 KiB.")
    pattern = (
        rb"\s*-----BEGIN " + label + rb"-----\s+"
        rb"([A-Za-z0-9+/=\r\n\t ]+)-----END " + label + rb"-----\s*"
    )
    match = re.fullmatch(pattern, raw)
    if match is None:
        raise FormatError(f"Expected one PEM block labeled {label.decode()}.")
    try:
        return base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
    except ValueError as exc:
        raise FormatError("Invalid PEM encoding.") from exc


def _tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:

    start = offset
    if offset + 2 > len(data):
        raise FormatError("Truncated DER key.")
    tag, length = data[offset : offset + 2]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4 or offset + count > len(data):
            raise FormatError("Invalid DER length.")
        if data[offset] == 0:
            raise FormatError("Noncanonical DER length.")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
        if length < 128:
            raise FormatError("Noncanonical DER length.")
    end = offset + length
    if end > len(data) or end <= start:
        raise FormatError("Truncated DER key.")
    return tag, data[offset:end], end


def _check_envelope(der: bytes, algorithm: str, *, private: bool) -> None:
    tag, content, end = _tlv(der)
    if tag != 0x30 or end != len(der):
        raise FormatError("Invalid DER key envelope.")
    offset = 0
    if private:
        tag, _, offset = _tlv(content)
        if tag != 0x02:
            raise FormatError("Invalid PKCS8 version.")
    start = offset
    tag, _, offset = _tlv(content, offset)
    if tag != 0x30 or content[start:offset] != ALGORITHM_IDENTIFIERS[algorithm]:
        raise FormatError("Key AlgorithmIdentifier does not match the required profile.")
    tag, value, end = _tlv(content, offset)
    if private:
        if tag != 0x04:
            raise FormatError("Invalid PKCS8 private-key field.")
    elif tag != 0x03 or not value or value[0] != 0 or end != len(content):
        raise FormatError("Invalid SPKI public-key field.")
    elif algorithm == PROFILES[1] and (len(value) != 66 or value[1] != 4):
        raise FormatError("P-256 SPKI requires an uncompressed SEC1 point.")


def load_public(raw: bytes):
    der = _unarmor(raw, b"PUBLIC KEY")
    try:
        key = serialization.load_der_public_key(der)
        algorithm = profile(key)
        _check_envelope(der, algorithm, private=False)
        if public_bytes(key, serialization.Encoding.DER) != der:
            raise FormatError("Public key must use standard DER SPKI encoding.")
        return key
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, FormatError):
            raise
        raise FormatError("Invalid or unsupported public key.") from exc


def load_private(raw: bytes):
    der = _unarmor(raw, b"PRIVATE KEY")
    try:
        key = serialization.load_der_private_key(der, password=None)
        _check_envelope(der, profile(key), private=True)
        return key
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, FormatError):
            raise
        raise FormatError("Invalid or unsupported PKCS8 private key.") from exc


def keygen(algorithm: str, prefix: str | Path, *, force: bool = False) -> dict:
    secret_path = Path(f"{prefix}.key.pem")
    public_path = Path(f"{prefix}.pub.pem")
    if not force and (secret_path.exists() or public_path.exists()):
        raise InputError("Key output already exists. Use --force to overwrite explicitly.")
    key = generate(algorithm)
    atomic_write(secret_path, private_bytes(key), overwrite=force, mode=0o600)
    try:
        atomic_write(public_path, public_bytes(key.public_key()), overwrite=force)
    except (OSError, InputError):
        if not force:
            secret_path.unlink(missing_ok=True)
        raise
    return {
        "algorithm": algorithm,
        "keyid": fingerprint(key.public_key()),
        "private_key": str(secret_path),
        "public_key": str(public_path),
    }
