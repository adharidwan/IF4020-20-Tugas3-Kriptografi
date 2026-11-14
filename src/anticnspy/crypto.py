from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

from .formats import PROFILES
from .keys import profile

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def sign(key, message: bytes) -> bytes:
    algorithm = profile(key)
    if algorithm == PROFILES[0]:
        return key.sign(message, _pss(), hashes.SHA256())
    if algorithm == PROFILES[1]:
        der = key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return key.sign(message)


def verify(key, message: bytes, signature: bytes) -> bool:
    algorithm = profile(key)
    expected_length = 384 if algorithm == PROFILES[0] else 64
    if len(signature) != expected_length:
        return False
    try:
        if algorithm == PROFILES[0]:
            key.verify(signature, message, _pss(), hashes.SHA256())
        elif algorithm == PROFILES[1]:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
                return False
            key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
