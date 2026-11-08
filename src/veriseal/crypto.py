"""Cryptographic operations and PEM key handling."""

import hashlib
from typing import NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

_SHA = hashes.SHA256()
_PSS = padding.PSS(mgf=padding.MGF1(_SHA), salt_length=32)
# _N = ec.SECP256R1()
_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_SIG_LEN = {"rsa-pss-sha256": 384, "ecdsa-p256-sha256": 64, "ed25519": 64}


class KeyInfo(NamedTuple):
    is_private: bool
    profile: str
    public_key_pem: str
    keyid: str


def _der(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _pem(pub) -> str:
    return pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _profile(pub) -> str:
    """Map a public key object to its profile; ValueError if params are wrong."""
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size == 3072 and pub.public_numbers().e == 65537:
            return "rsa-pss-sha256"
        raise ValueError("RSA key must be 3072-bit with e=65537")
    if isinstance(pub, ec.EllipticCurvePublicKey):
        if isinstance(pub.curve, ec.SECP256R1):
            return "ecdsa-p256-sha256"
        raise ValueError("EC key must be P-256")
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ed25519"
    raise ValueError("unsupported key type")


def _load(pem_str: str):
    """Return (key_object, is_private). ValueError if not a valid PKCS8/SPKI PEM."""
    # data = pem_str.encode()
    s = pem_str.strip()
    data = s.encode()
    try:
        if s.startswith("-----BEGIN PRIVATE KEY-----") and s.endswith("-----END PRIVATE KEY-----"):
            return serialization.load_pem_private_key(data, password=None), True
        # return serialization.load_pem_public_key(data), False
        if s.startswith("-----BEGIN PUBLIC KEY-----") and s.endswith("-----END PUBLIC KEY-----"):
            return serialization.load_pem_public_key(data), False
        raise ValueError("PEM key must be PKCS#8 (PRIVATE KEY) or SPKI (PUBLIC KEY)")
    except Exception as e:
        raise ValueError(f"invalid PEM key: {e}") from e


def generate_keypair(profile: str) -> tuple[str, str, str]:
    """Return (private_pem, public_pem, keyid)."""
    if profile == "rsa-pss-sha256":
        priv = rsa.generate_private_key(65537, 3072)
    elif profile == "ecdsa-p256-sha256":
        priv = ec.generate_private_key(ec.SECP256R1())
    elif profile == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"unknown profile: {profile}")
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return priv_pem, _pem(pub), hashlib.sha256(_der(pub)).hexdigest()


def inspect_key(pem_str: str) -> KeyInfo:
    """Parse and validate a PEM key. Raise ValueError if invalid."""
    key, is_private = _load(pem_str)
    pub = key.public_key() if is_private else key
    return KeyInfo(is_private, _profile(pub), _pem(pub), hashlib.sha256(_der(pub)).hexdigest())


def sign_bytes(priv_pem: str, message: bytes) -> bytes:
    """Return raw signature bytes over message."""
    key, is_private = _load(priv_pem)
    if not is_private:
        raise ValueError("private key required")
    profile = _profile(key.public_key())
    if profile == "rsa-pss-sha256":
        return key.sign(message, _PSS, _SHA)
    if profile == "ecdsa-p256-sha256":
        r, s = decode_dss_signature(key.sign(message, ec.ECDSA(_SHA)))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return key.sign(message)


def verify_bytes(pub_pem: str, profile: str, message: bytes, signature: bytes) -> bool:
    """Verify raw signature bytes over message."""
    key, is_private = _load(pub_pem)
    if is_private or _profile(key) != profile or len(signature) != _SIG_LEN.get(profile):
        return False
    try:
        if profile == "rsa-pss-sha256":
            key.verify(signature, message, _PSS, _SHA)
        elif profile == "ecdsa-p256-sha256":
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            if not (0 < r < _ORDER and 0 < s < _ORDER):
                return False
            key.verify(encode_dss_signature(r, s), message, ec.ECDSA(_SHA))
        else:
            key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
