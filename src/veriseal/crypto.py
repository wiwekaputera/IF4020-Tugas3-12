"""Cryptographic operations and PEM key handling."""

from typing import NamedTuple


class KeyInfo(NamedTuple):
    is_private: bool
    profile: str
    public_key_pem: str
    keyid: str


def generate_keypair(profile: str) -> tuple[str, str, str]:
    """Return (private_pem, public_pem, keyid)."""
    raise NotImplementedError


def inspect_key(pem_str: str) -> KeyInfo:
    """Parse and validate a PEM key. Raise ValueError if invalid."""
    raise NotImplementedError


def sign_bytes(priv_pem: str, message: bytes) -> bytes:
    """Return raw signature bytes over message."""
    raise NotImplementedError


def verify_bytes(pub_pem: str, profile: str, message: bytes, signature: bytes) -> bool:
    """Verify raw signature bytes over message."""
    raise NotImplementedError
