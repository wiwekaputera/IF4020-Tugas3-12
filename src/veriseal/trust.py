"""Trust store (``minisign-trust/v1``): trusted public keys and the packages
each key may sign. Invalid entries raise :class:`~veriseal.formats.FormatError`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from veriseal import crypto
from veriseal.contracts import PROFILES, TRUST_SCHEMA
from veriseal.formats import (
    HEX64_RE,
    PACKAGE_RE,
    FormatError,
    atomic_write,
    matches,
    require_object,
    require_str,
    strict_json_loads,
)

TRUST_KEYS = ("schema", "keys")
ENTRY_KEYS = ("keyid", "algorithm", "public_key_pem", "packages")


@dataclass
class TrustEntry:
    """One trusted public key and the packages it is authorized for."""

    keyid: str
    algorithm: str
    public_key_pem: str
    packages: list[str]

    def to_json(self) -> dict:
        """Return the entry as a JSON-ready dict in fixed field order."""
        return {
            "keyid": self.keyid,
            "algorithm": self.algorithm,
            "public_key_pem": self.public_key_pem,
            "packages": list(self.packages),
        }


@dataclass
class TrustStore:
    """An in-memory trust store. An empty store trusts no key."""

    keys: list[TrustEntry] = field(default_factory=list)

    def lookup(self, keyid: str) -> TrustEntry | None:
        """Return the entry with this ``keyid``, or ``None`` if absent."""
        for entry in self.keys:
            if entry.keyid == keyid:
                return entry
        return None

    def to_bytes(self) -> bytes:
        """Serialize the store as indented JSON."""
        doc = {"schema": TRUST_SCHEMA, "keys": [e.to_json() for e in self.keys]}
        return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def _validate_packages(value: object, where: str) -> list[str]:
    if not isinstance(value, list):
        raise FormatError(f"{where} must be an array of strings")
    if not value:
        raise FormatError(f"{where} must not be empty")
    seen: set[str] = set()
    for i, pkg in enumerate(value):
        require_str(pkg, f"{where}[{i}]", PACKAGE_RE)
        if pkg in seen:
            raise FormatError(f"{where} contains duplicate package {pkg!r}")
        seen.add(pkg)
    return list(value)


def _validate_entry(obj: object, where: str) -> TrustEntry:
    e = require_object(obj, ENTRY_KEYS, where)
    keyid = require_str(e["keyid"], f"{where}.keyid", HEX64_RE)
    algorithm = require_str(e["algorithm"], f"{where}.algorithm")
    if algorithm not in PROFILES:
        raise FormatError(f"{where}.algorithm is not a supported profile: {algorithm!r}")
    pem = require_str(e["public_key_pem"], f"{where}.public_key_pem")
    packages = _validate_packages(e["packages"], f"{where}.packages")

    try:
        info = crypto.inspect_key(pem)
    except (ValueError, TypeError) as exc:
        raise FormatError(f"{where}.public_key_pem is not a valid public key: {exc}") from None
    if info.is_private:
        raise FormatError(f"{where}.public_key_pem must be a public key")
    if info.profile != algorithm:
        raise FormatError(f"{where}: key type is {info.profile}, not {algorithm}")
    if info.keyid != keyid:
        raise FormatError(f"{where}.keyid does not match public_key_pem")
    return TrustEntry(keyid, algorithm, pem, packages)


def parse_trust_store(data: bytes) -> TrustStore:
    """Parse trust store bytes and check every entry, including its public key."""
    doc = require_object(strict_json_loads(data), TRUST_KEYS, "trust store")
    if doc["schema"] != TRUST_SCHEMA:
        raise FormatError(f"trust store schema must be {TRUST_SCHEMA!r}")
    if not isinstance(doc["keys"], list):
        raise FormatError("trust store 'keys' must be an array")
    store = TrustStore()
    for i, obj in enumerate(doc["keys"]):
        entry = _validate_entry(obj, f"keys[{i}]")
        if store.lookup(entry.keyid) is not None:
            raise FormatError(f"keys[{i}]: duplicate keyid {entry.keyid}")
        store.keys.append(entry)
    return store


def load_trust_store(path: str) -> TrustStore:
    """Read and validate the trust store at ``path``."""
    with open(path, "rb") as f:
        data = f.read()
    return parse_trust_store(data)


def save_trust_store(path: str, store: TrustStore) -> None:
    """Write ``store`` to ``path`` atomically."""
    atomic_write(path, store.to_bytes(), mode=0o644)


def add_key(store: TrustStore, public_key_pem: str, package: str) -> tuple[TrustEntry, bool]:
    """Authorize a public key for ``package``. Adding an existing pair changes nothing.

    :returns: ``(entry, changed)``.
    :raises ValueError: if the key is invalid or private, or the package name is invalid.

    Example::

        store = TrustStore()
        entry, changed = add_key(store, open("pub.pem").read(), "contoh-app")
    """
    if not matches(PACKAGE_RE, package):
        raise ValueError(f"invalid package name: {package!r}")
    info = crypto.inspect_key(public_key_pem)
    if info.is_private:
        raise ValueError("refusing to add a private key to the trust store; pass the .pub.pem file")
    entry = store.lookup(info.keyid)
    if entry is None:
        entry = TrustEntry(info.keyid, info.profile, info.public_key_pem, [package])
        store.keys.append(entry)
        return entry, True
    if package in entry.packages:
        return entry, False
    entry.packages.append(package)
    return entry, True


def remove_key(store: TrustStore, keyid: str) -> TrustEntry:
    """Remove and return the entry with ``keyid``; raise KeyError if absent."""
    entry = store.lookup(keyid)
    if entry is None:
        raise KeyError(keyid)
    store.keys.remove(entry)
    return entry


def store_exists(path: str) -> bool:
    """Return True if anything exists at ``path``."""
    return os.path.lexists(path)
