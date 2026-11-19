"""Manifest and bundle formats: strict JSON/Base64 parsing, canonical
serialization and file helpers.

Format violations raise :class:`FormatError`; I/O problems stay ``OSError``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import tempfile
from typing import Any

from veriseal.contracts import BUNDLE_SCHEMA, MANIFEST_SCHEMA

MAX_MANIFEST_BYTES = 16 * 1024
MAX_BUNDLE_BYTES = 64 * 1024

MAX_ARTIFACT_SIZE = 2**53 - 1
"""Largest ``artifact.size`` accepted (largest integer a JSON number holds exactly)."""

PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
ARTIFACT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")

MANIFEST_KEYS = ("schema", "package", "version", "algorithm", "keyid", "artifact")
ARTIFACT_KEYS = ("name", "size", "sha256")
BUNDLE_KEYS = ("schema", "manifest_b64", "signature_b64")

_UTF8_BOM = b"\xef\xbb\xbf"
_HASH_CHUNK = 1024 * 1024


class FormatError(ValueError):
    """A file or value violates the manifest, bundle or trust store format."""


def matches(pattern: re.Pattern[str], value: str) -> bool:
    """Return True if ``value`` matches ``pattern`` over its whole length.

    >>> matches(PACKAGE_RE, "contoh-app")
    True
    >>> matches(PACKAGE_RE, "contoh-app\\n")
    False
    """
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise FormatError(f"duplicate JSON field: {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise FormatError(f"non-standard JSON number: {name}")


def _reject_float(text: str) -> Any:
    raise FormatError(f"non-integer JSON number: {text}")


def strict_json_loads(data: bytes) -> Any:
    """Parse UTF-8 JSON bytes, rejecting a BOM, duplicate keys, NaN/Infinity and floats.

    >>> strict_json_loads(b'{"a":1}')
    {'a': 1}
    >>> strict_json_loads(b'{"a":1,"a":2}')
    Traceback (most recent call last):
    ...
    veriseal.formats.FormatError: duplicate JSON field: 'a'
    """
    if data.startswith(_UTF8_BOM):
        raise FormatError("UTF-8 byte order mark is not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError(f"invalid UTF-8: {exc.reason}") from None
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except json.JSONDecodeError as exc:
        raise FormatError(f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}") from None
    except RecursionError:
        raise FormatError("invalid JSON: nesting too deep") from None


def require_object(value: Any, keys: tuple[str, ...], where: str) -> dict[str, Any]:
    """Check that ``value`` is a JSON object with exactly ``keys``."""
    if not isinstance(value, dict):
        raise FormatError(f"{where} must be a JSON object")
    missing = [k for k in keys if k not in value]
    extra = [k for k in value if k not in keys]
    if missing:
        raise FormatError(f"{where} is missing field(s): {', '.join(missing)}")
    if extra:
        raise FormatError(f"{where} has unexpected field(s): {', '.join(extra)}")
    return value


def require_str(value: Any, where: str, pattern: re.Pattern[str] | None = None) -> str:
    """Check that ``value`` is a string, optionally matching ``pattern``."""
    if not isinstance(value, str):
        raise FormatError(f"{where} must be a string")
    if pattern is not None and not matches(pattern, value):
        raise FormatError(f"{where} has an invalid value: {value!r}")
    return value


def require_int(value: Any, where: str, minimum: int, maximum: int) -> int:
    """Check that ``value`` is an integer in range. Booleans are rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError(f"{where} must be an integer")
    if not minimum <= value <= maximum:
        raise FormatError(f"{where} is out of range ({minimum}..{maximum})")
    return value


def b64encode(data: bytes) -> str:
    """Encode bytes as standard, padded Base64 text."""
    return base64.b64encode(data).decode("ascii")


def b64decode_strict(value: Any, where: str = "Base64 value") -> bytes:
    """Decode standard Base64; anything that does not re-encode identically is rejected.

    >>> b64decode_strict("aGk=")
    b'hi'
    >>> b64decode_strict("aGk")
    Traceback (most recent call last):
    ...
    veriseal.formats.FormatError: Base64 value is not valid Base64
    """
    if not isinstance(value, str):
        raise FormatError(f"{where} must be a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise FormatError(f"{where} is not valid Base64") from None
    if b64encode(raw) != value:
        raise FormatError(f"{where} is not canonical Base64")
    return raw


def build_manifest(
    package: str,
    version: str,
    algorithm: str,
    keyid: str,
    name: str,
    size: int,
    sha256: str,
) -> dict[str, Any]:
    """Build and validate a manifest dict in canonical field order.

    >>> m = build_manifest("contoh-app", "1.0.0", "ed25519", "0" * 64, "a.zip", 3, "f" * 64)
    >>> list(m)
    ['schema', 'package', 'version', 'algorithm', 'keyid', 'artifact']
    """
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "package": package,
        "version": version,
        "algorithm": algorithm,
        "keyid": keyid,
        "artifact": {"name": name, "size": size, "sha256": sha256},
    }
    return validate_manifest(manifest)


def validate_manifest(obj: Any) -> dict[str, Any]:
    """Validate the structure, types and values of a manifest.

    ``algorithm`` is only checked to be a string, so an unknown profile is
    reported as ``UNSUPPORTED_ALGORITHM`` instead of ``FORMAT_ERROR``.
    """
    m = require_object(obj, MANIFEST_KEYS, "manifest")
    if m["schema"] != MANIFEST_SCHEMA:
        raise FormatError(f"manifest.schema must be {MANIFEST_SCHEMA!r}")
    require_str(m["package"], "manifest.package", PACKAGE_RE)
    require_str(m["version"], "manifest.version", VERSION_RE)
    require_str(m["algorithm"], "manifest.algorithm")
    require_str(m["keyid"], "manifest.keyid", HEX64_RE)
    art = require_object(m["artifact"], ARTIFACT_KEYS, "manifest.artifact")
    require_str(art["name"], "manifest.artifact.name", ARTIFACT_NAME_RE)
    require_int(art["size"], "manifest.artifact.size", 0, MAX_ARTIFACT_SIZE)
    require_str(art["sha256"], "manifest.artifact.sha256", HEX64_RE)
    return m


def serialize_manifest(manifest: dict[str, Any]) -> bytes:
    """Return the canonical manifest bytes ``M``: fixed field order, no whitespace, ASCII.

    >>> m = build_manifest("contoh-app", "1.0.0", "ed25519", "0" * 64, "a.zip", 3, "f" * 64)
    >>> serialize_manifest(m)[:52]
    b'{"schema":"minisign-manifest/v1","package":"contoh-a'
    """
    art = manifest["artifact"]
    ordered = {
        "schema": manifest["schema"],
        "package": manifest["package"],
        "version": manifest["version"],
        "algorithm": manifest["algorithm"],
        "keyid": manifest["keyid"],
        "artifact": {"name": art["name"], "size": art["size"], "sha256": art["sha256"]},
    }
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def parse_manifest(data: bytes) -> dict[str, Any]:
    """Parse manifest bytes ``M`` and require that they are canonical.

    :raises FormatError: if ``M`` is too large, invalid, or not byte-identical
        to its own canonical serialization.
    """
    if len(data) > MAX_MANIFEST_BYTES:
        raise FormatError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    manifest = validate_manifest(strict_json_loads(data))
    if serialize_manifest(manifest) != data:
        raise FormatError("manifest is not in canonical serialization")
    return manifest


def build_bundle(manifest_bytes: bytes, signature: bytes) -> bytes:
    """Return the bundle file contents for manifest bytes ``M`` and a signature."""
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "manifest_b64": b64encode(manifest_bytes),
        "signature_b64": b64encode(signature),
    }
    data = (json.dumps(bundle, separators=(",", ":")) + "\n").encode("ascii")
    if len(data) > MAX_BUNDLE_BYTES:
        raise FormatError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    return data


def parse_bundle(data: bytes) -> tuple[bytes, bytes]:
    """Parse bundle bytes and return ``(M, signature)``.

    Field order and whitespace of the bundle JSON are free. ``M`` is returned
    as received so it can be verified byte for byte.
    """
    if len(data) > MAX_BUNDLE_BYTES:
        raise FormatError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    b = require_object(strict_json_loads(data), BUNDLE_KEYS, "bundle")
    if b["schema"] != BUNDLE_SCHEMA:
        raise FormatError(f"bundle.schema must be {BUNDLE_SCHEMA!r}")
    manifest_bytes = b64decode_strict(b["manifest_b64"], "bundle.manifest_b64")
    signature = b64decode_strict(b["signature_b64"], "bundle.signature_b64")
    return manifest_bytes, signature


def read_limited(path: str, limit: int, what: str = "file") -> bytes:
    """Read a file, raising FormatError if it is larger than ``limit`` bytes."""
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise FormatError(f"{what} exceeds {limit} bytes")
    return data


def hash_file(path: str) -> tuple[int, str]:
    """Stream a file and return ``(size, lowercase hex SHA-256)``."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(_HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def atomic_write(path: str, data: bytes, mode: int = 0o644) -> None:
    """Write ``data`` to a temporary file in the same directory, then rename it over ``path``.

    On failure the old file is left untouched.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".veriseal-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
