"""Signed CycloneDX SBOM bound to a release artifact by its SHA-256.

The SBOM is signed as its own artifact with the same manifest and bundle
formats. The artifact hash is read from ``metadata.component.hashes``.
"""

from __future__ import annotations

import hashlib
from typing import Any

from veriseal.cli import CliError, VerifyResult, sign_release, verify_release
from veriseal.contracts import Status
from veriseal.formats import FormatError, hash_file, strict_json_loads

SBOM_FORMAT = "CycloneDX"
HASH_ALG = "SHA-256"


def load_sbom(path: str) -> dict[str, Any]:
    """Read and parse a CycloneDX SBOM JSON file."""
    with open(path, "rb") as f:
        return _parse_sbom(f.read())


def _parse_sbom(data: bytes) -> dict[str, Any]:
    doc = strict_json_loads(data)
    if not isinstance(doc, dict):
        raise FormatError("SBOM must be a JSON object")
    if doc.get("bomFormat") != SBOM_FORMAT:
        raise FormatError(f"SBOM bomFormat must be {SBOM_FORMAT!r}")
    return doc


def extract_release_sha256(sbom: dict[str, Any]) -> str:
    """Return the lowercase SHA-256 from the single ``SHA-256`` entry in ``metadata.component.hashes``.

    >>> extract_release_sha256({"metadata": {"component": {"hashes": [
    ...     {"alg": "SHA-256", "content": "AB" * 32}]}}}) == "ab" * 32
    True
    """
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    hashes = component.get("hashes") if isinstance(component, dict) else None
    if not isinstance(hashes, list):
        raise FormatError("SBOM has no metadata.component.hashes array")
    found = [h for h in hashes if isinstance(h, dict) and h.get("alg") == HASH_ALG]
    if len(found) != 1:
        raise FormatError(f"SBOM must record exactly one {HASH_ALG} hash in metadata.component.hashes")
    content = found[0].get("content")
    if not isinstance(content, str) or len(content) != 64 or any(c not in "0123456789abcdefABCDEF" for c in content):
        raise FormatError("SBOM SHA-256 hash content must be 64 hex characters")
    return content.lower()


def sign_sbom(sbom_path: str, artifact: str, package: str, version: str, key: str, out: str) -> dict[str, Any]:
    """Sign an SBOM file after checking that it records the SHA-256 of ``artifact``.

    :returns: the signed SBOM manifest.
    :raises CliError: on an invalid SBOM, a hash mismatch, or key/I/O problems.

    Example::

        sign_sbom("sbom.json", "contoh-app.zip", "contoh-app", "1.0.0",
                  "keys/publisher.key.pem", "sbom.bundle.json")
    """
    try:
        recorded = extract_release_sha256(load_sbom(sbom_path))
    except OSError as exc:
        raise CliError(f"cannot read SBOM {sbom_path!r}: {exc.strerror or exc}") from None
    except FormatError as exc:
        raise CliError(f"invalid SBOM {sbom_path!r}: {exc}") from None
    try:
        _, actual = hash_file(artifact)
    except OSError as exc:
        raise CliError(f"cannot read artifact {artifact!r}: {exc.strerror or exc}") from None
    if recorded != actual:
        raise CliError(f"SBOM records SHA-256 {recorded} but artifact {artifact!r} has {actual}")
    return sign_release(sbom_path, package, version, key, out)


def verify_sbom(
    sbom_path: str,
    sbom_bundle: str,
    artifact: str,
    artifact_bundle: str,
    trust_store: str,
    package: str,
    version: str,
) -> VerifyResult:
    """Verify the release bundle, the SBOM bundle, and that the SBOM hash matches the artifact.

    :returns: a :class:`~veriseal.cli.VerifyResult` describing the release artifact.
    """
    release = verify_release(artifact, artifact_bundle, trust_store, package, version)
    if not release.valid:
        return release.with_status(release.status, f"release artifact: {release.message}")

    sbom_res = verify_release(sbom_path, sbom_bundle, trust_store, package, version)
    if not sbom_res.valid:
        return sbom_res.with_status(sbom_res.status, f"SBOM: {sbom_res.message}")

    # Re-read the SBOM and make sure it is still the file that was verified.
    try:
        with open(sbom_path, "rb") as f:
            sbom_bytes = f.read()
    except OSError as exc:
        return release.with_status(Status.INPUT_ERROR, f"cannot read SBOM {sbom_path!r}: {exc.strerror or exc}")
    assert sbom_res.manifest is not None and release.manifest is not None
    if hashlib.sha256(sbom_bytes).hexdigest() != sbom_res.manifest["artifact"]["sha256"]:
        return release.with_status(Status.ARTIFACT_MISMATCH, "SBOM file changed during verification")
    try:
        recorded = extract_release_sha256(_parse_sbom(sbom_bytes))
    except FormatError as exc:
        return release.with_status(Status.FORMAT_ERROR, f"SBOM: {exc}")

    released = release.manifest["artifact"]["sha256"]
    if recorded != released:
        return release.with_status(
            Status.ARTIFACT_MISMATCH,
            f"SBOM references SHA-256 {recorded} but the verified artifact is {released}",
        )
    return release.with_status(Status.OK, "SBOM, release artifact and their SHA-256 binding are valid.")
