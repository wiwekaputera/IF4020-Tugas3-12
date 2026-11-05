"""Shared schema names, profiles, exit codes, and verification statuses."""

MANIFEST_SCHEMA = "minisign-manifest/v1"
BUNDLE_SCHEMA = "minisign-bundle/v1"
TRUST_SCHEMA = "minisign-trust/v1"

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")

EXIT_OK = 0
EXIT_VERIFY_FAIL = 1
EXIT_INPUT_ERROR = 2


class Status:
    INPUT_ERROR = "INPUT_ERROR"
    FORMAT_ERROR = "FORMAT_ERROR"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    METADATA_MISMATCH = "METADATA_MISMATCH"
    ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
    OK = "OK"
