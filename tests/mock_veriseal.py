#!/usr/bin/env python3
"""Standalone mock implementation of the veriseal CLI contract for dry-run testing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any

from veriseal.cli import build_parser
from veriseal.contracts import (
    BUNDLE_SCHEMA,
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_VERIFY_FAIL,
    MANIFEST_SCHEMA,
    PROFILES,
    TRUST_SCHEMA,
    Status,
)

PKG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
ASCII_STR_RE = re.compile(r"^[\x20-\x7e]+$")
MAX_MANIFEST_BYTES = 16384
MAX_BUNDLE_BYTES = 65536
MAX_ARTIFACT_SIZE = 9007199254740991

SIG_LENGTHS = {
    "rsa-pss-sha256": 384,
    "ecdsa-p256-sha256": 64,
    "ed25519": 64,
}


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate keys."""


def _no_dup_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKeyError(f"Duplicate JSON key: {k}")
        out[k] = v
    return out


def parse_json_strict(raw_bytes: bytes, max_bytes: int | None = None) -> Any:
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise ValueError("UTF-8 BOM is not allowed")
    if max_bytes is not None and len(raw_bytes) > max_bytes:
        raise ValueError("JSON exceeds maximum byte size")
    text = raw_bytes.decode("utf-8")
    return json.loads(text, object_pairs_hook=_no_dup_pairs)


def decode_b64_strict(b64_str: str) -> bytes:
    if not isinstance(b64_str, str) or not b64_str:
        raise ValueError("Invalid Base64 string")
    if any(ch.isspace() for ch in b64_str):
        raise ValueError("Whitespace in Base64 is not allowed")
    try:
        raw = base64.b64decode(b64_str, validate=True)
    except Exception as exc:
        raise ValueError("Invalid Base64 encoding") from exc
    if base64.b64encode(raw).decode("ascii") != b64_str:
        raise ValueError("Non-canonical Base64 encoding")
    return raw


def _wrap_pem(label: str, der_bytes: bytes) -> str:
    b64 = base64.b64encode(der_bytes).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def _unwrap_pem(pem_str: str, expected_label: str) -> bytes:
    if not isinstance(pem_str, str):
        raise ValueError("PEM must be a string")
    lines = [line.strip() for line in pem_str.strip().splitlines() if line.strip()]
    begin = f"-----BEGIN {expected_label}-----"
    end = f"-----END {expected_label}-----"
    if len(lines) < 3 or lines[0] != begin or lines[-1] != end:
        raise ValueError(f"Invalid PEM boundaries for {expected_label}")
    b64_str = "".join(lines[1:-1])
    return decode_b64_strict(b64_str)


def mock_generate_keypair(profile: str) -> tuple[str, str, str]:
    if profile not in PROFILES:
        raise ValueError(f"Unsupported profile: {profile}")
    secret = secrets.token_bytes(32)
    pub_token = hashlib.sha256(b"mock-pub:" + secret).digest()
    priv_der = f"MOCK-PRIV:{profile}:".encode("ascii") + secret + pub_token
    pub_der = f"MOCK-SPKI:{profile}:".encode("ascii") + pub_token
    keyid = hashlib.sha256(pub_der).hexdigest().lower()
    return (
        _wrap_pem("PRIVATE KEY", priv_der),
        _wrap_pem("PUBLIC KEY", pub_der),
        keyid,
    )


def mock_inspect_private_key(pem_str: str) -> tuple[str, bytes, bytes, str]:
    der = _unwrap_pem(pem_str, "PRIVATE KEY")
    prefix = b"MOCK-PRIV:"
    if not der.startswith(prefix):
        raise ValueError("Unrecognized private key format")
    rest = der[len(prefix) :]
    sep = rest.find(b":")
    if sep == -1:
        raise ValueError("Malformed private key payload")
    profile = rest[:sep].decode("ascii")
    key_bytes = rest[sep + 1 :]
    if profile not in PROFILES or len(key_bytes) != 64:
        raise ValueError("Invalid private key profile or length")
    secret, pub_token = key_bytes[:32], key_bytes[32:]
    if hashlib.sha256(b"mock-pub:" + secret).digest() != pub_token:
        raise ValueError("Corrupted private key token")
    pub_der = f"MOCK-SPKI:{profile}:".encode("ascii") + pub_token
    keyid = hashlib.sha256(pub_der).hexdigest().lower()
    return profile, secret, pub_token, keyid


def mock_inspect_public_key(pem_str: str) -> tuple[str, bytes, str]:
    der = _unwrap_pem(pem_str, "PUBLIC KEY")
    prefix = b"MOCK-SPKI:"
    if not der.startswith(prefix):
        raise ValueError("Unrecognized public key format")
    rest = der[len(prefix) :]
    sep = rest.find(b":")
    if sep == -1:
        raise ValueError("Malformed public key payload")
    profile = rest[:sep].decode("ascii")
    pub_token = rest[sep + 1 :]
    if profile not in PROFILES or len(pub_token) != 32:
        raise ValueError("Invalid public key profile or length")
    keyid = hashlib.sha256(der).hexdigest().lower()
    return profile, pub_token, keyid


def mock_sign_bytes(profile: str, pub_token: bytes, message: bytes) -> bytes:
    sig_len = SIG_LENGTHS[profile]
    if profile == "rsa-pss-sha256":
        salt = secrets.token_bytes(32)
        tag = hmac.new(pub_token, salt + message, hashlib.sha256).digest()
        pad = hashlib.sha256(tag + salt).digest() * 10
        return (salt + tag + pad)[:sig_len]
    # Deterministic 64-byte signature for ecdsa-p256-sha256 (RFC 6979) and ed25519 (RFC 8032)
    r_part = hmac.new(pub_token, b"R:" + message, hashlib.sha256).digest()
    s_part = hmac.new(pub_token, b"S:" + message, hashlib.sha256).digest()
    return r_part + s_part


def mock_verify_bytes(profile: str, pub_token: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != SIG_LENGTHS.get(profile, -1):
        return False
    if profile == "rsa-pss-sha256":
        salt = signature[:32]
        tag = hmac.new(pub_token, salt + message, hashlib.sha256).digest()
        pad = hashlib.sha256(tag + salt).digest() * 10
        expected = (salt + tag + pad)[:384]
        return hmac.compare_digest(signature, expected)
    r_part = hmac.new(pub_token, b"R:" + message, hashlib.sha256).digest()
    s_part = hmac.new(pub_token, b"S:" + message, hashlib.sha256).digest()
    return hmac.compare_digest(signature, r_part + s_part)


def serialize_manifest(m: dict[str, Any]) -> bytes:
    art = m["artifact"]
    ordered = {
        "schema": m["schema"],
        "package": m["package"],
        "version": m["version"],
        "algorithm": m["algorithm"],
        "keyid": m["keyid"],
        "artifact": {
            "name": art["name"],
            "size": art["size"],
            "sha256": art["sha256"],
        },
    }
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_manifest_structure(m: Any) -> dict[str, Any]:
    if not isinstance(m, dict):
        raise ValueError("Manifest must be a JSON object")
    expected_keys = ["schema", "package", "version", "algorithm", "keyid", "artifact"]
    if list(m.keys()) != expected_keys:
        raise ValueError("Manifest keys or key order invalid")
    if m["schema"] != MANIFEST_SCHEMA:
        raise ValueError("Invalid manifest schema")
    if not isinstance(m["package"], str) or not PKG_RE.match(m["package"]):
        raise ValueError("Invalid package name in manifest")
    if not isinstance(m["version"], str) or not VER_RE.match(m["version"]):
        raise ValueError("Invalid version in manifest")
    if not isinstance(m["algorithm"], str) or not ASCII_STR_RE.match(m["algorithm"]):
        raise ValueError("Invalid algorithm type in manifest")
    if not isinstance(m["keyid"], str) or not HEX64_RE.match(m["keyid"]):
        raise ValueError("Invalid keyid in manifest")

    art = m["artifact"]
    if not isinstance(art, dict):
        raise ValueError("artifact field must be a JSON object")
    if list(art.keys()) != ["name", "size", "sha256"]:
        raise ValueError("artifact keys or key order invalid")
    if not isinstance(art["name"], str) or not NAME_RE.match(art["name"]):
        raise ValueError("Invalid artifact.name")
    if isinstance(art["size"], bool) or not isinstance(art["size"], int):
        raise ValueError("Invalid artifact.size type")
    if art["size"] < 0 or art["size"] > MAX_ARTIFACT_SIZE:
        raise ValueError("artifact.size out of range")
    if not isinstance(art["sha256"], str) or not HEX64_RE.match(art["sha256"]):
        raise ValueError("Invalid artifact.sha256")
    return m


def validate_trust_store_bytes(raw_bytes: bytes) -> dict[str, Any]:
    data = parse_json_strict(raw_bytes)
    if not isinstance(data, dict) or set(data.keys()) != {"schema", "keys"}:
        raise ValueError("Invalid trust store top-level structure")
    if data["schema"] != TRUST_SCHEMA or not isinstance(data["keys"], list):
        raise ValueError("Invalid trust store schema or keys list")
    seen_keyids: set[str] = set()
    for entry in data["keys"]:
        if not isinstance(entry, dict):
            raise ValueError("Trust entry must be an object")
        if set(entry.keys()) != {"keyid", "algorithm", "public_key_pem", "packages"}:
            raise ValueError("Trust entry has invalid fields")
        keyid = entry["keyid"]
        alg = entry["algorithm"]
        pub_pem = entry["public_key_pem"]
        pkgs = entry["packages"]
        if not isinstance(keyid, str) or not HEX64_RE.match(keyid):
            raise ValueError("Invalid keyid in trust store")
        if keyid in seen_keyids:
            raise ValueError("Duplicate keyid in trust store")
        seen_keyids.add(keyid)
        if alg not in PROFILES:
            raise ValueError("Invalid algorithm in trust store")
        parsed_alg, _, computed_keyid = mock_inspect_public_key(pub_pem)
        if parsed_alg != alg or computed_keyid != keyid:
            raise ValueError("Trust store key mismatch")
        if not isinstance(pkgs, list) or len(pkgs) == 0:
            raise ValueError("Trust store packages must be a non-empty list")
        if len(set(pkgs)) != len(pkgs):
            raise ValueError("Duplicate packages in trust entry")
        for p in pkgs:
            if not isinstance(p, str) or not PKG_RE.match(p):
                raise ValueError("Invalid package name in trust store")
    return data


def atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_veriseal_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def emit_verify_result(
    json_output: bool,
    status: str,
    exit_code: int,
    message: str,
    manifest: dict[str, Any] | None = None,
    quiet: bool = False,
) -> int:
    if quiet:
        return exit_code
    valid = status == Status.OK
    if json_output:
        payload = {
            "valid": valid,
            "status": status,
            "message": message,
            "algorithm": manifest.get("algorithm") if manifest else None,
            "keyid": manifest.get("keyid") if manifest else None,
            "package": manifest.get("package") if manifest else None,
            "version": manifest.get("version") if manifest else None,
        }
        sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    if not valid:
        sys.stderr.write(f"{status}: {message}\n")
    elif not json_output:
        sys.stdout.write(f"{status}: {message}\n")
    return exit_code


def run_verify(
    file_path: str,
    bundle_path: str,
    trust_path: str,
    expected_pkg: str,
    expected_ver: str,
    json_output: bool,
    quiet: bool = False,
) -> int:
    # Step 1: INPUT_ERROR
    if not expected_pkg or not expected_ver:
        return emit_verify_result(
            json_output, Status.INPUT_ERROR, EXIT_INPUT_ERROR, "Empty package or version", None, quiet
        )
    try:
        artifact_bytes = Path(file_path).read_bytes()
        bundle_bytes = Path(bundle_path).read_bytes()
        trust_bytes = Path(trust_path).read_bytes()
    except Exception as exc:
        return emit_verify_result(
            json_output, Status.INPUT_ERROR, EXIT_INPUT_ERROR, f"I/O error: {exc}", None, quiet
        )

    # Step 2: FORMAT_ERROR
    manifest_obj: dict[str, Any] | None = None
    try:
        bundle_obj = parse_json_strict(bundle_bytes, max_bytes=MAX_BUNDLE_BYTES)
        if not isinstance(bundle_obj, dict) or set(bundle_obj.keys()) != {
            "schema",
            "manifest_b64",
            "signature_b64",
        }:
            raise ValueError("Invalid bundle keys")
        if bundle_obj["schema"] != BUNDLE_SCHEMA:
            raise ValueError("Invalid bundle schema")
        raw_manifest = decode_b64_strict(bundle_obj["manifest_b64"])
        raw_sig = decode_b64_strict(bundle_obj["signature_b64"])
        if len(raw_manifest) > MAX_MANIFEST_BYTES:
            raise ValueError("Manifest exceeds 16 KiB limit")
        parsed_m = parse_json_strict(raw_manifest, max_bytes=MAX_MANIFEST_BYTES)
        manifest_obj = validate_manifest_structure(parsed_m)
        if serialize_manifest(manifest_obj) != raw_manifest:
            raise ValueError("Manifest is not canonically serialized")
        trust_obj = validate_trust_store_bytes(trust_bytes)
    except Exception as exc:
        return emit_verify_result(
            json_output, Status.FORMAT_ERROR, EXIT_VERIFY_FAIL, f"Format error: {exc}", None, quiet
        )

    # Step 3: UNSUPPORTED_ALGORITHM
    alg = manifest_obj["algorithm"]
    if alg not in PROFILES:
        return emit_verify_result(
            json_output,
            Status.UNSUPPORTED_ALGORITHM,
            EXIT_VERIFY_FAIL,
            f"Unsupported algorithm: {alg}",
            manifest_obj,
            quiet,
        )

    # Step 4: KEY_NOT_TRUSTED
    keyid = manifest_obj["keyid"]
    matched_entry = next((e for e in trust_obj["keys"] if e["keyid"] == keyid), None)
    if (
        matched_entry is None
        or matched_entry["algorithm"] != alg
        or expected_pkg not in matched_entry["packages"]
    ):
        return emit_verify_result(
            json_output,
            Status.KEY_NOT_TRUSTED,
            EXIT_VERIFY_FAIL,
            "Key is not trusted for this package and algorithm",
            manifest_obj,
            quiet,
        )

    # Step 5: INVALID_SIGNATURE
    _, pub_token, _ = mock_inspect_public_key(matched_entry["public_key_pem"])
    if not mock_verify_bytes(alg, pub_token, raw_manifest, raw_sig):
        return emit_verify_result(
            json_output,
            Status.INVALID_SIGNATURE,
            EXIT_VERIFY_FAIL,
            "Signature verification failed",
            manifest_obj,
            quiet,
        )

    # Step 6: METADATA_MISMATCH
    basename = os.path.basename(file_path)
    if (
        manifest_obj["package"] != expected_pkg
        or manifest_obj["version"] != expected_ver
        or manifest_obj["artifact"]["name"] != basename
    ):
        return emit_verify_result(
            json_output,
            Status.METADATA_MISMATCH,
            EXIT_VERIFY_FAIL,
            "Package, version, or artifact filename mismatch",
            manifest_obj,
            quiet,
        )

    # Step 7: ARTIFACT_MISMATCH
    art_meta = manifest_obj["artifact"]
    actual_sha256 = hashlib.sha256(artifact_bytes).hexdigest().lower()
    if len(artifact_bytes) != art_meta["size"] or actual_sha256 != art_meta["sha256"]:
        return emit_verify_result(
            json_output,
            Status.ARTIFACT_MISMATCH,
            EXIT_VERIFY_FAIL,
            "Artifact size or SHA-256 mismatch",
            manifest_obj,
            quiet,
        )

    # Step 8: OK
    return emit_verify_result(
        json_output,
        Status.OK,
        EXIT_OK,
        "Signature and artifact are valid.",
        manifest_obj,
        quiet,
    )


def run_sign(
    file_path: str, pkg: str, ver: str, key_path: str, out_path: str
) -> int:
    try:
        if not PKG_RE.match(pkg) or not VER_RE.match(ver):
            raise ValueError("Invalid package or version format")
        basename = os.path.basename(file_path)
        if not NAME_RE.match(basename):
            raise ValueError("Invalid artifact filename")
        priv_pem = Path(key_path).read_text(encoding="utf-8")
        profile, _, pub_token, keyid = mock_inspect_private_key(priv_pem)
        artifact_bytes = Path(file_path).read_bytes()
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "package": pkg,
            "version": ver,
            "algorithm": profile,
            "keyid": keyid,
            "artifact": {
                "name": basename,
                "size": len(artifact_bytes),
                "sha256": hashlib.sha256(artifact_bytes).hexdigest().lower(),
            },
        }
        validate_manifest_structure(manifest)
        raw_manifest = serialize_manifest(manifest)
        if len(raw_manifest) > MAX_MANIFEST_BYTES:
            raise ValueError("Manifest exceeds 16 KiB limit")
        sig = mock_sign_bytes(profile, pub_token, raw_manifest)
        bundle = {
            "schema": BUNDLE_SCHEMA,
            "manifest_b64": base64.b64encode(raw_manifest).decode("ascii"),
            "signature_b64": base64.b64encode(sig).decode("ascii"),
        }
        atomic_write_json(Path(out_path), bundle)
        return EXIT_OK
    except Exception as exc:
        sys.stderr.write(f"Sign error: {exc}\n")
        return EXIT_INPUT_ERROR


def extract_sbom_artifact_hashes(sbom_obj: Any) -> list[str]:
    hashes: list[str] = []
    if not isinstance(sbom_obj, dict):
        return hashes
    if isinstance(sbom_obj.get("artifact_sha256"), str):
        hashes.append(sbom_obj["artifact_sha256"].lower())
    art = sbom_obj.get("artifact")
    if isinstance(art, dict) and isinstance(art.get("sha256"), str):
        hashes.append(art["sha256"].lower())
    subj = sbom_obj.get("subject")
    if isinstance(subj, dict) and isinstance(subj.get("sha256"), str):
        hashes.append(subj["sha256"].lower())
    meta_comp = sbom_obj.get("metadata", {})
    if isinstance(meta_comp, dict):
        comp = meta_comp.get("component", {})
        if isinstance(comp, dict) and isinstance(comp.get("hashes"), list):
            for h in comp["hashes"]:
                if isinstance(h, dict) and h.get("alg") in ("SHA-256", "sha256"):
                    if isinstance(h.get("content"), str):
                        hashes.append(h["content"].lower())
    return hashes


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "keygen":
        priv_path = Path(f"{args.out}.key.pem")
        pub_path = Path(f"{args.out}.pub.pem")
        if (priv_path.exists() or pub_path.exists()) and not args.force:
            sys.stderr.write("Key file already exists; use --force to overwrite\n")
            return EXIT_INPUT_ERROR
        try:
            priv_pem, pub_pem, keyid = mock_generate_keypair(args.algorithm)
            priv_path.parent.mkdir(parents=True, exist_ok=True)
            priv_path.write_text(priv_pem, encoding="utf-8")
            pub_path.write_text(pub_pem, encoding="utf-8")
            sys.stdout.write(f"{keyid}\n")
            return EXIT_OK
        except Exception as exc:
            sys.stderr.write(f"Keygen error: {exc}\n")
            return EXIT_INPUT_ERROR

    if args.command == "trust":
        store_path = Path(args.store)
        if args.trust_command == "add":
            try:
                if not PKG_RE.match(args.package):
                    raise ValueError("Invalid package name")
                pub_pem = Path(args.key).read_text(encoding="utf-8")
                alg, _, keyid = mock_inspect_public_key(pub_pem)
                if store_path.exists():
                    store = validate_trust_store_bytes(store_path.read_bytes())
                else:
                    store = {"schema": TRUST_SCHEMA, "keys": []}
                existing = next((e for e in store["keys"] if e["keyid"] == keyid), None)
                if existing is not None:
                    if args.package not in existing["packages"]:
                        existing["packages"].append(args.package)
                else:
                    store["keys"].append(
                        {
                            "keyid": keyid,
                            "algorithm": alg,
                            "public_key_pem": pub_pem,
                            "packages": [args.package],
                        }
                    )
                atomic_write_json(store_path, store)
                sys.stdout.write(f"{keyid} {alg} {args.package}\n")
                return EXIT_OK
            except Exception as exc:
                sys.stderr.write(f"Trust add error: {exc}\n")
                return EXIT_INPUT_ERROR

        if args.trust_command == "list":
            try:
                store = validate_trust_store_bytes(store_path.read_bytes())
                for entry in store["keys"]:
                    pkgs = ",".join(entry["packages"])
                    sys.stdout.write(f"{entry['keyid']} {entry['algorithm']} {pkgs}\n")
                return EXIT_OK
            except Exception as exc:
                sys.stderr.write(f"Trust list error: {exc}\n")
                return EXIT_INPUT_ERROR

        if args.trust_command == "remove":
            try:
                store = validate_trust_store_bytes(store_path.read_bytes())
                before = len(store["keys"])
                store["keys"] = [e for e in store["keys"] if e["keyid"] != args.keyid]
                if len(store["keys"]) == before:
                    sys.stderr.write("Keyid not found in trust store\n")
                    return EXIT_INPUT_ERROR
                atomic_write_json(store_path, store)
                sys.stdout.write(f"Removed {args.keyid}\n")
                return EXIT_OK
            except Exception as exc:
                sys.stderr.write(f"Trust remove error: {exc}\n")
                return EXIT_INPUT_ERROR

    if args.command == "sign":
        return run_sign(args.file, args.package, args.version, args.key, args.out)

    if args.command == "verify":
        return run_verify(
            args.file,
            args.bundle,
            args.trust_store,
            args.package,
            args.version,
            args.json_output,
        )

    if args.command == "sbom":
        if args.sbom_command == "sign":
            try:
                artifact_bytes = Path(args.artifact).read_bytes()
                artifact_sha = hashlib.sha256(artifact_bytes).hexdigest().lower()
                sbom_obj = parse_json_strict(Path(args.file).read_bytes())
                recorded = extract_sbom_artifact_hashes(sbom_obj)
                if not recorded or any(h != artifact_sha for h in recorded):
                    raise ValueError("SBOM does not match referenced artifact SHA-256")
            except Exception as exc:
                sys.stderr.write(f"SBOM sign validation error: {exc}\n")
                return EXIT_INPUT_ERROR
            return run_sign(args.file, args.package, args.version, args.key, args.out)

        if args.sbom_command == "verify":
            # Verify release artifact bundle first, then SBOM bundle, then hash binding
            rc_art = run_verify(
                args.artifact,
                args.artifact_bundle,
                args.trust_store,
                args.package,
                args.version,
                False,
                quiet=True,
            )
            if rc_art != EXIT_OK:
                return run_verify(
                    args.artifact,
                    args.artifact_bundle,
                    args.trust_store,
                    args.package,
                    args.version,
                    args.json_output,
                )
            rc_sbom = run_verify(
                args.file,
                args.bundle,
                args.trust_store,
                args.package,
                args.version,
                False,
                quiet=True,
            )
            if rc_sbom != EXIT_OK:
                return run_verify(
                    args.file,
                    args.bundle,
                    args.trust_store,
                    args.package,
                    args.version,
                    args.json_output,
                )
            try:
                artifact_bytes = Path(args.artifact).read_bytes()
                artifact_sha = hashlib.sha256(artifact_bytes).hexdigest().lower()
                sbom_obj = parse_json_strict(Path(args.file).read_bytes())
                bundle_obj = parse_json_strict(Path(args.bundle).read_bytes())
                manifest_obj = parse_json_strict(decode_b64_strict(bundle_obj["manifest_b64"]))
            except Exception as exc:
                return emit_verify_result(
                    args.json_output, Status.FORMAT_ERROR, EXIT_VERIFY_FAIL, str(exc), None
                )
            recorded = extract_sbom_artifact_hashes(sbom_obj)
            if not recorded or any(h != artifact_sha for h in recorded):
                return emit_verify_result(
                    args.json_output,
                    Status.ARTIFACT_MISMATCH,
                    EXIT_VERIFY_FAIL,
                    "SBOM artifact SHA-256 binding mismatch",
                    manifest_obj,
                )
            return emit_verify_result(
                args.json_output,
                Status.OK,
                EXIT_OK,
                "SBOM and referenced release artifact are valid.",
                manifest_obj,
            )

    return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
