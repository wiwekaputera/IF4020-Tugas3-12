"""Micro-benchmarks for pure cryptographic operations and artifact hashing."""

import base64
import hashlib
import json
import math
import statistics
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

# Add repo root to path for imports
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from veriseal.contracts import PROFILES
from veriseal.crypto import generate_keypair, sign_bytes, verify_bytes

DEFAULT_MANIFEST = (
    b'{"algorithm":"rsa-pss-sha256","package":"demo","release_digest":'
    b'"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",'
    b'"schema":"minisign-manifest/v1","size_bytes":1024,"version":"1.0.0"}'
)


def nearest_rank_p95(data: list[int | float]) -> float:
    """Calculate 95th percentile using nearest-rank method: ceil(0.95 * n)."""
    if not data:
        raise ValueError("data cannot be empty")
    s = sorted(data)
    idx = math.ceil(0.95 * len(s)) - 1
    return float(s[idx])


def measure_keygen(profile: str, runs: int = 5) -> dict[str, Any]:
    """Measure keypair generation latency (monotonic ns) over N runs."""
    latencies = []
    sample_keys = None
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        priv, pub, keyid = generate_keypair(profile)
        latencies.append(time.perf_counter_ns() - t0)
        sample_keys = (priv, pub, keyid)
    return {
        "profile": profile,
        "runs": runs,
        "latencies_ns": latencies,
        "median_ns": float(statistics.median(latencies)),
        "p95_ns": nearest_rank_p95(latencies),
        "sample_keys": sample_keys,
    }


def measure_artifact_hash(data: bytes, warmup: int = 5, runs: int = 30) -> dict[str, Any]:
    """Measure isolated SHA-256 artifact hashing time."""
    for _ in range(warmup):
        hashlib.sha256(data).digest()
    latencies = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        hashlib.sha256(data).digest()
        latencies.append(time.perf_counter_ns() - t0)
    return {
        "size_bytes": len(data),
        "runs": runs,
        "latencies_ns": latencies,
        "median_ns": float(statistics.median(latencies)),
        "p95_ns": nearest_rank_p95(latencies),
    }


def measure_crypto_sign_verify(
    profile: str,
    manifest_bytes: bytes = DEFAULT_MANIFEST,
    priv_pem: str | None = None,
    pub_pem: str | None = None,
    warmup: int = 5,
    runs: int = 30,
) -> dict[str, Any]:
    """Measure isolated cryptographic sign and verify operations over manifest bytes."""
    if not priv_pem or not pub_pem:
        priv_pem, pub_pem, _ = generate_keypair(profile)

    # Warmup
    for _ in range(warmup):
        sig = sign_bytes(priv_pem, manifest_bytes)
        verify_bytes(pub_pem, profile, manifest_bytes, sig)

    # Isolated Sign
    sign_latencies = []
    last_sig = b""
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        last_sig = sign_bytes(priv_pem, manifest_bytes)
        sign_latencies.append(time.perf_counter_ns() - t0)

    # Isolated Verify
    verify_latencies = []
    verify_ok = True
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        ok = verify_bytes(pub_pem, profile, manifest_bytes, last_sig)
        verify_latencies.append(time.perf_counter_ns() - t0)
        verify_ok = verify_ok and ok

    return {
        "profile": profile,
        "manifest_len": len(manifest_bytes),
        "runs": runs,
        "verify_ok": verify_ok,
        "sign_median_ns": float(statistics.median(sign_latencies)),
        "sign_p95_ns": nearest_rank_p95(sign_latencies),
        "verify_median_ns": float(statistics.median(verify_latencies)),
        "verify_p95_ns": nearest_rank_p95(verify_latencies),
        "sign_latencies_ns": sign_latencies,
        "verify_latencies_ns": verify_latencies,
    }


def measure_byte_sizes(
    profile: str,
    priv_pem: str,
    pub_pem: str,
    manifest_bytes: bytes = DEFAULT_MANIFEST,
) -> dict[str, int]:
    """Record real unencrypted DER keys, raw signature, and estimated bundle size."""
    priv_obj = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    pub_obj = serialization.load_pem_public_key(pub_pem.encode())

    der_priv = priv_obj.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    der_pub = pub_obj.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sig = sign_bytes(priv_pem, manifest_bytes)

    bundle_repr = json.dumps(
        {
            "schema": "minisign-bundle/v1",
            "manifest": base64.b64encode(manifest_bytes).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")

    return {
        "der_private_key_bytes": len(der_priv),
        "der_public_key_bytes": len(der_pub),
        "raw_signature_bytes": len(sig),
        "bundle_estimate_bytes": len(bundle_repr),
    }


def run_micro_benchmarks(
    artifact_sizes: tuple[int, ...] = (10 * 1024, 1024 * 1024, 10 * 1024 * 1024),
    runs: int = 30,
    warmup: int = 5,
) -> dict[str, Any]:
    """Execute full suite of Table 2.12 micro-benchmarks."""
    results: dict[str, Any] = {"keygen": {}, "hash": {}, "crypto_ops": {}, "sizes": {}}

    for p in PROFILES:
        res = measure_keygen(p, runs=max(5, runs // 6))
        results["keygen"][p] = res
        priv, pub, _ = res["sample_keys"]
        results["crypto_ops"][p] = measure_crypto_sign_verify(
            p, DEFAULT_MANIFEST, priv, pub, warmup=warmup, runs=runs
        )
        results["sizes"][p] = measure_byte_sizes(p, priv, pub, DEFAULT_MANIFEST)

    for sz in artifact_sizes:
        dummy_data = b"X" * sz
        label = f"{sz // 1024}KB" if sz < 1024 * 1024 else f"{sz // (1024 * 1024)}MB"
        results["hash"][label] = measure_artifact_hash(dummy_data, warmup=warmup, runs=runs)

    return results


if __name__ == "__main__":
    print("Running veriseal crypto micro-benchmarks...")
    res = run_micro_benchmarks(artifact_sizes=(10 * 1024, 1024 * 1024, 10 * 1024 * 1024))

    print("\n>>> 1. Key Generation Latency (ns)")
    for prof, data in res["keygen"].items():
        print(f"  [{prof}] Median: {data['median_ns']:.0f} ns | P95: {data['p95_ns']:.0f} ns")

    print("\n>>> 2. Artifact SHA-256 Latency (ns)")
    for lbl, data in res["hash"].items():
        print(f"  [{lbl}] Median: {data['median_ns']:.0f} ns | P95: {data['p95_ns']:.0f} ns")

    print("\n>>> 3. Isolated Crypto Sign & Verify Latency (ns)")
    for prof, data in res["crypto_ops"].items():
        print(f"  [{prof}] Sign Median: {data['sign_median_ns']:.0f} ns | P95: {data['sign_p95_ns']:.0f} ns")
        print(f"  [{prof}] Verify Median: {data['verify_median_ns']:.0f} ns | P95: {data['verify_p95_ns']:.0f} ns")

    print("\n>>> 4. Real Byte Sizes (bytes)")
    for prof, data in res["sizes"].items():
        print(f"  [{prof}] DER Priv: {data['der_private_key_bytes']}B | DER Pub: {data['der_public_key_bytes']}B | Sig: {data['raw_signature_bytes']}B | Bundle: {data['bundle_estimate_bytes']}B")
