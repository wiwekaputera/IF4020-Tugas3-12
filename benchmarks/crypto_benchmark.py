"""Micro-benchmarks and End-to-End CLI benchmarks for veriseal."""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from cryptography.hazmat.primitives import serialization

# Allow running without installing the package
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from veriseal import cli
from veriseal.contracts import PROFILES
from veriseal.crypto import generate_keypair, inspect_key, sign_bytes, verify_bytes
from veriseal.formats import build_bundle, build_manifest, hash_file, serialize_manifest

RESULTS_DIR = Path(__file__).resolve().parent / "results"

DEFAULT_MANIFEST = serialize_manifest(
    build_manifest(
        package="contoh-app",
        version="1.0.0",
        algorithm="ed25519",
        keyid="8326a614cf1e5f2c4ecc107656f2577a00e813eafe4dc748c88819a00ef44d86",
        name="contoh-app.zip",
        size=1048576,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
)

ARTIFACT_SPECS: tuple[tuple[str, str, int], ...] = (
    ("10KB", "artifact-10kb.bin", 10 * 1024),
    ("1MB", "artifact-1mb.bin", 1024 * 1024),
    ("50MB", "artifact-50mb.bin", 50 * 1024 * 1024),
)


def nearest_rank_p95(data: list[int | float]) -> float:
    """Calculate 95th percentile using nearest-rank method: ceil(0.95 * n)."""
    if not data:
        raise ValueError("data cannot be empty")
    s = sorted(data)
    idx = math.ceil(0.95 * len(s)) - 1
    return float(s[idx])


def _canonical_manifest_for(profile: str, keyid: str, name: str = "contoh-app.zip", size: int = 1048576) -> bytes:
    """Build canonical manifest bytes M for a given profile and keyid."""
    return serialize_manifest(
        build_manifest(
            package="contoh-app",
            version="1.0.0",
            algorithm=profile,
            keyid=keyid,
            name=name,
            size=size,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
    )


def measure_keygen(profile: str, runs: int = 5, warmup: int = 1) -> dict[str, Any]:
    """Measure keypair generation latency (monotonic ns) over N runs."""
    for _ in range(warmup):
        generate_keypair(profile)
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
    """Measure isolated SHA-256 artifact hashing time over in-memory bytes."""
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


def measure_file_hash(path: Path, warmup: int = 5, runs: int = 30) -> dict[str, Any]:
    """Measure streaming SHA-256 artifact hashing time via veriseal.formats.hash_file."""
    size_bytes = path.stat().st_size
    for _ in range(warmup):
        hash_file(str(path))
    latencies = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        hash_file(str(path))
        latencies.append(time.perf_counter_ns() - t0)
    return {
        "size_bytes": size_bytes,
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

    for _ in range(warmup):
        sig = sign_bytes(priv_pem, manifest_bytes)
        verify_bytes(pub_pem, profile, manifest_bytes, sig)

    sign_latencies = []
    last_sig = b""
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        last_sig = sign_bytes(priv_pem, manifest_bytes)
        sign_latencies.append(time.perf_counter_ns() - t0)

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
    manifest_bytes: bytes | None = None,
) -> dict[str, int]:
    """Record unencrypted DER keys, PEM keys, canonical manifest, raw signature, and real bundle size."""
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
    info = inspect_key(pub_pem)
    if manifest_bytes is None:
        manifest_bytes = _canonical_manifest_for(profile, info.keyid)

    sig = sign_bytes(priv_pem, manifest_bytes)
    bundle_bytes = build_bundle(manifest_bytes, sig)

    return {
        "der_private_key_bytes": len(der_priv),
        "der_public_key_bytes": len(der_pub),
        "pem_private_key_bytes": len(priv_pem.encode("ascii")),
        "pem_public_key_bytes": len(pub_pem.encode("ascii")),
        "manifest_bytes": len(manifest_bytes),
        "raw_signature_bytes": len(sig),
        "bundle_bytes": len(bundle_bytes),
        "bundle_estimate_bytes": len(bundle_bytes),
    }


def _invoke_cli_quiet(argv: list[str]) -> int:
    """Run veriseal.cli.main(argv) while capturing stdout/stderr."""
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
        return cli.main(argv)


def measure_e2e_cli(
    artifact_specs: tuple[tuple[str, str, int], ...] = ARTIFACT_SPECS,
    warmup: int = 5,
    runs: int = 30,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Measure full End-to-End CLI `veriseal sign` and `veriseal verify` across 3 artifacts and 3 profiles.

    Includes CLI argument parsing, file I/O, streaming SHA-256 calculation,
    canonical manifest/bundle/trust-store parsing & validation, cryptographic
    signing/verification, and atomic file writing.
    """
    results: dict[str, dict[str, dict[str, Any]]] = {p: {} for p in PROFILES}

    with tempfile.TemporaryDirectory(prefix="veriseal-e2e-bench-") as tmpdir:
        work = Path(tmpdir)
        trust_path = work / "trust.json"

        key_paths: dict[str, Path] = {}
        for profile in PROFILES:
            prefix = work / f"key-{profile}"
            rc = _invoke_cli_quiet(["keygen", "--algorithm", profile, "--out", str(prefix), "--force"])
            if rc != 0:
                raise RuntimeError(f"E2E keygen failed for {profile}")
            key_paths[profile] = Path(f"{prefix}.key.pem")
            rc = _invoke_cli_quiet(
                [
                    "trust",
                    "add",
                    "--key",
                    f"{prefix}.pub.pem",
                    "--package",
                    "contoh-app",
                    "--store",
                    str(trust_path),
                ]
            )
            if rc != 0:
                raise RuntimeError(f"E2E trust add failed for {profile}")

        # Same artifact bytes for every profile
        artifact_paths: dict[str, Path] = {}
        rng_block = hashlib.sha256(b"veriseal-benchmark-seed").digest() * (1024 // 32)  # 1 KB block
        for label, filename, size_bytes in artifact_specs:
            art_path = work / filename
            with open(art_path, "wb") as f:
                remaining = size_bytes
                while remaining > 0:
                    chunk = rng_block if remaining >= len(rng_block) else rng_block[:remaining]
                    f.write(chunk)
                    remaining -= len(chunk)
            artifact_paths[label] = art_path

        for label, filename, size_bytes in artifact_specs:
            art_path = artifact_paths[label]
            for profile in PROFILES:
                priv_path = key_paths[profile]
                bundle_path = work / f"bundle-{profile}-{label}.json"

                sign_argv = [
                    "sign",
                    "--file",
                    str(art_path),
                    "--package",
                    "contoh-app",
                    "--version",
                    "1.0.0",
                    "--key",
                    str(priv_path),
                    "--out",
                    str(bundle_path),
                ]
                verify_argv = [
                    "verify",
                    "--file",
                    str(art_path),
                    "--bundle",
                    str(bundle_path),
                    "--trust-store",
                    str(trust_path),
                    "--package",
                    "contoh-app",
                    "--version",
                    "1.0.0",
                    "--json",
                ]

                for _ in range(warmup):
                    if bundle_path.exists():
                        bundle_path.unlink()
                    rc_s = _invoke_cli_quiet(sign_argv)
                    rc_v = _invoke_cli_quiet(verify_argv)
                    if rc_s != 0 or rc_v != 0:
                        raise RuntimeError(f"Warmup failed for {profile} {label}: sign={rc_s}, verify={rc_v}")

                sign_latencies: list[int] = []
                for _ in range(runs):
                    if bundle_path.exists():
                        bundle_path.unlink()
                    t0 = time.perf_counter_ns()
                    rc_s = _invoke_cli_quiet(sign_argv)
                    sign_latencies.append(time.perf_counter_ns() - t0)
                    if rc_s != 0:
                        raise RuntimeError(f"E2E sign failed for {profile} {label}")

                verify_latencies: list[int] = []
                for _ in range(runs):
                    t0 = time.perf_counter_ns()
                    rc_v = _invoke_cli_quiet(verify_argv)
                    verify_latencies.append(time.perf_counter_ns() - t0)
                    if rc_v != 0:
                        raise RuntimeError(f"E2E verify failed for {profile} {label}")

                results[profile][label] = {
                    "profile": profile,
                    "artifact_label": label,
                    "artifact_name": filename,
                    "artifact_size_bytes": size_bytes,
                    "bundle_size_bytes": bundle_path.stat().st_size,
                    "warmup": warmup,
                    "runs": runs,
                    "sign_median_ns": float(statistics.median(sign_latencies)),
                    "sign_p95_ns": nearest_rank_p95(sign_latencies),
                    "verify_median_ns": float(statistics.median(verify_latencies)),
                    "verify_p95_ns": nearest_rank_p95(verify_latencies),
                    "sign_latencies_ns": sign_latencies,
                    "verify_latencies_ns": verify_latencies,
                }

    return results


def get_environment_specs() -> dict[str, str]:
    """Collect hardware, OS, Python runtime, and library version metadata."""
    cpu_model = platform.processor() or "Unknown"
    if Path("/proc/cpuinfo").exists():
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break

    mem_total = "Unknown"
    if Path("/proc/meminfo").exists():
        for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("MemTotal:"):
                mem_total = line.split(":", 1)[1].strip()
                break

    return {
        "cpu_model": cpu_model,
        "cpu_logical_cores": str(os.cpu_count() or 1),
        "ram_total": mem_total,
        "os_platform": platform.platform(),
        "os_kernel": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python_version": platform.python_version(),
        "cryptography_version": cryptography.__version__,
        "openssl_version": openssl_backend.openssl_version_text(),
        "timer": "time.perf_counter_ns (monotonic clock)",
        "percentile_method": "nearest-rank: ceil(0.95 * n) (1-indexed)",
    }


def run_micro_benchmarks(
    artifact_sizes: tuple[int, ...] = (10 * 1024, 1024 * 1024, 10 * 1024 * 1024),
    runs: int = 30,
    warmup: int = 5,
) -> dict[str, Any]:
    """Run the keygen, hash, sign/verify and size micro-benchmarks."""
    results: dict[str, Any] = {"keygen": {}, "hash": {}, "crypto_ops": {}, "sizes": {}}

    for p in PROFILES:
        res = measure_keygen(p, runs=max(5, runs // 6))
        results["keygen"][p] = res
        priv, pub, keyid = res["sample_keys"]
        manifest_bytes = _canonical_manifest_for(p, keyid)
        results["crypto_ops"][p] = measure_crypto_sign_verify(
            p, manifest_bytes, priv, pub, warmup=warmup, runs=runs
        )
        results["sizes"][p] = measure_byte_sizes(p, priv, pub, manifest_bytes)

    for sz in artifact_sizes:
        dummy_data = b"X" * sz
        label = f"{sz // 1024}KB" if sz < 1024 * 1024 else f"{sz // (1024 * 1024)}MB"
        results["hash"][label] = measure_artifact_hash(dummy_data, warmup=warmup, runs=runs)

    return results


def run_full_benchmarks(
    artifact_specs: tuple[tuple[str, str, int], ...] = ARTIFACT_SPECS,
    keygen_runs: int = 10,
    runs: int = 30,
    warmup: int = 5,
    results_dir: Path = RESULTS_DIR,
) -> dict[str, Any]:
    """Run all benchmarks (micro + E2E CLI) and write the results to benchmarks/results/."""
    results_dir.mkdir(parents=True, exist_ok=True)
    env = get_environment_specs()

    keygen_res: dict[str, Any] = {}
    crypto_ops_res: dict[str, Any] = {}
    sizes_res: dict[str, Any] = {}

    for p in PROFILES:
        kg = measure_keygen(p, runs=keygen_runs, warmup=1)
        priv, pub, keyid = kg["sample_keys"]
        keygen_res[p] = {k: v for k, v in kg.items() if k != "sample_keys"}
        manifest_bytes = _canonical_manifest_for(p, keyid)
        crypto_ops_res[p] = measure_crypto_sign_verify(
            p, manifest_bytes, priv, pub, warmup=warmup, runs=runs
        )
        sizes_res[p] = measure_byte_sizes(p, priv, pub, manifest_bytes)

    hash_res: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="veriseal-hash-bench-") as td:
        tdir = Path(td)
        for label, filename, sz in artifact_specs:
            fpath = tdir / filename
            fpath.write_bytes(b"A" * sz)
            in_mem = measure_artifact_hash(b"A" * sz, warmup=warmup, runs=runs)
            streamed = measure_file_hash(fpath, warmup=warmup, runs=runs)
            hash_res[label] = {
                "size_bytes": sz,
                "runs": runs,
                "in_memory_median_ns": in_mem["median_ns"],
                "in_memory_p95_ns": in_mem["p95_ns"],
                "in_memory_latencies_ns": in_mem["latencies_ns"],
                "file_stream_median_ns": streamed["median_ns"],
                "file_stream_p95_ns": streamed["p95_ns"],
                "file_stream_latencies_ns": streamed["latencies_ns"],
                "median_ns": streamed["median_ns"],
                "p95_ns": streamed["p95_ns"],
                "latencies_ns": streamed["latencies_ns"],
            }

    e2e_res = measure_e2e_cli(artifact_specs=artifact_specs, warmup=warmup, runs=runs)

    full_data = {
        "environment": env,
        "parameters": {
            "keygen_runs": keygen_runs,
            "warmup_runs": warmup,
            "measured_runs": runs,
            "artifacts": [
                {"label": lbl, "name": fname, "size_bytes": sz} for lbl, fname, sz in artifact_specs
            ],
        },
        "keygen": keygen_res,
        "hash": hash_res,
        "crypto_ops": crypto_ops_res,
        "e2e": e2e_res,
        "sizes": sizes_res,
    }

    json_path = results_dir / "benchmark_results.json"
    json_path.write_text(json.dumps(full_data, indent=2) + "\n", encoding="utf-8")

    csv_path = results_dir / "raw_latencies.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "profile", "artifact_label", "operation", "run_index", "latency_ns", "latency_ms"])
        for p, d in keygen_res.items():
            for idx, ns in enumerate(d["latencies_ns"], 1):
                writer.writerow(["keygen", p, "N/A", "generate_keypair", idx, ns, f"{ns / 1e6:.6f}"])
        for lbl, d in hash_res.items():
            for idx, ns in enumerate(d["in_memory_latencies_ns"], 1):
                writer.writerow(["artifact_hash", "sha256", lbl, "sha256_memory", idx, ns, f"{ns / 1e6:.6f}"])
            for idx, ns in enumerate(d["file_stream_latencies_ns"], 1):
                writer.writerow(["artifact_hash", "sha256", lbl, "sha256_file_stream", idx, ns, f"{ns / 1e6:.6f}"])
        for p, d in crypto_ops_res.items():
            for idx, ns in enumerate(d["sign_latencies_ns"], 1):
                writer.writerow(["isolated_crypto", p, "manifest_M", "sign_bytes", idx, ns, f"{ns / 1e6:.6f}"])
            for idx, ns in enumerate(d["verify_latencies_ns"], 1):
                writer.writerow(["isolated_crypto", p, "manifest_M", "verify_bytes", idx, ns, f"{ns / 1e6:.6f}"])
        for p, by_label in e2e_res.items():
            for lbl, d in by_label.items():
                for idx, ns in enumerate(d["sign_latencies_ns"], 1):
                    writer.writerow(["e2e_cli", p, lbl, "veriseal_sign", idx, ns, f"{ns / 1e6:.6f}"])
                for idx, ns in enumerate(d["verify_latencies_ns"], 1):
                    writer.writerow(["e2e_cli", p, lbl, "veriseal_verify", idx, ns, f"{ns / 1e6:.6f}"])

    md_path = results_dir / "SUMMARY.md"
    _write_summary_markdown(md_path, full_data)

    return full_data


def _ns_to_ms(ns: float) -> str:
    return f"{ns / 1e6:.3f}"


def _ns_to_us(ns: float) -> str:
    return f"{ns / 1e3:.2f}"


def _write_summary_markdown(path: Path, data: dict[str, Any]) -> None:
    env = data["environment"]
    params = data["parameters"]
    lines = [
        "# Performance Benchmark Results (`veriseal` — Table 2.12)",
        "",
        "## 1. Environment & Methodology",
        "",
        "| Component | Specification |",
        "| :--- | :--- |",
        f"| **CPU** | {env['cpu_model']} ({env['cpu_logical_cores']} logical cores) |",
        f"| **Memory (RAM)** | {env['ram_total']} |",
        f"| **Operating System / Kernel** | {env['os_kernel']} (`{env['os_platform']}`) |",
        f"| **Python Runtime** | Python {env['python_version']} |",
        f"| **Cryptographic Library** | `cryptography` {env['cryptography_version']} ({env['openssl_version']}) |",
        f"| **Monotonic Timer** | `{env['timer']}` |",
        f"| **Percentile Formula** | {env['percentile_method']} |",
        f"| **Repetitions** | {params['warmup_runs']} warm-up runs + {params['measured_runs']} measured runs (Keygen: {params['keygen_runs']} runs) |",
        "",
        "---",
        "",
        "## 2. Key Generation Latency (`generate_keypair`)",
        "",
        "| Profile | Runs | Median (ms) | P95 (ms) | Median (µs) | P95 (µs) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]
    for p in PROFILES:
        d = data["keygen"][p]
        lines.append(
            f"| `{p}` | {d['runs']} | {_ns_to_ms(d['median_ns'])} | {_ns_to_ms(d['p95_ns'])} "
            f"| {_ns_to_us(d['median_ns'])} | {_ns_to_us(d['p95_ns'])} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 3. Artifact SHA-256 Hashing Latency",
            "",
            "| Artifact | Size (Bytes) | In-Memory Median (ms) | In-Memory P95 (ms) | File Stream Median (ms) | File Stream P95 (ms) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: |",
        ]
    )
    for lbl, d in data["hash"].items():
        lines.append(
            f"| **{lbl}** | {d['size_bytes']:,} | {_ns_to_ms(d['in_memory_median_ns'])} | {_ns_to_ms(d['in_memory_p95_ns'])} "
            f"| {_ns_to_ms(d['file_stream_median_ns'])} | {_ns_to_ms(d['file_stream_p95_ns'])} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 4. Isolated Cryptographic Sign & Verify Latency (over Canonical Manifest `M`)",
            "",
            "| Profile | Manifest `|M|` (B) | Sign Median (µs) | Sign P95 (µs) | Verify Median (µs) | Verify P95 (µs) | Sign Median (ms) | Verify Median (ms) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
    )
    for p in PROFILES:
        d = data["crypto_ops"][p]
        lines.append(
            f"| `{p}` | {d['manifest_len']} | {_ns_to_us(d['sign_median_ns'])} | {_ns_to_us(d['sign_p95_ns'])} "
            f"| {_ns_to_us(d['verify_median_ns'])} | {_ns_to_us(d['verify_p95_ns'])} "
            f"| {_ns_to_ms(d['sign_median_ns'])} | {_ns_to_ms(d['verify_median_ns'])} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 5. End-to-End CLI `veriseal sign` & `veriseal verify` Latency",
            "",
            "| Profile | Artifact | Size (Bytes) | E2E `sign` Median (ms) | E2E `sign` P95 (ms) | E2E `verify` Median (ms) | E2E `verify` P95 (ms) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
    )
    for p in PROFILES:
        for lbl, d in data["e2e"][p].items():
            lines.append(
                f"| `{p}` | **{lbl}** | {d['artifact_size_bytes']:,} "
                f"| {_ns_to_ms(d['sign_median_ns'])} | {_ns_to_ms(d['sign_p95_ns'])} "
                f"| {_ns_to_ms(d['verify_median_ns'])} | {_ns_to_ms(d['verify_p95_ns'])} |"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 6. Key, Signature, Manifest, and Bundle Byte Sizes",
            "",
            "| Profile | Private Key DER (B) | Public Key SPKI DER (B) | Private Key PEM (B) | Public Key PEM (B) | Canonical Manifest `M` (B) | Raw Signature (B) | Bundle JSON (B) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
    )
    for p in PROFILES:
        s = data["sizes"][p]
        lines.append(
            f"| `{p}` | {s['der_private_key_bytes']} | {s['der_public_key_bytes']} "
            f"| {s['pem_private_key_bytes']} | {s['pem_public_key_bytes']} "
            f"| {s['manifest_bytes']} | {s['raw_signature_bytes']} | {s['bundle_bytes']} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 7. How to Reproduce",
            "",
            "```sh",
            "uv run python benchmarks/crypto_benchmark.py",
            "```",
            "",
            "- Complete JSON output (with all raw latency arrays): `benchmarks/results/benchmark_results.json`",
            "- Complete CSV output (for Appendix `j.iii`): `benchmarks/results/raw_latencies.csv`",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    print("Running full veriseal benchmarks (Table 2.12: Keygen, Hash, Isolated Crypto, E2E CLI, Byte Sizes)...")
    res = run_full_benchmarks()

    print("\n>>> 1. Key Generation Latency")
    for prof, data in res["keygen"].items():
        print(f"  [{prof:<18}] Median: {data['median_ns']/1e6:8.3f} ms | P95: {data['p95_ns']/1e6:8.3f} ms")

    print("\n>>> 2. Artifact SHA-256 Latency (Streaming File I/O)")
    for lbl, data in res["hash"].items():
        print(f"  [{lbl:<6}] Median: {data['file_stream_median_ns']/1e6:8.3f} ms | P95: {data['file_stream_p95_ns']/1e6:8.3f} ms")

    print("\n>>> 3. Isolated Crypto Sign & Verify Latency")
    for prof, data in res["crypto_ops"].items():
        print(
            f"  [{prof:<18}] Sign Med: {data['sign_median_ns']/1e3:8.2f} µs (P95: {data['sign_p95_ns']/1e3:8.2f} µs) | "
            f"Verify Med: {data['verify_median_ns']/1e3:8.2f} µs (P95: {data['verify_p95_ns']/1e3:8.2f} µs)"
        )

    print("\n>>> 4. End-to-End CLI `veriseal sign` & `veriseal verify` Latency")
    for prof, by_lbl in res["e2e"].items():
        for lbl, data in by_lbl.items():
            print(
                f"  [{prof:<18} | {lbl:<4}] Sign Med: {data['sign_median_ns']/1e6:8.3f} ms (P95: {data['sign_p95_ns']/1e6:8.3f} ms) | "
                f"Verify Med: {data['verify_median_ns']/1e6:8.3f} ms (P95: {data['verify_p95_ns']/1e6:8.3f} ms)"
            )

    print("\n>>> 5. Byte Sizes (Table 2.12)")
    for prof, data in res["sizes"].items():
        print(
            f"  [{prof:<18}] DER Priv: {data['der_private_key_bytes']:4d}B | DER Pub: {data['der_public_key_bytes']:3d}B | "
            f"Manifest: {data['manifest_bytes']:3d}B | Sig: {data['raw_signature_bytes']:3d}B | Bundle: {data['bundle_bytes']:3d}B"
        )

    print(f"\nSaved full results to:\n  - {RESULTS_DIR / 'SUMMARY.md'}\n  - {RESULTS_DIR / 'benchmark_results.json'}\n  - {RESULTS_DIR / 'raw_latencies.csv'}")
