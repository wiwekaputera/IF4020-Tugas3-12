"""Unit tests for Task 1.5: Crypto micro-benchmark module."""

import math
import unittest
from pathlib import Path

from veriseal.contracts import PROFILES
from veriseal.crypto import inspect_key

import sys
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.crypto_benchmark import (
    DEFAULT_MANIFEST,
    measure_artifact_hash,
    measure_byte_sizes,
    measure_crypto_sign_verify,
    measure_keygen,
    nearest_rank_p95,
)


def report(test_name: str, inp: str, expected: str, real: str, passed: bool) -> None:
    print(f"\n>>> Testing [{test_name}]")
    print(f"Input: {inp}")
    print(f"Expected Output: {expected}")
    print(f"Real Output: {real}")
    print(f"Status: [{'PASS' if passed else 'FAIL'}]")


class TestCryptoBenchmark(unittest.TestCase):
    def test_nearest_rank_p95(self):
        with self.assertRaises(ValueError):
            nearest_rank_p95([])

        # 100 elements: 1..100. ceil(0.95 * 100) = 95 -> index 94 -> 95
        data_100 = list(range(1, 101))
        p95_100 = nearest_rank_p95(data_100)
        passed_100 = p95_100 == 95.0

        # 20 elements: 1..20. ceil(0.95 * 20) = 19 -> index 18 -> 19
        data_20 = list(range(1, 21))
        p95_20 = nearest_rank_p95(data_20)
        passed_20 = p95_20 == 19.0

        all_passed = passed_100 and passed_20
        report(
            test_name="Nearest-Rank P95 Formula ceil(0.95 * n)",
            inp="data_100=[1..100], data_20=[1..20]",
            expected="p95_100=95.0, p95_20=19.0",
            real=f"p95_100={p95_100}, p95_20={p95_20}",
            passed=all_passed,
        )
        self.assertTrue(all_passed)

    def test_measure_keygen(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                res = measure_keygen(profile, runs=5)
                passed = (
                    res["runs"] == 5
                    and len(res["latencies_ns"]) == 5
                    and res["median_ns"] > 0
                    and res["p95_ns"] >= res["median_ns"]
                )
                priv, pub, keyid = res["sample_keys"]
                info = inspect_key(pub)
                key_valid = (info.profile == profile and info.keyid == keyid)
                all_passed = passed and key_valid

                report(
                    test_name=f"Benchmark Keygen ({profile})",
                    inp=f"profile='{profile}', runs=5",
                    expected=f"runs=5, median>0, profile='{profile}'",
                    real=f"runs={res['runs']}, median={res['median_ns']:.0f}ns, profile='{info.profile}'",
                    passed=all_passed,
                )
                self.assertTrue(all_passed)

    def test_measure_artifact_hash(self):
        payload = b"Hello, Veriseal Benchmark!" * 50
        res = measure_artifact_hash(payload, warmup=2, runs=10)
        passed = (
            res["size_bytes"] == len(payload)
            and res["runs"] == 10
            and len(res["latencies_ns"]) == 10
            and res["median_ns"] > 0
            and res["p95_ns"] > 0
        )
        report(
            test_name="Benchmark Artifact SHA-256",
            inp=f"payload_len={len(payload)}B, warmup=2, runs=10",
            expected=f"size={len(payload)}, runs=10, median>0",
            real=f"size={res['size_bytes']}, runs={res['runs']}, median={res['median_ns']:.0f}ns",
            passed=passed,
        )
        self.assertTrue(passed)

    def test_measure_crypto_sign_verify(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                res = measure_crypto_sign_verify(
                    profile=profile,
                    manifest_bytes=DEFAULT_MANIFEST,
                    warmup=2,
                    runs=5,
                )
                passed = (
                    res["verify_ok"] is True
                    and res["runs"] == 5
                    and res["sign_median_ns"] > 0
                    and res["verify_median_ns"] > 0
                )
                report(
                    test_name=f"Benchmark Isolated Sign & Verify ({profile})",
                    inp=f"profile='{profile}', manifest_len={len(DEFAULT_MANIFEST)}B, runs=5",
                    expected="verify_ok=True, runs=5, medians>0",
                    real=f"verify_ok={res['verify_ok']}, sign_med={res['sign_median_ns']:.0f}ns, verify_med={res['verify_median_ns']:.0f}ns",
                    passed=passed,
                )
                self.assertTrue(passed)

    def test_measure_byte_sizes(self):
        expected_sig_lens = {"rsa-pss-sha256": 384, "ecdsa-p256-sha256": 64, "ed25519": 64}
        for profile in PROFILES:
            with self.subTest(profile=profile):
                keygen_res = measure_keygen(profile, runs=1)
                priv, pub, _ = keygen_res["sample_keys"]
                sizes = measure_byte_sizes(profile, priv, pub, DEFAULT_MANIFEST)
                passed = (
                    sizes["der_private_key_bytes"] > 0
                    and sizes["der_public_key_bytes"] > 0
                    and sizes["raw_signature_bytes"] == expected_sig_lens[profile]
                    and sizes["bundle_estimate_bytes"] > sizes["raw_signature_bytes"]
                )
                report(
                    test_name=f"Benchmark Byte Sizes ({profile})",
                    inp=f"profile='{profile}'",
                    expected=f"raw_sig={expected_sig_lens[profile]}B, der_priv>0, der_pub>0",
                    real=f"raw_sig={sizes['raw_signature_bytes']}B, der_priv={sizes['der_private_key_bytes']}B, der_pub={sizes['der_public_key_bytes']}B, bundle={sizes['bundle_estimate_bytes']}B",
                    passed=passed,
                )
                self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()
