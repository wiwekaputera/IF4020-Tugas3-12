"""Unit tests for Task 1.3: Keypair generation and keys/ verification."""

import unittest
from pathlib import Path

from veriseal.contracts import PROFILES
from veriseal.crypto import (
    KeyInfo,
    _SIG_LEN,
    generate_keypair,
    inspect_key,
    sign_bytes,
    verify_bytes,
)

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"

EXPECTED_TEST_KEYIDS = {
    "rsa-pss-sha256": "00ac4599f135c12763211c80bfb65f06c4020a10a9ee7d193e67b6f7a810e469",
    "ecdsa-p256-sha256": "0229d5712f22ebbc96f3c28fbb19911b3711501b39b56a7a930ab51404c42f61",
    "ed25519": "8326a614cf1e5f2c4ecc107656f2577a00e813eafe4dc748c88819a00ef44d86",
}


def report(test_name: str, inp: str, expected: str, real: str, passed: bool) -> None:
    print(f"\n>>> Testing [{test_name}]")
    print(f"Input: {inp}")
    print(f"Expected Output: {expected}")
    print(f"Real Output: {real}")
    print(f"Status: [{'PASS' if passed else 'FAIL'}]")


class TestKeyGenerate(unittest.TestCase):
    def test_generate_all_profiles(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                priv, pub, keyid = generate_keypair(profile)
                info_priv = inspect_key(priv)
                info_pub = inspect_key(pub)

                passed = (
                    priv.startswith("-----BEGIN PRIVATE KEY-----")
                    and pub.startswith("-----BEGIN PUBLIC KEY-----")
                    and len(keyid) == 64
                    and info_priv.is_private is True
                    and info_pub.is_private is False
                    and info_priv.keyid == keyid
                    and info_pub.keyid == keyid
                )

                report(
                    test_name=f"Generate Keypair ({profile})",
                    inp=f"profile='{profile}'",
                    expected="PKCS#8 priv, SPKI pub, keyid len 64 hex, inspect_key matches",
                    real=f"keyid='{keyid}', priv_len={len(priv)}, pub_len={len(pub)}",
                    passed=passed,
                )
                self.assertTrue(passed)

    def test_generate_unknown_profile_raises(self):
        passed = False
        err_msg = ""
        try:
            generate_keypair("unknown-algo")
        except ValueError as e:
            passed = "unknown profile" in str(e)
            err_msg = str(e)

        report(
            test_name="Generate Unknown Profile",
            inp="profile='unknown-algo'",
            expected="ValueError('unknown profile: unknown-algo')",
            real=f"ValueError('{err_msg}')" if err_msg else "No exception",
            passed=passed,
        )
        self.assertTrue(passed)

    def test_pre_generated_keys_test_vectors(self):
        msg = b'{"schema":"minisign-manifest/v1","package":"demo","version":"1.0.0"}'
        for profile in PROFILES:
            with self.subTest(profile=profile):
                priv_file = KEYS_DIR / f"test-{profile}.key.pem"
                pub_file = KEYS_DIR / f"test-{profile}.pub.pem"
                priv_pem = priv_file.read_text()
                pub_pem = pub_file.read_text()

                priv_info = inspect_key(priv_pem)
                pub_info = inspect_key(pub_pem)
                expected_keyid = EXPECTED_TEST_KEYIDS[profile]

                sig = sign_bytes(priv_pem, msg)
                verify_ok = verify_bytes(pub_pem, profile, msg, sig)

                passed = (
                    priv_info.keyid == expected_keyid
                    and pub_info.keyid == expected_keyid
                    and priv_info.is_private is True
                    and pub_info.is_private is False
                    and len(sig) == _SIG_LEN[profile]
                    and verify_ok is True
                )

                report(
                    test_name=f"Pre-generated Keys Vector ({profile})",
                    inp=f"keys/test-{profile}.{{key,pub}}.pem, msg={msg.decode()}",
                    expected=f"keyid='{expected_keyid}', sig_len={_SIG_LEN[profile]}, verify=True",
                    real=f"keyid='{pub_info.keyid}', sig_len={len(sig)}, verify={verify_ok}",
                    passed=passed,
                )
                self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()
