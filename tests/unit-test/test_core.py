"""Unit tests for Task 1.2: Core crypto inspect, sign, and verify."""

import unittest
from pathlib import Path

from veriseal.contracts import PROFILES
from veriseal.crypto import (
    KeyInfo,
    _ORDER,
    _SIG_LEN,
    generate_keypair,
    inspect_key,
    sign_bytes,
    verify_bytes,
)

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"


def report(test_name: str, inp: str, expected: str, real: str, passed: bool) -> None:
    print(f"\n>>> Testing [{test_name}]")
    print(f"Input: {inp}")
    print(f"Expected Output: {expected}")
    print(f"Real Output: {real}")
    print(f"Status: [{'PASS' if passed else 'FAIL'}]")


class TestCryptoCore(unittest.TestCase):
    def test_inspect_key_valid_and_invalid_inputs(self):
        priv_pem, pub_pem, keyid = generate_keypair("ed25519")
        info = inspect_key(pub_pem)
        valid_passed = (info == KeyInfo(is_private=False, profile="ed25519", public_key_pem=pub_pem, keyid=keyid))

        report(
            test_name="Inspect Valid Public Key (ed25519)",
            inp=f"pub_pem (SPKI), keyid='{keyid}'",
            expected=f"KeyInfo(is_private=False, profile='ed25519', keyid='{keyid}')",
            real=f"KeyInfo(is_private={info.is_private}, profile='{info.profile}', keyid='{info.keyid}')",
            passed=valid_passed,
        )
        self.assertTrue(valid_passed)

        invalid_inputs = [
            ("plain string", "not a valid pem"),
            ("legacy pkcs1 pem", "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"),
        ]
        for name, bad_input in invalid_inputs:
            with self.subTest(case=name):
                err = ""
                try:
                    inspect_key(bad_input)
                except ValueError as e:
                    err = str(e)

                passed = len(err) > 0
                report(
                    test_name=f"Inspect Invalid Key ({name})",
                    inp=bad_input[:35] + ("..." if len(bad_input) > 35 else ""),
                    expected="ValueError",
                    real=f"ValueError('{err}')" if err else "No exception",
                    passed=passed,
                )
                self.assertTrue(passed)

    def test_sign_and_verify_payload_variations(self):
        payloads = [
            ("text_manifest", b'{"schema":"minisign-manifest/v1","package":"app","version":"1.0.0"}'),
            ("binary_payload", bytes(range(256)) * 4),
            ("empty_payload", b""),
        ]

        for payload_name, msg_bytes in payloads:
            for profile in PROFILES:
                with self.subTest(payload=payload_name, profile=profile):
                    priv, pub, _ = generate_keypair(profile)
                    sig = sign_bytes(priv, msg_bytes)
                    valid = verify_bytes(pub, profile, msg_bytes, sig)
                    passed = len(sig) == _SIG_LEN[profile] and valid is True

                    report(
                        test_name=f"Sign & Verify ({payload_name} / {profile})",
                        inp=f"payload_len={len(msg_bytes)}B, profile='{profile}'",
                        expected=f"sig_len={_SIG_LEN[profile]}, verify=True",
                        real=f"sig_len={len(sig)}, verify={valid}",
                        passed=passed,
                    )
                    self.assertTrue(passed)

    def test_deterministic_ed25519_golden_vector(self):
        priv_pem = (KEYS_DIR / "test-ed25519.key.pem").read_text()
        pub_pem = (KEYS_DIR / "test-ed25519.pub.pem").read_text()
        msg = b"hello veriseal"
        expected_sig_hex = (
            "1ba48791485f30c8dc1601fb8ca41a9eab1baa16e5763b3f06793ebed6e7dac0"
            "6123c1283915d535a1f18db62502ad073cbd8d38e3b42447745980def17b3f08"
        )

        sig = sign_bytes(priv_pem, msg)
        real_hex = sig.hex()
        verified = verify_bytes(pub_pem, "ed25519", msg, sig)
        passed = (real_hex == expected_sig_hex and verified is True)

        report(
            test_name="Ed25519 RFC 8032 Deterministic Vector",
            inp=f"msg=b'{msg.decode()}', priv_key=keys/test-ed25519.key.pem",
            expected=f"sig_hex='{expected_sig_hex[:32]}...', verify=True",
            real=f"sig_hex='{real_hex[:32]}...', verify={verified}",
            passed=passed,
        )
        self.assertTrue(passed)

    def test_sign_with_public_key_raises(self):
        _, pub, _ = generate_keypair("ed25519")
        err = ""
        try:
            sign_bytes(pub, b"msg")
        except ValueError as e:
            err = str(e)

        passed = "private key required" in err
        report(
            test_name="Sign With Public Key Error Check",
            inp="pub_pem passed to sign_bytes()",
            expected="ValueError('private key required')",
            real=f"ValueError('{err}')" if err else "No exception",
            passed=passed,
        )
        self.assertTrue(passed)

    def test_verify_tampered_payload_fails(self):
        msg = b"authentic data"
        for profile in PROFILES:
            with self.subTest(profile=profile):
                priv, pub, _ = generate_keypair(profile)
                sig = sign_bytes(priv, msg)
                verified = verify_bytes(pub, profile, msg + b"tamper", sig)
                passed = verified is False

                report(
                    test_name=f"Reject Tampered Payload ({profile})",
                    inp=f"msg='{msg.decode()}tamper', authentic signature",
                    expected="verify=False",
                    real=f"verify={verified}",
                    passed=passed,
                )
                self.assertTrue(passed)

    def test_verify_tampered_signature_fails(self):
        msg = b"authentic data"
        for profile in PROFILES:
            with self.subTest(profile=profile):
                priv, pub, _ = generate_keypair(profile)
                bad_sig = bytearray(sign_bytes(priv, msg))
                bad_sig[0] ^= 0x01
                verified = verify_bytes(pub, profile, msg, bytes(bad_sig))
                passed = verified is False

                report(
                    test_name=f"Reject 1-Bit Flipped Signature ({profile})",
                    inp=f"sig[0] ^= 0x01, authentic msg='{msg.decode()}'",
                    expected="verify=False",
                    real=f"verify={verified}",
                    passed=passed,
                )
                self.assertTrue(passed)

    def test_verify_mismatches_fail(self):
        msg = b"authentic data"
        priv1, pub1, _ = generate_keypair("ed25519")
        _, pub2, _ = generate_keypair("ed25519")
        sig = sign_bytes(priv1, msg)

        res_wrong_key = verify_bytes(pub2, "ed25519", msg, sig)
        res_wrong_prof = verify_bytes(pub1, "rsa-pss-sha256", msg, sig)
        res_priv_key = verify_bytes(priv1, "ed25519", msg, sig)
        res_truncated = verify_bytes(pub1, "ed25519", msg, sig[:10])

        passed = not any([res_wrong_key, res_wrong_prof, res_priv_key, res_truncated])
        report(
            test_name="Reject Key/Profile/Length Mismatches (ed25519)",
            inp="wrong_key, wrong_profile, priv_pem_as_pub, truncated_sig",
            expected="verify=False for all 4 mismatch conditions",
            real=f"wrong_key={res_wrong_key}, wrong_prof={res_wrong_prof}, priv={res_priv_key}, trunc={res_truncated}",
            passed=passed,
        )
        self.assertTrue(passed)

    def test_ecdsa_bounds_checks(self):
        priv, pub, _ = generate_keypair("ecdsa-p256-sha256")
        msg = b"ecdsa domain bounds check"
        sig = sign_bytes(priv, msg)
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")

        cases = [
            ("r_is_zero", (0).to_bytes(32, "big") + s.to_bytes(32, "big")),
            ("s_is_zero", r.to_bytes(32, "big") + (0).to_bytes(32, "big")),
            ("r_exceeds_order", _ORDER.to_bytes(32, "big") + s.to_bytes(32, "big")),
            ("s_exceeds_order", r.to_bytes(32, "big") + _ORDER.to_bytes(32, "big")),
        ]
        for name, invalid_sig in cases:
            with self.subTest(case=name):
                verified = verify_bytes(pub, "ecdsa-p256-sha256", msg, invalid_sig)
                passed = verified is False
                report(
                    test_name=f"ECDSA Out-of-bounds Check ({name})",
                    inp=f"invalid raw r||s ({name})",
                    expected="verify=False",
                    real=f"verify={verified}",
                    passed=passed,
                )
                self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()
