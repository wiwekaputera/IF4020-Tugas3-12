"""Unit tests for Task 1.4: Cross-verification with OpenSSL CLI."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from veriseal.contracts import PROFILES
from veriseal.crypto import sign_bytes, verify_bytes

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"


def report(test_name: str, inp: str, expected: str, real: str, passed: bool) -> None:
    print(f"\n>>> Testing [{test_name}]")
    print(f"Input: {inp}")
    print(f"Expected Output: {expected}")
    print(f"Real Output: {real}")
    print(f"Status: [{'PASS' if passed else 'FAIL'}]")


class TestInterop(unittest.TestCase):
    def setUp(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl CLI not available in PATH")

    @staticmethod
    def _ossl(*args) -> bool:
        return subprocess.run(["openssl", *map(str, args)], capture_output=True).returncode == 0

    def test_openssl_cross_verification(self):
        msg = b'{"schema":"minisign-manifest/v1","note":"interop-unit-test"}'
        pss_opts = [
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:32",
            "-sigopt", "rsa_mgf1_md:sha256",
        ]

        with tempfile.TemporaryDirectory() as td:
            tpath = Path(td)
            msg_file = tpath / "msg.bin"
            bad_file = tpath / "bad.bin"
            sig_file = tpath / "sig.bin"

            msg_file.write_bytes(msg)
            bad_file.write_bytes(msg + b"tamper")

            for profile in PROFILES:
                with self.subTest(profile=profile):
                    priv_path = KEYS_DIR / f"test-{profile}.key.pem"
                    pub_path = KEYS_DIR / f"test-{profile}.pub.pem"
                    priv_pem = priv_path.read_text()
                    pub_pem = pub_path.read_text()
                    is_ec = profile == "ecdsa-p256-sha256"

                    # 1. veriseal signs -> OpenSSL verifies
                    raw_sig = sign_bytes(priv_pem, msg)
                    if is_ec:
                        r = int.from_bytes(raw_sig[:32], "big")
                        s = int.from_bytes(raw_sig[32:], "big")
                        sig_file.write_bytes(encode_dss_signature(r, s))
                    else:
                        sig_file.write_bytes(raw_sig)

                    if profile == "ed25519":
                        ossl_ok = self._ossl(
                            "pkeyutl", "-verify", "-rawin", "-pubin",
                            "-inkey", str(pub_path), "-in", str(msg_file), "-sigfile", str(sig_file)
                        )
                        ossl_tamper = self._ossl(
                            "pkeyutl", "-verify", "-rawin", "-pubin",
                            "-inkey", str(pub_path), "-in", str(bad_file), "-sigfile", str(sig_file)
                        )
                    else:
                        extra = pss_opts if profile == "rsa-pss-sha256" else []
                        ossl_ok = self._ossl(
                            "dgst", "-sha256", *extra, "-verify", str(pub_path),
                            "-signature", str(sig_file), str(msg_file)
                        )
                        ossl_tamper = self._ossl(
                            "dgst", "-sha256", *extra, "-verify", str(pub_path),
                            "-signature", str(sig_file), str(bad_file)
                        )

                    # 2. OpenSSL signs -> veriseal verifies
                    if profile == "ed25519":
                        signed = self._ossl(
                            "pkeyutl", "-sign", "-rawin", "-inkey", str(priv_path),
                            "-in", str(msg_file), "-out", str(sig_file)
                        )
                    else:
                        extra = pss_opts if profile == "rsa-pss-sha256" else []
                        signed = self._ossl(
                            "dgst", "-sha256", *extra, "-sign", str(priv_path),
                            "-out", str(sig_file), str(msg_file)
                        )

                    osig = sig_file.read_bytes()
                    if is_ec:
                        r, s = decode_dss_signature(osig)
                        veriseal_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                    else:
                        veriseal_sig = osig

                    veriseal_ok = verify_bytes(pub_pem, profile, msg, veriseal_sig)

                    passed = ossl_ok and (not ossl_tamper) and signed and veriseal_ok
                    report(
                        test_name=f"OpenSSL Interoperability ({profile})",
                        inp=f"profile='{profile}', msg={msg.decode()}",
                        expected="veriseal->openssl=True, openssl_rejects_tamper=True, openssl->veriseal=True",
                        real=f"veriseal->openssl={ossl_ok}, openssl_rejects_tamper={not ossl_tamper}, openssl->veriseal={veriseal_ok}",
                        passed=passed,
                    )
                    self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()
