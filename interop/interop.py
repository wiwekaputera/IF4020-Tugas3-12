"""Interop: veriseal <-> OpenSSL CLI, both directions, all 3 profiles."""

import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from veriseal.contracts import PROFILES
from veriseal.crypto import sign_bytes, verify_bytes

KEYS = Path(__file__).resolve().parent.parent / "keys"
MSG = b'{"schema":"minisign-manifest/v1","note":"interop"}'
PSS = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"]


def ossl(*args) -> bool:
    return subprocess.run(["openssl", *map(str, args)], capture_output=True).returncode == 0


def ossl_sign(profile, key, msg, sig) -> None:
    if profile == "ed25519":
        ok = ossl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", msg, "-out", sig)
    else:
        extra = PSS if profile == "rsa-pss-sha256" else []
        ok = ossl("dgst", "-sha256", *extra, "-sign", key, "-out", sig, msg)
    assert ok, f"openssl sign failed ({profile})"


def ossl_verify(profile, pub, msg, sig) -> bool:
    if profile == "ed25519":
        return ossl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub, "-in", msg, "-sigfile", sig)
    extra = PSS if profile == "rsa-pss-sha256" else []
    return ossl("dgst", "-sha256", *extra, "-verify", pub, "-signature", sig, msg)


def raw_to_der(raw: bytes) -> bytes:  # ECDSA r||s -> DER
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def der_to_raw(der: bytes) -> bytes:  # ECDSA DER -> r||s
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def main() -> int:
    fails = 0
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        msg, bad = d / "m", d / "bad"
        msg.write_bytes(MSG)
        bad.write_bytes(MSG + b"x")
        for p in PROFILES:
            kp, pp = KEYS / f"test-{p}.key.pem", KEYS / f"test-{p}.pub.pem"
            priv, pub = kp.read_text(), pp.read_text()
            ec = p == "ecdsa-p256-sha256"
            sig = d / "sig"

            # veriseal signs -> openssl verifies
            raw = sign_bytes(priv, MSG)
            sig.write_bytes(raw_to_der(raw) if ec else raw)
            a = ossl_verify(p, pp, msg, sig)
            neg = not ossl_verify(p, pp, bad, sig)  # control: openssl must reject tampered msg

            # openssl signs -> veriseal verifies
            ossl_sign(p, kp, msg, sig)
            osig = sig.read_bytes()
            b = verify_bytes(pub, p, MSG, der_to_raw(osig) if ec else osig)

            res = a and neg and b
            fails += not res
            print(f"{'PASS' if res else 'FAIL'} {p}: veriseal->openssl={a} openssl->veriseal={b} openssl-rejects-tamper={neg}")
    return 1 if fails else 0

