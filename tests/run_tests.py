#!/usr/bin/env python3
"""Automated black-box CLI test scenarios (U01-U14 + SBOM00-SBOM02) for veriseal."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import shutil
import sys
from pathlib import Path

from helpers import FIXTURES_DIR, RESULTS_DIR, ROOT_DIR, CliRunner, TestContext, make_sbom_fixture
from veriseal.contracts import BUNDLE_SCHEMA, PROFILES, TRUST_SCHEMA, Status


def ensure_fixtures(fixtures_dir: Path) -> tuple[Path, Path, Path, Path, Path]:
    """Create persistent base input files in tests/fixtures/ if not already present."""
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    text_file = fixtures_dir / "contoh-app.txt"
    if not text_file.exists():
        text_file.write_text("veriseal release notes v1.0.0\nline 2\n", encoding="utf-8")

    bin_file = fixtures_dir / "contoh-app.bin"
    if not bin_file.exists():
        bin_file.write_bytes(os.urandom(4096))

    empty_file = fixtures_dir / "empty.dat"
    if not empty_file.exists():
        empty_file.write_bytes(b"")

    base_zip = fixtures_dir / "contoh-app.zip"
    if not base_zip.exists():
        base_zip.write_bytes(b"PK\x03\x04veriseal-deterministic-payload-v1.0.0" * 32)

    sbom_file = fixtures_dir / "sbom.json"
    sbom_file.write_text(json.dumps(make_sbom_fixture(base_zip, "contoh-app", "1.0.0"), indent=2) + "\n", encoding="utf-8")

    return text_file, bin_file, empty_file, base_zip, sbom_file


def setup_context(runner: CliRunner) -> TestContext:
    # 1. Reset results directory
    if runner.results_dir.exists():
        shutil.rmtree(runner.results_dir)
    runner.results_dir.mkdir(parents=True, exist_ok=True)

    # 2. Ensure persistent input fixtures exist in tests/fixtures/
    text_file, bin_file, empty_file, base_zip, sbom_file = ensure_fixtures(FIXTURES_DIR)

    # 3. Create temporary scratch workspace for per-run bundles and keys
    work = runner.results_dir / "_work"
    work.mkdir(parents=True, exist_ok=True)
    trust_store = work / "trust.json"
    keyids: dict[str, str] = {}

    # 4. Generate keys & populate trust store for all 3 profiles
    for prof in PROFILES:
        prefix = work / f"pub-{prof}"
        res_kg = runner.invoke(["keygen", "--algorithm", prof, "--out", str(prefix), "--force"])
        if res_kg.returncode != 0:
            raise RuntimeError(f"Setup keygen failed for {prof}: {res_kg.stderr}")
        keyids[prof] = res_kg.stdout.strip().splitlines()[-1].strip()
        res_ta = runner.invoke(
            ["trust", "add", "--key", f"{prefix}.pub.pem", "--package", "contoh-app", "--store", str(trust_store)]
        )
        if res_ta.returncode != 0:
            raise RuntimeError(f"Setup trust add failed for {prof}: {res_ta.stderr}")

    # 5. Sign baseline reference bundle (ed25519) for tamper scenarios U02-U13
    ref_prof = "ed25519"
    ref_priv = work / f"pub-{ref_prof}.key.pem"
    ref_bundle = work / "ref_bundle.json"
    if runner.sign(base_zip, ref_priv, ref_bundle) != 0:
        raise RuntimeError("Setup baseline sign failed")
    ref_b_obj = json.loads(ref_bundle.read_text(encoding="utf-8"))
    raw_m = base64.b64decode(ref_b_obj["manifest_b64"])

    return TestContext(
        work=work,
        trust_store=trust_store,
        keyids=keyids,
        text_file=text_file,
        bin_file=bin_file,
        empty_file=empty_file,
        base_zip=base_zip,
        sbom_file=sbom_file,
        ref_prof=ref_prof,
        ref_priv=ref_priv,
        ref_bundle=ref_bundle,
        ref_b_obj=ref_b_obj,
        raw_m=raw_m,
    )


def _write_bundle(path: Path, manifest_bytes: bytes, sig_b64: str) -> None:
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signature_b64": sig_b64,
    }
    path.write_text(json.dumps(bundle), encoding="utf-8")


def test_u01(runner: CliRunner, ctx: TestContext) -> None:
    """U01: Sign and verify text, binary, and empty files across all 3 profiles."""
    files = [("text", ctx.text_file), ("binary", ctx.bin_file), ("empty", ctx.empty_file)]
    for prof in PROFILES:
        priv = ctx.work / f"pub-{prof}.key.pem"
        for label, fpath in files:
            tid = f"U01-{prof}-{label}"
            bundle = ctx.work / f"{tid}.json"
            rc = runner.sign(fpath, priv, bundle)
            runner.check_verify(
                tid,
                f"Sign and verify {label} file ({fpath.stat().st_size} B)",
                prof,
                fpath,
                bundle,
                ctx.trust_store,
                0,
                Status.OK,
                input_desc=str(fpath),
                extra_passed=(rc == 0),
            )


def test_u02(runner: CliRunner, ctx: TestContext) -> None:
    """U02: Flip 1 byte in artifact preserving file size and filename."""
    d = ctx.work / "u02"
    d.mkdir()
    art = d / "contoh-app.zip"
    mut = bytearray(ctx.base_zip.read_bytes())
    mut[0] ^= 0xFF
    art.write_bytes(bytes(mut))
    runner.check_verify(
        "U02",
        "Modify 1 byte in artifact preserving size and filename",
        ctx.ref_prof,
        art,
        ctx.ref_bundle,
        ctx.trust_store,
        1,
        Status.ARTIFACT_MISMATCH,
        input_desc=f"{ctx.base_zip} (1B flipped)",
    )


def test_u03(runner: CliRunner, ctx: TestContext) -> None:
    """U03: Append 1 byte (U03a) and truncate 1 byte (U03b) from artifact."""
    cases = [
        ("U03a", "Append 1 byte to artifact", ctx.base_zip.read_bytes() + b"\x00", f"{ctx.base_zip} (+1B)"),
        ("U03b", "Truncate 1 byte from artifact", ctx.base_zip.read_bytes()[:-1], f"{ctx.base_zip} (-1B)"),
    ]
    for sub_id, desc, data, in_desc in cases:
        d = ctx.work / sub_id
        d.mkdir()
        art = d / "contoh-app.zip"
        art.write_bytes(data)
        runner.check_verify(
            sub_id, desc, ctx.ref_prof, art, ctx.ref_bundle, ctx.trust_store, 1, Status.ARTIFACT_MISMATCH, input_desc=in_desc
        )


def test_u04(runner: CliRunner, ctx: TestContext) -> None:
    """U04: Modify version in manifest keeping original signature."""
    bundle = ctx.work / "u04_bundle.json"
    u04_m = ctx.raw_m.replace(b'"version":"1.0.0"', b'"version":"1.0.1"')
    _write_bundle(bundle, u04_m, ctx.ref_b_obj["signature_b64"])
    runner.check_verify(
        "U04",
        "Modify manifest version (1.0.0 -> 1.0.1) reusing old signature",
        ctx.ref_prof,
        ctx.base_zip,
        bundle,
        ctx.trust_store,
        1,
        Status.INVALID_SIGNATURE,
        input_desc=f"{ctx.base_zip} + tampered manifest_b64",
        ver="1.0.1",
    )


def test_u05(runner: CliRunner, ctx: TestContext) -> None:
    """U05: Flip 1 bit in signature preserving byte length and Base64."""
    bundle = ctx.work / "u05_bundle.json"
    sig_b = bytearray(base64.b64decode(ctx.ref_b_obj["signature_b64"]))
    sig_b[0] ^= 0x01
    _write_bundle(bundle, ctx.raw_m, base64.b64encode(bytes(sig_b)).decode("ascii"))
    runner.check_verify(
        "U05",
        "Flip 1 bit in signature_b64 preserving byte length",
        ctx.ref_prof,
        ctx.base_zip,
        bundle,
        ctx.trust_store,
        1,
        Status.INVALID_SIGNATURE,
        input_desc=f"{ctx.base_zip} + 1-bit flipped signature_b64",
    )


def test_u06(runner: CliRunner, ctx: TestContext) -> None:
    """U06: Empty trust store (U06a) and removed publisher key (U06b)."""
    empty_trust = ctx.work / "empty_trust.json"
    empty_trust.write_text(json.dumps({"schema": TRUST_SCHEMA, "keys": []}) + "\n", encoding="utf-8")
    runner.check_verify(
        "U06a",
        "Verify using an empty trust store",
        ctx.ref_prof,
        ctx.base_zip,
        ctx.ref_bundle,
        empty_trust,
        1,
        Status.KEY_NOT_TRUSTED,
        input_desc=f"{ctx.base_zip} + empty trust store",
    )

    removed_trust = ctx.work / "removed_trust.json"
    shutil.copyfile(ctx.trust_store, removed_trust)
    rm_rc = runner.invoke(
        ["trust", "remove", "--keyid", ctx.keyids[ctx.ref_prof], "--store", str(removed_trust)]
    ).returncode
    runner.check_verify(
        "U06b",
        "Remove publisher key via trust remove prior to verify",
        ctx.ref_prof,
        ctx.base_zip,
        ctx.ref_bundle,
        removed_trust,
        1,
        Status.KEY_NOT_TRUSTED,
        input_desc=f"{ctx.base_zip} + trust store after trust remove",
        extra_passed=(rm_rc == 0),
    )


def test_u07(runner: CliRunner, ctx: TestContext) -> None:
    """U07: Key authorized only for a different package."""
    other_trust = ctx.work / "other_trust.json"
    ta_rc = runner.invoke(
        [
            "trust",
            "add",
            "--key",
            str(ctx.work / f"pub-{ctx.ref_prof}.pub.pem"),
            "--package",
            "other-pkg",
            "--store",
            str(other_trust),
        ]
    ).returncode
    runner.check_verify(
        "U07",
        "Verify with key only authorized for 'other-pkg'",
        ctx.ref_prof,
        ctx.base_zip,
        ctx.ref_bundle,
        other_trust,
        1,
        Status.KEY_NOT_TRUSTED,
        input_desc=f"{ctx.base_zip} + trust store (pkg=other-pkg)",
        extra_passed=(ta_rc == 0),
    )


def test_u08(runner: CliRunner, ctx: TestContext) -> None:
    """U08: Matching package name but different expected version."""
    runner.check_verify(
        "U08",
        "Verify valid v1.0.0 bundle with expected --version 2.0.0",
        ctx.ref_prof,
        ctx.base_zip,
        ctx.ref_bundle,
        ctx.trust_store,
        1,
        Status.METADATA_MISMATCH,
        input_desc=f"{ctx.base_zip} (--version 2.0.0)",
        ver="2.0.0",
    )


def test_u09(runner: CliRunner, ctx: TestContext) -> None:
    """U09: Rename artifact file without modifying contents."""
    renamed_art = ctx.work / "renamed-app.zip"
    shutil.copyfile(ctx.base_zip, renamed_art)
    runner.check_verify(
        "U09",
        "Rename artifact file to renamed-app.zip with identical bytes",
        ctx.ref_prof,
        renamed_art,
        ctx.ref_bundle,
        ctx.trust_store,
        1,
        Status.METADATA_MISMATCH,
        input_desc=f"{ctx.base_zip} renamed to renamed-app.zip",
    )


def test_u10(runner: CliRunner, ctx: TestContext) -> None:
    """U10: 4 separate format errors (duplicate key, wrong type, bad Base64, >16 KiB manifest)."""
    u10a = ctx.work / "u10a.json"
    u10a.write_text(
        f'{{"schema":"{BUNDLE_SCHEMA}","schema":"{BUNDLE_SCHEMA}",'
        f'"manifest_b64":"{ctx.ref_b_obj["manifest_b64"]}",'
        f'"signature_b64":"{ctx.ref_b_obj["signature_b64"]}"}}\n',
        encoding="utf-8",
    )
    runner.check_verify(
        "U10a",
        "Reject duplicate JSON field name in bundle",
        ctx.ref_prof,
        ctx.base_zip,
        u10a,
        ctx.trust_store,
        1,
        Status.FORMAT_ERROR,
        input_desc=f"{ctx.base_zip} + bundle with duplicate key",
    )

    u10b = ctx.work / "u10b.json"
    bad_m = ctx.raw_m.replace(f'"size":{ctx.base_zip.stat().st_size}'.encode("ascii"), b'"size":true')
    _write_bundle(u10b, bad_m, ctx.ref_b_obj["signature_b64"])
    runner.check_verify(
        "U10b",
        "Reject wrong data type in manifest (size = true)",
        ctx.ref_prof,
        ctx.base_zip,
        u10b,
        ctx.trust_store,
        1,
        Status.FORMAT_ERROR,
        input_desc=f"{ctx.base_zip} + manifest with boolean size",
    )

    u10c = ctx.work / "u10c.json"
    _write_bundle(u10c, ctx.raw_m, "!!!not-valid-base64!!!")
    runner.check_verify(
        "U10c",
        "Reject invalid Base64 in signature_b64",
        ctx.ref_prof,
        ctx.base_zip,
        u10c,
        ctx.trust_store,
        1,
        Status.FORMAT_ERROR,
        input_desc=f"{ctx.base_zip} + bundle with invalid Base64",
    )

    u10d = ctx.work / "u10d.json"
    over_m = b'{"schema":"minisign-manifest/v1","pad":"' + (b"a" * 17000) + b'"}'
    _write_bundle(u10d, over_m, ctx.ref_b_obj["signature_b64"])
    runner.check_verify(
        "U10d",
        "Reject manifest exceeding 16 KiB size limit",
        ctx.ref_prof,
        ctx.base_zip,
        u10d,
        ctx.trust_store,
        1,
        Status.FORMAT_ERROR,
        input_desc=f"{ctx.base_zip} + >16 KiB manifest",
    )


def test_u11(runner: CliRunner, ctx: TestContext) -> None:
    """U11: Unsupported algorithm string in manifest."""
    u11 = ctx.work / "u11.json"
    u11_m = ctx.raw_m.replace(b'"algorithm":"ed25519"', b'"algorithm":"rsa-pkcs1-v15"')
    _write_bundle(u11, u11_m, ctx.ref_b_obj["signature_b64"])
    runner.check_verify(
        "U11",
        "Reject unsupported algorithm 'rsa-pkcs1-v15' in manifest",
        "rsa-pkcs1-v15",
        ctx.base_zip,
        u11,
        ctx.trust_store,
        1,
        Status.UNSUPPORTED_ALGORITHM,
        input_desc=f"{ctx.base_zip} + manifest alg=rsa-pkcs1-v15",
    )


def test_u12(runner: CliRunner, ctx: TestContext) -> None:
    """U12: Sign with untrusted key K2 of the same profile."""
    k2_prefix = ctx.work / "untrusted-k2"
    kg_rc = runner.invoke(["keygen", "--algorithm", ctx.ref_prof, "--out", str(k2_prefix), "--force"]).returncode
    u12_bundle = ctx.work / "u12.json"
    s_rc = runner.sign(ctx.base_zip, Path(f"{k2_prefix}.key.pem"), u12_bundle)
    runner.check_verify(
        "U12",
        "Sign with untrusted key K2 of same profile",
        ctx.ref_prof,
        ctx.base_zip,
        u12_bundle,
        ctx.trust_store,
        1,
        Status.KEY_NOT_TRUSTED,
        input_desc=f"{ctx.base_zip} signed by untrusted K2",
        extra_passed=(kg_rc == 0 and s_rc == 0),
    )


def test_u13(runner: CliRunner, ctx: TestContext) -> None:
    """U13: Reordered outer bundle keys with custom whitespace."""
    u13 = ctx.work / "u13.json"
    u13.write_text(
        "{\n"
        f'  "signature_b64" : "{ctx.ref_b_obj["signature_b64"]}" ,\n'
        f'  "manifest_b64" : "{ctx.ref_b_obj["manifest_b64"]}" ,\n'
        f'  "schema" : "{BUNDLE_SCHEMA}"\n'
        "}\n",
        encoding="utf-8",
    )
    runner.check_verify(
        "U13",
        "Accept outer bundle with custom whitespace and reversed key order",
        ctx.ref_prof,
        ctx.base_zip,
        u13,
        ctx.trust_store,
        0,
        Status.OK,
        input_desc=f"{ctx.base_zip} + reformatted outer bundle JSON",
    )


def test_u14(runner: CliRunner, ctx: TestContext) -> None:
    """U14: Sign identical manifest twice across all 3 profiles and compare signatures."""
    for prof in PROFILES:
        tid = f"U14-{prof}"
        priv = ctx.work / f"pub-{prof}.key.pem"
        b1, b2 = ctx.work / f"{tid}-1.json", ctx.work / f"{tid}-2.json"
        rc1 = runner.sign(ctx.base_zip, priv, b1)
        rc2 = runner.sign(ctx.base_zip, priv, b2)
        v1 = runner.invoke(
            [
                "verify",
                "--file", str(ctx.base_zip),
                "--bundle", str(b1),
                "--trust-store", str(ctx.trust_store),
                "--package", "contoh-app",
                "--version", "1.0.0",
                "--json",
            ]
        )
        same_sig = False
        if b1.exists() and b2.exists():
            same_sig = json.loads(b1.read_text())["signature_b64"] == json.loads(b2.read_text())["signature_b64"]
        if prof == "rsa-pss-sha256":
            sig_ok, note = not same_sig, "Randomized 32B salt -> signatures differ"
        elif prof == "ed25519":
            sig_ok, note = same_sig, "Deterministic RFC 8032 -> signatures identical"
        else:
            sig_ok, note = True, "Deterministic RFC 6979 -> identical" if same_sig else "CSPRNG nonce -> differ"
        runner.check_verify(
            tid,
            f"Sign twice, verify both & compare ({note})",
            prof,
            ctx.base_zip,
            b2,
            ctx.trust_store,
            0,
            Status.OK,
            input_desc=f"{ctx.base_zip} (signed twice: bundle1 & bundle2)",
            extra_passed=(rc1 == 0 and rc2 == 0 and v1.returncode == 0 and sig_ok),
            extra_notes=note,
        )


def test_sbom00(runner: CliRunner, ctx: TestContext) -> None:
    """SBOM00: Sign and verify valid SBOM bound to valid release artifact."""
    sbom0_b = ctx.work / "sbom0_bundle.json"
    s_rc = runner.invoke(
        [
            "sbom", "sign",
            "--file", str(ctx.sbom_file),
            "--artifact", str(ctx.base_zip),
            "--package", "contoh-app",
            "--version", "1.0.0",
            "--key", str(ctx.ref_priv),
            "--out", str(sbom0_b),
        ]
    ).returncode
    runner.check_verify(
        "SBOM00",
        "Sign and verify valid SBOM bound to release artifact",
        ctx.ref_prof,
        ctx.sbom_file,
        sbom0_b,
        ctx.trust_store,
        0,
        Status.OK,
        input_desc=f"{ctx.sbom_file} + {ctx.base_zip}",
        extra_passed=(s_rc == 0),
        custom_args=[
            "sbom", "verify",
            "--file", str(ctx.sbom_file),
            "--bundle", str(sbom0_b),
            "--artifact", str(ctx.base_zip),
            "--artifact-bundle", str(ctx.ref_bundle),
            "--trust-store", str(ctx.trust_store),
            "--package", "contoh-app",
            "--version", "1.0.0",
            "--json",
        ],
    )


def test_sbom01(runner: CliRunner, ctx: TestContext) -> None:
    """SBOM01: Modify SBOM component after signing."""
    sbom1 = ctx.work / "sbom1.json"
    sbom1_b = ctx.work / "sbom1_bundle.json"
    sbom1_obj = json.loads(ctx.sbom_file.read_text(encoding="utf-8"))
    sbom1.write_text(json.dumps(sbom1_obj, indent=2) + "\n", encoding="utf-8")
    s_rc = runner.invoke(
        [
            "sbom", "sign",
            "--file", str(sbom1),
            "--artifact", str(ctx.base_zip),
            "--package", "contoh-app",
            "--version", "1.0.0",
            "--key", str(ctx.ref_priv),
            "--out", str(sbom1_b),
        ]
    ).returncode
    sbom1_obj["components"][0]["version"] = "44.0.9-tampered"
    sbom1.write_text(json.dumps(sbom1_obj, indent=2) + "\n", encoding="utf-8")
    runner.check_verify(
        "SBOM01",
        "Modify SBOM component after signing",
        ctx.ref_prof,
        sbom1,
        sbom1_b,
        ctx.trust_store,
        1,
        Status.ARTIFACT_MISMATCH,
        input_desc=f"{ctx.sbom_file} (tampered) + {ctx.base_zip}",
        extra_passed=(s_rc == 0),
        custom_args=[
            "sbom", "verify",
            "--file", str(sbom1),
            "--bundle", str(sbom1_b),
            "--artifact", str(ctx.base_zip),
            "--artifact-bundle", str(ctx.ref_bundle),
            "--trust-store", str(ctx.trust_store),
            "--package", "contoh-app",
            "--version", "1.0.0",
            "--json",
        ],
    )


def test_sbom02(runner: CliRunner, ctx: TestContext) -> None:
    """SBOM02: Replace artifact A1 with validly signed A2 against A1 SBOM."""
    sbom2_b = ctx.work / "sbom2_bundle.json"
    sbom_rc = runner.invoke(
        [
            "sbom", "sign",
            "--file", str(ctx.sbom_file),
            "--artifact", str(ctx.base_zip),
            "--package", "contoh-app",
            "--version", "1.0.0",
            "--key", str(ctx.ref_priv),
            "--out", str(sbom2_b),
        ]
    ).returncode
    a2_dir = ctx.work / "a2"
    a2_dir.mkdir()
    a2_zip = a2_dir / "contoh-app.zip"
    a2_zip.write_bytes(b"PK\x03\x04different-release-artifact-A2-payload" * 32)
    a2_b = a2_dir / "a2_bundle.json"
    a2_rc = runner.sign(a2_zip, ctx.ref_priv, a2_b)
    runner.check_verify(
        "SBOM02",
        "Replace artifact A1 with validly signed A2 against A1 SBOM",
        ctx.ref_prof,
        ctx.sbom_file,
        sbom2_b,
        ctx.trust_store,
        1,
        Status.ARTIFACT_MISMATCH,
        input_desc=f"{ctx.sbom_file} (for A1) + swapped A2 contoh-app.zip",
        extra_passed=(sbom_rc == 0 and a2_rc == 0),
        custom_args=[
            "sbom", "verify",
            "--file", str(ctx.sbom_file),
            "--bundle", str(sbom2_b),
            "--artifact", str(a2_zip),
            "--artifact-bundle", str(a2_b),
            "--trust-store", str(ctx.trust_store),
            "--package", "contoh-app",
            "--version", "1.0.0",
            "--json",
        ],
    )


ALL_TESTS = [
    test_u01,
    test_u02,
    test_u03,
    test_u04,
    test_u05,
    test_u06,
    test_u07,
    test_u08,
    test_u09,
    test_u10,
    test_u11,
    test_u12,
    test_u13,
    test_u14,
    test_sbom00,
    test_sbom01,
    test_sbom02,
]


def run_all_tests(runner: CliRunner) -> int:
    ctx = setup_context(runner)
    try:
        for test_fn in ALL_TESTS:
            try:
                test_fn(runner, ctx)
            except Exception as exc:
                print(f"[FAIL] {test_fn.__name__:<22} | unhandled error: {exc}", file=sys.stderr)
                runner.records.append(
                    {
                        "id": test_fn.__name__,
                        "scenario": test_fn.__doc__ or "",
                        "profile": "n/a",
                        "input_files": "n/a",
                        "command": "",
                        "expected": {"exit_code": 0, "status": "N/A", "valid": False},
                        "actual": {"exit_code": -1, "status": "EXCEPTION", "valid": False, "stdout": "", "stderr": str(exc)},
                        "notes": "",
                        "passed": False,
                    }
                )
    finally:
        shutil.rmtree(ctx.work, ignore_errors=True)
    return runner.write_reports()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run U01-U14 and SBOM black-box tests.")
    parser.add_argument("--mock", action="store_true", help="Run against tests/mock_veriseal.py.")
    args = parser.parse_args()
    if args.mock:
        base_cmd = [sys.executable, "tests/mock_veriseal.py"]
        suite_cmd = "uv run python tests/run_tests.py --mock"
    else:
        base_cmd = shlex.split(os.environ.get("VERISEAL_CMD", "uv run --no-cache veriseal"))
        suite_cmd = "uv run python tests/run_tests.py"
    os.chdir(ROOT_DIR)
    return run_all_tests(CliRunner(base_cmd=base_cmd, suite_cmd=suite_cmd, results_dir=RESULTS_DIR))


if __name__ == "__main__":
    raise SystemExit(main())
