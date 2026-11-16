# Black-Box Security Test Results (`U01`–`U14` + `SBOM00`–`SBOM02`)

## How to Run (Tata Cara Menjalankan Pengujian)

```sh
uv run python tests/run_tests.py
```

## Execution Metadata

- **Test Suite Command:** `uv run python tests/run_tests.py`
- **Target CLI:** `uv run --no-cache veriseal`
- **Base Input Fixtures (`berkas masukan`):** `tests/fixtures/` (`contoh-app.txt`, `contoh-app.bin`, `empty.dat`, `contoh-app.zip`, `sbom.json`)
- **Passed:** `32 / 32`

## Complete Test Matrix & Results

| ID | Profile | Input File(s) (`Berkas Masukan`) | Scenario | Expected (`Exit` / `Status` / `Valid`) | Actual (`Exit` / `Status` / `Valid`) | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `U01-rsa-pss-sha256-text` | `rsa-pss-sha256` | `tests/fixtures/contoh-app.txt` | Sign and verify text file (37 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-rsa-pss-sha256-binary` | `rsa-pss-sha256` | `tests/fixtures/contoh-app.bin` | Sign and verify binary file (4096 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-rsa-pss-sha256-empty` | `rsa-pss-sha256` | `tests/fixtures/empty.dat` | Sign and verify empty file (0 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-ecdsa-p256-sha256-text` | `ecdsa-p256-sha256` | `tests/fixtures/contoh-app.txt` | Sign and verify text file (37 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-ecdsa-p256-sha256-binary` | `ecdsa-p256-sha256` | `tests/fixtures/contoh-app.bin` | Sign and verify binary file (4096 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-ecdsa-p256-sha256-empty` | `ecdsa-p256-sha256` | `tests/fixtures/empty.dat` | Sign and verify empty file (0 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-ed25519-text` | `ed25519` | `tests/fixtures/contoh-app.txt` | Sign and verify text file (37 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-ed25519-binary` | `ed25519` | `tests/fixtures/contoh-app.bin` | Sign and verify binary file (4096 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U01-ed25519-empty` | `ed25519` | `tests/fixtures/empty.dat` | Sign and verify empty file (0 B) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U02` | `ed25519` | `tests/fixtures/contoh-app.zip (1B flipped)` | Modify 1 byte in artifact preserving size and filename | `1` / `ARTIFACT_MISMATCH` / `false` | `1` / `ARTIFACT_MISMATCH` / `false` | **PASS** |
| `U03a` | `ed25519` | `tests/fixtures/contoh-app.zip (+1B)` | Append 1 byte to artifact | `1` / `ARTIFACT_MISMATCH` / `false` | `1` / `ARTIFACT_MISMATCH` / `false` | **PASS** |
| `U03b` | `ed25519` | `tests/fixtures/contoh-app.zip (-1B)` | Truncate 1 byte from artifact | `1` / `ARTIFACT_MISMATCH` / `false` | `1` / `ARTIFACT_MISMATCH` / `false` | **PASS** |
| `U04` | `ed25519` | `tests/fixtures/contoh-app.zip + tampered manifest_b64` | Modify manifest version (1.0.0 -> 1.0.1) reusing old signature | `1` / `INVALID_SIGNATURE` / `false` | `1` / `INVALID_SIGNATURE` / `false` | **PASS** |
| `U05` | `ed25519` | `tests/fixtures/contoh-app.zip + 1-bit flipped signature_b64` | Flip 1 bit in signature_b64 preserving byte length | `1` / `INVALID_SIGNATURE` / `false` | `1` / `INVALID_SIGNATURE` / `false` | **PASS** |
| `U06a` | `ed25519` | `tests/fixtures/contoh-app.zip + empty trust store` | Verify using an empty trust store | `1` / `KEY_NOT_TRUSTED` / `false` | `1` / `KEY_NOT_TRUSTED` / `false` | **PASS** |
| `U06b` | `ed25519` | `tests/fixtures/contoh-app.zip + trust store after trust remove` | Remove publisher key via trust remove prior to verify | `1` / `KEY_NOT_TRUSTED` / `false` | `1` / `KEY_NOT_TRUSTED` / `false` | **PASS** |
| `U07` | `ed25519` | `tests/fixtures/contoh-app.zip + trust store (pkg=other-pkg)` | Verify with key only authorized for 'other-pkg' | `1` / `KEY_NOT_TRUSTED` / `false` | `1` / `KEY_NOT_TRUSTED` / `false` | **PASS** |
| `U08` | `ed25519` | `tests/fixtures/contoh-app.zip (--version 2.0.0)` | Verify valid v1.0.0 bundle with expected --version 2.0.0 | `1` / `METADATA_MISMATCH` / `false` | `1` / `METADATA_MISMATCH` / `false` | **PASS** |
| `U09` | `ed25519` | `tests/fixtures/contoh-app.zip renamed to renamed-app.zip` | Rename artifact file to renamed-app.zip with identical bytes | `1` / `METADATA_MISMATCH` / `false` | `1` / `METADATA_MISMATCH` / `false` | **PASS** |
| `U10a` | `ed25519` | `tests/fixtures/contoh-app.zip + bundle with duplicate key` | Reject duplicate JSON field name in bundle | `1` / `FORMAT_ERROR` / `false` | `1` / `FORMAT_ERROR` / `false` | **PASS** |
| `U10b` | `ed25519` | `tests/fixtures/contoh-app.zip + manifest with boolean size` | Reject wrong data type in manifest (size = true) | `1` / `FORMAT_ERROR` / `false` | `1` / `FORMAT_ERROR` / `false` | **PASS** |
| `U10c` | `ed25519` | `tests/fixtures/contoh-app.zip + bundle with invalid Base64` | Reject invalid Base64 in signature_b64 | `1` / `FORMAT_ERROR` / `false` | `1` / `FORMAT_ERROR` / `false` | **PASS** |
| `U10d` | `ed25519` | `tests/fixtures/contoh-app.zip + >16 KiB manifest` | Reject manifest exceeding 16 KiB size limit | `1` / `FORMAT_ERROR` / `false` | `1` / `FORMAT_ERROR` / `false` | **PASS** |
| `U11` | `rsa-pkcs1-v15` | `tests/fixtures/contoh-app.zip + manifest alg=rsa-pkcs1-v15` | Reject unsupported algorithm 'rsa-pkcs1-v15' in manifest | `1` / `UNSUPPORTED_ALGORITHM` / `false` | `1` / `UNSUPPORTED_ALGORITHM` / `false` | **PASS** |
| `U12` | `ed25519` | `tests/fixtures/contoh-app.zip signed by untrusted K2` | Sign with untrusted key K2 of same profile | `1` / `KEY_NOT_TRUSTED` / `false` | `1` / `KEY_NOT_TRUSTED` / `false` | **PASS** |
| `U13` | `ed25519` | `tests/fixtures/contoh-app.zip + reformatted outer bundle JSON` | Accept outer bundle with custom whitespace and reversed key order | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U14-rsa-pss-sha256` | `rsa-pss-sha256` | `tests/fixtures/contoh-app.zip (signed twice: bundle1 & bundle2)` | Sign twice, verify both & compare (Randomized 32B salt -> signatures differ) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U14-ecdsa-p256-sha256` | `ecdsa-p256-sha256` | `tests/fixtures/contoh-app.zip (signed twice: bundle1 & bundle2)` | Sign twice, verify both & compare (CSPRNG nonce -> differ) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `U14-ed25519` | `ed25519` | `tests/fixtures/contoh-app.zip (signed twice: bundle1 & bundle2)` | Sign twice, verify both & compare (Deterministic RFC 8032 -> signatures identical) | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `SBOM00` | `ed25519` | `tests/fixtures/sbom.json + tests/fixtures/contoh-app.zip` | Sign and verify valid SBOM bound to release artifact | `0` / `OK` / `true` | `0` / `OK` / `true` | **PASS** |
| `SBOM01` | `ed25519` | `tests/fixtures/sbom.json (tampered) + tests/fixtures/contoh-app.zip` | Modify SBOM component after signing | `1` / `ARTIFACT_MISMATCH` / `false` | `1` / `ARTIFACT_MISMATCH` / `false` | **PASS** |
| `SBOM02` | `ed25519` | `tests/fixtures/sbom.json (for A1) + swapped A2 contoh-app.zip` | Replace artifact A1 with validly signed A2 against A1 SBOM | `1` / `ARTIFACT_MISMATCH` / `false` | `1` / `ARTIFACT_MISMATCH` / `false` | **PASS** |
