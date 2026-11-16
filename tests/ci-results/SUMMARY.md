# CI/CD Integration Test Results (`C01`–`C05`)

- **Pinned Image Reference:** `ghcr.io/wiwekaputera/if4020-tugas3-12/veriseal:1.0.0@sha256:bdd18999b4e9d27937c0b7344b3ffedaf8466bfdada21ed924a73e87cd6054ce`
- **Runner UID:GID:** `1001:1001`
- **Network Mode:** `--network none` (offline execution after `docker pull`)

## Scenario Matrix & Results

| ID | Profile | Scenario | Expected Exit | Actual Exit | `verification.json` Status | `DEPLOYED.marker` | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `C01-rsa-pss-sha256` | `rsa-pss-sha256` | Digest pull, sign, verify valid artifact, gate deploy | `0` | `0` | `OK` (`valid: true`) | **PRESENT** | **PASS** |
| `C01-ecdsa-p256-sha256` | `ecdsa-p256-sha256` | Digest pull, sign, verify valid artifact, gate deploy | `0` | `0` | `OK` (`valid: true`) | **PRESENT** | **PASS** |
| `C01-ed25519` | `ed25519` | Digest pull, sign, verify valid artifact, gate deploy | `0` | `0` | `OK` (`valid: true`) | **PRESENT** | **PASS** |
| `C02` | `ed25519` | Modify 1 byte of artifact after `sign` (same size/name) | `1` | `1` | `ARTIFACT_MISMATCH` (`valid: false`) | **ABSENT** | **PASS** |
| `C03` | `ed25519` | Verify valid bundle with empty trust store (`ci/empty-trust.json`) | `1` | `1` | `KEY_NOT_TRUSTED` (`valid: false`) | **ABSENT** | **PASS** |
| `C04` | `ed25519` | Verify with non-existent artifact path (`/input/non-existent.zip`) | `2` | `2` | `INPUT_ERROR` (`valid: false`) | **ABSENT** | **PASS** |
| `C05` | `ed25519` | Run CLI with `--user 1001:1001`, no TTY, `--network none` | `0` | `0` | `OK` (`valid: true`) | N/A (owner `1001:1001`) | **PASS** |

## Verification JSON Outputs

- **`C01 (rsa-pss-sha256)`:** `{"valid": true, "status": "OK", "message": "Signature and artifact are valid.", "algorithm": "rsa-pss-sha256", "keyid": "219075dd6523e5a542e108f0cfe752cbd0e8578c8f9c3a5a691f37c0a91154fa", "package": "contoh-app", "version": "1.0.0"}`
- **`C01 (ecdsa-p256-sha256)`:** `{"valid": true, "status": "OK", "message": "Signature and artifact are valid.", "algorithm": "ecdsa-p256-sha256", "keyid": "8293dd472dc883f84cbbe3fccddb58676f138dda95b3c8024dde2227e7931448", "package": "contoh-app", "version": "1.0.0"}`
- **`C01 (ed25519)`:** `{"valid": true, "status": "OK", "message": "Signature and artifact are valid.", "algorithm": "ed25519", "keyid": "d1340745590bdd90264565bb62ae366480c045bf119a65a59f08c13e284c955d", "package": "contoh-app", "version": "1.0.0"}`
- **`C02`:** `{"valid": false, "status": "ARTIFACT_MISMATCH", "message": "artifact SHA-256 does not match the manifest", "algorithm": "ed25519", "keyid": "d1340745590bdd90264565bb62ae366480c045bf119a65a59f08c13e284c955d", "package": "contoh-app", "version": "1.0.0"}`
- **`C03`:** `{"valid": false, "status": "KEY_NOT_TRUSTED", "message": "keyid is not in the trust store", "algorithm": "ed25519", "keyid": "d1340745590bdd90264565bb62ae366480c045bf119a65a59f08c13e284c955d", "package": "contoh-app", "version": "1.0.0"}`
- **`C04`:** `{"valid": false, "status": "INPUT_ERROR", "message": "cannot read artifact '/input/non-existent.zip': does not exist or is not a regular file", "algorithm": null, "keyid": null, "package": null, "version": null}`
- **`C05`:** `{"valid": true, "status": "OK", "message": "Signature and artifact are valid.", "algorithm": "ed25519", "keyid": "d1340745590bdd90264565bb62ae366480c045bf119a65a59f08c13e284c955d", "package": "contoh-app", "version": "1.0.0"}`
