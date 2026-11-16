# veriseal

Software release signing and verification tool for IF4020 Cryptography Assignment 3.

## Overview

`veriseal` signs and verifies software releases, following the blob-signing
flow of Sigstore Cosign but fully offline:

1. The publisher builds a **release manifest** (`minisign-manifest/v1`) that
   records the package name, version, signature profile, key fingerprint and
   the artifact's name, size and SHA-256.
2. The canonical manifest bytes are signed with the publisher's private key
   (RSA-PSS 3072, ECDSA P-256 or Ed25519). The manifest and signature are
   stored together in a **bundle** (`minisign-bundle/v1`).
3. The consumer verifies the bundle against a local **trust store**
   (`minisign-trust/v1`) that lists trusted public keys and the packages each
   key may sign, then checks the expected package/version and the artifact
   bytes. Verification stops at the first failing check and reports why.

A valid signature proves who published a release and that it arrived
unchanged. It does not prove that the software is free of malware.

<!-- P1: (ii) Tech stack, (iii) Dependencies, (vi-a) algorithm-to-library mapping & key formats, API docs URL -->

<!-- P3: (iv) Registry pull (tag + sha256 digest), CI/CD runner usage, test reproduction commands -->

## Local Setup (`uv`)

1. Install `uv` (skip if already installed):
   ```sh
   # macOS / Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # Windows (PowerShell)
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

2. Create `.venv` from `uv.lock` (needed for editor autocomplete):
   ```sh
   uv sync
   ```

3. Run the CLI:
   ```sh
   uv run veriseal --help
   ```

4. Add a dependency (updates `pyproject.toml` and `uv.lock` together):
   ```sh
   uv add <package>
   ```

## Usage Outside CI/CD

After `uv sync`, run commands with `uv run veriseal <subcommand> ...`, or
activate `.venv` and call `veriseal` directly. All commands are
non-interactive: missing options, invalid input and output conflicts fail
with a clear message on stderr and exit code `2`.

## Commands

| Command | Parameters | Output |
| :--- | :--- | :--- |
| `keygen` | `--algorithm <profile> --out <prefix> [--force]` | `<prefix>.key.pem` (PKCS#8, mode `0600`), `<prefix>.pub.pem` (SPKI). The key fingerprint is printed as the last stdout line. Existing files are only overwritten with `--force`. Missing parent directories are created. |
| `sign` | `--file <path> --package <name> --version <ver> --key <private.pem> --out <bundle.json>` | Bundle at `--out`. The profile comes from the private key. `--out` must not already exist. |
| `verify` | `--file <path> --bundle <bundle.json> --trust-store <trust.json> --package <name> --version <ver> [--json]` | Verification result. With `--json`, one JSON object on stdout (see below). |
| `trust add` | `--key <public.pem> --package <name> --store <trust.json>` | Authorizes the key for the package. Creates the store if missing. Prints `keyid  algorithm  packages`. Re-adding the same key/package is a no-op. |
| `trust list` | `--store <trust.json>` | One line per key: `keyid  algorithm  pkg1,pkg2`. |
| `trust remove` | `--keyid <fingerprint> --store <trust.json>` | Removes the entry. An unknown keyid exits with `2`. |
| `sbom sign` | `--file <sbom.json> --artifact <path> --package <name> --version <ver> --key <private.pem> --out <sbom.bundle.json>` | Checks that the SBOM records the artifact's SHA-256, then signs the SBOM file. |
| `sbom verify` | `--file <sbom.json> --bundle <sbom.bundle.json> --artifact <path> --artifact-bundle <bundle.json> --trust-store <trust.json> --package <name> --version <ver> [--json]` | Verifies both bundles and the SBOM-to-artifact SHA-256 binding. |
| global | `--help`, `--version` | Usage and program version. |

Profiles: `rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519`.

### Example (POSIX shell)

```sh
# Publisher
veriseal keygen --algorithm ed25519 --out keys/publisher
veriseal sign --file contoh-app.zip --package contoh-app \
  --version 1.0.0 --key keys/publisher.key.pem --out release.json

# Consumer (check the fingerprint through a trusted channel first)
veriseal trust add --key keys/publisher.pub.pem \
  --package contoh-app --store trust.json
veriseal trust list --store trust.json
veriseal verify --file contoh-app.zip --bundle release.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json

# Signed SBOM (bonus)
veriseal sbom sign --file sbom.json --artifact contoh-app.zip \
  --package contoh-app --version 1.0.0 \
  --key keys/publisher.key.pem --out sbom.bundle.json
veriseal sbom verify --file sbom.json --bundle sbom.bundle.json \
  --artifact contoh-app.zip --artifact-bundle release.json \
  --trust-store trust.json --package contoh-app --version 1.0.0 --json

# Revoke trust
veriseal trust remove --keyid <fingerprint> --store trust.json
```

### Verification order, statuses and exit codes

Checks run in this order and stop at the first failure:

| # | Status on failure | Check | Exit |
| :--- | :--- | :--- | :--- |
| 1 | `INPUT_ERROR` | Options valid, artifact/bundle/trust store readable | `2` |
| 2 | `FORMAT_ERROR` | Bundle, manifest (incl. canonical bytes) and trust store match their schemas; Base64 valid | `1` |
| 3 | `UNSUPPORTED_ALGORITHM` | Manifest `algorithm` is a supported profile | `1` |
| 4 | `KEY_NOT_TRUSTED` | `keyid` is in the trust store, its profile equals the manifest's, and it is authorized for `--package` | `1` |
| 5 | `INVALID_SIGNATURE` | Signature over the received manifest bytes verifies with the trusted key | `1` |
| 6 | `METADATA_MISMATCH` | Manifest package/version equal `--package`/`--version`; `artifact.name` equals the file's basename | `1` |
| 7 | `ARTIFACT_MISMATCH` | File size and SHA-256 equal the manifest | `1` |
| 8 | `OK` | All checks passed | `0` |

`verify --json` output (stdout, one line). The `algorithm`, `keyid`,
`package` and `version` fields are `null` until the manifest could be parsed:

```json
{"valid": true, "status": "OK", "message": "Signature and artifact are valid.", "algorithm": "ed25519", "keyid": "<fingerprint>", "package": "contoh-app", "version": "1.0.0"}
```

## File Formats

### Release manifest — `minisign-manifest/v1`

| Field | Type | Rule |
| :--- | :--- | :--- |
| `schema` | string | `minisign-manifest/v1` |
| `package` | string | `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}` |
| `algorithm` | string | `rsa-pss-sha256` \| `ecdsa-p256-sha256` \| `ed25519` |
| `keyid` | string | `hex_lower(SHA256(DER_SPKI))`, 64 chars |
| `artifact.name` | string | `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` (basename) |
| `artifact.size` | integer | `0 … 9007199254740991` (booleans rejected) |
| `artifact.sha256` | string | 64 lowercase hex chars |

The signed bytes `M` are the canonical serialization: UTF-8 without BOM,
field order `schema, package, version, algorithm, keyid, artifact` (and
`name, size, sha256`), no whitespace outside strings, no trailing newline,
no `\uXXXX` escapes, at most 16 KiB. On verify the manifest is parsed
strictly, re-serialized and compared byte for byte with `M`, and the
signature is always checked against the received `M`.

### Bundle — `minisign-bundle/v1`

```json
{"schema":"minisign-bundle/v1","manifest_b64":"<Base64(M)>","signature_b64":"<Base64(signature)>"}
```

UTF-8 without BOM, at most 64 KiB, exactly these three fields. Base64 is
standard RFC 4648 with padding and no whitespace (checked by decode and
re-encode). The order and whitespace of the outer bundle JSON are free.
Signatures are 384 bytes (RSA-PSS), 64 bytes `r || s` big-endian (ECDSA) or
64 bytes (Ed25519).

### Trust store — `minisign-trust/v1`

```json
{
  "schema": "minisign-trust/v1",
  "keys": [
    {
      "keyid": "<64 hex>",
      "algorithm": "ed25519",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "packages": ["contoh-app"]
    }
  ]
}
```

Every field is required and extra fields are rejected. `keyid` values are
unique. `packages` is non-empty, has no duplicates and no wildcards. The PEM
must be a public key whose type and parameters match `algorithm` and whose
fingerprint equals `keyid`; otherwise verification fails with
`FORMAT_ERROR`. An empty `keys` array is valid and trusts nothing. The store
is written atomically (temporary file in the same directory, then rename)
and is never updated from bundle contents.

### SBOM (bonus)

The SBOM is a CycloneDX JSON document (`"bomFormat": "CycloneDX"`). The
release artifact hash is read from exactly one entry
`metadata.component.hashes[] = {"alg": "SHA-256", "content": "<64 hex>"}`.
The SBOM file is signed as its own artifact with the same manifest and
bundle formats.

`sbom verify` returns `OK` only if (1) the release artifact verifies against
`--artifact-bundle`, (2) the SBOM verifies against `--bundle`, and (3) the
SHA-256 recorded in the SBOM equals the verified artifact's SHA-256. The
first failure is reported with the normal statuses, prefixed with
`release artifact:` or `SBOM:`. A binding mismatch is reported as
`ARTIFACT_MISMATCH`.
