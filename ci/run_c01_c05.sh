#!/usr/bin/env bash
# CI/CD Integration Scenarios C01-C05 for veriseal (Spec Section 2.9, Tables 2.13-2.15)
set -eu

: "${IMAGE:?IMAGE environment variable (pinned with @sha256:...) is mandatory}"
: "${CI_SIGNING_KEY_RSA:?CI_SIGNING_KEY_RSA secret is mandatory}"
: "${CI_SIGNING_KEY_ECDSA:?CI_SIGNING_KEY_ECDSA secret is mandatory}"
: "${CI_SIGNING_KEY_ED25519:?CI_SIGNING_KEY_ED25519 secret is mandatory}"

# Enforce digest pinning per Table 2.13 ("Workflows pin the image reference by digest")
case "$IMAGE" in
  *@sha256:*) ;;
  *)
    echo "ERROR: IMAGE must be pinned by @sha256:<digest> (got: $IMAGE)" >&2
    exit 2
    ;;
esac

SIGNING_KEY_FILE=""
cleanup_secret() {
  if [ -n "${SIGNING_KEY_FILE:-}" ] && [ -f "$SIGNING_KEY_FILE" ]; then
    rm -f "$SIGNING_KEY_FILE"
  fi
}
trap cleanup_secret EXIT INT TERM

HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# Clean and prepare isolated directories
rm -rf dist out
mkdir -p dist out

# Create deterministic dist/contoh-app.zip across runners (1312 bytes, matches tests/fixtures/contoh-app.zip)
if [ -f "tests/fixtures/contoh-app.zip" ]; then
  cp "tests/fixtures/contoh-app.zip" "dist/contoh-app.zip"
else
  awk 'BEGIN { for (i = 0; i < 32; i++) printf "PK\003\004veriseal-deterministic-payload-v1.0.0" }' > "dist/contoh-app.zip"
fi

echo "=== Stage 1: Preparation ==="
echo "Pulling release image by pinned digest: $IMAGE"
if [ "${SKIP_DOCKER_PULL:-0}" != "1" ]; then
  docker pull "$IMAGE"
fi
printf '%s\n' "$IMAGE" > out/image-digest.txt

# Helper to assert JSON fields in verification.json without external dependencies
assert_verification_json() {
  json_file="$1"
  expected_status="$2"
  expected_valid="$3"

  if [ ! -s "$json_file" ]; then
    echo "FAIL: $json_file is missing or empty" >&2
    exit 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, sys
data = json.load(open(sys.argv[1]))
assert data.get('status') == sys.argv[2], f'Expected status {sys.argv[2]}, got {data.get(\"status\")}'
assert str(data.get('valid')).lower() == sys.argv[3], f'Expected valid {sys.argv[3]}, got {data.get(\"valid\")}'
" "$json_file" "$expected_status" "$expected_valid"
  else
    if ! grep -q "\"status\":\"$expected_status\"" "$json_file" && ! grep -q "\"status\": \"$expected_status\"" "$json_file"; then
      echo "FAIL: Expected status '$expected_status' in $json_file, got: $(cat "$json_file")" >&2
      exit 1
    fi
    if ! grep -q "\"valid\":$expected_valid" "$json_file" && ! grep -q "\"valid\": $expected_valid" "$json_file"; then
      echo "FAIL: Expected valid=$expected_valid in $json_file, got: $(cat "$json_file")" >&2
      exit 1
    fi
  fi
}

# Helper to sign an artifact inside container using an ephemeral 0600 private key file
sign_in_container() {
  secret_value="$1"
  input_dir="$2"
  output_dir="$3"
  bundle_name="$4"

  SIGNING_KEY_FILE="$(mktemp)"
  chmod 600 "$SIGNING_KEY_FILE"
  printf '%s\n' "$secret_value" | tr -d '\r' > "$SIGNING_KEY_FILE"

  docker run --rm --network none \
    --user "$HOST_UID:$HOST_GID" \
    -v "$input_dir:/input:ro" \
    -v "$output_dir:/output" \
    -v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" \
    "$IMAGE" sign --file /input/contoh-app.zip \
    --package contoh-app --version 1.0.0 \
    --key /run/signing.key.pem --out "/output/$bundle_name"

  # Immediately delete private key so verification stage never has access to it
  rm -f "$SIGNING_KEY_FILE"
  SIGNING_KEY_FILE=""
}

# ==============================================================================
# Scenario C01: Pull by digest -> Sign -> Verify -> Gate Deploy Marker (All 3 profiles)
# ==============================================================================
run_c01_profile() {
  profile="$1"
  secret_val="$2"
  scen_dir="$PWD/out/c01-$profile"
  rm -rf "$scen_dir"
  mkdir -p "$scen_dir"

  echo "=== Running C01 ($profile) ==="
  cp "$PWD/dist/contoh-app.zip" "$scen_dir/contoh-app.zip"

  # Stage 2: Signing (with ephemeral private key)
  sign_in_container "$secret_val" "$PWD/dist" "$scen_dir" "rilis.json"

  # Stage 3: Verification (no private key mounted; uses pre-prepared ci/trust.json)
  docker run --rm --network none \
    --user "$HOST_UID:$HOST_GID" \
    -v "$PWD/dist:/input:ro" \
    -v "$scen_dir:/output:ro" \
    -v "$PWD/ci/trust.json:/trust.json:ro" \
    "$IMAGE" verify --file /input/contoh-app.zip \
    --bundle /output/rilis.json --trust-store /trust.json \
    --package contoh-app --version 1.0.0 --json \
    > "$scen_dir/verification.json"

  assert_verification_json "$scen_dir/verification.json" "OK" "true"

  # Stage 4: Deployment strictly conditioned on verification exit 0
  printf 'DEPLOYED package=contoh-app version=1.0.0 profile=%s\n' "$profile" > "$scen_dir/DEPLOYED.marker"

  if [ ! -f "$scen_dir/DEPLOYED.marker" ]; then
    echo "FAIL: C01 ($profile) did not create DEPLOYED.marker" >&2
    exit 1
  fi
  echo "[PASS] C01 ($profile): exit=0, status=OK, DEPLOYED.marker created"
}

run_c01_profile "rsa-pss-sha256" "$CI_SIGNING_KEY_RSA"
run_c01_profile "ecdsa-p256-sha256" "$CI_SIGNING_KEY_ECDSA"
run_c01_profile "ed25519" "$CI_SIGNING_KEY_ED25519"

# ==============================================================================
# Scenario C02: Post-sign 1-byte artifact modification (preserving size & filename)
# ==============================================================================
echo "=== Running C02 (ed25519 — 1-byte artifact tamper after signing) ==="
C02_DIR="$PWD/out/c02"
rm -rf "$C02_DIR"
mkdir -p "$C02_DIR"

cp "$PWD/dist/contoh-app.zip" "$C02_DIR/contoh-app.zip"
sign_in_container "$CI_SIGNING_KEY_ED25519" "$C02_DIR" "$C02_DIR" "rilis.json"

# Flip 1st byte in C02_DIR/contoh-app.zip preserving exact byte size and filename
ORIG_SIZE="$(wc -c < "$C02_DIR/contoh-app.zip" | tr -d ' ')"
printf '\x00' | dd of="$C02_DIR/contoh-app.zip" bs=1 count=1 conv=notrunc 2>/dev/null
NEW_SIZE="$(wc -c < "$C02_DIR/contoh-app.zip" | tr -d ' ')"
if [ "$ORIG_SIZE" != "$NEW_SIZE" ]; then
  echo "FAIL: C02 byte modification altered file size ($ORIG_SIZE vs $NEW_SIZE)" >&2
  exit 1
fi

set +e
docker run --rm --network none \
  --user "$HOST_UID:$HOST_GID" \
  -v "$C02_DIR:/input:ro" \
  -v "$C02_DIR:/output:ro" \
  -v "$PWD/ci/trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/contoh-app.zip \
  --bundle /output/rilis.json --trust-store /trust.json \
  --package contoh-app --version 1.0.0 --json \
  > "$C02_DIR/verification.json" 2> "$C02_DIR/stderr.log"
C02_RC=$?
set -e

if [ "$C02_RC" -eq 0 ]; then
  printf 'DEPLOYED\n' > "$C02_DIR/DEPLOYED.marker"
fi

if [ "$C02_RC" -ne 1 ]; then
  echo "FAIL: C02 expected exit code 1, got $C02_RC" >&2
  exit 1
fi
assert_verification_json "$C02_DIR/verification.json" "ARTIFACT_MISMATCH" "false"
if [ -e "$C02_DIR/DEPLOYED.marker" ]; then
  echo "FAIL: C02 must NOT create DEPLOYED.marker" >&2
  exit 1
fi
echo "[PASS] C02: exit=1, status=ARTIFACT_MISMATCH, DEPLOYED.marker absent"

# ==============================================================================
# Scenario C03: Verify valid signed artifact using empty trust store (ci/empty-trust.json)
# ==============================================================================
echo "=== Running C03 (ed25519 — empty trust store) ==="
C03_DIR="$PWD/out/c03"
rm -rf "$C03_DIR"
mkdir -p "$C03_DIR"

cp "$PWD/dist/contoh-app.zip" "$C03_DIR/contoh-app.zip"
sign_in_container "$CI_SIGNING_KEY_ED25519" "$PWD/dist" "$C03_DIR" "rilis.json"

set +e
docker run --rm --network none \
  --user "$HOST_UID:$HOST_GID" \
  -v "$PWD/dist:/input:ro" \
  -v "$C03_DIR:/output:ro" \
  -v "$PWD/ci/empty-trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/contoh-app.zip \
  --bundle /output/rilis.json --trust-store /trust.json \
  --package contoh-app --version 1.0.0 --json \
  > "$C03_DIR/verification.json" 2> "$C03_DIR/stderr.log"
C03_RC=$?
set -e

if [ "$C03_RC" -eq 0 ]; then
  printf 'DEPLOYED\n' > "$C03_DIR/DEPLOYED.marker"
fi

if [ "$C03_RC" -ne 1 ]; then
  echo "FAIL: C03 expected exit code 1, got $C03_RC" >&2
  exit 1
fi
assert_verification_json "$C03_DIR/verification.json" "KEY_NOT_TRUSTED" "false"
if [ -e "$C03_DIR/DEPLOYED.marker" ]; then
  echo "FAIL: C03 must NOT create DEPLOYED.marker" >&2
  exit 1
fi
echo "[PASS] C03: exit=1, status=KEY_NOT_TRUSTED, DEPLOYED.marker absent"

# ==============================================================================
# Scenario C04: Verify with non-existent artifact path (/input/non-existent.zip)
# ==============================================================================
echo "=== Running C04 (ed25519 — missing artifact path) ==="
C04_DIR="$PWD/out/c04"
rm -rf "$C04_DIR"
mkdir -p "$C04_DIR"

sign_in_container "$CI_SIGNING_KEY_ED25519" "$PWD/dist" "$C04_DIR" "rilis.json"

set +e
docker run --rm --network none \
  --user "$HOST_UID:$HOST_GID" \
  -v "$PWD/dist:/input:ro" \
  -v "$C04_DIR:/output:ro" \
  -v "$PWD/ci/trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/non-existent.zip \
  --bundle /output/rilis.json --trust-store /trust.json \
  --package contoh-app --version 1.0.0 --json \
  > "$C04_DIR/verification.json" 2> "$C04_DIR/stderr.log"
C04_RC=$?
set -e

if [ "$C04_RC" -eq 0 ]; then
  printf 'DEPLOYED\n' > "$C04_DIR/DEPLOYED.marker"
fi

if [ "$C04_RC" -ne 2 ]; then
  echo "FAIL: C04 expected exit code 2, got $C04_RC" >&2
  exit 1
fi
assert_verification_json "$C04_DIR/verification.json" "INPUT_ERROR" "false"
if [ -e "$C04_DIR/DEPLOYED.marker" ]; then
  echo "FAIL: C04 must NOT create DEPLOYED.marker" >&2
  exit 1
fi
echo "[PASS] C04: exit=2, status=INPUT_ERROR, DEPLOYED.marker absent"

# ==============================================================================
# Scenario C05: Runner UID/GID (--user), no TTY (no -i/-t), and --network none
# ==============================================================================
echo "=== Running C05 (ed25519 — non-root UID:GID, no TTY, --network none) ==="
C05_DIR="$PWD/out/c05"
rm -rf "$C05_DIR"
mkdir -p "$C05_DIR"

sign_in_container "$CI_SIGNING_KEY_ED25519" "$PWD/dist" "$C05_DIR" "rilis.json" < /dev/null

docker run --rm --network none \
  --user "$HOST_UID:$HOST_GID" \
  -v "$PWD/dist:/input:ro" \
  -v "$C05_DIR:/output:ro" \
  -v "$PWD/ci/trust.json:/trust.json:ro" \
  "$IMAGE" verify --file /input/contoh-app.zip \
  --bundle /output/rilis.json --trust-store /trust.json \
  --package contoh-app --version 1.0.0 --json \
  < /dev/null > "$C05_DIR/verification.json"

assert_verification_json "$C05_DIR/verification.json" "OK" "true"

# Verify output bundle ownership matches runner's UID:GID
if stat -c "%u:%g" "$C05_DIR/rilis.json" >/dev/null 2>&1; then
  FILE_OWNER="$(stat -c "%u:%g" "$C05_DIR/rilis.json")"
else
  FILE_OWNER="$(stat -f "%u:%g" "$C05_DIR/rilis.json")"
fi
printf 'owner=%s expected=%s:%s\n' "$FILE_OWNER" "$HOST_UID" "$HOST_GID" > "$C05_DIR/ownership.txt"
if [ "$FILE_OWNER" != "$HOST_UID:$HOST_GID" ]; then
  echo "FAIL: C05 output file owner ($FILE_OWNER) does not match runner ($HOST_UID:$HOST_GID)" >&2
  exit 1
fi
echo "[PASS] C05: exit=0, status=OK, owner=$FILE_OWNER, --network none, no TTY"

# ==============================================================================
# Evidence Generation: out/marker-proof.txt and out/SUMMARY.md
# ==============================================================================
{
  echo "# Marker Proof & Output Directory Listing (C01-C05)"
  echo "Image Reference: $IMAGE"
  echo ""
  for d in out/c01-rsa-pss-sha256 out/c01-ecdsa-p256-sha256 out/c01-ed25519 out/c02 out/c03 out/c04 out/c05; do
    echo "=== $d ==="
    if [ -e "$d/DEPLOYED.marker" ]; then
      echo "DEPLOYED.marker: PRESENT"
    else
      echo "DEPLOYED.marker: ABSENT"
    fi
    ls -la "$d" | awk 'NR==1 || $NF !~ /^\.\.?$/ {print}'
    echo ""
  done
} > out/marker-proof.txt

cat <<EOF > out/SUMMARY.md
# CI/CD Integration Test Results (\`C01\`–\`C05\`)

- **Pinned Image Reference:** \`$IMAGE\`
- **Runner UID:GID:** \`$HOST_UID:$HOST_GID\`
- **Network Mode:** \`--network none\` (offline execution after \`docker pull\`)

## Scenario Matrix & Results

| ID | Profile | Scenario | Expected Exit | Actual Exit | \`verification.json\` Status | \`DEPLOYED.marker\` | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| \`C01-rsa-pss-sha256\` | \`rsa-pss-sha256\` | Digest pull, sign, verify valid artifact, gate deploy | \`0\` | \`0\` | \`OK\` (\`valid: true\`) | **PRESENT** | **PASS** |
| \`C01-ecdsa-p256-sha256\` | \`ecdsa-p256-sha256\` | Digest pull, sign, verify valid artifact, gate deploy | \`0\` | \`0\` | \`OK\` (\`valid: true\`) | **PRESENT** | **PASS** |
| \`C01-ed25519\` | \`ed25519\` | Digest pull, sign, verify valid artifact, gate deploy | \`0\` | \`0\` | \`OK\` (\`valid: true\`) | **PRESENT** | **PASS** |
| \`C02\` | \`ed25519\` | Modify 1 byte of artifact after \`sign\` (same size/name) | \`1\` | \`$C02_RC\` | \`ARTIFACT_MISMATCH\` (\`valid: false\`) | **ABSENT** | **PASS** |
| \`C03\` | \`ed25519\` | Verify valid bundle with empty trust store (\`ci/empty-trust.json\`) | \`1\` | \`$C03_RC\` | \`KEY_NOT_TRUSTED\` (\`valid: false\`) | **ABSENT** | **PASS** |
| \`C04\` | \`ed25519\` | Verify with non-existent artifact path (\`/input/non-existent.zip\`) | \`2\` | \`$C04_RC\` | \`INPUT_ERROR\` (\`valid: false\`) | **ABSENT** | **PASS** |
| \`C05\` | \`ed25519\` | Run CLI with \`--user $HOST_UID:$HOST_GID\`, no TTY, \`--network none\` | \`0\` | \`0\` | \`OK\` (\`valid: true\`) | N/A (owner \`$FILE_OWNER\`) | **PASS** |

## Verification JSON Outputs

- **\`C01 (rsa-pss-sha256)\`:** \`$(cat out/c01-rsa-pss-sha256/verification.json)\`
- **\`C01 (ecdsa-p256-sha256)\`:** \`$(cat out/c01-ecdsa-p256-sha256/verification.json)\`
- **\`C01 (ed25519)\`:** \`$(cat out/c01-ed25519/verification.json)\`
- **\`C02\`:** \`$(cat out/c02/verification.json)\`
- **\`C03\`:** \`$(cat out/c03/verification.json)\`
- **\`C04\`:** \`$(cat out/c04/verification.json)\`
- **\`C05\`:** \`$(cat out/c05/verification.json)\`
EOF

echo "=== All C01-C05 CI Integration Scenarios PASSED ==="
