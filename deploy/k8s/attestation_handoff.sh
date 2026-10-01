#!/usr/bin/env bash
# ==============================================================================
# SafeGGUF Immutable Handoff: Copy-Once Staging -> Validate -> Digest -> CAS
#
# Usage:
#   attestation_handoff.sh <model_path> <work_dir> [profile]
#
# work_dir must be a private, writable filesystem with free space at least the
# size of the model. Staging and CAS share that filesystem, so publishing the
# validated bytes into the CAS is an atomic rename.
#
# Layout:
#   <work_dir>/private-stage/model.gguf        one-time copy of untrusted source
#   <work_dir>/private-stage/validated/<hash>  immutable CAS entry
#   <work_dir>/model.gguf.sha256               digest attestation (pin + verify)
#
# Process:
#   0. Copy the untrusted model exactly once into private staging.
#   1. Structural & arithmetic validation of the STAGED bytes (fail-closed).
#   2. SHA-256 the STAGED bytes and rename them into validated/<sha256>.
#   3. Verification gate: re-check the digest against the CAS entry.
#
# Anti-pattern removed (TOCTOU):
#   This script used to run `safegguf inspect <model_path>` and then
#   `sha256sum <model_path>` against the SAME mutable upload path, while the
#   serving container mounted that mutable volume too. A writer with access to
#   the upload could replace it between the verdict and the digest (or between
#   the digest and the load), so the runtime consumed bytes SafeGGUF never
#   inspected. The source is now copied once into private staging; validation,
#   hashing, and the CAS rename all operate on that copy, and downstream
#   consumers load only the digest-named CAS entry -- never the source path.
# ==============================================================================

set -euo pipefail

MODEL_PATH="${1:-}"
WORK_DIR="${2:-}"
PROFILE="${3:-llama-cpp}"

if [[ -z "$MODEL_PATH" || -z "$WORK_DIR" ]]; then
    echo "Usage: $0 <model_path> <work_dir> [profile]" >&2
    exit 64
fi

if [[ ! -f "$MODEL_PATH" ]]; then
    echo "Error: Model file does not exist: $MODEL_PATH" >&2
    exit 74
fi

mkdir -p "$WORK_DIR"
WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"

MODEL_FILENAME="$(basename "$MODEL_PATH")"
STAGED_PATH="$WORK_DIR/private-stage/$MODEL_FILENAME"
CAS_DIR="$WORK_DIR/private-stage/validated"
ATTESTATION_FILE="$WORK_DIR/$MODEL_FILENAME.sha256"

echo "=== [SafeGGUF Handoff Gate: Phase 0 - One-Time Copy to Private Staging] ==="
echo "Untrusted Source : $MODEL_PATH"
echo "Private Staging  : $STAGED_PATH"
echo "Profile          : $PROFILE"

# Copy the untrusted source exactly once; from here on every step operates on
# the staged copy, never again on the mutable source path.
mkdir -p "$CAS_DIR"
cp "$MODEL_PATH" "$STAGED_PATH"

echo "=== [SafeGGUF Handoff Gate: Phase 1 - Structural Inspection of Staged Bytes] ==="
# Structural and arithmetic validation of the staged copy (fail closed).
VALIDATION_RC=0
safegguf inspect "$STAGED_PATH" --profile "$PROFILE" --format json --endian auto || VALIDATION_RC=$?

if [[ $VALIDATION_RC -ne 0 ]]; then
    echo "[CRITICAL] SafeGGUF rejected model! Exit code: $VALIDATION_RC. Aborting ingress." >&2
    exit "$VALIDATION_RC"
fi

echo "=== [SafeGGUF Handoff Gate: Phase 2 - Digest Staged Bytes & Publish to CAS] ==="
# Hash exactly the bytes that were just validated, then atomically rename them
# into the content-addressed store. The digest is the object name.
DIGEST="$(sha256sum "$STAGED_PATH" | awk '{print $1}')"
mv "$STAGED_PATH" "$CAS_DIR/$DIGEST"
chmod 0444 "$CAS_DIR/$DIGEST"
printf '%s  %s\n' "$DIGEST" "$DIGEST" > "$ATTESTATION_FILE"
echo "CAS entry: $CAS_DIR/$DIGEST"

echo "=== [SafeGGUF Handoff Gate: Phase 3 - Digest Verification Gate] ==="
# Downstream consumers must load "$CAS_DIR/<digest>" (digest-pinned), never the
# original source path. This re-binds the attestation to the CAS bytes.
(cd "$CAS_DIR" && sha256sum -c "$ATTESTATION_FILE")
echo "[SUCCESS] sha256:$DIGEST pins the exact bytes that passed structural validation."
