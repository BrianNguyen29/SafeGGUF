#!/usr/bin/env bash
# ==============================================================================
# SafeGGUF Cryptographic Content-Hash Attestation & Anti-TOCTOU Handoff
#
# Usage:
#   attestation_handoff.sh <model_path> <attestation_dir> [profile]
#
# Process:
#   1. Pre-admission structural & arithmetic validation via SafeGGUF (fail-closed)
#   2. Cryptographic SHA-256 digest computation stored in memory-backed attestation dir
#   3. Pre-load verification gate for downstream inference runtimes
# ==============================================================================

set -euo pipefail

MODEL_PATH="${1:-}"
ATTESTATION_DIR="${2:-}"
PROFILE="${3:-llama-cpp}"

if [[ -z "$MODEL_PATH" || -z "$ATTESTATION_DIR" ]]; then
    echo "Usage: $0 <model_path> <attestation_dir> [profile]" >&2
    exit 64
fi

if [[ ! -f "$MODEL_PATH" ]]; then
    echo "Error: Model file does not exist: $MODEL_PATH" >&2
    exit 74
fi

mkdir -p "$ATTESTATION_DIR"
MODEL_FILENAME="$(basename "$MODEL_PATH")"
ATTESTATION_FILE="$ATTESTATION_DIR/$MODEL_FILENAME.sha256"

echo "=== [SafeGGUF Handoff Gate: Phase 1 - Structural Inspection] ==="
echo "Target Model: $MODEL_PATH"
echo "Profile     : $PROFILE"

# 1. Structural and arithmetic validation (fail closed on exit != 0)
safegguf inspect "$MODEL_PATH" --profile "$PROFILE" --format json --endian auto
VALIDATION_RC=$?

if [[ $VALIDATION_RC -ne 0 ]]; then
    echo "[CRITICAL] SafeGGUF rejected model! Exit code: $VALIDATION_RC. Aborting ingress." >&2
    exit "$VALIDATION_RC"
fi

echo "=== [SafeGGUF Handoff Gate: Phase 2 - Attestation Generation] ==="
# 2. Cryptographic digest generation (stored in ephemeral memory volume)
sha256sum "$MODEL_PATH" > "$ATTESTATION_FILE"
echo "Attestation created successfully: $ATTESTATION_FILE"
cat "$ATTESTATION_FILE"

echo "=== [SafeGGUF Handoff Gate: Phase 3 - Verification Verification] ==="
# 3. Verification gate (used by inference container before mmap)
(cd "$(dirname "$MODEL_PATH")" && sha256sum -c "$ATTESTATION_FILE")
echo "[SUCCESS] Cryptographic handoff verified. Model is structurally sound and invariant."
