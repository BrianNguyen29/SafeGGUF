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
# Layout (content-addressed; no untrusted name is ever used as a path):
#   <work_dir>/private-stage.XXXXXXXX/model.gguf   per-run private staging dir
#   <work_dir>/validated/<sha256>                  immutable CAS entry
#   <work_dir>/attestations/<sha256>.json          bound attestation document
#   <work_dir>/attestations/<sha256>.sha256        `sha256sum -c` pin file
#
# Process:
#   0. Copy the untrusted model exactly once into a per-run private staging dir.
#   1. Structural & arithmetic validation of the STAGED bytes (fail-closed),
#      with an explicit size ceiling and a file-stability check.
#   2. SHA-256 the STAGED bytes and rename them into validated/<sha256>.
#   3. Verification gate: re-check the digest against the CAS entry.
#   4. Publish a canonical, signing-ready attestation JSON binding digest,
#      verdict, validator version, profile, and limits.
#
# Concurrency: every run stages into its own `mktemp -d` directory (mode 0700),
# so two runs handling same-named uploads cannot swap staged bytes between the
# verdict and the digest. Published paths are content-addressed (keyed by the
# SHA-256 digest), so concurrent runs can never tear or cross-write each
# other's CAS entry or attestation.
#
# Anti-patterns removed:
#   TOCTOU (earlier revision): the script ran `safegguf inspect <model_path>`
#   and then `sha256sum <model_path>` against the SAME mutable upload path,
#   while the serving container mounted that mutable volume too. A writer with
#   access to the upload could replace it between the verdict and the digest
#   (or between the digest and the load), so the runtime consumed bytes
#   SafeGGUF never inspected. The source is now copied once into private
#   staging; validation, hashing, and the CAS rename all operate on that copy,
#   and downstream consumers load only the digest-named CAS entry -- never the
#   source path.
#   Same-name race (this revision): staging and attestation paths were derived
#   from `basename` of the untrusted upload inside a shared work_dir, so two
#   concurrent runs with the same filename overwrote each other between
#   validation and hashing -- one run's digest could attest the other run's
#   bytes. Staging is now per-run and every published artifact is
#   content-addressed by the SHA-256 digest.
# ==============================================================================

set -euo pipefail

MODEL_PATH="${1:-}"
WORK_DIR="${2:-}"
PROFILE="${3:-llama-cpp}"

# Explicit admission ceiling for the validator: 16 GiB, matching the README
# example and the staging volume sizeLimit in the K8s manifest. The value is
# bound into the attestation, so the verdict is reproducible from the document.
MAX_FILE_SIZE_BYTES=17179869184

usage() {
    echo "Usage: $0 <model_path> <work_dir> [profile]" >&2
    exit 64
}

if [[ -z "$MODEL_PATH" || -z "$WORK_DIR" ]]; then
    usage
fi

# The profile is embedded in the attestation JSON, so it must be one of the
# two values the CLI accepts; anything else would emit an invalid document.
case "$PROFILE" in
    llama-cpp | gguf-spec) ;;
    *)
        echo "Error: profile must be 'llama-cpp' or 'gguf-spec': $PROFILE" >&2
        exit 64
        ;;
esac

if [[ ! -f "$MODEL_PATH" ]]; then
    echo "Error: Model file does not exist: $MODEL_PATH" >&2
    exit 74
fi

mkdir -p -- "$WORK_DIR"
WORK_DIR="$(cd -- "$WORK_DIR" && pwd -P)"

# Per-run private staging directory. mktemp -d creates it atomically with mode
# 0700, and the staged file has a fixed name inside it: no attacker-controlled
# filename ever becomes a path component.
RUN_DIR="$(mktemp -d -- "${WORK_DIR%/}/private-stage.XXXXXXXX")"
cleanup() {
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT

STAGED_PATH="$RUN_DIR/model.gguf"
CAS_DIR="$WORK_DIR/validated"
ATTESTATIONS_DIR="$WORK_DIR/attestations"

printf '=== [SafeGGUF Handoff Gate: Phase 0 - One-Time Copy to Private Staging] ===\n'
printf 'Untrusted Source : %s\n' "$MODEL_PATH"
printf 'Private Staging  : %s\n' "$STAGED_PATH"
printf 'Profile          : %s\n' "$PROFILE"

# Copy the untrusted source exactly once; from here on every step operates on
# the staged copy, never again on the mutable source path.
mkdir -p -- "$CAS_DIR" "$ATTESTATIONS_DIR"
cp -- "$MODEL_PATH" "$STAGED_PATH"

printf '=== [SafeGGUF Handoff Gate: Phase 1 - Structural Inspection of Staged Bytes] ===\n'
# Structural and arithmetic validation of the staged copy (fail closed), with
# an explicit size ceiling and a file-stability check over the validation
# window. `--` separates the file operand from the flags.
VALIDATION_RC=0
safegguf inspect -- "$STAGED_PATH" \
    --profile "$PROFILE" \
    --format json \
    --endian auto \
    --max-file-size-bytes "$MAX_FILE_SIZE_BYTES" \
    --require-stable-file || VALIDATION_RC=$?

if [[ "$VALIDATION_RC" -ne 0 ]]; then
    echo "[CRITICAL] SafeGGUF rejected model! Exit code: $VALIDATION_RC. Aborting ingress." >&2
    exit "$VALIDATION_RC"
fi

printf '=== [SafeGGUF Handoff Gate: Phase 2 - Digest Staged Bytes & Publish to CAS] ===\n'
# Hash exactly the bytes that were just validated, then atomically rename them
# into the content-addressed store. The digest is the object name.
DIGEST="$(sha256sum -- "$STAGED_PATH" | awk '{print $1}')"
SIZE_BYTES="$(wc -c < "$STAGED_PATH" | tr -d '[:space:]')"

# `safegguf --version` prints `SafeGGUF <version>` followed by provenance
# lines; the version and source commit are bound into the attestation. A
# missing/unparseable value fails closed: the attestation must not silently
# drop a required field.
VERSION_OUTPUT="$(safegguf --version)"
SAFEGGUF_VERSION="$(printf '%s\n' "$VERSION_OUTPUT" | awk 'NR==1 {print $2}')"
SAFEGGUF_SOURCE_COMMIT="$(printf '%s\n' "$VERSION_OUTPUT" | awk -F': ' '/^source_commit:/ {print $2}')"
if [[ -z "$SAFEGGUF_VERSION" || -z "$SAFEGGUF_SOURCE_COMMIT" ]]; then
    echo "[CRITICAL] Could not determine safegguf version/build provenance; refusing to emit an incomplete attestation." >&2
    exit 70
fi

mv -- "$STAGED_PATH" "$CAS_DIR/$DIGEST"
chmod -- 0444 "$CAS_DIR/$DIGEST"

# Canonical one-line JSON, deterministic for a given (digest, verdict,
# version, profile, limits): no timestamps and no untrusted strings, so the
# same bytes always produce the same document and a signature over it is
# stable. Only the digest-keyed relative CAS name is embedded, never an
# arbitrary filesystem path.
ATTESTATION_JSON="$ATTESTATIONS_DIR/$DIGEST.json"
printf '{"schema_version":1,"digest":{"algorithm":"sha256","value":"%s"},"size_bytes":%s,"verdict":{"status":"PASS","validator_exit_code":0},"validator":{"version":"%s","source_commit":"%s","profile":"%s","limits":{"max_file_size_bytes":%s,"require_stable_file":true}},"cas":{"relative_path":"validated/%s","sha256":"%s"}}\n' \
    "$DIGEST" "$SIZE_BYTES" "$SAFEGGUF_VERSION" "$SAFEGGUF_SOURCE_COMMIT" "$PROFILE" "$MAX_FILE_SIZE_BYTES" "$DIGEST" "$DIGEST" \
    > "$RUN_DIR/attestation.json"
mv -- "$RUN_DIR/attestation.json" "$ATTESTATION_JSON"

# `sha256sum -c` pin file: the CAS entry name is the digest, so the check runs
# from CAS_DIR and binds the published bytes to the attested digest.
PIN_FILE="$ATTESTATIONS_DIR/$DIGEST.sha256"
printf '%s  %s\n' "$DIGEST" "$DIGEST" > "$RUN_DIR/pin.sha256"
mv -- "$RUN_DIR/pin.sha256" "$PIN_FILE"

printf 'CAS entry: %s\n' "$CAS_DIR/$DIGEST"
printf 'Attestation: %s\n' "$ATTESTATION_JSON"

printf '=== [SafeGGUF Handoff Gate: Phase 3 - Digest Verification Gate] ===\n'
# Downstream consumers must load "$CAS_DIR/<digest>" (digest-pinned), never the
# original source path. This re-binds the attestation to the CAS bytes.
(cd -- "$CAS_DIR" && sha256sum -c -- "$PIN_FILE")
printf '[SUCCESS] sha256:%s pins the exact bytes that passed structural validation.\n' "$DIGEST"
