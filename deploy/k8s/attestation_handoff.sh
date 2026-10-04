#!/usr/bin/env bash
# Single-process admission handoff. The work directory must be trusted,
# private and writable, with enough free space for the staged model.
# Usage: attestation_handoff.sh <model_path> <work_dir> [profile] [admit flags...]
# Objects: <work_dir>/validated/<sha256>
# Statements and checksum pins: <work_dir>/attestations/<sha256>.{json,sha256}
# The native publisher owns copying, hashing, validation and atomic publication;
# this wrapper never reopens the upload to compute an independent digest.
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <model_path> <work_dir> [profile] [admit flags...]" >&2
    exit 64
fi
MODEL_PATH="$1"
WORK_DIR="$2"
shift 2
PROFILE="${1:-llama-cpp}"
if [[ $# -gt 0 ]]; then shift; fi
case "$PROFILE" in
    llama-cpp|gguf-spec) ;;
    *) echo "Error: profile must be llama-cpp or gguf-spec" >&2; exit 64 ;;
esac
if [[ -z "$MODEL_PATH" || -z "$WORK_DIR" ]]; then
    echo "Error: model path and work directory must be non-empty" >&2
    exit 64
fi

# Preparation only: no source copy happens here.
mkdir -p -- "$WORK_DIR"
WORK_DIR="$(cd -- "$WORK_DIR" && pwd -P)"
mkdir -p -- "$WORK_DIR/validated" "$WORK_DIR/attestations"
exec safegguf admit -- "$MODEL_PATH" \
    --cas-dir "$WORK_DIR/validated" \
    --attestations-dir "$WORK_DIR/attestations" \
    --profile "$PROFILE" \
    --endian auto \
    --max-file-size-bytes 17179869184 \
    "$@"