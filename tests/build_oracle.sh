#!/usr/bin/env bash
# Build an upstream ggml oracle binary.
#
# Oracle A (pinned, default) is the blocking compatibility contract: ggml
# v0.23.0 at PINNED_COMMIT. The no-argument invocation keeps the legacy paths
# (.cache/ggml-upstream + tests/oracle/ggml_oracle) so existing callers
# (tests/differential.py, tests/test_oracle_types.py, CI) are unchanged.
#
# Oracle B (rolling canary) builds one exact upstream commit into an isolated
# per-SHA cache and binary: --name rolling --ref <full-40-hex-sha>. Floating
# refs (e.g. "master") are rejected so nightly runs always record a full SHA.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GGML_URL="https://github.com/ggml-org/ggml.git"
PINNED_COMMIT="e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
PINNED_TAG="v0.23.0"

NAME=""
REF=""
OUTPUT=""
FORCE=0

usage() {
    cat <<'EOF'
Usage: tests/build_oracle.sh [--name pinned|rolling] [--ref <full-sha>] [--output <path>] [--force]

Default (no arguments): pinned Oracle A with legacy paths
  cache  .cache/ggml-upstream
  binary tests/oracle/ggml_oracle

--name pinned   isolated pinned Oracle A
  cache  .cache/oracle/pinned
  binary tests/oracle/ggml_oracle_pinned (override with --output)
--name rolling  exact rolling Oracle B; requires --ref <full 40-hex commit sha>
  cache  .cache/oracle/rolling/<sha>
  binary tests/oracle/ggml_oracle_rolling (override with --output)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --name)
            NAME="${2:-}"
            [ -n "$NAME" ] || { echo "FATAL: --name requires a value" >&2; usage >&2; exit 64; }
            shift 2
            ;;
        --ref)
            REF="${2:-}"
            [ -n "$REF" ] || { echo "FATAL: --ref requires a value" >&2; usage >&2; exit 64; }
            shift 2
            ;;
        --output)
            OUTPUT="${2:-}"
            [ -n "$OUTPUT" ] || { echo "FATAL: --output requires a value" >&2; usage >&2; exit 64; }
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument: $1" >&2
            usage >&2
            exit 64
            ;;
    esac
done

LEGACY=0
if [ -z "$NAME" ]; then
    if [ -n "$REF" ]; then
        echo "FATAL: --ref requires --name (pinned|rolling); the default invocation is the pinned oracle" >&2
        exit 64
    fi
    NAME="pinned"
    LEGACY=1
fi

case "$NAME" in
    pinned|rolling) ;;
    *) echo "FATAL: --name must be 'pinned' or 'rolling' (got '$NAME')" >&2; exit 64 ;;
esac

if [ "$NAME" = "pinned" ]; then
    REF="${REF:-$PINNED_COMMIT}"
else
    if ! [[ "$REF" =~ ^[0-9a-f]{40}$ ]]; then
        echo "FATAL: rolling oracle requires --ref <full 40-hex commit sha>; refusing floating ref '${REF:-<none>}'" >&2
        exit 64
    fi
fi

if [ "$LEGACY" = 1 ]; then
    CACHE_DIR="$REPO_ROOT/.cache/ggml-upstream"
elif [ "$NAME" = "rolling" ]; then
    CACHE_DIR="$REPO_ROOT/.cache/oracle/rolling/$REF"
else
    CACHE_DIR="$REPO_ROOT/.cache/oracle/$NAME"
fi

if [ -z "$OUTPUT" ]; then
    if [ "$LEGACY" = 1 ]; then
        OUTPUT="$SCRIPT_DIR/oracle/ggml_oracle"
    else
        OUTPUT="$SCRIPT_DIR/oracle/ggml_oracle_$NAME"
    fi
fi

# Reproducibility stamp: records which source commit the CMake build dir was
# configured from. A missing or stale stamp forces a clean reconfigure so the
# oracle binary can never be linked against the wrong ggml sources.
STAMP_FILE="$CACHE_DIR/build/.source-sha"
if [ "$NAME" = "pinned" ] && [ "$REF" = "$PINNED_COMMIT" ]; then
    STAMP_VALUE="$PINNED_COMMIT (ggml $PINNED_TAG)"
else
    STAMP_VALUE="$REF (ggml $NAME)"
fi

if [ -f "$OUTPUT" ] && [ "$FORCE" != 1 ]; then
    CURRENT_STAMP="$(cat "$STAMP_FILE" 2>/dev/null || true)"
    if [ "$CURRENT_STAMP" = "$STAMP_VALUE" ]; then
        echo "Oracle binary already exists at $OUTPUT (source stamp matches $STAMP_VALUE)"
        exit 0
    fi
    echo "Oracle binary exists at $OUTPUT but source stamp is missing or stale; rebuilding..."
fi

echo "=== Building ggml $NAME oracle (commit $REF) ==="

if [ "$NAME" = "pinned" ] && [ "$REF" = "$PINNED_COMMIT" ]; then
    # Pinned Oracle A: shallow clone of the v0.23.0 tag (legacy path).
    if [ ! -d "$CACHE_DIR/.git" ]; then
        echo "Cloning ggml at pinned commit $REF..."
        mkdir -p "$(dirname "$CACHE_DIR")"
        git clone --depth 1 --branch "$PINNED_TAG" "$GGML_URL" "$CACHE_DIR"
    fi
    cd "$CACHE_DIR"
    git checkout --detach "$REF"
else
    # Rolling Oracle B: fetch exactly one full SHA; never a floating ref.
    mkdir -p "$(dirname "$CACHE_DIR")"
    if [ ! -d "$CACHE_DIR/.git" ]; then
        echo "Initializing isolated ggml cache at $CACHE_DIR..."
        git init -q "$CACHE_DIR"
        git -C "$CACHE_DIR" remote add origin "$GGML_URL"
    fi
    if [ "$(git -C "$CACHE_DIR" rev-parse --verify --quiet "$REF^{commit}" || true)" != "$REF" ]; then
        echo "Fetching ggml commit $REF..."
        git -C "$CACHE_DIR" fetch --depth 1 origin "$REF"
    fi
    cd "$CACHE_DIR"
    git checkout --detach "$REF"
fi

ACTUAL_COMMIT="$(git rev-parse HEAD)"
if [ "$ACTUAL_COMMIT" != "$REF" ]; then
    echo "FATAL: Checked out commit $ACTUAL_COMMIT does not match requested commit $REF" >&2
    exit 1
fi

CURRENT_STAMP="$(cat "$STAMP_FILE" 2>/dev/null || true)"
if [ "$CURRENT_STAMP" != "$STAMP_VALUE" ]; then
    if [ -d build ]; then
        echo "Source stamp mismatch (have: ${CURRENT_STAMP:-<none>}, want: $STAMP_VALUE); wiping build dir and reconfiguring..."
        rm -rf build
    fi
    echo "Configuring ggml libraries with CMake..."
    cmake -B build -DGGML_BUILD_TESTS=OFF -DGGML_BUILD_EXAMPLES=OFF -DCMAKE_BUILD_TYPE=Release
fi

echo "Building ggml libraries with CMake (incremental)..."
cmake --build build --target ggml -j4

printf '%s\n' "$STAMP_VALUE" > "$STAMP_FILE"

cd "$REPO_ROOT"
CXX_COMPILER="${CXX:-c++}"
mkdir -p "$(dirname "$OUTPUT")"
echo "Compiling $OUTPUT with $CXX_COMPILER..."
$CXX_COMPILER -std=c++17 -O2 "$SCRIPT_DIR/oracle/ggml_oracle.cpp" \
    -I"$CACHE_DIR/include" \
    -L"$CACHE_DIR/build/src" \
    -lggml-base -lggml \
    -Wl,-rpath,"$CACHE_DIR/build/src" \
    -o "$OUTPUT"

echo "Oracle built successfully at $OUTPUT"
