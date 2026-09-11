#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="$REPO_ROOT/.cache/ggml-upstream"
PINNED_COMMIT="e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
ORACLE_BIN="$SCRIPT_DIR/oracle/ggml_oracle"

# Reproducibility stamp: records which source commit the CMake build dir was
# configured from. A missing or stale stamp forces a clean reconfigure so the
# oracle binary can never be linked against the wrong ggml sources.
STAMP_FILE="$CACHE_DIR/build/.source-sha"
STAMP_VALUE="$PINNED_COMMIT (ggml v0.23.0)"

if [ -f "$ORACLE_BIN" ] && [ "${1:-}" != "--force" ]; then
    CURRENT_STAMP="$(cat "$STAMP_FILE" 2>/dev/null || true)"
    if [ "$CURRENT_STAMP" = "$STAMP_VALUE" ]; then
        echo "Oracle binary already exists at $ORACLE_BIN (source stamp matches $STAMP_VALUE)"
        exit 0
    fi
    echo "Oracle binary exists at $ORACLE_BIN but source stamp is missing or stale; rebuilding..."
fi

echo "=== Building Upstream ggml 0.23.0 Oracle (commit $PINNED_COMMIT) ==="

if [ ! -d "$CACHE_DIR/.git" ]; then
    echo "Cloning ggml at pinned commit $PINNED_COMMIT..."
    mkdir -p "$(dirname "$CACHE_DIR")"
    git clone --depth 1 --branch v0.23.0 https://github.com/ggml-org/ggml.git "$CACHE_DIR"
fi

cd "$CACHE_DIR"
git checkout --detach "$PINNED_COMMIT"
ACTUAL_COMMIT="$(git rev-parse HEAD)"
if [ "$ACTUAL_COMMIT" != "$PINNED_COMMIT" ]; then
    echo "FATAL: Checked out commit $ACTUAL_COMMIT does not match pinned commit $PINNED_COMMIT" >&2
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
echo "Compiling tests/oracle/ggml_oracle with $CXX_COMPILER..."
$CXX_COMPILER -std=c++17 -O2 "$SCRIPT_DIR/oracle/ggml_oracle.cpp" \
    -I"$CACHE_DIR/include" \
    -L"$CACHE_DIR/build/src" \
    -lggml-base -lggml \
    -Wl,-rpath,"$CACHE_DIR/build/src" \
    -o "$ORACLE_BIN"

echo "Oracle built successfully at $ORACLE_BIN"
