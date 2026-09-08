#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="$REPO_ROOT/.cache/ggml-upstream"
PINNED_COMMIT="e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
ORACLE_BIN="$SCRIPT_DIR/oracle/ggml_oracle"

if [ -f "$ORACLE_BIN" ] && [ "${1:-}" != "--force" ]; then
    echo "Oracle binary already exists at $ORACLE_BIN"
    exit 0
fi

echo "=== Building Upstream ggml 0.23.0 Oracle (commit $PINNED_COMMIT) ==="

if [ ! -d "$CACHE_DIR/.git" ]; then
    echo "Cloning ggml at pinned commit $PINNED_COMMIT..."
    mkdir -p "$(dirname "$CACHE_DIR")"
    git clone --depth 1 --branch v0.23.0 https://github.com/ggml-org/ggml.git "$CACHE_DIR"
fi

cd "$CACHE_DIR"
git checkout -q "$PINNED_COMMIT" || true

if [ ! -f "build/src/libggml.so" ] && [ ! -f "build/src/libggml.dylib" ]; then
    echo "Configuring and building ggml libraries with CMake..."
    cmake -B build -DGGML_BUILD_TESTS=OFF -DGGML_BUILD_EXAMPLES=OFF -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target ggml -j4
fi

cd "$REPO_ROOT"
CXX_COMPILER="${CXX:-c++}"
echo "Compiling tests/oracle/ggml_oracle with $CXX_COMPILER..."
$CXX_COMPILER -O2 "$SCRIPT_DIR/oracle/ggml_oracle.cpp" \
    -I"$CACHE_DIR/include" \
    -L"$CACHE_DIR/build/src" \
    -lggml-base -lggml \
    -Wl,-rpath,"$CACHE_DIR/build/src" \
    -o "$ORACLE_BIN"

echo "Oracle built successfully at $ORACLE_BIN"
