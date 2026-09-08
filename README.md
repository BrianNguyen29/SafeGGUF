# SafeGGUF 🛡️

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg)](https://ziglang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Upstream ggml](https://img.shields.io/badge/ggml-0.23.0%20(e91ded11)-blue.svg)](https://github.com/ggerganov/llama.cpp)

An overflow-checked GGUF v3 structural and arithmetic validator written in **Zig**, designed to inspect model headers, metadata, and tensor descriptors to reject malformed or adversarial input before weights are mapped into production inference runtimes.

SafeGGUF operates purely on file headers and descriptors without loading multi-gigabyte tensor payload data into host memory.

---

## 🎯 Threat Model & Motivation

GGUF is the standard container format for local and edge LLM inference (`llama.cpp`, Ollama, vLLM). Because model files are typically loaded via `mmap` and parsed in C/C++, malformed or crafted files present direct security risks:

* **Integer Overflows in Tensor Byte Math:** Crafting extreme tensor dimensions can overflow integer calculations in block quantization, bypassing bounds checks and triggering undersized allocations or heap buffer overflows (e.g., CVE-2026-33298, CVE-2026-27940).
* **Allocation Denial-of-Service (DoS):** Corrupted headers specifying astronomical tensor counts or metadata counts can exhaust system memory before any payload is verified.
* **Overlapping Tensor Mappings:** Maliciously overlapping tensor offsets can cause subsequent tensor operations to overwrite or misinterpret memory segments.
* **Semantic Format Exploits:** Malformed boolean values, invalid UTF-8 byte sequences, or unconstrained nested arrays can cause parser panics, memory corruption, or unbounded call-stack recursion.

SafeGGUF provides a hardened pre-admission boundary that validates format compliance, arithmetic bounds, and memory layout before inference engines open model files.

---

## 🛡️ Architectural Guarantees & Implementation

SafeGGUF implements strict invariants to protect parsing environments:

### 1. Canonical Upstream Type Table (ggml 0.23.0 / `e91ded11`)
Supports all **35 active GGML types** in GGUF v3 with exact `(block_size, type_size)` traits:
* Includes standard floating point (`F32`, `F16`, `BF16`, `F64`), integers (`I8`..`I64`), k-quants (`Q2_K`..`Q8_K`), i-quants (`IQ1_S`, `IQ1_M`, `IQ2_XXS`..`IQ4_XS`), t-quants (`TQ1_0`, `TQ2_0`), and modern micro-float types (`MXFP4`, `NVFP4`, `Q1_0`, `Q2_0`).
* Deprecated/removed slots (4, 5, 31..33, 36..38) and IDs $\ge 43$ are strictly rejected (`InvalidTensorType`).
* Row divisibility is strictly enforced: $\\text{dimensions}[0] \\pmod{\\text{block\\_size}} = 0$.
* Regression-tested against truncated NVFP4 payloads (`type40_truncated_false_pass.gguf`).

### 2. Anti-DoS Protection & Total Allocation Budget
* **Stream Bounds Pre-Checks:** Verifies `metadata_kv_count \le (remaining / 13)` and `tensor_count \le (remaining / 33)` before performing heap allocations.
* **Global Allocation Ceiling:** Enforces `max_total_alloc_bytes` (128 MB default) to prevent allocation amplification from crafted descriptor streams.
* **Variable Array Ceiling:** Limits string and nested array elements (`max_variable_array_elements = 100_000`) to eliminate syscall-heavy I/O DoS loops.

### 3. Strict Semantic & Format Validation
* **Boolean Invariant:** Enforces that scalar booleans are strictly `0` or `1` (`InvalidBoolean`). Boolean arrays are scanned in 4KB chunks ensuring all bytes $\le 1$ (blind $O(1)$ skipping is explicitly avoided).
* **UTF-8 Validation:** Metadata strings and tensor names are streaming-validated using `std.unicode.utf8ValidateSlice` (`InvalidUtf8`).
* **Key Grammar:** Enforces hierarchical `lower_snake_case` namespaces without hyphens (`^[a-z0-9_]+(\.[a-z0-9_]+)*$`).
* **Alignment Profiles:** Supports `--profile gguf-spec` (uint32, multiple of 8) and `--profile llama-cpp` (uint32, power of two).

### 4. Overlap & Range Verification
* Performs sorted interval analysis ($O(N \log N)$) across all tensor ranges $[\text{start}, \text{end})$ to ensure every tensor resides within file bounds and that no two tensors overlap.
* Duplicate metadata keys and duplicate tensor names are rejected (`std.StringHashMap`).

### 5. Memory Safety & Leak Prevention
* Scoped deferral and `Document.deinit(allocator)` ensure complete cleanup across all error and exit paths.
* Error paths are exercised under `std.testing.allocator`, which reports leaked test allocations.

---

## 🚀 Quick Start

### Prerequisites
* **Zig 0.13.0** (pinned toolchain)
* Python 3.10+ (for synthetic test fixture generation)

### Building from Source

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF

# Build release binary (ReleaseSafe is recommended for security validators)
zig build -Doptimize=ReleaseSafe

# Binary is available at zig-out/bin/safegguf
./zig-out/bin/safegguf
```

### Running the Test Suite

```bash
# Run 22 unit, integration, oracle, and regression tests with leak checking
zig build test --summary all
```

---

## 💻 CLI Usage

### Inspect a Model (Human-Readable Output)

```bash
safegguf inspect /path/to/model.gguf
```

### Structured Output (JSON for CI/CD Pipelines)

```bash
safegguf inspect /path/to/model.gguf --format json
```

Valid file output:
```json
{
  "status": "PASS",
  "version": 3,
  "file_size": 448,
  "metadata_entries": 1,
  "tensors": 2,
  "alignment": 32,
  "tensor_data_offset": 192,
  "checks": {
    "structural": "PASS",
    "arithmetic": "PASS",
    "bounds": "PASS",
    "overlap": "PASS"
  },
  "findings": []
}
```

### Selecting Validation Profiles

```bash
# GGUF Specification profile (uint32, multiple of 8) - default
safegguf inspect /path/to/model.gguf --profile gguf-spec

# llama.cpp Compatibility profile (uint32, power-of-two alignment)
safegguf inspect /path/to/model.gguf --profile llama-cpp
```

---

## 📂 Project Structure

```
safegguf/
├── .github/
│   └── workflows/
│       └── ci.yml                      # Multi-platform CI (Ubuntu & macOS 14)
├── build.zig                           # Modular Zig 0.13.0 build script
├── src/
│   ├── root.zig                        # Package root module exports
│   ├── main.zig                        # CLI entry point (profiles, text & JSON)
│   ├── gguf/
│   │   ├── types.zig                   # Canonical ggml 0.23.0 type traits (35 active)
│   │   ├── error.zig                   # ParseError enum and structured findings
│   │   ├── limits.zig                  # Anti-DoS thresholds & profile configuration
│   │   ├── reader.zig                  # Random-access Bounded Reader abstraction
│   │   ├── metadata.zig                # UTF-8, bool validation, & strict key grammar
│   │   └── parser.zig                  # Header, tensor & metadata parsing with DoS limits
│   └── validate/
│       ├── arithmetic.zig              # Checked arithmetic & block quantization math
│       └── structural.zig              # Tensor alignment, bounds, & overlap verification
└── tests/
    ├── validator_test.zig              # 22 tests (0..50 oracle, false-PASS regression)
    └── generate_fixtures.py            # Fixture generator (valid & attack vectors)
```

---

## 📄 License
MIT License.
