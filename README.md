# SafeGGUF 🛡️

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg)](https://ziglang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Upstream ggml](https://img.shields.io/badge/ggml-0.23.0%20(e91ded11)-blue.svg)](https://github.com/ggerganov/llama.cpp)
[![Release](https://img.shields.io/badge/release-v0.2.3-green.svg)](https://github.com/BrianNguyen29/SafeGGUF/releases)

A memory-safe, overflow-checked GGUF v3 structural and arithmetic pre-admission validator written in **Zig**, designed to inspect model headers, metadata, and tensor descriptors to reject malformed or adversarial input before weights are mapped into production inference runtimes.

SafeGGUF operates purely on file headers and descriptors without loading multi-gigabyte tensor payload data into host memory.

---

## 🎯 Threat Model & Motivation

GGUF is the standard container format for local and edge LLM inference (`llama.cpp`, Ollama, vLLM). Because model files are typically loaded via `mmap` and parsed in C/C++, malformed or crafted files present direct security risks:

* **Integer Overflows in Tensor Byte Math:** Crafting extreme tensor dimensions can overflow integer calculations in block quantization, bypassing bounds checks and triggering undersized allocations or heap buffer overflows (e.g., CVE-2026-33298, CVE-2026-27940).
* **Contiguous Layout Addition Overflows:** In runtime loaders requiring strictly sequential layouts, calculating expected offsets ($O_{next} = O_{cur} + S$) without checked arithmetic can trigger integer overflows and crash or panic scanning processes.
* **Memory Exhaustion & Heap DoS:** Corrupted headers declaring massive tensor counts or nested metadata arrays can exhaust host memory before payload verification.
* **Layout Inconsistencies & Loader Crashes:** Files with arbitrary tensor gaps or descriptor misalignments can crash runtime loaders like `llama.cpp` which assert sequential, contiguous memory layout (`ti.offset == ctx->size`).
* **Semantic Format Exploits:** Malformed boolean values (bytes $\notin \{0, 1\}$), invalid UTF-8 sequences, or unconstrained nested arrays can trigger parser panics or memory corruption.

SafeGGUF acts as a hardened **pre-admission gateway** in model supply chain pipelines, running before weights are mapped or executed.

---

## 🛡️ Architectural Guarantees & Features (v0.2.3)

### 1. Canonical Upstream Type Table (ggml 0.23.0 / `e91ded11`)
Supports all **35 active GGML types** with exact `(block_size, type_size)` traits:
* Includes standard floating point (`F32`, `F16`, `BF16`, `F64`), integers (`I8`..`I64`), k-quants (`Q2_K`..`Q8_K`), i-quants (`IQ1_S`, `IQ1_M`, `IQ2_XXS`..`IQ4_XS`), t-quants (`TQ1_0`, `TQ2_0`), and modern micro-float types (`MXFP4`, `NVFP4`, `Q1_0`, `Q2_0`).
* Deprecated/removed slots (4, 5, 31..33, 36..38) and IDs $\ge 43$ are strictly rejected (`InvalidTensorType`).
* Row divisibility is strictly enforced: $\text{dimensions}[0] \pmod{\text{block\_size}} = 0$.
* Checked arithmetic prevents integer overflow across every dimension product, block calculation, and alignment step.
* Fixed P0 unchecked addition overflow in contiguous layout validation via `checkedAdd`.

### 2. Profile Separation (`gguf-spec` vs `llama-cpp`)
Different runtimes enforce different constraints. SafeGGUF strictly decouples spec validation from runtime loader validation:

| Constraint | `--profile gguf-spec` (Default) | `--profile llama-cpp` |
| :--- | :--- | :--- |
| **GGUF Version** | Exactly version 3 | Version 2 and Version 3 |
| **Tensor Layout** | Arbitrary order & gaps permitted (non-overlapping) | Strictly contiguous in descriptor order (`offset == prev_end`) |
| **Nested Arrays** | Permitted (depth limited to 16) | Strictly rejected (`NestedArrayNotSupported`) |
| **Scalar Tensors** | Requires $1 \le \text{n\_dims} \le 4$ | Supports $\text{n\_dims} = 0$ (scalar, 1 element = `type_size`) |
| **Tensor Name Length** | $1 \le \text{len} \le 64$ bytes | $1 \le \text{len} < 64$ bytes (`GGML_MAX_NAME` check) |
| **Alignment** | Multiple of 8 (uint32) | Power-of-two (uint32) |
| **Zero Dimensions** | Strictly rejected (`ZeroDimensionNotAllowed`) | Strictly rejected (`ZeroDimensionNotAllowed`) |

### 3. Comprehensive Resource Budgeting & Anti-DoS
* **Global Quota Allocator:** Wraps GPA / test allocator with hard live and peak memory ceilings (`max_total_alloc_bytes = 128 MB`), bounding memory consumption across all parser tables, hash maps, strings, and sorting buffers.
* **Quota Exhaustion vs Host OOM:** Quota exhaustion explicitly flags `isQuotaExceeded()` and exits with code `2` (`E_TotalAllocationLimitExceeded`), while unbudgeted host memory starvation exits with code `70` (`EX_SOFTWARE`).
* **Global Work Budget:** Monotonically charged across parsing, metadata traversal, descriptor decoding, sorting $O(N \log N)$, and interval scanning (`max_work_units = 10_000_000`) to prevent CPU exhaustion.
* **Buffered I/O (64 KiB Sliding Window):** Caches reads to protect the host against syscall exhaustion attacks from fragmented metadata streams.
* **Pre-Allocation Stream Bounds Checks:** Verifies `tensor_count \le (remaining / 33)` and `metadata_kv_count \le (remaining / 13)` before attempting memory allocations.

### 4. Fail-Closed CLI & Standard Exit Code Taxonomy
SafeGGUF uses standard, deterministic exit codes suitable for automated CI/CD and deployment pipelines:

| Exit Code | Constant | Meaning |
| :---: | :--- | :--- |
| **`0`** | `PASS` | Model successfully passed all structural, arithmetic, and profile checks. |
| **`2`** | `REJECT` | File is malformed, out-of-bounds, corrupted, or violates profile/security invariants. |
| **`64`** | `EX_USAGE` | Command-line syntax error, missing argument, or unknown option (fail-closed). |
| **`70`** | `EX_SOFTWARE` | Internal system error or host out-of-memory. |
| **`74`** | `EX_IOERR` | Target file could not be opened, `stat()` failed, or stream read I/O error. |

---

## 🚀 Quick Start

### Prerequisites
* **Zig 0.13.0** (pinned toolchain)
* Python 3.10+ (for synthetic fixtures, integration, and differential tests)

### Building from Source

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF

# Build release binary (ReleaseSafe enables runtime safety checks with optimization)
zig build -Doptimize=ReleaseSafe

# Binary is placed at zig-out/bin/safegguf
./zig-out/bin/safegguf
```

### Running the Test Suite

```bash
# Run all unit tests, regression tests, and fuzz corpus sweep with 0-leak verification
zig build test --summary all

# Run standalone fuzz harness across corpus
zig build fuzz

# Run end-to-end CLI integration tests (exact exit codes & timeouts)
python tests/generate_fixtures.py
python tests/cli_test.py

# Run differential test suite comparing gguf-spec and llama-cpp profile verdicts
python tests/differential.py
```

---

## 💻 CLI Usage

### Inspect a Model (Human-Readable Output)

```bash
safegguf inspect /path/to/model.gguf
```

### Structured Output (JSON for Security Orchestration)

```bash
safegguf inspect /path/to/model.gguf --format json
```

Valid file output (`--profile gguf-spec`):
```json
{
  "status": "PASS",
  "profile": "gguf-spec",
  "version": 3,
  "file_size": 448,
  "metadata_entries": 1,
  "tensors": 2,
  "alignment": 32,
  "tensor_data_offset": 192,
  "type_layout_source": {
    "project": "ggml",
    "version": "0.23.0",
    "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
  },
  "checks": {
    "structural": "PASS",
    "arithmetic": "PASS",
    "bounds": "PASS",
    "overlap": "PASS"
  },
  "findings": []
}
```

Valid file output (`--profile llama-cpp`):
```json
{
  "status": "PASS",
  "profile": "llama-cpp",
  "version": 3,
  "file_size": 448,
  "metadata_entries": 1,
  "tensors": 2,
  "alignment": 32,
  "tensor_data_offset": 192,
  "compatibility_target": {
    "project": "ggml",
    "version": "0.23.0",
    "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
  },
  "checks": {
    "structural": "PASS",
    "arithmetic": "PASS",
    "bounds": "PASS",
    "overlap": "PASS"
  },
  "findings": []
}
```

Rejected file output:
```json
{
  "status": "REJECT",
  "profile": "llama-cpp",
  "error": "NonContiguousTensorOffset",
  "error_code": "E_NonContiguousTensorOffset",
  "stage": "validation",
  "version": 3,
  "file_size": 608,
  "findings": [
    {
      "code": "E_NonContiguousTensorOffset",
      "severity": "reject",
      "message": "Structural invariant violation"
    }
  ]
}
```

### Selecting Validation Profiles

```bash
# GGUF Specification profile (uint32, multiple of 8, version 3) - default
safegguf inspect /path/to/model.gguf --profile gguf-spec

# llama.cpp Loader profile (contiguous layout, version 2/3, name < 64 bytes, scalar tensors)
safegguf inspect /path/to/model.gguf --profile llama-cpp
```

---

## 📂 Project Structure

```
safegguf/
├── .github/
│   └── workflows/
│       └── ci.yml                      # Multi-platform CI (Ubuntu & macOS 14, 10m timeout)
├── build.zig                           # Zig 0.13.0 build configuration with fuzz step
├── src/
│   ├── root.zig                        # Package root module exports
│   ├── main.zig                        # CLI entry point (exit codes 0/2/64/70/74, JSON differentiation)
│   ├── gguf/
│   │   ├── types.zig                   # Canonical ggml 0.23.0 type traits & profile enums
│   │   ├── error.zig                   # ParseError enum and structured findings
│   │   ├── limits.zig                  # QuotaAllocator (isQuotaExceeded), WorkBudget, & DoS limits
│   │   ├── reader.zig                  # Bounded Reader with 64KB sliding-window BufferedReader
│   │   ├── metadata.zig                # UTF-8, bool chunk scan, & lower_snake_case grammar
│   │   └── parser.zig                  # Header, tensor & metadata parsing with scalar tensor support
│   └── validate/
│       ├── arithmetic.zig              # Checked arithmetic & block quantization math
│       └── structural.zig              # Tensor alignment, bounds, overlap, contiguous checks & WorkBudget
└── tests/
    ├── validator_test.zig              # 28 unit tests (P0 overflow regression, scalar, QuotaAllocator)
    ├── fuzz_target.zig                 # Native fuzzer harness and corpus runner (LLVMFuzzer entrypoint)
    ├── generate_fixtures.py            # Fixture generator (18 test files)
    ├── cli_test.py                     # CLI integration suite (exact exit codes, timeout=10)
    ├── differential.py                 # Differential test harness (spec vs llama-cpp verdicts)
    └── corpus/                         # Seed corpus directory for fuzzing (18 seed files)
```

---

## 📄 License
MIT License.
