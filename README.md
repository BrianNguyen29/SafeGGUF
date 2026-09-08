# SafeGGUF 🛡️

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg)](https://ziglang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Upstream ggml](https://img.shields.io/badge/ggml-0.23.0%20(e91ded11)-blue.svg)](https://github.com/ggml-org/ggml/tree/e91ded11bdcd78c42f9c8d3978ff6686eb4c1226)
[![Release](https://img.shields.io/badge/release-v0.3.1-green.svg)](https://github.com/BrianNguyen29/SafeGGUF/releases)

A memory-safe, overflow-checked GGUF v3 structural and arithmetic pre-admission validator written in **Zig**, designed to inspect model headers, metadata, and tensor descriptors to reject malformed or adversarial input before weights are mapped into production inference runtimes.

SafeGGUF operates purely on file headers and descriptors without loading multi-gigabyte tensor payload data into host memory.

---

## 🎯 Threat Model & Motivation

GGUF is the standard container format for local and edge LLM inference (`llama.cpp`, Ollama, vLLM). Because model files are typically loaded via `mmap` and parsed in C/C++, malformed or crafted files present direct security risks:

* **Integer Overflows in Tensor Byte Math:** Crafting extreme tensor dimensions can overflow integer calculations in block quantization, bypassing bounds checks and triggering undersized allocations or heap buffer overflows (e.g., CVE-2026-33298, CVE-2026-27940).
* **Contiguous Layout & Trailing Padding Exploits:** In runtime loaders requiring strictly sequential layouts, calculating expected offsets ($O_{next} = O_{cur} + S$) without checked arithmetic can trigger integer overflows and crash. Furthermore, files truncating trailing tensor padding cause runtime loaders to abort with truncated reads (`failed to read tensor data binary blob`).
* **Memory & I/O Exhaustion (Anti-DoS):** Corrupted headers declaring massive tensor counts or nested string arrays can exhaust host memory or force gigabytes of stream byte validation without exceeding logical element counts.
* **Semantic Format Exploits:** Malformed boolean values (bytes $\notin \{0, 1\}$), invalid UTF-8 sequences, or unconstrained nested arrays can trigger parser panics or memory corruption.

SafeGGUF acts as a hardened **pre-admission gateway** in model supply chain pipelines, running before weights are mapped or executed.

---

## 🛡️ Architectural Guarantees & Features (v0.3.0)

### 1. Canonical Upstream Type Table Verified by C Oracle
Supports all **35 active GGML types** matching `ggml 0.23.0` (`e91ded11`):
* Verified against an independent compiled C++ upstream oracle (`tests/test_oracle_types.py`) inspecting exact `sizeof` and `blck_size` across all 43 upstream type slots.
* Includes standard floating point (`F32`, `F16`, `BF16`, `F64`), integers (`I8`..`I64`), k-quants (`Q2_K`..`Q8_K`), i-quants (`IQ1_S`, `IQ1_M`, `IQ2_XXS`..`IQ4_XS`), t-quants (`TQ1_0`, `TQ2_0`), and modern micro-float types (`MXFP4`, `NVFP4`, `Q1_0`, `Q2_0`).
* Deprecated/removed slots (4, 5, 31..33, 36..38) and IDs $\ge 43$ are strictly rejected (`InvalidTensorType`).
* Row divisibility is strictly enforced: $\text{dimensions}[0] \pmod{\text{block\_size}} = 0$.
* Checked arithmetic prevents integer overflow across every dimension product, block calculation, alignment, and contiguous layout traversal.

### 2. Profile Separation: Specification vs Runtime Safe Subset
Different runtimes enforce different constraints. SafeGGUF strictly decouples spec validation from runtime loader validation:

| Constraint | `--profile gguf-spec` (Default) | `--profile llama-cpp` |
| :--- | :--- | :--- |
| **Profile Role** | Resource-bounded GGUF v3 structural safe subset | ggml 0.23.0 Safe Pre-Admission Subset |
| **GGUF Version** | Exactly version 3 | Version 2 and Version 3 |
| **Tensor Layout** | Arbitrary order & gaps permitted (non-overlapping) | Strictly contiguous in descriptor order + checked trailing padding |
| **Nested Arrays** | Permitted (depth limited to 16) | Strictly rejected (`NestedArrayNotSupported`) |
| **Scalar Tensors** | Supported ($\text{n\_dims} = 0$, 1 element = `type_size`) | Supported ($\text{n\_dims} = 0$, 1 element = `type_size`) |
| **Zero Dimensions** | Strictly rejected (`dimensions[i] > 0`) | Strictly rejected (`dimensions[i] > 0`) |
| **Tensor Name Length** | $1 \le \text{len} \le 64$ bytes | $1 \le \text{len} < 64$ bytes (`GGML_MAX_NAME` check) |
| **Alignment** | Multiple of 8 (uint32) | Power-of-two (uint32) |

> [!NOTE]
> Both `--profile gguf-spec` and `--profile llama-cpp` are **safe pre-admission subsets** designed for defense-in-depth. They enforce deliberate security invariants over raw formats: strict boolean bytes ($\in \{0, 1\}$), non-empty tensor names ($1 \le \text{len}$), non-zero dimensions ($d > 0$), strict lower_snake_case key grammar, checked integer overflow prevention (mitigating upstream `GGML_PAD` unsigned wrap-around), and finite resource budgets.

### 3. Comprehensive Multi-Layer Resource Budgeting (Anti-DoS)
* **Global Quota Allocator:** Wraps GPA / test allocator with hard live and peak memory ceilings (`max_total_alloc_bytes = 128 MB`), bounding memory consumption across all parser tables, hash maps, strings, and sorting buffers.
* **Quota Exhaustion vs Host OOM:** Quota exhaustion explicitly flags `isQuotaExceeded()` and exits with code `2` (`E_TotalAllocationLimitExceeded`), while unbudgeted host memory starvation exits with code `70` (`EX_SOFTWARE`).
* **Global Work Budget:** Monotonically charged across parsing, metadata traversal, descriptor decoding, sorting $O(N \log N)$, and interval scanning (`max_work_units = 10_000_000`) to prevent CPU algorithmic complexity attacks.
* **Byte-Scanning Budget:** Dedicated accounting (`max_scanned_bytes = 256 MB`) charging every byte read during UTF-8 stream validation, boolean array scanning, key validation, and string parsing to eliminate CPU/IO sink attacks.
* **Buffered I/O (64 KiB Sliding Window):** Caches reads to protect the host against syscall exhaustion attacks from fragmented metadata streams.

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

## 🔬 Independent Verification & Testing Infrastructure

SafeGGUF incorporates an exhaustive, multi-tier verification harness:

1. **Independent Type Oracle Verification (`tests/test_oracle_types.py`):**
   Automatically builds a C++ helper against `ggml-org/ggml@e91ded11` and asserts that all 43 GGML type traits match with 100% precision.
2. **True Upstream Differential Validation (`tests/differential.py`):**
   Executes SafeGGUF alongside the compiled upstream `ggml` oracle running both metadata-only and normal tensor data loading paths (`gguf_init_from_file`). Enforces an explicit, audited allowlist for intentional security divergences. Any unexpected divergence immediately fails CI.
3. **Seed Corpus Crash Regression & Fuzz Harness (`tests/fuzz_target.zig`):**
   Provides an official `LLVMFuzzerTestOneInput` C ABI entry point for libFuzzer/OSS-Fuzz and a corpus runner (`zig build fuzz`) verifying parser memory safety across 19 adversarial seed fixtures.
4. **Leak-Free Unit & Regression Suite (`zig build test`):**
   30 exhaustive tests verifying arithmetic overflows, trailing padding truncation, quota tracking, and DoS limits with 0 memory leaks under `std.testing.allocator`.

---

## 🔒 Supply Chain & TOCTOU Considerations

SafeGGUF acts as a fast pre-admission barrier inspecting headers before runtime mapping. In environments where local file storage is shared or writable by untrusted processes:

* **Time-Of-Check to Time-Of-Use (TOCTOU):** A file validated by SafeGGUF could theoretically be modified on disk before a downstream inference engine loads it.
* **Recommended Mitigations:**
  1. **Immutable Content-Addressed Storage (CAS):** Store models in read-only volumes (e.g., S3/OCI read-only layers, dm-verity) and validate before promoting to the admitted store.
  2. **File Descriptor Chaining:** In programmatic / library integrations, open the file descriptor once with read-only permissions (`O_RDONLY`), validate the descriptor via SafeGGUF, and pass the same descriptor to the runtime loader.
  3. **Digest Verification:** Verify SHA-256 or BLAKE3 digests of admitted artifacts before deployment.

---

## 🚀 Quick Start

### Prerequisites
* **Zig 0.13.0** (pinned toolchain)
* Python 3.10+
* CMake & C++ compiler (for building the upstream verification oracle)

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
# 1. Verify code formatting
zig fmt --check src/ build.zig tests/*.zig

# 2. Run all unit tests, regression tests, and fuzz corpus sweep with 0-leak verification
zig build test --summary all

# 3. Generate synthetic adversarial fixtures
python tests/generate_fixtures.py

# 4. Run end-to-end CLI integration tests (exact exit codes & timeouts)
python tests/cli_test.py

# 5. Build upstream ggml oracle and verify type traits
bash tests/build_oracle.sh
python tests/test_oracle_types.py

# 6. Run true upstream differential test suite (SafeGGUF vs Upstream ggml 0.23.0)
python tests/differential.py

# 7. Run high-throughput mutation fuzzing (2,000 hostile permutations)
python tests/fuzz_mutation.py --iterations 2000
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

---

## 📄 License
MIT License.
