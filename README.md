# SafeGGUF 🛡️

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg)](https://ziglang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An overflow-checked GGUF v3 structural and arithmetic validator written in **Zig**, designed to inspect model headers, metadata, and tensor descriptors to reject malformed or adversarial input before weights are mapped into production inference runtimes.

SafeGGUF operates purely on file headers and descriptors without loading multi-gigabyte tensor payload data into host memory.

---

## 🎯 Threat Model & Problem Statement

GGUF is the standard container format for local and edge LLM inference (`llama.cpp`, Ollama, vLLM). Because model files are typically loaded via `mmap` and parsed in C/C++, malformed or crafted files present direct security risks:

* **Integer Overflows in Tensor Byte Math:** Crafting extreme tensor dimensions can overflow integer calculations in block quantization, bypassing bounds checks and triggering undersized allocations or heap buffer overflows (e.g., CVE-2026-33298, CVE-2026-27940).
* **Allocation Denial-of-Service (DoS):** Corrupted headers specifying astronomical tensor counts or metadata counts can exhaust system memory before any payload is verified.
* **Overlapping Tensor Mappings:** Maliciously overlapping tensor offsets can cause subsequent tensor operations to overwrite or misinterpret memory segments.
* **Metadata Exploits:** Unchecked recursive structures or arbitrary metadata keys can cause deep call-stack exhaustion or parser hangs.

SafeGGUF provides a hardened pre-admission boundary that validates format compliance, arithmetic bounds, and memory layout before inference engines open model files.

---

## 🛡️ Architectural Guarantees & Implementation

SafeGGUF implements strict invariants to protect parsing environments:

### 1. Bounded Allocation Pre-Checks (Anti-DoS)
Before allocating memory for descriptor tables, SafeGGUF verifies that the requested counts are physically possible within the remaining file stream:
* Metadata entries: verified against `(file_size - offset) / min_metadata_size`.
* Tensor descriptors: verified against `(file_size - offset) / min_tensor_descriptor_size` (minimum 33 bytes per descriptor).
* Descriptors exceeding physical stream limits are rejected with `UnexpectedEof` before any dynamic allocation occurs.

### 2. Checked Block-Quantization Arithmetic
Validates dimensions and byte sizes across **all 43 upstream GGML types** (F32 down to modern NVFP4 and MXFP4):
$$\text{nbytes} = \frac{\prod_i \text{dimensions}_i}{\text{block\_size}(\text{type})} \times \text{type\_size}(\text{type})$$
* **Row Divisibility:** Verifies that $\text{dimensions}[0]$ is evenly divisible by $\text{block\_size}(\text{type})$.
* **Overflow Protection:** Every step (product of dimensions, block division, multiplication, and alignment padding) uses checked arithmetic (`std.math.add`, `std.math.mul`).

### 3. Structural Alignment & Memory Range Verification
* Verifies `tensor_data_base` and every tensor `offset` respect file alignment (default: 32 bytes).
* Performs sorted interval analysis ($O(N \log N)$) across all tensor ranges $[\text{start}, \text{end})$ to ensure every tensor resides within file bounds and that no two tensors overlap.

### 4. Metadata Hardening
* **Key Format:** Enforces hierarchical `lower_snake_case` namespaces (`[a-z0-9_.-]+`).
* **Duplicate Detection:** Rejects duplicate metadata keys and duplicate tensor names.
* **Recursion Limit:** Nested arrays are strictly bounded to `max_metadata_depth = 8` to eliminate call-stack exhaustion.
* **Fast-Path Skipping:** Fixed-size primitive arrays are range-skipped in $O(1)$ arithmetic without per-element loop overhead.

### 5. Leak-Free Memory Lifecycle
All partial allocations on error paths are reclaimed via scoped deferral and verified by Zig's `GeneralPurposeAllocator` leak detection hooks.

---

## 🚀 Quick Start

### Prerequisites
* **Zig 0.13.0** (pinned toolchain)
* Python 3.10+ (for synthetic test fixture generation)

### Building from Source

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF

# Build optimized release binary
zig build -Doptimize=ReleaseFast

# Binary is available at zig-out/bin/safegguf
./zig-out/bin/safegguf
```

### Running the Test Suite

```bash
# Run 15 unit and integration tests with leak checking
zig build test --summary all
```

---

## 💻 CLI Usage

### Inspect a Model (Human-Readable Output)

```bash
safegguf inspect /path/to/model.gguf
```

Output:
```text
GGUF version: 3
File size: 448 bytes
Metadata entries: 1
Tensors: 2
Alignment: 32
Tensor data offset: 192

Validation:
  structural: PASS
  arithmetic: PASS
  bounds: PASS
  overlap: PASS
Result: PASS
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

Rejected file output (e.g., duplicate tensor names):
```json
{
  "status": "REJECT",
  "error": "DuplicateTensorName",
  "error_code": "E_DuplicateTensorName",
  "stage": "validation",
  "version": 3,
  "file_size": 384
}
```

---

## 📂 Project Structure

```
safegguf/
├── .github/
│   └── workflows/
│       └── ci.yml                      # Multi-platform CI (Ubuntu & macOS)
├── build.zig                           # Modular Zig 0.13.0 build script
├── src/
│   ├── root.zig                        # Package root module exports
│   ├── main.zig                        # CLI entry point (text & JSON output)
│   ├── gguf/
│   │   ├── types.zig                   # GGUF v3 wire types & full 43 GGML traits
│   │   ├── error.zig                   # ParseError enum and structured findings
│   │   ├── limits.zig                  # Anti-DoS thresholds & resource limits
│   │   ├── reader.zig                  # Random-access Bounded Reader abstraction
│   │   ├── metadata.zig                # Key validation, nested arrays & fast-path
│   │   └── parser.zig                  # Header & descriptor parsing with DoS pre-checks
│   └── validate/
│       ├── arithmetic.zig              # Checked arithmetic & block size calculation
│       └── structural.zig              # Tensor alignment, bounds, & overlap verification
└── tests/
    ├── validator_test.zig              # Comprehensive unit tests with GPA leak checks
    └── generate_fixtures.py            # Fixture generator (valid & attack vectors)
```

---

## 📄 License
MIT License.
