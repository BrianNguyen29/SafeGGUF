# SafeGGUF 🛡️

A high-performance, memory-safe GGUF v3 structural and arithmetic validator written in **Zig**.

SafeGGUF inspects model headers, metadata, and tensor descriptors without loading multi-gigabyte tensor payloads into memory, preventing memory corruption and denial-of-service vulnerabilities.

---

## 🎯 Threat Model & Motivation

Recent security research and CVE disclosures have revealed recurring memory corruption vulnerabilities in C/C++ GGUF parsers:

* **CVE-2026-33298 (CVSS 7.8 High):** Integer overflow in ggml_nbytes allowing heap buffer overflows via crafted tensor dimensions.
* **CVE-2026-27940 (CVSS 7.8 High):** Integer overflow in gguf_init_from_file_impl leading to undersized allocations and heap overflows (bypassing the patch for **CVE-2025-53630**).
* **CVE-2024-34359 (CVSS 9.7 Critical):** Unsandboxed Jinja2 template execution from model metadata leading to Remote Code Execution (RCE).

While SafeTensors was created to eliminate code execution from Pickle, **GGUF remains the de-facto standard for local LLM inference (Ollama, llama.cpp)**. Existing scanners like Protect AI's ModelScan currently lack GGUF support (Issue #111). SafeGGUF fills this critical gap with a zero-panic, mathematically verified validator.

---

## ✨ Key Invariants & Features

1. **Block-Quantization Arithmetic Invariant:**
   Properly validates block-quantized tensors (Q4_0, Q4_K, Q8_0, etc.) with explicit row-divisibility checking:
   \text{nbytes} = \frac{\prod_i \text{dimensions}_i}{\text{block\_size}(\text{type})} \times \text{type\_size}(\text{type})
   Every calculation is checked for overflow:
   checked_product $\rightarrow$ ow_divisibility $\rightarrow$ checked_div $\rightarrow$ checked_mul $\rightarrow$ checked_align_up $\rightarrow$ offset + size <= file_size.

2. **Bounded Random-Access Reader Abstraction:**
   * Decoupled from OS memory-mapping (mmap).
   * SliceReader for in-memory testing and fuzzing harnesses.
   * FileReader utilizing thread-safe preadAll on files.

3. **Strict Resource Limits (Anti-DoS):**
   * Configurable ceilings on metadata count, tensor count, string lengths, and array elements to prevent memory exhaustion from hostile headers.

4. **Zero-Panic Error Model:**
   * Malicious or malformed inputs return structured error findings (ArithmeticOverflow, MisalignedTensor, TensorOutOfBounds, TensorOverlap) rather than crashing or aborting.

---

## 🚀 Quick Start

### Prerequisites
* **Zig 0.13.0+**

### Building from Source
`ash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF

# Build optimized binary
zig build -Doptimize=ReleaseFast

# Binary is available at zig-out/bin/safegguf
./zig-out/bin/safegguf
`

### Running Unit Tests
`ash
zig build test --summary all
`

---

## 💻 Usage

### Inspect a Model
`ash
safegguf inspect path/to/model.gguf
`

**Valid Output Example:**
`	ext
GGUF version: 3
File size: 384 bytes
Metadata entries: 1
Tensors: 2
Alignment: 32
Tensor data offset: 192

Validation:
  structural: PASS
  arithmetic: PASS
  bounds: PASS
  overlap: PASS
`

**Rejected Output Example (Hostile Payload):**
`	ext
GGUF version: 3
File size: 83 bytes
Metadata entries: 0
Tensors: 1
Alignment: 32
Tensor data offset: 96

Validation: REJECT [E_ArithmeticOverflow]
`

---

## 📂 Project Structure

`
safegguf/
├── build.zig                           # Modular Zig build configuration
├── src/
│   ├── root.zig                        # Library root & exports
│   ├── main.zig                        # CLI inspect tool
│   ├── gguf/
│   │   ├── types.zig                   # GGUF v3 wire definitions & GGML type traits
│   │   ├── error.zig                   # Structured ParseError & Findings
│   │   ├── limits.zig                  # Anti-DoS resource constraints
│   │   ├── reader.zig                  # Bounded Reader (SliceReader & FileReader)
│   │   ├── metadata.zig                # Spec-compliant metadata key/value parsing
│   │   └── parser.zig                  # Document & Header parser
│   └── validate/
│       ├── arithmetic.zig              # Checked arithmetic & block size math
│       └── structural.zig              # Offset alignment, bounds, & overlap checks
└── tests/
    ├── validator_test.zig              # Comprehensive unit tests
    └── generate_fixtures.py            # Synthetic binary test fixture generator
`

---

## 📄 License
MIT License.
