# Security Policy

SafeGGUF is designed as a memory-safe, overflow-checked pre-admission validation layer for AI model weights stored in the GGUF format.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

## Threat Model & Security Invariants

SafeGGUF enforces pre-admission defense-in-depth before untrusted model files are mapped into memory or parsed by upstream C/C++ runtimes (such as `llama.cpp` or `ggml`):

1. **Zero Unchecked Panics:** All arithmetic operations on dimensions, offsets, alignments, and sizes use checked arithmetic (`checkedAdd`, `checkedMul`, `checkedAlignUp`). Any integer overflow immediately terminates validation cleanly with exit code `2` (`REJECT`).
2. **Resource Exhaustion Resistance (DoS Prevention):**
   - **Memory Quota:** Total memory allocated for metadata structures is capped at 128 MB via `QuotaAllocator`. Exceeding this quota fails closed with `E_TotalAllocationLimitExceeded` (exit code `2`).
   - **Work Budget:** Parser and structural validator operations are tracked via monotonic work units (maximum 1,000,000 units).
   - **Byte Scanning Budget:** Streaming string validation, UTF-8 checks, and boolean scans are tracked against a 256 MB scanning limit via `WorkBudget.consumeBytes()`.
3. **Fail-Closed Exit Taxonomy:**
   - `0`: Valid GGUF file meeting the requested profile constraints.
   - `2`: Invalid GGUF file or resource quota violation.
   - `64`: Command-line usage or syntax error.
   - `70`: Internal software / host memory failure.
   - `74`: File I/O or filesystem stat error.
4. **Time-of-Check to Time-of-Use (TOCTOU):**
   SafeGGUF validates files on disk or streams. To prevent TOCTOU vulnerabilities where a file is swapped or modified between validation and loading:
   - Deployers should validate files in immutable content-addressable storage (CAS).
   - Verify cryptographic hashes (e.g. SHA-256) matching the validated file before admission to inference runtimes.

## Reporting a Vulnerability

If you discover a potential security vulnerability, memory safety bug, integer overflow bypass, or DoS vector in SafeGGUF:

1. **Do not open a public GitHub issue.**
2. Report the vulnerability privately via GitHub Security Advisories or by emailing the project maintainer at `duong.nguyen@example.com` (or the repository contact).
3. Include:
   - Detailed description of the vulnerability.
   - Minimal proof-of-concept (PoC) or `.gguf` fixture reproducing the issue.
   - Expected vs actual behavior.
   - Affected profile(s) (`gguf-spec`, `llama-cpp`, or both).

## Response SLA

- **Initial Triage:** Within 48 hours of report receipt.
- **Root-Cause Analysis & Reproduction:** Within 5 business days.
- **Fix & Advisory Release:** Coordinated disclosure within 30 days.
