# Security Policy

SafeGGUF is designed as a memory-safe, overflow-checked pre-admission validation layer for AI model weights stored in the GGUF format.

> **Release status:** **v0.3.5** is the latest tagged release; `main` is unreleased and carries post-v0.3.5 assurance work (v0.3.6). Unless marked otherwise, the guarantees below describe `main`.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

## Release Verification

Tagged releases publish the cross-platform binaries, `SHA256SUMS.txt`, a keyless Sigstore signature bundle (`SHA256SUMS.txt.sigstore.json`), and an SPDX 2.3 SBOM (`safegguf.spdx.json`). GitHub artifact attestations cover the release binaries and the SBOM. The release workflow verifies checksums, signature, and attestations **before** publishing and aborts on any failure.

Signing is keyless (the release workflow's GitHub OIDC identity; no long-lived release private key). Verify a downloaded release before use:

```bash
# 1. Verify the checksum manifest's keyless Sigstore signature
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/BrianNguyen29/SafeGGUF/\.github/workflows/ci\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt

# 2. Verify the binaries against the signed manifest
sha256sum -c SHA256SUMS.txt

# 3. Verify the GitHub build provenance attestation for a binary
gh attestation verify safegguf-x86_64-linux --repo BrianNguyen29/SafeGGUF
```

`safegguf --version` reports the embedded version, source commit, Zig version, build mode, target, and pinned ggml target/commit.

### Regression Fixture Provenance

Security regression claims are provenance-tiered: `synthetic-class-exemplar` fixtures exercise a malformed-input bug class and never carry a CVE/advisory identity, while advisory regressions require a verifiable primary source and a documented rejection mechanism. Mechanism-equivalent cases are labeled as such and are not claimed as byte-for-byte reproductions of downstream behavior.

## Threat Model & Security Invariants

SafeGGUF enforces pre-admission defense-in-depth before untrusted model files are mapped into memory or parsed by upstream C/C++ runtimes (such as `llama.cpp` or `ggml`):

1. **Checked Arithmetic on Attacker-Controlled Values:** Arithmetic on file-controlled dimensions, offsets, alignments, and sizes uses checked arithmetic (`checkedAdd`, `checkedMul`, `checkedAlignUp`); integer overflow terminates validation with exit code `2` (`REJECT`) instead of wrapping. This invariant is enforced by the implementation and exercised by the regression suite, the differential harness against the pinned upstream ggml oracle, and mutation fuzzing — it is not guaranteed by construction alone.
2. **Resource Exhaustion Resistance (DoS Prevention):**
   - **Allocation Quota (validator-managed):** Memory allocated through the validator's wrapped `QuotaAllocator` — parser tables, metadata structures, strings, and sorting buffers — is capped at 128 MB (default). Exceeding the quota fails closed with `E_TotalAllocationLimitExceeded` (exit code `2`). This bounds allocations routed through the validator's allocator; it is not an OS-level process RSS or page-cache limit.
   - **Logical Work Budget:** Parser and structural validator operations are charged against deterministic logical work units (default 10,000,000) via `WorkBudget`. This bounds algorithmic work inside the validator; it is not a CPU-instruction, CPU-time, or wall-clock cap.
   - **Scanned-Byte Budget:** Streaming string validation, UTF-8 checks, and boolean scans are charged against a 256 MB scanned-byte limit via `WorkBudget.consumeBytes()` (validator-managed).
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
5. **`PASS` Scope:** `PASS` means the file satisfies the selected SafeGGUF structural, arithmetic, and resource-policy checks. It is not a trust or malware verdict for model behavior, templates, or downstream runtime code.

### Deployment Limits (Hostile Multi-Tenant Uploads)

SafeGGUF's budgets are validator-managed quotas over its own allocations and logical work; they do not cap process RSS, page cache, stack, CPU time, or allocator/kernel overhead. For untrusted multi-tenant uploads, additionally run validation under OS/container limits: a cgroup/job-object memory limit, a CPU quota plus wall-clock timeout, an input file-size limit, a read-only filesystem where possible, and a seccomp/sandbox profile.

## Reporting a Vulnerability

If you discover a potential security vulnerability, memory safety bug, integer overflow bypass, or DoS vector in SafeGGUF:

1. **Do not open a public GitHub issue.**
2. Report the vulnerability privately via [GitHub Security Advisories](https://github.com/BrianNguyen29/SafeGGUF/security/advisories/new) or contact the project maintainer via GitHub.
3. Include:
   - Detailed description of the vulnerability.
   - Minimal proof-of-concept (PoC) or `.gguf` fixture reproducing the issue.
   - Expected vs actual behavior.
   - Affected profile(s) (`gguf-spec`, `llama-cpp`, or both).

## Response SLA

- **Initial Triage:** Within 48 hours of report receipt.
- **Root-Cause Analysis & Reproduction:** Within 5 business days.
- **Fix & Advisory Release:** Coordinated disclosure within 30 days.
