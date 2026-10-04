# SafeGGUF 0.1.0

SafeGGUF validates GGUF model files before an inference runtime loads them.
This release provides a CLI, C API, Python bindings and container integration.

## Features

- Structural and tensor-layout validation with checked arithmetic.
- `llama-cpp` and `gguf-spec` validation profiles, with bounded allocation,
  logical-work and scanned-byte budgets.
- Single-process `admit` publishing to content-addressed storage, with
  admission schema v2 recording effective policy and build provenance.
- Stable exit codes, JSON diagnostics, canonical error codes and optional
  metrics and structured logs.
- C APIs for paths and open file descriptors; Python bindings that bundle the
  native library when packaged as a wheel.
- Nonroot containers for Linux amd64/arm64, with signed release images and
  a digest-pinned Kubernetes deployment example.

## Defaults and compatibility

The CLI and Python bindings default to `llama-cpp` and automatic byte-order
detection. C callers passing `NULL` options use the same defaults; explicitly
initialize options when using a caller-owned structure.

The `llama-cpp` profile rejects embedded NUL tensor names. Admission statements
use schema v2; inspection and error diagnostics use schema v1. API and schema
versions are independent of the package version.

## Verification

Release assets include binaries for Linux, macOS and Windows, SHA-256 checksums,
a keyless signature bundle and an SPDX SBOM. See [SECURITY.md](https://github.com/BrianNguyen29/SafeGGUF/blob/v0.1.0/SECURITY.md)
for signature and provenance verification.

A PASS verdict covers the selected structural and resource policy. Model
authenticity, weight behavior and inference compatibility require separate
verification. See the [deployment guide](https://github.com/BrianNguyen29/SafeGGUF/blob/v0.1.0/docs/production_deployment.md) and
[admission contract](https://github.com/BrianNguyen29/SafeGGUF/blob/v0.1.0/docs/admission-attestation.md).
