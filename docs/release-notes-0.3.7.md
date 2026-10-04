# 0.3.7 release preparation (unreleased)

The source default remains `0.3.7-dev` until release. Release jobs inject the
tag version into binaries, libraries and images. This document does not claim
that 0.3.7 has been published.

- Reject embedded NUL tensor names in the llama-cpp profile, preventing
  different byte strings from aliasing one upstream C-string name. The
  gguf-spec profile retains length-delimited names. Rejection uses the existing
  `E_InvalidTensorName` / `SGGUF_E_INVALID_TENSOR_NAME` codes and exit 2.
- Admission schema v2 binds every effective policy limit, key policy,
  requested/resolved endian and build/type-table provenance. CAS paths now
  resolve relative to `--cas-dir`; migrate admission v1 consumers explicitly.
  Inspect and error diagnostics remain schema v1.
- Canonical C error-code mapping always returns library-owned static storage,
  including canonical input held in a caller-owned temporary buffer.
- The shell handoff and Kubernetes admission container use the same native
  single-process publisher. The release workflow renders the Kubernetes
  template from its signed, digest-pinned container image.
- The serving checksum gate restores `/app` before launching the pinned
  llama.cpp runtime, allowing its bundled dynamic libraries to resolve.
  Regression checks prevent serving after checksum failure or ambiguous pins.
- Container smoke tests cover nonroot admission, statement/object identity and
  rejection without publication on both release architectures. Docker contexts
  exclude generated fixtures/caches and Git metadata; CI injects source commit
  explicitly with `SAFEGGUF_SOURCE_COMMIT`.
- Fixture generation fails visibly if security fixture generation fails.
  NUL, mutable-buffer lifetime, policy replay and deployment rendering have
  regression coverage.

The CLI default changes already on this development branch are retained:
`llama-cpp` + `auto`. Pin explicit flags if migrating from older CLI defaults.
See [admission v2](admission-attestation.md),
[deployment](production_deployment.md), and [release verification](../SECURITY.md).
