# Security Policy

SafeGGUF is designed as a memory-safe, overflow-checked pre-admission validation layer for AI model weights stored in the GGUF format.

The current source version is **0.1.0**. Support applies to signed artifacts
published through [GitHub Releases](https://github.com/BrianNguyen29/SafeGGUF/releases),
not to arbitrary source builds or locally renamed binaries.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.0 release artifacts | Supported |
| Other versions | Unsupported |

Source builds use the version declared in `VERSION`; matching a version string
alone does not establish release authenticity.

## Release Verification

Tagged releases publish the cross-platform binaries, `SHA256SUMS.txt`, a keyless Sigstore signature bundle (`SHA256SUMS.txt.sigstore.json`), and an SPDX 2.3 SBOM (`safegguf.spdx.json`). GitHub artifact attestations cover the release binaries: a build-provenance attestation, and an SBOM attestation whose `spdx.dev/Document` predicate is the SBOM content and whose subjects are those same binaries. The `safegguf.spdx.json` release asset itself is not an attestation subject; verify the attested SBOM content through a binary subject, as in step 4. The release workflow verifies checksums, signature, and attestations **before** publishing and aborts on any failure.

Signing is keyless (the release workflow's GitHub OIDC identity; no long-lived release private key). Verify a downloaded release before use:

```bash
# Use the reviewed source commit of the release being verified.
RELEASE_TAG=v0.1.0
RELEASE_COMMIT="$(git rev-parse "${RELEASE_TAG}^{commit}")"

# 1. Verify the checksum manifest's keyless Sigstore signature
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/BrianNguyen29/SafeGGUF/\.github/workflows/ci\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt

# 2. Verify the binaries against the signed manifest
sha256sum -c SHA256SUMS.txt

# 3. Verify the build provenance attestation for a binary, pinning the signer
#    workflow and the expected source tag and commit
gh attestation verify safegguf-x86_64-linux \
  --repo BrianNguyen29/SafeGGUF \
  --signer-workflow BrianNguyen29/SafeGGUF/.github/workflows/ci.yml \
  --predicate-type https://slsa.dev/provenance/v1 \
  --source-ref "refs/tags/${RELEASE_TAG}" \
  --source-digest "$RELEASE_COMMIT"

# 4. Verify the attested SBOM content (spdx.dev/Document predicate) for the
#    same binary; --format json prints the verified statement, whose
#    verificationResult.statement.predicate is the signed SBOM
gh attestation verify safegguf-x86_64-linux \
  --repo BrianNguyen29/SafeGGUF \
  --signer-workflow BrianNguyen29/SafeGGUF/.github/workflows/ci.yml \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --source-ref "refs/tags/${RELEASE_TAG}" \
  --source-digest "$RELEASE_COMMIT"
```

Use a trusted checkout containing the reviewed release tag. Pin both the source
reference and its expected commit when verifying provenance.

`safegguf --version` reports the version, source commit, Zig version, build mode,
target and pinned ggml baseline. CI checks source metadata against `VERSION`
and requires the release tag to match before publication.

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
   SafeGGUF provides in-process descriptor validation (`safegguf_validate_fd` / `safegguf.validate_fd`). To achieve TOCTOU-resistance:
   - Downstream inference loaders must consume the exact same open file descriptor (`O_RDONLY`) whose inode is protected from untrusted writers, OR
   - Deployers must validate files stored in immutable Content-Addressable Storage (CAS) and hand off the verified cryptographic digest (e.g. SHA-256) directly to downstream inference runtimes.
   Path-based validation (`safegguf_validate_path`) alone cannot prevent external file swapping if an attacker possesses write permissions on the file path between validation and loader ingestion.
5. **`PASS` Scope:** `PASS` means the file satisfies the selected SafeGGUF structural, arithmetic, and resource-policy checks. It is not a trust or malware verdict for model behavior, templates, or downstream runtime code.

### Immutable CAS Example (Stage, Validate, Digest-Pin, Load)

The digest must describe the same protected bytes that passed validation. Use
the single-process publisher in a private workspace controlled by the service:

```bash
mkdir -p /srv/safegguf/validated /srv/safegguf/attestations
safegguf admit /uploads/model.gguf \
  --cas-dir /srv/safegguf/validated \
  --attestations-dir /srv/safegguf/attestations \
  --profile llama-cpp --max-file-size-bytes 17179869184 > admission.json
# Continue only after exit 0. Resolve cas.relative_path from the CAS directory,
# verify the digest, and load that object from a protected read-only mount.
```

Never validate and hash a mutable upload path separately. The handoff wrapper
and Kubernetes template both use `admit`. Descriptor identity checks do not
make an inode immutable; 0444 mode does not prevent its owner from changing
permissions or a directory writer from replacing the path. Exclude untrusted
same-UID/privileged writers from staging and CAS, and give serving read-only
mounts. Admission statements are unsigned unless a trusted signing layer signs
them; image/release signatures are separate from model-admission signatures.
See [admission v2](docs/admission-attestation.md) and the
[deployment guide](docs/production_deployment.md).

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
