# SafeGGUF — Remediation & Implementation Plan for F-02 / F-04 / F-05 / F-06 / F-07 / F-09

> **Archived historical document.** This is a point-in-time snapshot kept for provenance;
> it is not the current security contract. Current guarantees live in
> [`SECURITY.md`](../../SECURITY.md); current operations docs are
> [`docs/runbooks/`](../runbooks/) and [`docs/production_deployment.md`](../production_deployment.md).

> **Repository:** `BrianNguyen29/SafeGGUF`  
> **Repository URL:** https://github.com/BrianNguyen29/SafeGGUF  
> **Baseline HEAD reviewed:** `1036a2766c397192af6d97a5fe9c9ba2ffa9b945`  
> **Date:** 2026-09-11  
> **Purpose:** Detailed engineering plan to close the remaining assurance and production-readiness gaps identified in the deep review.

## Scope

This document covers:

- **F-02** — CVE provenance and true advisory regressions
- **F-04** — Real-world GGUF compatibility corpus
- **F-05** — True coverage-guided fuzzing
- **F-06** — Independent `Result` ownership
- **F-07** — Release signing, SBOM and build provenance
- **F-09** — Rolling upstream oracle / compatibility canary

---

# 1. Executive Summary

SafeGGUF's parser, arithmetic validation, bounds checks, resource budgeting and pinned upstream differential testing are already relatively strong. The remaining work is primarily about the **quality of assurance evidence**, **real ecosystem compatibility**, **library ownership safety**, **release trust**, and **upstream drift detection**.

The recommended implementation order is:

```text
F-02  True advisory provenance
      ↓
F-09  Rolling upstream canary
      ↓
F-04  Real-world GGUF corpus
      ↓
F-06  Independent Result ownership
      ↓
F-05  Coverage-guided fuzzing
      ↓
F-07  Signed / attested release chain
```

This order is intentional:

1. **F-02** makes security regression claims auditable.
2. **F-09** provides early warning about changes in `ggml` / GGUF behavior.
3. **F-04** closes the biggest real-world compatibility evidence gap.
4. **F-06** removes a public API lifetime hazard.
5. **F-05** strengthens deep parser exploration.
6. **F-07** should become the final release gate once runtime/API behavior is stable.

The desired end state is:

```text
untrusted GGUF
    ↓
SafeGGUF structural + arithmetic admission
    ↓
real-world compatibility evidence
    ↓
coverage-guided parser assurance
    ↓
independent owned library result
    ↓
signed + attested release artifacts
    ↓
rolling upstream compatibility monitoring
```

SafeGGUF should still remain explicitly scoped as a **defense-in-depth pre-admission validator**, not a complete trust or malware verdict.

---

# 2. Baseline State

Reviewed baseline:

```text
1036a2766c397192af6d97a5fe9c9ba2ffa9b945
```

Already implemented at this baseline:

- variable-array cap raised from 100,000 to 1,000,000;
- `--max-variable-array-elements` CLI override;
- synthetic negative fixtures separated from CVE identities;
- placeholders for modern advisories;
- CI split into independent `core`, `oracle`, `fuzz`, `bench`;
- backend-read benchmark instrumentation;
- Ubuntu/macOS CI currently green;
- resource-budget documentation corrected;
- zero-padding wording corrected;
- PASS semantics clarified.

The six findings below therefore represent the next assurance phase, not a parser rewrite.

---

# 3. Priority Matrix

| Finding | Priority | Recommended Solution | Risk if Deferred |
|---|---:|---|---|
| F-02 | P1 | Promote advisory placeholders to provenance-backed regression cases | Security claims remain only partially auditable |
| F-04 | P1 | Immutable real-model manifest + bounded nightly/weekly corpus | Real-model false rejects may survive synthetic tests |
| F-05 | P1 | Coverage-guided fuzz lane in addition to mutation fuzz | Deep parser paths may remain underexplored |
| F-06 | P1 | Heap-stable per-result allocator state | `Result` remains lifetime-sensitive to `Validator` |
| F-07 | P1 | GitHub attestations + SPDX SBOM + keyless signature | Validator binaries remain weakly authenticated |
| F-09 | P2→P1 assurance | Pinned blocking oracle + rolling nightly canary | Upstream drift may go unnoticed |

---

# 4. F-02 — CVE Provenance and True Advisory Regressions

## 4.1 Problem

SafeGGUF has already corrected the previous overclaim where synthetic malformed files used CVE names without matching the published mechanisms.

The remaining issue is that the modern entries:

```text
CVE-2025-53630
CVE-2026-27940
CVE-2026-33298
```

are still effectively unresolved placeholders rather than full provenance-backed regression tests.

A fixture named after a CVE should prove one of two things:

```text
exact reproduction
```

or:

```text
clearly documented mechanism-equivalent rejection
```

Anything else should remain `synthetic-*`.

---

## 4.2 Target Provenance Schema

Recommended advisory record:

```json
{
  "id": "CVE-2026-33298",
  "ghsa": "GHSA-96jg-mvhq-q7q7",
  "fixture": "cve-2026-33298-ggml-nbytes-overflow.gguf",
  "fixture_type": "advisory-regression",
  "fixture_origin": "advisory-derived",
  "source_url": "PRIMARY_SOURCE_URL",
  "source_title": "PRIMARY_SOURCE_TITLE",
  "affected_versions": "< b7437",
  "patched_versions": ">= b7824",
  "affected_commit_sha": null,
  "patched_commit_sha": null,
  "mechanism": "dimension/stride arithmetic overflow underestimates tensor bytes",
  "expected_protection": "checked tensor byte arithmetic",
  "expected_error_code": "E_ArithmeticOverflow",
  "sha256": "..."
}
```

Important rule:

> Do not treat an upstream build/revision identifier such as `b7824` as a Git commit SHA unless a real full SHA has been independently verified.

Use separate fields for:

```text
affected_versions
patched_versions
affected_commit_sha
patched_commit_sha
```

---

# 5. F-02 — CVE-2025-53630

## Vulnerability class

Cumulative tensor data sizing can overflow when aligned tensor sizes are added together.

## SafeGGUF property to test

Individual tensor sizes remain valid, but cumulative layout becomes impossible.

Expected validation path:

```text
tensor nbytes valid
    ↓
checkedAlignUp
    ↓
next tensor nbytes valid
    ↓
checked cumulative addition
    ↓
overflow
    ↓
E_ArithmeticOverflow
```

## Fixture design

Create multiple tensors such that:

```text
individual_nbytes <= UINT64_MAX
```

while:

```text
aligned_previous_end + aligned_next_size > UINT64_MAX
```

The purpose is to hit cumulative layout arithmetic, not simply single-tensor multiplication.

## Expected contract

```text
exit = 2
error_code = E_ArithmeticOverflow
category = arithmetic
```

---

# 6. F-02 — CVE-2026-33298

This should become the flagship advisory regression because it closely matches SafeGGUF's core purpose.

Recommended advisory-derived tensor:

```text
type = F32
shape = [1024, 1024, 4398046511105, 1]
```

where:

```text
4398046511105 = 2^42 + 1
```

Expected path:

```text
checked dimension product
    ↓
checked element count
    ↓
checked byte multiplication
    ↓
overflow
    ↓
E_ArithmeticOverflow
```

In addition to the `.gguf` fixture, add a **direct arithmetic test** around `computeTensorBytes()`.

This gives two layers:

```text
unit arithmetic invariant
+
full parser/admission regression
```

---

# 7. F-02 — CVE-2026-27940

This case should not be marketed as an exact reproduction unless SafeGGUF actually exercises the same downstream allocation expression.

The vulnerability involves a downstream context memory-size calculation after tensor size aggregation.

SafeGGUF does not perform the same allocation.

Therefore classify the regression as:

```text
fixture_type = advisory-regression
fixture_origin = mechanism-equivalent
```

Recommended documentation:

> SafeGGUF rejects an adversarial tensor-sizing state before it can reach the vulnerable downstream memory-allocation path. The fixture proves an equivalent admission property and does not reproduce the downstream heap allocation byte-for-byte.

This preserves technical accuracy.

---

# 8. F-02 — Mechanical Provenance Enforcement

`tests/negative_corpus.py` should fail generation for any `cve-*` entry missing:

```text
CVE ID
GHSA/advisory ID where applicable
primary source URL
source title
affected range
patched range
fixture_origin
expected protection
expected error code
SHA256
```

Pseudo-check:

```python
REQUIRED_CVE_FIELDS = [
    "id",
    "source_url",
    "affected_versions",
    "patched_versions",
    "fixture_origin",
    "expected_protection",
    "expected_error_code",
]

for case in CASES:
    if case["name"].startswith("cve-"):
        for field in REQUIRED_CVE_FIELDS:
            value = case.get(field)
            if not value or value == "TRIAGE-PENDING":
                fail(...)
```

Synthetic fixtures must never borrow an advisory identity.

---

# 9. F-02 — CI and Documentation

Rename CI step from:

```text
Run Negative CVE & Upstream Regression Corpus
```

to:

```text
Run Negative Corpus & Advisory Provenance Checks
```

until true CVE regressions are fully present.

Recommended fixture categories:

```text
synthetic-class-exemplar
advisory-regression
advisory-derived-regression
upstream-issue-regression
```

## Definition of Done

- [ ] Every `cve-*` fixture has a primary source.
- [ ] No `TRIAGE-PENDING` field is allowed on an executed CVE regression.
- [ ] CVE-2025-53630 has a deterministic cumulative-overflow test.
- [ ] CVE-2026-33298 has fixture-level + arithmetic-level regression.
- [ ] CVE-2026-27940 is explicitly classified as exact or mechanism-equivalent.
- [ ] Fixture SHA256 is stored.
- [ ] CI validates the provenance schema.
- [ ] README/SECURITY distinguish synthetic exemplars from advisory regressions.

---

# 10. F-04 — Real-World GGUF Corpus

## 10.1 Problem

Synthetic tests answer:

```text
Does the validator handle designed boundaries?
```

They do not fully answer:

```text
Does the validator accept current real-world GGUF output?
```

This is now the largest compatibility evidence gap.

---

# 11. F-04 — Three-Tier Corpus Strategy

## Tier 0 — Pull Requests

No network.

Contains:

```text
generated fixtures
systematic matrix
negative corpus
fuzz seed corpus
```

Purpose:

```text
fast deterministic correctness
```

---

## Tier 1 — Nightly Real Corpus

Target total size:

```text
approximately 0.5–1 GB
```

Purpose:

```text
detect practical false rejects
```

Recommended initial models:

### Qwen2.5 small GGUF

Reasons:

- mainstream decoder architecture;
- tokenizer >100k;
- directly validates F-01;
- small enough for bounded nightly use.

### Small BGE embedding GGUF

Reasons:

- non-decoder use case;
- much smaller download;
- adds architecture and metadata diversity.

---

## Tier 2 — Weekly / Manual Corpus

Expand gradually to:

```text
Llama
Mistral
Gemma
Phi
DeepSeek
embedding
reranker
multimodal/mmproj
vocab-only
LoRA GGUF if supported
```

Do not place every multi-GB model in nightly CI.

---

# 12. F-04 — Manifest

Create:

```text
tests/real-corpus-manifest.json
```

Recommended schema:

```json
{
  "schema_version": 1,
  "models": [
    {
      "id": "qwen2.5-0.5b-q4-k-m",
      "provider": "huggingface",
      "repo": "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
      "revision": "IMMUTABLE_REVISION",
      "filename": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
      "size_bytes": 491000000,
      "sha256": "EXPECTED_SHA256",
      "license": "Apache-2.0",
      "tier": "nightly",
      "tags": [
        "decoder",
        "qwen",
        "tokenizer>100k"
      ],
      "expected": {
        "gguf-spec": "PASS",
        "llama-cpp": "PASS"
      }
    }
  ]
}
```

---

# 13. F-04 — Manifest Invariants

Every entry must include:

```text
id
provider/source
repository or canonical origin
immutable revision
filename
declared size
SHA256
license
tier
tags
expected result per profile
```

Do not rely only on a floating branch such as:

```text
main
```

The artifact identity should be:

```text
revision + filename + SHA256
```

with SHA256 authoritative.

---

# 14. F-04 — Real Corpus Runner

Create:

```text
tests/real_corpus.py
```

Pipeline:

```text
load manifest
    ↓
validate schema
    ↓
select tier
    ↓
download to temporary path
    ↓
stream SHA256 while downloading
    ↓
enforce max download size
    ↓
verify final size
    ↓
verify SHA256
    ↓
promote to digest cache
    ↓
run safegguf --format json
    ↓
compare expected verdict
    ↓
write real-corpus-report.json
```

---

# 15. F-04 — Failure Classification

Use separate states:

```text
DOWNLOAD_ERROR
HASH_MISMATCH
SIZE_MISMATCH
SAFEGGUF_PASS
SAFEGGUF_REJECT
SAFEGGUF_ERROR
EXPECTED_RESULT_MISMATCH
```

A network outage must not be reported as a SafeGGUF compatibility regression.

---

# 16. F-04 — Cache

Recommended path:

```text
.cache/real-corpus/<sha256>.gguf
```

GitHub Actions key:

```text
real-corpus-<sha256>
```

Advantages:

- immutable;
- reproducible;
- avoids repeated downloads;
- no ambiguity when upstream changes a file.

---

# 17. F-04 — Download Safety

Enforce:

```text
declared maximum size
actual streamed bytes <= configured maximum
hash while streaming
temporary file
atomic promote only after verification
```

Do not trust HTTP `Content-Length` alone.

---

# 18. F-04 — Report

Example:

```json
{
  "schema_version": 1,
  "safegguf_commit": "...",
  "models": [
    {
      "id": "qwen2.5-0.5b-q4-k-m",
      "sha256": "...",
      "profile": "llama-cpp",
      "expected": "PASS",
      "actual": "PASS",
      "duration_ms": 1234
    }
  ]
}
```

Upload this report as a nightly artifact.

## Definition of Done

- [ ] Manifest schema exists.
- [ ] Every model pins revision, SHA256, size and license.
- [ ] Real Qwen GGUF passes.
- [ ] Real embedding/non-decoder GGUF passes.
- [ ] Hash mismatch fails closed.
- [ ] Network errors are separated from validator verdicts.
- [ ] Nightly download budget is bounded.
- [ ] Weekly/manual tier covers at least five architecture/use-case groups.
- [ ] False reject is reported as a compatibility regression.

---

# 19. F-05 — Coverage-Guided Fuzzing

## 19.1 Current State

SafeGGUF already has:

```text
mutation fuzzing
persistent corpus
profile/endian exercise
crash artifact persistence
nightly mutation campaigns
LLVMFuzzerTestOneInput-style entry point
```

But the current system does not yet use execution coverage to decide whether an input is valuable.

---

# 20. F-05 — Recommended Strategy

Do not replace deterministic mutation fuzzing.

Use three complementary systems:

```text
coverage-guided fuzzing
+
deterministic mutation fuzzing
+
upstream differential testing
```

---

# 21. F-05 — Toolchain Decision

Do not migrate the production compiler immediately just to gain a fuzzer.

Use a time-boxed instrumentation spike:

```text
Phase A
    ↓
try current source with coverage instrumentation
    ↓
prove two inputs produce distinguishable coverage
    ↓
if successful:
    use AFL++ or equivalent
else:
    use fuzz-only newer Zig lane
```

Time-box:

```text
<= 1 engineering day
```

---

# 22. F-05 — Option A: AFL++ / External Coverage Engine

Preferred if current production source can be reliably instrumented.

Required proof:

```text
input A → coverage map X
input B → coverage map Y
X != Y
```

If the coverage map does not meaningfully reflect parser path differences, do not proceed with this option.

---

# 23. F-05 — Option B: Fuzz-Only Newer Zig Toolchain

If Zig 0.13 cannot provide practical feedback instrumentation:

```text
production build:
    Zig 0.13

coverage fuzz build:
    newer Zig
```

Only port the minimal fuzz target.

Do not migrate all production code and release tooling solely to gain coverage fuzzing.

---

# 24. F-05 — In-Process Harness

Avoid subprocess fuzzing:

```text
fuzzer
→ write temp file
→ launch safegguf CLI
→ inspect exit code
```

Preferred:

```zig
fn fuzzOne(
    data: []const u8,
    profile: types.Profile,
    endian: std.builtin.Endian,
) void {
    var sr = reader.SliceReader.init(data);
    var validator = Validator.init(...);
    validator.endian = endian;

    var doc = validator.validate(sr.reader()) catch return;
    validator.deinitDocument(&doc);
}
```

This improves throughput dramatically.

---

# 25. F-05 — Target Split

Recommended targets:

```text
fuzz_gguf_spec_little
fuzz_gguf_spec_big
fuzz_llama_cpp_little
```

Optional smoke target:

```text
fuzz_llama_cpp_big
```

Because the llama-cpp big-endian case rejects early, it provides less deep coverage.

---

# 26. F-05 — Coverage Corpus Policy

Coverage corpus entries should be kept because they create:

```text
new edges
new paths
new comparisons
new cleanup/error paths
```

not because they PASS validation.

Malformed files are high-value fuzz inputs.

Do not require coverage-corpus inputs to be accepted by `llama-cpp`.

---

# 27. F-05 — Seed Corpus

Recommended seeds:

```text
minimal valid GGUF
metadata-only GGUF
large tokenizer metadata
nested metadata
all active tensor types
alignment boundaries
zero tensors
truncated descriptor
invalid UTF-8
dimension overflow
tensor overlap
CVE regressions
differential matrix samples
minimized real-world structures
```

Do not seed multi-GB models directly.

---

# 28. F-05 — Sanitizers / Failure Taxonomy

Where supported:

```text
ASan
UBSan
coverage instrumentation
runtime safety
```

Classify separately:

```text
panic
signal crash
timeout
OOM
sanitizer finding
unexpected exit
```

---

# 29. F-05 — Corpus Persistence

Persist:

```text
coverage-increasing inputs
minimized representatives
promoted regressions
```

Do not persist every random mutation.

Use bounded storage, for example:

```text
max entries: 10,000
max total bytes: 256 MiB
```

Tune after observing real corpus growth.

---

# 30. F-05 — Crash Artifact Contract

Store:

```text
original input
minimized input
profile
endian
engine
engine version
compiler
SafeGGUF commit
coverage statistics
sanitizer output
reproduction command
```

---

# 31. F-05 — Regression Promotion

Every confirmed fuzz bug should follow:

```text
discover
    ↓
minimize
    ↓
root cause
    ↓
fix
    ↓
deterministic regression
```

A fuzz crash should not be considered resolved until the bug is represented in deterministic CI.

## Definition of Done

- [ ] Coverage feedback is demonstrably active.
- [ ] Corpus evolves from new coverage.
- [ ] Nightly sustained run has a defined time budget.
- [ ] Crash input is persisted.
- [ ] Crash minimization works.
- [ ] Reproduction command is recorded.
- [ ] Coverage summary is uploaded.
- [ ] Existing mutation campaign remains.
- [ ] Confirmed bugs become deterministic tests.

---

# 32. F-06 — Independent `Result` Ownership

## 32.1 Current Problem

Current conceptual relationship:

```text
Result
  ├── Document
  └── Allocator
        └── ptr → Validator.quota_alloc
```

Therefore:

```text
Result lifetime
    depends on
Validator lifetime and address stability
```

The API is easier to use than raw `Document`, but it is not truly ownership-independent.

---

# 33. F-06 — Target Contract

After remediation:

```text
Result.deinit()
```

must remain valid even if the producing `Validator` has:

```text
left scope
been reused
been moved
been destroyed
```

---

# 34. F-06 — Recommended Architecture

Introduce a heap-stable owned state:

```zig
const OwnedValidationState = struct {
    parent_allocator: std.mem.Allocator,
    quota_alloc: limits.QuotaAllocator,
};
```

Then:

```zig
pub const Result = struct {
    doc: parser.Document,
    state: ?*OwnedValidationState,
};
```

Relationship:

```text
Result
  ├── Document allocations
  │      allocated through
  │
  └── *OwnedValidationState
          └── QuotaAllocator
                └── parent allocator
```

The state address does not depend on the `Validator` object's location.

---

# 35. F-06 — Proposed `deinit()`

Concept:

```zig
pub fn deinit(self: *Result) void {
    const state = self.state orelse return;

    const parent = state.parent_allocator;
    self.doc.deinit(state.quota_alloc.allocator());

    self.state = null;
    parent.destroy(state);
}
```

Making `state` optional also permits safe debug-friendly repeated `deinit()` handling.

---

# 36. F-06 — `validateOwned()` Redesign

Do not implement owned validation by calling the borrowed allocator path.

Bad:

```zig
return .{
    .doc = try self.validate(r),
    .alloc = self.quota_alloc.allocator(),
};
```

Preferred:

```text
allocate OwnedValidationState
    ↓
initialize independent QuotaAllocator
    ↓
create local WorkBudget
    ↓
parse using owned quota allocator
    ↓
structural validate
    ↓
return Result(doc + owned state)
```

The work budget does not need to survive after validation.

Only the allocation state backing `Document` must remain alive.

---

# 37. F-06 — Shared Internal Helper

To avoid duplication, extract an internal helper such as:

```zig
fn validateWith(
    allocator: std.mem.Allocator,
    work_budget: *limits.WorkBudget,
    lim: limits.Limits,
    profile: types.Profile,
    endian: std.builtin.Endian,
    r: reader_mod.Reader,
) !parser.Document
```

Then:

```text
borrowed validate
owned validate
```

reuse the same parser/structural logic.

---

# 38. F-06 — API Migration

Recommended transition:

## Current release

Keep:

```text
validate()
deinitDocument()
validateOwned()
```

Recommend `validateOwned()` for new users.

## Next API cleanup

Expose semantic names:

```text
validateBorrowed()
validateOwned()
```

Mark legacy pairing deprecated.

Do not remove it abruptly.

---

# 39. F-06 — Mandatory Tests

## Result survives Validator scope

```zig
var result = blk: {
    var validator = Validator.init(...);
    break :blk try validator.validateOwned(reader);
};

defer result.deinit();
```

Must be valid.

## Multiple live Results

```text
Result A
Result B
deinit B
deinit A
```

No leak, no accounting corruption.

## Validator reuse

Result A remains alive while Validator validates another file.

## Error cleanup

Exercise:

```text
parse failure
structural failure
quota failure
```

Owned state must always be freed.

## Relocation

Moving/copying the producing `Validator` after creating an owned Result must not affect the Result.

## Leak check

`std.testing.allocator` must finish cleanly.

## Definition of Done

- [ ] `Result` no longer contains allocator context pointing into `Validator`.
- [ ] Producing Validator may be destroyed before `Result.deinit()`.
- [ ] Multiple Results can coexist.
- [ ] Error paths leak nothing.
- [ ] API ownership contract is simple and mechanical.
- [ ] Library callers do not need to preserve a producing object address.

---

# 40. F-07 — Signing, SBOM and Build Provenance

## 40.1 Current State

Current release chain is approximately:

```text
build binaries
    ↓
SHA256SUMS.txt
    ↓
GitHub Release upload
```

This provides checksums but only partial provenance.

---

# 41. F-07 — Target Release Chain

Recommended:

```text
source commit
    ↓
reviewed GitHub Actions workflow
    ↓
ReleaseSafe build
    ↓
SHA256 manifest
    ↓
SPDX SBOM
    ↓
artifact provenance attestation
    ↓
SBOM attestation
    ↓
Cosign keyless signature
    ↓
self-verification
    ↓
publish GitHub Release
```

---

# 42. F-07 — GitHub Artifact Attestations

Release workflow should add:

```yaml
permissions:
  contents: write
  id-token: write
  attestations: write
```

Each release binary should receive provenance.

Initial target:

```text
SLSA Build Level 2-style provenance
```

Do not claim Level 3 until workflow isolation/reusable workflow requirements have actually been satisfied.

---

# 43. F-07 — SBOM

Use one canonical format:

```text
SPDX JSON
```

Recommended output:

```text
dist/safegguf.spdx.json
```

Include:

```text
SafeGGUF package/version
source repository
source commit
declared license
release files
file hashes
package/dependency metadata
build-generation metadata
```

Do not misrepresent the Zig compiler as a runtime dependency.

Toolchain identity belongs primarily in build provenance.

---

# 44. F-07 — Keyless Signing

Use Sigstore/Cosign keyless signing.

Recommended signed object:

```text
SHA256SUMS.txt
```

Output:

```text
SHA256SUMS.txt.sigstore.json
```

This gives one authenticated manifest covering all release binaries.

Each binary should still be individually attested.

Avoid a long-lived release private key stored in repository secrets unless an organization specifically requires that model.

---

# 45. F-07 — `--version`

Recommended output:

```text
SafeGGUF 0.x.y
source_commit: 1036a2766c397192af6d97a5fe9c9ba2ffa9b945
zig: 0.13.0
build_mode: ReleaseSafe
target: x86_64-linux
ggml_target: 0.23.0
ggml_commit: e91ded11bdcd78c42f9c8d3978ff6686eb4c1226
```

Avoid embedding wall-clock build timestamps if reproducible builds are a future objective.

---

# 46. F-07 — Build Metadata

`build.zig` should inject:

```text
SafeGGUF version
source commit
Zig version
build mode
target
pinned ggml version
pinned ggml commit
```

Expose through generated build options or:

```text
src/build_info.zig
```

---

# 47. F-07 — Release Must Verify Before Publish

Required order:

```text
build
    ↓
hash
    ↓
generate SBOM
    ↓
attest binaries
    ↓
attest SBOM
    ↓
sign checksum manifest
    ↓
verify hash
    ↓
verify signature
    ↓
verify provenance
    ↓
publish
```

If any verification step fails:

```text
do not publish
```

---

# 48. F-07 — Recommended Release Assets

```text
safegguf-x86_64-linux
safegguf-aarch64-linux
safegguf-x86_64-macos
safegguf-aarch64-macos
safegguf-x86_64-windows.exe

SHA256SUMS.txt
SHA256SUMS.txt.sigstore.json
safegguf.spdx.json
```

Artifact attestations may remain linked through GitHub rather than uploaded as arbitrary opaque files if the platform provides native verification.

---

# 49. F-07 — Documentation

README should document verification using:

```text
SHA256
Cosign
GitHub artifact attestation verification
```

Do not stop at:

```text
compare checksum manually
```

## Definition of Done

- [ ] Every release binary has provenance attestation.
- [ ] SPDX SBOM exists.
- [ ] SBOM is attested.
- [ ] SHA256 manifest is keylessly signed.
- [ ] Release workflow verifies the above before upload.
- [ ] `--version` exposes build identity.
- [ ] README documents verification.
- [ ] No production-oriented release is published if supply-chain verification fails.

---

# 50. F-09 — Rolling Upstream Oracle

## 50.1 Problem

The current oracle is intentionally pinned:

```text
ggml 0.23.0
e91ded11bdcd78c42f9c8d3978ff6686eb4c1226
```

This provides deterministic compatibility.

It cannot detect:

```text
new tensor types
type-layout changes
new metadata behavior
new upstream rejection rules
removed divergences
new divergences
```

---

# 51. F-09 — Two-Oracle Model

## Oracle A — Pinned / Blocking

Purpose:

```text
reproducible compatibility contract
```

Properties:

```text
exact commit
stable behavior
PR blocking
release blocking
```

---

## Oracle B — Rolling / Canary

Purpose:

```text
detect ecosystem drift
```

Properties:

```text
nightly
current upstream resolved to full SHA
report-oriented
not PR blocking
```

---

# 52. F-09 — Separate Storage

Do not reuse the same cache/build/binary paths.

Recommended:

```text
.cache/oracle/pinned/
.cache/oracle/rolling/<sha>/

tests/oracle/ggml_oracle_pinned
tests/oracle/ggml_oracle_rolling
```

This prevents a rolling build from contaminating the pinned oracle.

---

# 53. F-09 — Refactor `build_oracle.sh`

Support:

```bash
tests/build_oracle.sh \
  --name pinned \
  --ref e91ded11bdcd78c42f9c8d3978ff6686eb4c1226 \
  --output tests/oracle/ggml_oracle_pinned
```

and:

```bash
tests/build_oracle.sh \
  --name rolling \
  --ref <resolved-full-sha> \
  --output tests/oracle/ggml_oracle_rolling
```

Default invocation should remain pinned for backward compatibility.

---

# 54. F-09 — Resolve Floating Upstream Once

Nightly:

```text
resolve upstream master
    ↓
obtain full SHA
    ↓
checkout exact full SHA
    ↓
build exact SHA
    ↓
record exact SHA in report
```

Never report the tested identity merely as:

```text
master
```

---

# 55. F-09 — Type Drift First

Before full differential tests, compare:

```text
type IDs
type names
block sizes
type sizes
slot count
```

Report:

```text
new type
removed type
changed type size
changed block size
renamed type
```

This catches upstream format evolution even if current fixture matrix does not generate the new type.

---

# 56. F-09 — Differential Report Mode

Add:

```text
tests/differential.py --report-json <path>
```

Recommended output:

```json
{
  "schema_version": 1,
  "safegguf_sha": "...",
  "upstream_sha": "...",
  "new_type_ids": [],
  "new_divergences": [],
  "resolved_divergences": [],
  "safe_accept_upstream_reject": [],
  "safe_reject_upstream_accept": [],
  "oracle_errors": []
}
```

---

# 57. F-09 — Divergence Semantics

```text
Safe PASS / Upstream PASS
    agreement

Safe REJECT / Upstream REJECT
    agreement

Safe REJECT / Upstream PASS
    intentional safe subset
    or compatibility false reject

Safe PASS / Upstream REJECT
    possible SafeGGUF false accept
    or upstream tightening

Oracle build/crash/API failure
    infrastructure or upstream breaking change
```

---

# 58. F-09 — Baseline Policy

Do not auto-update the rolling baseline.

Use:

```text
reviewed baseline
    ↓
new nightly result
    ↓
diff
    ↓
human review
    ↓
explicit baseline update commit
```

Automatic acceptance of new rolling behavior would remove most of the security value of the canary.

---

# 59. F-09 — Workflow

Create:

```text
.github/workflows/upstream-canary.yml
```

Recommended:

```text
nightly schedule
manual workflow_dispatch
Ubuntu initially
resolve upstream SHA
build rolling oracle
run rolling type comparison
run differential report
upload JSON
upload readable summary
```

The canary should not be required for PR merges.

It may legitimately go red when upstream changes unexpectedly.

## Definition of Done

- [ ] Pinned Oracle A remains unchanged and blocking.
- [ ] Rolling Oracle B resolves and records full upstream SHA.
- [ ] Cache and binaries are isolated.
- [ ] Rolling type table comparison runs first.
- [ ] Differential JSON report is generated.
- [ ] Report is uploaded nightly.
- [ ] Baseline updates require explicit review.
- [ ] Rolling behavior never silently replaces the pinned compatibility contract.

---

# 60. Cross-Cutting CI Architecture

Recommended final structure:

```text
PR / Main CI
├── core
├── pinned-oracle
├── deterministic-fuzz
└── bench

Nightly Assurance
├── coverage-fuzz
├── real-corpus-tier1
└── rolling-upstream-canary

Weekly / Manual
└── real-corpus-tier2

Release
├── require normal CI
├── build
├── hash
├── SBOM
├── attest
├── sign
├── verify
└── publish
```

---

# 61. Files to Modify

## F-02

```text
tests/negative_corpus.py
tests/fixtures/negative/manifest.json   # generated
README.md
SECURITY.md
.github/workflows/ci.yml
```

Optional:

```text
tests/advisories.json
```

---

## F-04

```text
tests/real-corpus-manifest.json
tests/real_corpus.py
.github/workflows/real-corpus.yml
README.md
docs/assurance-roadmap-issues.md
```

---

## F-05

```text
tests/fuzz_target.zig
build.zig
.github/workflows/coverage-fuzz.yml
tests/fuzz/
```

Optional:

```text
tests/afl/
tests/libfuzzer/
```

---

## F-06

```text
src/validate/validator.zig
src/root.zig
tests/validator_test.zig
README.md
AGENTS.md
SECURITY.md
```

Optional:

```text
src/validate/owned_state.zig
```

---

## F-07

```text
build.zig
src/main.zig
src/build_info.zig
.github/workflows/ci.yml
README.md
SECURITY.md
```

Generated:

```text
dist/SHA256SUMS.txt
dist/SHA256SUMS.txt.sigstore.json
dist/safegguf.spdx.json
```

---

## F-09

```text
tests/build_oracle.sh
tests/differential.py
tests/test_oracle_types.py
tests/canary_drift.py
.github/workflows/upstream-canary.yml
docs/assurance-roadmap-issues.md
```

---

# 62. Recommended Implementation Sequence

## Phase A — Assurance Truthfulness

### A1 — F-02

Complete true provenance + CVE regressions.

Estimated effort:

```text
0.5–1.5 days
```

### A2 — F-09

Build rolling upstream canary.

Estimated:

```text
1–2 days
```

---

# 63. Phase B — Compatibility Evidence

### B1 — F-04 Tier 1

Add:

```text
one real Qwen model
one small embedding/BGE model
```

plus manifest, runner and nightly report.

Estimated:

```text
1–2 days
```

### B2 — F-04 Tier 2

Expand to more model families after license/download review.

Estimated:

```text
incremental 0.5–1 day
```

---

# 64. Phase C — API Safety

### C1 — F-06

Implement independent owned validation state.

Estimated:

```text
1–2 days
```

Complete before describing `validateOwned()` as a production-safe ownership abstraction.

---

# 65. Phase D — Parser Assurance

### D1 — F-05 Instrumentation Spike

Time-box:

```text
<= 1 day
```

Outcome:

```text
AFL++ / external engine
or
fuzz-only newer Zig
```

### D2 — Full Coverage Fuzzer

Estimated:

```text
1–3 days
```

depending on toolchain friction.

---

# 66. Phase E — Release Supply Chain

### E1 — F-07

Implement:

```text
build identity
SPDX SBOM
artifact attestation
keyless signature
self-verification
```

Estimated:

```text
1–2 days
```

This should become a release gate before the next production-oriented release.

---

# 67. Required vs Advisory Checks

## Required for PR / Main

```text
core
pinned oracle
deterministic fuzz
bench
```

## Required for Release

```text
all normal CI
SBOM generation
artifact attestation
signature generation
signature verification
provenance verification
```

## Nightly / Advisory

```text
coverage fuzz
real-world corpus
rolling upstream oracle
```

For a major release candidate, manually require recent green nightly assurance evidence.

---

# 68. Final Milestone Exit Criteria

SafeGGUF can reasonably move from:

```text
pre-production / maturing
```

toward:

```text
production-capable defense-in-depth component
```

when:

- [ ] Real Qwen GGUF passes.
- [ ] Real non-decoder/embedding GGUF passes.
- [ ] CVE regressions are provenance-backed.
- [ ] Coverage-guided fuzzing is demonstrably active.
- [ ] `Result` survives producing `Validator` destruction.
- [ ] Rolling upstream drift reports run nightly.
- [ ] Release binaries are attested.
- [ ] SPDX SBOM is published.
- [ ] Checksum manifest is signed.
- [ ] Release workflow verifies all supply-chain evidence before publishing.

---

# 69. Key Risks and Mitigations

## Real corpus becomes expensive

Mitigate with:

```text
tiering
digest cache
small nightly subset
weekly large subset
```

## Fuzz compiler differs from production compiler

Mitigate with:

```text
production deterministic tests remain on production compiler
every fuzz bug promoted to production-toolchain regression
```

## Result redesign causes API migration cost

Mitigate with:

```text
keep old API temporarily
document migration
deprecate before removal
```

## Rolling oracle becomes noisy

Mitigate with:

```text
drift classification
non-blocking nightly
manual baseline approval
```

## Supply-chain workflow makes release brittle

Mitigate with:

```text
separate build / attest / verify / publish stages
publish only after self-verification
```

---

# 70. Proposed Tracking Status

| Finding | Proposed Status |
|---|---|
| F-02 | READY TO IMPLEMENT |
| F-04 | READY TO IMPLEMENT — bounded Tier 1 first |
| F-05 | ENGINEERING SPIKE REQUIRED |
| F-06 | READY TO IMPLEMENT |
| F-07 | READY TO IMPLEMENT |
| F-09 | READY TO IMPLEMENT |

Only F-05 needs a short technical spike before the final fuzz engine is selected.

---

# 71. Final Recommendation

The next phase should not prioritize adding more ad-hoc parser checks unless a new parser bug is found.

The highest-value work is now:

```text
provenance-backed security regressions
+
real ecosystem compatibility
+
true coverage feedback
+
mechanically safe ownership
+
verifiable release artifacts
+
upstream drift monitoring
```

The target assurance stack becomes:

```text
defensive SafeGGUF core
    +
real-world corpus
    +
coverage-guided fuzzing
    +
independent Result ownership
    +
signed / attested releases
    +
rolling upstream oracle
```

This would materially improve SafeGGUF's suitability as a production **pre-admission defense-in-depth control**.

The guarantee boundary should remain:

> `PASS` means the file satisfies SafeGGUF's selected structural, arithmetic and resource-policy checks. It does not prove benign model behavior, publisher trust, downstream runtime safety or absence of malicious model semantics.

---

# 72. Reference Links

## SafeGGUF

- Repository:  
  https://github.com/BrianNguyen29/SafeGGUF

- Reviewed baseline commit:  
  https://github.com/BrianNguyen29/SafeGGUF/commit/1036a2766c397192af6d97a5fe9c9ba2ffa9b945

- Security policy:  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/SECURITY.md

- Deep review fix plan:  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/docs/deep-review-fix-plan.md

- Assurance roadmap:  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/docs/assurance-roadmap-issues.md

## Upstream Advisories

- CVE-2025-53630 / GHSA-vgg9-87g3-85w8  
  https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-vgg9-87g3-85w8

- CVE-2026-27940 / GHSA-3p4r-fq3f-q74v  
  https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v

- CVE-2026-33298 / GHSA-96jg-mvhq-q7q7  
  https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-96jg-mvhq-q7q7

## Supply Chain

- GitHub Artifact Attestations  
  https://docs.github.com/en/actions/concepts/security/artifact-attestations

- GitHub Artifact Attestation Usage  
  https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

- Sigstore / Cosign Blob Signing  
  https://docs.sigstore.dev/cosign/signing/signing_with_blobs/

## Zig

- Downloads / release notes  
  https://ziglang.org/download/

---

## End of document
