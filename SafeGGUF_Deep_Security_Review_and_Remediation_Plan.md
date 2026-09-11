# SafeGGUF — Deep Security Review, Findings & Remediation Plan

> **Repository:** `BrianNguyen29/SafeGGUF`  
> **Repository URL:** https://github.com/BrianNguyen29/SafeGGUF  
> **Review snapshot:** `main` at commit `158308eee14fe767a45bd60a7ffe8d731941665c`  
> **Review date:** 2026-09-11  
> **Primary upstream compatibility target used by project:** `ggml 0.23.0`, commit `e91ded11bdcd78c42f9c8d3978ff6686eb4c1226`  
> **Review type:** Technical due diligence + security architecture review + compatibility/assurance review  
> **Status at review snapshot:** Promising / security-conscious / **pre-production**, not yet production-hardened

---

## 1. Executive Summary

SafeGGUF is a relatively small Zig project intended to validate GGUF model files **before** they are admitted into a production inference runtime. Its design goal is reasonable and addresses a real attack surface: malformed or adversarial GGUF files have historically triggered integer overflows, undersized allocations, out-of-bounds accesses, heap corruption and potentially remote code execution in downstream C/C++ runtimes such as `ggml` / `llama.cpp`.

The core implementation is materially stronger than a superficial “parse-and-check-magic” validator. The reviewed code contains:

- checked `u64` addition/multiplication/division and checked alignment;
- bounds checking before file reads;
- count and string-length guards before allocation;
- independent limits for allocation, work units and scanned bytes;
- streaming UTF-8 validation;
- strict boolean validation;
- metadata recursion-depth controls;
- duplicate key/name detection;
- tensor type/block-size validation;
- tensor byte-range bounds checks;
- tensor overlap detection;
- compatibility-profile-specific constraints;
- a pinned compiled upstream oracle for differential testing;
- deterministic unit, CLI, negative, differential and mutation tests;
- release-safe builds and SHA-pinned CI actions.

These are substantive engineering controls, not merely README claims.

However, the review identified several issues that currently prevent a strong “production hardened” recommendation. The most important are:

1. **P0 — Default variable-array element limit is likely to reject valid mainstream models.**  
   `max_variable_array_elements = 100_000` is applied to metadata arrays of strings. GGUF stores `tokenizer.ggml.tokens` as `array[string]`; Qwen2 uses a vocabulary size of `151,936`, and Llama 3 uses roughly 128K tokens. The CLI uses the default limits and exposes no override. This creates a high-confidence risk of false rejection for legitimate, widely used GGUF models.

2. **P0 — The “CVE regression corpus” has incorrect CVE-to-mechanism mapping.**  
   Current fixtures named after CVE-2024-25664, CVE-2024-25665 and CVE-2024-25668 do not faithfully model the mechanisms associated with those CVEs in the original GGUF vulnerability research. They remain useful malformed-input tests, but should not be presented as CVE regressions until their provenance and mechanisms are corrected.

3. **P0 — `main` is red on Ubuntu at the reviewed commit.**  
   Core tests pass, but the resource benchmark fails a Linux syscall-count assertion. This causes subsequent upstream-oracle, differential and fuzz steps to be skipped on Ubuntu. macOS passes the full pipeline. A security-sensitive project should not release from a red default branch.

4. **P1 — No real-world GGUF corpus gate yet.**  
   Synthetic matrices are good for boundary coverage but insufficient to detect practical false rejects across current model families, tokenizers, sidecars and conversion pipelines.

5. **P1 — Fuzzing is not yet true coverage-guided fuzzing.**  
   The project exposes a libFuzzer-compatible entry point and runs mutation campaigns, but the current Zig 0.13 setup does not provide sustained coverage-feedback fuzzing. For an untrusted binary parser, this remains an important assurance gap.

6. **P1 — `validateOwned()` / `Result` is not truly ownership-independent.**  
   `Result` captures an allocator whose context pointer still references the producing `Validator`’s embedded `QuotaAllocator`. The API documentation warns about lifetime constraints, but the naming can imply stronger ownership independence than actually exists. Relocation/copy/lifetime misuse should be designed out or made much harder.

7. **P1/P2 — Supply-chain assurance remains basic.**  
   Release checksums exist and CI dependencies are pinned, but there is no complete signed provenance/SBOM/attestation story, and the reviewed HEAD commit is unsigned.

8. **P2 — Some documentation overstates or mischaracterizes specification behavior.**  
   In particular, zero-filled alignment padding is described as a SafeGGUF-specific stricter invariant, while the GGUF specification itself states that required padding is filled with `0x00`.

The correct deployment posture today is therefore:

> **Use SafeGGUF as one defense-in-depth pre-admission layer, not as the sole trust boundary for untrusted GGUF files.**

A suitable hardened pipeline is:

```text
download/import
    ↓
source identity + cryptographic digest
    ↓
SafeGGUF structural/arithmetic admission
    ↓
organization policy checks
    ↓
immutable/content-addressed storage
    ↓
sandboxed / isolated inference runtime
```

---

## 2. Overall Assessment

### 2.1 Rating at the reviewed snapshot

| Area | Rating | Notes |
|---|---:|---|
| Security architecture | 8.5 / 10 | Good problem framing and layered controls |
| Defensive parsing | 8.5 / 10 | Strong bounds/overflow/resource handling |
| Tensor arithmetic | 8.5 / 10 | Checked arithmetic and range validation are strong |
| Test engineering | 7.5 / 10 | Unusually good for project age, but still assurance gaps |
| Real-world compatibility | 5.5 / 10 | Major risk from current variable-array cap |
| API/library maturity | 6.5 / 10 | Functional, but ownership/lifetime ergonomics need work |
| CI/release maturity | 6.0 / 10 | Good structure, currently red on Ubuntu |
| Supply-chain assurance | 5.0 / 10 | Checksums/pinning good; signing/attestation missing |
| Production readiness | ~6 / 10 | Pre-production |
| Potential after P0/P1 fixes | High | Core design does not require rewrite |

### 2.2 Recommended status label

**Recommended label:** `pre-production / security-conscious / promising`

Not recommended yet:

- as the only control protecting a privileged model-serving host;
- as a universal “GGUF is safe” verdict;
- as a strict compatibility validator for arbitrary current GGUF models without first fixing limits and validating a real-world corpus.

---

## 3. Review Scope and Method

The review covered the following areas.

### 3.1 Repository structure

Reviewed key paths include:

```text
src/gguf/
  error.zig
  limits.zig
  metadata.zig
  parser.zig
  reader.zig
  types.zig

src/validate/
  arithmetic.zig
  structural.zig
  validator.zig

src/main.zig
src/root.zig
build.zig

tests/
  arithmetic_oracle.py
  bench_scales.zig
  build_oracle.sh
  cli_test.py
  differential.py
  differential_matrix.py
  fuzz_mutation.py
  fuzz_target.zig
  generate_fixtures.py
  negative_corpus.py
  test_oracle_types.py
  validator_test.zig

.github/workflows/
  ci.yml
  nightly.yml

README.md
SECURITY.md
docs/assurance-roadmap-issues.md
```

### 3.2 Security surfaces reviewed

- attacker-controlled header counts;
- attacker-controlled metadata length/count/type fields;
- nested arrays;
- variable-size arrays;
- UTF-8 validation;
- boolean parsing;
- tensor name/dimension/type/offset fields;
- dimension products and quantized block calculations;
- offset alignment and cumulative layout arithmetic;
- tensor data bounds;
- overlap detection;
- allocation exhaustion;
- CPU/work exhaustion;
- I/O/syscall amplification;
- public/library API lifecycle;
- failure taxonomy;
- CI and release pipeline;
- oracle provenance;
- fuzzing strategy;
- real-world compatibility risk;
- TOCTOU and supply-chain posture.

### 3.3 External references considered

The project was also compared against:

- current/pinned GGUF specification;
- `ggml` type definitions at the pinned upstream commit;
- official `llama.cpp` security advisories;
- published GGUF parser vulnerability research;
- official/common model tokenizer sizes for current families.

---

# 4. Positive Findings — Controls That Are Correctly Implemented

These are important because remediation should preserve them.

## 4.1 Checked reader boundary

`Reader.readBytes()` computes the end offset with checked addition and verifies it against `Reader.size` before dispatching to the backend reader.

Conceptually:

```zig
const end = std.math.add(u64, offset, dest.len)
    catch return err.ParseError.UnexpectedEof;

if (end > self.size)
    return err.ParseError.UnexpectedEof;
```

This is the correct pattern for an untrusted binary format. It avoids trusting `offset + len` arithmetic.

### Recommendation

Keep the generic `Reader` boundary invariant centralized. New reader implementations should **not** be allowed to bypass it from public parser code.

---

## 4.2 Pre-allocation count and length checks

The parser rejects excessive:

- tensor count;
- metadata entry count;
- string length;
- tensor-name length;
- dimension count;

before performing relevant allocations.

This directly reduces classic parser allocation attacks such as:

```text
attacker count
    ↓
count * sizeof(T)
    ↓ overflow or huge allocation
    ↓
heap corruption / OOM
```

### Recommendation

Preserve the “validate declaration before allocation” rule as an explicit project invariant in `AGENTS.md` / contributor docs.

---

## 4.3 Separate resource budgets

The project uses multiple independent controls:

```text
max_total_alloc_bytes = 128 MiB
max_work_units        = 10,000,000
max_scanned_bytes     = 256 MiB
```

This is better than relying on one generic element-count limit.

The intent is good:

- allocation budget → memory pressure;
- work budget → algorithmic/loop work;
- scanned-byte budget → string/bool validation I/O and CPU.

### Recommendation

Do not remove these budgets when fixing compatibility. Instead, **decouple semantic element-count caps from resource budgets**.

This distinction becomes central to Finding F-01.

---

## 4.4 Streaming UTF-8 validation

Large string values are not copied wholesale to an unbounded heap buffer merely for UTF-8 validation. Validation proceeds in chunks with carry handling across UTF-8 sequence boundaries.

This is the right architecture for potentially large metadata strings.

### Recommendation

Keep deterministic tests for:

- 2-byte sequence split at buffer boundary;
- 3-byte sequence split;
- 4-byte sequence split;
- truncated trailing sequence;
- overlong sequences;
- invalid continuation byte.

The repository already moved in this direction.

---

## 4.5 Strict boolean validation

The validator accepts boolean bytes only in `{0, 1}`.

That is a useful canonicalization rule and removes ambiguity created by C-like “any non-zero is true” behavior.

---

## 4.6 Tensor type table pinned to upstream code, not documentation alone

SafeGGUF pins:

```text
ggml 0.23.0
commit e91ded11bdcd78c42f9c8d3978ff6686eb4c1226
```

At that upstream commit, the actual header defines:

```text
NVFP4 = 40
Q1_0  = 41
Q2_0  = 42
COUNT = 43
```

SafeGGUF reflects this and independently compiles an upstream oracle.

This is a particularly good decision because upstream documentation and implementation can temporarily drift.

### Recommendation

Retain the compiled oracle. Add a rolling-current canary separately rather than replacing the pinned target.

---

## 4.7 Tensor byte arithmetic is defensive

`computeTensorBytes()` validates:

- known tensor type;
- dimension count;
- scalar semantics;
- block divisibility;
- dimension product overflow;
- block count;
- byte-size multiplication overflow.

This directly addresses the class of integer-overflow bugs that has repeatedly affected GGUF loaders.

Official `llama.cpp` advisories relevant to this class include:

- CVE-2025-53630;
- CVE-2026-27940;
- CVE-2026-33298.

These should become explicit regression targets later in this document.

---

## 4.8 Structural range validation

The validator checks:

- alignment;
- absolute tensor offset;
- tensor end offset;
- file bounds;
- duplicate tensor names;
- overlap between tensor byte ranges.

The range-sorting approach is straightforward and auditable.

---

## 4.9 Differential testing design is strong

The repository builds an external upstream `ggml` oracle, pins it to the declared compatibility commit and compares SafeGGUF behavior with both load/no-load paths.

A strong aspect of `tests/differential.py` is that it does **not** require SafeGGUF to blindly match upstream. Intentional security divergences are enumerated.

That is appropriate for a safe-subset validator.

---

# 5. Finding Summary

| ID | Priority | Area | Finding |
|---|---|---|---|
| F-01 | **P0** | Compatibility / policy | Default 100k variable-array cap can reject valid modern tokenizer arrays |
| F-02 | **P0** | Assurance / security evidence | CVE regression fixture names do not match CVE mechanisms |
| F-03 | **P0** | CI / benchmark | Ubuntu `main` is red because syscall benchmark bound is too brittle |
| F-04 | **P1** | Compatibility assurance | No real-world GGUF corpus gate |
| F-05 | **P1** | Fuzzing | No sustained true coverage-guided fuzzing yet |
| F-06 | **P1** | API ownership | `Result` still depends on producing Validator allocator state/address |
| F-07 | **P1** | Supply chain | No complete signing/SBOM/provenance/attestation |
| F-08 | P2 | Documentation | Zero-filled padding described as stricter-than-spec although spec requires zero padding |
| F-09 | P2 | Compatibility drift | Only pinned compatibility oracle; no rolling upstream canary |
| F-10 | P2 | Security semantics | Resource-budget wording can be misread as OS-level process limits |
| F-11 | P2 | Platform assurance | Windows artifacts are built but not equivalently runtime-tested |
| F-12 | P2 | Deployment model | Validator PASS must not be represented as full model trust |
| F-13 | P2 | Release/version hygiene | HEAD feature/version state and README/release badge are temporarily out of sync |

---

# 6. Detailed Findings and Remediation

---

## F-01 — P0 — `max_variable_array_elements = 100_000` can reject valid modern GGUF tokenizers

### Severity

**Priority:** P0  
**Type:** Compatibility / false reject / operational availability  
**Confidence:** High

### Evidence in SafeGGUF

`src/gguf/limits.zig` defaults include:

```zig
max_array_elements: u64 = 10_000_000,
max_variable_array_elements: u64 = 100_000,
```

`src/gguf/metadata.zig` contains logic equivalent to:

```zig
if (elem_type == .string or elem_type == .array) {
    if (count > limit.max_variable_array_elements)
        return err.ParseError.ResourceLimitExceeded;
}
```

`src/main.zig` constructs:

```zig
const limit = limits.Limits{};
```

The CLI currently does not expose a general mechanism to raise this specific limit.

### Why this is a real compatibility problem

The GGUF specification defines:

```text
tokenizer.ggml.tokens: array[string]
```

That array typically contains one entry per tokenizer token ID.

Examples:

- **Qwen2** default vocabulary size: `151,936`
- **Llama 3** tokenizer: approximately `128K` tokens; common configs use `128,256`

Both exceed SafeGGUF's default `100,000` cap.

Thus a structurally valid GGUF can be rejected before tensor validation solely because its tokenizer is larger than an arbitrary safe-subset threshold.

### Impact

Primary impact:

- valid GGUF models may be rejected by default;
- operators may conclude the model is malformed or dangerous when it is not;
- SafeGGUF becomes impractical as a universal admission gate for modern model families;
- test confidence is distorted because synthetic fixtures do not represent real tokenizer scales.

This is a **false reject**, not a memory-safety bypass.

### Root cause

A semantic count cap is being used as a coarse anti-DoS control even though the project already has more appropriate global controls:

- scanned-byte budget;
- work-unit budget;
- allocation quota.

Variable-array element count and resource consumption are correlated, but not equivalent.

### Recommended remediation

#### Option A — Preferred: remove the low generic variable-element cap as the primary defense

For string arrays:

```text
accept count if:
  count <= high structural sanity cap
AND work budget can cover count
AND scanned byte budget can cover actual strings
AND allocation quota remains within policy
AND declared bytes remain in file bounds
```

A high structural sanity ceiling can remain to prevent absurd values, but it should be well above mainstream tokenizer sizes.

Example direction:

```zig
pub const Limits = struct {
    max_array_elements: u64 = 10_000_000,

    // Structural sanity ceiling, not primary DoS budget.
    max_variable_array_elements: u64 = 1_000_000,

    max_total_alloc_bytes: u64 = 128 * 1024 * 1024,
    max_work_units: u64 = 10_000_000,
    max_scanned_bytes: u64 = 256 * 1024 * 1024,
};
```

`1_000_000` is only an illustrative starting point. The final value should be derived from an actual model corpus.

#### Option B — Add policy profiles

Example:

```text
--limits-profile hardened
--limits-profile model-compatible
--limits-profile custom
```

Possible policy meaning:

```text
hardened:
    smaller tokenizer/array limits
    deployment explicitly accepts compatibility loss

model-compatible:
    supports current mainstream vocabulary sizes
    still bounded by work/byte/memory budgets
```

#### Option C — Allow explicit CLI overrides

For example:

```text
--max-variable-array-elements N
--max-array-elements N
--max-scanned-bytes N
--max-work-units N
--max-total-alloc-bytes N
```

If exposing these, reject:

- zero where nonsensical;
- parse overflows;
- contradictory values;
- values exceeding build-time hard ceilings if desired.

### Required tests

Add fixtures for at least:

```text
tokenizer array[string] length:
  99,999      PASS
  100,000     PASS
  100,001     behavior based on new policy
  128,256     PASS in model-compatible profile
  151,936     PASS in model-compatible profile
  250,000     expected policy result
  huge count  REJECT by budget/sanity limit
```

Also verify:

- scanned byte limit still rejects pathological total payload;
- work budget still rejects pathological count;
- allocation quota still works;
- valid tokenizer arrays do not require loading tensor payloads.

### Definition of Done

- [ ] Qwen2 GGUF from a pinned real-world corpus passes the intended profile.
- [ ] Llama 3 GGUF from a pinned real-world corpus passes the intended profile.
- [ ] A pathological million-element variable array still cannot bypass work/byte/memory budgets.
- [ ] CLI documents whether rejection is format invalidity or local policy/resource rejection.
- [ ] Tests prevent the 100k regression from returning.

---

## F-02 — P0 — Current “CVE regression corpus” has incorrect CVE mechanism mapping

### Severity

**Priority:** P0  
**Type:** Security assurance / evidence integrity  
**Confidence:** High

### Evidence in repository

`tests/negative_corpus.py` currently includes fixtures such as:

```text
cve-2024-25664-parse-metadata-string-past-eof.gguf
cve-2024-25665-int-overflow-dims-product.gguf
cve-2024-25665-int-overflow-nbytes.gguf
cve-2024-25668-types-invalid-tensor-type-43.gguf
```

The file itself correctly says these are **PoC-inspired class exemplars**, not byte-for-byte copies.

The problem is that the attached CVE identities imply that the fixture reproduces or meaningfully models that vulnerability mechanism.

### Published mechanism mapping

The widely cited Databricks GGUF research identifies the 2024 group as:

```text
CVE-2024-25664 — Heap Overflow #1: Unchecked KV Count
CVE-2024-25665 — Heap Overflow #2: Reading string types
CVE-2024-25666 — Heap Overflow #3: Tensor count unchecked
CVE-2024-25667 — Heap Overflow #4: User-supplied Array Elements
CVE-2024-25668 — Heap Overflow #5: Unpacking KV string type arrays
```

Current SafeGGUF mappings therefore do not accurately correspond:

| Fixture label | Current SafeGGUF mechanism | Expected historical mechanism |
|---|---|---|
| CVE-2024-25664 | string extends past EOF | unchecked metadata KV count/allocation |
| CVE-2024-25665 | tensor dimension/nbytes overflow | unsafe string-length allocation/read |
| CVE-2024-25668 | invalid tensor type ID 43 | unpacking string arrays |

### Why this matters

Security assurance requires traceability.

A regression test named after a CVE should answer:

> “Would this validator reject the same malformed condition or vulnerability trigger class that caused the published CVE?”

The current fixtures instead answer:

> “Does SafeGGUF reject some malformed input that belongs to a broadly security-relevant class?”

The latter is still useful, but it is not a CVE regression test.

### Impact

- documentation can overstate assurance;
- external reviewers may incorrectly infer direct protection against named vulnerabilities;
- future code changes can “pass CVE regression” without actually covering the historical mechanism;
- security claims become harder to audit.

### Recommended remediation

Split the corpus into two categories.

#### 1. True advisory/CVE regression fixtures

Naming:

```text
cve-2024-25664-<mechanism>.gguf
cve-2024-25665-<mechanism>.gguf
...
```

Each case must include metadata:

```json
{
  "id": "CVE-2024-25664",
  "source_url": "...",
  "source_title": "...",
  "affected_version_or_commit": "...",
  "patched_version_or_commit": "...",
  "mechanism": "...",
  "fixture_type": "reproduction|minimized-reproduction|mechanism-equivalent",
  "expected_safegguf_error": "...",
  "sha256": "..."
}
```

#### 2. Synthetic bug-class regression fixtures

Rename existing useful cases where provenance is not exact:

```text
synthetic-string-past-eof.gguf
synthetic-dimension-product-overflow.gguf
synthetic-invalid-tensor-type-43.gguf
synthetic-array-count-dos.gguf
```

Do not discard them.

### Add modern CVEs

At minimum add dedicated regressions for:

#### CVE-2025-53630

Cumulative tensor data size overflow in GGUF parsing.

Expected SafeGGUF protection path:

```text
compute tensor bytes
    ↓
checkedAlignUp
    ↓
checked cumulative offset/size
    ↓
REJECT on overflow
```

#### CVE-2026-27940

Bypass of CVE-2025-53630 fix involving final context memory size arithmetic.

SafeGGUF is not allocating the same downstream ggml context, so the test should clearly state what equivalent admission property it proves.

#### CVE-2026-33298

`ggml_nbytes()` dimension/stride arithmetic overflow can drastically underestimate tensor bytes.

This is especially aligned with SafeGGUF's purpose and should be a flagship regression.

Official advisory example uses a tensor shaped around:

```text
F32
[1024, 1024, 2^42 + 1, 1]
```

The SafeGGUF regression should demonstrate that checked byte-size logic rejects the condition.

### Definition of Done

- [ ] Every `cve-*` fixture has a verifiable primary source.
- [ ] Fixture mechanism matches the advisory mechanism.
- [ ] Synthetic cases no longer use CVE labels without direct provenance.
- [ ] Manifest stores source URL, affected/patched references and SHA-256.
- [ ] CVE-2025-53630, 2026-27940 and 2026-33298 are explicitly covered.
- [ ] README/security documentation distinguishes “CVE regression” from “bug-class exemplar”.

---

## F-03 — P0 — Ubuntu CI is red because the syscall benchmark gate is brittle

### Severity

**Priority:** P0  
**Type:** CI reliability / assurance pipeline integrity  
**Confidence:** High

### Observed CI state

At reviewed HEAD:

```text
commit:
158308eee14fe767a45bd60a7ffe8d731941665c
```

The Ubuntu job:

- format check: PASS;
- fixture generation: PASS;
- 62 tests: PASS;
- ReleaseSafe build: PASS;
- CLI integration: PASS;
- negative corpus: PASS;
- **resource benchmark: FAIL**;
- later upstream oracle / arithmetic oracle / type oracle / differential / mutation fuzz: SKIPPED.

The macOS job completed the full pipeline successfully.

### Failing benchmark

The 256 MiB scanned-string benchmark reported approximately:

```text
direct:
  read_syscalls ≈ 81,927

buffered:
  read_syscalls ≈ 4,355
```

So the cache clearly reduced syscalls by roughly an order of magnitude.

However, the test enforces:

```zig
const slides_bound = buffered.file_size / window_bytes + 16;
expect(sys <= slides_bound);
```

For a ~256 MiB file, that theoretical bound is near ~4.1k calls, while the actual count is ~4.35k.

Result: CI fails despite the cache obviously working.

### Root cause

The assertion assumes the number of backend reads will be almost exactly bounded by one 64 KiB slide per sequential file window.

That does not account robustly for:

- parser access patterns;
- boundary-crossing reads;
- repeated/overlapping cache windows;
- procfs accounting noise;
- other reads included in process-level `/proc/self/io` `syscr`;
- short-read/retry behavior;
- metadata layout causing extra cache slides.

The project is attempting to assert an implementation property using a process-global OS metric that is too indirect.

### Impact

- default branch is red;
- Linux differential/fuzz/oracle stages are skipped after the failure;
- contributors can lose trust in benchmark gates;
- release confidence is reduced;
- genuine regressions can be hidden among flaky/non-portable failures.

### Recommended remediation

#### Preferred: instrument backend reads directly

Create a test reader backend that counts actual `preadAll()` calls inside the SafeGGUF abstraction, rather than reading process-global syscall counters.

Concept:

```zig
const InstrumentedFileReader = struct {
    file: std.fs.File,
    file_size: u64,
    backend_reads: u64 = 0,
    backend_bytes: u64 = 0,

    fn pread(self: *InstrumentedFileReader, dest: []u8, offset: u64) !usize {
        self.backend_reads += 1;
        self.backend_bytes += dest.len;
        return self.file.preadAll(dest, offset);
    }
};
```

Then test invariants such as:

```text
buffered.backend_reads << direct.backend_reads
```

and:

```text
buffered.backend_reads <= conservative_access_pattern_bound
```

based on actual reader behavior rather than `/proc`.

#### Keep `/proc/self/io` only as telemetry

It can remain useful informational output:

```text
read_syscalls = observed process metric
```

but should not be the sole pass/fail gate.

#### Alternative interim fix

If instrumentation takes time, relax the hard bound and gate only on relative reduction:

```text
if direct >= 1000 reads:
    buffered < direct / 4
```

This is less exact but substantially more stable.

### CI sequencing improvement

Security assurance stages should not all disappear just because a performance benchmark fails.

Split jobs:

```text
core-tests
oracle-differential
fuzz-smoke
bench-regression
```

A benchmark failure should make CI red, but it should not prevent collecting evidence from the other independent jobs.

### Definition of Done

- [ ] Ubuntu CI is green on repeated runs.
- [ ] Cache regression gate measures SafeGGUF backend reads directly.
- [ ] Oracle/differential/fuzz jobs run even if benchmark job fails.
- [ ] Benchmark telemetry still records process syscall metrics when available.
- [ ] At least 10 repeated CI runs show no benchmark flake.

---

## F-04 — P1 — Missing real-world model corpus is creating compatibility blind spots

### Severity

**Priority:** P1  
**Type:** Compatibility assurance  
**Confidence:** High

### Current strengths

The repository has:

- hand-written fixtures;
- systematic generated boundary matrices;
- upstream differential testing;
- mutation fuzzing.

These are valuable for parser correctness.

### What they do not prove

They do not prove that SafeGGUF accepts real converter output from the current ecosystem.

A real-world model may include:

- large tokenizer arrays;
- unusual metadata key combinations;
- chat templates;
- sidecar types;
- architecture-specific metadata;
- large alignment values;
- different tensor ordering generated by conversion tools;
- metadata fields that synthetic test generators do not know about.

### Recommended corpus categories

Maintain a manifest rather than committing multi-GB models.

Suggested families:

```text
Llama 3 / Llama 3.x
Qwen2 / Qwen2.5
Mistral
Gemma / Gemma 2
Phi
DeepSeek family
embedding models
rerankers
mmproj sidecars
LoRA GGUF where applicable
vocab-only GGUF
small test GGUF generated by llama.cpp tooling
```

Manifest entry:

```json
{
  "id": "qwen2-small-q4",
  "url": "...",
  "sha256": "...",
  "size": 123456789,
  "license_note": "...",
  "expected": {
    "gguf-spec": "PASS",
    "llama-cpp": "PASS"
  },
  "tags": ["qwen2", "tokenizer>100k"]
}
```

### CI strategy

Do not download every large model per pull request.

Use tiers:

```text
PR smoke:
  tiny curated real-world fixtures

nightly:
  medium representative subset

weekly/manual:
  large/full compatibility corpus
```

### Definition of Done

- [ ] Manifest is committed.
- [ ] SHA-256 is verified before use.
- [ ] At least one model from each target family is covered.
- [ ] False-reject regressions fail CI.
- [ ] Corpus includes vocab >100k cases.

---

## F-05 — P1 — Fuzzing is not yet sustained coverage-guided fuzzing

### Severity

**Priority:** P1  
**Type:** Parser assurance  
**Confidence:** High

### Current implementation

`tests/fuzz_target.zig` exposes:

```zig
pub export fn LLVMFuzzerTestOneInput(...)
```

and validates each input across:

```text
gguf-spec × little
gguf-spec × big
llama-cpp × little
llama-cpp × big
```

with restricted limits.

This is good harness design.

The project also has mutation campaigns and persisted crash artifacts.

### Gap

The current nightly workflow itself acknowledges that Zig 0.13 does not provide the desired built-in libFuzzer/sancov setup being targeted. Therefore current campaigns are mutation-driven, not genuine feedback-driven exploration of new code paths.

### Why coverage guidance matters

Binary parsers frequently contain path combinations that random mutation reaches very inefficiently:

```text
valid header
+ valid metadata count
+ nested type path
+ exact boundary length
+ tensor descriptor
+ arithmetic edge
```

Coverage feedback makes it much more likely that mutations preserve enough structure to push execution deeper.

### Recommended paths

#### Option 1 — Upgrade fuzz toolchain separately

The production compiler can remain Zig 0.13 initially while fuzz CI uses a newer supported toolchain, provided behavior differences are understood.

#### Option 2 — AFL++

Build a stable C ABI fuzz target and use AFL++ instrumentation.

#### Option 3 — Clang/libFuzzer bridge

Expose the parser entry point through a C ABI and build only the harness using a compatible sanitizer/fuzzer toolchain.

### Minimum fuzz configuration

```text
ASan/UBSan where applicable
persistent corpus
coverage feedback
both profiles
endianness matrix
crash minimization
timeout/hang classification
OOM differentiation
artifact upload
commit/toolchain metadata
```

### Definition of Done

- [ ] Fuzzer reports coverage/corpus evolution.
- [ ] Corpus persists between nightly runs.
- [ ] New coverage is retained.
- [ ] Crash inputs are automatically minimized.
- [ ] 0 unexpected exits/panics/leaks in sustained campaign.
- [ ] Reproduction command is stored with artifact.

---

## F-06 — P1 — `validateOwned()` Result still depends on producing Validator state/address

### Severity

**Priority:** P1  
**Type:** API robustness / lifetime safety  
**Confidence:** Medium-High  
**Important:** This is a design/lifetime risk, not a demonstrated malicious-file exploit.

### Current API

`Validator` contains:

```zig
quota_alloc: limits.QuotaAllocator,
work_budget: limits.WorkBudget,
```

`QuotaAllocator.allocator()` returns a `std.mem.Allocator` whose context pointer is:

```zig
.ptr = self
```

`validateOwned()` returns roughly:

```zig
Result {
    .doc = ...,
    .alloc = self.quota_alloc.allocator(),
}
```

`Result.deinit()` later frees via that captured allocator.

### Why the name is potentially misleading

The result “owns” the document interface, but the allocator context remains tied to the live `QuotaAllocator` embedded inside the producing `Validator`.

The docs correctly warn:

- Validator must remain alive;
- Result must be deinitialized before Validator destruction;
- concurrent use is unsupported.

However, the result is not independent in the intuitive RAII sense.

### Additional concern: relocation/copy semantics

Because `Validator` is a value containing the allocator state, moving/copying/relocating the struct after capturing an allocator can be dangerous if an allocator pointer still refers to its previous address.

Whether a specific ordinary caller path triggers this depends on Zig value/lifetime usage, but this is exactly the kind of subtle contract that a production API should avoid requiring users to reason about.

### Recommended redesign

#### Option A — Heap-stable validation session

Allocate quota/session state separately:

```text
Validator
  ↓ owns/refers to
ValidationState*  (heap stable)
  - QuotaAllocator
  - WorkBudget
  - reference count / ownership state
```

A `Result` can retain that state until its document is freed.

#### Option B — Result owns an arena/session

For every validation:

```text
create per-validation arena/quota
parse
return Result {
    doc,
    owned_state
}
```

Then:

```zig
result.deinit();
```

requires no producing Validator lifetime.

#### Option C — Make API intentionally borrowed

If independent ownership is not desired, rename it to communicate borrowing, e.g.:

```text
validateBorrowed()
ValidationHandle
```

and prevent use after the session.

### Tests to add

Explicitly test:

```text
Validator copied/moved before Result.deinit
multiple simultaneously live Results
sequential validation with a prior Result still alive
deinit order
double deinit detection where practical
quota accounting with multiple live documents
```

### Definition of Done

Preferred:

- [ ] `Result.deinit()` does not require the original Validator object address to remain valid.
- [ ] Ownership/lifetime can be explained in one short paragraph.
- [ ] API misuse is difficult, not merely documented.
- [ ] relocation/copy tests exist.

---

## F-07 — P1 — Supply-chain assurance is incomplete

### Severity

**Priority:** P1  
**Type:** Release trust / artifact integrity  
**Confidence:** High

### Existing positive controls

- GitHub Actions are pinned by SHA.
- Zig version is pinned.
- Upstream ggml compatibility target is pinned.
- Release artifacts include SHA-256 checksums.
- Cross-platform release artifacts are produced in CI.

These are good fundamentals.

### Missing controls

The reviewed roadmap still lists as incomplete:

- artifact attestations;
- SLSA-style provenance;
- release signing;
- SBOM;
- richer `--version` provenance.

Reviewed HEAD was also reported by GitHub as unsigned.

### Why it matters

SafeGGUF itself becomes part of the trust root.

If an operator is relying on SafeGGUF to say:

```text
untrusted model → admitted/rejected
```

then substituting the validator binary defeats the gate.

### Recommended remediation

#### Release identity

Use a documented signing identity:

- Sigstore keyless signing, or
- organization-controlled signing key.

#### Artifact provenance

For each release publish:

```text
source commit
workflow identity
toolchain version
target triple
build mode
ggml compatibility target
artifact SHA-256
```

#### SBOM

SPDX or CycloneDX is sufficient. The project is small, so SBOM should be simple.

#### Version command

Recommended:

```text
safegguf 0.x.y
source_commit: ...
zig: 0.13.0
build_mode: ReleaseSafe
target: x86_64-linux-gnu
ggml_target: 0.23.0
ggml_commit: e91ded11...
```

### Definition of Done

- [ ] signed/attested release artifacts;
- [ ] provenance attached to release;
- [ ] SBOM attached;
- [ ] `--version` exposes build identity;
- [ ] verification instructions documented.

---

## F-08 — P2 — Zero-filled padding is incorrectly described as stricter than the GGUF specification

### Severity

**Priority:** P2  
**Type:** Documentation correctness  
**Confidence:** High

### Current description

The project describes zero-filled descriptor/alignment padding as a SafeGGUF-specific canonicalization rule stronger than the base specification.

### GGUF specification

The GGUF specification states that where padding is required, the file is padded with `0x00` bytes to the next alignment boundary.

Therefore the more accurate wording is:

> SafeGGUF explicitly enforces the specification's zero-padding requirement even when a particular upstream runtime may align past the bytes without validating their contents.

### Why correction matters

“Stricter than spec” and “enforces spec more strictly than upstream implementation” are materially different claims.

The latter is accurate and defensible.

### Definition of Done

- [ ] README updated.
- [ ] differential-test rationale updated.
- [ ] security docs updated.
- [ ] no claim remains that zero padding is invented solely as a SafeGGUF extension.

---

## F-09 — P2 — Pinned oracle is reproducible but does not detect upstream drift

### Severity

**Priority:** P2  
**Type:** Compatibility monitoring  
**Confidence:** High

### Current model

SafeGGUF intentionally pins:

```text
ggml 0.23.0 @ e91ded11...
```

This is correct for reproducibility.

### Gap

A pinned oracle cannot detect:

- new tensor types;
- loader semantic changes;
- new metadata handling;
- upstream security fixes;
- behavior divergence with the current ecosystem.

### Recommendation: two-oracle model

#### Oracle A — pinned, blocking

Purpose:

```text
reproducible compatibility target
```

Must remain stable and PR-blocking.

#### Oracle B — rolling current, canary

Purpose:

```text
detect ecosystem drift
```

Nightly only initially.

Report:

```text
new type IDs
new divergence
previous divergence removed
new upstream rejection
SafeGGUF false reject
SafeGGUF false accept relative to selected policy
```

### Definition of Done

- [ ] pinned oracle remains stable;
- [ ] current upstream canary runs nightly;
- [ ] drift report is saved;
- [ ] upstream changes do not silently invalidate compatibility claims.

---

## F-10 — P2 — Resource-budget documentation should not imply process-level hard limits

### Severity

**Priority:** P2  
**Type:** Documentation / operational security  
**Confidence:** High

### Current mechanism

`QuotaAllocator` tracks allocations performed through its wrapped allocator.

That does **not** strictly cap:

- total process RSS;
- file/page cache;
- stack;
- allocator metadata;
- unrelated library allocations;
- kernel buffers.

Similarly, `WorkBudget` tracks logical units chosen by SafeGGUF. It is not a CPU-instruction or wall-time sandbox.

### Recommended wording

Prefer:

```text
validator-managed live allocation quota
logical parser/validation work budget
validated/scanned-byte budget
```

Avoid language that can be interpreted as:

```text
process cannot exceed 128 MiB
CPU is hard-capped at N operations
```

### Deployment recommendation

For hostile multi-tenant uploads, run validation under OS/container limits too:

```text
cgroup/job-object memory limit
CPU quota/time limit
file-size limit
read-only filesystem where possible
seccomp/sandbox profile
```

---

## F-11 — P2 — Windows release artifacts are cross-built but not equivalently runtime-tested

### Severity

**Priority:** P2  
**Type:** Platform assurance  
**Confidence:** High

### Current pattern

CI testing matrix:

```text
Ubuntu
macOS
```

Release build includes:

```text
x86_64-linux
aarch64-linux
x86_64-macos
aarch64-macos
x86_64-windows
```

Cross-compilation proves that Windows code builds, not that it behaves correctly.

### Risks worth testing

- large file `stat()` behavior;
- pread/file I/O semantics;
- path handling;
- exit code behavior;
- >2 GiB sparse files;
- allocator behavior;
- console stdout/stderr JSON behavior.

### Recommended remediation

Add a Windows CI job that runs at least:

```text
unit tests
CLI tests
negative fixtures
small differential subset if oracle build is practical
```

---

## F-12 — P2 — PASS must not be interpreted as “the model is safe”

### Severity

**Priority:** P2  
**Type:** Security scope  
**Confidence:** High

### Correct guarantee

SafeGGUF can establish properties such as:

```text
file structurally matches selected safe subset
declared tensor arithmetic is bounded
descriptors do not overlap
metadata parsing stayed within configured limits
```

### What PASS cannot prove

A PASS does not prove:

- the model weights are benign;
- the model has no behavioral backdoor;
- the chat template is semantically safe;
- downstream architecture-specific code has no vulnerability;
- tokenizer processing is free of all bugs;
- runtime GPU kernels are safe;
- file contents cannot be changed after validation;
- the source/publisher is trusted.

The official `llama.cpp` security guidance similarly recommends isolating untrusted models.

### Recommended output wording

Consider adding a standard documentation statement:

> `PASS` means the file satisfies the selected SafeGGUF structural, arithmetic and resource-policy checks. It is not a trust or malware verdict for model behavior or downstream runtime code.

---

## F-13 — P2 — Version/release documentation can drift during rapid development

### Severity

**Priority:** P2  
**Type:** Release hygiene  
**Confidence:** High

### Observed state

At review time:

- repository HEAD contains a commit message identifying `v0.3.6` assurance work;
- published release remains `v0.3.5`;
- README release badge still showed v0.3.5.

This is not inherently wrong during development, but security documentation should always identify whether a claim refers to:

```text
latest tagged release
or
unreleased main
```

### Recommendation

Add generated build/version provenance and mark README sections:

```text
Released guarantees
Unreleased/main changes
```

---

# 7. Additional Observations

## 7.1 The project is very young and has changed rapidly

The commit history shows numerous important fixes in a short period, including fixes for:

- type-table correctness;
- false-PASS behavior;
- unchecked contiguous-layout overflow;
- trailing tensor-padding bounds;
- endian compatibility;
- public API alignment/division guards;
- work-budget accounting;
- fuzz persistence;
- validator lifecycle handling.

This has two interpretations:

### Positive

The maintainer responds quickly and is actively hardening the system.

### Risk

The code has not yet accumulated long-term stability evidence.

For security infrastructure, “many bugs fixed quickly” should not be confused with “few bugs remain”.

---

## 7.2 ReleaseSafe is the correct default direction

For this project, shipping a build mode that retains runtime safety checks is sensible.

Do not optimize toward maximum speed by switching production validation to unchecked release modes without a measured reason.

---

## 7.3 JSON diagnostics are useful for policy engines

Structured fields such as:

```text
status
profile
error_code
category
stage
tensor_index
tensor
offset
expected_offset
key
message
```

are valuable for:

- quarantine policy;
- observability;
- security analytics;
- triage.

Recommended next step: document a stable JSON schema/version.

Example:

```json
{
  "schema_version": 1,
  "status": "REJECT",
  "error_code": "E_TensorOutOfBounds",
  "category": "arithmetic",
  "stage": "structural"
}
```

Without schema versioning, future field changes can break automation.

---

# 8. Recommended Code-Level Remediation Sketches

The following are design sketches, not copy-paste patches.

---

## 8.1 Separate hard structural ceilings from resource budgets

Instead of:

```zig
if (elem_type == .string or elem_type == .array) {
    if (count > limit.max_variable_array_elements)
        return error.ResourceLimitExceeded;
}
```

move toward:

```zig
if (count > limit.max_variable_array_elements_hard)
    return error.ResourceLimitExceeded;

try work_budget.consume(variableElementCost(count));

// Actual string bytes continue to consume scanned-byte budget.
```

Possible structure:

```zig
pub const Limits = struct {
    // Format / structural ceilings
    max_tensors: u64 = 1_000_000,
    max_metadata_entries: u64 = 1_000_000,
    max_string_bytes: u64 = 65_536,
    max_tensor_name_bytes: u64 = 64,
    max_dimensions: u32 = 4,
    max_array_elements: u64 = 10_000_000,
    max_variable_array_elements_hard: u64 = 1_000_000,
    max_metadata_depth: u32 = 16,

    // Resource policy
    max_total_alloc_bytes: u64 = 128 * 1024 * 1024,
    max_work_units: u64 = 10_000_000,
    max_scanned_bytes: u64 = 256 * 1024 * 1024,
};
```

---

## 8.2 Distinguish format rejection from local resource-policy rejection

Today both can become exit `2`, which is reasonable operationally, but diagnostics should distinguish:

```text
format
compatibility
arithmetic
resource_policy
```

Example:

```json
{
  "status": "REJECT",
  "category": "resource",
  "policy": "max_variable_array_elements",
  "limit": 100000,
  "observed": 151936
}
```

This lets an operator know:

```text
“valid-looking model exceeded my local policy”
```

rather than:

```text
“file format is corrupt”
```

---

## 8.3 Stable `ValidationSession`

Suggested ownership direction:

```zig
pub const ValidationSession = struct {
    state: *State,

    const State = struct {
        quota: QuotaAllocator,
        work: WorkBudget,
        ...
    };
};
```

A result can own/reference a stable state allocation rather than an embedded movable struct.

---

## 8.4 Benchmark reader instrumentation

Introduce an interface-level counter:

```zig
pub const IOStats = struct {
    backend_read_calls: u64 = 0,
    backend_bytes: u64 = 0,
};
```

Allow `BufferedReader` tests to assert:

```text
backend_read_calls buffered << direct
```

No `/proc` dependency is necessary for correctness.

---

# 9. Test Plan After Remediation

## 9.1 Parser boundary matrix

| Field | Test values |
|---|---|
| tensor_count | 0, 1, max-1, max, max+1, UINT64_MAX |
| kv_count | 0, 1, max-1, max, max+1, UINT64_MAX |
| key length | 0, 1, 65535, 65536, 65537, UINT64_MAX |
| string length | 0, 1, cap, cap+1, EOF-1, EOF, EOF+1 |
| n_dims | 0..5, UINT32_MAX |
| dimensions | 0, 1, block-1, block, block+1, INT64_MAX±1, UINT64_MAX |
| tensor type | every active, removed slots, count, count+1, UINT32_MAX |
| alignment | 0, 1, 7, 8, 16, 24, 32, power-of-two large, overflow-adjacent |

---

## 9.2 Real tokenizer tests

Must include:

```text
32k vocabulary
64k vocabulary
100k vocabulary
128,256 vocabulary
151,936 vocabulary
>200k representative future case
```

For string arrays, vary:

```text
empty strings
short ASCII
multibyte UTF-8
4 KiB boundary splits
64 KiB maximum individual values
```

---

## 9.3 CVE matrix

Recommended table:

| Advisory | Regression needed | Expected SafeGGUF defense |
|---|---|---|
| CVE-2024-25664 | unchecked KV count | pre-allocation count/resource rejection |
| CVE-2024-25665 | unsafe string length/read | checked length + EOF + byte budget |
| CVE-2024-25666 | unchecked tensor count | pre-allocation tensor-count rejection |
| CVE-2024-25667 | user-controlled array elements | checked count/size/work budget |
| CVE-2024-25668 | string-array unpacking | bounded count + streaming checks |
| CVE-2025-53630 | cumulative tensor-size overflow | checked cumulative arithmetic |
| CVE-2026-27940 | mem-size overflow bypass | admission rejects impossible cumulative sizing |
| CVE-2026-33298 | tensor nbytes arithmetic overflow | checked product/block/type-size arithmetic |

Also consider coverage for relevant Talos GGUF parser CVEs as a separate tracked work item.

---

# 10. CI Architecture Recommendation

A better pipeline separates evidence-producing jobs.

```text
job: core
  fmt
  unit tests
  CLI tests
  negative corpus

job: upstream-oracle
  build pinned oracle
  type oracle
  arithmetic oracle
  differential matrix

job: fuzz-smoke
  deterministic corpus
  mutation campaign

job: bench
  resource benchmarks
  backend read-count assertions

job: platform-windows
  unit
  CLI
  negative fixtures

job: nightly-real-corpus
  download SHA-pinned GGUF corpus
  compatibility validation

job: nightly-fuzz
  coverage-guided campaign
```

Benefits:

- one benchmark failure does not suppress differential evidence;
- failures are easier to classify;
- security assurance stays observable even if performance gates regress.

---

# 11. Suggested Remediation Sequence

## Phase 0 — Restore trustworthy baseline

Do first.

### P0.1 Fix Ubuntu benchmark gate

Goal:

```text
main green
```

### P0.2 Correct CVE fixture naming/provenance

Goal:

```text
security evidence says exactly what it proves
```

### P0.3 Fix variable-array compatibility limit

Goal:

```text
modern valid tokenizer arrays are not rejected by default intended profile
```

Do not publish a “hardened” release before these three are addressed.

---

## Phase 1 — Real compatibility evidence

### P1.1 Add real-world corpus manifest

Include Qwen2 and Llama 3 immediately because they exercise >100k tokenizer arrays.

### P1.2 Add modern upstream CVE regressions

Especially:

```text
CVE-2025-53630
CVE-2026-27940
CVE-2026-33298
```

### P1.3 Add current upstream canary

Keep it non-blocking initially.

---

## Phase 2 — Parser assurance

### P2.1 Coverage-guided fuzzing

Persistent nightly campaign.

### P2.2 Expand malformed corpus

Feed minimized fuzzer discoveries back into deterministic regression tests.

This creates the desirable loop:

```text
fuzzer discovery
    ↓
minimize
    ↓
root cause
    ↓
fix
    ↓
deterministic regression fixture
```

---

## Phase 3 — API and release hardening

### P3.1 Redesign owned result/session lifetime

Make ownership mechanically safe.

### P3.2 Add schema version to JSON

Protect integrations.

### P3.3 Signed release + SBOM + provenance

Make SafeGGUF itself verifiable as part of the trust chain.

---

# 12. Proposed GitHub Issue Breakdown

These can be opened almost directly.

## Issue 1 — P0: Raise/decouple variable-array limits to support modern tokenizer vocabularies

**Problem:** current 100k string/array cap rejects Qwen2/Llama 3 tokenizer sizes.

**Acceptance:**

- real Qwen2 fixture passes model-compatible policy;
- real Llama 3 fixture passes;
- abuse remains bounded by work/scan/allocation budgets.

---

## Issue 2 — P0: Correct CVE corpus provenance and fixture naming

**Problem:** current CVE names do not correspond to actual published mechanisms.

**Acceptance:**

- `cve-*` means traceable advisory regression;
- synthetic fixtures renamed;
- manifest includes primary source.

---

## Issue 3 — P0: Replace procfs syscall hard gate with reader-backend instrumentation

**Problem:** Linux benchmark false fails despite effective caching.

**Acceptance:**

- repeated Ubuntu runs green;
- backend read regression remains measurable.

---

## Issue 4 — P1: Build real-world GGUF compatibility corpus

**Acceptance:**

- model-family manifest;
- SHA verification;
- nightly compatibility run.

---

## Issue 5 — P1: Add coverage-guided fuzz campaign

**Acceptance:**

- feedback-driven coverage;
- persistent corpus;
- auto-minimized crash artifacts.

---

## Issue 6 — P1: Make Result ownership independent of Validator relocation/lifetime

**Acceptance:**

- result owns stable allocation state;
- no hidden dependency on producing object address.

---

## Issue 7 — P1: Add true CVE-2025/2026 regression fixtures

**Acceptance:**

- 53630;
- 27940;
- 33298;
- documented expected rejection paths.

---

## Issue 8 — P1: Add release signing, attestation and SBOM

---

## Issue 9 — P2: Add rolling upstream compatibility canary

---

## Issue 10 — P2: Add Windows runtime CI

---

## Issue 11 — P2: Correct zero-padding specification wording

---

## Issue 12 — P2: Document precise PASS semantics and resource-budget scope

---

# 13. Security Claim Language Recommended for README

Suggested wording:

> SafeGGUF is a resource-bounded structural and arithmetic pre-admission validator for GGUF files. A PASS means that the file satisfies the selected SafeGGUF format/profile invariants and configured resource policies. A PASS does not establish that model weights, metadata semantics, chat templates, downstream inference code, or model behavior are trustworthy. Untrusted models should still be loaded and executed in an appropriately isolated runtime.

For compatibility profile:

> The `llama-cpp` profile is a SafeGGUF compatibility/safety subset derived from a pinned `ggml` target. It does not claim behavioral equivalence with every current or historical llama.cpp release.

For allocation:

> `max_total_alloc_bytes` bounds validator-managed live allocations routed through SafeGGUF's quota allocator. It is not a hard operating-system RSS limit.

---

# 14. Security Invariants Worth Making Explicit in Contributor Documentation

Recommended invariants:

1. **No attacker-controlled integer addition/multiplication without checked arithmetic when the result affects memory size, offset, index or loop bounds.**

2. **No allocation based on a file-declared count before structural/resource validation.**

3. **Every file read must be bounded by the declared/stat file size through the Reader abstraction.**

4. **Every unbounded traversal must charge a finite resource budget.**

5. **Variable-sized string validation must charge scanned bytes.**

6. **No tensor byte range may overflow `u64`, exceed file size or overlap another accepted tensor range.**

7. **Compatibility divergence from the pinned upstream target must be explicit and tested.**

8. **Every security advisory fixture must have traceable provenance.**

9. **Every fuzz-discovered crash must become a deterministic regression case after triage.**

10. **Release claims must distinguish tagged release behavior from unreleased `main`.**

---

# 15. Production Deployment Guidance

Even after the proposed fixes, recommended deployment is defense-in-depth.

## 15.1 Ingestion

```text
receive file
→ enforce maximum upload/file size
→ write to temporary non-executable storage
→ calculate SHA-256/BLAKE3
```

## 15.2 Validation

```text
run SafeGGUF in isolated process/container
→ CPU limit
→ memory limit
→ wall-clock timeout
→ no network
→ read-only input
```

## 15.3 Admission

Only after PASS:

```text
record:
  digest
  SafeGGUF version
  source commit
  profile
  limits
  validation output
```

Then promote the exact bytes to immutable/CAS storage.

## 15.4 Runtime

Inference runtime should read the same immutable object/digest.

Do not:

```text
validate /tmp/model.gguf
then later load a mutable path with same filename
```

That leaves a TOCTOU gap.

---

# 16. Final Assessment

SafeGGUF is solving the correct class of problem and its core implementation demonstrates credible security engineering:

- checked arithmetic is pervasive in the important tensor paths;
- bounds checks are centralized;
- metadata traversal is resource-aware;
- tensor ranges are validated;
- upstream behavior is tested through a compiled oracle;
- CI/release tooling is more disciplined than typical early-stage utilities.

The project should therefore **not** be dismissed as security theater.

At the same time, the current assurance story is ahead of the practical compatibility and release evidence.

The highest-value work is not a rewrite. It is to close a small set of high-impact gaps:

```text
1. fix 100k tokenizer-array false rejects
2. correct CVE provenance
3. restore green Linux CI
4. establish real-world model corpus
5. enable true coverage-guided fuzzing
6. harden Result/session lifetime
7. sign and attest releases
```

If these items are completed with deterministic acceptance tests, SafeGGUF could reasonably move from:

```text
pre-production security utility
```

toward:

```text
credible production defense-in-depth admission component
```

The appropriate conclusion at the reviewed snapshot is:

> **Promising and technically sound in its core security design, but not yet sufficiently validated, compatible and operationally mature to be treated as a production-grade standalone trust boundary.**

---

# 17. Source / Evidence Index

## SafeGGUF repository

- Repository  
  https://github.com/BrianNguyen29/SafeGGUF

- README  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/README.md

- Security policy  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/SECURITY.md

- Parser  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/gguf/parser.zig

- Metadata parser  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/gguf/metadata.zig

- Limits / QuotaAllocator / WorkBudget  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/gguf/limits.zig

- Reader  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/gguf/reader.zig

- GGML type traits  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/gguf/types.zig

- Arithmetic validation  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/validate/arithmetic.zig

- Structural validation  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/validate/structural.zig

- Validator / Result API  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/validate/validator.zig

- CLI  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/src/main.zig

- CI  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/.github/workflows/ci.yml

- Nightly fuzz workflow  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/.github/workflows/nightly.yml

- Differential harness  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/tests/differential.py

- Negative corpus  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/tests/negative_corpus.py

- Fuzz target  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/tests/fuzz_target.zig

- Resource benchmark  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/tests/bench_scales.zig

- Assurance roadmap  
  https://github.com/BrianNguyen29/SafeGGUF/blob/main/docs/assurance-roadmap-issues.md

---

## GGUF / ggml specification and pinned target

- GGUF specification  
  https://github.com/ggml-org/ggml/blob/master/docs/gguf.md

- Pinned ggml header at SafeGGUF target commit  
  https://github.com/ggml-org/ggml/blob/e91ded11bdcd78c42f9c8d3978ff6686eb4c1226/include/ggml.h

- Current gguf header  
  https://github.com/ggml-org/ggml/blob/master/include/gguf.h

---

## Official / published security references

- llama.cpp security policy and advisories  
  https://github.com/ggml-org/llama.cpp/security

- CVE-2025-53630 / GHSA-vgg9-87g3-85w8  
  https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-vgg9-87g3-85w8

- CVE-2026-27940 / GHSA-3p4r-fq3f-q74v  
  https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v

- CVE-2026-33298 / GHSA-96jg-mvhq-q7q7  
  https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-96jg-mvhq-q7q7

- Databricks — GGML GGUF File Format Vulnerabilities  
  https://www.databricks.com/blog/ggml-gguf-file-format-vulnerabilities

---

## Tokenizer compatibility evidence

- GGUF `tokenizer.ggml.tokens: array[string]` specification  
  https://github.com/ggml-org/ggml/blob/master/docs/gguf.md

- Hugging Face Transformers Qwen2 documentation (`vocab_size` default `151936`)  
  https://huggingface.co/docs/transformers/model_doc/qwen2

- Qwen2 model config example (`vocab_size: 151936`)  
  https://huggingface.co/Qwen/Qwen2-0.5B/blob/main/config.json

- Meta Llama 3 model card (128K-token vocabulary)  
  https://github.com/meta-llama/llama3/blob/main/MODEL_CARD.md

---

# 18. Review Caveats

This document is a source-level and project-assurance review, not a formal certification.

It does **not** claim:

- exhaustive proof of memory safety;
- formal verification;
- complete vulnerability discovery;
- exploitability of every design concern described;
- compatibility with every GGUF producer/runtime;
- that a PASS model is behaviorally trustworthy.

Findings explicitly marked as API/design risks should be treated differently from confirmed parser failures.

For a production security certification effort, follow this review with:

```text
independent manual code audit
coverage-guided fuzz campaign
sanitizer runs
real model corpus
platform-specific testing
release provenance verification
threat-model review in target deployment architecture
```

---

## End of report
