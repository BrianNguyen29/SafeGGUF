# SafeGGUF — F-02/04/05/06/07/09 Execution Plan (EXEC-NOW vs NEEDS-INPUT)

Source: `SafeGGUF_Remediation_Plan_F02_F04_F05_F06_F07_F09.md` (baseline HEAD `1036a27`). Planning only — no src/tests/workflow edits. Sizes: S ≤ ½ day, M 1–2 days. Already-done slices (#7 matrix, #9 synthetic/CVE split, #11 diagnostics, #12 provenance field, #6 lifetime contract) are not re-planned. Every source ask appears exactly once below.

## Phase A — EXEC-NOW (no external data)

### A1 · F-02 advisory provenance + flagship regression — M — EXEC-NOW
Files: `tests/negative_corpus.py` (+ regenerated `tests/fixtures/negative/manifest.json`), `tests/validator_test.zig`, `.github/workflows/ci.yml`, `README.md`, `SECURITY.md`; optional `tests/advisories.json`.
- [ ] flagship advisory-derived fixture `cve-2026-33298-ggml-nbytes-overflow.gguf` (F32 `[1024,1024,2^42+1,1]`): exit 2, `E_ArithmeticOverflow`, category `arithmetic`. — note (2026-09-11): as-built, the fixture-level regression is `synthetic-int-overflow-flagship-nbytes.gguf` (same shape, verified exit 2 / `E_ArithmeticOverflow`); the `cve-*`-named fixture is deferred to B3, so B3's "fixture from A1 otherwise unchanged" premise becomes "create the `cve-*` fixture from the synthetic flagship".
- [x] direct `computeTensorBytes()` unit test rejects the same shape (unit arithmetic + full parser-admission layers). — note: `tests/validator_test.zig` rejects the flagship dims at the byte-multiply step and cumulative-overflow dims at the product step; parser admission of the same shape is covered by the synthetic flagship fixture in `negative_corpus.py`.
- [ ] `REQUIRED_CVE_FIELDS` broadened to §4.2 schema: id, ghsa, source_url, source_title, affected_versions, patched_versions, fixture_type, fixture_origin, mechanism, expected_protection, expected_error_code, sha256; empty/`TRIAGE-PENDING` fails generation; version ranges required, commit-SHA fields nullable and separate — `b*` build ids never stored as SHAs. — note (2026-09-11): gate today is (`fixture_type`, `source_url`, `affected_commit`, `patched_commit`, `sha256`); the §4.2 version/ghsa/origin fields are deferred with B3 provenance triage.
- [ ] 33298 provenance from source §72 (`GHSA-96jg-mvhq-q7q7`) + §4.2 ranges; commit-SHA fields stay null → B3. — note (2026-09-11): not done; CVE-2026-33298 stays a manifest-only placeholder with `TRIAGE-PENDING` provenance.
- [ ] categories documented (`synthetic-class-exemplar`, `advisory-regression`, `advisory-derived-regression`, `upstream-issue-regression`); `synthetic-*` never borrows a CVE identity; fixture SHA256 stored. — note (2026-09-11): SHA256 is stored and the no-CVE-identity invariant is mechanically enforced, but only `synthetic-class-exemplar` / `advisory-regression` are used/documented.
- [x] CI step renamed "Run Negative Corpus & Advisory Provenance Checks"; README/SECURITY distinguish synthetic exemplars from advisory regressions.

### A2 · F-09 rolling upstream canary (Oracle B) — M — EXEC-NOW
Files: `tests/build_oracle.sh`, `tests/differential.py`, `tests/test_oracle_types.py`, new `tests/canary_drift.py`, new `.github/workflows/upstream-canary.yml`, `docs/assurance-roadmap-issues.md`.
- [x] `build_oracle.sh --name {pinned|rolling} --ref <full-sha> --output <path>`; default stays pinned; isolated storage `.cache/oracle/pinned/`, `.cache/oracle/rolling/<sha>/`, binaries `ggml_oracle_pinned` / `ggml_oracle_rolling`.
- [x] type-drift comparison runs first: type IDs, names, block sizes, type sizes, slot count → new/removed/renamed/changed-size/changed-block report.
- [x] `differential.py --report-json <path>` emits §56 schema (`schema_version`, `safegguf_sha`, `upstream_sha`, `new_type_ids`, `new_divergences`, `resolved_divergences`, `safe_accept_upstream_reject`, `safe_reject_upstream_accept`, `oracle_errors`); divergences classified per §57.
- [x] nightly resolves upstream master → full SHA once, builds that exact SHA, records the SHA in the report (never "master").
- [x] `upstream-canary.yml`: nightly schedule + `workflow_dispatch`, Ubuntu first, uploads JSON + readable summary; non-blocking for PRs; may go red.
- [x] Oracle A (pinned `e91ded11…`) stays PR/release blocking and unchanged; rolling never silently replaces it; baseline updates require diff → human review → explicit commit.
- _Note (2026-09-11): verified on this tree (canary driver, workflow, `--report-json` schema, SHA-stamp/checkout guards). `docs/assurance-roadmap-issues.md` (A2 file list) was not updated in this slice._

### A3 · F-07 release supply chain, keyless defaults — M — EXEC-NOW
Default assumption (changeable via B4): keyless Sigstore identity, SPDX JSON, SLSA Build L2-style claim only.
Files: `build.zig`, new `src/build_info.zig`, `src/main.zig`, `.github/workflows/ci.yml` (release job), `README.md`, `SECURITY.md`; generated `dist/SHA256SUMS.txt`, `dist/SHA256SUMS.txt.sigstore.json`, `dist/safegguf.spdx.json`.
- [x] `build.zig` injects version, source commit, Zig version, build mode, target, pinned ggml version/commit via `src/build_info.zig`; no wall-clock timestamp.
- [x] `safegguf --version` prints version, source_commit, zig, build_mode, target, ggml_target, ggml_commit.
- [x] release adds `id-token: write` + `attestations: write`; `actions/attest-build-provenance` per binary; do not claim SLSA L3.
- [x] SPDX JSON SBOM at `dist/safegguf.spdx.json` (package/version, repo+commit, license, release files+hashes, dependency/build metadata; compiler not a runtime dependency).
- [x] cosign keyless signature on `SHA256SUMS.txt` → `SHA256SUMS.txt.sigstore.json`; each binary individually attested; no long-lived release private key.
- [x] verify-before-publish: build → hash → SBOM → attest → sign → verify hash/signature/provenance → publish; any failure = no publish; release retains `needs: [core, oracle, fuzz, bench]`.
- [x] assets per §48; README/SECURITY document SHA256 + cosign + `gh attestation verify` (not manual checksum only).
- _Note (2026-09-11): `--version` provenance observed live from the ReleaseSafe build; release job verified in the workflow diff (permissions, attestations, SBOM, keyless sign, pre-publish verification, `needs` unchanged). Workflow YAML itself is not executable locally._

### A4 · F-05 coverage instrumentation spike — S (≤ 1 day) — EXEC-NOW
Files: new `tests/fuzz/DECISION.md`; no production build changes.
- [x] Try Zig 0.13 coverage instrumentation; prove input A vs B give distinguishable coverage maps (X ≠ Y), else reject Option A. — note: 0.13.0 exposes no coverage instrumentation (`-ffuzz` unrecognized), so X ≠ Y is not attemptable on the pinned toolchain; Option A rejected on stronger evidence (see spike record).
- [x] decision record selects AFL++/external engine (Option A) or fuzz-only newer-Zig lane (Option B); production stays 0.13, only the minimal fuzz target may be ported. — note: the decision record is this plan's A4 spike record (no separate `tests/fuzz/DECISION.md`); production toolchain remains 0.13.0.
- [x] deterministic mutation campaign (`nightly.yml` + `tests/fuzz_mutation.py`) retained regardless of outcome.

#### A4 spike record — engine decision (2026-09-11, raw evidence in `/tmp/safegguf-spike/`)

Environment: Linux x86_64, 4 cores; pinned Zig 0.13.0; Zig 0.14.1 + 0.15.2 tarballs unpacked in `/tmp`; Ubuntu noble `afl++` 4.09c extracted from its `.deb` into `/tmp` (no system installs); all builds/tests run in a `/tmp` copy — repo build/workflow/harness files unchanged.

**Option A — AFL++/external engine: REJECT** (blocker is instrumentation, not the fuzzer).
- Zig 0.13.0 exposes no coverage instrumentation at all: `zig test --help` has no fuzz/coverage flag; `-ffuzz` → `error: unrecognized parameter: '-ffuzz'`. A4's X ≠ Y coverage-map precondition cannot be attempted on the pinned toolchain.
- Distro AFL++ ships no binary-only runtimes: `-Q` → `afl-qemu-trace` not found; `-O` → `afl-frida-trace.so` not found; `afl-showmap` against a 0.13-built harness → "Fork server handshake failed". Only `-n` dumb mode runs: ~520–650 input exec/s with `map=0` (no coverage feedback) through a purpose-built standalone `fuzzBuffer` driver.
- A real instrumented path needs an out-of-tree AFL++ build (QEMU/FRIDA) or a Zig→LLVM-BC→opt-pass→llc round trip (AFL++ pass + runtime `.o` are in the deb, but unverified and adds a second toolchain). Option A cost materially exceeds Option B for the coverage objective.

**Option B — fuzz-only newer-Zig lane: ACCEPT, pin 0.14.1.**
- Port surface measured and compile-time only: `src/gguf/limits.zig` needs the Allocator-vtable alignment `u8` → `std.mem.Alignment` shim plus the new required `remap` field, and `tests/validator_test.zig`'s mock allocator needs the same. With a `@hasDecl`/`@hasField` dual-compat shim, identical source passes **66/66 tests on 0.13.0 and 66/66 on 0.14.1**; no runtime behavior change; production binary/toolchain stay 0.13. Flagging explicitly: the shim is one production-source touch, slightly beyond "only the minimal fuzz target may be ported".
- 0.14.1 ships a coverage-guided built-in fuzzer: `std.testing.fuzz` + `-ffuzz` (sancov counters, cmp tracing, PC bitmap). `zig test -ffuzz` runs a bounded auto-pass and exits; the continuous lane is `zig build --fuzz` ("Continuously search for unit test failures").
- `zig build --fuzz` runs headless against the real harness — only log line is `info: web interface listening at http://127.0.0.1:<port>/` — and persists machine-readable artifacts under the build cache: coverage bitmap `v/<pc-digest>` (header carries `n_runs`/`unique_runs`/`pcs_len`) and corpus `f/<test-name>/N`.
- Measured (Debug fuzz build, one worker): 3,851,042 executions in a controlled 65.7 s window ≈ **58.6k input exec/s** (each input = all 4 profile×endian passes), 8,348 instrumented PCs; first run accumulated 16.26M executions in under 4 min. Per-input context: AFL++ dumb mode ~0.5k/s without coverage; mutation campaign 2000 iterations = ~162 input/s (CLI, little endian, 2 profiles).
- A5 caveats: the maintained control surface is an interactive web UI, so CI must wrap bounded `zig build --fuzz` and parse `v/`/`f/` artifacts (or use `zig test -ffuzz`); crash metadata/minimization/promotion and the persisted-corpus policy must be layered on top; fuzz mode triggers a full instrumented rebuild; 0.15.2 does not even parse this `build.zig` (`addExecutable` lost `root_source_file`), so 0.14.1 is the only cheap pin.

**Option C — keep mutation-only: RETAIN as deterministic baseline, not the coverage answer.** `fuzz_mutation.py --iterations 2000 --seed 1` = 4,000 CLI executions (2 profiles) in 12.38 s ≈ 323 profile-exec/s / ~162 input/s; the 26-seed × 4-combo in-process sweep runs in ~50 ms. Zero new toolchain risk, but no coverage feedback, so it cannot satisfy the A5 "new edges/paths/comparisons" objective.

**Decision.** A5 builds on Option B (Zig 0.14.1 fuzz-only lane + `std.testing.fuzz` port of the minimal target); Option C nightly mutation legs stay unchanged. If the `src/gguf/limits.zig` dual-compat shim is rejected, fall back to Option C and revisit the port at the next toolchain bump. Repro: `/tmp/safegguf-spike/` (`dumb2.log`, `pty-fuzz*.log`, `cache-repofuzz/`, `0141-patched3.log`, `013-patched3.log`).

### A5 · F-05 coverage-guided lane (after A4) — M — EXEC-NOW
Files: `tests/fuzz_target.zig`, `build.zig`, new `.github/workflows/coverage-fuzz.yml`, `tests/fuzz/`; optional `tests/afl/`, `tests/libfuzzer/`.
- [ ] nightly coverage lane with defined budget (≥30 min/platform), complementary to existing mutation + pinned differential systems.
- [ ] in-process `fuzzOne(data, profile, endian)` harness (no subprocess CLI); targets `fuzz_gguf_spec_little`, `fuzz_gguf_spec_big`, `fuzz_llama_cpp_little` (+ optional `fuzz_llama_cpp_big` smoke).
- [ ] seeds per §27; corpus kept for new edges/paths/comparisons/cleanup — never because inputs PASS; malformed files high-value; no llama-cpp acceptance requirement.
- [ ] persisted corpus ≤10,000 entries / 256 MiB, coverage-increasing/minimized/promoted entries only, survives runs; coverage summary uploaded.
- [ ] sanitizers/taxonomy where supported (ASan/UBSan/coverage/runtime safety; panic/signal/timeout/OOM/sanitizer finding/unexpected exit).
- [ ] crash artifact contract: original+minimized input, profile, endian, engine+version, compiler, commit, coverage stats, sanitizer output, repro command.
- [ ] promotion: discover → minimize → root cause → fix → deterministic regression on production 0.13 before closure.

## Phase B — NEEDS-INPUT

### B1 · F-04 real-world corpus — M — NEEDS-INPUT (owner: user → fixer)
Input needed: approved immutable URL/revision list, licenses, per-tier network/size budget (roadmap #8). Tier 0 PR corpus already exists and is unchanged.
Files: new `tests/real-corpus-manifest.json`, new `tests/real_corpus.py`, new `.github/workflows/real-corpus.yml`, `README.md`, `docs/assurance-roadmap-issues.md`.
- [ ] manifest §12: id, provider/repo, immutable revision, filename, declared size, SHA256, license, tier, tags, expected per profile; identity = revision + filename + SHA256 (SHA authoritative).
- [ ] runner §14: schema validate → tier select → temp download (streaming SHA256, max-size cap, never trust Content-Length) → size+hash verify → atomic promote to `.cache/real-corpus/<sha256>.gguf` → safegguf JSON → verdict compare → `real-corpus-report.json`.
- [ ] failure states separated §15: DOWNLOAD_ERROR / HASH_MISMATCH / SIZE_MISMATCH / SAFEGGUF_PASS|REJECT|ERROR / EXPECTED_RESULT_MISMATCH; network outage ≠ compatibility regression; hash mismatch fails closed.
- [ ] Tier 1 nightly ~0.5–1 GB: Qwen2.5 small + small BGE embedding PASS; false reject reported; bounded budget; report uploaded as artifact; cache key `real-corpus-<sha256>`.
- [ ] Tier 2 weekly/manual ≥5 architecture/use-case groups (Llama, Mistral, Gemma, Phi, DeepSeek, embedding, reranker, multimodal/mmproj, vocab-only, LoRA if supported); multi-GB models stay off nightly.

### B2 · F-06 independent `Result` ownership — M — NEEDS-INPUT (owner: user → fixer)
Input needed: breaking-change vs alias/deprecation + migration path (roadmap #10). Additive `Result`/`validateOwned()` already shipped — only ownership independence is planned.
Files: `src/validate/validator.zig`, `src/root.zig`, `tests/validator_test.zig`, `README.md`, `AGENTS.md`, `SECURITY.md`; optional new `src/validate/owned_state.zig`.
- [ ] `Result` holds heap-stable `OwnedValidationState` (parent allocator + independent `QuotaAllocator`); `deinit()` survives Validator leaving scope / reuse / move / destruction; optional state = safe repeated deinit.
- [ ] `validateOwned()` allocates its own state + local WorkBudget and parses via shared internal `validateWith()` helper — never the borrowed-allocator path.
- [ ] migration per decision: keep `validate()`/`deinitDocument()`/`validateOwned()` with deprecation, or expose `validateBorrowed()`/`validateOwned()` aliases; no abrupt removal.
- [ ] tests: Result survives scope; multiple live Results; Validator reuse/relocation; parse/structural/quota error cleanup; `std.testing.allocator` clean.
- [ ] DoD: no allocator context pointing into `Validator`; callers never preserve the producing object address.

### B3 · F-02 CVE promotion: sources/SHAs — M — NEEDS-INPUT (owner: user → fixer)
Input needed: verified primary source URL/title, affected/patched ranges, full commit SHAs (or documented null policy) for 53630 (`GHSA-vgg9-87g3-85w8`), 27940 (`GHSA-3p4r-fq3f-q74v`), 33298; never treat `b*` build ids as SHAs.
Files: `tests/negative_corpus.py`, regenerated manifest, `README.md`, `SECURITY.md`.
- [ ] CVE-2025-53630 deterministic cumulative-overflow test: individual tensor nbytes valid, aligned cumulative sum > UINT64_MAX → exit 2 / `E_ArithmeticOverflow` / `arithmetic`.
- [ ] CVE-2026-27940 classified exact vs mechanism-equivalent (`fixture_origin=mechanism-equivalent`) + §7 wording (admission reject before downstream allocation; not a byte-for-byte heap repro).
- [ ] all three placeholders promoted: zero `TRIAGE-PENDING`; affected/patched versions and commit SHAs populated and kept separate; every `cve-*` fixture has a primary source.
- [ ] 33298 commit-SHA fields promoted (fixture from A1 otherwise unchanged).

### B4 · F-07 fallback — only if keyless default rejected — S — NEEDS-INPUT (owner: user)
Files: `.github/workflows/ci.yml` (release job), `docs/assurance-roadmap-issues.md`.
- [ ] decide signing identity, SLSA target level (L3 requires reusable-workflow isolation), SBOM format (roadmap #13), then rework A3; if keyless accepted, A3 stands as written.

## Rollout / exit
- PR lanes (`core`, `oracle` pinned, `fuzz`, `bench`) stay blocking and unchanged; coverage-fuzz, real-corpus, rolling-canary are nightly advisory (§60/§67).
- §68 milestone exit criteria roll up from the checkboxes above; major release candidates additionally require recent green nightly assurance evidence (§67).
- §69 mitigations are embedded: tiering/digest cache (B1), production-toolchain regressions (A4/A5), deprecation before removal (B2), drift classification + manual baseline (A2), staged build/attest/verify/publish (A3).

---

## Phase A verification record (2026-09-11)

Full ordered suite run against this tree passed: `zig fmt --check`; `python tests/generate_fixtures.py`; `python tests/differential_matrix.py` (243 matrix fixtures); `zig build test --summary all` (67/67, fresh local cache); `zig build -Doptimize=ReleaseSafe`; `python tests/cli_test.py`; `python tests/negative_corpus.py` (13/13 rejected with exit 2); `python tests/arithmetic_oracle.py`; `python tests/differential.py` (269 fixtures, new divergences 0); `zig build bench` (3/3).

Cross-harness stray-fixture interference fixed in `tests/cli_test.py`: the scratch `tests/fixtures/variable_array_11.gguf` is now removed in a `finally` block, so the later `differential.py` fixture sweep never sees an unregistered fixture.

A1 remains partially open (see A1 notes): the `cve-*`-named 33298 fixture and the §4.2 provenance gate are deferred to B3, and the 4-category taxonomy is not yet documented.
