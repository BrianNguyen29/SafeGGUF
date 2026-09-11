# SafeGGUF — Deep-Review Fix Plan (F-01…F-13)

Source: `SafeGGUF_Deep_Security_Review_and_Remediation_Plan.md`, reviewed HEAD `158308e` (2026-09-11).
Tracking: this file only — no GitHub issues. Work already owned by `docs/assurance-roadmap-issues.md` is listed under **Already tracked** and is not re-planned.
Sizes: S ≈ <½ day, M ≈ 1–2 days. `[ ]` = acceptance checkbox.

## Phase 0 — P0: restore trustworthy baseline

### F-01 — variable-array cap false-rejects modern tokenizers — M — NEEDS-USER-DECISION
Recommendation: **A + C** — raise the generic cap to a corpus-derived structural sanity ceiling (~1,000,000) and add explicit CLI overrides for the five limits. Rationale: the element-count cap is only a sanity bound; `max_work_units` / `max_scanned_bytes` / `max_total_alloc_bytes` remain the real DoS bound, so raising it does not open a memory/CPU bypass. Option B (limits profiles) is deferred unless the user prefers presets over flags.
Files: `src/gguf/limits.zig`, `src/gguf/metadata.zig` (only if the count check moves), `src/main.zig` (flags; reject zero/overflow/contradictory values), `tests/generate_fixtures.py`, `tests/validator_test.zig`, `tests/cli_test.py`, `README.md`, `AGENTS.md`.
Boundary tests (tokenizer `array[string]` length): 99,999 PASS · 100,000 PASS · 100,001 per new policy · 128,256 PASS intended profile · 151,936 PASS intended profile · 250,000 expected policy result · huge count REJECT by budget/sanity.
- [x] 99,999 / 100,000 / 100,001 / 128,256 / 151,936 / 250,000 fixtures assert pass/reject as decided — implemented as in-memory docs (both profiles) in `tests/validator_test.zig` (“tokenizer-scale string arrays pass the default variable-array cap”); count+1 (1,000,001) rejected.
- [x] pathological million-element array still rejected by work / byte / quota budget — declared 1,000,001-element doc rejects before scanning; work-budget (2,000 tokens @ 1,000 units) and scanned-byte (1,000 tokens @ 100 B) tests still reject inside the raised cap; existing quota tests stay green.
- [x] valid large tokenizer arrays need no tensor payload load — fixture docs are metadata-only (`tensor_count = 0`); tokenizer arrays validate without touching tensor payload.
- [x] CLI output distinguishes format rejection vs local policy/resource rejection — `tests/cli_test.py` asserts override rejection `E_ResourceLimitExceeded` with `category: "resource"` in JSON.
- [ ] Qwen2 and Llama 3 real files pass intended profile (blocked on #8 URLs) — synthetic 151,936 / 128,256 token counts pass; real files still blocked on #8.
Decision: A+C (recommended) vs B profiles vs keep hardened default; final ceiling value.
Verify 2026-09-11: `zig build test --summary all` 66/66; `python tests/cli_test.py` green incl. `--max-variable-array-elements` accept/override/exit-64 contract.

### F-02 — CVE fixture provenance — M
Split the negative corpus: rename the four mislabeled `cve-2024-*` cases in `tests/negative_corpus.py` to `synthetic-*` (keep the mechanisms, drop CVE labels); add a true-advisory section holding **placeholder** entries for CVE-2025-53630, CVE-2026-27940, CVE-2026-33298 with mechanism + expected protection path, `source_url` and affected/patched refs marked `TRIAGE-PENDING`. Do not fabricate tracker/advisory URLs; promote a placeholder to a real `cve-*` fixture only after triage. This corrects the output of already-done roadmap slice #9; it does not re-run it.
Files: `tests/negative_corpus.py`, regenerated `tests/fixtures/negative/manifest.json`, `README.md`, `SECURITY.md`.
- [x] no `cve-*` fixture lacks a verifiable primary source; synthetic cases carry no CVE label — all 12 cases renamed `synthetic-*` (no advisory identity); `_require_triaged_provenance()` fails generation if any `cve-*` case lacks `source_url` / `affected_commit` / `patched_commit`.
- [x] three CVEs present as placeholders; CVE-2026-33298 flagship path (checked byte-size rejects `[1024,1024,2^42+1,1]`) — placeholders are manifest-only (`fixture: null`, TRIAGE-PENDING); the flagship shape’s checked byte-size reject verified ad hoc (not committed as a fixture pending triage).
- [x] manifest stores source URL, affected/patched refs, SHA-256 once triaged — manifest emits `source_url` / `affected_commit` / `patched_commit` / `sha256` per case; placeholders carry TRIAGE-PENDING (no fabricated URLs or SHAs).
- [ ] docs distinguish “CVE regression” from “bug-class exemplar” — README/SECURITY.md provenance wording not updated in this slice.
Verify 2026-09-11: `python tests/negative_corpus.py` 12/12 reject (exit 2); 3 advisory placeholders remain TRIAGE-PENDING (manifest-only, unverified).

### F-03 — CI red from brittle syscall gate — M
Replace the `/proc/self/io` pass/fail gate with a test backend that counts actual `preadAll()` calls; assert `buffered.backend_reads << direct.backend_reads` plus a conservative access-pattern bound. Keep procfs counters as telemetry only. Split `ci.yml` into independent jobs — `core` (fmt/unit/CLI/negative), `oracle` (build + type/arithmetic/differential), `fuzz` (corpus + mutation), `bench` (scales + backend-read gate) — so a bench failure cannot suppress oracle/fuzz evidence.
Files: `tests/bench_scales.zig`, `src/gguf/reader.zig` (only if a counting hook is needed), `.github/workflows/ci.yml`.
- [x] cache regression gate measures backend reads, not procfs — `tests/bench_scales.zig` gates on instrumented `backend_reads` (window-slide bound + ≥4× head-to-head vs direct); procfs `read_syscalls` demoted to telemetry.
- [ ] Ubuntu CI green on ≥10 consecutive runs — not verifiable from this checkout; the split workflow has not run yet.
- [x] oracle/differential/fuzz jobs run even when bench fails — `.github/workflows/ci.yml` split into independent `core` / `oracle` / `fuzz` / `bench` jobs; release `needs` all four.
- [x] procfs syscall counters still recorded as telemetry when available — `read_syscalls` column retained, optional (`n/a` off-Linux/restricted `/proc`).
Verify 2026-09-11: `zig build bench --summary all` 3/3 pass (backend-read gates on all platforms); CI job split implemented.

## Phase 1 — P2 documentation quick wins

### F-08 — zero-padding wording — S
README (line 53), `AGENTS.md`, and the `tests/differential.py` rationale claim SafeGGUF is “stricter than spec”. The spec requires `0x00` padding; the accurate claim is that SafeGGUF enforces the spec’s zero-padding requirement where a particular upstream runtime may align past the bytes without checking contents.
Files: `README.md`, `AGENTS.md`, `tests/differential.py`, `SECURITY.md` (if it repeats the claim).
- [x] no remaining claim that zero padding is a SafeGGUF-only extension — 2026-09-11: README line 53 reworded to “explicitly enforces the GGUF specification's zero-padding requirement … even where a particular upstream runtime may align past those bytes without validating their contents”; SECURITY.md had no such claim. AGENTS.md line 51 (“stricter than the GGUF spec”) still stands and is outside this docs pass's declared scope (README+SECURITY only) — follow-up required before this box closes. Closed 2026-09-11: AGENTS.md line 51 now reads “enforcing the GGUF spec's zero-padding requirement — stricter than upstream runtimes, which may align past those bytes without validating their contents”.
- [x] rationale says “enforces spec more strictly than upstream”, not “stricter than spec” — 2026-09-11: README note now states spec enforcement vs upstream. `tests/differential.py` rationale (line 88) does not claim “stricter than spec” but still frames zero padding as a SafeGGUF safe-subset invariant without naming the spec; not edited (tests/ out of scope) — follow-up required. Closed 2026-09-11: differential.py line 88 now names the GGUF specification's zero-padding requirement as the invariant SafeGGUF enforces; expected verdicts [REJECT, PASS, PASS] and runtime behavior unchanged.

### F-10 — resource-budget wording + deployment limits — S
Reword README §3/§7 and `SECURITY.md` §2: “validator-managed live allocation quota”, “logical parser/validation work budget”, “scanned-byte budget” — never “process ≤128 MB” or “CPU hard-capped”. Add deployment guidance: run under cgroup/job-object memory + CPU quota, file-size limit, read-only filesystem, seccomp/sandbox profile for hostile multi-tenant uploads.
Files: `README.md`, `SECURITY.md`.
- [x] no wording reads as an OS-level process limit — 2026-09-11: README §3 + Library API and SECURITY.md §2 now say “validator-managed allocation quota”, “logical work budget”, and “scanned-byte budget”, each with an explicit not-an-OS-level-limit caveat (no “process ≤128 MB”, no “CPU hard-capped”).
- [x] deployment-limits subsection added — README §3 IMPORTANT callout + SECURITY.md “Deployment Limits (Hostile Multi-Tenant Uploads)”: cgroup/job-object memory limit, CPU quota + wall-clock timeout, input file-size limit, read-only filesystem where possible, seccomp/sandbox profile.

### F-12 — PASS scope statement — S
Add the standard statement wherever PASS semantics are documented (README exit-code table + output section, `SECURITY.md`): PASS means the file satisfies the selected structural/arithmetic/resource-policy checks; it is not a trust or malware verdict for weights, templates, or downstream runtime code. Docs only — no code change.
Files: `README.md`, `SECURITY.md`.
- [x] PASS statement present in README and SECURITY.md — 2026-09-11: README exit-code `0` row + “`PASS` scope” callout + JSON output-section note; SECURITY.md item 5.
- [x] no docs imply PASS = model safe or publisher trusted — the scope statements explicitly exclude trust/malware verdicts, benign weights, semantic template safety, downstream runtime/GPU vulnerabilities, publisher trust, and post-validation mutation.

### F-13 — version/badge sync — S
Verified 2026-09-11 at HEAD `158308e`: latest tag `v0.3.5`, README release badge + section header and `src/main.zig --version` all say v0.3.5, while HEAD is the v0.3.6 assurance commit. Choose one: tag `v0.3.6` at HEAD then sync badge/section/version string, or mark docs “Unreleased main”. Add “Released guarantees / Unreleased main” labels to security claims.
Files: `README.md`, `src/main.zig` (version string), tag/release metadata.
- [x] version string, badge, README section, and latest tag agree (or are explicitly labelled unreleased) — 2026-09-11: verified latest tag `v0.3.5` = README release badge = `src/main.zig` version string; HEAD `158308e` (“feat(v0.3.6)”) is one commit past the tag with uncommitted work on top, so README section header is now labelled “unreleased `main`; latest release v0.3.5” and a top-of-file Release status note distinguishes tagged release from `main`. No tag created (docs-only pass).
- [x] README marks which claims apply to released vs unreleased main — README Release status note + labelled guarantees header + CLI override paragraph marked unreleased `main` (v0.3.5 has no `--max-variable-array-elements` and caps at 100,000); SECURITY.md carries a matching Release status note.

## Phase 2 — new-medium items

### F-09 — rolling upstream canary (Oracle B) — M
Nightly, non-blocking: build current ggml `master` alongside pinned Oracle A, run the differential subset in report mode, save a drift report (new type IDs, new/removed divergences, new upstream rejects, SafeGGUF false reject/accept). Oracle A stays pinned and PR-blocking.
Files: `.github/workflows/nightly.yml` (or new `canary.yml`), `tests/build_oracle.sh` (ref/checkout override), `tests/differential.py` (report mode), new `tests/canary_drift.py`.
- [ ] nightly canary runs; drift report uploaded as artifact
- [ ] canary failure never blocks PRs; pinned oracle unaffected
- [ ] drift report names new type IDs / divergences / false accept-reject

### F-11 — Windows runtime tests — M — NEEDS-USER-DECISION (runner cost)
Add a Windows CI job running unit tests, CLI tests, and the negative corpus on real Windows I/O: `stat()`, pread semantics, paths, exit codes, console stdout/stderr JSON, >2 GiB sparse files; small differential subset only if an oracle build is practical.
Files: `.github/workflows/ci.yml`, `tests/cli_test.py` (path handling if needed).
- [ ] Windows job runs unit + CLI + negative corpus
- [ ] >2 GiB sparse-file and console JSON behavior covered or explicitly waived
- [ ] job cost/runtime acceptable (decision below)

## Already tracked (do not re-plan)

- F-04 real-world corpus → `assurance-roadmap-issues.md` #8 (HITL: URLs/license/size)
- F-05 coverage-guided fuzzing → #1 (HITL: libFuzzer vs AFL++; nightly wrapper exists)
- F-06 `Result` ownership independent of Validator → #10 (HITL: breaking vs alias)
- F-07 signing/SBOM/provenance → #13 (HITL: signing identity, SLSA level, SBOM format)

## Decisions needed (owner: user)

1. **F-01 limits policy** — A+C (recommended) vs B profiles; final sanity ceiling value.
2. **F-11 Windows runner cost** — approve hosted Windows runner minutes, or defer.
3. **F-04/#8 corpus URLs** — approved URL list, licenses, CI download size.
4. **F-07/#13 supply chain** — signing identity, SLSA target level, SBOM format.
