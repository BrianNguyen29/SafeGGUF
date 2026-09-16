# SafeGGUF Security Review Package

Purpose: let an external engineer build, test, and audit SafeGGUF without reverse-engineering the
repository. Every behavioral claim below is linked to the file and line range it was read from in
this working tree. Claims that could not be confirmed from the tree are explicitly marked
`UNCONFIRMED`.

Read this first, then use [§17](#17-audit-target-files-and-functions) as the audit map,
[§18](#18-reproduction-commands) for runnable commands, and [§19](#19-expected-ci-signals) to
interpret CI.

## Revision and provenance

| Item | Value | Source |
| :--- | :--- | :--- |
| Latest release tag | `v0.3.6` (annotated tag object `f688b59`, peels to commit `ddbf045591cd7a2c7c69252012092440025723eb`) | `README.md:13`, `SECURITY.md:5`; verified with `git tag`/`git rev-parse f688b59^{commit}` |
| Working-tree base commit | `2322534` ("Update validation, tests and CI") | `git rev-parse --short HEAD` |
| Working-tree state | 16 tracked files modified at authoring time; `scripts/` and the root `SafeGGUF_Remediation_Plan_F02_F04_F05_F06_F07_F09.md` (+ its `:Zone.Identifier` siblings) untracked | `git status --short`, `git ls-files` |
| Pinned upstream type table | ggml `0.23.0` @ `e91ded11bdcd78c42f9c8d3978ff6686eb4c1226` | `src/gguf/types.zig:7-10` |
| Toolchain | Zig `0.13.0` (pinned in CI; also used by all harnesses except the advisory coverage-fuzz lane), Python 3, CMake/C++ only for the oracle | `AGENTS.md:5-9`, `.github/workflows/ci.yml:23-31`, `tests/fuzz/README.md:5-15` |

Notes for the reviewer:

* The behavior claims and line numbers describe **this working tree**, not the released `v0.3.6`
  commit. Several files carry uncommitted edits relative to `ddbf045` (including
  `src/validate/validator.zig`, `tests/differential.py`, and all CI workflows).
* `scripts/version_consistency.py` is referenced by `.github/workflows/ci.yml` but is **untracked** in this tree
  (`git ls-tree -r HEAD` has no `scripts/`); if you check out a bare commit, that CI step needs the
  file from the working tree.
* `UNCONFIRMED:` none of the test suites/CI lanes in this document were executed while writing it.
  Their green/red status on this exact revision is not asserted; only the contracts they assert are
  documented.
* SafeGGUF reports `safegguf --version` with the embedded default `0.3.6`; release artifacts are
  overridden per tag with `-Dversion=<tag>` (`build.zig:16-22`, `.github/workflows/ci.yml:272-288`).

## 1. Threat model

SafeGGUF is a pre-admission validator for untrusted GGUF model files. GGUF fields — element counts,
string lengths, dimensions, offsets, alignment — are attacker-controlled and drive allocations and
pointer arithmetic in downstream loaders (`README.md:9-23`). SafeGGUF rejects the input classes that
most commonly break those loaders **before** any downstream runtime maps the file
(`SECURITY.md:63-65`):

* `u64` arithmetic that would wrap during dimension/block/byte-size computation (`README.md:19-20`);
* descriptor tables and cumulative offsets that overflow or extend past end of file
  (`README.md:20`);
* alignment padding that violates the GGUF specification's zero-padding requirement
  (`README.md:21`);
* resource exhaustion (huge counts, oversized strings, deep nesting) before allocation is attempted
  (`README.md:22`);
* semantic violations: invalid UTF-8, invalid booleans, unknown/deprecated tensor type IDs, zero
  dimensions (`README.md:23`).

The verdict taxonomy is fail-closed: `0` PASS, `2` REJECT, `64` usage error, `70` internal/host-OOM
error, `74` I/O error (`README.md:116-124`, `SECURITY.md:70-75`, implemented in `src/main.zig:16-25`
and `src/main.zig:196-234`).

`PASS` is explicitly **not** a trust or malware verdict (`README.md:374`, `SECURITY.md:80`).

## 2. Trust boundaries (filesystem / CAS / downstream / sandbox)

* **Input boundary — filesystem.** The only production entrypoint opens the target read-only via
  `std.fs.cwd().openFile` and stats it (`src/main.zig:152-175`); reads are issued as `preadAll`
  calls through the reader abstraction (`src/gguf/reader.zig:90-95`, `132-163`). The validator never
  writes to the file, and validation reads only the header, metadata, descriptor table, alignment
  padding, and string bytes; tensor payload bytes are never read, so models larger than memory can be
  inspected (`README.md:11`, `src/gguf/parser.zig:263-289`).
* **Content-addressed storage (CAS).** SafeGGUF validates a path/stream; it cannot prevent a file
  from being swapped between validation and load. Deployers should validate in immutable
  content-addressable storage and verify a cryptographic digest (e.g. SHA-256) of the exact bytes
  admitted to the runtime (`SECURITY.md:76-79`, `README.md:374`).
* **Downstream runtime boundary.** `llama-cpp` is a deliberately safe pre-admission subset derived
  from pinned ggml `0.23.0`, differential-tested against it; it is not a full compatibility claim for
  every `llama.cpp` build, and divergences are pinned in an audited baseline inside
  `tests/differential.py` (`README.md:244`, `tests/differential.py:38-143`).
* **Sandbox boundary.** The validator's quotas bound only validator-managed allocations and logical
  work; they do not cap process RSS, page cache, stack, CPU time, or wall clock. For hostile
  multi-tenant uploads, additionally apply a cgroup/job-object memory limit, CPU quota plus
  wall-clock timeout, input file-size limit, read-only filesystem where possible, and a
  seccomp/sandbox profile (`SECURITY.md:82-84`, `README.md:266`).
* **Diagnostic output boundary.** Untrusted names/keys are escaped byte-safely into JSON so output
  stays parseable (`src/main.zig:356-408`) and sanitized to printable ASCII in text mode
  (`src/main.zig:410-421`), preventing terminal/log injection.
* **Library boundary.** Embedding callers get a `Validator` that owns a `QuotaAllocator` and
  `WorkBudget`; a single instance is not thread-safe and must be used one-per-thread or with external
  synchronization; `validateOwned()` results own their heap state
  (`src/validate/validator.zig:30-49`, `README.md:307-330`).

## 3. Non-goals

SafeGGUF does not:

* prove that model weights, chat templates, or downstream runtime/GPU kernel code are benign
  (`README.md:374`);
* protect against TOCTOU between validation and runtime admission (`SECURITY.md:76-79`);
* enforce OS-level resource limits by itself (`SECURITY.md:82-84`);
* guarantee full `llama.cpp`/ggml compatibility — only the documented, differential-tested subset
  (`README.md:244`);
* inspect tensor payload content at all; a structurally valid file with hostile weights passes
  (`README.md:11`);
* detect duplicate metadata keys across shards, authorize publishers, or verify model licenses.

## 4. Security invariants

1. **Checked arithmetic on attacker-controlled values.** No silent `u64` wraparound:
   `checkedAdd`/`checkedMul`/`checkedDiv`/`checkedAlignUp` map overflow to `ArithmeticOverflow`
   (`src/validate/arithmetic.zig:5-23`), used on descriptor cumulative offsets
   (`src/validate/structural.zig:99-102`, `123-125`), metadata string extents
   (`src/gguf/parser.zig:124`, `216`), array byte extents (`src/gguf/metadata.zig:187`, `223`,
   `251-253`), and alignment computation (`src/gguf/parser.zig:264`).
2. **Block divisibility.** `dims[0] % block_size == 0` is enforced for non-scalar tensors
   (`src/validate/arithmetic.zig:68-71`); scalar (`n_dims == 0`) tensors are valid only when
   `block_size == 1` (`src/validate/arithmetic.zig:60-66`).
3. **Bounds.** Each tensor's absolute end must be `<= file_size` (`src/validate/structural.zig:123-129`)
   and ranges may not overlap (`src/validate/structural.zig:143-152`).
4. **Zero padding.** Descriptor-to-data alignment padding bytes must be `0x00` in both profiles
   (`src/gguf/parser.zig:271-289`); this is a deliberate anti-tamper safe-subset invariant, stricter
   than upstream runtimes that align past those bytes (`AGENTS.md:60`, `tests/differential.py:99-102`).
5. **Limits before allocation.** Counts/limits are checked before allocations: tensor and metadata
   counts (`src/gguf/parser.zig:82-86`), minimum-size prechecks before allocating descriptor tables
   (`src/gguf/parser.zig:88-91`, `179-186`), array counts (`src/gguf/metadata.zig:211-216`).
6. **Duplicate rejection.** Duplicate metadata keys (`src/gguf/parser.zig:144-148`) and duplicate
   tensor names (`src/validate/structural.zig:78-82`) are rejected.
7. **Fail-closed CLI.** Missing/unknown commands and unknown or invalid options exit `64`
   (`src/main.zig:38-41`, `53-57`, `136-141`); missing file path exits `64` (`src/main.zig:59-63`).
8. **Quota vs host OOM.** Quota exhaustion is a policy REJECT (exit `2`,
   `E_TotalAllocationLimitExceeded`), unbudgeted host OOM is exit `70`
   (`src/main.zig:209-231`, `SECURITY.md:67`).
9. **Pinned provenance.** Every JSON result (PASS/REJECT/ERROR) carries the pinned ggml source as
   `type_layout_source` (`gguf-spec`) or `compatibility_target` (`llama-cpp`)
   (`src/main.zig:144-150`, `238-253`, `README.md:147`).

## 5. Parser architecture

Files: `src/gguf/reader.zig`, `src/gguf/parser.zig`, `src/gguf/metadata.zig`, `src/gguf/error.zig`.

* **Reader abstraction.** A vtable-backed `Reader` checks `offset + len <= size` before dispatch
  (`src/gguf/reader.zig:5-19`). Three implementations: `SliceReader` for in-memory bytes
  (`38-63`), `FileReader` for direct `preadAll` (`65-96`), and the production `BufferedReader`, a
  64 KiB sliding window with cache-hit fast path, large-read bypass, and window slide
  (`98-164`).
* **Parse order** (`src/gguf/parser.zig:40-298`): llama-cpp native-endian check (`52-54`), magic
  (`58-64`), version (`66-77`), counts with limits (`79-91`), metadata loop (`110-177`), tensor
  descriptors (`184-261`), tensor-data base + zero-padding verification (`263-289`).
* **Metadata.** Key grammar is strict lower_snake_case with dot segments (`src/gguf/metadata.zig:33-53`).
  Values are bounded (string length `<= max_string_bytes`, `src/gguf/metadata.zig:184-195`), arrays are
  length-capped (`209-216`), booleans must be 0/1 including inside arrays (`158-164`, `221-240`),
  nesting depth is capped at `max_metadata_depth = 16` (`197`), and nested arrays are rejected under
  `llama-cpp` (`204-207`). Strings are UTF-8 validated streaming in 4 KiB chunks with
  carry-over across boundaries (`57-101`).
* **Diagnostics.** Raise sites snapshot position into `ParseContext` (`src/gguf/error.zig:135-186`);
  stages are `"parse"` (`src/gguf/parser.zig:48`) and `"structural"` (`src/validate/structural.zig:25`).
  Key/name snapshots copy into fixed buffers before unwind, so no dangling pointers
  (`src/gguf/error.zig:130-140`, `166-177`).
* **Per-error metadata.** Exhaustive `categoryOf`/`messageOf` tables
  (`src/gguf/error.zig:45-90`, `94-128`) feed REJECT output (`src/main.zig:275-317`).

## 6. Arithmetic model

* **Primitives** (`src/validate/arithmetic.zig:5-23`): `checkedAdd`, `checkedMul`, `checkedDiv`
  (division by zero maps to overflow), `checkedAlignUp` (rejects non-multiples-of-8 alignment and
  overflow of the aligned value).
* **Dimension validation** (`src/validate/arithmetic.zig:25-44`): `n_dims <= 4`, no zero
  dimensions; under `llama-cpp` additionally each dim `<= INT64_MAX` and the element product must
  stay `< INT64_MAX` (implemented by pre-checking `INT64_MAX / d > element_product`).
* **Byte computation order** (`src/validate/arithmetic.zig:56-77`): type-traits lookup →
  `n_dims <= 4` → scalar special case → row/block divisibility → checked element product → checked
  division by block size → checked multiply by type size. Each failure maps to a distinct
  `ParseError` and therefore a distinct `error_code` (`src/gguf/error.zig:94-128`).
* **llama-cpp contiguous layout** (`src/validate/structural.zig:84-106`): expected offsets are the
  checked chain `expected = alignUp(expected + nbytes, alignment)`; the aligned end of the final
  tensor must exist within the file (`102-105`).
* **Verification of the arithmetic model.** A u128 oracle sweep in
  `tests/validator_test.zig:435-523`; a Python bigint oracle re-derives the exact result and
  classification (phase 1, `tests/arithmetic_oracle.py:167-300`; shared vectors mirrored in
  `tests/validator_test.zig` are asserted at `tests/arithmetic_oracle.py:169-180`), and phase 2
  cross-checks the compiled CLI on exact-fit/one-byte-short files (`tests/arithmetic_oracle.py:359-421`).

## 7. Allocation model and quota

* **Defaults** (`src/gguf/limits.zig:11-29`): `max_tensors = 1,000,000`,
  `max_metadata_entries = 1,000,000`, `max_string_bytes = 65,536`,
  `max_tensor_name_bytes = 64`, `max_dimensions = 4`, `max_array_elements = 10,000,000`,
  `max_variable_array_elements = 1,000,000` (CLI-adjustable, ceiling = `max_array_elements`),
  `max_metadata_depth = 16`, `max_total_alloc_bytes = 128 MiB`, `max_work_units = 10,000,000`,
  `max_scanned_bytes = 256 MiB`.
* **QuotaAllocator** wraps the parent allocator and tracks live + peak bytes; `alloc`/`resize`
  fail (returning null/false) and set `quota_exceeded` when the ceiling would be crossed
  (`src/gguf/limits.zig:80-188`); `free` saturates instead of underflowing (`180-188`), and resize
  shrink saturates too (`156-169`).
* **Wiring.** `Validator.init` constructs the quota allocator and work budget from `Limits`
  (`src/validate/validator.zig:58-71`); all parser/structural allocations go through the managed
  allocator (`src/validate/validator.zig:93-96`, `118-140`).
* **Failure semantics.** Quota exhaustion arrives as `OutOfMemory` with
  `isQuotaExceeded() == true` and is rendered as `REJECT`/`E_TotalAllocationLimitExceeded` exit `2`
  (`src/main.zig:209-219`); genuine host OOM without the flag exits `70` (`src/main.zig:220-230`).
* **Owned results.** `validateOwned()` allocates a heap `OwnedValidationState` (its own quota
  allocator + work budget) so `Result` outlives the producing `Validator`; `Result.deinit()` is
  idempotent, `take()` moves ownership, and struct copies are a documented aliasing hazard
  (`src/validate/validator.zig:151-292`).
* **Scope caveat.** The quota caps validator-routed allocations only; it is not an OS RSS/page-cache
  limit (`SECURITY.md:67`).

## 8. Work budget

* **Model** (`src/gguf/limits.zig:31-76`): `WorkBudget` tracks deterministic logical units
  (`consume`) and scanned bytes (`consumeBytes`); both fail closed with `error.ResourceLimitExceeded`
  on overflow or when the ceiling would be exceeded.
* **Charging sites:** one unit per metadata entry (`src/gguf/parser.zig:117`), per tensor descriptor
  (`src/gguf/parser.zig:203`), per metadata value (`src/gguf/metadata.zig:113`), per array element
  (`src/gguf/metadata.zig:218`), per dimension/tensor/hash-insert/range/sort/overlap pass
  (`src/validate/structural.zig:50`, `73`, `88`, `112`, `140-141`, `147`). Scanned bytes are charged
  for key/name lengths (`src/gguf/parser.zig:122`, `214`), alignment padding (`274`), streamed
  string UTF-8 validation (`src/gguf/metadata.zig:66`), and bool-array scans (`src/gguf/metadata.zig:230`).
* **Design intent:** the budgets, not the variable-array sanity cap, are the primary DoS control
  (`src/gguf/limits.zig:18-24`).
* **Failure semantics:** `ResourceLimitExceeded` flows to `REJECT` exit `2` via the standard
  rejection path (`src/main.zig:233-234`; category `resource` in `src/gguf/error.zig:82-84`).
  Overrun is not a CPU-time or wall-clock cap (`SECURITY.md:68`).

## 9. Profile semantics

CLI `--profile` defaults to `gguf-spec` (`src/main.zig:70-72`); `Profile` is defined in
`src/gguf/types.zig:14-17`. Both profiles validate only GGUF structure — never payload bytes.

| Constraint | `gguf-spec` (default) | `llama-cpp` | Code |
| :--- | :--- | :--- | :--- |
| GGUF version | exactly `3` | `2` or `3` | `src/gguf/parser.zig:69-77` |
| Endianness | any (CLI `--endian`) | host-native only | `src/gguf/parser.zig:51-54` |
| Tensor layout | arbitrary order/gaps; overlap rejected | strictly contiguous in descriptor order; aligned final end must exist | `src/validate/structural.zig:84-106`, `143-152` |
| Nested metadata arrays | allowed, depth ≤ 16 | rejected (`NestedArrayNotSupported`) | `src/gguf/metadata.zig:197-207` |
| Tensor name length | 1–64 bytes | 1–63 bytes (`>= 64` rejected) | `src/gguf/parser.zig:208-213` |
| Alignment | positive multiple of 8 | multiple of 8 **and** power of two | `src/gguf/parser.zig:163-171`, `src/validate/structural.zig:31-36` |
| Scalar tensors (`n_dims == 0`) | allowed when `block_size == 1` | same | `src/validate/arithmetic.zig:60-66` |
| Zero dimensions | rejected | rejected | `src/validate/arithmetic.zig:31-33` |
| Dimension bounds | checked `u64` arithmetic | dims `<= INT64_MAX`, product `< INT64_MAX` | `src/validate/arithmetic.zig:34-42` |

Default alignment is 32 (`src/gguf/types.zig:5`, `src/gguf/parser.zig:99`). Both profiles enforce the
zero-padding rule (invariant 4). The profile table in `README.md:230-241` mirrors these rules.

## 10. Divergences: GGUF spec vs `gguf-spec` vs `llama-cpp` vs pinned upstream

"Upstream" means the pinned ggml `0.23.0` (`e91ded11`) loader as exercised by the C++ oracle. The
hand-written fixture matrix records the pinned expectations per fixture in
`tests/differential.py:38-143`; generated matrix entries extend it at `tests/differential.py:145-149`.

Intentional `llama-cpp` divergences from upstream (SafeGGUF REJECTs where upstream accepts):

| Fixture | Safe | Upstream load | Upstream no-load | Rationale (source line) |
| :--- | :---: | :---: | :---: | :--- |
| `nonzero_header_padding` | R | P | P | SafeGGUF enforces spec zero-padding; upstream aligns without checking byte contents (`tests/differential.py:99-102`) |
| `llama_cpp_overflow` | R | P | P | checked arithmetic prevents `u64` overflow; upstream `GGML_PAD` wraps to 0 (`tests/differential.py:87-90`) |
| `zero_dimension` | R | P | P | explicit zero-element dimensions rejected (`tests/differential.py:139-142`) |
| `empty_tensor_name` | R | P | P | non-empty names enforced (`tests/differential.py:67-70`) |
| `hyphen_key` / `invalid_key` | R | P | P | strict lower_snake_case key grammar (`tests/differential.py:75-86`) |
| `invalid_bool` | R | P | P | bool bytes must be 0/1 (`tests/differential.py:79-82`) |

Divergences where upstream is stricter or mode-dependent (both tools reject where it matters):

* `truncated_final_padding` and `type40_truncated_false_pass`: SafeGGUF and upstream `--load-data`
  reject; upstream `--no-load` passes because it never reads the data blob
  (`tests/differential.py:123-130`; no-load semantics documented at `tests/differential_matrix.py:29-31`).
* GGUF version: `gguf-spec` rejects v2 while `llama-cpp` accepts it (`tests/differential.py:135-138`,
  `src/gguf/parser.zig:69-77`).
* Zero-tensor padding: `gguf-spec` strictly rejects a truncated header padding for zero-tensor files
  while `llama-cpp` mirrors upstream non-seek acceptance (`tests/differential.py:39-42`,
  `src/gguf/parser.zig:266-269`).

Additional generated-matrix divergences are documented in `tests/differential_matrix.py:19-33`:
upstream accepts alignment 1 (SafeGGUF requires multiple of 8), upstream string cap is 1 GiB vs
SafeGGUF 64 KiB, and zero-element tensors (upstream zero-byte acceptance vs SafeGGUF rejection).

Divergence classification and monitoring: `classify_divergence` labels
SafeGGUF-REJECT/upstream-PASS as the intentional subset and SafeGGUF-PASS/upstream-REJECT as a
possible false accept or upstream tightening (`tests/differential.py:319-325`); any observed verdict
different from the pinned baseline column fails the pinned sweep (`tests/differential.py:411-421`,
`517-521`), so baseline changes require an explicit commit.

## 11. Oracle architecture

Two C++ oracles build from upstream ggml sources; both compile `tests/oracle/ggml_oracle.cpp`:

* **Oracle A (pinned, blocking).** `tests/build_oracle.sh:16-18` pins `v0.23.0` @
  `e91ded11...`; the script shallow-clones the tag, detaches at the exact commit, and refuses to
  continue if `HEAD != REF` (`136-165`). A `.source-sha` stamp forces a clean reconfigure when the
  build dir does not match the requested source (`115-132`, `167-175`). CMake builds the `ggml`
  target, then the oracle is compiled with `-std=c++17 -O2` and linked against `ggml-base`/`ggml`
  (`177-191`). Default artifacts: `.cache/ggml-upstream`, `tests/oracle/ggml_oracle`.
* **Oracle B (rolling canary, advisory).** `tests/build_oracle.sh --name rolling --ref <40-hex>` uses an
  isolated per-SHA cache and requires a full commit SHA — floating refs are rejected
  (`tests/build_oracle.sh:90-97`, `146-159`). `tests/canary_drift.py` resolves
  `refs/heads/master` to one full SHA, builds Oracle B, verifies the oracle's reported commit
  against the resolved SHA, then runs the differential sweep with `--report-json`; Oracle A is never
  touched or replaced, and divergences are report-only (`tests/canary_drift.py:11-21`, `78-89`,
  `242-272`, `274-299`).

**Oracle interface** (`tests/oracle/ggml_oracle.cpp`): `--version` (ggml version/commit, `13-16`),
`--dump-types` (all 43 slots with name/block/type sizes, `18-28`), and both `--load-data` and
`--no-load` modes (`30-54`). Only exit `0` (PASS) and `2` (REJECT) count as verdicts; anything else
is treated as an oracle error by the harness (`tests/differential.py:220-237`).

**Identity pinning.** Both `tests/test_oracle_types.py:16-25` and `tests/differential.py:178-182`
assert the oracle reports `ggml_version: 0.23.0` / `ggml_commit: e91ded1...` before trusting it.
`tests/test_oracle_types.py` compares all 43 type slots and fails on missing/renamed/changed traits or on
SafeGGUF accepting a removed slot (`tests/test_oracle_types.py:90-122`).

## 12. Differential methodology

`tests/differential.py` is the blocking compatibility sweep (run by the `oracle` CI job):

1. Build/verify the pinned oracle identity (`tests/differential.py:160-182`).
2. **Type drift first**: dump the oracle type table and diff it against the pinned SafeGGUF table
   (`tests/differential.py:257-305`, `359-368`) — catches upstream format evolution even when no
   fixture can generate the new type.
3. Load hand-written fixtures plus generated `matrix/` fixtures (`tests/differential.py:370-383`;
   matrix built by `tests/differential_matrix.py`, which covers all 35 active types × 6 shape
   variants, `n_dims` 0–5 and `UINT32_MAX`/`INT64_MAX` boundaries, ten alignment values
   (`0/1/7/8/16/24/32/40/64` and `2^31`), and
   metadata edge shapes — `tests/differential_matrix.py:1-43`).
4. For every fixture, run **three columns** — SafeGGUF `--profile llama-cpp`, oracle `--load-data`,
   oracle `--no-load` — and assert each equals the pinned expectation; an unregistered fixture is a
   hard failure (`tests/differential.py:392-421`).
5. Classify actual divergences and, with `--report-json`, emit a machine-readable report
   (`schema_version 1`) with type drift, new/resolved divergences, both divergence directions, and
   oracle errors (`tests/differential.py:497-515`).

The differential harness auto-builds the pinned oracle when missing and auto-builds the SafeGGUF
ReleaseSafe binary when missing (`tests/differential.py:160-170`). The rolling canary reuses the
same sweep with Oracle B and never fails on divergence (`tests/canary_drift.py:274-299`).

## 13. Fuzzing methodology

Four complementary layers:

* **(a) Corpus sweep (blocking, in `zig build test`).** `tests/fuzz_target.zig` runs every
  `tests/corpus/*.gguf` through the libFuzzer-style entrypoint under both profiles × both endians
  (`tests/fuzz_target.zig:57-76`), with the corpus sweep test requiring ≥ 15 files
  (`tests/fuzz_target.zig:84-103`); wired into `test` and `fuzz` steps in `build.zig:49-60`. Fuzzer limits
  are tightened (4 MiB quota, 100k work units, 1k strings/keys — `tests/fuzz_target.zig:26-39`), and a
  `GeneralPurposeAllocator` leak check panics on leak (`tests/fuzz_target.zig:46-66`).
* **(b) Deterministic mutation campaign (blocking, 2,000 iterations = 4,000 executions).**
  `tests/fuzz_mutation.py` mutates seeds with bit flips, byte overwrite/insert/delete, interesting-
  integer overwrites (including `0xFFFFFFFFFFFFFFFF`), splicing, truncation, and chunk shuffles
  (`tests/fuzz_mutation.py:59-116`), then requires exit `0` or `2` under both profiles; timeouts,
  signals, and other exits fail and preserve `.gguf` + metadata artifacts with commit/seed context
  (`tests/fuzz_mutation.py:24-56`, `171-209`). A synthetic self-test verifies crash-artifact persistence
  (`tests/fuzz_mutation.py:125-142`).
* **(c) Nightly deep campaign (scheduled).** 100,000 mutation iterations (leg 1), a 50,000-iteration
  matrix leg across both profiles × both endians, acceptance-filtered corpus evolution (only inputs
  `llama-cpp` accepts and that stay inside the `{0, 2}` contract on all four combinations), bounded
  corpus caps (3,000 entries / 64 MiB), crash minimization by prefix truncation, and an
  `environment.info` repro bundle (`.github/workflows/nightly.yml:85-414`, `429-433`, `442-452`).
  Corpus persistence via `actions/cache` (`.github/workflows/nightly.yml:67-79`, `435-440`).
* **(d) Coverage-guided lane (advisory, Zig 0.14.1 only).** `tests/fuzz/coverage_lane.py` drives
  `zig build --fuzz` per profile × endian target under a time budget and stall detection, parses the
  built-in fuzzer's `v/`/`f/` artifacts, promotes coverage-increasing inputs (deduped by sha256,
  capped at 10,000 entries / 256 MiB), and classifies incidents as
  `validator_crash`/`engine_crash`/`timeout`/`oom` with repro status; only a non-reproducing
  engine-internal crash is advisory (`tests/fuzz/README.md:17-105`,
  `.github/workflows/coverage-fuzz.yml:1-34`, `146-153`). The dual-toolchain allocator shim that
  keeps `src/gguf/limits.zig` compiling on 0.13.0 and 0.14.1 is at `src/gguf/limits.zig:4-9`.

Fuzz claim discipline: no ASan/UBSan runtime; detectable failures are panics, signals, timeouts,
OOM markers, unexpected exits, and (in-process) allocator leaks
(`tests/fuzz/README.md:149-157`, `tests/fuzz_target.zig:46-66`).

## 14. Real-corpus methodology

`tests/real_corpus.py` is a manifest-driven gate whose identity is the file's SHA-256:

* **Manifest.** `tests/real-corpus-manifest.json` holds maintainer-approved immutable entries only;
  every entry requires `name`, `url`, `sha256`, `size`, `license`, `tier`, `expected_profile`, with
  duplicate names/digests rejected and schema errors failing closed before any download
  (`tests/real_corpus.py:86`, `163-220`). As of this revision the manifest has 16 tier-1 entries, two of
  which expect REJECT (`tests/real-corpus-manifest.json:15-240`, e.g. lines 142-155 and 184-197).
* **Pipeline per entry:** bounded streaming download to a temp file with SHA-256 computed as bytes
  arrive (declared `Content-Length` ignored; default cap 1 GiB), size check, hash check, then atomic
  promote to `.cache/real-corpus/<sha256>.gguf`; only size+hash-verified bytes are ever admitted
  (`tests/real_corpus.py:18-23`, `106-112`, `238-303`). Cache hits are re-verified by size+hash; corrupt
  cache entries are discarded and re-fetched (`tests/real_corpus.py:278-293`).
* **Verdict compare:** `safegguf inspect --format json --profile <p>` per expected profile; exit `0`
  → pass, `2` → reject, anything else → `SAFEGGUF_ERROR` (`tests/real_corpus.py:306-344`, `374-396`).
* **Coverage floors:** a run can never PASS vacuously — default `--min-successful-entries 1`, and
  values `< 1` are rejected; exit `0` requires the floors met by verified+matched entries
  (`tests/real_corpus.py:35-39`, `449-465`, `515-518`).
* **Exit taxonomy:** `0` PASS / `1` FAIL / `3` INCONCLUSIVE (NEUTRAL, tolerated network-only
  failure with `--tolerate-download-errors`); real findings (size/hash/verdict mismatch, CLI error)
  fail in every mode, and fail-closed mode turns a download outage into FAIL
  (`tests/real_corpus.py:41-53`, `473-510`).
* **CI wiring:** PR lane runs `--tier 1 --tolerate-download-errors` and maps exit `3` to a neutral
  notice; `v*` tags run fail-closed with no flag (`.github/workflows/ci.yml:109-123`). The nightly advisory lane
  (`.github/workflows/real-corpus.yml`) runs the same runner with `continue-on-error: true` and uploads the JSON
  report (`.github/workflows/real-corpus.yml:17-20`, `77-115`). Tier 2 entries are manual/weekly, not in the blocking
  gate (`tests/real_corpus.py:8-12`, `.github/workflows/real-corpus.yml:31-38`).

## 15. Supply-chain verification

* **Build inputs.** No `build.zig.zon` and zero Zig package dependencies — std only
  (`AGENTS.md:8`; verified by repository listing). Python harnesses use stdlib + optional
  network/CMake for oracles.
* **CI action pinning.** Every third-party action in every workflow is pinned by full commit SHA
  with a version comment (e.g. `.github/workflows/ci.yml:21`, `24`, `29`; `.github/workflows/coverage-fuzz.yml:81`, `84`, `89`).
  Toolchains are pinned: Zig `0.13.0` (`.github/workflows/ci.yml:23-26`), Python `3.12` (`.github/workflows/ci.yml:28-31`); the
  coverage lane is the sole `0.14.1` exception (`.github/workflows/coverage-fuzz.yml:83-86`).
* **Release pipeline** (`.github/workflows/ci.yml:243-433`, tag `v*` only):
  1. Build five targets with `-Dversion=<tag>` and produce `SHA256SUMS.txt` (`272-291`).
  2. Generate an SPDX 2.3 SBOM with SHA1+SHA256 per file and a purl referencing the exact commit
     (`293-383`).
  3. Attest build provenance for the binaries and attach the SPDX document as an SBOM attestation
     subject (`385-394`).
  4. Keyless Sigstore signing of `SHA256SUMS.txt` (`396-403`).
  5. **Verify before publish**: checksum manifest, cosign signature with workflow-identity regexp
     and GitHub OIDC issuer, and `gh attestation verify` for every artifact; abort on any failure
     (`405-423`).
  6. Publish all assets to the GitHub Release (`425-433`).
* **Consumer verification steps** (copy-ready): `README.md:268-305`, `SECURITY.md:16-55`.
* **Version consistency.** A dedicated CI job compares the embedded `build.zig` default against the
  newest `v*` tag and fails on drift or shallow checkout (`.github/workflows/ci.yml:55-71`,
  `scripts/version_consistency.py:60-104`).
* **Binary/result provenance.** Build metadata is injected at compile time with no wall-clock
  timestamp (`build.zig:12-26`, `src/build_info.zig:1-17`) and surfaced by `--version`
  (`src/main.zig:423-431`); every JSON result carries the pinned ggml source
  (`src/main.zig:144-150`).
* **Oracle supply chain.** The pinned oracle checks out and verifies the exact upstream commit
  before building (`tests/build_oracle.sh:136-165`), and both oracle harnesses assert the oracle's
  reported version/commit before trusting results (`tests/test_oracle_types.py:16-25`,
  `tests/differential.py:178-182`).

## 16. Limitations and risks

Known, by design:

* **Structural only.** Tensor payload bytes are never read or validated; a structurally valid file
  with hostile weights passes (`README.md:11`, `374`).
* **TOCTOU.** Validation cannot bind later use of the file; use immutable CAS plus digest checks
  (`SECURITY.md:76-79`).
* **Budgets ≠ sandbox.** Quota/work/scanned-byte budgets bound validator-managed work only; add
  OS/container limits for hostile uploads (`SECURITY.md:82-84`).
* **Pinned-baseline drift.** The pinned differential contract is a hand-maintained `EXPECTED_MATRIX`
  (`tests/differential.py:36-143`); only the advisory rolling canary watches moving upstream, and it
  is report-only with no automatic baseline update (`.github/workflows/upstream-canary.yml:11-21`,
  `tests/canary_drift.py:14-21`). A new upstream change can therefore go unnoticed until a human
  reviews the canary report.
* **Fixture-bounded differential coverage.** The sweep can only detect what its hand-written +
  generated fixtures exercise (`tests/differential.py:370-383`).
* **Gate coverage tiers.** Only tier-1 corpus entries run in the blocking gate; tier 2 is manual
  (`tests/real_corpus.py:8-12`).
* **Advisory fuzz/coverage scope.** Coverage-guided fuzzing runs only on Zig 0.14.1 nightly and is
  advisory; engine-crash handling has an explicit advisory carve-out
  (`tests/fuzz/README.md:9-15`, `99-104`), and no ASan/UBSan runtime exists on the pinned toolchain
  (`tests/fuzz/README.md:149-157`).
* **Windows lane scope.** Native Windows validation covers core tests + CLI + negative corpus but
  deliberately excludes oracle/differential, mutation fuzzing, coverage fuzzing, and the
  Linux-only bench suite (`.github/workflows/windows.yml:22-36`).
* **Threading.** A `Validator` is single-threaded/not thread-safe; one instance per thread or
  external synchronization (`src/validate/validator.zig:33-42`).
* **Platform semantics.** `llama-cpp` rejects non-native-endian files because upstream ggml does
  (`src/gguf/parser.zig:50-54`); use `--endian big` with `gguf-spec` for big-endian files.
* **Advisory provenance discipline is manual.** CVE cases require triaged primary sources;
  un-triaged advisories stay manifest-only placeholders and are neither generated nor asserted
  (`tests/negative_corpus.py:1-33`, `694-704`). As of this tree the placeholder registry is empty
  and three CVE fixtures are promoted (`tests/negative_corpus.py:577-691`).

Risks/unknowns for a reviewer to chase:

* `UNCONFIRMED:` whether the uncommitted working tree passes the full CI matrix; no suite was
  executed during authoring of this document.
* `UNCONFIRMED:` behavior on 32-bit hosts, non-Linux/macOS/Windows platforms, and non-little-endian
  hosts outside the covered matrix; no build or test was performed there.
* The `max_variable_array_elements` sanity cap is documented as **not** the primary DoS control
  (`src/gguf/limits.zig:18-24`); reviewers should confirm the budget charging sites in
  [§8](#8-work-budget) are exhaustive for new parser paths.

## 17. Audit target files and functions

Priority order for a deep review (highest attacker reachability first):

| # | Target | Functions / lines | Audit focus |
| :--: | :--- | :--- | :--- |
| 1 | `src/gguf/parser.zig` | `parseDocument` (`40-298`) | length/offset arithmetic, count-vs-size prechecks (`79-91`, `179-182`), descriptor loop bounds (`197-261`), zero-padding scan (`263-289`) |
| 2 | `src/gguf/metadata.zig` | `validateKey` (`33-53`), `validateUtf8Stream` (`57-101`), `skipMetadataValue` (`103-267`) | recursion depth, array count caps, bool/UTF-8 scanning, integer-width handling |
| 3 | `src/validate/structural.zig` | `validateStructural` (`19-153`) | contiguity chain arithmetic (`84-106`), bounds (`119-129`), sort/overlap (`143-152`) |
| 4 | `src/validate/arithmetic.zig` | all (`5-77`) | overflow classification order and divisibility invariant |
| 5 | `src/gguf/reader.zig` | `Reader.readBytes` (`14-19`), `BufferedReader.readBytesImpl` (`132-163`) | bounds before dispatch, window slide arithmetic, large-read bypass |
| 6 | `src/gguf/limits.zig` | `WorkBudget` (`31-76`), `QuotaAllocator` (`80-188`) | accounting saturation, `resize`/`free` correctness, quota flag |
| 7 | `src/validate/validator.zig` | `Validator` (`50-149`), `OwnedValidationState` (`151-195`), `Result` (`197-292`) | ownership/lifetime, double-free hazards, quota mirroring |
| 8 | `src/main.zig` | arg parsing (`79-142`), error mapping (`196-235`), `emitRejection`/`writeJsonString` (`275-421`) | exit-code contract, untrusted-string escaping, quota-vs-OOM split |
| 9 | `src/gguf/error.zig` | `categoryOf`/`messageOf` (`45-128`), `ParseContext` (`130-186`) | exhaustive mappings, snapshot lifetime |
| 10 | `src/gguf/types.zig` | pinned table (`1-131`) | must match pinned upstream (enforced by `tests/test_oracle_types.py`, `tests/differential.py`) |

Secondary targets: `build.zig` (test/fuzz/bench wiring, `38-123`), `src/root.zig:1-12` (public
surface), `tests/validator_test.zig` (2,436 lines; 77 tests), `tests/differential.py`,
`tests/real_corpus.py`, `tests/negative_corpus.py`, and the six workflows under
`.github/workflows/`.

## 18. Reproduction commands

Prerequisites: Zig 0.13.0, Python 3, and (oracle only) CMake + a C++ toolchain
(`README.md:40-44`, `AGENTS.md:5-9`). Run from the repository root; order matches CI
(`AGENTS.md:11-19`).

```sh
# --- Core (blocking CI order) -------------------------------------------------
zig fmt --check src/ build.zig tests/*.zig
python tests/generate_fixtures.py      # fresh clone: required before zig build test
zig build test --summary all           # unit + regression + fuzz corpus sweep
zig build -Doptimize=ReleaseSafe       # tests/cli_test.py tests whatever binary is installed
python tests/cli_test.py               # exit-code contract 0/2/64/70/74, JSON/context
python tests/negative_corpus.py        # generate + assert every negative case rejects (exit 2)
python scripts/version_consistency.py  # full clone with tags; exits 0 on match

# --- Oracle / differential (network clone + CMake; needs ReleaseSafe binary) ---
bash tests/build_oracle.sh             # pinned ggml 0.23.0 @ e91ded11; skips if built (--force rebuilds)
python tests/arithmetic_oracle.py      # bigint phase 1 + CLI phase 2
python tests/test_oracle_types.py      # 43/43 slots must match the C++ oracle
python tests/differential_matrix.py    # generate matrix/ fixtures BEFORE tests/differential.py
python tests/differential.py           # 3-column sweep vs pinned oracle; nonzero = failure
python tests/canary_drift.py           # advisory rolling-oracle canary (needs network)

# --- Fuzzing ------------------------------------------------------------------
python tests/fuzz_mutation.py --iterations 2000   # 4,000 executions; artifacts on failure
python tests/fuzz_mutation.py --test-crash-handler
python tests/fuzz/coverage_lane.py --zig zig --budget-seconds 1800 --smoke-seconds 300   # Zig 0.14.1 only

# --- Real corpus (network; verify exit codes) ---------------------------------
python tests/real_corpus.py --tier 1 --tolerate-download-errors   # PR mode: 0 PASS / 1 FAIL / 3 INCONCLUSIVE
python tests/real_corpus.py --tier 1                              # release mode: fail-closed
```

Exit-code expectations for a healthy tree: `real_corpus` returns `0`, `1`, or `3` per the taxonomy
in [§14](#14-real-corpus-methodology); all other commands above exit `0` (the differential report
JSON is written wherever `--report-json <path>` says). `zig build test` fails on a fresh clone until
`tests/generate_fixtures.py` has run (`AGENTS.md:57`). `tests/cli_test.py` silently tests the existing
`zig-out/bin/safegguf`, so rebuild ReleaseSafe first (`AGENTS.md:59`).

## 19. Expected CI signals

Blocking jobs (`.github/workflows/ci.yml`, push to `main`/`v*` tags + PRs):

| Job | Lines | Runs | Green means |
| :--- | :--- | :--- | :--- |
| `core` (ubuntu-24.04, macos-14) | `11-49` | fmt check, fixture generation, `zig build test --summary all`, ReleaseSafe build, `tests/cli_test.py`, `tests/negative_corpus.py` | Formatting clean; unit/regression/fuzz-corpus/CLI/negative contracts all pass |
| `version-consistency` | `55-71` | `scripts/version_consistency.py` on a full-history checkout | Embedded `build.zig` default equals the newest `v*` tag |
| `real-corpus` (tier 1; PR + `v*` tags only) | `87-123` | `tests/real_corpus.py --tier 1` | PR: exit `0`, or exit `3` mapped to a neutral notice; tag: strictly exit `0` (fail-closed) |
| `oracle` (ubuntu + macos) | `125-166` | pinned oracle build, arithmetic oracle, type oracle, matrix generation, differential sweep | Oracle identity pinned; types match; no unexpected verdict divergence |
| `fuzz` (ubuntu + macos) | `168-208` | crash-handler self-test + 2,000 mutation iterations | Zero crash/panic/leak/unexpected exit; artifacts uploaded on failure (`202-208`) |
| `bench` (ubuntu + macos) | `210-228` | `zig build bench --summary all` | Resource-budget benchmark suite passes (ReleaseSafe-pinned, `build.zig:62-74`) |
| `windows-gate` (tags only, reuses `.github/workflows/windows.yml`) | `236-241` | native Windows core lane | Windows binary validated on the tagged commit; a failed/skipped gate skips `release` |
| `release` (tags only) | `243-433` | needs all of the above (`251`) | Five target binaries + `SHA256SUMS.txt` + SPDX SBOM + Sigstore signature published **after** pre-publish verification |

`.github/workflows/windows.yml` also runs directly on `main` pushes and PRs (`.github/workflows/windows.yml:40-45`);
on tags it runs exactly once through the `windows-gate` call (`.github/workflows/windows.yml:4-10`).

Scheduled/advisory lanes (never required checks):

| Workflow | Cadence | Signal |
| :--- | :--- | :--- |
| `.github/workflows/nightly.yml` | cron `30 2 * * *` | Deep mutation campaigns (100k + 50k matrix), corpus evolution, sweep; 0 crash/panic/leak/unexpected exit (`.github/workflows/nightly.yml:1-26`, `420-452`) |
| `.github/workflows/coverage-fuzz.yml` | cron `17 3 * * *` | Advisory coverage-guided lane on Zig 0.14.1; validator crashes/timeouts/OOM fail; non-reproducing engine crashes are advisory (`.github/workflows/coverage-fuzz.yml:1-34`) |
| `.github/workflows/real-corpus.yml` | cron `17 5 * * *` | Report-only real-corpus run with report artifact; never blocks (`.github/workflows/real-corpus.yml:17-20`, `77-115`) |
| `.github/workflows/upstream-canary.yml` | cron `43 4 * * *` | Rolling Oracle B drift report; divergences never fail; only infrastructure failures can redden it (`.github/workflows/upstream-canary.yml:1-21`, `69-95`) |

Local equivalents for every blocking job are in [§18](#18-reproduction-commands). A red `core`,
`version-consistency`, `oracle`, `fuzz`, `bench`, or fail-closed `real-corpus` on a tag blocks the
release by construction (`.github/workflows/ci.yml:243-252`).

---

*This document is docs-only: it changes no code, tests, or workflows. Last updated against working
tree base `2322534` with uncommitted modifications present; re-derive line numbers if the tree
moves (`git diff --stat` before trusting a citation).*
