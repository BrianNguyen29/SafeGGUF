# Coverage-guided fuzz lane (A5)

Advisory nightly lane, complementary to the existing deterministic systems:

| system | toolchain | role |
| --- | --- | --- |
| `zig build test` / `zig build fuzz` | pinned **0.13.0** | unit + corpus-sweep regression (blocking) |
| `tests/fuzz_mutation.py`, nightly mutation legs | pinned **0.13.0** | deterministic mutation campaigns |
| `tests/fuzz/coverage_lane.py` (this lane) | **0.14.1, fuzz-only** | coverage-guided search (`std.testing.fuzz`) |

The pinned production toolchain remains 0.13.0; 0.14.1 exists only so the lane
can use Zig's built-in coverage fuzzer. The 0.13 `test`/`fuzz`/`bench` steps are
unchanged. `src/gguf/limits.zig` carries a dual-compat allocator-vtable shim
(`u8` vs `std.mem.Alignment` + `remap`) so the same production source compiles
on both toolchains; no validation behavior differs.

## Components

- `../fuzz_cov_target.zig` - `std.testing.fuzz` root, compiled once per
  profile x endian (`fuzz_options` build options) so each `--fuzz` invocation
  drives exactly one target and concurrent writers cannot race the shared
  `v/<digest>` coverage file.
- `../fuzz_cov_repro.zig` - single-input replay used by artifact minimization.
- `coverage_lane.py` - bounded wrapper around `zig build --fuzz`: time budget,
  process-group termination, `v/`/`f/` artifact parsing, corpus persistence,
  incident taxonomy + repro status, crash artifacts, advisory trend history.
- `build.zig` steps (only defined on Zig >= 0.14): `fuzz-cov-gguf-spec-little`,
  `fuzz-cov-gguf-spec-big`, `fuzz-cov-llama-cpp-little`,
  `fuzz-cov-llama-cpp-big`, `fuzz-cov-repro`.
- `.github/workflows/coverage-fuzz.yml` - nightly advisory lane.

## Running

```sh
python tests/generate_fixtures.py
python tests/fuzz/coverage_lane.py --zig zig --budget-seconds 1800 --smoke-seconds 300
```

Individual target (continuous, unbounded - Ctrl-C to stop):

```sh
zig build --fuzz fuzz-cov-gguf-spec-little --cache-dir .cache/coverage-fuzz/cache-manual
```

`zig build --fuzz` is an interactive continuous mode (web UI on a random local
port); the wrapper is what makes it CI-shaped. It signals the whole process
group (SIGINT, then SIGKILL) and treats "still fuzzing at the budget" as OK.

## Budget

- CI: `--budget-seconds 1800` (`--smoke-seconds 300`) = 30 min of fuzzing per
  platform across the required targets, plus startup/build time.
- Required targets: `gguf-spec/little`, `gguf-spec/big`, `llama-cpp/little`.
  `llama-cpp/big` is the optional smoke target.
- `--stall-seconds` (default 300) aborts a target whose run counter stops
  advancing (hang/OOM suspicion) and fails the lane.

## Corpus policy

- Seeds per run: generated `tests/corpus` plus the persisted corpus directory
  passed to the harness as `SAFEGGUF_COV_FUZZ_SEEDS`.
- The engine writes a new `f/<test-name>/N` file only when an input increases
  coverage; the lane promotes every entry except the highest index (the
  current mmapped input) into the persisted corpus, keyed by content sha256.
- Inputs are **never** kept because they PASS; malformed inputs are high-value;
  no llama-cpp acceptance requirement. Coverage is the only promotion gate.
- Persisted corpus caps: **10,000 entries / 256 MiB**, oldest pruned first
  (`tests/fuzz-artifacts/coverage-fuzz/coverage_summary.json` reports the
  inventory).
- Zig 0.14.1 does not persist the input length: `f/` files are sized to mmap
  capacity and may carry trailing NUL padding. Persisted entries are the
  engine's bytes exactly as stored; the lane does not invent an input size.

## Incident taxonomy and crash policy

Every non-ok target run is classified into exactly one taxonomy class, with a
repro status for the recovered input:

| taxonomy | detected by | lane |
| --- | --- | --- |
| `validator_crash` | crash trace tops out in `src/` or `tests/`; also the conservative default when no frame is classified | fails |
| `engine_crash` | crash trace tops out in Zig's `lib/fuzzer.zig` built-in fuzzer | fails if the recovered input reproduces; advisory (exit 0) if it does not |
| `timeout` | startup timeout, or no execution (run counter) progress for `--stall-seconds` | fails |
| `oom` | OOM markers in the lane log (`OutOfMemory`, `out of memory`, ...), or an early exit with no trace and a SIGKILL status | fails |

Crash markers are `panic:`, `Segmentation fault`, `all fuzz workers crashed`
and `failed with error`; a build that exits 0 before the budget is `failed`.

Repro status comes from replaying the recovered input (highest `f/` index)
through `zig build fuzz-cov-repro`:

- `repro_confirmed` - the replay crashed or hung; minimization runs,
- `repro_not_confirmed` - the replay exited cleanly,
- `repro_timeout` - the replay exceeded 300 s (original preserved, minimization
  skipped - every minimization probe would time out too),
- `repro_not_attempted` - no recoverable input, or a timeout/om incident where
  replaying a possibly-hanging input is not attempted.

An **engine-internal** crash whose recovered input does **not** reproduce is
the only advisory outcome: artifacts and metadata are preserved and reported
in the summary, but the lane exits 0. Everything else - validator crashes
(whether or not they replay), reproduced engine crashes, timeouts, OOM
incidents and unexpected exits - fails the lane (workflow red). This keeps the
lane actionable while Zig 0.14.1's built-in fuzzer stability is imperfect.

Artifacts under `tests/fuzz-artifacts/coverage-fuzz/`:

- `crash-<target>-<utc>.gguf` - recovered original (highest `f/` index),
- `crash-<target>-<utc>-minimized.gguf` - smallest prefix confirmed to still
  crash by `zig build fuzz-cov-repro` (trailing-NUL trim + bounded prefix
  truncation, <= 24 repro calls); if the repro does not confirm, the original
  is preserved unmodified and `minimization` records that,
- `crash-<target>-<utc>.json` - `taxonomy` (`validator_crash` |
  `engine_crash` | `timeout` | `oom`), crash site (`validator` | `engine` |
  `unknown`), `stack_top_frames`, `repro_status` + `repro_calls`,
  target/profile/endian/`host_endian`/`seed`, engine + Zig version, compiler,
  commit, platform, coverage stats, sanitizer story, input `sha256` + `sizes`
  (original, minimized), log excerpt and an exact repro command,
- `<target>.log` - full lane log for the target,
- `coverage_history.json` - advisory trend state (schema
  `safegguf-coverage-fuzz-history/2`): up to 90 per-run records, restored and
  saved through the `coverage-fuzz-history-*` actions/cache entry. On a cache
  miss the lane rebuilds it from the compact `recent_runs` embedded in the
  previous `coverage_summary.json` (or from that summary's totals alone), and
  the workflow additionally recovers both files from the latest completed
  run's uploaded artifact via `gh run download`. Never a gate,
- `coverage_summary.json` / `.txt` - per-target executions (`runs`), unique
  inputs (`unique`), covered PCs / coverage %, corpus growth (`promoted`,
  inventory), incident status + taxonomy + repro status, plus the advisory
  history block (`delta` / `targets_delta` against the previous record,
  `recent_runs`, and the recent `coverage_pct` trend). The `.txt` (and the
  workflow step summary) print the human-readable `delta coverage:` /
  `delta search:` / `delta corpus:` / `delta incidents:` / `delta repro:`
  lines and per-target `d_runs=` / `d_edges=` / `d_pct=` deltas; deltas are
  commit-relative and informational only, never enforced.

Repro command for a preserved artifact:

```sh
SAFEGGUF_COV_FUZZ_REPRO=tests/fuzz-artifacts/coverage-fuzz/<file>.gguf \
SAFEGGUF_COV_FUZZ_PROFILE=<gguf-spec|llama-cpp> \
SAFEGGUF_COV_FUZZ_ENDIAN=<little|big> \
zig build fuzz-cov-repro
```

Promotion rule: discover -> minimize -> root cause -> fix -> deterministic
regression on the pinned 0.13.0 toolchain before closure.

## Sanitizer story

- Debug safety checks (bounds/overflow/UB) plus `GeneralPurposeAllocator`
  leak detection (the harness panics on leak).
- Zig's built-in fuzzer in 0.14.1 has no ASan/UBSan runtime; panic, signal,
  timeout (startup/stall), OOM markers and SIGKILL are the detectable
  taxonomy above. Engine exit codes are not part of the contract here - any
  unexpected exit fails the lane, except the non-reproducing engine-internal
  crash classified advisory above.
