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
  crash artifacts.
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

## Crash policy

A target fails (lane exits non-zero, workflow red) on:

- a **harness** crash - a worker crash (`panic:`, `Segmentation fault`,
  `all fuzz workers crashed`, `failed with error`) whose trace tops out in
  `src/` or `tests/` - whether or not the recovered input replays, or
- a worker crash that is not trace-classified (conservative default), or
- a build that exits early with a non-zero status, or
- startup/stall timeout.

An **engine-internal** crash - trace top frames in Zig's `lib/fuzzer.zig`
built-in fuzzer (for example a spontaneous SIGSEGV in
`appendSliceAssumeCapacity`) - whose recovered input does **not** reproduce
under `fuzz-cov-repro` is classified `engine_crash` (advisory): artifacts and
metadata are preserved and reported in the summary, but the lane exits 0.
Reproduced crashes always fail the lane. This keeps the lane actionable while
Zig 0.14.1's built-in fuzzer stability is imperfect.

Artifacts under `tests/fuzz-artifacts/coverage-fuzz/`:

- `crash-<target>-<utc>.gguf` - recovered original (highest `f/` index),
- `crash-<target>-<utc>-minimized.gguf` - smallest prefix confirmed to still
  crash by `zig build fuzz-cov-repro` (trailing-NUL trim + bounded prefix
  truncation, <= 24 repro calls); if the repro does not confirm, the original
  is preserved unmodified and `minimization` records that,
- `crash-<target>-<utc>.json` - target/profile/endian, crash site
  (`harness` | `engine` | `unknown`) and repro result, engine + Zig version,
  compiler, commit, platform, coverage stats, sanitizer story, log excerpt and
  an exact repro command,
- `<target>.log` - full lane log for the target,
- `coverage_summary.json` / `.txt` - per-target runs, unique runs, covered
  PCs, coverage %, promoted entries and corpus inventory.

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
  OOM exit and stall are the detectable taxonomy. Engine exit codes are not
  part of the contract here - any unexpected exit fails the lane, except the
  non-reproducing engine-internal crash classified advisory above.
