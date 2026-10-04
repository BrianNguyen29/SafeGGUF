# AGENTS.md

SafeGGUF: memory-safe GGUF v3 structural/arithmetic validator (Zig). Keep these invariants intact when changing anything.

## Toolchain

- Zig **0.13.0** pinned in CI only — no `.zig-version` file; install 0.13.0 yourself. Code uses 0.13.0 std APIs; do not "modernize" to newer Zig idioms.
- No `build.zig.zon` — zero Zig package dependencies, std only. Don't add packages.
- `VERSION` is the canonical source version; Docker metadata and release tags must match it. Run `python scripts/version_consistency.py` after changing release metadata.
- Python 3 for fixture generation and test harnesses; CMake + C++ compiler only for the upstream oracle.

## Commands (run from repo root, in this order — matches CI)

```sh
zig fmt --check src/ build.zig tests/*.zig
python tests/generate_fixtures.py   # writes gitignored tests/fixtures/*.gguf + tests/corpus/ seed corpus
zig build test --summary all        # unit + regression + fuzz corpus sweep; FAILS on fresh clone without fixtures
zig build -Doptimize=ReleaseSafe    # -> zig-out/bin/safegguf (plain `zig build` is Debug; cli_test.py runs whatever binary is installed)
python tests/cli_test.py            # e2e exit-code contract; needs fresh ReleaseSafe binary + fixtures
```

Standalone negative-corpus check (no `generate_fixtures.py` dependency; verify pass needs ReleaseSafe binary):

```sh
python tests/negative_corpus.py     # generates tests/fixtures/negative/ (fixtures + manifest.json) deterministically, then asserts every case rejects (exit 2) with its expected error_code
```

Real-corpus gate (`real-corpus` job in ci.yml; needs network + ReleaseSafe binary; verifies each manifest entry by size + sha256 before comparing per-profile verdicts; coverage floors mean 0 verified entries can never PASS):

```sh
python tests/real_corpus.py --tier 1 --tolerate-download-errors   # PR mode (ci.yml accepts 0|3): exit 0 PASS / 1 FAIL / 3 INCONCLUSIVE (NEUTRAL, tolerated network-only failure); real findings and unmet floors still fail
python tests/real_corpus.py --tier 1                              # fail-closed mode (v* tags/releases); an outage, skipped entry, or unmet floor blocks
```

Windows runtime lane (`.github/workflows/windows.yml`) runs `generate_fixtures.py` → `zig build test` → ReleaseSafe build → `cli_test.py` → `negative_corpus.py` natively on windows-latest. It runs directly on main pushes and pull requests and is also the release gate on `v*` tags: ci.yml reuses it via `workflow_call` as its tag-only `windows-gate` job, which `release` needs — a failed or skipped gate skips the release, so the Windows binary is never published without native validation of the tagged commit.

Expensive suites — network clone + CMake; only run when touching parsing/types/upstream-compat behavior:

```sh
bash tests/build_oracle.sh          # clones ggml v0.23.0 @ e91ded11 into .cache/ggml-upstream, builds tests/oracle/ggml_oracle; skips if binary exists (--force rebuilds)
python tests/arithmetic_oracle.py   # Python bigint oracle (no C oracle needed): phase 1 sweeps ~77k checked-arithmetic tuples; phase 2 CLI cross-checks, needs ReleaseSafe binary
python tests/test_oracle_types.py   # all 43 GGML type traits must match the oracle 100%
python tests/differential_matrix.py # generates deterministic matrix fixtures (tests/fixtures/matrix/); run BEFORE differential.py, which otherwise degrades to the hand-written fixtures only
python tests/differential.py        # SafeGGUF vs upstream oracle; needs ReleaseSafe binary + fixtures + oracle (auto-invokes build_oracle.sh if oracle missing)
python tests/fuzz_mutation.py --iterations 2000   # 4,000 executions across both profiles; --test-crash-handler verifies crash persistence
```

## Entrypoints

- `src/root.zig` — library root; re-exports all public modules (import as `safegguf`).
- `src/main.zig` — CLI: `inspect <file>` and `admit <file> --cas-dir <dir> --attestations-dir <dir>`. Both default to `llama-cpp` + `--endian auto`; fail-closed (unknown args exit 64). `--max-variable-array-elements N` caps `array[string]`/nested-array elements (default 1,000,000; range 1..10,000,000). Admission success emits schema v2; inspect diagnostics remain schema v1.
- `src/gguf/` — `types.zig` (pinned ggml type table + `Profile`), `error.zig`, `limits.zig` (quota/budget config), `reader.zig` (64 KiB sliding window), `metadata.zig`, `parser.zig`.
- `src/validate/` — `arithmetic.zig` (checked ops), `structural.zig` (profile rules), `validator.zig` (facade managing QuotaAllocator + WorkBudget).
- `tests/validator_test.zig` + `tests/fuzz_target.zig` — Zig test roots wired in `build.zig` (`zig build test` runs both; `zig build fuzz` runs the corpus sweep only). Python harnesses live in `tests/*.py`.

## Quirks that bite

- `zig build test` fails on a fresh clone: the fuzz target opens `tests/corpus` relative to CWD and that dir is generated, not committed. Always run `generate_fixtures.py` first.
- Generated artifacts are gitignored — never commit or hand-edit; regenerate instead: `zig-out/`, `.zig-cache/`, `tests/fixtures/*.gguf`, `tests/fixtures/matrix/`, `tests/fixtures/negative/`, `tests/corpus/*.gguf`, `tests/oracle/ggml_oracle`, `tests/fuzz-artifacts/`, `.cache/`.
- `cli_test.py` silently tests whatever binary sits at `zig-out/bin/safegguf` — a stale binary yields misleading passes; rebuild ReleaseSafe before running it.
- Zero-filled descriptor padding (`0x00`) is a deliberate anti-tamper safe-subset invariant enforcing the GGUF spec's zero-padding requirement — stricter than upstream runtimes, which may align past those bytes without validating their contents. Do not relax it.
- Quota exhaustion (`QuotaAllocator` ceiling exceeded) exits 2 (REJECT); unbudgeted host OOM exits 70. Do not conflate them.

## Exit codes (contract asserted by cli_test.py; do not renumber)

`0` PASS/help · `2` REJECT (malformed, out-of-bounds, or quota exceeded) · `64` usage/unknown arg · `70` internal error/host OOM · `74` file open/stat/read I/O error.

REJECT/ERROR JSON carries rich diagnostics: `error_code`, `category` (format|compatibility|arithmetic|resource|io|internal), `stage`, plus context (`tensor_index`/`tensor`/`expected_offset`/`key`) when known; text output mirrors the same fields (`src/main.zig`).

Every JSON output (PASS/REJECT/ERROR) also carries pinned-ggml provenance — `compatibility_target` (`llama-cpp`) / `type_layout_source` (`gguf-spec`) = `{project: "ggml", version, commit}` from `GGML_PINNED_*` (`src/main.zig`) — naming the type-table source the profile's layout rules derive from.

Admission documents have a separate version (`attestation_schema_version` in
`src/root.zig`). v2 binds every effective Limits field, requested/resolved
endianness and build provenance. `cas.relative_path` is relative to `--cas-dir`,
never its parent. The shell handoff delegates to `admit`; do not reintroduce a
separate inspect/hash/publish sequence. `scripts/render_k8s_manifest.py` renders
the Kubernetes template only from a version-matching digest-pinned release
image. `python tests/test_release_deployment.py` checks rendering offline.

Public source checks: `python scripts/check_public_tree.py` inspects staged
paths and Markdown links. Keep session notes, incident runbooks, archived audit
reports and local release records untracked; do not force-add ignored records.

## Profiles

- `gguf-spec` (opt-in): GGUF v3 only; arbitrary tensor order and gaps allowed; nested arrays allowed (depth ≤ 16); alignment multiple of 8; length-delimited tensor names.
- `llama-cpp` (default): GGUF v2+v3; strictly contiguous descriptors + checked trailing padding; nested arrays rejected; alignment power-of-two; embedded NUL tensor names rejected to prevent C-string aliasing.
- GGML type table is pinned to ggml 0.23.0 @ `e91ded11` (`src/gguf/types.zig` `GGML_PINNED_*`); deprecated slots and IDs ≥ 43 are rejected. The Zig table must stay in sync with pinned upstream — enforced by `test_oracle_types.py` and `differential.py`.
