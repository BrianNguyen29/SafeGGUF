# Runbook D — Fuzz nightly red

**Trigger:** a scheduled fuzz workflow is red:

- `Nightly Fuzz` (`nightly.yml`) — blocking deterministic lane on pinned Zig 0.13.0:
  mutation campaigns, corpus evolution, and the `zig build fuzz` corpus sweep.
- `Coverage Fuzz (Zig 0.14.1 advisory)` (`coverage-fuzz.yml`) — advisory coverage lane;
  `validator_crash`, `unknown_crash`, `timeout`, `oom` fail it, a non-reproducing
  `engine_crash` does not.
- `Upstream Canary` (`upstream-canary.yml`) — report-only drift lane; red means
  infrastructure (SHA resolution / oracle build), not a validation failure.

**Principle:** classify first — **harness/setup vs infrastructure vs engine vs
validator**. Only validator-class red is a product bug. Do not report setup flakes as
validator crashes, and do not leave a validator-class red open for days without an
issue.

## D1 — Identify the lane and pull the artifacts

```sh
gh run list --workflow nightly.yml --limit 5
gh run list --workflow coverage-fuzz.yml --limit 5
gh run view <run-id> --log-failed

# artifacts
gh run download <run-id> -n nightly-fuzz-artifacts-ubuntu-24.04 -D /tmp/incident-nightly
gh run download <run-id> -n coverage-fuzz-artifacts-ubuntu-24.04 -D /tmp/incident-coverage
```

Artifact map:

- Nightly: `tests/fuzz-artifacts/crash-*.gguf|.json`, minimized variant,
  `environment.info` (commit, toolchain, RNG seeds, corpus manifest, sanitizer story),
  `sweep.log`; the workflow's `report` step already minimizes the newest crash.
- Coverage: `tests/fuzz-artifacts/coverage-fuzz/crash-<target>-<utc>.gguf`,
  `-minimized.gguf`, `.json` (strict schema: `layer`, `taxonomy`, `repro_status`,
  `input_sha256`, `commit`, `toolchain`, `command`, `first_failing_frame`),
  `coverage_summary.json|.txt`, `<target>.log`.

## D2 — Classify

| Class | Signals | Action |
| :--- | :--- | :--- |
| Harness / setup | coverage taxonomies `setup_missing_corpus` (no generated `tests/corpus`), `setup_file_not_found`, `setup_build_failure`, `setup_error`; nightly missing corpus, `py_compile` failure of the driver | fix the workflow/setup step (run `python tests/generate_fixtures.py` first), rerun via `workflow_dispatch`; not a validator bug |
| Infrastructure | runner outage, cache/network failures, job timeout with no execution progress, artifact upload failure | rerun; if recurring, open a CI-infra issue; no product change |
| Engine | coverage `engine_crash`: crash trace tops out in Zig's built-in `lib/fuzzer.zig` | advisory when the recovered input does **not** reproduce (`repro_not_confirmed`); if it reproduces, treat as validator-class |
| Validator | coverage `validator_crash`, `unknown_crash` (after a standalone replay confirms), `timeout`, `oom`; nightly `CRASH_SIG*`, `UNEXPECTED_EXIT_*`, `TIMEOUT` | open a tracking issue **immediately** and run Runbook A |

The coverage lane's split is precise: a crash is a `validator_crash` only when proven
by the target process (fatal signal, or panic/worker-crash marker with a nonzero exit)
with a stack touching `src/`/`tests/`, or when a deterministic standalone replay of the
recovered input confirms it; harness/setup failures are classified before crash
taxonomies and are never reported as validator crashes.

Reproduce a coverage artifact on the fuzz-only toolchain:

```sh
SAFEGGUF_COV_FUZZ_REPRO=tests/fuzz-artifacts/coverage-fuzz/<file>.gguf \
SAFEGGUF_COV_FUZZ_PROFILE=<gguf-spec|llama-cpp> \
SAFEGGUF_COV_FUZZ_ENDIAN=<little|big> \
zig build fuzz-cov-repro
```

Replay a nightly mutant through the pinned lane:

```sh
python tests/generate_fixtures.py
python tests/fuzz_mutation.py --iterations 2000 --seed <seed-from-artifact>
```

## D3 — Red-duration discipline

- A validator-class red gets a tracking issue the same day with: run URL, workflow,
  commit, taxonomy, `input_sha256`, artifact link, and the exact repro command.
- A lane must not stay red for multiple days without an issue/owner. If the lane is
  broken (setup/infra), fixing the lane is the deliverable; if the product is broken,
  the fix + deterministic regression on pinned 0.13.0 is the deliverable (Runbook A).
- Escalate to the security owner when a validator crash reproduces from a released tag;
  follow `SECURITY.md` (private advisory) for any release-affecting finding.

## D4 — Exit criteria

- Lane green again (or an advisory `engine_crash` documented as non-reproducing), and
- incident closed with: taxonomy, root cause, fix commit (if any), regression test
  path, and a link to the green rerun.
