# Runbook A — Validator crash

**Scope:** a SafeGGUF validator process crashes (panic, fatal signal, abort), or exits
outside the documented fail-closed contract, on one concrete input. `exit 2` (REJECT,
including quota exhaustion) is *expected* for malformed input and is not a crash;
`exit 70` is an internal error / host OOM and must not be conflated with `exit 2`.

**Severity:** critical when reproducible from a released artifact; high otherwise.

**Artifacts this runbook refers to**

- Nightly mutation lane: `tests/fuzz-artifacts/crash-seed<seed>-iter<iter>.gguf` +
  `.json`, minimized `*-minimized` variant, `environment.info`, `sweep.log`.
- Coverage lane: `tests/fuzz-artifacts/coverage-fuzz/crash-<target>-<utc>.gguf`,
  `-minimized.gguf`, `.json` (strict incident schema: `layer`, `taxonomy`,
  `repro_status`, `input_sha256`, `commit`, `toolchain`, `command`,
  `first_failing_frame`, exact repro command), `<target>.log`.
- CI uploads: nightly → `gh run download <run-id> -n nightly-fuzz-artifacts-ubuntu-24.04 -D <dir>`;
  coverage → `-n coverage-fuzz-artifacts-ubuntu-24.04`.

## A1 — Quarantine the input

Copy the exact bytes into quarantine, content-addressed and read-only; never edit the
original artifact.

```sh
sha256sum <artifact>.gguf
install -m 0444 <artifact>.gguf /srv/quarantine/gguf/<sha256>.gguf
```

Record the mapping original artifact name → digest.

## A2 — Store the digest

- If the incident came from a fuzz lane, cross-check the incident JSON
  `input_sha256` against the quarantine digest (a mismatch means a corrupted or
  wrong artifact — stop and re-collect).
- Use the digest as the incident key in the tracker and in all reports.

## A3 — Preserve the artifact

Copy the full artifact set unchanged (original + minimized + JSON + lane log +
`environment.info` where present) into the incident record. Do not re-minimize or
truncate the preserved original. If the run is in CI, download it before retention
expires (90 days) and attach the download to the tracker.

## A4 — Collect version/commit

```sh
safegguf --version        # version, source_commit, zig, build_mode, target, ggml target/commit
git rev-parse HEAD
```

Compare with the incident JSON fields `commit` / `toolchain` / `command`. Record
whether the crash reproduces from a tagged release artifact or only from a dev build —
release impact depends on this.

## A5 — Disable affected release

- Find the releases containing the crashing commit: `git tag --contains <commit>`.
- Mark those tags affected in the tracking issue; pause promotion of new release
  artifacts from the affected line until the fix lands.
- If the crashing build is already public, follow `SECURITY.md`: report through the
  private advisory path first, then coordinate disclosure. Record the supported-version
  impact (`SECURITY.md` "Supported Versions").

## A6 — Reproduce

Minimal replay against the quarantined copy:

```sh
safegguf inspect /srv/quarantine/gguf/<sha256>.gguf \
  --profile <gguf-spec|llama-cpp> --endian <little|big|auto> --format json
```

Coverage-lane artifact (Zig 0.14.1 fuzz lane; see `tests/fuzz/README.md`):

```sh
SAFEGGUF_COV_FUZZ_REPRO=<artifact>.gguf \
SAFEGGUF_COV_FUZZ_PROFILE=<gguf-spec|llama-cpp> \
SAFEGGUF_COV_FUZZ_ENDIAN=<little|big> \
zig build fuzz-cov-repro
```

Pinned-toolchain reproduction and regression:

```sh
zig build -Doptimize=ReleaseSafe
cp /srv/quarantine/gguf/<sha256>.gguf tests/corpus/incident-<sha256-prefix>.gguf
zig build fuzz                      # corpus sweep through the harness
zig build test --summary all
python tests/fuzz_mutation.py --iterations 2000
```

Then root-cause, add a focused unit test in `tests/validator_test.zig`, and keep the
input in the committed regression set (corpus entry and/or
`tests/negative_corpus.py` case) so the sweep covers it permanently.

## A7 — Close

- Promotion rule: discover → minimize → root cause → fix → deterministic regression
  on the pinned 0.13.0 toolchain.
- Record in the incident issue: root cause, affected releases/tags, fix commit,
  regression test path, and the exact repro command that fails before / passes after.
- Re-enable release promotion only after the full gate is green
  (`zig fmt --check src/ build.zig tests/*.zig`, `zig build test --summary all`,
  `python tests/cli_test.py`, `python tests/negative_corpus.py`, the fuzz lanes).
