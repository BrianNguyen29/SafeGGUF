# Runbook C — False accept / downstream crash

**Trigger:** SafeGGUF reports PASS (`exit 0`) for a file that then crashes, corrupts, or
otherwise harms a downstream runtime; or an artifact is later found to violate an
invariant the validator should have caught.

**Severity: critical.** First establish whether the failure is inside SafeGGUF's
structural scope. `PASS` means the file satisfied the selected structural, arithmetic,
and resource checks — it is **not** a trust or malware verdict for model behavior,
templates, or downstream runtime code (`SECURITY.md`, invariant 5).

## C1 — Isolate the model

Stop all loads of the artifact and pin the exact bytes under investigation:

```sh
sha256sum /models/<file>.gguf
install -m 0444 /models/<file>.gguf /srv/quarantine/accepted/<sha256>.gguf
```

Freeze the source (read-only) so bytes cannot change during the investigation.

## C2 — Stop admission

- Fail closed at the gate: add the digest to the quarantine/deny set (or remove it from
  the CAS admission set) and pause the ingestion lane until the rule is understood.
- Keep the original PASS verdict JSON — it is evidence of exactly what was validated.
- Notify the downstream runtime owner and the security owner; treat as critical until
  scope is known.

## C3 — Reproduce downstream

Re-validate the exact digest and keep the provenance:

```sh
safegguf inspect /srv/quarantine/accepted/<sha256>.gguf \
  --profile llama-cpp --endian auto --format json
```

- Confirm the PASS and record `compatibility_target` (pinned ggml provenance).
- Reproduce in an isolated sandbox with the downstream runtime at a recorded version /
  commit; preserve the crash log, stack, and runtime version. Never reproduce in
  production.
- Cross-check the oracles:

```sh
tests/oracle/ggml_oracle --no-load /srv/quarantine/accepted/<sha256>.gguf
tests/oracle/ggml_oracle --load-data /srv/quarantine/accepted/<sha256>.gguf
python tests/canary_drift.py     # rolling upstream, report-only
```

If the failure is outside SafeGGUF's structural scope (weight semantics, prompt
template, runtime code), mark the incident out-of-contract and route to the downstream
owner — but still promote a regression fixture if the input violates an invariant.

## C4 — Promote a fixture

Add the case to `tests/negative_corpus.py` (`CASES` registry):

- Name it `synthetic-<bug-class>-<slug>.gguf` unless a **verifiable advisory** exists —
  `cve-*` names are allowed only with full triage provenance (`source_url`, `ghsa`,
  patched reference, `sha256`), enforced by `_require_triaged_provenance` and documented
  in the module docstring; never invent CVE identity or URLs (`SECURITY.md`,
  "Regression Fixture Provenance").
- Record `expected_behavior` (exit 2 + expected `error_code`), `expected_profile`, and
  the source mechanism.

Then:

```sh
zig build -Doptimize=ReleaseSafe
python tests/negative_corpus.py        # generates + verifies; every case must reject
```

Add the input to `tests/corpus/` so `zig build fuzz` sweeps it, and add a focused
unit/boundary test in `tests/validator_test.zig` for the invariant that was missed.

## C5 — Patch and release

- Fix the invariant violation; re-run the full gate:

```sh
zig fmt --check src/ build.zig tests/*.zig
python tests/generate_fixtures.py
zig build test --summary all
zig build -Doptimize=ReleaseSafe
python tests/cli_test.py
python tests/negative_corpus.py
bash tests/build_oracle.sh && python tests/differential.py
python tests/fuzz_mutation.py --iterations 2000
```

- Release a patch on the supported line (`SECURITY.md` "Supported Versions") and follow
  the release verification gates.
- If a released artifact is affected: open a private advisory first, coordinate
  disclosure, and state the PASS-scope boundary in the advisory. Re-enable the
  ingestion lane only after the fix is released and the digest denylist is reviewed.
