# Runbook B — False reject

**Scope:** a file that should be admitted is rejected (`exit 2`), or a real-corpus
entry fails. Goal: classify **intentional profile/policy rejection** vs **regression**,
with pinned/rolling oracle evidence before any code or policy change.

Prophylactic note: production admission should use `--profile llama-cpp` explicitly —
the CLI default is `gguf-spec`, which is the looser profile and not the admission
contract for `llama.cpp`-style runtimes.

## B1 — Capture the corpus entry

Preserve exact bytes and the full verdict; the verdict JSON is evidence.

```sh
sha256sum <file>.gguf
install -m 0444 <file>.gguf /srv/quarantine/rejects/<sha256>.gguf
safegguf inspect /srv/quarantine/rejects/<sha256>.gguf \
  --profile <gguf-spec|llama-cpp> --endian auto --format json > verdict.json
```

From `verdict.json` record: `error_code`, `canonical_error_code`, `category`, `stage`,
context fields (`tensor_index` / `tensor` / `expected_offset` / `key`), and the
provenance block (`compatibility_target` / `type_layout_source` = pinned ggml commit).
Canonical codes are documented in `docs/error-codes.md`.

## B2 — Classify the rejection first

Common intentional causes; check them before treating the verdict as a bug:

- **Profile mismatch** — `gguf-spec` allows nested arrays, arbitrary tensor order and
  gaps (depth ≤ 16, alignment multiple of 8); `llama-cpp` requires strictly contiguous
  descriptors, checked trailing padding, native endianness, and rejects nested arrays.
- **Endianness** — the profile requires native byte order; `--endian auto` only detects
  the declared order, it does not relax the profile rule.
- **Variable-array sanity cap** — `--max-variable-array-elements` defaults to
  1,000,000 (accepted range 1..10,000,000); large tokenizer `array[string]` payloads can
  trip it. This is a deliberate sanity bound; re-run with an override only to triage,
  not to silently widen production policy.
- **Resource policy** — `QuotaAllocator` (128 MB default), `WorkBudget`
  (10,000,000 units) and the scanned-byte budget reject by design on hostile inputs.
- **Zero-padding invariant** — non-zero descriptor padding (`0x00`) is a deliberate
  anti-tamper rule, stricter than upstream runtimes that may align past those bytes.

If the rejection is intentional, document the code + invariant in the tracker and stop;
if the policy itself is too strict for a real model family, that is a policy decision
with its own review — not a validator bug.

## B3 — Compare the pinned oracle (Oracle A)

```sh
bash tests/build_oracle.sh                 # pinned ggml 0.23.0 @ e91ded11 (skips if built; --force rebuilds)
python tests/differential.py --report-json .cache/differential-report.json
python tests/test_oracle_types.py          # 43/43 type traits must match upstream
```

Single-file verdicts against the same oracle binary:

```sh
tests/oracle/ggml_oracle --no-load /srv/quarantine/rejects/<sha256>.gguf
tests/oracle/ggml_oracle --load-data /srv/quarantine/rejects/<sha256>.gguf
```

Interpretation:

- Upstream also rejects → not a SafeGGUF regression; the file is malformed for the
  pinned baseline. Confirm the expected rejection is recorded (see
  `EXPECTED_MATRIX` in `tests/differential.py`).
- Upstream accepts, SafeGGUF rejects, and the shape is **not** in `EXPECTED_MATRIX` →
  candidate regression: preserve the fixture and proceed to B6.
- Upstream accepts and the shape **is** a documented divergence → intentional; cite the
  matrix rationale.

## B4 — Compare the rolling oracle (Oracle B)

```sh
python tests/canary_drift.py               # resolves upstream master to one SHA; report-only
```

Rolling divergences never fail CI and are **compatibility signals, not bugs**: a
rolling accept that the pinned baseline rejects is triage input, not an automatic
false reject. Baseline updates require human review plus an explicit commit.

## B5 — Real-corpus check

```sh
python tests/real_corpus.py --tier 1 --tolerate-download-errors
```

A manifest entry that previously passed and now fails is a regression. A new real model
that fails: classify in B2/B3 and, if it should pass, add it to
`tests/real-corpus-manifest.json` with its expected profile/verdict only after the fix.

## B6 — Classify and act

- **Regression:** add the input to `tests/corpus/` (so `zig build fuzz` sweeps it) and a
  focused unit test to `tests/validator_test.zig`; fix; then extend
  `EXPECTED_MATRIX` in `tests/differential.py` only after human review — it is the
  pinned compatibility contract. Re-run the full gate from Runbook A/A7.
- **Intentional:** close with the invariant and evidence links; update only docs whose
  wording was wrong — never relax an invariant to silence a false reject.
