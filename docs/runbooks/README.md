# Incident Runbooks — SafeGGUF

Operational runbooks for the production admission gate and the assurance lanes.
Each runbook is written against this repository's tooling, commands, and artifact
paths; they describe diagnosis and release hygiene only — none of them changes
validation behavior.

## Which runbook?

| Symptom | Runbook |
| :--- | :--- |
| Validator crashes (panic / fatal signal / unexpected exit) on a concrete input | [Runbook A — Validator crash](runbook-a-validator-crash.md) |
| A file that should pass is rejected (exit 2), or a real-corpus entry fails | [Runbook B — False reject](runbook-b-false-reject.md) |
| Exit 0 (PASS) for a file that then crashes or corrupts a downstream runtime | [Runbook C — False accept / downstream crash](runbook-c-false-accept-downstream-crash.md) |
| A scheduled fuzz workflow is red (`Nightly Fuzz` / `Coverage Fuzz`) | [Runbook D — Fuzz nightly red](runbook-d-fuzz-nightly-red.md) |

Severity: Runbook C is **critical**, Runbook A is **critical when reproducible from a
released artifact**, Runbook B is compatibility/quality (not a memory-safety incident),
Runbook D is a routing runbook that may escalate into A.

## Exit-code contract (do not conflate)

| Exit | Meaning |
| :---: | :--- |
| `0` | PASS — file satisfies the selected profile's structural / arithmetic / resource checks |
| `2` | REJECT — malformed input **or** validator-managed quota exhaustion |
| `64` | Usage error |
| `70` | Internal software error / host OOM (not a REJECT) |
| `74` | File open / stat / read I/O error |

A *crash* is a fatal signal, panic/abort, or an exit outside `{0,2,64,70,74}` — never
`exit 2`. `PASS` is not a trust verdict (`SECURITY.md`, "Threat Model & Security
Invariants", invariant 5).

## Shared prerequisites

```sh
# Pinned toolchain: Zig 0.13.0 (see AGENTS.md). ReleaseSafe binary:
zig build -Doptimize=ReleaseSafe        # -> zig-out/bin/safegguf

# Fixtures + seed corpus are generated, gitignored; generate before any test run:
python tests/generate_fixtures.py
```

- Build provenance for any incident report: `safegguf --version` (version, source
  commit, Zig version, build mode, target, pinned ggml target/commit) plus
  `git rev-parse HEAD`.
- Preserve artifacts with their SHA-256; treat the digest as the incident key.
- Quarantine copies read-only (e.g. `install -m 0444`); never edit an incident
  artifact in place.
- Reproduce on the pinned 0.13.0 toolchain before closing: the coverage lane's
  promotion rule is *discover → minimize → root cause → fix → deterministic
  regression on the pinned 0.13.0 toolchain* (`tests/fuzz/README.md`).
- Escalation owner per class: validator/crash and false-accept incidents → security
  owner (private advisory path in `SECURITY.md`); lane/setup failures → CI owner.
