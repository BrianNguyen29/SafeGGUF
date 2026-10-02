# SafeGGUF

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Zig 0.13.0](https://img.shields.io/badge/Zig-0.13.0-orange.svg?style=flat-square&logo=zig)](https://ziglang.org/download/0.13.0/release-notes.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Release: v0.3.7-dev](https://img.shields.io/badge/release-v0.3.7--dev-blue.svg?style=flat-square)](https://github.com/BrianNguyen29/SafeGGUF/releases)
[![ggml 0.23.0 (e91ded11)](https://img.shields.io/badge/ggml-0.23.0%20%28e91ded11%29-blueviolet.svg?style=flat-square)](https://github.com/ggml-org/ggml/tree/e91ded11bdcd78c42f9c8d3978ff6686eb4c1226)
[![Container: Distroless](https://img.shields.io/badge/container-distroless-2496ED.svg?style=flat-square&logo=docker)](Dockerfile)

SafeGGUF is a memory-safe, overflow-checked structural and arithmetic validator
for GGUF model files — a fail-closed pre-admission gate for untrusted uploads,
written in Zig with no external package dependencies.

This tree is the development snapshot for **0.3.7-dev**; the latest tagged
release is **v0.3.6** (2026-09-15). Only released artifacts are supported — see
[SECURITY.md](SECURITY.md).

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [API](#api)
- [Security](#security)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Checked arithmetic on attacker-controlled values.** Dimensions, offsets,
  alignments, and sizes use `checkedAdd`/`checkedMul`/`checkedAlignUp`; overflow
  exits `2`. Exercised by regression, the pinned ggml differential oracle, and
  mutation fuzzing; a fixture covers CVE-2025-53630 / GHSA-vgg9-87g3-85w8
  (`llama-cpp` profile).
- **Bounded memory, fail-closed admission.** A 64 KiB sliding-window reader;
  `QuotaAllocator` (128 MiB default) and `WorkBudget` (10,000,000 units, 256 MiB
  scanned bytes) cap validator-managed work; exit taxonomy `0`/`2`/`64`/`70`/`74`;
  descriptor validation (`safegguf_validate_fd_v1` / `safegguf.validate_fd`) or a
  CAS digest handoff ([Kubernetes example](#kubernetes)).
- **Profiles and interfaces.** `llama-cpp` (unified default across the CLI,
  C ABI, and Python bindings: v2/v3 pre-admission subset, differential-tested
  against pinned ggml 0.23.0 `e91ded11`) and `gguf-spec` (GGUF v3 safe subset;
  opt in with `--profile gguf-spec`); CLI, C ABI, Python bindings; metrics/JSON
  logs on stderr; distroless container, K8s init pattern, hybrid triage
  ([deployment guide](docs/production_deployment.md)).

## Quick Start

Requires Zig 0.13.0.

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git && cd SafeGGUF
zig build -Doptimize=ReleaseSafe
./zig-out/bin/safegguf inspect /path/to/model.gguf --profile llama-cpp --endian auto --format json
```

Exit `0` passed, `2` rejected ([Exit Codes](#exit-codes)); `--version` prints provenance.

## Installation

Requires Zig 0.13.0 (pinned in CI and the Dockerfile); Python 3 only for fixtures
and Python test harnesses, CMake and a C++ compiler only for the optional
upstream ggml oracle; no Zig package dependencies — std only.

```bash
zig build -Doptimize=ReleaseSafe
python3 -m pip install ./bindings/python   # or: python3 -m pip wheel ./bindings/python --no-deps -w dist
```

| Artifact | Contents |
| :--- | :--- |
| `zig-out/bin/safegguf` | CLI executable |
| `zig-out/lib/libsafegguf.so`, `libsafegguf.a` | C ABI shared/static libraries (`libsafegguf.dylib` on macOS, `safegguf.dll` on Windows) |

The multi-stage [`Dockerfile`](Dockerfile) cross-compiles with Zig and ships on
`gcr.io/distroless/static-debian12:nonroot` (multi-arch manifest digest, UID
65532 `nonroot`, target under 5 MB); build/run commands are under [Docker](#docker).
The wheel bundles the native library built from the same commit and reports its
version. Tagged releases publish cross-platform binaries (`x86_64-linux`,
`aarch64-linux`, `x86_64-macos`, `aarch64-macos`, `x86_64-windows`),
`SHA256SUMS.txt`, a keyless Sigstore bundle, and an SPDX 2.3 SBOM (GitHub
attestations cover the binaries; [SECURITY.md](SECURITY.md)). Source builds run
on Linux/macOS/Windows, release binaries on x86_64/aarch64 Linux and macOS plus
x86_64 Windows, and containers on `linux/amd64`/`linux/arm64`.

## Usage

### CLI

```
safegguf inspect <path_to_model.gguf> [options]
```

```bash
safegguf inspect /path/to/model.gguf --profile llama-cpp --endian auto     # text (default)
safegguf inspect /path/to/model.gguf --profile llama-cpp --format json    # JSON on stdout
safegguf inspect /path/to/model.gguf --max-file-size-bytes 17179869184 --require-stable-file  # v1.1 controls
safegguf inspect /path/to/model.gguf --max-string-bytes 131072 --key-policy lenient           # v1.2 relief (opt-in)
safegguf inspect /path/to/model.gguf --emit-metrics --log-json --request-id req-123 --tenant-id tenant-a  # stderr
```

The CLI defaults match the C ABI and Python bindings: `--profile llama-cpp`
and `--endian auto` (byte order is detected, falling back to little-endian).
Opt into the resource-bounded GGUF v3 safe subset with `--profile gguf-spec`,
or pin `--endian little|big` explicitly.

Relief flags are opt-in and leave the defaults fail-closed:
`--max-string-bytes <N>` raises the 65536-byte metadata key/string cap, and
`--key-policy lenient` admits `-` and uppercase ASCII letters in metadata keys.
Both are also available as `SAFEGGUF_MAX_STRING_BYTES` / `SAFEGGUF_KEY_POLICY`,
as the appended C ABI `max_string_bytes` / `key_policy` option fields (v1.2),
and as Python `validate_path` / `validate_fd` parameters; the same file yields
the same default verdict through every surface.

> **Change note (0.3.7-dev).** The CLI default flipped from `gguf-spec` /
> little-endian to `llama-cpp` / auto to match the C ABI and Python defaults.
> C ABI callers passing `NULL` options always had llama-cpp + auto; a
> zero-initialized options struct still means gguf-spec + little. Pin
> `--profile` / `--endian` (or set the struct fields explicitly) if you relied
> on the old CLI default. The legacy `error_code` strings are unchanged; the
> llama.cpp dimension-product guard now resolves to the canonical detail
> `SGGUF_E_DIMENSION_OVERFLOW` (`canonical_error_code` in JSON,
> `safegguf_result_canonical_error_code()` in the C ABI) while its
> `error_code` stays `E_CompatibilityViolation`.

### Exit Codes

| Exit | Constant (`include/safegguf.h`) | Meaning |
| :---: | :--- | :--- |
| `0` | `SAFEGGUF_OK` | PASS: the file satisfies the selected profile's structural, arithmetic, and resource checks |
| `2` | `SAFEGGUF_REJECT` | REJECT: malformed input, checked-arithmetic overflow, or validator-managed quota exhaustion |
| `64` | `SAFEGGUF_EX_USAGE` | Usage/argument error, including unknown flags and invalid option values |
| `70` | `SAFEGGUF_EX_SOFTWARE` | Internal software error or host OOM (not a REJECT) |
| `74` | `SAFEGGUF_EX_IOERR` | File open, stat, or read I/O error |

### JSON Diagnostics

Every ERROR/REJECT object carries `schema_version`, `status`, `error_code`
(compatibility identifier), `canonical_error_code` (stable `SGGUF_E_*`),
`category`, `stage`, and context fields when known; PASS objects carry `checks`
and an empty `findings` array. The CLI emits one line; this REJECT is
pretty-printed:

```json
{"schema_version": 1, "status": "REJECT", "profile": "llama-cpp",
 "compatibility_target": {"project": "ggml", "version": "0.23.0", "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"},
 "error": "ArithmeticOverflow", "error_code": "E_ArithmeticOverflow", "canonical_error_code": "SGGUF_E_ARITHMETIC_OVERFLOW",
 "category": "arithmetic", "stage": "structural", "message": "Checked arithmetic overflow while computing tensor layout",
 "tensor_index": 1, "tensor": "cve-2025-53630-cumulative-1", "offset": 9223372036854775808, "expected_offset": 9223372036854775808, "findings": [{"code": "E_ArithmeticOverflow", "severity": "reject"}]}
```

Policy engines should key on `canonical_error_code` — or map
`safegguf_result_t.error_code` via `safegguf_canonical_error_code()` over the
C ABI. Legacy `error_code` is unchanged; additive fields keep `schema_version`
1, a breaking change increments it ([`docs/error-codes.md`](docs/error-codes.md)).

### Build Provenance

`--version` reports `SafeGGUF 0.3.7-dev`, source commit, `zig: 0.13.0`,
`build_mode: ReleaseSafe`, target, and pinned `ggml_target: 0.23.0` /
`ggml_commit: e91ded11bdcd78c42f9c8d3978ff6686eb4c1226` (source tree/toolchain
only; no wall-clock timestamp). JSON outputs carry the same provenance under
`compatibility_target` (`llama-cpp`) or `type_layout_source` (`gguf-spec`);
source builds report the embedded default version (CI checks it against the latest tag), release artifacts the built tag.

## Configuration

### CLI Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--endian <little\|big\|auto>` | `little` | Byte order. `auto` detects from the magic/version bytes. |
| `--format <text\|json>` | `text` | Output format. |
| `--profile <gguf-spec\|llama-cpp>` | `gguf-spec` | Validation profile; see [Profiles](#profiles). |
| `--max-variable-array-elements <N>` | `1000000` | Cap on string and nested-array elements. Accepted range `1..10000000`. |
| `--max-memory-mb <N>` | `128` | Maximum validator-managed allocation quota, in MiB. |
| `--max-work-budget <N>` | `10000000` | Maximum logical work units. |
| `--max-file-size-bytes <N>` | no limit | Reject files larger than `N` bytes before the first read. |
| `--require-stable-file` | off | Reject a PASS verdict if the open file's dev/inode/size/mtime/ctime change during validation. A bounded identity check, not cryptographic immutability. |
| `--emit-metrics` | off | Emit per-run metrics JSON to stderr. |
| `--log-json` | off | Emit one structured JSON log record to stderr (adds a SHA-256 file digest). |
| `--request-id <id>` | random per run | Correlation id for `--log-json`. |
| `--tenant-id <id>` | unset | Tenant id for `--log-json`; logged only as a SHA-256 pseudonym. |
| `--help`, `-h` / `--version` | — | Print usage, or version and build provenance, and exit `0`. |

### Environment Variables

| Variable | Effect | Default |
| :--- | :--- | :--- |
| `SAFEGGUF_MAX_MEMORY_MB` | Allocation quota in MiB. | `128` |
| `SAFEGGUF_MAX_ALLOC_BYTES` | Allocation quota in bytes; applied after `SAFEGGUF_MAX_MEMORY_MB`. | 128 MiB |
| `SAFEGGUF_MAX_WORK_BUDGET` | Logical work-unit budget. | `10000000` |
| `SAFEGGUF_MAX_WORK_UNITS` | Logical work-unit budget; applied after `SAFEGGUF_MAX_WORK_BUDGET`. | `10000000` |
| `SAFEGGUF_MAX_SCANNED_BYTES` | Scanned-byte budget for streaming string, UTF-8, and boolean scans. | 256 MiB |

CLI flags override environment values; malformed environment values are ignored.

### Profiles

| Profile | GGUF versions | Tensor layout | Nested metadata arrays | Alignment | Endianness |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gguf-spec` (default) | v3 only | Arbitrary descriptor order and gaps allowed | Allowed, depth ≤ 16 | Multiple of 8 | `little`, `big`, or `auto` |
| `llama-cpp` | v2 and v3 | Strictly contiguous in descriptor order, with checked trailing padding | Rejected | Power of two | Host-native only; non-native byte order is rejected |

The GGML type table is pinned to ggml 0.23.0 (`e91ded11`): 43 slots, 35 active
types; deprecated slots and IDs ≥ 43 are rejected. Zero-filled descriptor padding
is enforced in both profiles (anti-tamper; stricter than runtimes that align past
those bytes).

### Resource Budgets

| Budget | Default | Scope |
| :--- | :--- | :--- |
| Allocation quota (`QuotaAllocator`) | 128 MiB | Parser tables, metadata structures, strings, sorting buffers |
| Work budget (`WorkBudget`) | 10,000,000 units | Parser and structural-validator operations |
| Scanned-byte budget | 256 MiB | Streaming string, UTF-8, and boolean scans |

Validator-managed quotas only — not process RSS, page cache, stack, CPU time, or
kernel overhead. For hostile multi-tenant uploads add OS/container limits
(cgroup memory, CPU quota + wall-clock timeout, file-size limit, read-only FS,
seccomp); see [SECURITY.md](SECURITY.md), "Deployment Limits".

### Observability

Metrics counters are recorded every run; JSON emission is opt-in and always
stderr (stdout stays one result document). `--log-json` writes one structured
record (verdict, timing, budgets, SHA-256 digest, request/tenant ids — tenant pseudonymized); emission failures never change a verdict or exit code.

## Deployment

```
  upload             stage              validate             CAS by digest           load
model.gguf ------> private staging ----> safegguf inspect ----> validated/<sha256> ----> llama.cpp
(mutable)          (exact copy)         (fail-closed)          (sha256 -c gate)        (digest-pinned)
```

### Docker

The [container release pipeline](.github/workflows/container-release.yml) builds
`linux/amd64`/`linux/arm64` images (arm64 run under QEMU), emits an SBOM and SLSA
provenance (`provenance: mode=max`), signs the image digest with keyless Cosign
OIDC, and publishes `ghcr.io/briannguyen29/safegguf` for `v*` tags after every
validation job passes (tags: release version, `major.minor`, `latest`).

```bash
docker build -t safegguf:latest .
docker run --rm -v "$(pwd)/models:/models:ro" safegguf:latest \
  inspect /models/model.gguf --profile llama-cpp --format json
```

### Kubernetes

[`deploy/k8s/safegguf-initcontainer.yaml`](deploy/k8s/safegguf-initcontainer.yaml)
implements the stage → validate → digest-pin → load flow: the upload is copied
once into private staging, validated, then hashed and atomically renamed to
`validated/<sha256>`; the serving container loads only the digest-named CAS
entry, never the mutable upload path. Read-only mounts, `runAsNonRoot` UID 65532
contexts, and seccomp profiles are in the manifest; the companion script
[`deploy/k8s/attestation_handoff.sh`](deploy/k8s/attestation_handoff.sh)
provides the same handoff outside Kubernetes.

| Phase | Container | Action |
| :--- | :--- | :--- |
| 0 | `safegguf-staging-copy` | Copy the upload once into `/private-stage/model.gguf` |
| 1 | `safegguf-pre-admission-validator` (`ghcr.io/briannguyen29/safegguf:v0.3.7-dev` at HEAD; substitute a release tag) | `inspect /private-stage/model.gguf --profile llama-cpp --format json --endian auto` |
| 2 | `safegguf-attestation-generator` | SHA-256 the validated bytes, atomically rename to `validated/<sha256>`, write the digest to `/attestation/model.gguf.sha256` |
| load | `llama-cpp-server` | Verify with `sha256sum -c`, then load `/validated/$DIGEST` |

## API

### Python Bindings

The `safegguf` package exposes `validate_path` and `validate_fd`
(descriptor-based, anti-TOCTOU), with the same profiles, endianness options,
and resource controls as the CLI, including the v1.1 `max_file_size_bytes` and
`require_stable_file` controls and the v1.2 `max_string_bytes` /
`key_policy` relief parameters (both default to the engine defaults, so
omitting them is fail-closed); `safegguf.version()` returns the native library
version. Library lookup: `SAFEGGUF_LIB_PATH` (absolute regular file), packaged
wheel, source `zig-out`, platform search; unenforceable controls fail closed
with `E_USAGE_UNSUPPORTED_OPTIONS` (exit `64`). See [`bindings/python`](bindings/python).

### C ABI

[`include/safegguf.h`](include/safegguf.h) exports `safegguf_validate_path_v1` /
`safegguf_validate_fd_v1` (legacy `safegguf_validate_path` /
`safegguf_validate_fd`), `safegguf_version`, `safegguf_canonical_error_code`,
and `safegguf_result_canonical_error_code` (resolves context-dependent
canonical details such as `SGGUF_E_DIMENSION_OVERFLOW` from a whole result),
with exit constants `SAFEGGUF_OK`, `SAFEGGUF_REJECT`, `SAFEGGUF_EX_USAGE`,
`SAFEGGUF_EX_SOFTWARE`, `SAFEGGUF_EX_IOERR` and option enums
`SAFEGGUF_PROFILE_LLAMA_CPP` / `SAFEGGUF_ENDIAN_AUTO`. `safegguf_options_v1_t`
is caller-owned; `struct_size` gates appended fields, so a v1.0-layout caller
keeps the legacy defaults (`max_file_size_bytes = 0`, `require_stable_file = 0`)
and a v1.1-layout caller keeps the default string cap and strict key grammar,
unknown sizes exit `64`; concurrent calls are safe if the struct is not mutated
mid-call. `NULL` options select the engine defaults (llama-cpp + auto), while a
zero-initialized struct means gguf-spec + little.

## Security

Threat model, security invariants, release verification, supported versions, and
vulnerability reporting live in [SECURITY.md](SECURITY.md); regression coverage
includes the CVE-2025-53630 advisory fixture (see [Features](#features)). `PASS`
is a structural/arithmetic/resource-policy verdict, not a trust or malware
verdict.

Tagged releases publish binaries, `SHA256SUMS.txt`, a keyless Sigstore bundle
(`SHA256SUMS.txt.sigstore.json`), and an SPDX 2.3 SBOM (`safegguf.spdx.json`);
GitHub artifact attestations cover the binaries, and container images are signed
with keyless Cosign (commands in [SECURITY.md](SECURITY.md), "Release Verification").

### Historical Verification Snapshot

Historical snapshot of the internal multi-agent campaign (18 suites, more than
76,000 checks, all meeting expected verdicts) in the
[archived audit report](docs/archive/production_audit_report.md); not live CI.

| # | Suite / security domain | Scope | Scale | Result |
| :---: | :--- | :--- | :--- | :--- |
| 01 | Zig unit & fuzz sweep | 35 active GGML types, limits, memory, sliding-window reader, checked arithmetic, fuzz corpus | 78 / 78 tests | PASS |
| 03 | Negative corpus suite | 6 synthetic bug classes; 3 advisory placeholders (manifest-only) | 15 / 15 cases | REJECT (exit 2) |
| 04 | BigInt arithmetic oracle | alignUp, product, and tensorBytes cross-checked against Python BigInt | 74,626 ops | PASS |
| 10 | C-ABI adversarial probes | NULL, invalid handles, TOCTOU | 57 / 57 probes | PASS |
| 18 | Cloud-native packaging audit | Distroless nonroot image, K8s manifest, docs completeness | 18 / 18 checks | PASS |

## Documentation

| Document | Contents |
| :--- | :--- |
| [`docs/production_deployment.md`](docs/production_deployment.md) | Production deployment and integration guide |
| [`docs/error-codes.md`](docs/error-codes.md) | Canonical `SGGUF_E_*` namespace and JSON schema versioning policy |
| [`docs/runbooks/README.md`](docs/runbooks/README.md) | Incident runbooks: validator crash, false reject, false accept/downstream crash, fuzz nightly red |
| [`SECURITY.md`](SECURITY.md) | Threat model, security invariants, release verification, vulnerability reporting |
| [`docs/archive/production_audit_report.md`](docs/archive/production_audit_report.md) | Archived internal audit report (historical) |
| [`AGENTS.md`](AGENTS.md) | Repository invariants, toolchain pinning, command reference |

## Contributing

Contributions are welcome via GitHub issues and pull requests; keep the
repository invariants in [`AGENTS.md`](AGENTS.md) intact.

### Development and Testing

Run from the repository root, in this order (matches CI):

```sh
zig fmt --check src/ build.zig tests/*.zig
python3 tests/generate_fixtures.py     # writes gitignored fixtures + seed corpus
zig build test --summary all           # unit + regression + fuzz corpus sweep
zig build -Doptimize=ReleaseSafe       # -> zig-out/bin/safegguf
python3 tests/cli_test.py              # end-to-end exit-code contract
python3 tests/negative_corpus.py       # negative corpus + advisory provenance (exit 2)
```

`zig build test` fails on a fresh clone until fixtures are generated (the fuzz
target opens `tests/corpus`); `cli_test.py` tests whatever binary is at
`zig-out/bin/safegguf` — rebuild ReleaseSafe first. Heavier suites are listed in
[AGENTS.md](AGENTS.md).

### CI and Release

- **CI** ([`ci.yml`](.github/workflows/ci.yml)): core tests on
  `ubuntu-24.04`/`macos-14`, embedded-version consistency, real-corpus gate,
  oracle/differential suites, mutation fuzzing, benchmarks, Windows gate,
  container release, and release assembly; [`windows.yml`](.github/workflows/windows.yml)
  runs fixtures, `zig build test`, ReleaseSafe build, CLI tests, and the
  negative corpus natively on `windows-latest`.
- **Scheduled/advisory**: Nightly Fuzz, Coverage Fuzz (Zig 0.14.1 advisory),
  Real Corpus (advisory), Upstream Canary (rolling oracle).
- **Releases**: `v*` tags trigger the release job, gated on every validation job
  including the fail-closed Windows gate; a failed or skipped gate blocks it.

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
