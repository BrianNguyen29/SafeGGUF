# SafeGGUF

[![CI][ci-badge]][ci-url]
[![Zig 0.13.0][zig-badge]][zig-url]
[![License: MIT][license-badge]][license-url]
[![Release: v0.3.7-dev][release-badge]][releases-url]
[![ggml 0.23.0 (e91ded11)][ggml-badge]][ggml-url]
[![Container: Distroless][container-badge]][dockerfile-url]

SafeGGUF is a memory-safe, overflow-checked structural and arithmetic validator
for GGUF model files, written in Zig with no external package dependencies. It
inspects the header, metadata, and tensor descriptor tables of untrusted model
files under bounded memory and work budgets before a runtime such as llama.cpp
maps tensor weights, and it fails closed with a deterministic exit-code contract
for CI gates and ingress admission.

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

- **Checked arithmetic on attacker-controlled values.** File-controlled
  dimensions, offsets, alignments, and sizes are combined with checked
  operations (`checkedAdd`, `checkedMul`, `checkedAlignUp`); an overflow
  terminates validation with exit code `2` instead of wrapping. The invariant is
  exercised by the regression suite, the differential harness against the
  pinned upstream ggml oracle, and mutation fuzzing — it is not guaranteed by
  construction alone. Regression coverage includes an advisory-derived fixture
  for CVE-2025-53630 / GHSA-vgg9-87g3-85w8 (cumulative tensor-size overflow,
  pinned to the `llama-cpp` profile).
- **Bounded validation memory.** A 64 KiB sliding-window reader inspects files
  of any size. Validator-managed allocations are capped by `QuotaAllocator`
  (128 MiB default), and logical work is bounded by `WorkBudget` (10,000,000
  units and a 256 MiB scanned-byte budget by default). Tensor weight payloads
  are never loaded. These budgets bound validator-managed allocations and work —
  they are not process RSS, page-cache, CPU-time, or kernel-overhead limits.
- **Fail-closed exit taxonomy.** `0` PASS, `2` REJECT (malformed input or
  validator-managed quota exhaustion), `64` usage, `70` internal/host OOM, `74`
  I/O. Unknown CLI arguments are rejected with exit `64`.
- **TOCTOU controls.** The C ABI and Python bindings validate an already-open
  descriptor (`safegguf_validate_fd_v1` / `safegguf.validate_fd`), so a writer
  cannot swap the file between check and load. Path-based validation alone
  cannot prevent that; pair it with immutable content-addressable storage and a
  digest handoff, as in the [Kubernetes example](#kubernetes) and
  [SECURITY.md](SECURITY.md).
- **Two validation profiles.** `gguf-spec` (default) is a resource-bounded safe
  subset of GGUF v3; `llama-cpp` is a pre-admission subset derived from and
  differential-tested against pinned ggml 0.23.0 (`e91ded11`).
- **Endianness handling.** `--endian little|big|auto`; `auto` detects byte order
  from the magic and version bytes. The `llama-cpp` profile accepts host-native
  endianness only, matching upstream ggml behavior.
- **Interfaces.** CLI, C ABI shared/static library with a versioned options
  struct, and Python bindings that bundle the native library.
- **Observability.** Opt-in per-run metrics JSON and structured JSON logs on
  stderr; stdout stays reserved for the result document.
- **Deployment.** Multi-arch distroless container (`linux/amd64`,
  `linux/arm64`) and a Kubernetes init-container pattern that stages, validates,
  and digest-pins the model before the serving container starts.

## Quick Start

Requires Zig 0.13.0.

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF
zig build -Doptimize=ReleaseSafe
./zig-out/bin/safegguf --version
./zig-out/bin/safegguf inspect /path/to/model.gguf --profile llama-cpp --endian auto --format json
```

Exit code `0` means the file passed; `2` means it was rejected. See
[Exit Codes](#exit-codes) for the full contract.

## Installation

### From Source

Prerequisites: Zig 0.13.0 (the version pinned in CI and in the Dockerfile).
Python 3 is needed only for fixture generation and the Python test harnesses;
CMake and a C++ compiler are needed only for the optional upstream ggml oracle.
There are no Zig package dependencies — the project uses the standard library
only.

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF
zig build -Doptimize=ReleaseSafe
```

Build artifacts:

| Path | Contents |
| :--- | :--- |
| `zig-out/bin/safegguf` | CLI executable |
| `zig-out/lib/libsafegguf.so`, `libsafegguf.a` | C ABI shared and static libraries (`libsafegguf.dylib` on macOS, `safegguf.dll` on Windows) |

### Container Image

The [`Dockerfile`](Dockerfile) builds a multi-stage image. The builder stage
runs on the build platform and cross-compiles with Zig: `TARGETARCH=amd64`
maps to `x86_64-linux-musl`, `arm64` maps to `aarch64-linux-musl`, and any
other architecture fails the build. The final stage is
`gcr.io/distroless/static-debian12:nonroot`, pinned to its multi-arch manifest
list digest, running as UID 65532 (`nonroot`). The Dockerfile targets an image
under 5 MB.

```bash
docker build -t safegguf:latest .
docker run --rm -v "$(pwd)/models:/models:ro" safegguf:latest \
  inspect /models/model.gguf --profile llama-cpp --endian auto
```

Release images are published to `ghcr.io/briannguyen29/safegguf` only for `v*`
tags, after the full CI validation gate, tagged with the release version,
`major.minor`, and `latest`. See [Docker](#docker) for the release pipeline.

### Python Package

Build the native library first, then install the package:

```bash
zig build -Doptimize=ReleaseSafe
python3 -m pip install ./bindings/python

# Or build a platform-specific wheel that bundles the same native library:
python3 -m pip wheel ./bindings/python --no-deps -w dist
python3 -m pip install dist/safegguf-*.whl
```

The wheel bundles the native library built from the same commit, and the
package version is the version that library reports. See
[Python Bindings](#python-bindings).

### Release Artifacts

Tagged releases publish cross-platform binaries (`x86_64-linux`,
`aarch64-linux`, `x86_64-macos`, `aarch64-macos`, `x86_64-windows`),
`SHA256SUMS.txt`, a keyless Sigstore signature bundle, and an SPDX 2.3 SBOM.
GitHub artifact attestations cover the release binaries. Verification steps are
in [SECURITY.md](SECURITY.md).

### Platforms

- Source builds: Linux, macOS, and Windows. CI runs the core suite on
  `ubuntu-24.04` and `macos-14`, plus a native Windows runtime lane.
- Release binaries: x86_64 and aarch64 Linux/macOS, x86_64 Windows.
- Container images: `linux/amd64` and `linux/arm64`.

## Usage

### CLI

```
safegguf inspect <path_to_model.gguf> [options]
safegguf --help | -h
safegguf --version
```

```bash
# Text output (default): summary fields and a PASS/REJECT result line
safegguf inspect /path/to/model.gguf --profile llama-cpp --endian auto

# JSON result document on stdout
safegguf inspect /path/to/model.gguf --profile llama-cpp --format json

# Admission ceiling and file-stability check (also exposed as v1.1 C ABI options)
safegguf inspect /path/to/model.gguf --max-file-size-bytes 17179869184 --require-stable-file

# Per-run metrics and one structured log record, both on stderr
safegguf inspect /path/to/model.gguf \
  --emit-metrics --log-json --request-id req-123 --tenant-id tenant-a
```

### Exit Codes

| Exit | Constant (`include/safegguf.h`) | Meaning |
| :---: | :--- | :--- |
| `0` | `SAFEGGUF_OK` | PASS: the file satisfies the selected profile's structural, arithmetic, and resource checks |
| `2` | `SAFEGGUF_REJECT` | REJECT: malformed input, checked-arithmetic overflow, or validator-managed quota exhaustion |
| `64` | `SAFEGGUF_EX_USAGE` | Usage/argument error, including unknown flags and invalid option values |
| `70` | `SAFEGGUF_EX_SOFTWARE` | Internal software error or host OOM (not a REJECT) |
| `74` | `SAFEGGUF_EX_IOERR` | File open, stat, or read I/O error |

Quota exhaustion routed through `QuotaAllocator` exits `2`; an unbudgeted host
allocation failure exits `70`. The two are deliberately distinct.

### JSON Diagnostics

Every ERROR/REJECT JSON object carries `schema_version`, `status`,
`error_code` (compatibility identifier), `canonical_error_code` (stable
`SGGUF_E_*` namespace), `category`, `stage`, and context fields when known.
PASS objects carry `checks` and an empty `findings` array. The CLI emits one
line; this REJECT example is pretty-printed:

```json
{
  "schema_version": 1,
  "status": "REJECT",
  "profile": "llama-cpp",
  "compatibility_target": {"project": "ggml", "version": "0.23.0", "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"},
  "error": "ArithmeticOverflow",
  "error_code": "E_ArithmeticOverflow",
  "canonical_error_code": "SGGUF_E_ARITHMETIC_OVERFLOW",
  "category": "arithmetic",
  "stage": "structural",
  "message": "Checked arithmetic overflow while computing tensor layout",
  "tensor_index": 1,
  "tensor": "cve-2025-53630-cumulative-1",
  "offset": 9223372036854775808,
  "expected_offset": 9223372036854775808,
  "findings": [
    {
      "code": "E_ArithmeticOverflow",
      "severity": "reject",
      "message": "Checked arithmetic overflow while computing tensor layout",
      "stage": "structural",
      "category": "arithmetic",
      "tensor_index": 1,
      "tensor": "cve-2025-53630-cumulative-1",
      "offset": 9223372036854775808,
      "expected_offset": 9223372036854775808
    }
  ]
}
```

Policy engines should key on `canonical_error_code` — or map
`safegguf_result_t.error_code` through `safegguf_canonical_error_code()` over
the C ABI. The legacy `error_code` value is kept unchanged for backward
compatibility; additive fields keep `schema_version` 1, and a breaking change
increments it. The full namespace and versioning policy are in
[`docs/error-codes.md`](docs/error-codes.md).

### Build Provenance

`--version` reports the embedded build metadata:

```
SafeGGUF 0.3.7-dev
source_commit: <commit>
zig: 0.13.0
build_mode: ReleaseSafe
target: x86_64-linux
ggml_target: 0.23.0
ggml_commit: e91ded11bdcd78c42f9c8d3978ff6686eb4c1226
```

The metadata is derived from the source tree and toolchain only (no wall-clock
timestamp), so the same commit, toolchain, and options produce identical
metadata. Every JSON output also carries the pinned ggml provenance under
`compatibility_target` (for `llama-cpp`) or `type_layout_source` (for
`gguf-spec`). Source builds report the embedded default version, which CI
checks against the latest tagged release; release artifacts report the tag they
were built from.

### Hybrid Triage

[`tools/safegguf-triage/safegguf_triage.py`](tools/safegguf-triage/safegguf_triage.py)
adds a semantic admission layer on top of the SafeGGUF verdict. Offline mode
runs a deterministic rule classifier with no network access; online mode calls
the TypeSafe Jev System One model when `TYPESAFE_API_KEY` is set and falls back
to the offline classifier transparently. A structural `PASS` maps to
`STRUCTURALLY_ACCEPTED`, which is not a semantic trust verdict.

```bash
# Prerequisites: ReleaseSafe binary in zig-out/bin and generated fixtures
python3 tests/generate_fixtures.py
python3 tests/negative_corpus.py
python3 tools/safegguf-triage/safegguf_triage.py \
  tests/fixtures/negative/cve-2025-53630-cumulative-overflow.gguf \
  --mode offline --format json
```

Sample output for the advisory-regression fixture above:

```json
{
  "file": "tests/fixtures/negative/cve-2025-53630-cumulative-overflow.gguf",
  "profile": "llama-cpp",
  "safegguf_verdict": "REJECT",
  "safegguf_exit_code": 2,
  "error_code": "E_ArithmeticOverflow",
  "triage": {
    "engine": "deterministic_rule_classifier",
    "structural_verdict": "REJECT",
    "score": 0.98,
    "risk_score": 0.98,
    "risk_band": "Critical",
    "severity": "Critical",
    "category": "Arithmetic-Exploit",
    "threat_category": "Arithmetic-Exploit",
    "action": "HARD_DROP_INGRESS",
    "recommendation": "HARD_DROP_INGRESS",
    "rationale": "Arithmetic overflow or integer exploit detected (E_ArithmeticOverflow)."
  }
}
```

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
| `--help`, `-h` | — | Print usage and exit `0`. |
| `--version` | — | Print version and build provenance and exit `0`. |

### Environment Variables

| Variable | Effect | Default |
| :--- | :--- | :--- |
| `SAFEGGUF_MAX_MEMORY_MB` | Allocation quota in MiB. | `128` |
| `SAFEGGUF_MAX_ALLOC_BYTES` | Allocation quota in bytes; applied after `SAFEGGUF_MAX_MEMORY_MB`. | 128 MiB |
| `SAFEGGUF_MAX_WORK_BUDGET` | Logical work-unit budget. | `10000000` |
| `SAFEGGUF_MAX_WORK_UNITS` | Logical work-unit budget; applied after `SAFEGGUF_MAX_WORK_BUDGET`. | `10000000` |
| `SAFEGGUF_MAX_SCANNED_BYTES` | Scanned-byte budget for streaming string, UTF-8, and boolean scans. | 256 MiB |

CLI flags override environment values. Malformed environment values are
ignored, leaving the corresponding default in place.

### Profiles

| Profile | GGUF versions | Tensor layout | Nested metadata arrays | Alignment | Endianness |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gguf-spec` (default) | v3 only | Arbitrary descriptor order and gaps allowed | Allowed, depth ≤ 16 | Multiple of 8 | `little`, `big`, or `auto` |
| `llama-cpp` | v2 and v3 | Strictly contiguous in descriptor order, with checked trailing padding | Rejected | Power of two | Host-native only; non-native byte order is rejected |

The GGML type table is pinned to ggml 0.23.0 (`e91ded11`): 43 table slots with
35 active types. Deprecated slots and IDs ≥ 43 are rejected. Zero-filled
descriptor padding is enforced in both profiles as an anti-tamper invariant —
stricter than runtimes that align past those bytes without validating their
contents.

### Resource Budgets

`QuotaAllocator` caps allocations routed through the validator (parser tables,
metadata structures, strings, and sorting buffers). `WorkBudget` charges parser
and structural-validator operations against logical work units and charges
streaming string/UTF-8/boolean scans against the scanned-byte budget. These are
validator-managed quotas; they do not cap process RSS, page cache, stack, CPU
time, or allocator/kernel overhead.

For hostile multi-tenant uploads, run validation under OS/container limits as
well: a cgroup/job-object memory limit, a CPU quota plus wall-clock timeout, an
input file-size limit, a read-only filesystem where possible, and a
seccomp/sandbox profile. See [SECURITY.md](SECURITY.md), "Deployment Limits".

### Observability

Metrics counters are recorded on every run; JSON emission is opt-in and always
goes to stderr, so stdout remains a single result document. `--emit-metrics`
writes a per-run metrics JSON object; `--log-json` writes one structured log
record including the verdict, timing, budgets, a SHA-256 file digest, and the
request/tenant identifiers (`--tenant-id` is pseudonymized before logging).
Emission failures are ignored — observability never changes a verdict or exit
code.

## Deployment

### Docker

The [container release pipeline](.github/workflows/container-release.yml) is
reusable-only and is called by CI for `v*` tags, after every validation job has
passed on the tagged commit. It:

- builds `linux/amd64` and `linux/arm64` images and runs each one (arm64 under
  QEMU) before publishing;
- emits an SBOM and SLSA provenance (`provenance: mode=max`);
- signs the image digest with keyless Cosign OIDC and verifies the signature
  before the job is allowed to succeed.

Images are tagged with the release version, `major.minor`, and `latest`, and
published to `ghcr.io/briannguyen29/safegguf`. Local builds use the same
Dockerfile:

```bash
docker build -t safegguf:latest .
docker run --rm -v "$(pwd)/models:/models:ro" safegguf:latest \
  inspect /models/model.gguf --profile llama-cpp --format json
```

### Kubernetes

[`deploy/k8s/safegguf-initcontainer.yaml`](deploy/k8s/safegguf-initcontainer.yaml)
implements the stage → validate → digest-pin → load flow: the untrusted upload
is copied exactly once into private staging, SafeGGUF validates the staged
bytes, and the validated bytes are hashed and atomically renamed to
`validated/<sha256>`. The serving container loads only the digest-named CAS
entry, so it never reads the mutable upload path. A companion script,
[`deploy/k8s/attestation_handoff.sh`](deploy/k8s/attestation_handoff.sh),
provides the same handoff outside Kubernetes.

The snippet below is abridged from the manifest (volume definitions, resources,
securityContext blocks, and some command detail are omitted; see the full file
for read-only mounts, `runAsNonRoot` UID 65532 contexts, and seccomp profiles).
The image tag shown is the one in the manifest at HEAD; substitute a release
tag for production.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: llm-inference-pod-with-safegguf
  namespace: ai-serving
spec:
  initContainers:
    # Phase 0: copy the untrusted upload exactly once into private staging.
    - name: safegguf-staging-copy
      image: busybox:1.36-musl
      command:
        - /bin/sh
        - -c
        - |
          set -euo pipefail
          mkdir -p /private-stage
          cp /models/model.gguf /private-stage/model.gguf
    # Phase 1: fail-closed validation of the staged bytes.
    - name: safegguf-pre-admission-validator
      image: ghcr.io/briannguyen29/safegguf:v0.3.7-dev
      command:
        - /usr/local/bin/safegguf
        - inspect
        - /private-stage/model.gguf
        - --profile
        - llama-cpp
        - --format
        - json
        - --endian
        - auto
    # Phase 2: hash exactly the validated bytes and publish validated/<sha256>.
    - name: safegguf-attestation-generator
      image: busybox:1.36-musl
      command:
        - /bin/sh
        - -c
        - |
          set -euo pipefail
          DIGEST="$(sha256sum /private-stage/model.gguf | awk '{print $1}')"
          mkdir -p /private-stage/validated
          mv /private-stage/model.gguf "/private-stage/validated/$DIGEST"
          printf '%s  %s\n' "$DIGEST" "$DIGEST" > /attestation/model.gguf.sha256
  containers:
    # Serving: digest-pinned load from the immutable CAS; never the source path.
    - name: llama-cpp-server
      image: ghcr.io/ggerganov/llama.cpp:server
      command:
        - /bin/sh
        - -c
        - |
          set -euo pipefail
          DIGEST="$(awk '{print $1}' /attestation/model.gguf.sha256)"
          cd /validated
          sha256sum -c /attestation/model.gguf.sha256
          exec /server -m "/validated/$DIGEST" -c 4096 --host 0.0.0.0 --port 8080
```

## API

### Python Bindings

The `safegguf` package validates by path or by open file descriptor and exposes
the same profiles, endianness options, and resource controls as the CLI,
including the v1.1 `max_file_size_bytes` and `require_stable_file` controls.

```python
import safegguf

# Path-based validation
result = safegguf.validate_path(
    "/models/llama-3.gguf",
    profile="llama-cpp",
    endian="auto",
    max_file_size_bytes=16 * 1024**3,  # v1.1 admission ceiling; 0 = unlimited
    require_stable_file=True,          # v1.1: reject if identity changes mid-validation
)
if not result.is_valid:
    raise RuntimeError(f"rejected: {result.error_code} (exit {result.exit_code})")

# Descriptor-based validation (anti-TOCTOU). The descriptor's seek offset is
# preserved across the call.
with open("/models/llama-3.gguf", "rb") as f:
    res = safegguf.validate_fd(f.fileno(), profile="llama-cpp", endian="auto")
    if not res.is_valid:
        raise RuntimeError(f"rejected: {res.error_code} (exit {res.exit_code})")
```

`safegguf.version()` returns the native library version. The library is located
in this order: `SAFEGGUF_LIB_PATH` (must be an absolute path to a regular
file), the packaged wheel, the source tree's `zig-out`, and finally the
platform library search. If a control cannot be enforced by the loaded native
library (legacy options layout), the call fails closed with
`E_USAGE_UNSUPPORTED_OPTIONS` (exit `64`) instead of silently dropping it.

### C ABI

The public header is [`include/safegguf.h`](include/safegguf.h). It exports the
versioned entry points `safegguf_validate_path_v1` and
`safegguf_validate_fd_v1`, the legacy `safegguf_validate_path` /
`safegguf_validate_fd` calls, `safegguf_version`, and
`safegguf_canonical_error_code`. Exit constants are `SAFEGGUF_OK`,
`SAFEGGUF_REJECT`, `SAFEGGUF_EX_USAGE`, `SAFEGGUF_EX_SOFTWARE`, and
`SAFEGGUF_EX_IOERR`.

`safegguf_options_v1_t` is caller-owned and read only for the duration of the
call. `struct_size` gates appended fields, so a caller compiled against the
v1.0 layout keeps the legacy defaults (`max_file_size_bytes = 0` unlimited,
`require_stable_file = 0` off); unknown sizes are rejected with exit `64`.
Calls are independent and safe to make concurrently; a single options struct
must not be mutated while a call using it runs.

```c
#include "safegguf.h"
#include <stdio.h>

int main(void) {
    safegguf_options_v1_t options = {
        .struct_size = sizeof(safegguf_options_v1_t),
        .profile = SAFEGGUF_PROFILE_LLAMA_CPP,
        .endian = SAFEGGUF_ENDIAN_AUTO,
        .max_alloc_bytes = 128 * 1024 * 1024, /* 128 MiB ceiling */
        .max_work_units = 10000000,
        .max_scanned_bytes = 0,               /* 0 = default limit */
        .reserved = NULL,
        .max_file_size_bytes = 0,             /* v1.1: 0 = unlimited */
        .require_stable_file = 0              /* v1.1: 1 = reject if identity changes */
    };

    safegguf_result_t result;

    /* Use safegguf_validate_fd_v1 for an already-open descriptor. */
    int rc = safegguf_validate_path_v1("/path/to/model.gguf", &options, &result);
    if (rc == SAFEGGUF_OK) {
        printf("Model passed structural validation.\n");
    } else {
        printf("Rejected (exit %d, [%s] %s): %s\n",
               rc, result.category, result.error_code, result.message);
    }
    return rc;
}
```

## Security

SafeGGUF's threat model, security invariants, release verification procedure,
supported versions, and vulnerability-reporting process live in
[SECURITY.md](SECURITY.md). In summary, it enforces:

1. Checked arithmetic on file-controlled values, with overflow rejected
   (exit `2`) instead of wrapped.
2. Resource-exhaustion resistance via validator-managed allocation, work, and
   scanned-byte budgets.
3. A fail-closed exit taxonomy (`0`, `2`, `64`, `70`, `74`).
4. TOCTOU controls: descriptor validation, or validation against immutable
   content-addressable storage with a digest handoff.
5. A bounded `PASS` scope.

### What SafeGGUF Does and Does Not Check

| Checked | Not checked |
| :--- | :--- |
| GGUF header, metadata, and tensor descriptor structure against the selected profile | Tensor weight payload contents or model quality |
| Checked arithmetic for dimensions, offsets, alignments, and sizes | Model behavior, chat templates, or tokenizer semantics |
| Zero-filled descriptor padding and alignment rules | Downstream runtime code (e.g. llama.cpp itself) |
| Validator-managed allocation, work, and scan budgets | OS-level memory, CPU, or wall-clock limits |

`PASS` means the file satisfies the selected SafeGGUF structural, arithmetic,
and resource-policy checks. It is not a trust or malware verdict.

### Release Verification

Tagged releases publish binaries, `SHA256SUMS.txt`, a keyless Sigstore
signature bundle (`SHA256SUMS.txt.sigstore.json`), and an SPDX 2.3 SBOM
(`safegguf.spdx.json`). GitHub artifact attestations cover the release binaries
with build-provenance and SBOM predicates, and the release workflow verifies
checksums, signature, and attestations before publishing. Container images are
signed with keyless Cosign and verified before the pipeline succeeds. Copy-paste
verification commands are in [SECURITY.md](SECURITY.md), "Release
Verification".

### Historical Verification Snapshot

The table below is a historical snapshot of the internal multi-agent
verification campaign recorded in the
[archived audit report](docs/archive/production_audit_report.md). It is
retained for provenance; it is a point-in-time record, not a live CI status.
The archived report records more than 76,000 checks across these suites, all
meeting their expected verdicts.

| # | Suite / security domain | Scope | Scale | Result |
| :---: | :--- | :--- | :--- | :--- |
| 01 | Zig unit & fuzz sweep | 35 active GGML types, limits, memory, sliding-window reader, checked arithmetic, fuzz corpus | 78 / 78 tests | PASS |
| 02 | CLI E2E contract suites | Exit codes `0`/`2`/`64`/`70`/`74`, JSON formatting, rich diagnostics, provenance | 10 / 10 suites | PASS |
| 03 | Negative corpus suite | 6 synthetic bug classes; 3 advisory placeholders (manifest-only) | 15 / 15 cases | REJECT (exit 2) |
| 04 | BigInt arithmetic oracle | alignUp, product, and tensorBytes cross-checked against Python BigInt | 74,626 ops | PASS |
| 05 | Advanced security testbed | Dimension-product overflow, zero-padding, quota DoS, profile decoupling | 62 / 62 tests | PASS |
| 06 | Adversarial endianness sweep | Byte mutations, magic/version boundaries, big-endian v2/v3 auto-detection | 577 / 577 tests | PASS |
| 07 | Truncation & binary noise stress | Byte slicing (0..64) and 500 random binary streams | 949 / 949 slices | PASS |
| 08 | CLI resource & boundary probing | Values ≥ 2^44 on `--max-memory-mb` and `--max-work-budget` | 38 / 38 probes | PASS (exit 64) |
| 09 | Python bindings integration | Path and raw file-descriptor validation | 10 / 10 suites | PASS |
| 10 | C-ABI adversarial probes | NULL, invalid handles, TOCTOU | 57 / 57 probes | PASS |
| 11 | C-ABI deep stress & concurrency | 0..100k characters, surrogate UTF-16, 32-thread contention | 48 / 48 probes | PASS |
| 12 | FFI boundaries & robustness | `struct_size` fuzzing, enum bounds, `reserved != NULL`, pre-validation | 79 / 79 checks | PASS |
| 13 | Hybrid triage unit & regression | Offline rule logic, `structural_verdict` invariants | 41 / 41 tests | PASS |
| 14 | Triage challenger 1 | Risk classification across the security fixture set | 42 / 42 probes | PASS |
| 15 | Triage challenger 2 | Exploit leakage (39 exploit files, 0 leaked), neutral renaming, concurrency | 56 / 56 probes | PASS |
| 16 | Triage network adversarial stress | Socket timeout, 502, HTML, corrupted JSON, CLI boundaries | 45 / 45 tests | PASS |
| 17 | Version progression guard | Semver progression logic in `scripts/version_consistency.py` | 7 / 7 checks | PASS |
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

Contributions are welcome via GitHub issues and pull requests. Before changing
anything, keep the repository invariants in [`AGENTS.md`](AGENTS.md) intact.

### Development and Testing

Run these from the repository root, in this order (matches CI):

```sh
zig fmt --check src/ build.zig tests/*.zig
python3 tests/generate_fixtures.py     # writes gitignored fixtures + seed corpus
zig build test --summary all           # unit + regression + fuzz corpus sweep
zig build -Doptimize=ReleaseSafe       # -> zig-out/bin/safegguf
python3 tests/cli_test.py              # end-to-end exit-code contract
python3 tests/negative_corpus.py       # negative corpus + advisory provenance (exit 2)
```

Two quirks to know: `zig build test` fails on a fresh clone until fixtures are
generated, because the fuzz target opens the generated `tests/corpus`
directory; and `cli_test.py` tests whatever binary is at
`zig-out/bin/safegguf`, so rebuild ReleaseSafe before running it.

Heavier suites (run when touching parsing, types, or upstream-compat
behavior):

```sh
python3 tests/arithmetic_oracle.py
python3 tests/test_oracle_types.py
python3 tests/differential_matrix.py && python3 tests/differential.py
python3 tests/fuzz_mutation.py --iterations 2000
python3 tests/real_corpus.py --tier 1 --tolerate-download-errors
```

### CI and Release

- **CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)): core tests on
  `ubuntu-24.04` and `macos-14`, embedded-version consistency against the
  latest tag, the real-corpus gate, the oracle/differential suites, mutation
  fuzzing, benchmarks, the Windows gate, container release, and release
  assembly.
- **Windows** ([`.github/workflows/windows.yml`](.github/workflows/windows.yml)):
  fixture generation, `zig build test`, ReleaseSafe build, CLI tests, and the
  negative corpus natively on `windows-latest`.
- **Scheduled/advisory**: Nightly Fuzz, Coverage Fuzz (Zig 0.14.1 advisory),
  Real Corpus (advisory), and Upstream Canary (rolling oracle).
- **Releases**: `v*` tags trigger the release job, which depends on every
  validation job including the fail-closed Windows gate. A failed or skipped
  gate blocks the release, so no artifact is published without native
  validation of the tagged commit.

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

[ci-badge]: https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml
[zig-badge]: https://img.shields.io/badge/Zig-0.13.0-orange.svg?style=flat-square&logo=zig
[zig-url]: https://ziglang.org/download/0.13.0/release-notes.html
[license-badge]: https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square
[license-url]: LICENSE
[release-badge]: https://img.shields.io/badge/release-v0.3.7--dev-blue.svg?style=flat-square
[releases-url]: https://github.com/BrianNguyen29/SafeGGUF/releases
[ggml-badge]: https://img.shields.io/badge/ggml-0.23.0%20(e91ded11)-blueviolet.svg?style=flat-square
[ggml-url]: https://github.com/ggml-org/ggml/tree/e91ded11bdcd78c42f9c8d3978ff6686eb4c1226
[container-badge]: https://img.shields.io/badge/container-distroless-2496ED.svg?style=flat-square&logo=docker
[dockerfile-url]: Dockerfile
