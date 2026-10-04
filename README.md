# SafeGGUF

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Windows](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/windows.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/windows.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

SafeGGUF validates GGUF model files before an inference runtime loads them.
Written in Zig, it checks file structure, tensor layout, arithmetic bounds and
resource limits through a CLI, C API and Python bindings.

Source version: **0.1.0**. Signed release artifacts are available through
[GitHub Releases](https://github.com/BrianNguyen29/SafeGGUF/releases).
Use the release's checksums and provenance to verify downloaded artifacts.

A PASS verdict means the file satisfies the selected validation policy. Model
authenticity, weight behavior and inference compatibility require separate
verification.

## Features

- Checked arithmetic for dimensions, offsets, alignments and tensor sizes.
- Configurable allocation, logical-work, scanned-byte and input-size limits.
- `llama-cpp` and `gguf-spec` profiles with explicit compatibility rules.
- Single-process admission to content-addressed storage, with policy-bound JSON
  statements and checksum pins.
- Stable exit codes, JSON diagnostics, canonical error codes, optional metrics
  and structured logs.
- Nonroot containers for Linux amd64/arm64 and a Kubernetes integration example.
- No external Zig package dependencies.

## Installation

### Build from source

Install **Zig 0.13.0**, then build with runtime safety checks enabled:

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF
zig build -Doptimize=ReleaseSafe
./zig-out/bin/safegguf --version
```

The build produces the CLI under `zig-out/bin` and shared/static C libraries
under `zig-out/lib`. Source builds support Linux, macOS and Windows.

Release binaries target x86_64/aarch64 Linux and macOS, and x86_64 Windows.
See [SECURITY.md](SECURITY.md) for artifact verification.

### Python bindings

Build the native library first, then install the bindings:

```bash
zig build -Doptimize=ReleaseSafe
python3 -m pip install ./bindings/python
```

Packaged wheels bundle the native shared library and derive their version from
it. See [Python packaging](bindings/python/pyproject.toml) for build requirements.

### Docker

```bash
docker build -t safegguf:0.1.0 .
docker run --rm -v "$PWD/models:/models:ro" safegguf:0.1.0 \
  inspect /models/model.gguf --format json
```

The [Dockerfile](Dockerfile) builds a static binary and uses a digest-pinned
distroless runtime. Published images are available at
`ghcr.io/briannguyen29/safegguf`; verify their signatures and pin the digest
before deployment.

## Usage

### Inspect a model

```bash
safegguf inspect model.gguf --format json
safegguf inspect model.gguf --profile llama-cpp --endian auto
safegguf inspect model.gguf --max-file-size-bytes 17179869184 --require-stable-file
```

The default profile is `llama-cpp`; byte order defaults to `auto`.
Use `--` before a path that starts with a dash.

JSON diagnostics use schema v1 and include the verdict, profile and pinned
upstream type-table provenance. Rejections include `error_code`,
`canonical_error_code`, category, stage and available context. Use canonical
codes for programmatic decisions; see [error codes](docs/error-codes.md).

### Admit a model

Prepare output directories controlled by the admission service, then run:

```bash
umask 077
mkdir -p /srv/safegguf/validated /srv/safegguf/attestations
safegguf admit model.gguf \
  --cas-dir /srv/safegguf/validated \
  --attestations-dir /srv/safegguf/attestations \
  --profile llama-cpp --endian auto > admission.json
```

`admit` copies and hashes the input into private staging, validates the same
staged inode, then publishes the validated bytes under their SHA-256 digest.
Continue only after exit code `0`.

The admission schema v2 document records effective limits, key policy,
requested/resolved byte order and build provenance. Its `cas.relative_path`
resolves from `--cas-dir`. Successful stdout matches the saved JSON statement.
Protect outputs from untrusted writers and verify the checksum before loading.

See the [admission contract](docs/admission-attestation.md) for fields, policy
replay and partial-publication failure semantics.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | PASS, or successful help/version output |
| `2` | Rejected input or validator-managed resource exhaustion |
| `64` | Invalid arguments or options |
| `70` | Internal error or host out-of-memory |
| `74` | File access, read or publication error |

## Validation policy

| Profile | GGUF versions | Tensor layout | Metadata arrays | Alignment |
| --- | --- | --- | --- | --- |
| `llama-cpp` (default) | v2/v3 | Contiguous in descriptor order; checked trailing padding | Nested arrays rejected | Power of two |
| `gguf-spec` | v3 | Descriptor order and gaps allowed | Nesting up to depth 16 | Multiple of 8 |

Both profiles use the type table from **ggml 0.23.0**, commit
[`e91ded11`](https://github.com/ggml-org/ggml/tree/e91ded11bdcd78c42f9c8d3978ff6686eb4c1226),
and enforce zero-filled descriptor padding. The `llama-cpp` profile requires
host-native byte order and rejects embedded NUL tensor names. Profiles define
a bounded safe subset; acceptance does not guarantee every downstream runtime
or model architecture can load the file.

### Resource controls

| Control | Default |
| --- | --- |
| Validator-managed allocation | 128 MiB |
| Logical work | 10,000,000 units |
| Scanned string/UTF-8/boolean bytes | 256 MiB |
| Variable-array elements | 1,000,000 |
| Metadata key/string length | 65,536 bytes |
| Input size | Unlimited for `inspect`; 16 GiB for `admit` |
| Metadata key policy | `strict` |

Use `--max-memory-mb`, `--max-work-budget`, `--max-variable-array-elements`,
`--max-string-bytes` and `--max-file-size-bytes` to set the corresponding
limits. `--key-policy lenient` explicitly permits additional metadata key
characters. Run `safegguf --help` for complete options.

Environment controls include `SAFEGGUF_MAX_ALLOC_BYTES`,
`SAFEGGUF_MAX_WORK_UNITS`, `SAFEGGUF_MAX_SCANNED_BYTES`,
`SAFEGGUF_MAX_STRING_BYTES` and `SAFEGGUF_KEY_POLICY`.
CLI flags override the corresponding environment settings; malformed
environment values are ignored.

These quotas apply to validator-managed operations. Apply OS/container limits
for process memory, CPU, wall-clock time and staging disk usage when processing
untrusted uploads.

## Integration

The C API supports paths and open descriptors through
`safegguf_validate_path_v1` and `safegguf_validate_fd_v1`; definitions and
ownership rules are in [safegguf.h](include/safegguf.h). A `NULL` options pointer
uses `llama-cpp` and `auto`; a zero-initialized options structure selects
`gguf-spec` and little-endian. Initialize the desired fields explicitly.

Python exposes `validate_path`, `validate_fd` and `version` using the same
native engine. Keep validated bytes protected throughout downstream use:
a file descriptor preserves inode identity, but does not prevent another writer
from changing its contents.

The [Kubernetes template](deploy/k8s/safegguf-initcontainer.yaml) runs admission
before serving and verifies the checksum before the runtime loads the digest
object. Render it with [render_k8s_manifest.py](scripts/render_k8s_manifest.py)
using a verified, version-matching image digest. Configure storage, resource
limits, readiness and lifecycle for the target environment.

Optional metrics and structured logs go to stderr through `--emit-metrics`
and `--log-json`; stdout remains the result document. `--version` reports
the version, source commit, toolchain, build mode, target and ggml baseline.
Release version, C API layout version and JSON schema version are independent.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, supported releases,
artifact verification and private vulnerability reporting.

Admission statements are unsigned unless an operator-owned signing layer
authenticates them. Protect staging and published objects from untrusted
same-UID or privileged writers; read-only serving mounts are part of that boundary.

## Development

Use Zig 0.13.0 and Python 3. Generate fixtures before running the test suite:

```bash
zig fmt --check src/ build.zig tests/*.zig
python3 tests/generate_fixtures.py
zig build test --summary all
zig build -Doptimize=ReleaseSafe
python3 tests/cli_test.py
python3 tests/negative_corpus.py
python3 scripts/version_consistency.py
```

CI covers Linux/macOS core tests, upstream differential checks, mutation fuzzing
and benchmarks. Native Windows checks run separately and gate release
publication. Tagged releases also require the real-model corpus and container
runtime checks.

Contributions are welcome through issues and pull requests. Follow the
repository invariants in [AGENTS.md](AGENTS.md), use concise Conventional
Commit messages, and keep local session records, audit reports and incident
runbooks outside the tracked public tree. Before committing staged changes,
run `python3 scripts/check_public_tree.py`.

## Documentation

- [Release notes](docs/release-notes-0.1.0.md)
- [Admission schema and policy replay](docs/admission-attestation.md)
- [Canonical error codes](docs/error-codes.md)
- [Deployment and integration](docs/production_deployment.md)
- [Security policy](SECURITY.md)

## License

[MIT](LICENSE).
