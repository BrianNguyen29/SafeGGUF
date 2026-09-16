# SafeGGUF

[![CI](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml/badge.svg)](https://github.com/BrianNguyen29/SafeGGUF/actions/workflows/ci.yml)
[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg)](https://ziglang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Upstream ggml](https://img.shields.io/badge/ggml-0.23.0%20(e91ded11)-blue.svg)](https://github.com/ggml-org/ggml/tree/e91ded11bdcd78c42f9c8d3978ff6686eb4c1226)
[![Release](https://img.shields.io/badge/release-v0.3.6-green.svg)](https://github.com/BrianNguyen29/SafeGGUF/releases)

SafeGGUF is a memory-safe, overflow-checked structural and arithmetic validator for **GGUF** model files, written in Zig. It inspects model headers, metadata, and tensor descriptors to reject malformed or adversarial input before weights are mapped into production inference runtimes such as `llama.cpp` or other `ggml`-based loaders.

Validation reads only the header, metadata, descriptor table, and alignment padding through a 64 KiB sliding-window reader; tensor payload bytes are never read, so models larger than available memory can be inspected. The CLI is fail-closed: unknown arguments exit with standard `EX_*` codes, and every result carries structured diagnostics and the pinned upstream type-table provenance.

> **Release status.** The latest tagged release is **v0.3.6** (tag object `f688b59`, commit `ddbf045`, published 2026-09-15); `main` currently matches that release commit. This README documents `main` unless a statement is explicitly marked as release-only.

## Overview

GGUF fields are attacker-controlled: element counts, string lengths, dimensions, offsets, and alignment all drive allocations and pointer arithmetic in downstream loaders. SafeGGUF rejects the input classes that most commonly break those loaders:

* dimension products, block counts, and byte sizes whose arithmetic would wrap `u64` (checked arithmetic, no silent overflow);
* descriptor tables and cumulative offsets that overflow or extend past the end of the file;
* alignment padding that violates the GGUF zero-padding requirement;
* resource exhaustion (huge counts, oversized strings, deep nesting) before any allocation is made;
* semantic violations: invalid UTF-8, invalid booleans, unknown tensor type IDs, zero dimensions.

`PASS` means the file satisfies the selected profile's structural, arithmetic, and resource-policy checks. It is not a trust or malware verdict — see [Security](#security).

## Features

* **Pinned ggml type table.** Supports the 35 active GGML types across the 43 type slots of pinned ggml `0.23.0` (`e91ded11`): `F32`/`F16`/`BF16`/`F64`, `I8`–`I64`, `Q4_0`–`Q8_1`, k-quants (`Q2_K`–`Q8_K`), i-quants (`IQ1_S`–`IQ4_XS`), t-quants (`TQ1_0`, `TQ2_0`), and `MXFP4`/`NVFP4`/`Q1_0`/`Q2_0`. Deprecated slots (4, 5, 31–33, 36–38) and type IDs ≥ 43 are rejected. Row/block divisibility (`dims[0] % block_size == 0`) is enforced, and the table is verified against a compiled upstream C++ oracle (`tests/test_oracle_types.py`).
* **Two validation profiles.** `gguf-spec` (default) validates a resource-bounded, format-level safe subset of GGUF v3. `llama-cpp` validates the stricter pre-admission subset derived from, and differential-tested against, pinned `ggml 0.23.0` (`e91ded11`). The two profiles are deliberately decoupled; see [Validation Profiles](#validation-profiles).
* **Checked arithmetic everywhere.** Dimensions, block counts, byte sizes, alignment, and contiguous-layout traversal are computed with checked operations (`checkedAdd`, `checkedMul`, `checkedAlignUp`); overflow yields a `REJECT`, never a wrapped value.
* **Validator-managed resource budgets.** A wrapping `QuotaAllocator` caps validator allocations, and a `WorkBudget` charges deterministic logical work units plus scanned bytes. Quota exhaustion fails closed with exit code `2`; see [Resource Limits](#resource-limits).
* **Fail-closed CLI with a standard exit taxonomy.** `0` PASS, `2` REJECT, `64` usage error, `70` internal software/host-OOM error, `74` I/O error — deterministic values suitable for CI/CD gates.
* **Structured diagnostics.** `--format json` emits machine-readable results with `error_code`, `category`, `stage`, and position context (tensor index/name, offset, expected offset, metadata key). Text mode mirrors the same fields and sanitizes untrusted strings.
* **Pinned provenance in every JSON result.** PASS, REJECT, and ERROR objects all carry the ggml source the profile's layout rules derive from — `type_layout_source` under `gguf-spec`, `compatibility_target` under `llama-cpp`.
* **Independent verification harness.** Upstream C++ type oracle, Python bigint arithmetic oracle, differential testing against the pinned upstream loader, a provenance-tiered negative corpus, and mutation fuzzing (details under [Testing](#testing)).

## Quick Start

### Prerequisites

* **Zig 0.13.0** (pinned toolchain; no Zig package dependencies)
* **Python 3** for fixture generation and the test harnesses
* **CMake and a C++ toolchain** — only needed to build the upstream verification oracle

### Build

```bash
git clone https://github.com/BrianNguyen29/SafeGGUF.git
cd SafeGGUF

# ReleaseSafe enables runtime safety checks (overflow, bounds) with optimization,
# and is the configuration the Python harnesses expect.
zig build -Doptimize=ReleaseSafe

# Binary: zig-out/bin/safegguf
./zig-out/bin/safegguf inspect /path/to/model.gguf
```

### Generate fixtures and run the tests

```bash
# Required once before `zig build test`: fixtures and seed corpus are generated,
# not committed (they live under gitignored tests/fixtures/ and tests/corpus/).
python tests/generate_fixtures.py

zig fmt --check src/ build.zig tests/*.zig
zig build test --summary all

zig build -Doptimize=ReleaseSafe
python tests/cli_test.py
python tests/negative_corpus.py
```

See [Testing](#testing) for the oracle, differential, benchmark, and fuzz commands.

## CLI Reference

```text
safegguf inspect <path_to_model.gguf> [options]
safegguf --version
safegguf --help | -h | help
```

`inspect` is the only subcommand. With no arguments, an unknown command, or an unknown option, SafeGGUF prints usage to stderr and exits `64` (fail-closed); a missing file path also exits `64`.

| Option | Values | Default | Description |
| :--- | :--- | :--- | :--- |
| `--endian` | `little` \| `big` | `little` | Byte order used to decode multi-byte header, metadata, and descriptor fields |
| `--format` | `text` \| `json` | `text` | Output format |
| `--profile` | `gguf-spec` \| `llama-cpp` | `gguf-spec` | Validation profile (see [Validation Profiles](#validation-profiles)) |
| `--max-variable-array-elements` | integer `1`..`10,000,000` | `1,000,000` | Sanity cap for variable-length element arrays (`array[string]` and nested arrays). The accepted ceiling equals the generic array-element limit; a missing value, `0`, non-integers, or values above the ceiling exit `64` |
| `--help`, `-h` | — | — | Print usage and exit `0` (also `safegguf help`, or `inspect --help`) |
| `--version` | — | — | Print version and build provenance, then exit `0` |

### Build provenance (`--version`)

```bash
safegguf --version
```

Output from the released v0.3.6 `x86_64-linux` binary:

```text
SafeGGUF 0.3.6
source_commit: ddbf045591cd7a2c7c69252012092440025723eb
zig: 0.13.0
build_mode: ReleaseSafe
target: x86_64-linux
ggml_target: 0.23.0
ggml_commit: e91ded11bdcd78c42f9c8d3978ff6686eb4c1226
```

All values are injected at build time from the source tree, toolchain, and build options; no wall-clock timestamp is embedded. The version defaults to `0.3.5` for source builds and is set explicitly with `-Dversion=<value>` by the release workflow.

## Exit Codes

| Exit code | Constant | Meaning |
| :---: | :--- | :--- |
| `0` | `PASS` | The file satisfies the selected profile's structural, arithmetic, and resource-policy checks. |
| `2` | `REJECT` | The file is malformed, out of bounds, corrupted, or violates a profile/security invariant — including validator allocation-quota exhaustion. |
| `64` | `EX_USAGE` | Command-line usage error: unknown command/option, missing argument, or invalid option value (fail-closed). |
| `70` | `EX_SOFTWARE` | Internal error or host out-of-memory. |
| `74` | `EX_IOERR` | The target file could not be opened or stat'ed, or a stream read failed. |

## Output

`--format text` (the default) prints PASS details to stdout and routes REJECT/ERROR diagnostics to stderr, mirroring the JSON fields as labeled text lines; untrusted strings are sanitized to printable ASCII.

```text
GGUF version: 3
Profile: gguf-spec
File size: 448 bytes
Metadata entries: 1
Tensors: 2
Alignment: 32
Tensor data offset: 192

Validation:
  structural: PASS
  arithmetic: PASS
  bounds: PASS
  overlap: PASS
Result: PASS
```

`--format json` emits one JSON object per invocation to stdout, with the exit code carrying the verdict. Every JSON object — PASS, REJECT, and ERROR — carries the pinned provenance object (`type_layout_source` under `gguf-spec`, `compatibility_target` under `llama-cpp`) with `project`, `version`, and `commit` fields.

PASS, `--profile gguf-spec`:

```json
{
  "status": "PASS",
  "profile": "gguf-spec",
  "version": 3,
  "file_size": 448,
  "metadata_entries": 1,
  "tensors": 2,
  "alignment": 32,
  "tensor_data_offset": 192,
  "type_layout_source": {
    "project": "ggml",
    "version": "0.23.0",
    "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
  },
  "checks": {
    "structural": "PASS",
    "arithmetic": "PASS",
    "bounds": "PASS",
    "overlap": "PASS"
  },
  "findings": []
}
```

REJECT, `--profile gguf-spec`, with position context (REJECT objects include `error`, `error_code`, `category`, `stage`, `message`, a `findings` array, and whichever context fields the rejection site recorded: `tensor_index`, `tensor`, `offset`, `expected_offset`, `key`, `key_truncated`):

```json
{
  "status": "REJECT",
  "profile": "gguf-spec",
  "type_layout_source": {
    "project": "ggml",
    "version": "0.23.0",
    "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
  },
  "error": "TensorOutOfBounds",
  "error_code": "E_TensorOutOfBounds",
  "category": "format",
  "stage": "structural",
  "message": "Tensor data extends past end of file",
  "tensor_index": 0,
  "tensor": "test",
  "offset": 1024,
  "findings": [
    {
      "code": "E_TensorOutOfBounds",
      "severity": "reject",
      "message": "Tensor data extends past end of file",
      "stage": "structural",
      "category": "format",
      "tensor_index": 0,
      "tensor": "test",
      "offset": 1024
    }
  ]
}
```

ERROR objects (I/O and internal failures) carry `status`, `error`, `error_code`, `message`, and the provenance object; `profile` is present when the failure occurs after profile selection. Example — file not found (exit `74`):

```json
{
  "status": "ERROR",
  "type_layout_source": {
    "project": "ggml",
    "version": "0.23.0",
    "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"
  },
  "error": "FileNotFound",
  "error_code": "E_FILE_OPEN_FAILED",
  "message": "Failed to open file"
}
```

`error_code` values are `E_` prefixed error names (for example `E_TensorOutOfBounds`, `E_InvalidAlignmentPadding`, `E_ArithmeticOverflow`). `category` is one of `format`, `compatibility`, `arithmetic`, `resource`, `io`, or `internal`. JSON strings derived from untrusted input are escaped byte-safely, so rejection output stays parseable even for malformed names and keys.

## Validation Profiles

| Constraint | `--profile gguf-spec` (default) | `--profile llama-cpp` |
| :--- | :--- | :--- |
| Role | Resource-bounded GGUF v3 structural safe subset | Pre-admission subset derived from pinned ggml `0.23.0` (`e91ded11`) |
| GGUF version | Exactly `3` | `2` or `3` |
| Tensor layout | Arbitrary order and gaps permitted; overlapping data ranges rejected | Strictly contiguous in descriptor order, with the aligned end of the final tensor required to exist within the file |
| Nested arrays | Permitted up to the metadata depth limit (`16`) | Rejected (`NestedArrayNotSupported`) |
| Tensor name length | 1–64 bytes | 1–63 bytes (`GGML_MAX_NAME` bound) |
| Alignment | Multiple of 8 | Multiple of 8 and power of two |
| Scalar tensors (`n_dims = 0`) | Supported (1 element = `type_size`) | Supported (1 element = `type_size`) |
| Zero dimensions | Rejected | Rejected |
| Dimension bounds | Checked `u64` arithmetic | Signed 64-bit bounds and a non-overflowing element product |

Both profiles enforce the GGUF specification's zero-padding requirement: the alignment padding between the descriptor table and the tensor data region must be `0x00` bytes. This is stricter than runtimes that align past those bytes without validating their contents.

Both profiles are deliberately safe pre-admission subsets, not full compatibility claims for every `llama.cpp` build: the `llama-cpp` profile is differential-tested against the pinned ggml revision, and divergences are enforced through an audited allowlist in CI.

## Resource Limits

All limits are validator-managed quotas over the validator's own allocations and logical work. Defaults are defined in `src/gguf/limits.zig`:

| Limit | Default | Bounds |
| :--- | :--- | :--- |
| `max_tensors` | 1,000,000 | Maximum tensor count |
| `max_metadata_entries` | 1,000,000 | Maximum metadata key/value entries |
| `max_string_bytes` | 65,536 (64 KiB) | Maximum metadata string value length (including `array[string]` elements) |
| `max_tensor_name_bytes` | 64 | Maximum tensor name length (`llama-cpp` requires less than 64) |
| `max_dimensions` | 4 | Maximum `n_dims` per tensor |
| `max_array_elements` | 10,000,000 | Maximum elements of any metadata array |
| `max_variable_array_elements` | 1,000,000 | Sanity cap for `array[string]` / nested arrays; CLI-adjustable |
| `max_metadata_depth` | 16 | Maximum nested-array depth |
| `max_total_alloc_bytes` | 128 MiB | `QuotaAllocator` ceiling for validator allocations |
| `max_work_units` | 10,000,000 | `WorkBudget` logical work units (parsing, traversal, sorting, interval scan) |
| `max_scanned_bytes` | 256 MiB | `WorkBudget` byte budget for streaming string, UTF-8, and boolean scans |

Two failure modes are kept distinct: exceeding the validator allocation quota is a policy `REJECT` (exit `2`, `E_TotalAllocationLimitExceeded`), while unbudgeted host memory starvation is an internal error (exit `70`, `EX_SOFTWARE`).

> **Deployment limits.** These budgets do not cap process RSS, page cache, stack, CPU time, or wall-clock time. For hostile multi-tenant uploads, additionally run validation under OS/container limits: a cgroup/job-object memory limit, a CPU quota plus wall-clock timeout, an input file-size limit, a read-only filesystem where possible, and a seccomp/sandbox profile.

## Verifying Releases

Tagged releases publish cross-platform binaries, `SHA256SUMS.txt`, a keyless Sigstore signature bundle (`SHA256SUMS.txt.sigstore.json`), and an SPDX 2.3 SBOM (`safegguf.spdx.json`). GitHub artifact attestations cover the release binaries: a build-provenance attestation, and an SBOM attestation whose `spdx.dev/Document` predicate is the SBOM content and whose subjects are those same binaries. The `safegguf.spdx.json` release asset itself is not an attestation subject; verify the attested SBOM content through a binary subject, as in step 4. The release workflow verifies checksums, signature, and attestations **before** publishing and aborts on any failure; signing is keyless (the release workflow's GitHub OIDC identity — no long-lived release signing key).

```bash
# 1. Verify the checksum manifest's keyless Sigstore signature
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/BrianNguyen29/SafeGGUF/\.github/workflows/ci\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt

# 2. Verify the binaries against the signed manifest
sha256sum -c SHA256SUMS.txt

# 3. Verify the build provenance attestation for a binary, pinning the signer
#    workflow and the expected source tag and commit
gh attestation verify safegguf-x86_64-linux \
  --repo BrianNguyen29/SafeGGUF \
  --signer-workflow BrianNguyen29/SafeGGUF/.github/workflows/ci.yml \
  --predicate-type https://slsa.dev/provenance/v1 \
  --source-ref refs/tags/v0.3.6 \
  --source-digest ddbf045591cd7a2c7c69252012092440025723eb

# 4. Verify the attested SBOM content (spdx.dev/Document predicate) for the
#    same binary; --format json prints the verified statement, whose
#    verificationResult.statement.predicate is the signed SBOM
gh attestation verify safegguf-x86_64-linux \
  --repo BrianNguyen29/SafeGGUF \
  --signer-workflow BrianNguyen29/SafeGGUF/.github/workflows/ci.yml \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --source-ref refs/tags/v0.3.6 \
  --source-digest ddbf045591cd7a2c7c69252012092440025723eb
```

The `--source-ref`/`--source-digest` values above are those of the latest tagged release (v0.3.6); substitute the tag and commit of the release being verified.

Do not rely on a manually compared checksum alone: the manifest is only meaningful when its signature and the binaries' provenance attestations verify.

## Embedding (Zig Library)

The library exposes a `Validator` that manages its own `QuotaAllocator` and `WorkBudget` from a `Limits` value. `validateOwned()` returns a `Result` that owns the parsed document and frees it through the captured validator-managed allocator:

```zig
const std = @import("std");
const safegguf = @import("safegguf");

pub fn validateGgufFile(allocator: std.mem.Allocator, file: std.fs.File) !void {
    const stat = try file.stat();
    var buffered = safegguf.reader.BufferedReader.init(file, stat.size);

    // Defaults: 128 MiB allocation quota, 10M work units, 256 MiB scanned bytes.
    // The profile is .gguf_spec or .llama_cpp.
    var validator = safegguf.Validator.init(allocator, .{}, .gguf_spec);

    var result = try validator.validateOwned(buffered.reader());
    defer result.deinit();

    std.debug.print("Validated: {d} tensors\n", .{result.doc.header.tensor_count});
}
```

The document's allocations live in the validator-managed allocator: call `Result.deinit()` while the producing `Validator` is still alive, and free each `Result` exactly once. A `Validator` is not thread-safe, but it can be reused sequentially; use one instance per thread or add external synchronization. The legacy `validate()` + `deinitDocument()` pair remains supported.

## Testing

Fixtures and the seed corpus are generated, not committed, so run `tests/generate_fixtures.py` before `zig build test` on a fresh clone.

```bash
# Core checks (as run by CI)
zig fmt --check src/ build.zig tests/*.zig
python tests/generate_fixtures.py
zig build test --summary all          # unit, regression, and fuzz-corpus sweep
zig build -Doptimize=ReleaseSafe
python tests/cli_test.py              # end-to-end CLI exit-code contract
python tests/negative_corpus.py       # provenance-tiered reject corpus (exit 2 per case)

# Upstream oracles and differential testing (network clone + CMake)
bash tests/build_oracle.sh            # pinned ggml 0.23.0 oracle; skips if built
python tests/arithmetic_oracle.py     # Python bigint arithmetic oracle + CLI cross-checks
python tests/test_oracle_types.py     # all 43 GGML type traits vs the C++ oracle
python tests/differential_matrix.py   # generate matrix fixtures (run before differential.py)
python tests/differential.py          # SafeGGUF vs the upstream oracle

# Benchmarks and fuzzing
zig build bench                       # resource-budget benchmark suite
python tests/fuzz_mutation.py --iterations 2000
python tests/real_corpus.py           # tier-1 real-world corpus gate (default --tier 1):
                                      # manifest-pinned downloads are size+sha256 verified
                                      # before the per-profile verdict compare; needs the
                                      # ReleaseSafe binary + network
```

CI (`.github/workflows/ci.yml`) runs `core`, `oracle`, `fuzz`, and `bench` jobs on Ubuntu 24.04 and macOS 14, plus a tier-1 `real-corpus` gate on pull requests and `v*` tags; a tag-triggered `release` job builds five targets, generates the SBOM, signs the checksum manifest, and publishes after verifying its own artifacts.

The `real-corpus` gate evaluates the manifest's tier-1 entries and enforces the runner's coverage floors, so a run with 0 verified entries can never `PASS` (`0` PASS / `1` FAIL / `3` INCONCLUSIVE, the last one NEUTRAL for a tolerated network-only failure on pull requests; `v*` tags run the gate fail-closed, where an outage, a skipped entry, or an unmet floor blocks the release). Additional scheduled workflows cover nightly fuzzing and the nightly advisory real-world corpus lane (report-only).

## Project Status

* **Latest tagged release:** v0.3.6 (tag object `f688b59`, commit `ddbf045`, published 2026-09-15); `main` currently matches the release commit.
* **Upstream type table pinned to:** ggml `0.23.0` (`e91ded11bdcd78c42f9c8d3978ff6686eb4c1226`); the Zig table must stay in sync with the pinned revision, enforced by the type-oracle and differential checks.
* **Toolchain pinned to:** Zig `0.13.0`; the project has zero Zig package dependencies and builds with the standard library only.

## Security

`PASS` means the file satisfies the selected SafeGGUF structural, arithmetic, and resource-policy checks. It is not a trust or malware verdict: it does not prove model weights are benign, chat templates are semantically safe, downstream runtime or GPU kernel code is vulnerability-free, the publisher is trusted, or that file contents cannot change between validation and use (TOCTOU). Validate in immutable content-addressed storage or verify digests immediately before admission to the runtime.

For the full threat model, invariants, deployment guidance, and reporting process, see [SECURITY.md](SECURITY.md). To report a vulnerability, use [GitHub Security Advisories](https://github.com/BrianNguyen29/SafeGGUF/security/advisories/new) rather than a public issue.

## License

MIT — see [LICENSE](LICENSE).
