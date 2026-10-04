# Admission document contract (v2)

`safegguf admit <file> --cas-dir <dir> --attestations-dir <dir>` copies the
upload once, hashes the copy stream, validates its owned staged inode and
publishes the result. Output directories must already exist and be trusted.
The handoff shell wrapper calls this publisher directly.

## Version and migration

Success has `schema_version: 2` and `document_type: "safegguf-admission"`.
This is independent of inspect/error diagnostics, which retain schema v1.
The version increments because `cas.relative_path` now resolves from the
supplied **CAS directory**, not a presumed workspace parent. A CAS directory
called `objects`, `validated` or any other name behaves identically.

Admission v1 statements omitted policy controls and assumed `validated/` in
the path. Do not silently interpret them as v2. A consumer that needs complete
policy evidence must re-admit the object using the intended policy, or reject
the old statement. Reject unsupported admission schema versions.

## Bound fields

| Field | Meaning |
| --- | --- |
| `digest.algorithm`, `digest.value` | SHA-256 of the copied model bytes. |
| `size_bytes` | Actual copied byte count. |
| `verdict.status`, `verdict.validator_exit_code` | `PASS` and `0`; structural/arithmetic/resource policy only. |
| `validator.version`, `validator.source_commit` | Build version and source provenance. |
| `validator.profile` | Selected `llama-cpp` or `gguf-spec` profile. |
| `validator.endian`, `validator.resolved_endian` | Requested mode and actual byte order used. |
| `validator.zig_version`, `build_mode`, `target` | Toolchain/build/target provenance (fields inside `validator`). |
| `validator.type_layout_source` | Pinned ggml project, version and commit. |
| `validator.limits` | Every effective `Limits` field, plus mandatory `require_stable_file: true`. |
| `cas.relative_to` | Always `cas-dir`. |
| `cas.relative_path`, `cas.sha256` | Digest-only object name, and the same SHA-256. |

The limits include tensor/metadata counts, dimensions, tensor-name length,
string length, key policy, array lengths/depth, allocation quota, logical work,
scanned bytes and input size. Environment overrides are resolved before
serialization; explicit CLI values take precedence. The document contains no
arbitrary filesystem paths or wall-clock timestamps.

## Verify and replay

Treat an unsigned statement as trusted only inside a protected local handoff.
Across trust boundaries, authenticate the statement with the operator's signing
policy; a model digest alone does not authenticate its verdict. Validate schema,
profile, accepted build/type provenance and **all effective policy controls**
against the receiving service's admission policy.

Resolve `cas.relative_path` from the configured CAS root. Require it to equal
the 64-character lowercase digest (no path separators), recompute SHA-256 and
compare size before loading from storage protected against untrusted writes.
The checksum pin `<digest>.sha256` is intended for `sha256sum -c` from CAS root.

Replay with the same validator build/profile, recorded resolved endian,
`--key-policy`, `--max-string-bytes`, `--max-variable-array-elements`,
`--max-file-size-bytes` and `--require-stable-file`. Set the exact recorded
allocation/work/scan budgets through `SAFEGGUF_MAX_ALLOC_BYTES`,
`SAFEGGUF_MAX_WORK_UNITS` and `SAFEGGUF_MAX_SCANNED_BYTES`. Check the remaining
fixed parser ceilings against that build. Clear unrelated environment overrides
or explicitly replace them. A newer build or policy is a new admission decision.

## Publication and trust boundaries

The object is `<cas-dir>/<digest>`, the document is
`<attestations-dir>/<digest>.json`, and the pin is `<digest>.sha256`. Successful
stdout is byte-identical to the saved document. Concurrent writers publish
complete files via unique temporary files and atomic renames. Re-admitting one
digest under a different policy replaces its current statement; retain signed
statements separately when an audit history is required.

REJECT publishes nothing for that run and removes staging. An I/O failure after
object publication exits 74 and retains the orphan object; a document or pin
may already have been written. Consumers must require successful admission and
the complete matching outputs. The three outputs are not one filesystem
transaction, and directory renames are not a power-loss durability guarantee.

Staging uses an exclusive 0600 file in a private POSIX 0700 directory; Windows
uses filesystem access controls. FileIdentity checks bound mutation during
validation but are not cryptographic immutability. Same-identity or privileged
writers must be excluded from staging/CAS. Read-only file mode alone does not
protect a writable parent directory. Serving should mount CAS read-only.

`admit` defaults to a 16 GiB input ceiling. Copying and hashing the complete
model add disk/I/O cost beyond parser budgets; enforce admission timeouts and
OS resource/storage limits at the integration layer. PASS is not evidence of
model trust, semantic safety, or successful inference.
