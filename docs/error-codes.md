# Canonical Error Codes & JSON Schema Version

This document is the contract of record for SafeGGUF diagnostics. Policy
engines, admission controllers, and triage tooling should key on the
**canonical `SGGUF_E_*` namespace** and the CLI **`schema_version`** field — not
on implementation enum names, not on the legacy `E_*` codes (kept only for
backward compatibility).

## How to obtain a canonical code

| Surface | How |
| :--- | :--- |
| CLI `--format json` | Every ERROR/REJECT object carries `canonical_error_code` next to the compatibility `error_code`. |
| C ABI (`include/safegguf.h`) | `safegguf_result_t.error_code` keeps the compatibility identifier (e.g. `"ArithmeticOverflow"`, `"E_FILE_OPEN_FAILED"`); map it with `safegguf_canonical_error_code()`. |
| In-tree (Zig) | `safegguf.error_types.publicCodeOf(ParseError)` and `canonicalFromLegacy(code)`. |

`canonicalFromLegacy` / `safegguf_canonical_error_code` accept:

- bare implementation names (`ArithmeticOverflow`),
- CLI/FFI compatibility codes (`E_ArithmeticOverflow`, `E_FILE_OPEN_FAILED`),
- canonical codes already in the namespace (returned unchanged).

Unmapped input (and `NULL`) maps to `SGGUF_E_UNKNOWN`.

## Canonical namespace

`Category` values match the CLI `category` field (`format | compatibility |
arithmetic | resource | io | internal`, plus `usage` for C-ABI option errors).
Codes are only ever added, never renamed.

### Validation errors (`ParseError`)

| Compatibility code (CLI) | Canonical code | Category | Exit |
| :--- | :--- | :--- | :---: |
| `E_UnexpectedEof` | `SGGUF_E_UNEXPECTED_EOF` | format | 2 |
| `E_InvalidMagic` | `SGGUF_E_INVALID_MAGIC` | format | 2 |
| `E_UnsupportedVersion` | `SGGUF_E_UNSUPPORTED_VERSION` | format | 2 |
| `E_InvalidMetadataType` | `SGGUF_E_INVALID_METADATA_TYPE` | format | 2 |
| `E_InvalidTensorType` | `SGGUF_E_INVALID_TENSOR_TYPE` | format | 2 |
| `E_InvalidDimensionCount` | `SGGUF_E_INVALID_DIMENSION_COUNT` | format | 2 |
| `E_InvalidStringLength` | `SGGUF_E_INVALID_STRING_LENGTH` | format | 2 |
| `E_InvalidTensorName` | `SGGUF_E_INVALID_TENSOR_NAME` | format | 2 |
| `E_TensorNameTooLong` | `SGGUF_E_TENSOR_NAME_TOO_LONG` | compatibility | 2 |
| `E_InvalidKeyFormat` | `SGGUF_E_INVALID_KEY_FORMAT` | format | 2 |
| `E_InvalidBoolean` | `SGGUF_E_INVALID_BOOLEAN` | format | 2 |
| `E_InvalidUtf8` | `SGGUF_E_INVALID_UTF8` | format | 2 |
| `E_InvalidArrayLength` | `SGGUF_E_INVALID_ARRAY_LENGTH` | format | 2 |
| `E_ArithmeticOverflow` | `SGGUF_E_ARITHMETIC_OVERFLOW` | arithmetic | 2 |
| `E_BlockDivisibilityViolation` | `SGGUF_E_BLOCK_DIVISIBILITY_VIOLATION` | arithmetic | 2 |
| `E_InvalidAlignment` | `SGGUF_E_INVALID_ALIGNMENT` | format | 2 |
| `E_MisalignedTensor` | `SGGUF_E_MISALIGNED_TENSOR` | format | 2 |
| `E_InvalidAlignmentPadding` | `SGGUF_E_INVALID_ALIGNMENT_PADDING` | format | 2 |
| `E_TensorOutOfBounds` | `SGGUF_E_TENSOR_OUT_OF_BOUNDS` | format | 2 |
| `E_TensorOverlap` | `SGGUF_E_TENSOR_OVERLAP` | format | 2 |
| `E_NonContiguousTensorOffset` | `SGGUF_E_NON_CONTIGUOUS_TENSOR_OFFSET` | compatibility | 2 |
| `E_NestedArrayNotSupported` | `SGGUF_E_NESTED_ARRAY_NOT_SUPPORTED` | compatibility | 2 |
| `E_DuplicateTensorName` | `SGGUF_E_DUPLICATE_TENSOR_NAME` | format | 2 |
| `E_DuplicateMetadataKey` | `SGGUF_E_DUPLICATE_METADATA_KEY` | format | 2 |
| `E_RecursionDepthExceeded` | `SGGUF_E_RECURSION_DEPTH_EXCEEDED` | resource | 2 |
| `E_ResourceLimitExceeded` | `SGGUF_E_RESOURCE_LIMIT` | resource | 2 |
| `E_TotalAllocationLimitExceeded` | `SGGUF_E_TOTAL_ALLOCATION_LIMIT_EXCEEDED` | resource | 2 |
| `E_FileTooLarge` | `SGGUF_E_FILE_TOO_LARGE` | resource | 2 |
| `E_CompatibilityViolation` | `SGGUF_E_COMPATIBILITY_VIOLATION` | compatibility | 2 |
| `E_ZeroDimensionNotAllowed` | `SGGUF_E_ZERO_DIMENSION_NOT_ALLOWED` | format | 2 |
| `OutOfMemory` (bare, C ABI) / `E_OUT_OF_MEMORY` (CLI host OOM) | `SGGUF_E_OUT_OF_MEMORY` | resource | 70 (host OOM); quota exhaustion folds into `SGGUF_E_TOTAL_ALLOCATION_LIMIT_EXCEEDED` (2) |
| `E_IoError` | `SGGUF_E_IO_ERROR` | io | 74 |

### Filesystem, descriptor, and usage conditions

| Compatibility code | Canonical code | Category | Exit |
| :--- | :--- | :--- | :---: |
| `E_FILE_OPEN_FAILED` | `SGGUF_E_FILE_OPEN_FAILED` | io | 74 |
| `E_FILE_STAT_FAILED` | `SGGUF_E_FILE_STAT_FAILED` | io | 74 |
| `E_FileChangedDuringValidation` | `SGGUF_E_FILE_CHANGED_DURING_VALIDATION` | io | 2 |
| `E_USAGE_INVALID_OPTIONS` | `SGGUF_E_USAGE_INVALID_OPTIONS` | usage | 64 |
| `E_USAGE_INVALID_PROFILE` | `SGGUF_E_USAGE_INVALID_PROFILE` | usage | 64 |
| `E_USAGE_INVALID_ENDIAN` | `SGGUF_E_USAGE_INVALID_ENDIAN` | usage | 64 |
| `E_USAGE_NULL_PATH` | `SGGUF_E_USAGE_NULL_PATH` | usage | 64 |
| `E_IO_INVALID_PATH` | `SGGUF_E_IO_INVALID_PATH` | io | 74 |
| `E_INVALID_FD` | `SGGUF_E_INVALID_FD` | io | 74 |
| `E_INVALID_HANDLE` | `SGGUF_E_INVALID_HANDLE` | io | 74 |
| `E_FD_STAT_FAILED` | `SGGUF_E_FD_STAT_FAILED` | io | 74 |
| (unmapped identifier) | `SGGUF_E_UNKNOWN` | — | — |

The legacy `error_code` field is retained unchanged in CLI JSON and the C ABI
so existing consumers keep working; new integrations should only depend on the
canonical namespace.

## JSON schema version

Every CLI `--format json` object (PASS, REJECT, ERROR) starts with
`"schema_version": 1`:

```json
{
  "schema_version": 1,
  "status": "REJECT",
  "error_code": "E_ArithmeticOverflow",
  "canonical_error_code": "SGGUF_E_ARITHMETIC_OVERFLOW",
  "category": "arithmetic",
  "stage": "structural"
}
```

Policy (semver-style, applied to the output document):

- **Additive fields keep the current version.** Do not bump on new optional
  fields; consumers must ignore unknown fields.
- **A breaking change increments the version** (removed/renamed field, changed
  type or meaning of an existing field).

The version is defined once in `src/root.zig` (`json_schema_version`) and
mirrored by `SAFEGGUF_SCHEMA_VERSION` in `include/safegguf.h`; the contract
test suite (`tests/contract_test.zig`) keeps the two, the header macro
namespace, and every emitted error-code literal in sync.
