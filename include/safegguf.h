#ifndef SAFEGGUF_H
#define SAFEGGUF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* SafeGGUF Exit Codes Taxonomy */
#define SAFEGGUF_OK          0  /* PASS: File strictly adheres to security profile */
#define SAFEGGUF_REJECT      2  /* REJECT: Malformed, overflow, tampered or quota exceeded */
#define SAFEGGUF_EX_USAGE   64  /* Usage / argument error */
#define SAFEGGUF_EX_SOFTWARE 70 /* Internal software or host OOM error */
#define SAFEGGUF_EX_IOERR    74 /* File open / stat / read error */

/* JSON output schema version (CLI `--format json`). Backward-compatible
 * additive fields keep the current version; a breaking change increments it. */
#define SAFEGGUF_SCHEMA_VERSION 1

/*
 * Canonical public error-code namespace (stable contract).
 *
 * Policy engines should key on these codes, never on the implementation
 * identifiers ("ArithmeticOverflow") or compatibility codes ("E_...") carried
 * by safegguf_result_t.error_code. Every code below is also present in the CLI
 * JSON output as `canonical_error_code`; each macro expands to the canonical
 * string itself. Codes are only ever added, never renamed.
 */
#define SGGUF_E_UNEXPECTED_EOF                 "SGGUF_E_UNEXPECTED_EOF"
#define SGGUF_E_INVALID_MAGIC                  "SGGUF_E_INVALID_MAGIC"
#define SGGUF_E_UNSUPPORTED_VERSION            "SGGUF_E_UNSUPPORTED_VERSION"
#define SGGUF_E_INVALID_METADATA_TYPE          "SGGUF_E_INVALID_METADATA_TYPE"
#define SGGUF_E_INVALID_TENSOR_TYPE            "SGGUF_E_INVALID_TENSOR_TYPE"
#define SGGUF_E_INVALID_DIMENSION_COUNT        "SGGUF_E_INVALID_DIMENSION_COUNT"
#define SGGUF_E_INVALID_STRING_LENGTH          "SGGUF_E_INVALID_STRING_LENGTH"
#define SGGUF_E_INVALID_TENSOR_NAME            "SGGUF_E_INVALID_TENSOR_NAME"
#define SGGUF_E_TENSOR_NAME_TOO_LONG           "SGGUF_E_TENSOR_NAME_TOO_LONG"
#define SGGUF_E_INVALID_KEY_FORMAT             "SGGUF_E_INVALID_KEY_FORMAT"
#define SGGUF_E_INVALID_BOOLEAN                "SGGUF_E_INVALID_BOOLEAN"
#define SGGUF_E_INVALID_UTF8                   "SGGUF_E_INVALID_UTF8"
#define SGGUF_E_INVALID_ARRAY_LENGTH           "SGGUF_E_INVALID_ARRAY_LENGTH"
#define SGGUF_E_ARITHMETIC_OVERFLOW            "SGGUF_E_ARITHMETIC_OVERFLOW"
#define SGGUF_E_BLOCK_DIVISIBILITY_VIOLATION   "SGGUF_E_BLOCK_DIVISIBILITY_VIOLATION"
#define SGGUF_E_INVALID_ALIGNMENT              "SGGUF_E_INVALID_ALIGNMENT"
#define SGGUF_E_MISALIGNED_TENSOR              "SGGUF_E_MISALIGNED_TENSOR"
#define SGGUF_E_INVALID_ALIGNMENT_PADDING      "SGGUF_E_INVALID_ALIGNMENT_PADDING"
#define SGGUF_E_TENSOR_OUT_OF_BOUNDS           "SGGUF_E_TENSOR_OUT_OF_BOUNDS"
#define SGGUF_E_TENSOR_OVERLAP                 "SGGUF_E_TENSOR_OVERLAP"
#define SGGUF_E_NON_CONTIGUOUS_TENSOR_OFFSET   "SGGUF_E_NON_CONTIGUOUS_TENSOR_OFFSET"
#define SGGUF_E_NESTED_ARRAY_NOT_SUPPORTED     "SGGUF_E_NESTED_ARRAY_NOT_SUPPORTED"
#define SGGUF_E_DUPLICATE_TENSOR_NAME          "SGGUF_E_DUPLICATE_TENSOR_NAME"
#define SGGUF_E_DUPLICATE_METADATA_KEY         "SGGUF_E_DUPLICATE_METADATA_KEY"
#define SGGUF_E_RECURSION_DEPTH_EXCEEDED       "SGGUF_E_RECURSION_DEPTH_EXCEEDED"
#define SGGUF_E_RESOURCE_LIMIT                 "SGGUF_E_RESOURCE_LIMIT"
#define SGGUF_E_TOTAL_ALLOCATION_LIMIT_EXCEEDED "SGGUF_E_TOTAL_ALLOCATION_LIMIT_EXCEEDED"
#define SGGUF_E_FILE_TOO_LARGE                 "SGGUF_E_FILE_TOO_LARGE"
#define SGGUF_E_COMPATIBILITY_VIOLATION        "SGGUF_E_COMPATIBILITY_VIOLATION"
#define SGGUF_E_ZERO_DIMENSION_NOT_ALLOWED     "SGGUF_E_ZERO_DIMENSION_NOT_ALLOWED"
#define SGGUF_E_OUT_OF_MEMORY                  "SGGUF_E_OUT_OF_MEMORY"
#define SGGUF_E_IO_ERROR                       "SGGUF_E_IO_ERROR"

/* Filesystem / descriptor / usage conditions outside the parse error set. */
#define SGGUF_E_FILE_OPEN_FAILED               "SGGUF_E_FILE_OPEN_FAILED"
#define SGGUF_E_FILE_STAT_FAILED               "SGGUF_E_FILE_STAT_FAILED"
#define SGGUF_E_FILE_CHANGED_DURING_VALIDATION "SGGUF_E_FILE_CHANGED_DURING_VALIDATION"
#define SGGUF_E_USAGE_INVALID_OPTIONS          "SGGUF_E_USAGE_INVALID_OPTIONS"
#define SGGUF_E_USAGE_INVALID_PROFILE          "SGGUF_E_USAGE_INVALID_PROFILE"
#define SGGUF_E_USAGE_INVALID_ENDIAN           "SGGUF_E_USAGE_INVALID_ENDIAN"
#define SGGUF_E_USAGE_NULL_PATH                "SGGUF_E_USAGE_NULL_PATH"
#define SGGUF_E_IO_INVALID_PATH                "SGGUF_E_IO_INVALID_PATH"
#define SGGUF_E_INVALID_FD                     "SGGUF_E_INVALID_FD"
#define SGGUF_E_INVALID_HANDLE                 "SGGUF_E_INVALID_HANDLE"
#define SGGUF_E_FD_STAT_FAILED                 "SGGUF_E_FD_STAT_FAILED"

/* Fallback for identifiers outside the canonical namespace. */
#define SGGUF_E_UNKNOWN                        "SGGUF_E_UNKNOWN"

/* Validation Profiles */
#define SAFEGGUF_PROFILE_GGUF_SPEC 0 /* Safe subset of GGUF v3 */
#define SAFEGGUF_PROFILE_LLAMA_CPP 1 /* Strict pre-admission subset for llama.cpp / ggml */

/* Endianness */
#define SAFEGGUF_ENDIAN_LITTLE 0
#define SAFEGGUF_ENDIAN_BIG    1
#define SAFEGGUF_ENDIAN_AUTO   2

/**
 * Versioned options structure for extensible per-call resource limits and configuration.
 *
 * The caller MUST set struct_size to sizeof() of the layout it was compiled
 * against: either the previous v1.0 layout or the current one. struct_size
 * gates the appended fields, so a caller compiled against v1.0 keeps the
 * legacy defaults (max_file_size_bytes = 0 -> unlimited, require_stable_file
 * = 0 -> off). Unknown sizes are rejected (64, E_USAGE_INVALID_OPTIONS).
 *
 * Ownership and threading: the struct is caller-owned and read only for the
 * duration of the call - the library neither retains nor frees it (or the
 * reserved pointer). Calls are independent and safe to make concurrently;
 * a single options struct must not be mutated while a call using it runs.
 */
typedef struct safegguf_options_v1 {
    uint32_t struct_size;          /* sizeof() of the layout the caller compiled against; must remain valid during the call */
    int32_t  profile;              /* 0 = gguf-spec, 1 = llama-cpp */
    int32_t  endian;               /* 0 = little, 1 = big, 2 = auto */
    uint64_t max_alloc_bytes;      /* Per-call memory ceiling (0 = use env/default) */
    uint64_t max_work_units;       /* Per-call work unit budget (0 = use env/default) */
    uint64_t max_scanned_bytes;    /* Per-call byte scan limit (0 = use env/default) */
    void*    reserved;             /* Reserved for future expansion, must be NULL */
    uint64_t max_file_size_bytes;  /* Appended (v1.1): input admission ceiling in bytes, checked before the first read (0 = unlimited, default) */
    uint32_t require_stable_file;  /* Appended (v1.1): 0 = off (default), 1 = REJECT (2, E_FileChangedDuringValidation) if the open file's identity changes during validation */
} safegguf_options_v1_t;

/**
 * Structured diagnostic result populated upon return.
 *
 * `error_code` carries a compatibility identifier (an implementation name such
 * as "ArithmeticOverflow", or a code such as "E_FILE_OPEN_FAILED"). Key policy
 * decisions on the canonical `SGGUF_E_*` namespace: map this field through
 * safegguf_canonical_error_code().
 */
typedef struct safegguf_result {
    int32_t exit_code;             /* SafeGGUF exit code: 0, 2, 64, 70, 74 */
    char    error_code[64];        /* Compatibility error identifier; map with safegguf_canonical_error_code() */
    char    category[32];          /* Error category, e.g. "arithmetic", "format", "usage" */
    char    stage[32];             /* Validation stage, e.g. "validation", "options" */
    char    message[256];          /* Human-readable diagnostic description */
} safegguf_result_t;

/**
 * Validate a GGUF model file on disk by path (v1 versioned API).
 * 
 * @param path Null-terminated path to GGUF file.
 * @param options Pointer to safegguf_options_v1_t (optional, can be NULL).
 * @param out_result Pointer to safegguf_result_t for structured diagnostics (optional, can be NULL).
 * @return Exit code: 0 on PASS, 2 on REJECT, 64 on USAGE, 74 on I/O, 70 on software error.
 */
int safegguf_validate_path_v1(
    const char* path,
    const safegguf_options_v1_t* options,
    safegguf_result_t* out_result
);

/**
 * Validate an open GGUF model file descriptor directly (v1 versioned API, anti-TOCTOU).
 * 
 * @param fd Open file descriptor with read permissions.
 * @param options Pointer to safegguf_options_v1_t (optional, can be NULL).
 * @param out_result Pointer to safegguf_result_t for structured diagnostics (optional, can be NULL).
 * @return Exit code: 0 on PASS, 2 on REJECT, 64 on USAGE, 74 on I/O, 70 on software error.
 */
int safegguf_validate_fd_v1(
    intptr_t fd,
    const safegguf_options_v1_t* options,
    safegguf_result_t* out_result
);

/**
 * Legacy API: Validate a GGUF model file on disk by file path.
 * 
 * @param path Null-terminated path to GGUF file.
 * @param profile Validation profile (0 = gguf-spec, 1 = llama-cpp).
 * @param endian Endianness (0 = little, 1 = big, 2 = auto-detect).
 * @return Exit code: 0 on PASS, 2 on REJECT, 64 on USAGE, 74 on I/O, 70 on software error.
 */
int safegguf_validate_path(const char* path, int profile, int endian);

/**
 * Legacy API: Validate an open GGUF model file descriptor directly (anti-TOCTOU).
 * 
 * @param fd Open file descriptor with read permissions.
 * @param profile Validation profile (0 = gguf-spec, 1 = llama-cpp).
 * @param endian Endianness (0 = little, 1 = big, 2 = auto-detect).
 * @return Exit code: 0 on PASS, 2 on REJECT, 64 on USAGE, 74 on I/O, 70 on software error.
 */
int safegguf_validate_fd(intptr_t fd, int profile, int endian);

/**
 * Return SafeGGUF library version string.
 */
const char* safegguf_version(void);

/**
 * Map a safegguf_result_t.error_code value to its canonical SGGUF_E_* code.
 *
 * Accepts the implementation identifiers ("ArithmeticOverflow") and
 * compatibility codes ("E_FILE_OPEN_FAILED") emitted by this library, plus
 * canonical codes already in the namespace (returned unchanged). The returned
 * pointer is a static string that must not be freed; NULL and unmapped input
 * return SGGUF_E_UNKNOWN.
 */
const char* safegguf_canonical_error_code(const char* error_code);

#ifdef __cplusplus
}
#endif

#endif /* SAFEGGUF_H */
