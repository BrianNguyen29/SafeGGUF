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

/* Validation Profiles */
#define SAFEGGUF_PROFILE_GGUF_SPEC 0 /* Safe subset of GGUF v3 */
#define SAFEGGUF_PROFILE_LLAMA_CPP 1 /* Strict pre-admission subset for llama.cpp / ggml */

/* Endianness */
#define SAFEGGUF_ENDIAN_LITTLE 0
#define SAFEGGUF_ENDIAN_BIG    1
#define SAFEGGUF_ENDIAN_AUTO   2

/**
 * Versioned options structure for extensible per-call resource limits and configuration.
 * The caller MUST set struct_size = sizeof(safegguf_options_v1_t).
 */
typedef struct safegguf_options_v1 {
    uint32_t struct_size;          /* Must be sizeof(safegguf_options_v1_t) */
    int32_t  profile;              /* 0 = gguf-spec, 1 = llama-cpp */
    int32_t  endian;               /* 0 = little, 1 = big, 2 = auto */
    uint64_t max_alloc_bytes;      /* Per-call memory ceiling (0 = use env/default) */
    uint64_t max_work_units;       /* Per-call work unit budget (0 = use env/default) */
    uint64_t max_scanned_bytes;    /* Per-call byte scan limit (0 = use env/default) */
    void*    reserved;             /* Reserved for future expansion, must be NULL */
} safegguf_options_v1_t;

/**
 * Structured diagnostic result populated upon return.
 */
typedef struct safegguf_result {
    int32_t exit_code;             /* SafeGGUF exit code: 0, 2, 64, 70, 74 */
    char    error_code[64];        /* Specific error identifier, e.g. "ArithmeticOverflow" */
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

#ifdef __cplusplus
}
#endif

#endif /* SAFEGGUF_H */
