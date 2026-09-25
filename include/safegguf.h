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
 * Validate a GGUF model file on disk by file path.
 * 
 * @param path Null-terminated path to GGUF file.
 * @param profile Validation profile (0 = gguf-spec, 1 = llama-cpp).
 * @param endian Endianness (0 = little, 1 = big, 2 = auto-detect).
 * @return Exit code: 0 on PASS, 2 on REJECT, 74 on I/O error, 70 on software error.
 */
int safegguf_validate_path(const char* path, int profile, int endian);

/**
 * Validate an open GGUF model file descriptor directly (anti-TOCTOU).
 * 
 * @param fd Open file descriptor with read permissions.
 * @param profile Validation profile (0 = gguf-spec, 1 = llama-cpp).
 * @param endian Endianness (0 = little, 1 = big, 2 = auto-detect).
 * @return Exit code: 0 on PASS, 2 on REJECT, 74 on I/O error, 70 on software error.
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
