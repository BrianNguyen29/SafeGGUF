pub const types = @import("gguf/types.zig");
pub const error_types = @import("gguf/error.zig");
pub const limits = @import("gguf/limits.zig");
pub const reader = @import("gguf/reader.zig");
pub const metadata = @import("gguf/metadata.zig");
pub const parser = @import("gguf/parser.zig");
pub const arithmetic = @import("validate/arithmetic.zig");
pub const structural = @import("validate/structural.zig");
pub const validator = @import("validate/validator.zig");
pub const Validator = validator.Validator;
pub const metrics = @import("metrics.zig");
pub const log = @import("log.zig");
pub const Result = validator.Result;
pub const OwnedValidationState = validator.OwnedValidationState;

/// Schema version carried by CLI `--format json` output (`schema_version`).
/// Backward-compatible additive fields keep the current version; a breaking
/// change increments it. Mirrored by `SAFEGGUF_SCHEMA_VERSION` in
/// include/safegguf.h.
pub const json_schema_version: u32 = 1;
/// Admission documents v2 bind effective policy and resolve CAS paths from
/// --cas-dir. Independent of inspect diagnostics (schema version 1).
pub const attestation_schema_version: u32 = 2;
