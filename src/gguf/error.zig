const std = @import("std");

pub const ParseError = error{
    UnexpectedEof,
    InvalidMagic,
    UnsupportedVersion,
    InvalidMetadataType,
    InvalidTensorType,
    InvalidDimensionCount,
    InvalidStringLength,
    InvalidTensorName,
    TensorNameTooLong,
    InvalidKeyFormat,
    InvalidBoolean,
    InvalidUtf8,
    InvalidArrayLength,
    ArithmeticOverflow,
    BlockDivisibilityViolation,
    InvalidAlignment,
    MisalignedTensor,
    InvalidAlignmentPadding,
    TensorOutOfBounds,
    TensorOverlap,
    NonContiguousTensorOffset,
    NestedArrayNotSupported,
    DuplicateTensorName,
    DuplicateMetadataKey,
    RecursionDepthExceeded,
    ResourceLimitExceeded,
    TotalAllocationLimitExceeded,
    FileTooLarge,
    CompatibilityViolation,
    ZeroDimensionNotAllowed,
    OutOfMemory,
    IoError,
};

/// Canonical public error-code namespace (`SGGUF_E_*`): the stable contract for
/// policy engines and downstream consumers. Internal `ParseError` names and the
/// legacy `E_*` codes emitted for compatibility are implementation details -
/// use `publicCodeOf` / `canonicalFromLegacy` (CLI JSON `canonical_error_code`,
/// or the C ABI's `safegguf_canonical_error_code`) to obtain the canonical
/// code. Canonical codes are only ever added, never renamed.
pub const public_codes = struct {
    pub const unknown: [:0]const u8 = "SGGUF_E_UNKNOWN";
    pub const file_open_failed: [:0]const u8 = "SGGUF_E_FILE_OPEN_FAILED";
    pub const file_stat_failed: [:0]const u8 = "SGGUF_E_FILE_STAT_FAILED";
    pub const file_changed_during_validation: [:0]const u8 = "SGGUF_E_FILE_CHANGED_DURING_VALIDATION";
    pub const usage_invalid_options: [:0]const u8 = "SGGUF_E_USAGE_INVALID_OPTIONS";
    pub const usage_invalid_profile: [:0]const u8 = "SGGUF_E_USAGE_INVALID_PROFILE";
    pub const usage_invalid_endian: [:0]const u8 = "SGGUF_E_USAGE_INVALID_ENDIAN";
    pub const usage_null_path: [:0]const u8 = "SGGUF_E_USAGE_NULL_PATH";
    pub const io_invalid_path: [:0]const u8 = "SGGUF_E_IO_INVALID_PATH";
    pub const invalid_fd: [:0]const u8 = "SGGUF_E_INVALID_FD";
    pub const invalid_handle: [:0]const u8 = "SGGUF_E_INVALID_HANDLE";
    pub const fd_stat_failed: [:0]const u8 = "SGGUF_E_FD_STAT_FAILED";
    /// Context-dependent canonical detail for the llama.cpp dimension-product
    /// guard. The legacy `error_code` for that rejection stays
    /// `CompatibilityViolation`; this code is surfaced out-of-band (CLI JSON
    /// `canonical_error_code`, or `safegguf_result_canonical_error_code` in
    /// the C ABI) and distinguishes it from a true checked-arithmetic wrap
    /// (`SGGUF_E_ARITHMETIC_OVERFLOW`).
    pub const dimension_overflow: [:0]const u8 = "SGGUF_E_DIMENSION_OVERFLOW";
};

/// Specific diagnostic for the llama.cpp dimension-product guard; the generic
/// `CompatibilityViolation` message stays in use for every other rejection
/// carrying that legacy code. The C ABI accessor keys the canonical detail
/// split on this message, so it is a stable, pinned contract string.
pub const dimension_overflow_message = "Tensor dimensions exceed the llama.cpp signed 64-bit element-count limit";

pub const LegacyPublicCode = struct {
    legacy: []const u8,
    canonical: [:0]const u8,
};

/// Legacy codes emitted by the CLI/C ABI that do not correspond 1:1 to a
/// `ParseError` variant, mapped to their canonical public codes.
pub const legacy_public_codes = [_]LegacyPublicCode{
    .{ .legacy = "E_FILE_OPEN_FAILED", .canonical = public_codes.file_open_failed },
    .{ .legacy = "E_FILE_STAT_FAILED", .canonical = public_codes.file_stat_failed },
    .{ .legacy = "E_FileChangedDuringValidation", .canonical = public_codes.file_changed_during_validation },
    .{ .legacy = "E_OUT_OF_MEMORY", .canonical = "SGGUF_E_OUT_OF_MEMORY" },
    .{ .legacy = "E_USAGE_INVALID_OPTIONS", .canonical = public_codes.usage_invalid_options },
    .{ .legacy = "E_USAGE_INVALID_PROFILE", .canonical = public_codes.usage_invalid_profile },
    .{ .legacy = "E_USAGE_INVALID_ENDIAN", .canonical = public_codes.usage_invalid_endian },
    .{ .legacy = "E_USAGE_NULL_PATH", .canonical = public_codes.usage_null_path },
    .{ .legacy = "E_IO_INVALID_PATH", .canonical = public_codes.io_invalid_path },
    .{ .legacy = "E_INVALID_FD", .canonical = public_codes.invalid_fd },
    .{ .legacy = "E_INVALID_HANDLE", .canonical = public_codes.invalid_handle },
    .{ .legacy = "E_FD_STAT_FAILED", .canonical = public_codes.fd_stat_failed },
};

/// Canonical public code for an internal parse/validation error. Exhaustive: a
/// new `ParseError` variant without a row fails compilation.
pub fn publicCodeOf(e: ParseError) [:0]const u8 {
    return switch (e) {
        error.UnexpectedEof => "SGGUF_E_UNEXPECTED_EOF",
        error.InvalidMagic => "SGGUF_E_INVALID_MAGIC",
        error.UnsupportedVersion => "SGGUF_E_UNSUPPORTED_VERSION",
        error.InvalidMetadataType => "SGGUF_E_INVALID_METADATA_TYPE",
        error.InvalidTensorType => "SGGUF_E_INVALID_TENSOR_TYPE",
        error.InvalidDimensionCount => "SGGUF_E_INVALID_DIMENSION_COUNT",
        error.InvalidStringLength => "SGGUF_E_INVALID_STRING_LENGTH",
        error.InvalidTensorName => "SGGUF_E_INVALID_TENSOR_NAME",
        error.TensorNameTooLong => "SGGUF_E_TENSOR_NAME_TOO_LONG",
        error.InvalidKeyFormat => "SGGUF_E_INVALID_KEY_FORMAT",
        error.InvalidBoolean => "SGGUF_E_INVALID_BOOLEAN",
        error.InvalidUtf8 => "SGGUF_E_INVALID_UTF8",
        error.InvalidArrayLength => "SGGUF_E_INVALID_ARRAY_LENGTH",
        error.ArithmeticOverflow => "SGGUF_E_ARITHMETIC_OVERFLOW",
        error.BlockDivisibilityViolation => "SGGUF_E_BLOCK_DIVISIBILITY_VIOLATION",
        error.InvalidAlignment => "SGGUF_E_INVALID_ALIGNMENT",
        error.MisalignedTensor => "SGGUF_E_MISALIGNED_TENSOR",
        error.InvalidAlignmentPadding => "SGGUF_E_INVALID_ALIGNMENT_PADDING",
        error.TensorOutOfBounds => "SGGUF_E_TENSOR_OUT_OF_BOUNDS",
        error.TensorOverlap => "SGGUF_E_TENSOR_OVERLAP",
        error.NonContiguousTensorOffset => "SGGUF_E_NON_CONTIGUOUS_TENSOR_OFFSET",
        error.NestedArrayNotSupported => "SGGUF_E_NESTED_ARRAY_NOT_SUPPORTED",
        error.DuplicateTensorName => "SGGUF_E_DUPLICATE_TENSOR_NAME",
        error.DuplicateMetadataKey => "SGGUF_E_DUPLICATE_METADATA_KEY",
        error.RecursionDepthExceeded => "SGGUF_E_RECURSION_DEPTH_EXCEEDED",
        error.ResourceLimitExceeded => "SGGUF_E_RESOURCE_LIMIT",
        error.TotalAllocationLimitExceeded => "SGGUF_E_TOTAL_ALLOCATION_LIMIT_EXCEEDED",
        error.FileTooLarge => "SGGUF_E_FILE_TOO_LARGE",
        error.CompatibilityViolation => "SGGUF_E_COMPATIBILITY_VIOLATION",
        error.ZeroDimensionNotAllowed => "SGGUF_E_ZERO_DIMENSION_NOT_ALLOWED",
        error.OutOfMemory => "SGGUF_E_OUT_OF_MEMORY",
        error.IoError => "SGGUF_E_IO_ERROR",
    };
}

/// Static reference to a canonical public code by value, or null when `code`
/// is outside the `SGGUF_E_*` namespace. Unlike `canonicalFromLegacy`, this
/// accepts canonical codes directly (returned as-is) and is exhaustive over
/// the namespace, including additive context-dependent details such as
/// `public_codes.dimension_overflow`.
pub fn canonicalCodeRef(code: []const u8) ?[:0]const u8 {
    if (std.mem.eql(u8, code, public_codes.unknown)) return public_codes.unknown;
    if (std.mem.eql(u8, code, public_codes.dimension_overflow)) return public_codes.dimension_overflow;
    for (legacy_public_codes) |entry| {
        if (std.mem.eql(u8, code, entry.canonical)) return entry.canonical;
    }
    inline for (@typeInfo(ParseError).ErrorSet.?) |variant| {
        const e: ParseError = @field(ParseError, variant.name);
        const canonical = publicCodeOf(e);
        if (std.mem.eql(u8, code, canonical)) return canonical;
    }
    return null;
}

/// True when `code` is a canonical public code in the `SGGUF_E_*` namespace.
pub fn isPublicCode(code: []const u8) bool {
    return canonicalCodeRef(code) != null;
}

/// Maps a legacy/internal identifier to its canonical public code. Accepts the
/// CLI's `E_*` codes and the C ABI's bare Zig error names; returns null when
/// the identifier is outside the canonical namespace.
pub fn canonicalFromLegacy(code: []const u8) ?[:0]const u8 {
    for (legacy_public_codes) |entry| {
        if (std.mem.eql(u8, code, entry.legacy)) return entry.canonical;
    }
    const bare = if (std.mem.startsWith(u8, code, "E_")) code[2..] else code;
    inline for (@typeInfo(ParseError).ErrorSet.?) |variant| {
        if (std.mem.eql(u8, bare, variant.name)) {
            const e: ParseError = @field(ParseError, variant.name);
            return publicCodeOf(e);
        }
    }
    return null;
}

pub const FindingSeverity = enum {
    info,
    warning,
    reject,
};

/// Triage categories for rejections; consumed by policy engines to pick a
/// response (quarantine / manual review / retry / alert).
pub const ErrorCategory = enum {
    format,
    compatibility,
    arithmetic,
    resource,
    io,
    internal,
};

/// Per-variant category table. Exhaustive: adding a ParseError variant
/// without a category row fails compilation.
pub fn categoryOf(e: ParseError) ErrorCategory {
    return switch (e) {
        error.UnexpectedEof => .format,
        error.InvalidMagic => .format,
        error.UnsupportedVersion => .format,
        error.InvalidMetadataType => .format,
        error.InvalidTensorType => .format,
        error.InvalidDimensionCount => .format,
        error.InvalidStringLength => .format,
        error.InvalidTensorName => .format,
        error.TensorNameTooLong => .compatibility,
        error.InvalidKeyFormat => .format,
        error.InvalidBoolean => .format,
        error.InvalidUtf8 => .format,
        error.InvalidArrayLength => .format,
        error.ArithmeticOverflow => .arithmetic,
        error.BlockDivisibilityViolation => .arithmetic,
        error.InvalidAlignment => .format,
        error.MisalignedTensor => .format,
        error.InvalidAlignmentPadding => .format,
        error.TensorOutOfBounds => .format,
        error.TensorOverlap => .format,
        error.NonContiguousTensorOffset => .compatibility,
        error.NestedArrayNotSupported => .compatibility,
        error.DuplicateTensorName => .format,
        error.DuplicateMetadataKey => .format,
        error.RecursionDepthExceeded => .resource,
        error.ResourceLimitExceeded => .resource,
        error.TotalAllocationLimitExceeded => .resource,
        error.FileTooLarge => .resource,
        error.CompatibilityViolation => .compatibility,
        error.ZeroDimensionNotAllowed => .format,
        error.OutOfMemory => .resource,
        error.IoError => .io,
    };
}

/// Per-variant human-readable message; replaces the single generic
/// "Validator rejected untrusted GGUF stream" finding message.
pub fn messageOf(e: ParseError) []const u8 {
    return switch (e) {
        error.UnexpectedEof => "Truncated file: GGUF structure extends past end of file",
        error.InvalidMagic => "Invalid magic bytes: not a GGUF file",
        error.UnsupportedVersion => "GGUF version not supported by the selected profile",
        error.InvalidMetadataType => "Unknown or invalid metadata value type",
        error.InvalidTensorType => "Unknown, deprecated, or removed GGML tensor type",
        error.InvalidDimensionCount => "Tensor dimension count out of allowed range",
        error.InvalidStringLength => "String length out of allowed range",
        error.InvalidTensorName => "Invalid tensor name (empty or exceeds length limit)",
        error.TensorNameTooLong => "Tensor name exceeds the llama.cpp 64-byte limit",
        error.InvalidKeyFormat => "Metadata key violates the GGUF key grammar",
        error.InvalidBoolean => "Boolean value must be 0 or 1",
        error.InvalidUtf8 => "String or tensor name is not valid UTF-8",
        error.InvalidArrayLength => "Array length out of allowed range",
        error.ArithmeticOverflow => "Checked arithmetic overflow while computing tensor layout",
        error.BlockDivisibilityViolation => "Tensor row length not divisible by type block size",
        error.InvalidAlignment => "Alignment must be a positive multiple of 8",
        error.MisalignedTensor => "Tensor offset is not aligned to the file alignment",
        error.InvalidAlignmentPadding => "Alignment padding bytes are non-zero",
        error.TensorOutOfBounds => "Tensor data extends past end of file",
        error.TensorOverlap => "Tensor data ranges overlap",
        error.NonContiguousTensorOffset => "Tensor offsets are not strictly contiguous (llama.cpp layout)",
        error.NestedArrayNotSupported => "Nested metadata arrays are not supported by llama.cpp",
        error.DuplicateTensorName => "Duplicate tensor name",
        error.DuplicateMetadataKey => "Duplicate metadata key",
        error.RecursionDepthExceeded => "Metadata array nesting depth exceeded",
        error.ResourceLimitExceeded => "Configured resource limit exceeded",
        error.TotalAllocationLimitExceeded => "Configured memory allocation quota exceeded",
        error.FileTooLarge => "File size exceeds the configured admission limit",
        error.CompatibilityViolation => "File violates upstream ggml compatibility invariants",
        error.ZeroDimensionNotAllowed => "Tensor dimensions must be positive",
        error.OutOfMemory => "Host memory allocation failed",
        error.IoError => "I/O error while reading file",
    };
}

/// Diagnostic snapshot of where parsing/validation stood when an error was
/// raised. String fields are owned inline snapshots, never borrowed slices:
/// the parser's key/name buffers are freed while unwinding, so the context
/// must keep its own copy. Keys longer than `key_snapshot_max` are truncated
/// and flagged via `key_truncated`.
pub const ParseContext = struct {
    /// Diagnostics snapshot cap for metadata keys (GGUF keys validate at
    /// <= 65535 bytes; only a bounded prefix is needed for findings).
    pub const key_snapshot_max = 256;
    /// Matches limits.max_tensor_name_bytes (llama.cpp GGML_MAX_NAME).
    pub const tensor_name_snapshot_max = 64;

    stage: []const u8 = "",
    current_offset: ?u64 = null,
    metadata_index: ?u64 = null,
    tensor_index: ?u64 = null,
    expected_offset: ?u64 = null,
    key_buf: [key_snapshot_max]u8 = undefined,
    key_len: usize = 0,
    key_truncated: bool = false,
    name_buf: [tensor_name_snapshot_max]u8 = undefined,
    name_len: usize = 0,
    /// Additive canonical detail for a context-dependent rejection: a
    /// `SGGUF_E_*` code that refines a legacy error code whose cause is only
    /// known at the raise site (see `public_codes.dimension_overflow`).
    /// Static string owned by the canonical namespace, never a borrowed slice.
    canonical_detail: ?[:0]const u8 = null,

    /// Starts a new phase ("parse" / "structural"): stamps the stage and
    /// clears fields that can only describe other phases.
    pub fn beginPhase(self: *ParseContext, stage: []const u8) void {
        self.stage = stage;
        self.current_offset = null;
        self.expected_offset = null;
        self.metadata_index = null;
        self.tensor_index = null;
        self.key_len = 0;
        self.key_truncated = false;
        self.name_len = 0;
        self.canonical_detail = null;
    }

    /// Records the additive canonical detail for the rejection being raised.
    pub fn setCanonicalDetail(self: *ParseContext, code: [:0]const u8) void {
        self.canonical_detail = code;
    }

    pub fn setKey(self: *ParseContext, key_bytes: []const u8) void {
        const n = @min(key_bytes.len, key_snapshot_max);
        @memcpy(self.key_buf[0..n], key_bytes[0..n]);
        self.key_len = n;
        self.key_truncated = key_bytes.len > key_snapshot_max;
    }

    pub fn setTensorName(self: *ParseContext, name: []const u8) void {
        const n = @min(name.len, tensor_name_snapshot_max);
        @memcpy(self.name_buf[0..n], name[0..n]);
        self.name_len = n;
    }

    pub fn key(self: *const ParseContext) []const u8 {
        return self.key_buf[0..self.key_len];
    }

    pub fn tensorName(self: *const ParseContext) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const Finding = struct {
    code: []const u8,
    message: []const u8,
    severity: FindingSeverity = .reject,
    stage: []const u8 = "validation",
    tensor: ?[]const u8 = null,
    tensor_index: ?usize = null,
    offset: ?u64 = null,
    expected_offset: ?u64 = null,
    context: ?[]const u8 = null,
    category: ?ErrorCategory = null,
    key: ?[]const u8 = null,
    key_truncated: bool = false,
    /// Additive canonical detail code when the rejection's legacy `code` is
    /// context-dependent; renderers prefer it over the generic legacy
    /// mapping (see `public_codes.dimension_overflow`).
    canonical_detail: ?[:0]const u8 = null,
};
