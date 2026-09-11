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
    CompatibilityViolation,
    ZeroDimensionNotAllowed,
    OutOfMemory,
    IoError,
};

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
};
