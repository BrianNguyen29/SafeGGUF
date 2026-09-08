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
};
