const std = @import("std");

pub const ParseError = error{
    UnexpectedEof,
    InvalidMagic,
    UnsupportedVersion,
    InvalidMetadataType,
    InvalidTensorType,
    InvalidDimensionCount,
    InvalidStringLength,
    InvalidArrayLength,
    ArithmeticOverflow,
    BlockDivisibilityViolation,
    InvalidAlignment,
    MisalignedTensor,
    TensorOutOfBounds,
    TensorOverlap,
    ResourceLimitExceeded,
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
    severity: FindingSeverity,
    context: ?[]const u8 = null,
};
