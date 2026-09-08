const std = @import("std");

pub const MAGIC: [4]u8 = "GGUF".*;
pub const VERSION: u32 = 3;
pub const DEFAULT_ALIGNMENT: u64 = 32;

/// Pinned upstream compatibility reference:
/// ggml 0.23.0 (commit e91ded11bdcd78c42f9c8d3978ff6686eb4c1226)
pub const GGML_PINNED_VERSION = "0.23.0";
pub const GGML_PINNED_COMMIT = "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226";
pub const GGML_TYPE_COUNT: u32 = 43;
pub const ACTIVE_TYPE_COUNT: u32 = 35;

pub const Profile = enum {
    gguf_spec, // Resource-bounded safe subset of GGUF v3 specification
    llama_cpp, // Compatibility profile derived from and differential-tested against pinned ggml 0.23.0 (e91ded11)
};

pub const CompatibilityTarget = struct {
    project: []const u8 = "ggml",
    version: []const u8 = GGML_PINNED_VERSION,
    commit: []const u8 = GGML_PINNED_COMMIT,
};

pub const MetadataType = enum(u32) {
    uint8 = 0,
    int8 = 1,
    uint16 = 2,
    int16 = 3,
    uint32 = 4,
    int32 = 5,
    float32 = 6,
    bool_ = 7,
    string = 8,
    array = 9,
    uint64 = 10,
    int64 = 11,
    float64 = 12,
};

pub const GGMLType = enum(u32) {
    F32 = 0,
    F16 = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    // 4, 5: removed / deprecated
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    IQ2_XXS = 16,
    IQ2_XS = 17,
    IQ3_XXS = 18,
    IQ1_S = 19,
    IQ4_NL = 20,
    IQ3_S = 21,
    IQ2_S = 22,
    IQ4_XS = 23,
    I8 = 24,
    I16 = 25,
    I32 = 26,
    I64 = 27,
    F64 = 28,
    IQ1_M = 29,
    BF16 = 30,
    // 31, 32, 33: removed / deprecated
    TQ1_0 = 34,
    TQ2_0 = 35,
    // 36, 37, 38: removed / deprecated
    MXFP4 = 39,
    NVFP4 = 40,
    Q1_0 = 41,
    Q2_0 = 42,
    _,
};

pub const TypeTraits = struct {
    name: []const u8,
    block_size: u64,
    type_size: u64,
};

pub fn getTypeTraits(type_raw: u32) ?TypeTraits {
    return switch (type_raw) {
        0 => TypeTraits{ .name = "F32", .block_size = 1, .type_size = 4 },
        1 => TypeTraits{ .name = "F16", .block_size = 1, .type_size = 2 },
        2 => TypeTraits{ .name = "Q4_0", .block_size = 32, .type_size = 18 },
        3 => TypeTraits{ .name = "Q4_1", .block_size = 32, .type_size = 20 },
        // 4, 5: removed / deprecated -> null
        6 => TypeTraits{ .name = "Q5_0", .block_size = 32, .type_size = 22 },
        7 => TypeTraits{ .name = "Q5_1", .block_size = 32, .type_size = 24 },
        8 => TypeTraits{ .name = "Q8_0", .block_size = 32, .type_size = 34 },
        9 => TypeTraits{ .name = "Q8_1", .block_size = 32, .type_size = 36 },
        10 => TypeTraits{ .name = "Q2_K", .block_size = 256, .type_size = 84 },
        11 => TypeTraits{ .name = "Q3_K", .block_size = 256, .type_size = 110 },
        12 => TypeTraits{ .name = "Q4_K", .block_size = 256, .type_size = 144 },
        13 => TypeTraits{ .name = "Q5_K", .block_size = 256, .type_size = 176 },
        14 => TypeTraits{ .name = "Q6_K", .block_size = 256, .type_size = 210 },
        15 => TypeTraits{ .name = "Q8_K", .block_size = 256, .type_size = 292 },
        16 => TypeTraits{ .name = "IQ2_XXS", .block_size = 256, .type_size = 66 },
        17 => TypeTraits{ .name = "IQ2_XS", .block_size = 256, .type_size = 74 },
        18 => TypeTraits{ .name = "IQ3_XXS", .block_size = 256, .type_size = 98 },
        19 => TypeTraits{ .name = "IQ1_S", .block_size = 256, .type_size = 50 },
        20 => TypeTraits{ .name = "IQ4_NL", .block_size = 32, .type_size = 18 },
        21 => TypeTraits{ .name = "IQ3_S", .block_size = 256, .type_size = 110 },
        22 => TypeTraits{ .name = "IQ2_S", .block_size = 256, .type_size = 82 },
        23 => TypeTraits{ .name = "IQ4_XS", .block_size = 256, .type_size = 136 },
        24 => TypeTraits{ .name = "I8", .block_size = 1, .type_size = 1 },
        25 => TypeTraits{ .name = "I16", .block_size = 1, .type_size = 2 },
        26 => TypeTraits{ .name = "I32", .block_size = 1, .type_size = 4 },
        27 => TypeTraits{ .name = "I64", .block_size = 1, .type_size = 8 },
        28 => TypeTraits{ .name = "F64", .block_size = 1, .type_size = 8 },
        29 => TypeTraits{ .name = "IQ1_M", .block_size = 256, .type_size = 56 },
        30 => TypeTraits{ .name = "BF16", .block_size = 1, .type_size = 2 },
        // 31, 32, 33: removed / deprecated -> null
        34 => TypeTraits{ .name = "TQ1_0", .block_size = 256, .type_size = 54 },
        35 => TypeTraits{ .name = "TQ2_0", .block_size = 256, .type_size = 66 },
        // 36, 37, 38: removed / deprecated -> null
        39 => TypeTraits{ .name = "MXFP4", .block_size = 32, .type_size = 17 },
        40 => TypeTraits{ .name = "NVFP4", .block_size = 64, .type_size = 36 },
        41 => TypeTraits{ .name = "Q1_0", .block_size = 128, .type_size = 18 },
        42 => TypeTraits{ .name = "Q2_0", .block_size = 64, .type_size = 18 },
        else => null,
    };
}
