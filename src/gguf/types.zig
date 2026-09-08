const std = @import("std");

pub const MAGIC: [4]u8 = "GGUF".*;
pub const VERSION: u32 = 3;
pub const DEFAULT_ALIGNMENT: u64 = 32;

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
    I8 = 24,
    I16 = 25,
    I32 = 26,
    I64 = 27,
    F64 = 28,
    BF16 = 30,
    _,
};

pub const TypeTraits = struct {
    block_size: u64,
    type_size: u64,
};

pub fn getTypeTraits(type_raw: u32) ?TypeTraits {
    return switch (type_raw) {
        0 => TypeTraits{ .block_size = 1, .type_size = 4 }, // F32
        1 => TypeTraits{ .block_size = 1, .type_size = 2 }, // F16
        2 => TypeTraits{ .block_size = 32, .type_size = 18 }, // Q4_0
        3 => TypeTraits{ .block_size = 32, .type_size = 20 }, // Q4_1
        6 => TypeTraits{ .block_size = 32, .type_size = 22 }, // Q5_0
        7 => TypeTraits{ .block_size = 32, .type_size = 24 }, // Q5_1
        8 => TypeTraits{ .block_size = 32, .type_size = 34 }, // Q8_0
        9 => TypeTraits{ .block_size = 32, .type_size = 40 }, // Q8_1
        10 => TypeTraits{ .block_size = 256, .type_size = 84 }, // Q2_K
        11 => TypeTraits{ .block_size = 256, .type_size = 110 }, // Q3_K
        12 => TypeTraits{ .block_size = 256, .type_size = 144 }, // Q4_K
        13 => TypeTraits{ .block_size = 256, .type_size = 176 }, // Q5_K
        14 => TypeTraits{ .block_size = 256, .type_size = 210 }, // Q6_K
        15 => TypeTraits{ .block_size = 256, .type_size = 292 }, // Q8_K
        24 => TypeTraits{ .block_size = 1, .type_size = 1 }, // I8
        25 => TypeTraits{ .block_size = 1, .type_size = 2 }, // I16
        26 => TypeTraits{ .block_size = 1, .type_size = 4 }, // I32
        27 => TypeTraits{ .block_size = 1, .type_size = 8 }, // I64
        28 => TypeTraits{ .block_size = 1, .type_size = 8 }, // F64
        30 => TypeTraits{ .block_size = 1, .type_size = 2 }, // BF16
        else => null,
    };
}

