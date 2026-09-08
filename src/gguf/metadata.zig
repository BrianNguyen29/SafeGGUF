const std = @import("std");
const err = @import("error.zig");
const types = @import("types.zig");
const limits = @import("limits.zig");
const reader_mod = @import("reader.zig");
const Reader = reader_mod.Reader;

pub const MetadataValue = union(types.MetadataType) {
    uint8: u8,
    int8: i8,
    uint16: u16,
    int16: i16,
    uint32: u32,
    int32: i32,
    float32: f32,
    bool_: bool,
    string: []const u8,
    array: ArrayValue,
    uint64: u64,
    int64: i64,
    float64: f64,
};

pub const ArrayValue = struct {
    element_type: types.MetadataType,
    count: u64,
};

pub fn validateKey(key: []const u8) err.ParseError!void {
    if (key.len == 0 or key.len > 65535) {
        return err.ParseError.InvalidStringLength;
    }

    if (key[0] == '.' or key[key.len - 1] == '.') {
        return err.ParseError.InvalidKeyFormat;
    }

    var prev_dot = false;
    for (key) |c| {
        if (c == '.') {
            if (prev_dot) return err.ParseError.InvalidKeyFormat;
            prev_dot = true;
        } else if ((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_' or c == '-') {
            prev_dot = false;
        } else {
            return err.ParseError.InvalidKeyFormat;
        }
    }
}

pub fn skipMetadataValue(
    reader: Reader,
    offset_ptr: *u64,
    val_type: types.MetadataType,
    endian: std.builtin.Endian,
    limit: limits.Limits,
    depth: u32,
) err.ParseError!MetadataValue {
    var cur = offset_ptr.*;
    switch (val_type) {
        .uint8 => {
            const v = try reader.readInt(u8, cur, endian);
            cur += 1;
            offset_ptr.* = cur;
            return .{ .uint8 = v };
        },
        .int8 => {
            const v = try reader.readInt(i8, cur, endian);
            cur += 1;
            offset_ptr.* = cur;
            return .{ .int8 = v };
        },
        .uint16 => {
            const v = try reader.readInt(u16, cur, endian);
            cur += 2;
            offset_ptr.* = cur;
            return .{ .uint16 = v };
        },
        .int16 => {
            const v = try reader.readInt(i16, cur, endian);
            cur += 2;
            offset_ptr.* = cur;
            return .{ .int16 = v };
        },
        .uint32 => {
            const v = try reader.readInt(u32, cur, endian);
            cur += 4;
            offset_ptr.* = cur;
            return .{ .uint32 = v };
        },
        .int32 => {
            const v = try reader.readInt(i32, cur, endian);
            cur += 4;
            offset_ptr.* = cur;
            return .{ .int32 = v };
        },
        .float32 => {
            const v = try reader.readFloat(f32, cur, endian);
            cur += 4;
            offset_ptr.* = cur;
            return .{ .float32 = v };
        },
        .bool_ => {
            const raw = try reader.readInt(u8, cur, endian);
            cur += 1;
            offset_ptr.* = cur;
            return .{ .bool_ = (raw != 0) };
        },
        .uint64 => {
            const v = try reader.readInt(u64, cur, endian);
            cur += 8;
            offset_ptr.* = cur;
            return .{ .uint64 = v };
        },
        .int64 => {
            const v = try reader.readInt(i64, cur, endian);
            cur += 8;
            offset_ptr.* = cur;
            return .{ .int64 = v };
        },
        .float64 => {
            const v = try reader.readFloat(f64, cur, endian);
            cur += 8;
            offset_ptr.* = cur;
            return .{ .float64 = v };
        },
        .string => {
            const len = try reader.readInt(u64, cur, endian);
            cur += 8;
            if (len > limit.max_string_bytes) return err.ParseError.ResourceLimitExceeded;
            const end = std.math.add(u64, cur, len) catch return err.ParseError.ArithmeticOverflow;
            if (end > reader.size) return err.ParseError.UnexpectedEof;
            cur = end;
            offset_ptr.* = cur;
            return .{ .string = "" };
        },
        .array => {
            if (depth >= limit.max_metadata_depth) return err.ParseError.RecursionDepthExceeded;

            const raw_elem_type = try reader.readInt(u32, cur, endian);
            cur += 4;
            if (raw_elem_type > 12) return err.ParseError.InvalidMetadataType;
            const elem_type: types.MetadataType = @enumFromInt(raw_elem_type);

            const count = try reader.readInt(u64, cur, endian);
            cur += 8;
            if (count > limit.max_array_elements) return err.ParseError.ResourceLimitExceeded;

            const primitive_size: u64 = switch (elem_type) {
                .uint8, .int8, .bool_ => 1,
                .uint16, .int16 => 2,
                .uint32, .int32, .float32 => 4,
                .uint64, .int64, .float64 => 8,
                .string, .array => 0,
            };

            if (primitive_size > 0) {
                const total_bytes = std.math.mul(u64, count, primitive_size) catch return err.ParseError.ArithmeticOverflow;
                const end = std.math.add(u64, cur, total_bytes) catch return err.ParseError.ArithmeticOverflow;
                if (end > reader.size) return err.ParseError.UnexpectedEof;
                cur = end;
                offset_ptr.* = cur;
                return .{ .array = .{ .element_type = elem_type, .count = count } };
            }

            var i: u64 = 0;
            while (i < count) : (i += 1) {
                _ = try skipMetadataValue(reader, &cur, elem_type, endian, limit, depth + 1);
            }
            offset_ptr.* = cur;
            return .{ .array = .{ .element_type = elem_type, .count = count } };
        },
    }
}
