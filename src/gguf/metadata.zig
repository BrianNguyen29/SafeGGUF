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

/// Validates strict GGUF key specification:
/// Keys consist of segments separated by a single dot ('.').
/// Each segment must be strictly non-empty lower_snake_case: [a-z0-9_]+.
/// Hyphens ('-') and uppercase letters are rejected.
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
        } else if ((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_') {
            prev_dot = false;
        } else {
            return err.ParseError.InvalidKeyFormat;
        }
    }
}

/// Validates a UTF-8 stream in 4KB chunks without dynamic heap allocation,
/// properly handling multi-byte code point boundary carry-over.
pub fn validateUtf8Stream(reader: Reader, start_offset: u64, len: u64) err.ParseError!void {
    var cur = start_offset;
    var remaining = len;
    var buf: [4096]u8 = undefined;
    var carry_len: usize = 0;

    while (remaining > 0 or carry_len > 0) {
        const read_len = @min(remaining, buf.len - carry_len);
        if (read_len > 0) {
            try reader.readBytes(cur, buf[carry_len .. carry_len + read_len]);
            cur += read_len;
            remaining -= read_len;
        }
        const total_validating = carry_len + read_len;
        if (total_validating == 0) break;

        var valid_up_to = total_validating;
        if (remaining > 0) {
            var i = total_validating;
            while (i > 0 and (total_validating - i) < 4) {
                i -= 1;
                const byte = buf[i];
                if (byte & 0x80 == 0) {
                    break;
                } else if (byte & 0xC0 == 0xC0) {
                    const seq_len = std.unicode.utf8ByteSequenceLength(byte) catch return err.ParseError.InvalidUtf8;
                    if (total_validating - i < seq_len) {
                        valid_up_to = i;
                    }
                    break;
                }
            }
        }

        if (!std.unicode.utf8ValidateSlice(buf[0..valid_up_to])) {
            return err.ParseError.InvalidUtf8;
        }

        carry_len = total_validating - valid_up_to;
        if (carry_len > 0) {
            std.mem.copyForwards(u8, buf[0..carry_len], buf[valid_up_to..total_validating]);
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
            if (raw > 1) return err.ParseError.InvalidBoolean;
            return .{ .bool_ = (raw == 1) };
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

            try validateUtf8Stream(reader, cur, len);

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

            // Anti-DoS limit on variable array elements (strings, nested arrays)
            if (elem_type == .string or elem_type == .array) {
                if (count > limit.max_variable_array_elements) return err.ParseError.ResourceLimitExceeded;
            }

            // Bool arrays: scan and validate that all bytes are <= 1 (0 or 1)
            if (elem_type == .bool_) {
                const total_bytes = count;
                const end = std.math.add(u64, cur, total_bytes) catch return err.ParseError.ArithmeticOverflow;
                if (end > reader.size) return err.ParseError.UnexpectedEof;

                var remaining = count;
                var buf: [4096]u8 = undefined;
                while (remaining > 0) {
                    const chunk_size = @min(remaining, buf.len);
                    try reader.readBytes(cur, buf[0..chunk_size]);
                    for (buf[0..chunk_size]) |b| {
                        if (b > 1) return err.ParseError.InvalidBoolean;
                    }
                    cur += chunk_size;
                    remaining -= chunk_size;
                }
                offset_ptr.* = cur;
                return .{ .array = .{ .element_type = elem_type, .count = count } };
            }

            const primitive_size: u64 = switch (elem_type) {
                .uint8, .int8 => 1,
                .uint16, .int16 => 2,
                .uint32, .int32, .float32 => 4,
                .uint64, .int64, .float64 => 8,
                .bool_, .string, .array => 0,
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
