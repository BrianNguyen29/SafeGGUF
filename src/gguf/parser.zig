const std = @import("std");
const err = @import("error.zig");
const types = @import("types.zig");
const limits = @import("limits.zig");
const reader_mod = @import("reader.zig");
const metadata_mod = @import("metadata.zig");
const arithmetic = @import("../validate/arithmetic.zig");
const Reader = reader_mod.Reader;

pub const Header = struct {
    version: u32,
    tensor_count: u64,
    metadata_kv_count: u64,
};

pub const TensorInfo = struct {
    name: []const u8,
    dimensions: []const u64,
    tensor_type: u32,
    offset: u64,
};

pub const Document = struct {
    header: Header,
    alignment: u64,
    tensor_data_base: u64,
    tensors: []const TensorInfo,
    file_size: u64,
};

pub fn parseDocument(
    allocator: std.mem.Allocator,
    reader: Reader,
    endian: std.builtin.Endian,
    limit: limits.Limits,
) err.ParseError!Document {
    var cur: u64 = 0;

    // 1. Magic
    var magic_buf: [4]u8 = undefined;
    try reader.readBytes(cur, &magic_buf);
    cur += 4;
    if (!std.mem.eql(u8, &magic_buf, &types.MAGIC)) {
        return err.ParseError.InvalidMagic;
    }

    // 2. Version
    const version = try reader.readInt(u32, cur, endian);
    cur += 4;
    if (version != types.VERSION and version != 2) {
        return err.ParseError.UnsupportedVersion;
    }

    // 3. Counts
    const tensor_count = try reader.readInt(u64, cur, endian);
    cur += 8;
    if (tensor_count > limit.max_tensors) return err.ParseError.ResourceLimitExceeded;

    const metadata_kv_count = try reader.readInt(u64, cur, endian);
    cur += 8;
    if (metadata_kv_count > limit.max_metadata_entries) return err.ParseError.ResourceLimitExceeded;

    const header = Header{
        .version = version,
        .tensor_count = tensor_count,
        .metadata_kv_count = metadata_kv_count,
    };

    var alignment: u64 = types.DEFAULT_ALIGNMENT;

    // 4. Parse Metadata
    var m_idx: u64 = 0;
    while (m_idx < metadata_kv_count) : (m_idx += 1) {
        const key_len = try reader.readInt(u64, cur, endian);
        cur += 8;
        if (key_len > limit.max_string_bytes) return err.ParseError.ResourceLimitExceeded;

        const key_end = std.math.add(u64, cur, key_len) catch return err.ParseError.ArithmeticOverflow;
        if (key_end > reader.size) return err.ParseError.UnexpectedEof;

        const key_buf = allocator.alloc(u8, key_len) catch return err.ParseError.OutOfMemory;
        defer allocator.free(key_buf);
        try reader.readBytes(cur, key_buf);
        cur = key_end;

        try metadata_mod.validateKey(key_buf);

        const val_type_raw = try reader.readInt(u32, cur, endian);
        cur += 4;
        if (val_type_raw > 12) return err.ParseError.InvalidMetadataType;
        const val_type: types.MetadataType = @enumFromInt(val_type_raw);

        if (std.mem.eql(u8, key_buf, "general.alignment")) {
            if (val_type == .uint32) {
                const align_val = try reader.readInt(u32, cur, endian);
                cur += 4;
                if (align_val == 0 or align_val % 8 != 0) return err.ParseError.InvalidAlignment;
                alignment = align_val;
            } else if (val_type == .uint64) {
                const align_val = try reader.readInt(u64, cur, endian);
                cur += 8;
                if (align_val == 0 or align_val % 8 != 0) return err.ParseError.InvalidAlignment;
                alignment = align_val;
            } else {
                return err.ParseError.InvalidAlignment;
            }
        } else {
            _ = try metadata_mod.skipMetadataValue(reader, &cur, val_type, endian, limit);
        }
    }

    // 5. Parse Tensor Descriptors
    const tensors = allocator.alloc(TensorInfo, tensor_count) catch return err.ParseError.OutOfMemory;
    errdefer allocator.free(tensors);

    var t_idx: u64 = 0;
    while (t_idx < tensor_count) : (t_idx += 1) {
        const name_len = try reader.readInt(u64, cur, endian);
        cur += 8;
        if (name_len > limit.max_string_bytes) return err.ParseError.ResourceLimitExceeded;

        const name_end = std.math.add(u64, cur, name_len) catch return err.ParseError.ArithmeticOverflow;
        if (name_end > reader.size) return err.ParseError.UnexpectedEof;

        const name_buf = allocator.alloc(u8, name_len) catch return err.ParseError.OutOfMemory;
        try reader.readBytes(cur, name_buf);
        cur = name_end;

        const n_dims = try reader.readInt(u32, cur, endian);
        cur += 4;
        if (n_dims == 0 or n_dims > limit.max_dimensions) return err.ParseError.InvalidDimensionCount;

        const dims = allocator.alloc(u64, n_dims) catch return err.ParseError.OutOfMemory;
        var d_idx: u32 = 0;
        while (d_idx < n_dims) : (d_idx += 1) {
            dims[d_idx] = try reader.readInt(u64, cur, endian);
            cur += 8;
        }

        const tensor_type = try reader.readInt(u32, cur, endian);
        cur += 4;

        const offset = try reader.readInt(u64, cur, endian);
        cur += 8;

        tensors[t_idx] = TensorInfo{
            .name = name_buf,
            .dimensions = dims,
            .tensor_type = tensor_type,
            .offset = offset,
        };
    }

    // 6. Compute Tensor Data Base
    const tensor_data_base = try arithmetic.checkedAlignUp(cur, alignment);

    return Document{
        .header = header,
        .alignment = alignment,
        .tensor_data_base = tensor_data_base,
        .tensors = tensors,
        .file_size = reader.size,
    };
}

