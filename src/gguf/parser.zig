const std = @import("std");
const builtin = @import("builtin");
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

    pub fn deinit(self: *Document, allocator: std.mem.Allocator) void {
        for (self.tensors) |t| {
            allocator.free(t.name);
            allocator.free(t.dimensions);
        }
        allocator.free(self.tensors);
    }
};

pub fn parseDocument(
    allocator: std.mem.Allocator,
    reader: Reader,
    endian: std.builtin.Endian,
    limit: limits.Limits,
    profile: types.Profile,
    work_budget: *limits.WorkBudget,
) err.ParseError!Document {
    if (work_budget.ctx) |c| c.beginPhase("parse");

    // Under llama_cpp profile: upstream ggml 0.23.0 only supports host native endianness.
    // Models with non-native endianness are actively rejected by upstream ggml with endian mismatch.
    if (profile == .llama_cpp and endian != builtin.cpu.arch.endian()) {
        return err.ParseError.CompatibilityViolation;
    }

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
    if (profile == .gguf_spec) {
        if (version != types.VERSION) {
            return err.ParseError.UnsupportedVersion;
        }
    } else {
        if (version != types.VERSION and version != 2) {
            return err.ParseError.UnsupportedVersion;
        }
    }

    // 3. Counts
    const tensor_count = try reader.readInt(u64, cur, endian);
    cur += 8;
    if (tensor_count > limit.max_tensors) return err.ParseError.ResourceLimitExceeded;

    const metadata_kv_count = try reader.readInt(u64, cur, endian);
    cur += 8;
    if (metadata_kv_count > limit.max_metadata_entries) return err.ParseError.ResourceLimitExceeded;

    const min_meta_size: u64 = 8 + 1 + 4;
    if (cur > reader.size or metadata_kv_count > (reader.size - cur) / min_meta_size) {
        return err.ParseError.UnexpectedEof;
    }

    const header = Header{
        .version = version,
        .tensor_count = tensor_count,
        .metadata_kv_count = metadata_kv_count,
    };

    var alignment: u64 = types.DEFAULT_ALIGNMENT;

    var seen_keys = std.StringHashMap(void).init(allocator);
    defer {
        var it = seen_keys.keyIterator();
        while (it.next()) |k| {
            allocator.free(k.*);
        }
        seen_keys.deinit();
    }

    // 4. Parse Metadata
    var m_idx: u64 = 0;
    while (m_idx < metadata_kv_count) : (m_idx += 1) {
        if (work_budget.ctx) |c| {
            c.metadata_index = m_idx;
            c.current_offset = cur;
        }
        try work_budget.consume(1);

        const key_len = try reader.readInt(u64, cur, endian);
        cur += 8;
        if (key_len > limit.max_string_bytes) return err.ParseError.ResourceLimitExceeded;
        try work_budget.consumeBytes(key_len);

        const key_end = std.math.add(u64, cur, key_len) catch return err.ParseError.ArithmeticOverflow;
        if (key_end > reader.size) return err.ParseError.UnexpectedEof;

        const key_buf = allocator.alloc(u8, key_len) catch return err.ParseError.OutOfMemory;
        var key_registered = false;
        defer {
            if (!key_registered) {
                allocator.free(key_buf);
            }
        }

        try reader.readBytes(cur, key_buf);
        cur = key_end;

        // Snapshot the key into the context: key_buf may be freed on unwind.
        if (work_budget.ctx) |c| c.setKey(key_buf);

        try metadata_mod.validateKey(key_buf);

        if (seen_keys.contains(key_buf)) {
            return err.ParseError.DuplicateMetadataKey;
        }
        seen_keys.put(key_buf, {}) catch return err.ParseError.OutOfMemory;
        key_registered = true;

        const val_type_raw = try reader.readInt(u32, cur, endian);
        cur += 4;
        if (val_type_raw > 12) return err.ParseError.InvalidMetadataType;
        const val_type: types.MetadataType = @enumFromInt(val_type_raw);

        if (std.mem.eql(u8, key_buf, "general.alignment")) {
            // Spec requires general.alignment to be uint32
            if (val_type != .uint32) {
                return err.ParseError.InvalidAlignment;
            }
            const align_val = try reader.readInt(u32, cur, endian);
            cur += 4;

            if (align_val == 0) return err.ParseError.InvalidAlignment;
            if (align_val % 8 != 0) return err.ParseError.InvalidAlignment;

            if (profile == .llama_cpp) {
                // llama.cpp requires power-of-two alignment
                if ((align_val & (align_val - 1)) != 0) {
                    return err.ParseError.CompatibilityViolation;
                }
            }

            alignment = align_val;
        } else {
            _ = try metadata_mod.skipMetadataValue(reader, &cur, val_type, endian, limit, profile, work_budget, 0);
        }
    }

    const min_tensor_desc_size: u64 = 8 + 4 + 4 + 8; // 24 bytes: name_len(8) + n_dims(4) + type(4) + offset(8)
    if (cur > reader.size or tensor_count > (reader.size - cur) / min_tensor_desc_size) {
        return err.ParseError.UnexpectedEof;
    }

    // 5. Parse Tensor Descriptors
    const tensors = allocator.alloc(TensorInfo, tensor_count) catch return err.ParseError.OutOfMemory;

    var t_idx: u64 = 0;
    errdefer {
        for (tensors[0..t_idx]) |t| {
            allocator.free(t.name);
            allocator.free(t.dimensions);
        }
        allocator.free(tensors);
    }

    while (t_idx < tensor_count) {
        if (work_budget.ctx) |c| {
            c.tensor_index = t_idx;
            c.metadata_index = null;
            c.current_offset = cur;
        }
        try work_budget.consume(1);

        const name_len = try reader.readInt(u64, cur, endian);
        cur += 8;

        if (profile == .llama_cpp and name_len >= 64) {
            return err.ParseError.TensorNameTooLong;
        }
        if (name_len == 0 or name_len > limit.max_tensor_name_bytes) {
            return err.ParseError.InvalidTensorName;
        }
        try work_budget.consumeBytes(name_len);

        const name_end = std.math.add(u64, cur, name_len) catch return err.ParseError.ArithmeticOverflow;
        if (name_end > reader.size) return err.ParseError.UnexpectedEof;

        const name_buf = allocator.alloc(u8, name_len) catch return err.ParseError.OutOfMemory;
        errdefer allocator.free(name_buf);
        try reader.readBytes(cur, name_buf);
        cur = name_end;

        // Snapshot the name into the context: name_buf may be freed on unwind.
        if (work_budget.ctx) |c| c.setTensorName(name_buf);

        if (!std.unicode.utf8ValidateSlice(name_buf)) {
            return err.ParseError.InvalidUtf8;
        }

        const n_dims = try reader.readInt(u32, cur, endian);
        cur += 4;
        if (n_dims > limit.max_dimensions) {
            return err.ParseError.InvalidDimensionCount;
        }

        const dims = allocator.alloc(u64, n_dims) catch return err.ParseError.OutOfMemory;
        errdefer allocator.free(dims);

        var d_idx: u32 = 0;
        while (d_idx < n_dims) : (d_idx += 1) {
            dims[d_idx] = try reader.readInt(u64, cur, endian);
            cur += 8;
        }
        try arithmetic.validateDimensions(dims, profile);

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
        t_idx += 1;
    }

    // 6. Compute Tensor Data Base and validate zero alignment padding
    const tensor_data_base = try arithmetic.checkedAlignUp(cur, alignment);

    // GGUF v3 specification conformance: zero-tensor file must contain required alignment padding
    if (profile == .gguf_spec and header.tensor_count == 0 and tensor_data_base > reader.size) {
        return err.ParseError.UnexpectedEof;
    }

    const check_end = @min(tensor_data_base, reader.size);
    if (check_end > cur) {
        const padding_len = check_end - cur;
        try work_budget.consumeBytes(padding_len);
        var pad_buf: [256]u8 = undefined;
        var pad_cur = cur;
        while (pad_cur < check_end) {
            const chunk_len = @min(check_end - pad_cur, pad_buf.len);
            const chunk = pad_buf[0..chunk_len];
            try reader.readBytes(pad_cur, chunk);
            for (chunk) |b| {
                if (b != 0) {
                    if (work_budget.ctx) |c| c.current_offset = pad_cur;
                    return err.ParseError.InvalidAlignmentPadding;
                }
            }
            pad_cur += chunk_len;
        }
    }

    return Document{
        .header = header,
        .alignment = alignment,
        .tensor_data_base = tensor_data_base,
        .tensors = tensors,
        .file_size = reader.size,
    };
}
