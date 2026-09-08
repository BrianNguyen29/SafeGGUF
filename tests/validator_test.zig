const std = @import("std");
const safegguf = @import("safegguf");

const types = safegguf.types;
const err = safegguf.error_types;
const limits = safegguf.limits;
const reader_mod = safegguf.reader;
const parser = safegguf.parser;
const arithmetic = safegguf.arithmetic;
const structural = safegguf.structural;

test "arithmetic: checked add, mul, align" {
    try std.testing.expectEqual(@as(u64, 30), try arithmetic.checkedAdd(10, 20));
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedAdd(std.math.maxInt(u64), 1));

    try std.testing.expectEqual(@as(u64, 200), try arithmetic.checkedMul(10, 20));
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedMul(std.math.maxInt(u64), 2));

    try std.testing.expectEqual(@as(u64, 32), try arithmetic.checkedAlignUp(17, 32));
    try std.testing.expectEqual(@as(u64, 32), try arithmetic.checkedAlignUp(32, 32));
    try std.testing.expectError(error.InvalidAlignment, arithmetic.checkedAlignUp(10, 7)); // not multiple of 8
}

test "arithmetic: computeTensorBytes for Q4_0 and divisibility" {
    // Q4_0: block_size = 32, type_size = 18
    const valid_dims = [_]u64{ 64, 10 }; // 640 elements -> 20 blocks of 32 -> 20 * 18 = 360 bytes
    const bytes = try arithmetic.computeTensorBytes(&valid_dims, 2);
    try std.testing.expectEqual(@as(u64, 360), bytes);

    // Divisibility violation: dims[0] = 30 is not divisible by 32
    const invalid_dims = [_]u64{ 30, 10 };
    try std.testing.expectError(error.BlockDivisibilityViolation, arithmetic.computeTensorBytes(&invalid_dims, 2));

    // Overflow check on product
    const overflow_dims = [_]u64{ std.math.maxInt(u64), 2 };
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(&overflow_dims, 0)); // F32
}

test "arithmetic: upstream GGML types validation" {
    // BF16 (type 30)
    const bf16_traits = types.getTypeTraits(30).?;
    try std.testing.expectEqual(@as(u64, 1), bf16_traits.block_size);
    try std.testing.expectEqual(@as(u64, 2), bf16_traits.type_size);

    // Q4_K (type 12)
    const q4k_traits = types.getTypeTraits(12).?;
    try std.testing.expectEqual(@as(u64, 256), q4k_traits.block_size);
    try std.testing.expectEqual(@as(u64, 144), q4k_traits.type_size);

    // NVFP4 (type 42)
    const nvfp4_traits = types.getTypeTraits(42).?;
    try std.testing.expectEqual(@as(u64, 32), nvfp4_traits.block_size);
    try std.testing.expectEqual(@as(u64, 18), nvfp4_traits.type_size);

    // Unknown type 999
    try std.testing.expect(types.getTypeTraits(999) == null);
}

test "parser: reject invalid magic" {
    const invalid_magic_buf = [_]u8{ 'B', 'A', 'D', '!', 3, 0, 0, 0 };
    const slice_reader = reader_mod.SliceReader.init(&invalid_magic_buf);
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.InvalidMagic, result);
}

test "parser: reject unsupported version" {
    const invalid_version_buf = [_]u8{ 'G', 'G', 'U', 'F', 99, 0, 0, 0 };
    const slice_reader = reader_mod.SliceReader.init(&invalid_version_buf);
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.UnsupportedVersion, result);
}

test "parser: reject allocation DoS on tensor_count" {
    var buffer: [32]u8 = [_]u8{0} ** 32;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1_000_000, .little); // 1M tensors in 32-byte file!
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // Must be rejected with UnexpectedEof before attempting any 1M tensor allocation!
    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.UnexpectedEof, result);
}

test "parser: reject allocation DoS on metadata_kv_count" {
    var buffer: [32]u8 = [_]u8{0} ** 32;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1_000_000, .little); // 1M metadata entries in 32-byte file!

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // Must be rejected with UnexpectedEof before attempting allocations!
    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.UnexpectedEof, result);
}

test "parser: reject duplicate metadata keys" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 2, .little); // 2 keys

    // Key 1: "general.arch" -> uint32 (1)
    const key = "general.arch";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 4, .little); // uint32
    try writer.writeInt(u32, 1, .little);

    // Key 2: duplicate "general.arch" -> uint32 (2)
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 4, .little);
    try writer.writeInt(u32, 2, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.DuplicateMetadataKey, result);
}

test "parser: reject invalid metadata key format" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    // Uppercase not allowed in lower_snake_case hierarchical keys
    const bad_key = "General.Arch";
    try writer.writeInt(u64, bad_key.len, .little);
    try writer.writeAll(bad_key);
    try writer.writeInt(u32, 4, .little); // uint32
    try writer.writeInt(u32, 1, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.InvalidKeyFormat, result);
}

test "parser: reject nested metadata array exceeding depth limit" {
    var buffer: [512]u8 = [_]u8{0} ** 512;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "nested.array";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 9, .little); // val_type = array

    // Nest 10 levels of array (limit is 8)
    var depth: usize = 0;
    while (depth < 10) : (depth += 1) {
        try writer.writeInt(u32, 9, .little); // element type: array
        try writer.writeInt(u64, 1, .little); // count: 1
    }

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.RecursionDepthExceeded, result);
}

test "parser: valid mock GGUF document and structural verification" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 7, .little);
    try writer.writeAll("weights");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 2, .little); // Q4_0
    try writer.writeInt(u64, 0, .little);

    const written_len = fbs.getWritten().len;
    const tensor_data_base = (written_len + 31) & ~@as(usize, 31);
    const total_file_size = tensor_data_base + 18;

    const valid_slice = buffer[0..total_file_size];
    const slice_reader = reader_mod.SliceReader.init(valid_slice);
    const r = slice_reader.reader();

    var doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 3), doc.header.version);
    try std.testing.expectEqual(@as(u64, 1), doc.header.tensor_count);
    try std.testing.expectEqual(@as(u64, 32), doc.alignment);

    try structural.validateStructural(std.testing.allocator, doc);
}

test "validator: reject misaligned tensor" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 4, .little);
    try writer.writeAll("test");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 15, .little); // 15 % 32 != 0

    const written_len = fbs.getWritten().len;
    const slice_reader = reader_mod.SliceReader.init(buffer[0..written_len]);
    const r = slice_reader.reader();

    var doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.MisalignedTensor, structural.validateStructural(std.testing.allocator, doc));
}

test "validator: reject tensor out of bounds" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 4, .little);
    try writer.writeAll("test");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 1024, .little); // 1024 % 32 == 0, but > file size

    const written_len = fbs.getWritten().len;
    const slice_reader = reader_mod.SliceReader.init(buffer[0..written_len]);
    const r = slice_reader.reader();

    var doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.TensorOutOfBounds, structural.validateStructural(std.testing.allocator, doc));
}

test "validator: reject duplicate tensor names" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 2, .little); // 2 tensors
    try writer.writeInt(u64, 0, .little);

    // Tensor 0: "weight"
    try writer.writeInt(u64, 6, .little);
    try writer.writeAll("weight");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 0, .little);

    // Tensor 1: duplicate "weight"
    try writer.writeInt(u64, 6, .little);
    try writer.writeAll("weight");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 32, .little);

    const written_len = fbs.getWritten().len;
    const slice_reader = reader_mod.SliceReader.init(buffer[0..written_len]);
    const r = slice_reader.reader();

    var doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.DuplicateTensorName, structural.validateStructural(std.testing.allocator, doc));
}

test "validator: reject tensor overlap" {
    var buffer: [512]u8 = [_]u8{0} ** 512;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 2, .little);
    try writer.writeInt(u64, 0, .little);

    // Tensor 0: "t0", length 32 * 4 = 128 bytes, offset 0
    try writer.writeInt(u64, 2, .little);
    try writer.writeAll("t0");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 0, .little); // F32: 32 * 4 = 128 bytes
    try writer.writeInt(u64, 0, .little);

    // Tensor 1: "t1", offset 32 (overlaps with t0's [0, 128))
    try writer.writeInt(u64, 2, .little);
    try writer.writeAll("t1");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 0, .little); // F32
    try writer.writeInt(u64, 32, .little);

    const written_len = fbs.getWritten().len;
    const tensor_data_base = (written_len + 31) & ~@as(usize, 31);
    const total_file_size = tensor_data_base + 256;

    const valid_slice = buffer[0..total_file_size];
    const slice_reader = reader_mod.SliceReader.init(valid_slice);
    const r = slice_reader.reader();

    var doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.TensorOverlap, structural.validateStructural(std.testing.allocator, doc));
}
