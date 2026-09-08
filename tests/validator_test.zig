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
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 0, .little);

    const written_len = fbs.getWritten().len;
    const tensor_data_base = (written_len + 31) & ~@as(usize, 31);
    const total_file_size = tensor_data_base + 18;

    const valid_slice = buffer[0..total_file_size];
    const slice_reader = reader_mod.SliceReader.init(valid_slice);
    const r = slice_reader.reader();

    const doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer {
        for (doc.tensors) |t| {
            std.testing.allocator.free(t.name);
            std.testing.allocator.free(t.dimensions);
        }
        std.testing.allocator.free(doc.tensors);
    }

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

    const doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer {
        for (doc.tensors) |t| {
            std.testing.allocator.free(t.name);
            std.testing.allocator.free(t.dimensions);
        }
        std.testing.allocator.free(doc.tensors);
    }

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

    const doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer {
        for (doc.tensors) |t| {
            std.testing.allocator.free(t.name);
            std.testing.allocator.free(t.dimensions);
        }
        std.testing.allocator.free(doc.tensors);
    }

    try std.testing.expectError(error.TensorOutOfBounds, structural.validateStructural(std.testing.allocator, doc));
}
