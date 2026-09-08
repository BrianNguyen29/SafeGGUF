const std = @import("std");
const safegguf = @import("safegguf");

const types = safegguf.types;
const err = safegguf.error_types;
const limits = safegguf.limits;
const reader_mod = safegguf.reader;
const parser = safegguf.parser;
const arithmetic = safegguf.arithmetic;
const structural = safegguf.structural;

// ---------------------------------------------------------------------------
// 1. Upstream-Derived Exhaustive Type Oracle Test (ggml 0.23.0 / e91ded11)
// ---------------------------------------------------------------------------

const CanonicalOracleEntry = struct {
    id: u32,
    name: []const u8,
    block_size: u64,
    type_size: u64,
};

const CANONICAL_ORACLE = [_]CanonicalOracleEntry{
    .{ .id = 0, .name = "F32", .block_size = 1, .type_size = 4 },
    .{ .id = 1, .name = "F16", .block_size = 1, .type_size = 2 },
    .{ .id = 2, .name = "Q4_0", .block_size = 32, .type_size = 18 },
    .{ .id = 3, .name = "Q4_1", .block_size = 32, .type_size = 20 },
    // 4, 5 removed
    .{ .id = 6, .name = "Q5_0", .block_size = 32, .type_size = 22 },
    .{ .id = 7, .name = "Q5_1", .block_size = 32, .type_size = 24 },
    .{ .id = 8, .name = "Q8_0", .block_size = 32, .type_size = 34 },
    .{ .id = 9, .name = "Q8_1", .block_size = 32, .type_size = 40 },
    .{ .id = 10, .name = "Q2_K", .block_size = 256, .type_size = 84 },
    .{ .id = 11, .name = "Q3_K", .block_size = 256, .type_size = 110 },
    .{ .id = 12, .name = "Q4_K", .block_size = 256, .type_size = 144 },
    .{ .id = 13, .name = "Q5_K", .block_size = 256, .type_size = 176 },
    .{ .id = 14, .name = "Q6_K", .block_size = 256, .type_size = 210 },
    .{ .id = 15, .name = "Q8_K", .block_size = 256, .type_size = 292 },
    .{ .id = 16, .name = "IQ2_XXS", .block_size = 256, .type_size = 66 },
    .{ .id = 17, .name = "IQ2_XS", .block_size = 256, .type_size = 74 },
    .{ .id = 18, .name = "IQ3_XXS", .block_size = 256, .type_size = 98 },
    .{ .id = 19, .name = "IQ1_S", .block_size = 256, .type_size = 50 }, // 2 + 256/8 + 256/16 = 50
    .{ .id = 20, .name = "IQ4_NL", .block_size = 32, .type_size = 18 },
    .{ .id = 21, .name = "IQ3_S", .block_size = 256, .type_size = 110 },
    .{ .id = 22, .name = "IQ2_S", .block_size = 256, .type_size = 82 },
    .{ .id = 23, .name = "IQ4_XS", .block_size = 256, .type_size = 136 },
    .{ .id = 24, .name = "I8", .block_size = 1, .type_size = 1 },
    .{ .id = 25, .name = "I16", .block_size = 1, .type_size = 2 },
    .{ .id = 26, .name = "I32", .block_size = 1, .type_size = 4 },
    .{ .id = 27, .name = "I64", .block_size = 1, .type_size = 8 },
    .{ .id = 28, .name = "F64", .block_size = 1, .type_size = 8 },
    .{ .id = 29, .name = "IQ1_M", .block_size = 256, .type_size = 56 },
    .{ .id = 30, .name = "BF16", .block_size = 1, .type_size = 2 },
    // 31, 32, 33 removed
    .{ .id = 34, .name = "TQ1_0", .block_size = 256, .type_size = 54 }, // QK_K=256 -> 54
    .{ .id = 35, .name = "TQ2_0", .block_size = 256, .type_size = 66 }, // QK_K=256 -> 66
    // 36, 37, 38 removed
    .{ .id = 39, .name = "MXFP4", .block_size = 32, .type_size = 17 },
    .{ .id = 40, .name = "NVFP4", .block_size = 64, .type_size = 36 }, // 4 bytes scale + 32 bytes data
    .{ .id = 41, .name = "Q1_0", .block_size = 128, .type_size = 18 },
    .{ .id = 42, .name = "Q2_0", .block_size = 64, .type_size = 18 },
};

test "types: exhaustive oracle verification for all IDs 0..50" {
    var active_count: u32 = 0;

    var id: u32 = 0;
    while (id <= 50) : (id += 1) {
        const traits = types.getTypeTraits(id);

        // Find in canonical oracle
        var found_canonical: ?CanonicalOracleEntry = null;
        for (CANONICAL_ORACLE) |entry| {
            if (entry.id == id) {
                found_canonical = entry;
                break;
            }
        }

        if (found_canonical) |expected| {
            try std.testing.expect(traits != null);
            const actual = traits.?;
            try std.testing.expectEqualStrings(expected.name, actual.name);
            try std.testing.expectEqual(expected.block_size, actual.block_size);
            try std.testing.expectEqual(expected.type_size, actual.type_size);
            active_count += 1;
        } else {
            // Deprecated/removed slots (4, 5, 31..33, 36..38) and IDs >= 43 MUST return null!
            try std.testing.expect(traits == null);
        }
    }

    try std.testing.expectEqual(@as(u32, 35), active_count);
    try std.testing.expectEqual(@as(u32, 35), types.ACTIVE_TYPE_COUNT);
    try std.testing.expectEqual(@as(u32, 43), types.GGML_TYPE_COUNT);
}

// ---------------------------------------------------------------------------
// 2. Concrete False-PASS Regression Test (NVFP4 Truncation)
// ---------------------------------------------------------------------------

test "regression: type 40 (NVFP4) truncated file must be REJECTED" {
    // Open the synthetic fixture generated with a truncated 20-byte payload instead of 36 bytes.
    // SafeGGUF v0.2 mistakenly validated this as PASS because it misidentified type 40 as Q2_0 (20 bytes).
    // SafeGGUF v0.2.1 MUST reject this with TensorOutOfBounds!
    const file = std.fs.cwd().openFile("tests/fixtures/type40_truncated_false_pass.gguf", .{}) catch |e| {
        std.debug.print("Could not open fixture: {s}\n", .{@errorName(e)});
        return;
    };
    defer file.close();

    const stat = try file.stat();
    try std.testing.expectEqual(@as(u64, 84), stat.size);

    const file_reader = reader_mod.FileReader.init(file, stat.size);
    const r = file_reader.reader();

    var doc = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{});
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 40), doc.tensors[0].tensor_type);
    try std.testing.expectEqual(@as(u64, 64), doc.tensors[0].dimensions[0]);

    // Validation must REJECT with TensorOutOfBounds!
    try std.testing.expectError(error.TensorOutOfBounds, structural.validateStructural(std.testing.allocator, doc));
}

// ---------------------------------------------------------------------------
// 3. Checked Arithmetic & Divisibility Tests
// ---------------------------------------------------------------------------

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

test "arithmetic: NVFP4, MXFP4, and Q1_0 computation" {
    // NVFP4 (type 40): block 64, type_size 36
    const nvfp4_dims = [_]u64{ 128, 2 }; // 256 elements -> 4 blocks -> 4 * 36 = 144 bytes
    try std.testing.expectEqual(@as(u64, 144), try arithmetic.computeTensorBytes(&nvfp4_dims, 40));

    // MXFP4 (type 39): block 32, type_size 17
    const mxfp4_dims = [_]u64{ 64, 2 }; // 128 elements -> 4 blocks -> 4 * 17 = 68 bytes
    try std.testing.expectEqual(@as(u64, 68), try arithmetic.computeTensorBytes(&mxfp4_dims, 39));

    // Q1_0 (type 41): block 128, type_size 18
    const q1_0_dims = [_]u64{ 256, 1 }; // 256 elements -> 2 blocks -> 2 * 18 = 36 bytes
    try std.testing.expectEqual(@as(u64, 36), try arithmetic.computeTensorBytes(&q1_0_dims, 41));
}

// ---------------------------------------------------------------------------
// 4. Strict BOOL & UTF-8 Validation Tests
// ---------------------------------------------------------------------------

test "metadata: reject invalid scalar boolean (> 1)" {
    var buffer: [64]u8 = [_]u8{0} ** 64;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "is_valid";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 7, .little); // bool type
    try writer.writeByte(2); // Invalid: 2 > 1

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.InvalidBoolean, result);
}

test "metadata: reject invalid boolean in bool array" {
    var buffer: [128]u8 = [_]u8{0} ** 128;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "flags";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 9, .little); // array
    try writer.writeInt(u32, 7, .little); // elem_type: bool
    try writer.writeInt(u64, 4, .little); // 4 elements
    try writer.writeAll(&[_]u8{ 0, 1, 255, 0 }); // 255 is invalid!

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.InvalidBoolean, result);
}

test "metadata: reject invalid UTF-8 in metadata string" {
    var buffer: [128]u8 = [_]u8{0} ** 128;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "bad_utf8_meta";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 8, .little); // string
    const bad_utf8 = [_]u8{ 0xFF, 0xFE, 0xFD }; // illegal UTF-8
    try writer.writeInt(u64, bad_utf8.len, .little);
    try writer.writeAll(&bad_utf8);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.InvalidUtf8, result);
}

test "parser: reject invalid UTF-8 in tensor name" {
    var buffer: [128]u8 = [_]u8{0} ** 128;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    const bad_tensor_name = [_]u8{ 'b', 'a', 'd', 0xC0, 0xAF }; // Overlong UTF-8
    try writer.writeInt(u64, bad_tensor_name.len, .little);
    try writer.writeAll(&bad_tensor_name);
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.InvalidUtf8, result);
}

// ---------------------------------------------------------------------------
// 5. Strict Key Grammar Tests (lower_snake_case without hyphens)
// ---------------------------------------------------------------------------

test "metadata: reject key containing hyphens" {
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("general.model-arch"));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("Model_Arch"));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey(".leading_dot"));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("trailing_dot."));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("double..dot"));

    // Valid keys
    try safegguf.metadata.validateKey("general.architecture");
    try safegguf.metadata.validateKey("tokenizer.ggml.tokens");
    try safegguf.metadata.validateKey("blk_0_attn_q");
}

// ---------------------------------------------------------------------------
// 6. Alignment Profiles: GGUF Spec vs llama.cpp
// ---------------------------------------------------------------------------

test "alignment: profile validation" {
    var buffer: [128]u8 = [_]u8{0} ** 128;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "general.alignment";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 4, .little); // uint32
    try writer.writeInt(u32, 24, .little); // 24: multiple of 8, but NOT power of 2!

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // Under gguf_spec profile: 24 is accepted!
    const doc_spec = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{ .profile = .gguf_spec });
    var doc_mut = doc_spec;
    defer doc_mut.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 24), doc_spec.alignment);

    // Under llama_cpp profile: 24 must be rejected with CompatibilityViolation!
    const result_llama = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{ .profile = .llama_cpp });
    try std.testing.expectError(error.CompatibilityViolation, result_llama);
}

test "alignment: reject uint64 alignment in spec profile" {
    var buffer: [128]u8 = [_]u8{0} ** 128;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "general.alignment";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 10, .little); // uint64: violates spec (spec specifies uint32)
    try writer.writeInt(u64, 32, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.InvalidAlignment, result);
}

// ---------------------------------------------------------------------------
// 7. Structural Validation & Basic Parser Tests
// ---------------------------------------------------------------------------

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
    try writer.writeInt(u64, 1_000_000, .little);
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.UnexpectedEof, result);
}

test "parser: reject total allocation limit exceeded" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "long_key_entry";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 4, .little);
    try writer.writeInt(u32, 1, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // With a tiny max_total_alloc_bytes of 5 bytes, allocating 14-byte key must fail
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{ .max_total_alloc_bytes = 5 });
    try std.testing.expectError(error.TotalAllocationLimitExceeded, result);
}

test "parser: reject duplicate metadata keys" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 2, .little);

    const key = "general.arch";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 4, .little);
    try writer.writeInt(u32, 1, .little);

    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 4, .little);
    try writer.writeInt(u32, 2, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.DuplicateMetadataKey, result);
}

test "parser: reject nested metadata array exceeding depth limit" {
    var buffer: [512]u8 = [_]u8{0} ** 512;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "nested_array";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 9, .little); // array

    var depth: usize = 0;
    while (depth < 10) : (depth += 1) {
        try writer.writeInt(u32, 9, .little);
        try writer.writeInt(u64, 1, .little);
    }

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    const result = parser.parseDocument(std.testing.allocator, r, .little, .{});
    try std.testing.expectError(error.RecursionDepthExceeded, result);
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

test "validator: reject duplicate tensor names" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 2, .little);
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 6, .little);
    try writer.writeAll("weight");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 0, .little);

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

    try writer.writeInt(u64, 2, .little);
    try writer.writeAll("t0");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 0, .little); // F32: 32 * 4 = 128 bytes
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 2, .little);
    try writer.writeAll("t1");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 32, .little); // overlaps [0, 128)

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

test "validator: reject removed/deprecated type slot 31" {
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
    try writer.writeInt(u32, 31, .little); // Slot 31 is removed!
    try writer.writeInt(u64, 0, .little);

    const written_len = fbs.getWritten().len;
    const tensor_data_base = (written_len + 31) & ~@as(usize, 31);
    const total_file_size = tensor_data_base + 64;

    const slice_reader = reader_mod.SliceReader.init(buffer[0..total_file_size]);
    const r = slice_reader.reader();

    var doc = try parser.parseDocument(std.testing.allocator, r, .little, .{});
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidTensorType, structural.validateStructural(std.testing.allocator, doc));
}
