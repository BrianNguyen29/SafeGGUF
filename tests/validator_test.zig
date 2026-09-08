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
    .{ .id = 9, .name = "Q8_1", .block_size = 32, .type_size = 36 },
    .{ .id = 10, .name = "Q2_K", .block_size = 256, .type_size = 84 },
    .{ .id = 11, .name = "Q3_K", .block_size = 256, .type_size = 110 },
    .{ .id = 12, .name = "Q4_K", .block_size = 256, .type_size = 144 },
    .{ .id = 13, .name = "Q5_K", .block_size = 256, .type_size = 176 },
    .{ .id = 14, .name = "Q6_K", .block_size = 256, .type_size = 210 },
    .{ .id = 15, .name = "Q8_K", .block_size = 256, .type_size = 292 },
    .{ .id = 16, .name = "IQ2_XXS", .block_size = 256, .type_size = 66 },
    .{ .id = 17, .name = "IQ2_XS", .block_size = 256, .type_size = 74 },
    .{ .id = 18, .name = "IQ3_XXS", .block_size = 256, .type_size = 98 },
    .{ .id = 19, .name = "IQ1_S", .block_size = 256, .type_size = 50 },
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
    .{ .id = 34, .name = "TQ1_0", .block_size = 256, .type_size = 54 },
    .{ .id = 35, .name = "TQ2_0", .block_size = 256, .type_size = 66 },
    // 36, 37, 38 removed
    .{ .id = 39, .name = "MXFP4", .block_size = 32, .type_size = 17 },
    .{ .id = 40, .name = "NVFP4", .block_size = 64, .type_size = 36 },
    .{ .id = 41, .name = "Q1_0", .block_size = 128, .type_size = 18 },
    .{ .id = 42, .name = "Q2_0", .block_size = 64, .type_size = 18 },
};

test "types: exhaustive oracle verification for all IDs 0..50" {
    var active_count: u32 = 0;

    var id: u32 = 0;
    while (id <= 50) : (id += 1) {
        const traits = types.getTypeTraits(id);

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
            try std.testing.expect(traits == null);
        }
    }

    try std.testing.expectEqual(@as(u32, 35), active_count);
    try std.testing.expectEqual(@as(u32, 35), types.ACTIVE_TYPE_COUNT);
    try std.testing.expectEqual(@as(u32, 43), types.GGML_TYPE_COUNT);
}

// ---------------------------------------------------------------------------
// 2. In-Memory Concrete False-PASS Regression Test (NVFP4 Truncation)
// ---------------------------------------------------------------------------

test "regression: in-memory type 40 (NVFP4) truncated file must be REJECTED" {
    // Exact in-memory construction: 84 bytes total.
    // Descriptor ends at byte 57, tensor_data_base = 64.
    // Correct NVFP4 (type 40) payload for 64 elements = 36 bytes -> requires 100 bytes.
    // The truncated 84-byte buffer only contains 20 bytes payload.
    var buffer: [84]u8 = [_]u8{0} ** 84;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 1, .little); // name len
    try writer.writeAll("x");
    try writer.writeInt(u32, 1, .little); // 1 dim
    try writer.writeInt(u64, 64, .little); // 64 elements
    try writer.writeInt(u32, 40, .little); // NVFP4
    try writer.writeInt(u64, 0, .little); // offset 0

    // Pad up to byte 64
    const written_len = fbs.getWritten().len;
    try std.testing.expectEqual(@as(usize, 57), written_len);
    var p: usize = written_len;
    while (p < 64) : (p += 1) {
        try writer.writeByte(0);
    }
    // 20 bytes of payload (up to 84)
    var b: usize = 0;
    while (b < 20) : (b += 1) {
        try writer.writeByte(0xAA);
    }

    try std.testing.expectEqual(@as(usize, 84), fbs.getWritten().len);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1_000_000);
    var doc = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 40), doc.tensors[0].tensor_type);
    try std.testing.expectEqual(@as(u64, 64), doc.tensors[0].dimensions[0]);

    // Validation must REJECT with TensorOutOfBounds!
    try std.testing.expectError(error.TensorOutOfBounds, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &budget));
}

// ---------------------------------------------------------------------------
// 3. Profile Divergence Tests: gguf-spec vs llama-cpp
// ---------------------------------------------------------------------------

test "profile: tensor gaps allowed in gguf-spec, rejected in llama-cpp" {
    // 2 tensors:
    // Tensor 0: offset 0, size 32 -> end 32
    // Tensor 1: offset 64 (gap between 32 and 64!), size 32 -> end 96
    var buffer: [512]u8 = [_]u8{0} ** 512;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 2, .little);
    try writer.writeInt(u64, 0, .little);

    // Tensor 0
    try writer.writeInt(u64, 2, .little);
    try writer.writeAll("t0");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 8, .little);
    try writer.writeInt(u32, 0, .little); // F32: 8*4 = 32 bytes
    try writer.writeInt(u64, 0, .little);

    // Tensor 1: offset 64 (gap!)
    try writer.writeInt(u64, 2, .little);
    try writer.writeAll("t1");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 8, .little);
    try writer.writeInt(u32, 0, .little); // F32: 32 bytes
    try writer.writeInt(u64, 64, .little);

    const written_len = fbs.getWritten().len;
    const tensor_data_base = (written_len + 31) & ~@as(usize, 31);
    const total_file_size = tensor_data_base + 128;

    const slice_reader = reader_mod.SliceReader.init(buffer[0..total_file_size]);
    const r = slice_reader.reader();

    var budget1 = limits.WorkBudget.init(1000);
    var doc_spec = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget1);
    defer doc_spec.deinit(std.testing.allocator);

    // Under gguf_spec: gap is valid non-overlapping aligned layout -> PASS!
    var b_spec = limits.WorkBudget.init(1000);
    try structural.validateStructural(std.testing.allocator, doc_spec, .gguf_spec, &b_spec);

    // Under llama_cpp: non-contiguous offset violates upstream loader -> REJECT!
    var b_llama = limits.WorkBudget.init(1000);
    try std.testing.expectError(error.NonContiguousTensorOffset, structural.validateStructural(std.testing.allocator, doc_spec, .llama_cpp, &b_llama));
}

test "profile: nested arrays allowed in gguf-spec, rejected in llama-cpp" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 1, .little);

    const key = "nested_data";
    try writer.writeInt(u64, key.len, .little);
    try writer.writeAll(key);
    try writer.writeInt(u32, 9, .little); // outer array
    try writer.writeInt(u32, 9, .little); // inner array
    try writer.writeInt(u64, 1, .little); // 1 element
    try writer.writeInt(u32, 4, .little); // uint32
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u32, 42, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // Under gguf_spec: nested arrays are valid -> PASS!
    var b1 = limits.WorkBudget.init(1000);
    var doc_spec = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b1);
    defer doc_spec.deinit(std.testing.allocator);

    // Under llama_cpp: nested arrays are rejected by upstream ggml switch -> REJECT!
    var b2 = limits.WorkBudget.init(1000);
    const result_llama = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .llama_cpp, &b2);
    try std.testing.expectError(error.NestedArrayNotSupported, result_llama);
}

test "profile: 64-byte tensor name allowed in gguf-spec, rejected in llama-cpp" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    // Exactly 64-byte tensor name
    const exact_64_name = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789__";
    try std.testing.expectEqual(@as(usize, 64), exact_64_name.len);

    try writer.writeInt(u64, 64, .little);
    try writer.writeAll(exact_64_name);
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // Under gguf_spec: 64 bytes is allowed (<= 64) -> PASS!
    var b1 = limits.WorkBudget.init(1000);
    var doc_spec = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b1);
    defer doc_spec.deinit(std.testing.allocator);

    // Under llama_cpp: >= GGML_MAX_NAME (64) is rejected -> REJECT!
    var b2 = limits.WorkBudget.init(1000);
    const result_llama = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .llama_cpp, &b2);
    try std.testing.expectError(error.TensorNameTooLong, result_llama);
}

test "profile: version 2 rejected in gguf-spec, accepted in llama-cpp" {
    var buffer: [64]u8 = [_]u8{0} ** 64;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 2, .little); // version 2
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // Under gguf_spec: strictly version 3 -> REJECT!
    var b1 = limits.WorkBudget.init(1000);
    const result_spec = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b1);
    try std.testing.expectError(error.UnsupportedVersion, result_spec);

    // Under llama_cpp: supports version 2 and 3 -> PASS!
    var b2 = limits.WorkBudget.init(1000);
    var doc_llama = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .llama_cpp, &b2);
    defer doc_llama.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 2), doc_llama.header.version);
}

// ---------------------------------------------------------------------------
// 4. QuotaAllocator & WorkBudget Unit Tests
// ---------------------------------------------------------------------------

test "limits: QuotaAllocator strictly enforces global memory ceiling" {
    var quota = limits.QuotaAllocator.init(std.testing.allocator, 100);
    const alloc = quota.allocator();

    // Allocate 60 bytes: OK
    const slice1 = try alloc.alloc(u8, 60);
    try std.testing.expectEqual(@as(u64, 60), quota.allocated_bytes);

    // Allocate 50 bytes: Exceeds 100 (60 + 50 = 110) -> returns OutOfMemory
    try std.testing.expectError(error.OutOfMemory, alloc.alloc(u8, 50));

    // Free slice1: drops back to 0
    alloc.free(slice1);
    try std.testing.expectEqual(@as(u64, 0), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 60), quota.peak_bytes);
}

test "limits: WorkBudget strictly enforces work unit ceiling" {
    var budget = limits.WorkBudget.init(10);
    try budget.consume(5);
    try std.testing.expectEqual(@as(u64, 5), budget.consumed_units);

    try budget.consume(5);
    try std.testing.expectEqual(@as(u64, 10), budget.consumed_units);

    // Exceeds 10
    try std.testing.expectError(error.ResourceLimitExceeded, budget.consume(1));
}

// ---------------------------------------------------------------------------
// 5. Checked Arithmetic & Divisibility
// ---------------------------------------------------------------------------

test "arithmetic: checked add, mul, align" {
    try std.testing.expectEqual(@as(u64, 30), try arithmetic.checkedAdd(10, 20));
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedAdd(std.math.maxInt(u64), 1));

    try std.testing.expectEqual(@as(u64, 200), try arithmetic.checkedMul(10, 20));
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedMul(std.math.maxInt(u64), 2));

    try std.testing.expectEqual(@as(u64, 32), try arithmetic.checkedAlignUp(17, 32));
    try std.testing.expectEqual(@as(u64, 32), try arithmetic.checkedAlignUp(32, 32));
    try std.testing.expectError(error.InvalidAlignment, arithmetic.checkedAlignUp(10, 7));
}

test "arithmetic: computeTensorBytes for Q4_0 and divisibility" {
    const valid_dims = [_]u64{ 64, 10 };
    const bytes = try arithmetic.computeTensorBytes(&valid_dims, 2);
    try std.testing.expectEqual(@as(u64, 360), bytes);

    const invalid_dims = [_]u64{ 30, 10 };
    try std.testing.expectError(error.BlockDivisibilityViolation, arithmetic.computeTensorBytes(&invalid_dims, 2));

    const overflow_dims = [_]u64{ std.math.maxInt(u64), 2 };
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(&overflow_dims, 0));
}

// ---------------------------------------------------------------------------
// 6. Strict Format Semantics (BOOL, UTF-8, Key Grammar)
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
    try writer.writeInt(u32, 7, .little);
    try writer.writeByte(2);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
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
    try writer.writeInt(u32, 9, .little);
    try writer.writeInt(u32, 7, .little);
    try writer.writeInt(u64, 4, .little);
    try writer.writeAll(&[_]u8{ 0, 1, 255, 0 });

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
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
    try writer.writeInt(u32, 8, .little);
    const bad_utf8 = [_]u8{ 0xFF, 0xFE, 0xFD };
    try writer.writeInt(u64, bad_utf8.len, .little);
    try writer.writeAll(&bad_utf8);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
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

    const bad_tensor_name = [_]u8{ 'b', 'a', 'd', 0xC0, 0xAF };
    try writer.writeInt(u64, bad_tensor_name.len, .little);
    try writer.writeAll(&bad_tensor_name);
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 32, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
    try std.testing.expectError(error.InvalidUtf8, result);
}

test "metadata: reject key containing hyphens" {
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("general.model-arch"));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("Model_Arch"));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey(".leading_dot"));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("trailing_dot."));
    try std.testing.expectError(error.InvalidKeyFormat, safegguf.metadata.validateKey("double..dot"));

    try safegguf.metadata.validateKey("general.architecture");
    try safegguf.metadata.validateKey("tokenizer.ggml.tokens");
    try safegguf.metadata.validateKey("blk_0_attn_q");
}

test "parser: reject zero dimension in tensor" {
    var buffer: [128]u8 = [_]u8{0} ** 128;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 4, .little);
    try writer.writeAll("zero");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 0, .little); // 0 dimension!
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
    try std.testing.expectError(error.ZeroDimensionNotAllowed, result);
}

// ---------------------------------------------------------------------------
// 7. Structural & Basic Invariant Tests
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
    try writer.writeInt(u32, 24, .little); // 24: multiple of 8, not power of 2

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var b1 = limits.WorkBudget.init(1000);
    const doc_spec = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b1);
    var doc_mut = doc_spec;
    defer doc_mut.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 24), doc_spec.alignment);

    var b2 = limits.WorkBudget.init(1000);
    const result_llama = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .llama_cpp, &b2);
    try std.testing.expectError(error.CompatibilityViolation, result_llama);
}

test "parser: reject invalid magic" {
    const invalid_magic_buf = [_]u8{ 'B', 'A', 'D', '!', 3, 0, 0, 0 };
    const slice_reader = reader_mod.SliceReader.init(&invalid_magic_buf);
    const r = slice_reader.reader();

    var b = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    try std.testing.expectError(error.InvalidMagic, result);
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

    var b = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    try std.testing.expectError(error.UnexpectedEof, result);
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

    var b = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    try std.testing.expectError(error.DuplicateMetadataKey, result);
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

    var b = limits.WorkBudget.init(1000);
    var doc = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.MisalignedTensor, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &b));
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

    var b = limits.WorkBudget.init(1000);
    var doc = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.DuplicateTensorName, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &b));
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

    var b = limits.WorkBudget.init(1000);
    var doc = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.TensorOverlap, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &b));
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

    var b = limits.WorkBudget.init(1000);
    var doc = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    defer doc.deinit(std.testing.allocator);

    try std.testing.expectError(error.InvalidTensorType, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &b));
}

// ---------------------------------------------------------------------------
// 4. v0.2.3 Security Hardening & P0 Overflow Regression Tests
// ---------------------------------------------------------------------------

test "structural: llama_cpp contiguous offset overflow does not panic and returns ArithmeticOverflow" {
    // Demonstrates the P0 review finding:
    // Tensor 0: offset 0, 32 bytes (F32, dims=[8])
    // Tensor 1: offset 32, dims=[2_305_843_009_213_693_951], type F64 (8 bytes per elem -> nbytes = UINT64_MAX - 7)
    // Under llama_cpp, previous expected_offset = 32.
    // Unchecked: 32 + (UINT64_MAX - 7) overflows u64!
    // Checked arithmetic MUST return error.ArithmeticOverflow without panic!
    var dims0 = [_]u64{8};
    var dims1 = [_]u64{2_305_843_009_213_693_951};
    var tensors = [_]parser.TensorInfo{
        .{
            .name = "t0",
            .dimensions = &dims0,
            .tensor_type = 0, // F32
            .offset = 0,
        },
        .{
            .name = "t1",
            .dimensions = &dims1,
            .tensor_type = 28, // F64 (type_size 8, block_size 1)
            .offset = 32,
        },
    };

    const doc = parser.Document{
        .header = .{ .version = 3, .tensor_count = 2, .metadata_kv_count = 0 },
        .alignment = 32,
        .tensor_data_base = 64,
        .tensors = &tensors,
        .file_size = std.math.maxInt(u64),
    };

    var budget = limits.WorkBudget.init(1000);
    try std.testing.expectError(error.ArithmeticOverflow, structural.validateStructural(std.testing.allocator, doc, .llama_cpp, &budget));
}

test "profile: scalar tensor (n_dims == 0) supported under llama_cpp" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    try writer.writeInt(u64, 6, .little);
    try writer.writeAll("scalar");
    try writer.writeInt(u32, 0, .little); // n_dims == 0 (scalar!)
    try writer.writeInt(u32, 0, .little); // F32 -> 4 bytes
    try writer.writeInt(u64, 0, .little);

    const written_len = fbs.getWritten().len;
    const tensor_data_base = (written_len + 31) & ~@as(usize, 31);
    const total_file_size = tensor_data_base + 32;

    const slice_reader = reader_mod.SliceReader.init(buffer[0..total_file_size]);
    const r = slice_reader.reader();

    // Under both gguf_spec and llama_cpp: n_dims == 0 is accepted as a scalar tensor!
    var b_spec = limits.WorkBudget.init(1000);
    var doc_spec = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b_spec);
    defer doc_spec.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), doc_spec.tensors[0].dimensions.len);

    var b_llama = limits.WorkBudget.init(1000);
    var doc_llama = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .llama_cpp, &b_llama);
    defer doc_llama.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), doc_llama.tensors[0].dimensions.len);
    var b_val = limits.WorkBudget.init(1000);
    try structural.validateStructural(std.testing.allocator, doc_llama, .llama_cpp, &b_val);
}

test "limits: QuotaAllocator tracks isQuotaExceeded flag correctly" {
    var qa = limits.QuotaAllocator.init(std.testing.allocator, 100);
    const alloc = qa.allocator();

    try std.testing.expectEqual(false, qa.isQuotaExceeded());

    const buf1 = try alloc.alloc(u8, 50);
    defer alloc.free(buf1);
    try std.testing.expectEqual(false, qa.isQuotaExceeded());

    // This allocation would exceed 100 bytes (50 + 60 = 110 > 100)
    const err_alloc = alloc.alloc(u8, 60);
    try std.testing.expectError(error.OutOfMemory, err_alloc);
    try std.testing.expectEqual(true, qa.isQuotaExceeded());

    qa.resetQuotaExceeded();
    try std.testing.expectEqual(false, qa.isQuotaExceeded());
}

test "structural: WorkBudget exhaustion returns ResourceLimitExceeded" {
    var dims = [_]u64{32};
    var tensors = [_]parser.TensorInfo{
        .{
            .name = "t0",
            .dimensions = &dims,
            .tensor_type = 0,
            .offset = 0,
        },
    };

    const doc = parser.Document{
        .header = .{ .version = 3, .tensor_count = 1, .metadata_kv_count = 0 },
        .alignment = 32,
        .tensor_data_base = 32,
        .tensors = &tensors,
        .file_size = 256,
    };

    var budget = limits.WorkBudget.init(0); // 0 work units allowed!
    try std.testing.expectError(error.ResourceLimitExceeded, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &budget));
}

test "structural: llama_cpp rejects truncated final tensor padding (HIGH-01)" {
    // 1 scalar tensor (F32, 4 bytes), alignment 32.
    // doc.tensor_data_base = 32, tensor.offset = 0.
    // Unpadded end is 32 + 4 = 36 bytes.
    // Aligned end is 32 + 32 = 64 bytes.
    // If file_size is 36, safe unpadded check passes, but contiguous padded check must fail!
    const dims = [_]u64{};
    const tensors = [_]parser.TensorInfo{
        .{
            .name = "scalar",
            .dimensions = &dims,
            .tensor_type = 0, // F32 -> 4 bytes
            .offset = 0,
        },
    };

    const doc = parser.Document{
        .header = .{ .version = 3, .tensor_count = 1, .metadata_kv_count = 0 },
        .alignment = 32,
        .tensor_data_base = 32,
        .tensors = &tensors,
        .file_size = 36, // Missing 28 bytes of trailing padding!
    };

    var budget = limits.WorkBudget.init(1000);
    try std.testing.expectError(error.TensorOutOfBounds, structural.validateStructural(std.testing.allocator, doc, .llama_cpp, &budget));
}

test "limits: WorkBudget byte-scanning exhaustion returns ResourceLimitExceeded (HIGH-03)" {
    // Limits byte scanning to 50 bytes
    var budget = limits.WorkBudget.initWithLimits(1000, 50);
    try budget.consumeBytes(30);
    try std.testing.expectEqual(@as(u64, 30), budget.consumed_scanned_bytes);
    try std.testing.expectError(error.ResourceLimitExceeded, budget.consumeBytes(25)); // 30 + 25 = 55 > 50
}

test "parser: reject zero-element dimension" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little); // 1 tensor
    try writer.writeInt(u64, 0, .little); // 0 metadata

    const name = "zero_dim";
    try writer.writeInt(u64, name.len, .little);
    try writer.writeAll(name);
    try writer.writeInt(u32, 1, .little); // 1 dim
    try writer.writeInt(u64, 0, .little); // dim 0 is 0!
    try writer.writeInt(u32, 0, .little); // F32
    try writer.writeInt(u64, 0, .little); // offset 0

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var b = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    try std.testing.expectError(error.ZeroDimensionNotAllowed, result);
}

test "parser: reject empty tensor name" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little); // 1 tensor
    try writer.writeInt(u64, 0, .little); // 0 metadata

    // name length 0
    try writer.writeInt(u64, 0, .little);
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var b = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    try std.testing.expectError(error.InvalidTensorName, result);
}

test "structural: public API rejects alignment == 0 without panic" {
    var doc = parser.Document{
        .header = .{ .version = 3, .tensor_count = 0, .metadata_kv_count = 0 },
        .alignment = 0, // Malformed alignment passed directly via public API!
        .tensor_data_base = 32,
        .tensors = &[_]parser.TensorInfo{},
        .file_size = 256,
    };

    var budget = limits.WorkBudget.init(1000);
    try std.testing.expectError(error.InvalidAlignment, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &budget));

    // alignment not multiple of 8
    doc.alignment = 7;
    try std.testing.expectError(error.InvalidAlignment, structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &budget));

    // alignment not power of two under llama_cpp profile
    doc.alignment = 24;
    try std.testing.expectError(error.InvalidAlignment, structural.validateStructural(std.testing.allocator, doc, .llama_cpp, &budget));
}

test "parser: reject non-zero alignment padding bytes" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little); // 1 tensor
    try writer.writeInt(u64, 0, .little); // 0 metadata

    const name = "t0";
    try writer.writeInt(u64, name.len, .little);
    try writer.writeAll(name);
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 8, .little);
    try writer.writeInt(u32, 0, .little); // F32
    try writer.writeInt(u64, 0, .little); // offset 0

    // Current length is 4 + 4 + 8 + 8 + (8 + 2 + 4 + 8 + 4 + 8) = 24 + 34 = 58.
    // Alignment is 32 -> tensor_data_base is 64.
    // Padding bytes are 58..64 (6 bytes).
    // Write non-zero bytes in padding:
    try writer.writeAll(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
    try writer.writeAll(&[_]u8{0} ** 32); // tensor data

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    var b = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &b);
    try std.testing.expectError(error.InvalidAlignmentPadding, result);
}

test "parser: llama_cpp profile rejects non-native endianness" {
    // Construct valid big-endian buffer
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .big);
    try writer.writeInt(u64, 0, .big);
    try writer.writeInt(u64, 0, .big);

    const slice_reader = reader_mod.SliceReader.init(fbs.getWritten());
    const r = slice_reader.reader();

    // In a little-endian host, big-endian under llama-cpp must return CompatibilityViolation
    const host_endian = @import("builtin").cpu.arch.endian();
    const opposite_endian: std.builtin.Endian = if (host_endian == .little) .big else .little;

    var b = limits.WorkBudget.init(1000);
    const result = parser.parseDocument(std.testing.allocator, r, opposite_endian, limits.Limits{}, .llama_cpp, &b);
    try std.testing.expectError(error.CompatibilityViolation, result);
}
