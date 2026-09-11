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

    const written_len = fbs.getWritten().len;
    const padded_len = (written_len + 31) & ~@as(usize, 31);
    const slice_reader = reader_mod.SliceReader.init(buffer[0..padded_len]);
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

    const written_len = fbs.getWritten().len;
    const padded_len = (written_len + 31) & ~@as(usize, 31);
    const slice_reader = reader_mod.SliceReader.init(buffer[0..padded_len]);
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

test "arithmetic: computeTensorBytes rejects flagship and cumulative-overflow dims" {
    // Flagship advisory shape (CVE-2026-33298 class): F32 [1024, 1024,
    // 2^42 + 1, 1]. The cumulative element product 2^62 + 2^20 fits u64, so
    // rejection must come from the checked byte multiplication
    // (x4 = 2^64 + 2^22), never from wrapping.
    const flagship_dims = [_]u64{ 1024, 1024, (1 << 42) + 1, 1 };
    try std.testing.expectEqual(@as(u64, (1 << 62) + (1 << 20)), try arithmetic.checkedProduct(&flagship_dims));
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(&flagship_dims, 0));

    // Cumulative-overflow dims: the running product itself crosses u64 while
    // the dimension list is multiplied (2^21 x 2^21 x 2^21 x 2 = 2^64), so
    // the overflow is caught before any block/byte arithmetic.
    const cumulative_dims = [_]u64{ 1 << 21, 1 << 21, 1 << 21, 2 };
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedProduct(&cumulative_dims));
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(&cumulative_dims, 0));
}

// Deterministic LCG stream; identical constants are used by tests/arithmetic_oracle.py.
fn nextRandomU64(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.*;
}

test "arithmetic: alignUp invariants hold and overflow classification is exact" {
    const alignments = [_]u64{ 8, 16, 24, 32, 64, 256, 4096, 65536, 1 << 31 };
    const boundary_samples = [_]u64{
        0,                           1,                        7,                        8,                        9,                    31,    32,                       33,
        4095,                        4096,                     4097,                     65535,                    65536,                65537, std.math.maxInt(u64) / 2, std.math.maxInt(u64) / 2 + 1,
        std.math.maxInt(u64) - 4096, std.math.maxInt(u64) - 8, std.math.maxInt(u64) - 7, std.math.maxInt(u64) - 1, std.math.maxInt(u64),
    };

    var overflow_count: usize = 0;
    var fit_count: usize = 0;
    var state: u64 = 0x243F6A8885A308D3;

    for (alignments) |a| {
        // Boundary hits first, then deterministic pseudo-random values.
        var x_idx: usize = 0;
        while (x_idx < boundary_samples.len + 512) : (x_idx += 1) {
            const x = if (x_idx < boundary_samples.len)
                boundary_samples[x_idx]
            else
                nextRandomU64(&state) % (std.math.maxInt(u64) / 2);

            // u128 oracle: exact unbounded result for x + (a - x % a).
            const rem = x % a;
            const add: u128 = if (rem == 0) 0 else a - rem;
            const wide = @as(u128, x) + add;

            if (wide > std.math.maxInt(u64)) {
                try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedAlignUp(x, a));
                overflow_count += 1;
            } else {
                const aligned = try arithmetic.checkedAlignUp(x, a);
                try std.testing.expectEqual(@as(u64, @intCast(wide)), aligned);
                // Invariants: monotone, multiple of a, idempotent.
                try std.testing.expect(aligned >= x);
                try std.testing.expectEqual(@as(u64, 0), aligned % a);
                try std.testing.expectEqual(aligned, try arithmetic.checkedAlignUp(aligned, a));
                fit_count += 1;
            }
        }
    }

    try std.testing.expect(overflow_count > 0);
    try std.testing.expect(fit_count > 0);

    // Invalid alignments: zero and non-multiples of 8 are rejected outright.
    try std.testing.expectError(error.InvalidAlignment, arithmetic.checkedAlignUp(16, 0));
    try std.testing.expectError(error.InvalidAlignment, arithmetic.checkedAlignUp(16, 7));
    try std.testing.expectError(error.InvalidAlignment, arithmetic.checkedAlignUp(16, 12));
}

test "arithmetic: computeTensorBytes classification matches u128 oracle" {
    const types_sample = [_]u32{ 0, 2, 8, 12, 39, 42 };
    var counts = struct {
        ok: usize = 0,
        block_violation: usize = 0,
        product_overflow: usize = 0,
        nbytes_overflow: usize = 0,
    }{};
    var state: u64 = 0xBB67AE8584CAA73B;

    for (types_sample) |tensor_type| {
        const traits = types.getTypeTraits(tensor_type).?;
        var tuple_idx: usize = 0;
        while (tuple_idx < 700) : (tuple_idx += 1) {
            const n_dims: usize = @intCast(nextRandomU64(&state) % 5);
            var dims: [4]u64 = undefined;
            for (dims[0..n_dims]) |*d| {
                const pick = nextRandomU64(&state) % 4;
                d.* = switch (pick) {
                    // Small (hits divisibility and exact products).
                    0 => 1 + nextRandomU64(&state) % 256,
                    // Medium multi-block values.
                    1 => 256 + nextRandomU64(&state) % 8192,
                    // Huge values (hits product / byte-count overflow).
                    2 => std.math.maxInt(u64) - nextRandomU64(&state) % 4096,
                    // Occasional zero (product overflow via zero dimension).
                    else => 0,
                };
            }

            // u128 oracle mirroring the documented classification order:
            // traits lookup -> n_dims bound -> scalar -> row divisibility ->
            // product -> block division -> byte count.
            if (n_dims == 0) {
                if (traits.block_size != 1) {
                    try std.testing.expectError(error.BlockDivisibilityViolation, arithmetic.computeTensorBytes(dims[0..0], tensor_type));
                } else {
                    try std.testing.expectEqual(traits.type_size, try arithmetic.computeTensorBytes(dims[0..0], tensor_type));
                    counts.ok += 1;
                }
                continue;
            }

            const dims_slice = dims[0..n_dims];
            if (dims[0] % traits.block_size != 0) {
                try std.testing.expectError(error.BlockDivisibilityViolation, arithmetic.computeTensorBytes(dims_slice, tensor_type));
                counts.block_violation += 1;
                continue;
            }

            var prod128: u128 = 1;
            var zero_dim = false;
            var product_overflow = false;
            for (dims_slice) |d| {
                if (d == 0) {
                    zero_dim = true;
                    break;
                }
                // Only multiply while the accumulator still fits u64, so the
                // u128 multiplication itself can never overflow.
                if (!product_overflow) {
                    prod128 *= d;
                    if (prod128 > std.math.maxInt(u64)) product_overflow = true;
                }
            }
            if (zero_dim or product_overflow) {
                try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(dims_slice, tensor_type));
                counts.product_overflow += 1;
                continue;
            }

            const nbytes128 = (prod128 / traits.block_size) * traits.type_size;
            if (nbytes128 > std.math.maxInt(u64)) {
                try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(dims_slice, tensor_type));
                counts.nbytes_overflow += 1;
            } else {
                try std.testing.expectEqual(@as(u64, @intCast(nbytes128)), try arithmetic.computeTensorBytes(dims_slice, tensor_type));
                counts.ok += 1;
            }
        }
    }

    // Every classification branch must have been exercised at least once.
    try std.testing.expect(counts.ok > 0);
    try std.testing.expect(counts.block_violation > 0);
    try std.testing.expect(counts.product_overflow > 0);
    try std.testing.expect(counts.nbytes_overflow > 0);
}

test "arithmetic: computeTensorBytes rejects invalid types and dimension counts" {
    // Deprecated / removed / out-of-range type ids must all be rejected.
    for ([_]u32{ 4, 5, 31, 32, 33, 36, 37, 38, 43, std.math.maxInt(u32) }) |bad_type| {
        try std.testing.expectError(error.InvalidTensorType, arithmetic.computeTensorBytes(&[_]u64{32}, bad_type));
    }

    // n_dims > 4 rejected before any arithmetic.
    try std.testing.expectError(error.InvalidDimensionCount, arithmetic.computeTensorBytes(&[_]u64{ 32, 2, 2, 2, 2 }, 0));

    // Scalar tensors: block-1 types yield type_size; block types are rejected.
    try std.testing.expectEqual(@as(u64, 4), try arithmetic.computeTensorBytes(&[_]u64{}, 0));
    try std.testing.expectEqual(@as(u64, 8), try arithmetic.computeTensorBytes(&[_]u64{}, 27));
    try std.testing.expectError(error.BlockDivisibilityViolation, arithmetic.computeTensorBytes(&[_]u64{}, 2));
}

test "arithmetic: checkedProduct invariants and overflow" {
    try std.testing.expectEqual(@as(u64, 1), try arithmetic.checkedProduct(&[_]u64{1}));
    try std.testing.expectEqual(@as(u64, 105), try arithmetic.checkedProduct(&[_]u64{ 3, 5, 7 }));

    // Zero dimension overflows instead of silently yielding 0.
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedProduct(&[_]u64{ 3, 0, 7 }));

    // Empty dimension list is a contract violation, not a product.
    try std.testing.expectError(error.InvalidDimensionCount, arithmetic.checkedProduct(&[_]u64{}));

    // 2^32 * 2^33 = 2^65 does not wrap.
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.checkedProduct(&[_]u64{ 1 << 32, 1 << 33 }));
}

// Shared oracle vectors: the expected values below are cross-checked
// independently by tests/arithmetic_oracle.py (Python bigints).
test "arithmetic: oracle cross-check vectors" {
    try std.testing.expectEqual(@as(u64, 360), try arithmetic.computeTensorBytes(&[_]u64{ 64, 10 }, 2));
    try std.testing.expectEqual(@as(u64, 544), try arithmetic.computeTensorBytes(&[_]u64{ 256, 2 }, 8));
    try std.testing.expectEqual(@as(u64, 25_362_432), try arithmetic.computeTensorBytes(&[_]u64{ 4096, 11008 }, 12));

    // Product fits (2^64-32 = 32 * (2^59 - 1)) but (2^59 - 1) blocks * 34 bytes does not.
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(&[_]u64{std.math.maxInt(u64) - 31}, 8));
    try std.testing.expectError(error.ArithmeticOverflow, arithmetic.computeTensorBytes(&[_]u64{ std.math.maxInt(u64) / 2, 5 }, 0));
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

// Builds a minimal GGUF v3 document with a single string metadata entry whose
// value is `value`, exercising validateUtf8Stream through the metadata string
// path (metadata.zig skipMetadataValue -> validateUtf8Stream) with its 4096
// byte sliding buffer and carry logic.
fn buildMetadataStringDoc(allocator: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();
    const w = list.writer();

    try w.writeAll("GGUF");
    try w.writeInt(u32, 3, .little);
    try w.writeInt(u64, 0, .little); // tensor count
    try w.writeInt(u64, 1, .little); // metadata kv count

    const key = "text_payload";
    try w.writeInt(u64, key.len, .little);
    try w.writeAll(key);
    try w.writeInt(u32, 8, .little); // MetadataType.string
    try w.writeInt(u64, value.len, .little);
    try w.writeAll(value);

    // Zero-fill the required alignment padding up to alignUp(cur, 32) so the
    // document is structurally valid (parser rejects non-zero or missing padding).
    const padding = (32 - @as(u64, @intCast(list.items.len % 32))) % 32;
    try w.writeByteNTimes(0, @intCast(padding));

    return list.toOwnedSlice();
}

fn expectMetadataStringOk(value: []const u8) !void {
    const bytes = try buildMetadataStringDoc(std.testing.allocator, value);
    defer std.testing.allocator.free(bytes);

    const slice_reader = reader_mod.SliceReader.init(bytes);
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1_000_000);
    var doc = try parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
    defer doc.deinit(std.testing.allocator);
}

fn expectMetadataStringError(value: []const u8, expected: anyerror) !void {
    const bytes = try buildMetadataStringDoc(std.testing.allocator, value);
    defer std.testing.allocator.free(bytes);

    const slice_reader = reader_mod.SliceReader.init(bytes);
    const r = slice_reader.reader();

    var budget = limits.WorkBudget.init(1_000_000);
    const result = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .gguf_spec, &budget);
    try std.testing.expectError(expected, result);
}

test "metadata: utf8 carry accepts sequences straddling the 4096 chunk boundary" {
    const pad = [_]u8{'a'} ** 4095;
    const tail = [_]u8{'b'} ** 64;

    // 2-byte code point split as 4095|4096.
    const two_byte = pad ++ [_]u8{ 0xC3, 0xA9 } ++ tail;
    try expectMetadataStringOk(&two_byte);

    // 3-byte code point split as 4094|4095|4096.
    const three_byte = pad[0..4094].* ++ [_]u8{ 0xE2, 0x82, 0xAC } ++ tail;
    try expectMetadataStringOk(&three_byte);

    // 4-byte code point split as 4093|4094|4095|4096.
    const four_byte = pad[0..4093].* ++ [_]u8{ 0xF0, 0x9F, 0x98, 0x80 } ++ tail;
    try expectMetadataStringOk(&four_byte);

    // 4-byte code point ending exactly on the boundary.
    const at_boundary = pad[0..4092].* ++ [_]u8{ 0xF0, 0x9F, 0x98, 0x80 } ++ tail;
    try expectMetadataStringOk(&at_boundary);

    // Multi-chunk ASCII stream (carry_len stays 0 across chunk transitions).
    const ascii_multi_chunk = [_]u8{'a'} ** 8192;
    try expectMetadataStringOk(&ascii_multi_chunk);
}

test "metadata: utf8 carry accepts 3-byte stream split across three chunks" {
    // 8193 bytes of '€' (U+20AC, 3 bytes): chunk 1 carries the lead byte at
    // 4095, chunk 2 carries the next lead byte, chunk 3 validates the tail.
    const payload = [_]u8{ 0xE2, 0x82, 0xAC } ** 2731 ++ [_]u8{ 0xF0, 0x9F, 0x98, 0x80 } ** 8;
    try expectMetadataStringOk(&payload);
}

test "metadata: utf8 carry rejects invalid bytes beyond the first chunk" {
    // Valid prefix straddles the first boundary (lead byte carried at 4095);
    // the invalid 0xFF byte sits at file offset 6000, inside chunk 2.
    const payload = [_]u8{ 0xE2, 0x82, 0xAC } ** 2000 ++ [_]u8{0xFF} ++
        [_]u8{ 0xE2, 0x82, 0xAC } ** 731 ++ [_]u8{ 0xF0, 0x9F, 0x98, 0x80 } ** 8;
    try expectMetadataStringError(&payload, error.InvalidUtf8);
}

test "metadata: utf8 carry rejects truncated sequences across the boundary" {
    const pad = [_]u8{'a'} ** 4095;
    const tail = [_]u8{'b'} ** 64;

    // 2-byte sequence truncated after carry: only 0xC3 lands before the cut.
    const trunc_two = pad ++ [_]u8{0xC3} ++ tail;
    try expectMetadataStringError(&trunc_two, error.InvalidUtf8);

    // 3-byte sequence truncated after carry (lead + one continuation).
    const trunc_three = pad[0..4094].* ++ [_]u8{ 0xE2, 0x82 } ++ tail;
    try expectMetadataStringError(&trunc_three, error.InvalidUtf8);

    // 4-byte sequence truncated after carry (lead + two continuations).
    const trunc_four = pad[0..4093].* ++ [_]u8{ 0xF0, 0x9F, 0x98 } ++ tail;
    try expectMetadataStringError(&trunc_four, error.InvalidUtf8);

    // Truncated 3-byte sequence at end of stream (final chunk, no carry).
    const trunc_eof = [_]u8{'a'} ** 100 ++ [_]u8{ 0xE2, 0x82 };
    try expectMetadataStringError(&trunc_eof, error.InvalidUtf8);
}

test "metadata: utf8 carry rejects invalid continuation and overlong encodings across the boundary" {
    const pad = [_]u8{'a'} ** 4095;
    const tail = [_]u8{'b'} ** 64;

    // Invalid continuation byte after a carried lead byte.
    const bad_continuation = pad ++ [_]u8{ 0xC3, 0x41 } ++ tail;
    try expectMetadataStringError(&bad_continuation, error.InvalidUtf8);

    // Overlong 2-byte encoding split by the boundary.
    const overlong_two = pad ++ [_]u8{ 0xC0, 0xAF } ++ tail;
    try expectMetadataStringError(&overlong_two, error.InvalidUtf8);

    // Overlong 3-byte encoding split by the boundary.
    const overlong_three = pad ++ [_]u8{ 0xE0, 0x80, 0x80 } ++ tail;
    try expectMetadataStringError(&overlong_three, error.InvalidUtf8);

    // 5-byte lead byte at the boundary: rejected by the carry scan itself.
    const five_byte_lead = pad ++ [_]u8{ 0xF8, 0x80, 0x80, 0x80 } ++ tail;
    try expectMetadataStringError(&five_byte_lead, error.InvalidUtf8);

    // Overlong encoding fully inside a single chunk.
    const overlong_in_chunk = [_]u8{'a'} ** 100 ++ [_]u8{ 0xC0, 0xAF };
    try expectMetadataStringError(&overlong_in_chunk, error.InvalidUtf8);
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

    const slice_reader = reader_mod.SliceReader.init(buffer[0..72]);
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
    const padded_len = (written_len + 31) & ~@as(usize, 31);
    const slice_reader = reader_mod.SliceReader.init(buffer[0..padded_len]);
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
    const padded_len = (written_len + 31) & ~@as(usize, 31);
    const slice_reader = reader_mod.SliceReader.init(buffer[0..padded_len]);
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

test "spec: zero-tensor file must be padded to alignment under gguf_spec, accepted in llama_cpp" {
    // 24-byte zero-tensor buffer (unpadded)
    var buffer: [64]u8 = [_]u8{0} ** 64;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little); // 0 tensors
    try writer.writeInt(u64, 0, .little); // 0 metadata

    try std.testing.expectEqual(@as(usize, 24), fbs.getWritten().len);

    const r_unpadded = reader_mod.SliceReader.init(fbs.getWritten()).reader();

    // Under gguf_spec: missing alignment padding to 32 -> REJECT with UnexpectedEof!
    var b1 = limits.WorkBudget.init(1000);
    try std.testing.expectError(error.UnexpectedEof, parser.parseDocument(std.testing.allocator, r_unpadded, .little, limits.Limits{}, .gguf_spec, &b1));

    // Under llama_cpp: upstream ggml skips alignment seek when n_tensors == 0 -> PASS!
    var b2 = limits.WorkBudget.init(1000);
    var doc_llama = try parser.parseDocument(std.testing.allocator, r_unpadded, .little, limits.Limits{}, .llama_cpp, &b2);
    defer doc_llama.deinit(std.testing.allocator);

    // Now test properly 32-byte padded buffer -> PASS under both profiles!
    const r_padded = reader_mod.SliceReader.init(buffer[0..32]).reader();
    var b3 = limits.WorkBudget.init(1000);
    var doc_spec = try parser.parseDocument(std.testing.allocator, r_padded, .little, limits.Limits{}, .gguf_spec, &b3);
    defer doc_spec.deinit(std.testing.allocator);
}

test "llama_cpp: reject dimension exceeding INT64_MAX" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    const name = "t_neg";
    try writer.writeInt(u64, name.len, .little);
    try writer.writeAll(name);
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 0x8000000000000000, .little); // > INT64_MAX (negative in int64_t)
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const r = reader_mod.SliceReader.init(buffer[0..64]).reader();

    var b1 = limits.WorkBudget.init(1000);
    const res_llama = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .llama_cpp, &b1);
    try std.testing.expectError(error.CompatibilityViolation, res_llama);
}

test "llama_cpp: reject element product exceeding INT64_MAX" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    const name = "t_ovf";
    try writer.writeInt(u64, name.len, .little);
    try writer.writeAll(name);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 0x4000000000000000, .little); // dim 0
    try writer.writeInt(u64, 2, .little); // dim 1: product reaches 0x8000000000000000 >= INT64_MAX
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const r = reader_mod.SliceReader.init(buffer[0..64]).reader();

    var b1 = limits.WorkBudget.init(1000);
    const res_llama = parser.parseDocument(std.testing.allocator, r, .little, limits.Limits{}, .llama_cpp, &b1);
    try std.testing.expectError(error.CompatibilityViolation, res_llama);
}

test "structural: public API direct call with dimension == 0 returns ZeroDimensionNotAllowed without panic" {
    const dims = [_]u64{0};
    const tensors = [_]parser.TensorInfo{
        .{
            .name = "t_zero",
            .dimensions = &dims,
            .tensor_type = 0,
            .offset = 0,
        },
    };

    const doc = parser.Document{
        .header = .{
            .version = 3,
            .tensor_count = 1,
            .metadata_kv_count = 0,
        },
        .alignment = 32,
        .tensor_data_base = 32,
        .tensors = &tensors,
        .file_size = 128,
    };

    // Under llama_cpp: must NOT panic with division-by-zero, must return ZeroDimensionNotAllowed
    var b1 = limits.WorkBudget.init(1000);
    const res_llama = structural.validateStructural(std.testing.allocator, doc, .llama_cpp, &b1);
    try std.testing.expectError(error.ZeroDimensionNotAllowed, res_llama);

    // Under gguf_spec: must return ZeroDimensionNotAllowed
    var b2 = limits.WorkBudget.init(1000);
    const res_spec = structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &b2);
    try std.testing.expectError(error.ZeroDimensionNotAllowed, res_spec);
}

test "structural: public API direct call with mismatched tensor_count returns CompatibilityViolation" {
    const dims = [_]u64{10};
    const tensors = [_]parser.TensorInfo{
        .{
            .name = "t_test",
            .dimensions = &dims,
            .tensor_type = 0,
            .offset = 0,
        },
    };

    const doc = parser.Document{
        .header = .{
            .version = 3,
            .tensor_count = 100, // Inconsistent with tensors.len == 1
            .metadata_kv_count = 0,
        },
        .alignment = 32,
        .tensor_data_base = 32,
        .tensors = &tensors,
        .file_size = 128,
    };

    var b1 = limits.WorkBudget.init(1000);
    const res = structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &b1);
    try std.testing.expectError(error.CompatibilityViolation, res);
}

test "validator: high-level Validator API parses and validates valid GGUF" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little); // 0 tensors
    try writer.writeInt(u64, 0, .little); // 0 metadata

    // 32-byte alignment padding for zero-tensor valid GGUF
    const r = reader_mod.SliceReader.init(buffer[0..32]).reader();

    var val = safegguf.Validator.init(std.testing.allocator, limits.Limits{}, .gguf_spec);
    var res = try val.validateOwned(r);
    defer res.deinit();

    try std.testing.expectEqual(@as(u64, 0), res.doc.header.tensor_count);
    try std.testing.expectEqual(@as(u64, 0), res.doc.tensors.len);
    try std.testing.expect(!val.isQuotaExceeded());
}

test "validator: high-level Validator API enforces memory quota" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 1, .little);
    try writer.writeInt(u64, 0, .little);

    const name = "tensor_alloc";
    try writer.writeInt(u64, name.len, .little);
    try writer.writeAll(name);
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u64, 4, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u64, 0, .little);

    const r = reader_mod.SliceReader.init(buffer[0..64]).reader();

    // Very low allocation quota (e.g. 5 bytes) that cannot hold tensor allocations
    const tight_limits = limits.Limits{ .max_total_alloc_bytes = 5 };
    var val = safegguf.Validator.init(std.testing.allocator, tight_limits, .gguf_spec);
    const res = val.validate(r);
    try std.testing.expectError(error.OutOfMemory, res);
    try std.testing.expect(val.isQuotaExceeded());
}

test "quota_allocator: allocation, resize, free, and quota limit" {
    var quota_alloc = limits.QuotaAllocator.init(std.testing.allocator, 100);
    const alloc = quota_alloc.allocator();

    // 1. Allocate 40 bytes -> OK
    const slice1 = try alloc.alloc(u8, 40);
    try std.testing.expectEqual(@as(u64, 40), quota_alloc.allocated_bytes);

    // 2. Allocate another 50 bytes -> OK (total 90)
    const slice2 = try alloc.alloc(u8, 50);
    try std.testing.expectEqual(@as(u64, 90), quota_alloc.allocated_bytes);

    // 3. Allocate 20 bytes -> exceeds 100 byte quota!
    const fail_alloc = alloc.alloc(u8, 20);
    try std.testing.expectError(error.OutOfMemory, fail_alloc);
    try std.testing.expect(quota_alloc.isQuotaExceeded());

    // 4. Free slice1 -> allocated_bytes decreases to 50
    alloc.free(slice1);
    try std.testing.expectEqual(@as(u64, 50), quota_alloc.allocated_bytes);

    // 5. Free slice2 -> allocated_bytes decreases to 0
    alloc.free(slice2);
    try std.testing.expectEqual(@as(u64, 0), quota_alloc.allocated_bytes);
}

/// Parent allocator that passes alloc/free through but always refuses
/// in-place resizes, simulating a parent that cannot grow a buffer.
const ParentNoResize = struct {
    /// Dual-toolchain shim, mirroring src/gguf/limits.zig: Zig 0.13 vtable
    /// alignment is `u8`, Zig 0.14+ uses `std.mem.Alignment` and requires a
    /// `remap` entry. The mock still refuses every in-place resize.
    const VtableAlignment = if (@hasDecl(std.mem, "Alignment")) std.mem.Alignment else u8;

    backing: std.mem.Allocator,

    fn allocator(self: *ParentNoResize) std.mem.Allocator {
        const vtable: *const std.mem.Allocator.VTable = if (comptime @hasField(std.mem.Allocator.VTable, "remap"))
            &.{ .alloc = rawAlloc, .resize = rawResize, .free = rawFree, .remap = rawNoRemap }
        else
            &.{ .alloc = rawAlloc, .resize = rawResize, .free = rawFree };
        return .{ .ptr = self, .vtable = vtable };
    }

    fn rawNoRemap(ctx: *anyopaque, buf: []u8, buf_align: VtableAlignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    fn rawAlloc(ctx: *anyopaque, len: usize, ptr_align: VtableAlignment, ret_addr: usize) ?[*]u8 {
        const self: *ParentNoResize = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, ptr_align, ret_addr);
    }

    fn rawResize(ctx: *anyopaque, buf: []u8, buf_align: VtableAlignment, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return false;
    }

    fn rawFree(ctx: *anyopaque, buf: []u8, buf_align: VtableAlignment, ret_addr: usize) void {
        const self: *ParentNoResize = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(buf, buf_align, ret_addr);
    }
};

test "quota_allocator: resize grow updates accounting and peak" {
    // page_allocator maps a full page for the 40-byte request, so the
    // 40 -> 80 in-place resize reliably succeeds.
    var quota = limits.QuotaAllocator.init(std.heap.page_allocator, 1024);
    const alloc = quota.allocator();

    const slice = try alloc.alloc(u8, 40);
    try std.testing.expectEqual(@as(u64, 40), quota.allocated_bytes);

    try std.testing.expect(alloc.resize(slice, 80));
    try std.testing.expectEqual(@as(u64, 80), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);

    alloc.free(slice.ptr[0..80]);
    try std.testing.expectEqual(@as(u64, 0), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);
}

test "quota_allocator: resize beyond quota fails and preserves accounting" {
    var quota = limits.QuotaAllocator.init(std.heap.page_allocator, 100);
    const alloc = quota.allocator();

    const slice = try alloc.alloc(u8, 80);
    try std.testing.expectEqual(@as(u64, 80), quota.allocated_bytes);

    // 80 -> 120 exceeds the 100-byte quota: refused before touching the
    // parent, accounting stays at 80 and the sticky flag is set.
    try std.testing.expect(!alloc.resize(slice, 120));
    try std.testing.expect(quota.isQuotaExceeded());
    try std.testing.expectEqual(@as(u64, 80), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);

    // Shrink still succeeds after the flag; peak history is preserved.
    try std.testing.expect(alloc.resize(slice, 20));
    try std.testing.expectEqual(@as(u64, 20), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);

    alloc.free(slice.ptr[0..20]);
    try std.testing.expectEqual(@as(u64, 0), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);
}

test "quota_allocator: resize shrink keeps accounting and peak" {
    var quota = limits.QuotaAllocator.init(std.heap.page_allocator, 256);
    const alloc = quota.allocator();

    const slice = try alloc.alloc(u8, 80);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);

    try std.testing.expect(alloc.resize(slice, 20));
    try std.testing.expectEqual(@as(u64, 20), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);

    alloc.free(slice.ptr[0..20]);
    try std.testing.expectEqual(@as(u64, 0), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 80), quota.peak_bytes);
}

test "quota_allocator: parent resize failure keeps accounting and quota flag clean" {
    var parent = ParentNoResize{ .backing = std.testing.allocator };
    var quota = limits.QuotaAllocator.init(parent.allocator(), 1024);
    const alloc = quota.allocator();

    const slice = try alloc.alloc(u8, 30);
    try std.testing.expectEqual(@as(u64, 30), quota.allocated_bytes);

    // Parent cannot resize in place: growth is refused without quota drift
    // and without marking the quota as exceeded.
    try std.testing.expect(!alloc.resize(slice, 60));
    try std.testing.expectEqual(@as(u64, 30), quota.allocated_bytes);
    try std.testing.expectEqual(@as(u64, 30), quota.peak_bytes);
    try std.testing.expect(!quota.isQuotaExceeded());

    // Shrink is a resize too: a parent refusal must not change accounting.
    try std.testing.expect(!alloc.resize(slice, 10));
    try std.testing.expectEqual(@as(u64, 30), quota.allocated_bytes);
    try std.testing.expect(!quota.isQuotaExceeded());

    alloc.free(slice);
    try std.testing.expectEqual(@as(u64, 0), quota.allocated_bytes);
}

test "quota_allocator: deterministic stress keeps accounting invariants" {
    var quota = limits.QuotaAllocator.init(std.testing.allocator, 4096);
    const alloc = quota.allocator();

    var live: [32]?[]u8 = [_]?[]u8{null} ** 32;
    var shadow_total: u64 = 0;
    var max_shadow: u64 = 0;
    var state: u64 = 0x123456789ABCDEF0;

    var iteration: usize = 0;
    while (iteration < 1024) : (iteration += 1) {
        // Every 128th iteration: guaranteed over-quota alloc attempt.
        if (iteration % 128 == 127) {
            const fail_alloc = alloc.alloc(u8, 4097);
            try std.testing.expectError(error.OutOfMemory, fail_alloc);
            try std.testing.expect(quota.isQuotaExceeded());
            try std.testing.expectEqual(shadow_total, quota.allocated_bytes);
            continue;
        }

        state = state *% 6364136223846793005 +% 1442695040888963407;
        const op = state % 3;
        const slot: usize = @intCast((state >> 2) % live.len);

        switch (op) {
            0 => { // alloc
                if (live[slot] == null) {
                    const len: usize = @intCast(1 + (state >> 12) % 200);
                    if (alloc.alloc(u8, len)) |mem| {
                        live[slot] = mem;
                        shadow_total += len;
                    } else |_| {
                        // Quota (or host) refusal must leave accounting untouched.
                    }
                }
            },
            1 => { // resize
                if (live[slot]) |mem| {
                    const grow: usize = @intCast((state >> 12) % 240);
                    const new_len = if ((state >> 34) & 1 == 0)
                        mem.len + grow
                    else
                        (mem.len -| grow) + 1;
                    if (alloc.resize(mem, new_len)) {
                        live[slot] = mem.ptr[0..new_len];
                        if (new_len > mem.len) {
                            shadow_total += new_len - mem.len;
                        } else {
                            shadow_total -= mem.len - new_len;
                        }
                    }
                }
            },
            else => { // free
                if (live[slot]) |mem| {
                    alloc.free(mem);
                    live[slot] = null;
                    shadow_total -= mem.len;
                }
            },
        }

        // Invariants after every operation: accounting matches the independent
        // shadow sum, quota ceiling holds, peak is the running maximum.
        try std.testing.expectEqual(shadow_total, quota.allocated_bytes);
        try std.testing.expect(quota.allocated_bytes <= quota.max_bytes);
        try std.testing.expect(quota.peak_bytes >= quota.allocated_bytes);
        if (shadow_total > max_shadow) max_shadow = shadow_total;
        try std.testing.expectEqual(max_shadow, quota.peak_bytes);
    }

    // Drain: everything freed, accounting returns to zero, peak history kept.
    for (&live) |*entry| {
        if (entry.*) |mem| {
            alloc.free(mem);
            shadow_total -= mem.len;
            entry.* = null;
        }
    }
    try std.testing.expectEqual(@as(u64, 0), shadow_total);
    try std.testing.expectEqual(@as(u64, 0), quota.allocated_bytes);
    try std.testing.expect(quota.peak_bytes > 0);
}

test "buffered_reader: sliding window across 64 KiB boundary" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const file = try tmp_dir.dir.createFile("window_test.bin", .{ .read = true });
    defer file.close();

    const total_size: usize = 128 * 1024;
    var writer = file.writer();
    var byte_val: u8 = 0;
    var idx: usize = 0;
    while (idx < total_size) : (idx += 1) {
        try writer.writeByte(byte_val);
        byte_val +%= 1;
    }

    var buf_reader = reader_mod.BufferedReader.init(file, total_size);
    const r = buf_reader.reader();

    // Read bytes that straddle the 64 KiB (65536) window boundary
    var read_buf: [16]u8 = undefined;
    try r.readBytes(65530, &read_buf);

    for (read_buf, 0..) |b, i| {
        const expected = @as(u8, @truncate(65530 + i));
        try std.testing.expectEqual(expected, b);
    }
}

test "validator: reuse Validator across multiple files resets per-run work budget and quota flag" {
    var buffer: [256]u8 = [_]u8{0} ** 256;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("GGUF");
    try writer.writeInt(u32, 3, .little);
    try writer.writeInt(u64, 0, .little); // 0 tensors
    try writer.writeInt(u64, 0, .little); // 0 metadata

    // Set a moderate work budget limit (e.g. 50 units)
    const lim = limits.Limits{ .max_work_units = 50 };
    var val = safegguf.Validator.init(std.testing.allocator, lim, .gguf_spec);

    // Perform 10 consecutive validations on the same Validator instance.
    // If work budget was cumulative, 10 runs would accumulate units and exceed 50 units!
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const r = reader_mod.SliceReader.init(buffer[0..32]).reader();
        var res = try val.validateOwned(r);
        defer res.deinit();

        try std.testing.expectEqual(@as(u64, 0), res.doc.header.tensor_count);
        // Ensure per-run units were reset to 0 at the start of each validateOwned()
        try std.testing.expect(val.work_budget.consumed_units < 50);
        try std.testing.expect(!val.isQuotaExceeded());
    }
}

test "structural: low-level API validateStructural charges WorkBudget for dimension pre-pass" {
    const dims = [_]u64{10};
    const tensors = [_]parser.TensorInfo{
        .{ .name = "t0", .dimensions = &dims, .tensor_type = 0, .offset = 0 },
        .{ .name = "t1", .dimensions = &dims, .tensor_type = 0, .offset = 32 },
        .{ .name = "t2", .dimensions = &dims, .tensor_type = 0, .offset = 64 },
        .{ .name = "t3", .dimensions = &dims, .tensor_type = 0, .offset = 96 },
        .{ .name = "t4", .dimensions = &dims, .tensor_type = 0, .offset = 128 },
        .{ .name = "t5", .dimensions = &dims, .tensor_type = 0, .offset = 160 },
        .{ .name = "t6", .dimensions = &dims, .tensor_type = 0, .offset = 192 },
        .{ .name = "t7", .dimensions = &dims, .tensor_type = 0, .offset = 224 },
    };

    const doc = parser.Document{
        .header = .{
            .version = 3,
            .tensor_count = 8,
            .metadata_kv_count = 0,
        },
        .alignment = 32,
        .tensor_data_base = 32,
        .tensors = &tensors,
        .file_size = 512,
    };

    // Work budget only allows 3 units, but there are 8 tensors in dimension pre-pass
    var tight_budget = limits.WorkBudget.init(3);
    const res = structural.validateStructural(std.testing.allocator, doc, .gguf_spec, &tight_budget);
    try std.testing.expectError(error.ResourceLimitExceeded, res);
}

// ---------------------------------------------------------------------------
// 8. Variable-Array Sanity Cap Boundaries (F-01)
// ---------------------------------------------------------------------------

/// Builds a minimal metadata-only GGUF v3 document whose single entry is
/// `tokenizer.ggml.tokens: array[string]` with `token_count` payload entries of
/// `token_len` ASCII bytes each (0 = zero-length token). Alignment padding is
/// zero-filled so the document is structurally valid in both profiles.
/// Caller frees the returned bytes.
fn buildTokenizerTokensDoc(
    allocator: std.mem.Allocator,
    token_count: u64,
    token_len: usize,
) ![]u8 {
    const key = "tokenizer.ggml.tokens";
    const fixed_len: usize = 4 + 4 + 8 + 8 + (8 + key.len + 4) + (4 + 8);
    const raw_len = fixed_len + @as(usize, @intCast(token_count)) * (8 + token_len);
    const padded_len = (raw_len + 31) & ~@as(usize, 31);

    const buf = try allocator.alloc(u8, padded_len);
    errdefer allocator.free(buf);
    @memset(buf, 0);

    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeAll("GGUF");
    try w.writeInt(u32, 3, .little);
    try w.writeInt(u64, 0, .little); // tensor_count
    try w.writeInt(u64, 1, .little); // metadata_kv_count

    try w.writeInt(u64, key.len, .little);
    try w.writeAll(key);
    try w.writeInt(u32, 9, .little); // MetadataType.array
    try w.writeInt(u32, 8, .little); // MetadataType.string
    try w.writeInt(u64, token_count, .little);

    var i: u64 = 0;
    while (i < token_count) : (i += 1) {
        try w.writeInt(u64, token_len, .little);
        if (token_len > 0) try w.writeByteNTimes('a', token_len);
    }

    return buf;
}

/// Declares `token_count` elements without materializing any element payload:
/// the parser must reject on the count cap before scanning a single element.
fn buildDeclaredTokenizerTokensDoc(allocator: std.mem.Allocator, token_count: u64) ![]u8 {
    const key = "tokenizer.ggml.tokens";
    // Fixed header ends at 69 bytes; 96 keeps the required 32-byte padding.
    const buf = try allocator.alloc(u8, 96);
    errdefer allocator.free(buf);
    @memset(buf, 0);

    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();

    try w.writeAll("GGUF");
    try w.writeInt(u32, 3, .little);
    try w.writeInt(u64, 0, .little); // tensor_count
    try w.writeInt(u64, 1, .little); // metadata_kv_count

    try w.writeInt(u64, key.len, .little);
    try w.writeAll(key);
    try w.writeInt(u32, 9, .little); // MetadataType.array
    try w.writeInt(u32, 8, .little); // MetadataType.string
    try w.writeInt(u64, token_count, .little);

    return buf;
}

test "limits: tokenizer-scale string arrays pass the default variable-array cap" {
    // Qwen2 declares 151,936 tokens and Llama 3 ~128,256; the former default
    // cap of 100,000 false-rejected both. All of these must parse and validate.
    const counts = [_]u64{ 99_999, 100_000, 100_001, 128_256, 151_936, 250_000 };
    const policy = limits.Limits{};

    for (counts) |count| {
        const bytes = try buildTokenizerTokensDoc(std.testing.allocator, count, 0);
        defer std.testing.allocator.free(bytes);

        for ([_]types.Profile{ .gguf_spec, .llama_cpp }) |profile| {
            var parse_budget = limits.WorkBudget.initWithLimits(policy.max_work_units, policy.max_scanned_bytes);
            const r = reader_mod.SliceReader.init(bytes).reader();
            var doc = try parser.parseDocument(std.testing.allocator, r, .little, policy, profile, &parse_budget);
            defer doc.deinit(std.testing.allocator);

            var structural_budget = limits.WorkBudget.initWithLimits(policy.max_work_units, policy.max_scanned_bytes);
            try structural.validateStructural(std.testing.allocator, doc, profile, &structural_budget);
        }
    }
}

test "limits: string array one past the default sanity cap is rejected" {
    const policy = limits.Limits{};
    const count = policy.max_variable_array_elements + 1;
    const bytes = try buildDeclaredTokenizerTokensDoc(std.testing.allocator, count);
    defer std.testing.allocator.free(bytes);

    var budget = limits.WorkBudget.initWithLimits(policy.max_work_units, policy.max_scanned_bytes);
    const r = reader_mod.SliceReader.init(bytes).reader();
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        parser.parseDocument(std.testing.allocator, r, .little, policy, .gguf_spec, &budget),
    );
}

test "limits: work budget still bounds variable arrays within the sanity cap" {
    const bytes = try buildTokenizerTokensDoc(std.testing.allocator, 2_000, 0);
    defer std.testing.allocator.free(bytes);

    // Count is within the raised semantic cap, but the traversal cost must
    // still be charged against max_work_units before scanning elements.
    const policy = limits.Limits{};
    var budget = limits.WorkBudget.initWithLimits(1_000, policy.max_scanned_bytes);
    const r = reader_mod.SliceReader.init(bytes).reader();
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        parser.parseDocument(std.testing.allocator, r, .little, policy, .gguf_spec, &budget),
    );
}

test "limits: scanned-byte budget still bounds string payloads within the sanity cap" {
    // 1,000 one-byte tokens = 1,000 payload bytes scanned; a 100-byte scan
    // budget must reject mid-traversal regardless of the raised count cap.
    const bytes = try buildTokenizerTokensDoc(std.testing.allocator, 1_000, 1);
    defer std.testing.allocator.free(bytes);

    const policy = limits.Limits{};
    var budget = limits.WorkBudget.initWithLimits(policy.max_work_units, 100);
    const r = reader_mod.SliceReader.init(bytes).reader();
    try std.testing.expectError(
        error.ResourceLimitExceeded,
        parser.parseDocument(std.testing.allocator, r, .little, policy, .gguf_spec, &budget),
    );
}
