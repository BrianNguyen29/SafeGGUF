const std = @import("std");
const safegguf = @import("safegguf");

const parser = safegguf.parser;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;
const structural = safegguf.structural;

fn testOneProfileEndian(
    bytes: []const u8,
    profile: safegguf.types.Profile,
    endian: std.builtin.Endian,
    fuzzer_limits: limits.Limits,
    parent_alloc: std.mem.Allocator,
) void {
    const slice_reader = reader_mod.SliceReader.init(bytes);
    const r = slice_reader.reader();

    var val = safegguf.Validator.init(parent_alloc, fuzzer_limits, profile);
    val.endian = endian;

    var doc = val.validate(r) catch return;
    defer val.deinitDocument(&doc);
}

/// Fuzzer limits kept tight enough for in-process coverage fuzzing (4 MB
/// quota, bounded work) while still exercising parser/validator paths.
const fuzz_limits = limits.Limits{
    .max_tensors = 1000,
    .max_metadata_entries = 1000,
    .max_string_bytes = 1024,
    .max_tensor_name_bytes = 64,
    .max_dimensions = 4,
    .max_array_elements = 10_000,
    .max_variable_array_elements = 1000,
    .max_metadata_depth = 16,
    .max_total_alloc_bytes = 4 * 1024 * 1024, // 4 MB quota for fuzzer
    .max_work_units = 100_000,
};

/// Single profile x endian entry point for the coverage-guided lane (A5),
/// where each fuzz target fuzzes exactly one combination.
pub fn fuzzOne(bytes: []const u8, profile: safegguf.types.Profile, endian: std.builtin.Endian) void {
    if (bytes.len < 12) return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const check = gpa.deinit();
        if (check == .leak) {
            @panic("Memory leak detected in fuzz target");
        }
    }

    testOneProfileEndian(bytes, profile, endian, fuzz_limits, gpa.allocator());
}

pub fn fuzzBuffer(bytes: []const u8) void {
    if (bytes.len < 12) return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const check = gpa.deinit();
        if (check == .leak) {
            @panic("Memory leak detected in fuzz target");
        }
    }

    const profiles = [_]safegguf.types.Profile{ .gguf_spec, .llama_cpp };
    const endians = [_]std.builtin.Endian{ .little, .big };

    for (profiles) |p| {
        for (endians) |e| {
            testOneProfileEndian(bytes, p, e, fuzz_limits, gpa.allocator());
        }
    }
}

/// libFuzzer / OSS-Fuzz standard C ABI entrypoint
pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: usize) callconv(.C) c_int {
    fuzzBuffer(data[0..size]);
    return 0;
}

test "fuzz: execute corpus through fuzzer harness" {
    var dir = try std.fs.cwd().openDir("tests/corpus", .{ .iterate = true });
    defer dir.close();

    var it = dir.iterate();
    var count: usize = 0;
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        const file = try dir.openFile(entry.name, .{});
        defer file.close();

        const stat = try file.stat();
        const buf = try std.testing.allocator.alloc(u8, stat.size);
        defer std.testing.allocator.free(buf);

        const read_bytes = try file.readAll(buf);
        fuzzBuffer(buf[0..read_bytes]);
        count += 1;
    }
    try std.testing.expect(count >= 15);
}
