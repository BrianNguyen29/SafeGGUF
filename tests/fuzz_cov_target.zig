//! Coverage-guided fuzz target for the A5 lane (Zig 0.14.1 only).
//!
//! `build.zig` compiles this root once per profile x endian combination as a
//! separate `fuzz-cov-*` step, so each `zig build --fuzz <step>` invocation
//! runs exactly one fuzz target (avoids concurrent writers to the shared
//! coverage file). In fuzz mode `std.testing.fuzz` feeds every input to
//! `fuzz_target.fuzzOne`; without `--fuzz` the same test runs the seed corpus
//! once as a smoke pass.
//!
//! Seeds: the generated seed corpus (`tests/corpus`, seeded by
//! `tests/generate_fixtures.py`) plus, when set, every file under the
//! persisted-corpus directory named by `SAFEGGUF_COV_FUZZ_SEEDS`. The loader
//! is bounded to the same caps as the persisted lane policy: 10,000 entries /
//! 256 MiB (see tests/fuzz/README.md).
const std = @import("std");
const safegguf = @import("safegguf");
const ft = @import("fuzz_target.zig");
const fuzz_options = @import("fuzz_options");

const profile: safegguf.types.Profile = if (std.mem.eql(u8, fuzz_options.profile, "gguf-spec"))
    .gguf_spec
else
    .llama_cpp;

const endian: std.builtin.Endian = if (std.mem.eql(u8, fuzz_options.endian, "little"))
    .little
else
    .big;

const max_seed_files: usize = 10_000;
const max_seed_bytes: usize = 256 * 1024 * 1024;

test "fuzz: gguf validator coverage target" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const corpus = try loadSeeds(arena_state.allocator());
    try std.testing.fuzz({}, testOne, .{ .corpus = corpus });
}

fn testOne(_: void, input: []const u8) anyerror!void {
    ft.fuzzOne(input, profile, endian);
}

/// Reads the seed corpus. `tests/corpus` is required (the lane runs after
/// `generate_fixtures.py`); `SAFEGGUF_COV_FUZZ_SEEDS` is optional so a fresh
/// local run works without a persisted corpus.
fn loadSeeds(allocator: std.mem.Allocator) ![]const []const u8 {
    var seeds: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer {
        for (seeds.items) |bytes| allocator.free(bytes);
        seeds.deinit(allocator);
    }

    var total_bytes: usize = 0;
    try appendSeedsFromDir(allocator, "tests/corpus", &seeds, &total_bytes, .required);

    if (std.process.getEnvVarOwned(allocator, "SAFEGGUF_COV_FUZZ_SEEDS")) |seed_dir| {
        try appendSeedsFromDir(allocator, seed_dir, &seeds, &total_bytes, .optional);
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return seeds.items;
}

fn appendSeedsFromDir(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    seeds: *std.ArrayListUnmanaged([]const u8),
    total_bytes: *usize,
    required: enum { required, optional },
) !void {
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            if (required == .required) return err;
            return;
        },
        else => return err,
    };
    defer dir.close();

    // Sort names so the fuzzer's deterministic RNG (seeded with 0) replays the
    // same mutation sequence for the same seed set.
    var names: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (seeds.items.len + names.items.len >= max_seed_files) break;
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    for (names.items) |name| {
        if (seeds.items.len >= max_seed_files) break;
        if (total_bytes.* >= max_seed_bytes) break;
        const file = dir.openFile(name, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer file.close();
        const bytes = try file.readToEndAlloc(allocator, max_seed_bytes - total_bytes.*);
        if (bytes.len == 0) {
            allocator.free(bytes);
            continue;
        }
        total_bytes.* += bytes.len;
        try seeds.append(allocator, bytes);
    }
}
