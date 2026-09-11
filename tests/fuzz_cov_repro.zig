//! Single-input replay harness for the A5 coverage lane (Zig 0.14+).
//!
//! `zig build fuzz-cov-repro` with
//!   SAFEGGUF_COV_FUZZ_REPRO=<file>   input to replay
//!   SAFEGGUF_COV_FUZZ_PROFILE=gguf-spec|llama-cpp
//!   SAFEGGUF_COV_FUZZ_ENDIAN=little|big
//! runs exactly one file through the same `fuzzOne` entry point the coverage
//! target uses, so a recovered crash candidate can be replayed and
//! prefix-minimized deterministically. Skips (exit 0) when unset.
const std = @import("std");
const safegguf = @import("safegguf");
const ft = @import("fuzz_target.zig");

fn envOrSkip(name: []const u8) ![]const u8 {
    return std.process.getEnvVarOwned(std.testing.allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
}

test "repro: run one input through the coverage fuzz harness" {
    const path = try envOrSkip("SAFEGGUF_COV_FUZZ_REPRO");
    defer std.testing.allocator.free(path);

    const profile_name = try envOrSkip("SAFEGGUF_COV_FUZZ_PROFILE");
    defer std.testing.allocator.free(profile_name);
    const profile: safegguf.types.Profile = if (std.mem.eql(u8, profile_name, "gguf-spec"))
        .gguf_spec
    else if (std.mem.eql(u8, profile_name, "llama-cpp"))
        .llama_cpp
    else
        return error.SkipZigTest;

    const endian_name = try envOrSkip("SAFEGGUF_COV_FUZZ_ENDIAN");
    defer std.testing.allocator.free(endian_name);
    const endian: std.builtin.Endian = if (std.mem.eql(u8, endian_name, "little"))
        .little
    else if (std.mem.eql(u8, endian_name, "big"))
        .big
    else
        return error.SkipZigTest;

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(arena_state.allocator(), 64 * 1024 * 1024);

    ft.fuzzOne(data, profile, endian);
}
