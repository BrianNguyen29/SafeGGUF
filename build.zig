const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const safegguf_mod = b.addModule("safegguf", .{
        .root_source_file = b.path("src/root.zig"),
    });

    const exe = b.addExecutable(.{
        .name = "safegguf",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("safegguf", safegguf_mod);
    b.installArtifact(exe);

    const tests = b.addTest(.{
        .root_source_file = b.path("tests/validator_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.root_module.addImport("safegguf", safegguf_mod);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    const fuzz_tests = b.addTest(.{
        .root_source_file = b.path("tests/fuzz_target.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_tests.root_module.addImport("safegguf", safegguf_mod);

    const run_fuzz = b.addRunArtifact(fuzz_tests);
    test_step.dependOn(&run_fuzz.step);

    const fuzz_step = b.step("fuzz", "Run corpus through fuzz harness");
    fuzz_step.dependOn(&run_fuzz.step);
}
