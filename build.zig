const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const safegguf_mod = b.addModule("safegguf", .{
        .root_source_file = b.path("src/root.zig"),
    });

    // Build provenance injected into the binary (surfaced by
    // `safegguf --version` via src/build_info.zig). Derived from the source
    // tree and toolchain only - deliberately no wall-clock timestamp, so the
    // same commit/toolchain/options produce identical build metadata.
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", b.option([]const u8, "version", "Version reported by `safegguf --version`") orelse "0.3.5");
    build_options.addOption([]const u8, "source_commit", sourceCommit(b));
    build_options.addOption([]const u8, "zig_version", @import("builtin").zig_version_string);
    build_options.addOption([]const u8, "build_mode", @tagName(optimize));
    build_options.addOption([]const u8, "target", targetString(b, target));

    const exe = b.addExecutable(.{
        .name = "safegguf",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("safegguf", safegguf_mod);
    exe.root_module.addOptions("build_options", build_options);
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

    // Benchmarks are pinned to ReleaseSafe: wall-time numbers are meaningless in
    // Debug, and ReleaseSafe preserves the shipped binary's checked-arithmetic
    // posture (mirrors the fuzz addTest/addRunArtifact pair above).
    const bench_tests = b.addTest(.{
        .root_source_file = b.path("tests/bench_scales.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    bench_tests.root_module.addImport("safegguf", safegguf_mod);

    const run_bench = b.addRunArtifact(bench_tests);
    const bench_step = b.step("bench", "Run resource-budget benchmark suite");
    bench_step.dependOn(&run_bench.step);

    // Coverage-guided fuzz lane (A5): `std.testing.fuzz` + `zig build --fuzz`
    // ship in Zig 0.14+. The pinned production toolchain remains 0.13.0; these
    // steps only exist when the build runner itself is 0.14+, so `zig build
    // test`/`fuzz`/`bench` on 0.13.0 are untouched. `tests/fuzz_cov_target.zig`
    // is compiled once per profile x endian so a single `zig build --fuzz
    // <step>` invocation drives exactly one target at a time.
    if (comptime builtin.zig_version.major == 0 and builtin.zig_version.minor >= 14) {
        const cov_targets = [_]struct {
            step: []const u8,
            profile: []const u8,
            endian: []const u8,
        }{
            .{ .step = "fuzz-cov-gguf-spec-little", .profile = "gguf-spec", .endian = "little" },
            .{ .step = "fuzz-cov-gguf-spec-big", .profile = "gguf-spec", .endian = "big" },
            .{ .step = "fuzz-cov-llama-cpp-little", .profile = "llama-cpp", .endian = "little" },
            .{ .step = "fuzz-cov-llama-cpp-big", .profile = "llama-cpp", .endian = "big" },
        };
        for (cov_targets) |t| {
            const cov_options = b.addOptions();
            cov_options.addOption([]const u8, "profile", t.profile);
            cov_options.addOption([]const u8, "endian", t.endian);

            const cov_tests = b.addTest(.{
                .root_source_file = b.path("tests/fuzz_cov_target.zig"),
                .target = target,
                .optimize = optimize,
            });
            cov_tests.root_module.addImport("safegguf", safegguf_mod);
            cov_tests.root_module.addOptions("fuzz_options", cov_options);

            const run_cov = b.addRunArtifact(cov_tests);
            const cov_step = b.step(t.step, "Run one coverage-guided fuzz target (Zig 0.14+; bounded by the caller)");
            cov_step.dependOn(&run_cov.step);
        }

        // Single-input replay for crash artifacts; reads SAFEGGUF_COV_FUZZ_*
        // from the environment (see tests/fuzz_cov_repro.zig).
        const repro_tests = b.addTest(.{
            .root_source_file = b.path("tests/fuzz_cov_repro.zig"),
            .target = target,
            .optimize = optimize,
        });
        repro_tests.root_module.addImport("safegguf", safegguf_mod);

        const run_repro = b.addRunArtifact(repro_tests);
        const repro_step = b.step("fuzz-cov-repro", "Replay one input through the coverage fuzz harness (zig 0.14+)");
        repro_step.dependOn(&run_repro.step);
    }
}

/// Full commit SHA of the checked-out source, or "unknown" when git metadata
/// is unavailable (e.g. building from an exported source tree).
fn sourceCommit(b: *std.Build) []const u8 {
    return gitLine(b, &.{ "git", "rev-parse", "HEAD" }) orelse "unknown";
}

/// Zig-style arch/OS target label (e.g. "x86_64-linux") matching the names
/// used for release artifacts; ABI is intentionally omitted.
fn targetString(b: *std.Build, target: std.Build.ResolvedTarget) []const u8 {
    return std.fmt.allocPrint(b.allocator, "{s}-{s}", .{
        @tagName(target.result.cpu.arch),
        @tagName(target.result.os.tag),
    }) catch unreachable;
}

/// Runs a git command at configure time and returns its trimmed stdout, or
/// null on any failure (missing git, not a repository, non-zero exit).
fn gitLine(b: *std.Build, argv: []const []const u8) ?[]const u8 {
    const result = std.process.Child.run(.{
        .allocator = b.allocator,
        .argv = argv,
        .cwd = b.build_root.path,
        .max_output_bytes = 64 * 1024,
    }) catch return null;
    switch (result.term) {
        .Exited => |code| if (code != 0) return null,
        else => return null,
    }
    return std.mem.trim(u8, result.stdout, " \r\n\t");
}
