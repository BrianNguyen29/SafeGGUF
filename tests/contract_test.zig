// C-ABI / CLI contract tests for the canonical public error-code namespace and
// the JSON schema version. These assert the invariants the deep-review plan
// requires: every emitted error_code maps into `SGGUF_E_*`, the namespace in
// include/safegguf.h matches the Zig mapping, and CLI JSON output is versioned.
const std = @import("std");
const safegguf = @import("safegguf");
const err = safegguf.error_types;

// The C ABI surface under test (src/c_api.zig exported functions).
const cabi = @import("cabi");

const parse_error_variants = @typeInfo(err.ParseError).ErrorSet.?;

fn expectCanonicalFormat(code: []const u8) !void {
    try std.testing.expect(std.mem.startsWith(u8, code, "SGGUF_E_"));
    try std.testing.expect(code.len > "SGGUF_E_".len);
    for (code) |ch| {
        if (!std.ascii.isUpper(ch) and !std.ascii.isDigit(ch) and ch != '_') {
            std.debug.print("malformed canonical code: {s}\n", .{code});
            return error.MalformedCanonicalCode;
        }
    }
}

test "canonical: every ParseError variant maps to a unique, well-formed SGGUF_E_* code" {
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer seen.deinit();

    inline for (parse_error_variants) |variant| {
        const e: err.ParseError = @field(err.ParseError, variant.name);
        const code = err.publicCodeOf(e);
        try expectCanonicalFormat(code);
        const gop = try seen.getOrPut(code);
        if (gop.found_existing) {
            std.debug.print("duplicate canonical code for {s}: {s}\n", .{ variant.name, code });
            return error.DuplicateCanonicalCode;
        }
    }
    try std.testing.expectEqual(parse_error_variants.len, seen.count());
}

test "canonical: legacy CLI codes and bare C-ABI names map into the namespace" {
    var buf: [64]u8 = undefined;

    inline for (parse_error_variants) |variant| {
        const e: err.ParseError = @field(err.ParseError, variant.name);
        const canonical = err.publicCodeOf(e);
        // CLI JSON emits "E_<ZigName>"; the C ABI emits the bare Zig name.
        const cli_code = try std.fmt.bufPrint(&buf, "E_{s}", .{variant.name});
        try std.testing.expectEqualStrings(canonical, err.canonicalFromLegacy(cli_code).?);
        try std.testing.expectEqualStrings(canonical, err.canonicalFromLegacy(variant.name).?);
        try std.testing.expect(err.isPublicCode(canonical));
    }

    for (err.legacy_public_codes) |entry| {
        try std.testing.expectEqualStrings(entry.canonical, err.canonicalFromLegacy(entry.legacy).?);
        try std.testing.expect(err.isPublicCode(entry.canonical));
    }

    try std.testing.expect(err.isPublicCode(err.public_codes.unknown));
    try std.testing.expect(!err.isPublicCode("E_ArithmeticOverflow"));
    try std.testing.expect(err.canonicalFromLegacy("UnknownWidget") == null);
}

/// Scans a source file for emitted `"E_...` string literals and asserts each
/// one maps into the canonical namespace. Format placeholders ("E_{s}") are
/// skipped; the dynamic rejection path is covered by the variant round-trip
/// test above.
fn expectAllLiteralCodesMap(source: []const u8, source_name: []const u8) !void {
    var search: usize = 0;
    var found: usize = 0;
    while (std.mem.indexOfPos(u8, source, search, "\"E_")) |idx| {
        const value_start = idx + 1;
        const value_end = std.mem.indexOfScalarPos(u8, source, value_start, '"') orelse
            return error.UnterminatedLiteral;
        const code = source[value_start..value_end];
        search = value_end + 1;
        if (std.mem.indexOfAny(u8, code, "{}") != null) continue; // format placeholder
        found += 1;
        if (err.canonicalFromLegacy(code) == null) {
            std.debug.print("{s}: emitted code {s} has no canonical mapping\n", .{ source_name, code });
            return error.UnmappedEmittedCode;
        }
    }
    try std.testing.expect(found > 0);
}

test "contract: every emitted error_code literal maps into the canonical namespace" {
    const allocator = std.testing.allocator;
    const main_src = try std.fs.cwd().readFileAlloc(allocator, "src/main.zig", 1 << 20);
    defer allocator.free(main_src);
    try expectAllLiteralCodesMap(main_src, "src/main.zig");

    const c_api_src = try std.fs.cwd().readFileAlloc(allocator, "src/c_api.zig", 1 << 20);
    defer allocator.free(c_api_src);
    try expectAllLiteralCodesMap(c_api_src, "src/c_api.zig");
}

test "contract: every CLI JSON template carries schema_version" {
    const allocator = std.testing.allocator;
    const main_src = try std.fs.cwd().readFileAlloc(allocator, "src/main.zig", 1 << 20);
    defer allocator.free(main_src);

    const status_count = std.mem.count(u8, main_src, "\"status\":\"");
    const schema_count = std.mem.count(u8, main_src, "\"schema_version\":");
    try std.testing.expect(status_count > 0);
    try std.testing.expectEqual(status_count, schema_count);
}

fn expectMacroDefined(header: []const u8, code: []const u8) !void {
    var buf: [160]u8 = undefined;
    const define = try std.fmt.bufPrint(&buf, "#define {s}", .{code});
    const idx = std.mem.indexOf(u8, header, define) orelse {
        std.debug.print("include/safegguf.h is missing: {s}\n", .{define});
        return error.MissingCanonicalMacro;
    };
    // The macro value must be the canonical code string, on the same line
    // (alignment spaces between name and value are allowed).
    var value_buf: [160]u8 = undefined;
    const value = try std.fmt.bufPrint(&value_buf, "\"{s}\"", .{code});
    const line_end = std.mem.indexOfScalarPos(u8, header, idx, '\n') orelse header.len;
    if (std.mem.indexOf(u8, header[idx..line_end], value) == null) {
        std.debug.print("include/safegguf.h defines {s} with a non-canonical value\n", .{code});
        return error.WrongCanonicalMacroValue;
    }
}

test "contract: include/safegguf.h canonical namespace matches the Zig mapping" {
    const allocator = std.testing.allocator;
    const header = try std.fs.cwd().readFileAlloc(allocator, "include/safegguf.h", 1 << 20);
    defer allocator.free(header);

    // Every canonical code known to Zig is exported as a macro valued at the
    // code string.
    inline for (parse_error_variants) |variant| {
        const e: err.ParseError = @field(err.ParseError, variant.name);
        try expectMacroDefined(header, err.publicCodeOf(e));
    }
    for (err.legacy_public_codes) |entry| try expectMacroDefined(header, entry.canonical);
    try expectMacroDefined(header, err.public_codes.dimension_overflow);
    try expectMacroDefined(header, err.public_codes.unknown);

    // No SGGUF_E_* macro exists that the Zig mapping does not know about.
    var search: usize = 0;
    var macro_count: usize = 0;
    while (std.mem.indexOfPos(u8, header, search, "#define SGGUF_E_")) |idx| {
        const name_start = idx + "#define ".len;
        const name_end = std.mem.indexOfScalarPos(u8, header, name_start, ' ') orelse
            return error.MalformedMacro;
        const name = header[name_start..name_end];
        search = name_end;
        macro_count += 1;
        if (!err.isPublicCode(name)) {
            std.debug.print("header macro {s} is not in the Zig canonical namespace\n", .{name});
            return error.UnknownCanonicalMacro;
        }
    }
    try std.testing.expect(macro_count > 0);

    // The schema-version macro tracks the version the CLI embeds.
    var version_buf: [64]u8 = undefined;
    const version_macro = try std.fmt.bufPrint(&version_buf, "#define SAFEGGUF_SCHEMA_VERSION {d}", .{safegguf.json_schema_version});
    try std.testing.expect(std.mem.indexOf(u8, header, version_macro) != null);
}

fn resultCode(res: *const cabi.Result) []const u8 {
    return std.mem.sliceTo(&res.error_code, 0);
}

fn resultCanonical(res: *const cabi.Result) []const u8 {
    const ptr: [*:0]const u8 = @ptrCast(&res.error_code);
    return std.mem.span(cabi.safegguf_canonical_error_code(ptr));
}

test "ffi: C ABI codes map to canonical codes through the exported surface" {
    var res: cabi.Result = undefined;

    // NULL path -> usage error.
    try std.testing.expectEqual(@as(c_int, 64), cabi.safegguf_validate_path_v1(null, null, &res));
    try std.testing.expectEqualStrings("E_USAGE_NULL_PATH", resultCode(&res));
    try std.testing.expectEqualStrings(err.public_codes.usage_null_path, resultCanonical(&res));

    // Missing file -> open failure.
    try std.testing.expectEqual(
        @as(c_int, 74),
        cabi.safegguf_validate_path_v1("/nonexistent/safegguf-contract-test.gguf", null, &res),
    );
    try std.testing.expectEqualStrings("E_FILE_OPEN_FAILED", resultCode(&res));
    try std.testing.expectEqualStrings(err.public_codes.file_open_failed, resultCanonical(&res));

    // Invalid struct_size -> fail-closed usage error.
    var opts = cabi.OptionsV1{
        .struct_size = 1234,
        .profile = 0,
        .endian = 0,
        .max_alloc_bytes = 0,
        .max_work_units = 0,
        .max_scanned_bytes = 0,
        .reserved = null,
        .max_file_size_bytes = 0,
        .require_stable_file = 0,
        .max_string_bytes = 0,
        .key_policy = 0,
    };
    try std.testing.expectEqual(@as(c_int, 64), cabi.safegguf_validate_path_v1("ignored", &opts, &res));
    try std.testing.expectEqualStrings("E_USAGE_INVALID_OPTIONS", resultCode(&res));
    try std.testing.expectEqualStrings(err.public_codes.usage_invalid_options, resultCanonical(&res));

    // Invalid descriptor -> platform-specific io code, always canonical.
    try std.testing.expectEqual(@as(c_int, 74), cabi.safegguf_validate_fd_v1(-1, null, &res));
    try std.testing.expect(err.isPublicCode(resultCanonical(&res)));

    // Direct mapping surface: bare C-ABI name, compatibility code, unknown.
    try std.testing.expectEqualStrings(
        "SGGUF_E_ARITHMETIC_OVERFLOW",
        std.mem.span(cabi.safegguf_canonical_error_code("ArithmeticOverflow")),
    );
    try std.testing.expectEqualStrings(
        "SGGUF_E_ARITHMETIC_OVERFLOW",
        std.mem.span(cabi.safegguf_canonical_error_code("E_ArithmeticOverflow")),
    );
    try std.testing.expectEqualStrings(
        "SGGUF_E_FILE_TOO_LARGE",
        std.mem.span(cabi.safegguf_canonical_error_code("E_FileTooLarge")),
    );
    try std.testing.expectEqualStrings(
        "SGGUF_E_ARITHMETIC_OVERFLOW",
        std.mem.span(cabi.safegguf_canonical_error_code("SGGUF_E_ARITHMETIC_OVERFLOW")),
    );
    try std.testing.expectEqualStrings(err.public_codes.unknown, std.mem.span(cabi.safegguf_canonical_error_code("Bogus")));
    try std.testing.expectEqualStrings(err.public_codes.unknown, std.mem.span(cabi.safegguf_canonical_error_code(null)));
}

fn setResultField(dest: []u8, value: []const u8) void {
    @memset(dest, 0);
    @memcpy(dest[0..value.len], value);
}

test "ffi: canonical code pointers outlive the caller's mutable buffer" {
    var caller_buffer: [64:0]u8 = [_:0]u8{0} ** 64;
    const code = "SGGUF_E_ARITHMETIC_OVERFLOW";
    @memcpy(caller_buffer[0..code.len], code);
    const result = cabi.safegguf_canonical_error_code(&caller_buffer);
    try std.testing.expect(@intFromPtr(result) != @intFromPtr(&caller_buffer));
    @memset(caller_buffer[0..], 'X');
    try std.testing.expectEqualStrings(code, std.mem.span(result));
}

test "ffi: result accessor resolves the context-dependent dimension-overflow detail" {
    var res: cabi.Result = undefined;
    @memset(std.mem.asBytes(&res), 0);
    res.exit_code = 2;
    setResultField(&res.error_code, "CompatibilityViolation");
    setResultField(&res.category, "compatibility");
    setResultField(&res.stage, "validation");
    setResultField(&res.message, err.dimension_overflow_message);

    // Legacy error_code stays "CompatibilityViolation"; the accessor resolves
    // the additive SGGUF_E_DIMENSION_OVERFLOW detail.
    try std.testing.expectEqualStrings(
        err.public_codes.dimension_overflow,
        std.mem.span(cabi.safegguf_result_canonical_error_code(&res)),
    );

    // A generic compatibility rejection keeps the generic canonical code.
    setResultField(&res.message, "File violates upstream ggml compatibility invariants");
    try std.testing.expectEqualStrings(
        "SGGUF_E_COMPATIBILITY_VIOLATION",
        std.mem.span(cabi.safegguf_result_canonical_error_code(&res)),
    );

    // Legacy/bare identifier mapping and NULL handling.
    setResultField(&res.error_code, "ArithmeticOverflow");
    try std.testing.expectEqualStrings(
        "SGGUF_E_ARITHMETIC_OVERFLOW",
        std.mem.span(cabi.safegguf_result_canonical_error_code(&res)),
    );
    try std.testing.expectEqualStrings(
        err.public_codes.unknown,
        std.mem.span(cabi.safegguf_result_canonical_error_code(null)),
    );
}

test "ffi: closed descriptor returns an io error instead of trapping" {
    // Regression for the macOS CI abort on fd-v1-closed: std.posix.fstat maps
    // EBADF to `unreachable` (a process abort) and macOS poll() does not
    // report POLLNVAL for a closed descriptor, so a regression here aborts the
    // whole test process on macOS instead of failing an assertion. Both fd
    // entry points must report 74 (E_FD_STAT_FAILED) for a closed in-range
    // descriptor on every POSIX platform.
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    if (builtin.os.tag != .windows) {
        const stale_fd = std.posix.open("/dev/null", .{}, 0) catch return error.SkipZigTest;
        std.posix.close(stale_fd);

        var res: cabi.Result = undefined;
        try std.testing.expectEqual(@as(c_int, 74), cabi.safegguf_validate_fd_v1(stale_fd, null, &res));
        try std.testing.expectEqualStrings("E_FD_STAT_FAILED", resultCode(&res));
        try std.testing.expectEqualStrings(err.public_codes.fd_stat_failed, resultCanonical(&res));
        try std.testing.expectEqual(@as(c_int, 74), cabi.safegguf_validate_fd(stale_fd, 0, 0));
    }
}
