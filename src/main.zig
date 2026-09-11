const std = @import("std");
const safegguf = @import("safegguf");

const types = safegguf.types;
const err_types = safegguf.error_types;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;
const Validator = safegguf.Validator;

const OutputFormat = enum {
    text,
    json,
};

pub fn main() void {
    run() catch |e| {
        const rc: u8 = switch (e) {
            error.OutOfMemory => 70, // EX_SOFTWARE
            error.IoError => 74, // EX_IOERR
            else => 70, // EX_SOFTWARE
        };
        std.process.exit(rc);
    };
}

fn run() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var args = try std.process.argsWithAllocator(gpa.allocator());
    defer args.deinit();

    _ = args.next(); // program name
    const cmd = args.next() orelse {
        try printUsage(stderr);
        std.process.exit(64);
    };

    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "help")) {
        try printUsage(stdout);
        std.process.exit(0);
    }

    if (!std.mem.eql(u8, cmd, "inspect")) {
        try stderr.print("Unknown command: {s}\n", .{cmd});
        try printUsage(stderr);
        std.process.exit(64);
    }

    const file_path = args.next() orelse {
        try stderr.print("Error: Missing GGUF file path\n\n", .{});
        try printUsage(stderr);
        std.process.exit(64);
    };

    if (std.mem.eql(u8, file_path, "--help") or std.mem.eql(u8, file_path, "-h")) {
        try printUsage(stdout);
        std.process.exit(0);
    }

    var endian: std.builtin.Endian = .little;
    var format: OutputFormat = .text;
    var profile: types.Profile = .gguf_spec;
    const limit = limits.Limits{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--endian")) {
            const val_arg = args.next() orelse {
                try stderr.print("Error: --endian requires 'little' or 'big'\n", .{});
                std.process.exit(64);
            };
            if (std.mem.eql(u8, val_arg, "big")) {
                endian = .big;
            } else if (std.mem.eql(u8, val_arg, "little")) {
                endian = .little;
            } else {
                try stderr.print("Error: invalid endian value '{s}'\n", .{val_arg});
                std.process.exit(64);
            }
        } else if (std.mem.eql(u8, arg, "--format")) {
            const val_arg = args.next() orelse {
                try stderr.print("Error: --format requires 'text' or 'json'\n", .{});
                std.process.exit(64);
            };
            if (std.mem.eql(u8, val_arg, "json")) {
                format = .json;
            } else if (std.mem.eql(u8, val_arg, "text")) {
                format = .text;
            } else {
                try stderr.print("Error: invalid format value '{s}'\n", .{val_arg});
                std.process.exit(64);
            }
        } else if (std.mem.eql(u8, arg, "--profile")) {
            const val_arg = args.next() orelse {
                try stderr.print("Error: --profile requires 'gguf-spec' or 'llama-cpp'\n", .{});
                std.process.exit(64);
            };
            if (std.mem.eql(u8, val_arg, "gguf-spec")) {
                profile = .gguf_spec;
            } else if (std.mem.eql(u8, val_arg, "llama-cpp")) {
                profile = .llama_cpp;
            } else {
                try stderr.print("Error: invalid profile value '{s}'\n", .{val_arg});
                std.process.exit(64);
            }
        } else {
            // Fail closed: reject unknown arguments immediately
            try stderr.print("Error: unknown argument '{s}'\n\n", .{arg});
            try printUsage(stderr);
            std.process.exit(64);
        }
    }

    // Provenance object emitted in every JSON output (PASS/REJECT/ERROR):
    // the pinned ggml type-table source this profile's layout rules derive
    // from. Field name follows the profile (see roadmap issue #12, option B).
    const target_field_name = switch (profile) {
        .llama_cpp => "compatibility_target",
        .gguf_spec => "type_layout_source",
    };

    const file = std.fs.cwd().openFile(file_path, .{}) catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_OPEN_FAILED","message":"Failed to open file"}}
                \\
            , .{ target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, @errorName(e) });
        } else {
            try stderr.print("Error: Failed to open file '{s}': {s}\n", .{ file_path, @errorName(e) });
        }
        std.process.exit(74); // EX_IOERR
    };
    defer file.close();

    const stat = file.stat() catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_STAT_FAILED","message":"Failed to stat file"}}
                \\
            , .{ target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, @errorName(e) });
        } else {
            try stderr.print("Error: Failed to stat file '{s}': {s}\n", .{ file_path, @errorName(e) });
        }
        std.process.exit(74); // EX_IOERR
    };

    // Sliding-window buffered reader to mitigate syscall-heavy DoS attacks
    var buffered_reader = reader_mod.BufferedReader.init(file, stat.size);
    const r = buffered_reader.reader();

    const profile_str = switch (profile) {
        .gguf_spec => "gguf-spec",
        .llama_cpp => "llama-cpp",
    };

    // High-level Validator automatically manages QuotaAllocator and WorkBudget
    var val = Validator.init(gpa.allocator(), limit, profile);
    val.endian = endian;

    // Diagnostics channel: parse/structural raise sites snapshot their position
    // into parse_ctx (via WorkBudget.ctx) so a rejection can be rendered with
    // full context. parse_ctx outlives validate() and the rejection render.
    var parse_ctx = err_types.ParseContext{};
    val.work_budget.ctx = &parse_ctx;

    var doc = val.validate(r) catch |e| {
        if (e == error.IoError) {
            if (format == .json) {
                try stdout.print(
                    \\{{"status":"ERROR","profile":"{s}","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"IoError","error_code":"E_IoError","stage":"parser","message":"I/O error reading file stream"}}
                    \\
                , .{ profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT });
            } else {
                try stderr.print("Error: I/O error reading file stream: {s}\n", .{@errorName(e)});
            }
            std.process.exit(74); // EX_IOERR
        }

        if (e == error.OutOfMemory) {
            if (val.isQuotaExceeded()) {
                if (format == .json) {
                    try stdout.print(
                        \\{{"status":"REJECT","profile":"{s}","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"TotalAllocationLimitExceeded","error_code":"E_TotalAllocationLimitExceeded","stage":"validator","findings":[{{"code":"E_TotalAllocationLimitExceeded","severity":"reject","message":"Configured memory allocation quota exceeded"}}]}}
                        \\
                    , .{ profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT });
                } else {
                    try stderr.print("REJECT [E_TotalAllocationLimitExceeded] Error: Allocation quota exceeded ({d} bytes)\n", .{limit.max_total_alloc_bytes});
                }
                std.process.exit(2);
            } else {
                if (format == .json) {
                    try stdout.print(
                        \\{{"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"OutOfMemory","error_code":"E_OUT_OF_MEMORY","message":"Host system out of memory"}}
                        \\
                    , .{ target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT });
                } else {
                    try stderr.print("FATAL: Host system out of memory\n", .{});
                }
                std.process.exit(70); // EX_SOFTWARE
            }
        }

        try emitRejection(profile_str, target_field_name, e, &parse_ctx, format, stdout, stderr);
        std.process.exit(2);
    };
    defer val.deinitDocument(&doc);

    if (format == .json) {
        try stdout.print(
            \\{{"status":"PASS","profile":"{s}","version":{d},"file_size":{d},"metadata_entries":{d},"tensors":{d},"alignment":{d},"tensor_data_offset":{d},"{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"checks":{{"structural":"PASS","arithmetic":"PASS","bounds":"PASS","overlap":"PASS"}},"findings":[]}}
            \\
        , .{
            profile_str,
            doc.header.version,
            doc.file_size,
            doc.header.metadata_kv_count,
            doc.header.tensor_count,
            doc.alignment,
            doc.tensor_data_base,
            target_field_name,
            types.GGML_PINNED_VERSION,
            types.GGML_PINNED_COMMIT,
        });
    } else {
        try stdout.print("GGUF version: {d}\n", .{doc.header.version});
        try stdout.print("Profile: {s}\n", .{profile_str});
        try stdout.print("File size: {d} bytes\n", .{doc.file_size});
        try stdout.print("Metadata entries: {d}\n", .{doc.header.metadata_kv_count});
        try stdout.print("Tensors: {d}\n", .{doc.header.tensor_count});
        try stdout.print("Alignment: {d}\n", .{doc.alignment});
        try stdout.print("Tensor data offset: {d}\n", .{doc.tensor_data_base});
        try stdout.print("\nValidation:\n", .{});
        try stdout.print("  structural: PASS\n", .{});
        try stdout.print("  arithmetic: PASS\n", .{});
        try stdout.print("  bounds: PASS\n", .{});
        try stdout.print("  overlap: PASS\n", .{});
        try stdout.print("Result: PASS\n", .{});
    }
}

/// Builds the rejection Finding from the caught error plus the ParseContext
/// snapshot taken by parse/structural raise sites, then renders it as JSON
/// (stdout) or text (stderr). Replaces the former generic-only
/// "Validator rejected untrusted GGUF stream" message.
fn emitRejection(
    profile_str: []const u8,
    target_field_name: []const u8,
    e: err_types.ParseError,
    parse_ctx: *const err_types.ParseContext,
    format: OutputFormat,
    stdout_writer: anytype,
    stderr_writer: anytype,
) !void {
    const name = @errorName(e);
    var code_buf: [64]u8 = undefined;
    const code = std.fmt.bufPrint(&code_buf, "E_{s}", .{name}) catch name;
    const finding = err_types.Finding{
        .code = code,
        .message = err_types.messageOf(e),
        .severity = .reject,
        .stage = if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator",
        .tensor = if (parse_ctx.name_len > 0) parse_ctx.tensorName() else null,
        .tensor_index = if (parse_ctx.tensor_index) |ti| @as(usize, @intCast(ti)) else null,
        .offset = parse_ctx.current_offset,
        .expected_offset = parse_ctx.expected_offset,
        .category = err_types.categoryOf(e),
        .key = if (parse_ctx.key_len > 0) parse_ctx.key() else null,
        .key_truncated = parse_ctx.key_truncated,
    };
    switch (format) {
        .json => try writeRejectionJson(stdout_writer, profile_str, target_field_name, name, &finding),
        .text => try writeRejectionText(stderr_writer, &finding),
    }
}

fn writeRejectionJson(w: anytype, profile_str: []const u8, target_field_name: []const u8, name: []const u8, f: *const err_types.Finding) !void {
    try w.print("{{\"status\":\"REJECT\",\"profile\":\"{s}\",\"{s}\":{{\"project\":\"ggml\",\"version\":\"{s}\",\"commit\":\"{s}\"}},\"error\":\"{s}\",\"error_code\":\"{s}\",\"category\":\"{s}\",\"stage\":\"{s}\",\"message\":", .{
        profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, name, f.code, @tagName(f.category.?), f.stage,
    });
    try writeJsonString(w, f.message);
    try writeJsonContextFields(w, f);
    try w.print(",\"findings\":[{{\"code\":\"{s}\",\"severity\":\"reject\",\"message\":", .{f.code});
    try writeJsonString(w, f.message);
    try w.print(",\"stage\":\"{s}\",\"category\":\"{s}\"", .{ f.stage, @tagName(f.category.?) });
    try writeJsonContextFields(w, f);
    try w.writeAll("}]}\n");
}

fn writeRejectionText(w: anytype, f: *const err_types.Finding) !void {
    try w.print("REJECT [{s}] Error: {s}\n", .{ f.code, f.message });
    try w.print("  stage: {s}\n", .{f.stage});
    try w.print("  category: {s}\n", .{@tagName(f.category.?)});
    if (f.tensor_index) |ti| try w.print("  tensor_index: {d}\n", .{ti});
    if (f.tensor) |t| {
        try w.writeAll("  tensor: ");
        try writeTextValue(w, t);
        try w.writeAll("\n");
    }
    if (f.offset) |o| try w.print("  offset: {d}\n", .{o});
    if (f.expected_offset) |eo| try w.print("  expected_offset: {d}\n", .{eo});
    if (f.key) |k| {
        try w.writeAll("  key: ");
        try writeTextValue(w, k);
        if (f.key_truncated) try w.writeAll(" (truncated)");
        try w.writeAll("\n");
    }
}

/// Optional context fields shared by the top-level rejection object and the
/// findings entry; each field is emitted only when the snapshot carries it.
fn writeJsonContextFields(w: anytype, f: *const err_types.Finding) !void {
    if (f.tensor_index) |ti| try w.print(",\"tensor_index\":{d}", .{ti});
    if (f.tensor) |t| {
        try w.writeAll(",\"tensor\":");
        try writeJsonString(w, t);
    }
    if (f.offset) |o| try w.print(",\"offset\":{d}", .{o});
    if (f.expected_offset) |eo| try w.print(",\"expected_offset\":{d}", .{eo});
    if (f.key) |k| {
        try w.writeAll(",\"key\":");
        try writeJsonString(w, k);
    }
    if (f.key_truncated) try w.writeAll(",\"key_truncated\":true");
}

/// JSON string writer that is byte-safe for untrusted input: valid UTF-8
/// sequences escape as \uXXXX (surrogate pairs above the BMP), invalid bytes
/// escape as \u00XX one byte at a time. Output is always printable ASCII, so
/// rejection JSON stays parseable even for malformed names/keys.
fn writeJsonString(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    var i: usize = 0;
    while (i < s.len) {
        const b = s[i];
        switch (b) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            0x08 => try w.writeAll("\\b"),
            0x09 => try w.writeAll("\\t"),
            0x0A => try w.writeAll("\\n"),
            0x0C => try w.writeAll("\\f"),
            0x0D => try w.writeAll("\\r"),
            else => {
                if (b < 0x20) {
                    try w.print("\\u{x:0>4}", .{b});
                } else if (b < 0x80) {
                    try w.writeByte(b);
                } else {
                    const ulen = std.unicode.utf8ByteSequenceLength(b) catch {
                        try w.print("\\u{x:0>4}", .{b});
                        i += 1;
                        continue;
                    };
                    if (i + ulen > s.len) {
                        try w.print("\\u{x:0>4}", .{b});
                        i += 1;
                        continue;
                    }
                    const cp = std.unicode.utf8Decode(s[i..][0..ulen]) catch {
                        try w.print("\\u{x:0>4}", .{b});
                        i += 1;
                        continue;
                    };
                    if (cp < 0x10000) {
                        try w.print("\\u{x:0>4}", .{cp});
                    } else {
                        const c = cp - 0x10000;
                        try w.print("\\u{x:0>4}\\u{x:0>4}", .{ 0xD800 + (c >> 10), 0xDC00 + (c & 0x3FF) });
                    }
                    i += ulen;
                    continue;
                }
            },
        }
        i += 1;
    }
    try w.writeByte('"');
}

/// Text-mode sanitizer for untrusted strings: keeps printable ASCII and
/// replaces every other byte with '?' so hostile keys/names cannot inject
/// escape sequences or invalid UTF-8 into the terminal stream.
fn writeTextValue(w: anytype, s: []const u8) !void {
    for (s) |b| {
        if (b >= 0x20 and b < 0x7F) {
            try w.writeByte(b);
        } else {
            try w.writeByte('?');
        }
    }
}

fn printUsage(writer: anytype) !void {
    try writer.print("SafeGGUF v0.3.5 - Memory-Safe GGUF v3 Structural & Arithmetic Validator\n", .{});
    try writer.print("Usage: safegguf inspect <path_to_model.gguf> [options]\n", .{});
    try writer.print("Options:\n", .{});
    try writer.print("  --endian <little|big>           Byte order (default: little)\n", .{});
    try writer.print("  --format <text|json>            Output format (default: text)\n", .{});
    try writer.print("  --profile <gguf-spec|llama-cpp> Validation profile (default: gguf-spec):\n", .{});
    try writer.print("                                    gguf-spec: resource-bounded GGUF v3 structural safe subset\n", .{});
    try writer.print("                                    llama-cpp: ggml 0.23.0 safe pre-admission subset\n", .{});
    try writer.print("  --help, -h                      Display this help message and exit\n", .{});
}
