//! Unit/contract tests for the observability surface (plan §21 metrics,
//! §22 structured logging): counter accounting, bounded reject labels, the
//! closed log field set, and tenant/value redaction. These run as their own
//! test root (wired in build.zig next to validator_test.zig and
//! contract_test.zig).
const std = @import("std");
const safegguf = @import("safegguf");
const metrics_mod = safegguf.metrics;
const log_mod = safegguf.log;
const err = safegguf.error_types;

/// Exact JSON counter names the rendered metrics document must carry (plan
/// §21, namespace dropped because the document is already a `metrics` scope).
const metric_fields = [_][]const u8{
    "requests_total",
    "pass_total",
    "reject_total",
    "error_total",
    "validation_seconds",
    "file_bytes",
    "peak_alloc_bytes",
    "work_units",
    "scanned_bytes",
    "reject_by_error_code",
};

/// Exact JSON field names the structured log record must carry (plan §22).
const log_fields = [_][]const u8{
    "request_id",
    "tenant_id_hash",
    "digest",
    "file_size",
    "profile",
    "duration_ms",
    "verdict",
    "error_code",
    "stage",
    "version",
    "commit",
};

fn renderMetrics(allocator: std.mem.Allocator, m: *const metrics_mod.Metrics) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    try m.writeJson(buf.writer());
    return buf.toOwnedSlice();
}

fn parseJson(allocator: std.mem.Allocator, text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, text, .{});
}

fn expectExactKeys(object: std.json.ObjectMap, expected: []const []const u8) !void {
    if (object.count() != expected.len) {
        std.debug.print("expected {d} JSON fields, got {d}\n", .{ expected.len, object.count() });
        var it = object.iterator();
        while (it.next()) |entry| std.debug.print("  present: {s}\n", .{entry.key_ptr.*});
        return error.UnexpectedFieldSet;
    }
    for (expected) |name| {
        if (object.get(name) == null) {
            std.debug.print("missing JSON field: {s}\n", .{name});
            return error.MissingField;
        }
    }
}

test "metrics: request, verdict, duration, and budget counters record independently" {
    var m = metrics_mod.Metrics{};
    m.recordRequest();
    m.recordRequest();
    m.recordVerdict(.pass);
    m.recordVerdict(.reject);
    m.recordVerdict(.err);
    m.recordValidationNanos(1_500_000_000);
    m.recordValidationNanos(500_000_000);
    m.recordBudgets(4096, 8192, 100, 2048);
    m.recordBudgets(1024, 4096, 23, 512);

    try std.testing.expectEqual(@as(u64, 2), m.requests_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.pass_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.reject_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), m.error_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2_000_000_000), m.validation_ns_total.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1024), m.file_bytes.load(.monotonic)); // last file wins
    try std.testing.expectEqual(@as(u64, 8192), m.peak_alloc_bytes.load(.monotonic)); // running max
    try std.testing.expectEqual(@as(u64, 123), m.work_units.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2560), m.scanned_bytes.load(.monotonic));
}

test "metrics: writeJson emits every required counter with exact field names" {
    const allocator = std.testing.allocator;
    var m = metrics_mod.Metrics{};
    m.recordRequest();
    m.recordVerdict(.pass);
    m.recordValidationNanos(2_500_000_000);
    m.recordBudgets(1234, 5678, 42, 99);

    const text = try renderMetrics(allocator, &m);
    defer allocator.free(text);

    var parsed = try parseJson(allocator, text);
    defer parsed.deinit();
    const obj = parsed.value.object;
    try expectExactKeys(obj, &metric_fields);

    try std.testing.expectEqual(@as(i64, 1), obj.get("requests_total").?.integer);
    try std.testing.expectEqual(@as(i64, 1), obj.get("pass_total").?.integer);
    try std.testing.expectEqual(@as(i64, 0), obj.get("reject_total").?.integer);
    try std.testing.expectEqual(@as(i64, 0), obj.get("error_total").?.integer);
    try std.testing.expectApproxEqAbs(@as(f64, 2.5), obj.get("validation_seconds").?.float, 1e-9);
    try std.testing.expectEqual(@as(i64, 1234), obj.get("file_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 5678), obj.get("peak_alloc_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 42), obj.get("work_units").?.integer);
    try std.testing.expectEqual(@as(i64, 99), obj.get("scanned_bytes").?.integer);
    try std.testing.expectEqual(@as(usize, 0), obj.get("reject_by_error_code").?.object.count());
}

test "metrics: reject labels are bounded to the canonical namespace" {
    const allocator = std.testing.allocator;
    var m = metrics_mod.Metrics{};
    m.recordRejectCode("E_ArithmeticOverflow"); // legacy CLI spelling
    m.recordRejectCode("ArithmeticOverflow"); // bare C-ABI spelling
    m.recordRejectCode("SGGUF_E_TENSOR_OVERLAP"); // canonical spelling
    // Untrusted identifiers must never become labels.
    m.recordRejectCode("filename=/tenant-x/private/model.gguf");
    m.recordRejectCode("tensor_name=model.embed_tokens");
    m.recordRejectCode("metadata_key=tokenizer.ggml.tokens");

    const text = try renderMetrics(allocator, &m);
    defer allocator.free(text);

    for ([_][]const u8{ "tenant-x", "private/model.gguf", "model.embed_tokens", "tokenizer.ggml.tokens" }) |forbidden| {
        if (std.mem.indexOf(u8, text, forbidden) != null) {
            std.debug.print("untrusted identifier leaked into metrics: {s}\n", .{forbidden});
            return error.UnboundedLabel;
        }
    }

    var parsed = try parseJson(allocator, text);
    defer parsed.deinit();
    const labels = parsed.value.object.get("reject_by_error_code").?.object;
    try std.testing.expectEqual(@as(usize, 3), labels.count());
    try std.testing.expectEqual(@as(i64, 2), labels.get("SGGUF_E_ARITHMETIC_OVERFLOW").?.integer);
    try std.testing.expectEqual(@as(i64, 1), labels.get("SGGUF_E_TENSOR_OVERLAP").?.integer);
    try std.testing.expectEqual(@as(i64, 3), labels.get("SGGUF_E_UNKNOWN").?.integer);

    // Every emitted label must be a canonical public code.
    var it = labels.iterator();
    while (it.next()) |entry| {
        try std.testing.expect(err.isPublicCode(entry.key_ptr.*));
    }
}

test "log: record renders exactly the required fields with their values" {
    const allocator = std.testing.allocator;
    const record = log_mod.LogRecord{
        .request_id = "req-123",
        .tenant_id_hash = "0123456789abcdef0123456789abcdef",
        .digest = "aabbcc",
        .file_size = 4096,
        .profile = "llama-cpp",
        .duration_ms = 17,
        .verdict = "REJECT",
        .error_code = "E_TensorOverlap",
        .stage = "structural",
        .version = "0.1.0",
        .commit = "deadbeef",
    };

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try log_mod.writeJson(record, buf.writer());

    var parsed = try parseJson(allocator, buf.items);
    defer parsed.deinit();
    const obj = parsed.value.object;
    try expectExactKeys(obj, &log_fields);

    try std.testing.expectEqualStrings("req-123", obj.get("request_id").?.string);
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", obj.get("tenant_id_hash").?.string);
    try std.testing.expectEqualStrings("aabbcc", obj.get("digest").?.string);
    try std.testing.expectEqual(@as(i64, 4096), obj.get("file_size").?.integer);
    try std.testing.expectEqualStrings("llama-cpp", obj.get("profile").?.string);
    try std.testing.expectEqual(@as(i64, 17), obj.get("duration_ms").?.integer);
    try std.testing.expectEqualStrings("REJECT", obj.get("verdict").?.string);
    try std.testing.expectEqualStrings("E_TensorOverlap", obj.get("error_code").?.string);
    try std.testing.expectEqualStrings("structural", obj.get("stage").?.string);
    try std.testing.expectEqualStrings("0.1.0", obj.get("version").?.string);
    try std.testing.expectEqualStrings("deadbeef", obj.get("commit").?.string);
}

test "log: LogRecord field set is closed to the required redaction-safe whitelist" {
    comptime {
        if (log_fields.len != @typeInfo(log_mod.LogRecord).Struct.fields.len) {
            @compileError("LogRecord field count no longer matches the required field set");
        }
        for (@typeInfo(log_mod.LogRecord).Struct.fields) |field| {
            var allowed = false;
            for (log_fields) |name| {
                if (std.mem.eql(u8, name, field.name)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                @compileError("LogRecord gained a non-whitelisted field: " ++ field.name);
            }
        }
    }
}

test "log: tenant ids are pseudonymized deterministically and never emitted raw" {
    const allocator = std.testing.allocator;
    var buf_a: [log_mod.tenant_hash_hex_len]u8 = undefined;
    var buf_b: [log_mod.tenant_hash_hex_len]u8 = undefined;
    var buf_c: [log_mod.tenant_hash_hex_len]u8 = undefined;
    const hash_a = log_mod.pseudonymizeTenant("tenant-ACME-secret", &buf_a);
    const hash_b = log_mod.pseudonymizeTenant("tenant-ACME-secret", &buf_b);
    const hash_c = log_mod.pseudonymizeTenant("tenant-other", &buf_c);

    try std.testing.expectEqualStrings(hash_a, hash_b); // deterministic
    try std.testing.expect(!std.mem.eql(u8, hash_a, hash_c)); // tenant-separating
    try std.testing.expectEqual(@as(usize, log_mod.tenant_hash_hex_len), hash_a.len);
    for (hash_a) |ch| try std.testing.expect(std.ascii.isHex(ch));

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try log_mod.writeJson(.{ .request_id = "r1", .tenant_id_hash = hash_a, .verdict = "PASS" }, out.writer());

    if (std.mem.indexOf(u8, out.items, "ACME-secret") != null) {
        return error.RawTenantIdLeaked;
    }
    try std.testing.expect(std.mem.indexOf(u8, out.items, hash_a) != null);

    var parsed = try parseJson(allocator, out.items);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(hash_a, parsed.value.object.get("tenant_id_hash").?.string);
}

test "log: hostile field values cannot inject keys or leak paths" {
    const allocator = std.testing.allocator;
    const hostile = "r1\"\n,\"path\":\"/tenant/secret/model.gguf";

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try log_mod.writeJson(.{
        .request_id = hostile,
        .verdict = "ERROR",
        .error_code = "E_FILE_OPEN_FAILED",
    }, out.writer());

    // Injected `"path":` would appear unescaped only if the writer failed; the
    // escaped hostile value keeps the document a closed field set.
    if (std.mem.indexOf(u8, out.items, "\"path\":") != null) {
        return error.InjectedLogField;
    }

    var parsed = try parseJson(allocator, out.items);
    defer parsed.deinit();
    try expectExactKeys(parsed.value.object, &log_fields);
    try std.testing.expectEqualStrings(hostile, parsed.value.object.get("request_id").?.string);
}

test "contract: CLI parses and surfaces the observability flags stderr-only" {
    const allocator = std.testing.allocator;
    const main_src = try std.fs.cwd().readFileAlloc(allocator, "src/main.zig", 1 << 20);
    defer allocator.free(main_src);

    for ([_][]const u8{ "--emit-metrics", "--log-json", "--request-id", "--tenant-id" }) |flag| {
        if (std.mem.indexOf(u8, main_src, flag) == null) {
            std.debug.print("src/main.zig does not expose {s}\n", .{flag});
            return error.MissingObservabilityFlag;
        }
    }
    try std.testing.expect(std.mem.indexOf(u8, main_src, "metrics_mod.Metrics") != null);
    try std.testing.expect(std.mem.indexOf(u8, main_src, "log_mod.LogRecord") != null);
    // Both documents are rendered through std.io.getStdErr(), never stdout.
    try std.testing.expect(std.mem.indexOf(u8, main_src, "std.io.getStdErr().writer()") != null);
}
