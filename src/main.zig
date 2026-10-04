const std = @import("std");
const builtin = @import("builtin");
const safegguf = @import("safegguf");
const build_info = @import("build_info.zig");

const types = safegguf.types;
const err_types = safegguf.error_types;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;
const metrics_mod = safegguf.metrics;
const log_mod = safegguf.log;
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

    if (std.mem.eql(u8, cmd, "--version")) {
        try printVersion(stdout);
        std.process.exit(0);
    }

    // `admit` is a separate single-process publisher. It exits internally on
    // every terminal path (0/2/64/70/74) and never falls through to inspect.
    if (std.mem.eql(u8, cmd, "admit")) {
        try runAdmit(&args, gpa.allocator(), stdout, stderr);
        return;
    }

    if (!std.mem.eql(u8, cmd, "inspect")) {
        try stderr.print("Unknown command: {s}\n", .{cmd});
        try printUsage(stderr);
        std.process.exit(64);
    }

    // Positional path after `inspect`. A token starting with '-' is never
    // accepted as a path without an explicit `--` separator: a dash-leading
    // filename must not be silently read as a flag (fail closed, exit 64).
    const first_arg = args.next() orelse {
        try stderr.print("Error: Missing GGUF file path\n\n", .{});
        try printUsage(stderr);
        std.process.exit(64);
    };
    const file_path = resolvePositionalPath(&args, first_arg) catch |e| {
        switch (e) {
            error.MissingAfterSeparator => try stderr.print("Error: Missing GGUF file path after '--'\n\n", .{}),
            error.DashLeading => try stderr.print("Error: file path '{s}' starts with '-' and requires a '--' separator\n\n", .{first_arg}),
        }
        try printUsage(stderr);
        std.process.exit(64);
    };

    // Unified defaults across surfaces (inspect and admit share this parser):
    // llama-cpp + auto endianness, matching the C ABI and Python bindings.
    // `--profile` / `--endian` opt out.
    var common = CommonOptions{ .limit = limits.Limits.initFromEnv() };
    var format: OutputFormat = .text;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--format")) {
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
        } else if (try parseCommonFlag(&args, arg, &common, stderr)) {
            // Shared validation/observability flag, already applied.
        } else {
            // Fail closed: reject unknown arguments immediately
            try stderr.print("Error: unknown argument '{s}'\n\n", .{arg});
            try printUsage(stderr);
            std.process.exit(64);
        }
    }

    // Destructure the shared options so the inspect body below reads as before;
    // defaults live in CommonOptions / Limits.initFromEnv().
    const profile = common.profile;
    const limit = common.limit;
    const endian = common.endian;
    const auto_endian = common.auto_endian;
    const require_stable_file = common.require_stable_file;
    const emit_metrics = common.emit_metrics;
    const emit_log = common.emit_log;
    const request_id_arg = common.request_id_arg;
    const tenant_id_arg = common.tenant_id_arg;

    const profile_str = switch (profile) {
        .gguf_spec => "gguf-spec",
        .llama_cpp => "llama-cpp",
    };

    // Provenance object emitted in every JSON output (PASS/REJECT/ERROR):
    // the pinned ggml type-table source this profile's layout rules derive
    // from. Field name follows the profile (see roadmap issue #12, option B).
    const target_field_name = switch (profile) {
        .llama_cpp => "compatibility_target",
        .gguf_spec => "type_layout_source",
    };

    // Observability (metrics + structured log): additive, opt-in, and
    // stderr-only, so stdout stays reserved for the result document. Counters
    // are recorded on every run; JSON is emitted only when requested.
    var obs = RunObservability{
        .emit_metrics = emit_metrics,
        .emit_log = emit_log,
        .profile_str = profile_str,
        .request_start_ns = std.time.nanoTimestamp(),
    };
    obs.metrics.recordRequest();
    if (emit_log) {
        obs.setRequestId(request_id_arg);
        if (tenant_id_arg) |tenant_id| obs.setTenantId(tenant_id);
    }

    // Open policy is shared with the C ABI (reader.openRegularFile): POSIX
    // opens use O_NONBLOCK so a FIFO/device without a counterpart returns
    // immediately instead of blocking in open(2), and the regular-file kind
    // check runs on the just-opened descriptor (directories, FIFOs, devices,
    // sockets have no meaningful size for the sliding-window reader and are
    // rejected up front on the existing stat-failure path).
    const opened = reader_mod.openRegularFile(file_path) catch |e| {
        const code = try emitOpenFailure(e, file_path, target_field_name, format, stdout, stderr);
        obs.finish(74, .err, code, "io"); // EX_IOERR
    };
    const file = opened.file;
    defer file.close();

    obs.file_size = opened.size;

    // Admission gate: the configured input-size ceiling is enforced before any
    // O(file-size) work, in particular the opt-in --log-json SHA-256 digest
    // below, which otherwise reads the whole file. Mirrors the validator's own
    // admission check (parser.parseDocument) so an oversized input is rejected
    // without being hashed: same legacy code, category, stage, and exit code.
    if (opened.size > limit.max_file_size_bytes) {
        var admission_ctx = err_types.ParseContext{};
        admission_ctx.beginPhase("admission");
        try emitRejection(profile_str, target_field_name, error.FileTooLarge, &admission_ctx, format, stdout, stderr);
        obs.finish(2, .reject, "E_FileTooLarge", "admission"); // REJECT
    }

    // Optional stable-file check (--require-stable-file): snapshot the open
    // handle's identity before validation so it can be re-verified afterwards.
    // Captured before the digest so the digest is computed inside the window
    // the post-validation identity check covers. Off by default, so existing
    // behavior is unchanged. The check operates on the already-open handle
    // (never re-opens by path) and bounds dev/inode/size/mtime/ctime mutation;
    // it is not cryptographic immutability (see reader.FileIdentity for the
    // exact limits).
    var stable_identity: ?reader_mod.FileIdentity = null;
    if (require_stable_file) {
        stable_identity = reader_mod.FileIdentity.capture(file) catch {
            try emitFileStatFailed(file_path, target_field_name, format, stdout, stderr);
            obs.finish(74, .err, "E_FILE_STAT_FAILED", "io"); // EX_IOERR
        };
    }

    // Structured logging wants a content digest; computed here (opt-in only)
    // with an independent pread loop, so it cannot disturb the validation
    // reader. Failure leaves the digest empty - the log is diagnostic and must
    // never change the verdict.
    if (emit_log) obs.setDigest(file);

    // Sliding-window buffered reader to mitigate syscall-heavy DoS attacks
    var buffered_reader = reader_mod.BufferedReader.init(file, opened.size);
    const r = buffered_reader.reader();

    // High-level Validator automatically manages QuotaAllocator and WorkBudget
    var val = Validator.init(gpa.allocator(), limit, profile);
    obs.val = &val;
    if (auto_endian) {
        val.endian = safegguf.parser.detectEndianness(r) orelse .little;
    } else {
        val.endian = endian;
    }

    // Diagnostics channel: parse/structural raise sites snapshot their position
    // into parse_ctx (via WorkBudget.ctx) so a rejection can be rendered with
    // full context. parse_ctx outlives validate() and the rejection render.
    var parse_ctx = err_types.ParseContext{};
    val.work_budget.ctx = &parse_ctx;

    obs.validation_start_ns = std.time.nanoTimestamp();
    var doc = val.validate(r) catch |e| {
        if (e == error.IoError) {
            if (format == .json) {
                try stdout.print(
                    \\{{"schema_version":{d},"status":"ERROR","profile":"{s}","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"IoError","error_code":"E_IoError","canonical_error_code":"{s}","stage":"parser","message":"I/O error reading file stream"}}
                    \\
                , .{ safegguf.json_schema_version, profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.publicCodeOf(error.IoError) });
            } else {
                try stderr.print("Error: I/O error reading file stream: {s}\n", .{@errorName(e)});
            }
            obs.finish(74, .err, "E_IoError", "parser"); // EX_IOERR
        }

        if (e == error.OutOfMemory) {
            if (val.isQuotaExceeded()) {
                try emitQuotaReject(stdout, stderr, profile_str, target_field_name, format, limit.max_total_alloc_bytes);
                obs.finish(2, .reject, "E_TotalAllocationLimitExceeded", "validator");
            } else {
                try emitHostOom(stdout, stderr, target_field_name, format);
                obs.finish(70, .err, "E_OUT_OF_MEMORY", if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator"); // EX_SOFTWARE
            }
        }

        // Rejection code for observability: same legacy spelling the JSON/text
        // finding carries (`E_<ZigName>`); the bounded metric label is derived
        // from it by the metrics sink, except when the raise site recorded an
        // additive canonical detail (which then becomes the metric label).
        var code_buf: [64]u8 = undefined;
        const legacy_code = std.fmt.bufPrint(&code_buf, "E_{s}", .{@errorName(e)}) catch @errorName(e);
        const stage = if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator";
        obs.reject_detail = parse_ctx.canonical_detail;
        try emitRejection(profile_str, target_field_name, e, &parse_ctx, format, stdout, stderr);
        obs.finish(2, .reject, legacy_code, stage);
    };
    defer val.deinitDocument(&doc);

    // Stable-file mode: a PASS verdict must describe the bytes actually read,
    // so re-stat the same handle and reject when any identity field moved
    // while the file was being validated. Only the PASS path needs the check:
    // every failure path already exits non-zero for this file.
    if (stable_identity) |before| {
        before.verifyUnchanged(file) catch |e| switch (e) {
            error.FileChanged => {
                try writeFileChangedRejection(stdout, stderr, profile_str, target_field_name, format);
                obs.finish(2, .reject, "E_FileChangedDuringValidation", "stability"); // REJECT
            },
            error.FileStatFailed => {
                try emitFileStatFailed(file_path, target_field_name, format, stdout, stderr);
                obs.finish(74, .err, "E_FILE_STAT_FAILED", "stability"); // EX_IOERR
            },
        };
    }

    if (format == .json) {
        try stdout.print(
            \\{{"schema_version":{d},"status":"PASS","profile":"{s}","version":{d},"file_size":{d},"metadata_entries":{d},"tensors":{d},"alignment":{d},"tensor_data_offset":{d},"{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"checks":{{"structural":"PASS","arithmetic":"PASS","bounds":"PASS","overlap":"PASS"}},"findings":[]}}
            \\
        , .{
            safegguf.json_schema_version,
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

    // PASS is the only terminal path where run() returns normally, so record
    // and emit here; deferred cleanup below still runs.
    obs.conclude(.pass, "", "");
}

/// Per-run observability state: lock-free metrics counters, validation timing,
/// and the stderr-only structured log context. Recording happens on every run;
/// JSON emission is opt-in (`--emit-metrics` / `--log-json`) and always goes to
/// stderr, so stdout stays reserved for the result document. Emission failures
/// are ignored: observability must never change a verdict or exit code.
const RunObservability = struct {
    metrics: metrics_mod.Metrics = .{},
    emit_metrics: bool = false,
    emit_log: bool = false,
    profile_str: []const u8 = "gguf-spec",
    request_id: []const u8 = "",
    tenant_id_hash: []const u8 = "",
    file_size: u64 = 0,
    digest_hex: []const u8 = "",
    request_start_ns: i128 = 0,
    validation_start_ns: i128 = 0,
    val: ?*Validator = null,
    request_id_buf: [32]u8 = undefined,
    request_id_hex: [64]u8 = undefined,
    tenant_hash_buf: [log_mod.tenant_hash_hex_len]u8 = undefined,
    digest_buf: [64]u8 = undefined,
    /// Additive canonical detail recorded by the raise site for the current
    /// rejection; used as the bounded metric label in place of the legacy
    /// code when present. The structured log keeps the legacy `error_code`.
    reject_detail: ?[:0]const u8 = null,

    /// Records the verdict, validation duration, and run budgets, then renders
    /// the requested JSON documents on stderr.
    fn conclude(self: *RunObservability, verdict: metrics_mod.Verdict, error_code: []const u8, stage: []const u8) void {
        const now = std.time.nanoTimestamp();
        self.metrics.recordVerdict(verdict);
        if (verdict == .reject) {
            const metric_code = self.reject_detail orelse error_code;
            if (metric_code.len > 0) self.metrics.recordRejectCode(metric_code);
        }
        if (self.validation_start_ns != 0 and now > self.validation_start_ns) {
            self.metrics.recordValidationNanos(@intCast(now - self.validation_start_ns));
        }
        if (self.val) |v| {
            self.metrics.recordBudgets(self.file_size, v.quota_alloc.peak_bytes, v.work_budget.consumed_units, v.work_budget.consumed_scanned_bytes);
        } else {
            self.metrics.recordBudgets(self.file_size, 0, 0, 0);
        }

        const stderr_writer = std.io.getStdErr().writer();
        if (self.emit_metrics) self.metrics.writeJson(stderr_writer) catch {};
        if (self.emit_log) {
            const record = log_mod.LogRecord{
                .request_id = self.request_id,
                .tenant_id_hash = self.tenant_id_hash,
                .digest = self.digest_hex,
                .file_size = self.file_size,
                .profile = self.profile_str,
                .duration_ms = elapsedMs(self.request_start_ns, now),
                .verdict = verdictLabel(verdict),
                .error_code = error_code,
                .stage = stage,
                .version = build_info.version,
                .commit = build_info.source_commit,
            };
            log_mod.writeJson(record, stderr_writer) catch {};
        }
    }

    /// `conclude` followed by process exit with the contract exit code.
    fn finish(self: *RunObservability, rc: u8, verdict: metrics_mod.Verdict, error_code: []const u8, stage: []const u8) noreturn {
        self.conclude(verdict, error_code, stage);
        std.process.exit(rc);
    }

    /// Uses the supplied correlation id, or generates a 128-bit random one so
    /// every `--log-json` line still carries a stable per-run identifier.
    fn setRequestId(self: *RunObservability, supplied: ?[]const u8) void {
        if (supplied) |value| {
            self.request_id = value;
        } else {
            std.crypto.random.bytes(&self.request_id_buf);
            self.request_id_hex = std.fmt.bytesToHex(self.request_id_buf, .lower);
            self.request_id = &self.request_id_hex;
        }
    }

    /// Stores only the pseudonym; the raw tenant id is never logged.
    fn setTenantId(self: *RunObservability, tenant_id: []const u8) void {
        self.tenant_id_hash = log_mod.pseudonymizeTenant(tenant_id, &self.tenant_hash_buf);
    }

    fn setDigest(self: *RunObservability, file: std.fs.File) void {
        self.digest_hex = computeFileDigest(file, self.file_size, &self.digest_buf) orelse "";
    }
};

/// Best-effort SHA-256 of the open file, read through an independent pread
/// loop so it cannot disturb the validation reader. Returns null on any read
/// failure, leaving the log's digest empty.
fn computeFileDigest(file: std.fs.File, size: u64, out: *[64]u8) ?[]const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const want: usize = @intCast(@min(@as(u64, buf.len), size - offset));
        const n = file.preadAll(buf[0..want], offset) catch return null;
        if (n == 0) return null;
        hasher.update(buf[0..n]);
        offset += n;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    out.* = std.fmt.bytesToHex(digest, .lower);
    return out;
}

fn elapsedMs(start_ns: i128, end_ns: i128) u64 {
    if (end_ns <= start_ns) return 0;
    const delta: u128 = @intCast(end_ns - start_ns);
    return @intCast(@min(delta / std.time.ns_per_ms, std.math.maxInt(u64)));
}

fn verdictLabel(verdict: metrics_mod.Verdict) []const u8 {
    return switch (verdict) {
        .pass => "PASS",
        .reject => "REJECT",
        .err => "ERROR",
    };
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
        .message = if (parse_ctx.canonical_detail != null) err_types.dimension_overflow_message else err_types.messageOf(e),
        .severity = .reject,
        .stage = if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator",
        .tensor = if (parse_ctx.name_len > 0) parse_ctx.tensorName() else null,
        .tensor_index = if (parse_ctx.tensor_index) |ti| @as(usize, @intCast(ti)) else null,
        .offset = parse_ctx.current_offset,
        .expected_offset = parse_ctx.expected_offset,
        .category = err_types.categoryOf(e),
        .key = if (parse_ctx.key_len > 0) parse_ctx.key() else null,
        .key_truncated = parse_ctx.key_truncated,
        .canonical_detail = parse_ctx.canonical_detail,
    };
    switch (format) {
        .json => try writeRejectionJson(stdout_writer, profile_str, target_field_name, name, &finding),
        .text => try writeRejectionText(stderr_writer, &finding),
    }
}

fn writeRejectionJson(w: anytype, profile_str: []const u8, target_field_name: []const u8, name: []const u8, f: *const err_types.Finding) !void {
    // Additive canonical detail wins over the generic legacy mapping: the
    // legacy `error_code` bytes stay unchanged while `canonical_error_code`
    // names the specific cause (e.g. SGGUF_E_DIMENSION_OVERFLOW).
    const canonical = f.canonical_detail orelse err_types.canonicalFromLegacy(f.code) orelse err_types.public_codes.unknown;
    try w.print("{{\"schema_version\":{d},\"status\":\"REJECT\",\"profile\":\"{s}\",\"{s}\":{{\"project\":\"ggml\",\"version\":\"{s}\",\"commit\":\"{s}\"}},\"error\":\"{s}\",\"error_code\":\"{s}\",\"canonical_error_code\":\"{s}\",\"category\":\"{s}\",\"stage\":\"{s}\",\"message\":", .{
        safegguf.json_schema_version, profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, name, f.code, canonical, @tagName(f.category.?), f.stage,
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

/// Options parsed identically by `inspect` and `admit` through the single
/// shared parser below, so defaults and value contracts cannot drift between
/// subcommands. `--format` is inspect-only; the admit directories are
/// admit-only.
const CommonOptions = struct {
    endian: std.builtin.Endian = .little,
    auto_endian: bool = true,
    profile: types.Profile = .llama_cpp,
    limit: limits.Limits = .{},
    require_stable_file: bool = false,
    emit_metrics: bool = false,
    emit_log: bool = false,
    request_id_arg: ?[]const u8 = null,
    tenant_id_arg: ?[]const u8 = null,
};

/// `admit` admission ceiling: 16 GiB, matching the K8s handoff script and
/// the staging volume sizeLimit. Still overridable via --max-file-size-bytes.
const admit_default_max_file_size_bytes: u64 = 17179869184;

/// Resolves the positional path operand shared by `inspect` and `admit`. A
/// leading `--` separator admits a dash-leading path; without it, any token
/// starting with '-' is a usage error (fail closed, exit 64 at the call site).
fn resolvePositionalPath(
    args: *std.process.ArgIterator,
    first_arg: []const u8,
) error{ MissingAfterSeparator, DashLeading }![]const u8 {
    if (std.mem.eql(u8, first_arg, "--")) {
        return args.next() orelse error.MissingAfterSeparator;
    }
    if (first_arg.len > 0 and first_arg[0] == '-') return error.DashLeading;
    return first_arg;
}

/// Shared `--flag <positive u64>` value parser (missing / invalid / zero
/// messages identical for every flag that uses it).
fn parsePositiveU64(args: *std.process.ArgIterator, flag: []const u8, stderr: anytype) !u64 {
    const val_arg = args.next() orelse {
        try stderr.print("Error: {s} requires a positive integer N\n", .{flag});
        std.process.exit(64);
    };
    const parsed = std.fmt.parseInt(u64, val_arg, 10) catch {
        try stderr.print("Error: invalid {s} value '{s}'\n", .{ flag, val_arg });
        std.process.exit(64);
    };
    if (parsed == 0) {
        try stderr.print("Error: {s} must be greater than 0\n", .{flag});
        std.process.exit(64);
    }
    return parsed;
}

/// Single parser for every validation/observability flag shared by `inspect`
/// and `admit`. Returns true when `arg` was consumed (including any value read
/// from `args`), false when the caller must handle a command-specific flag.
/// Invalid values print and exit 64 (fail closed).
fn parseCommonFlag(
    args: *std.process.ArgIterator,
    arg: []const u8,
    opts: *CommonOptions,
    stderr: anytype,
) !bool {
    if (std.mem.eql(u8, arg, "--endian")) {
        const val_arg = args.next() orelse {
            try stderr.print("Error: --endian requires 'little', 'big', or 'auto'\n", .{});
            std.process.exit(64);
        };
        if (std.mem.eql(u8, val_arg, "big")) {
            opts.endian = .big;
            opts.auto_endian = false;
        } else if (std.mem.eql(u8, val_arg, "little")) {
            opts.endian = .little;
            opts.auto_endian = false;
        } else if (std.mem.eql(u8, val_arg, "auto")) {
            opts.auto_endian = true;
        } else {
            try stderr.print("Error: invalid endian value '{s}'\n", .{val_arg});
            std.process.exit(64);
        }
        return true;
    }
    if (std.mem.eql(u8, arg, "--profile")) {
        const val_arg = args.next() orelse {
            try stderr.print("Error: --profile requires 'gguf-spec' or 'llama-cpp'\n", .{});
            std.process.exit(64);
        };
        if (std.mem.eql(u8, val_arg, "gguf-spec")) {
            opts.profile = .gguf_spec;
        } else if (std.mem.eql(u8, val_arg, "llama-cpp")) {
            opts.profile = .llama_cpp;
        } else {
            try stderr.print("Error: invalid profile value '{s}'\n", .{val_arg});
            std.process.exit(64);
        }
        return true;
    }
    if (std.mem.eql(u8, arg, "--max-variable-array-elements")) {
        const val_arg = args.next() orelse {
            try stderr.print("Error: --max-variable-array-elements requires a positive integer N\n", .{});
            std.process.exit(64);
        };
        const parsed = std.fmt.parseInt(u64, val_arg, 10) catch {
            try stderr.print("Error: invalid --max-variable-array-elements value '{s}' (expected an integer in 1..{d})\n", .{ val_arg, opts.limit.max_array_elements });
            std.process.exit(64);
        };
        // Reject zero and contradictory values above the generic array cap;
        // not a budget bypass either way (work/scan/alloc budgets still
        // bound the actual parse cost).
        if (parsed == 0 or parsed > opts.limit.max_array_elements) {
            try stderr.print("Error: --max-variable-array-elements value {d} is out of range (expected 1..{d})\n", .{ parsed, opts.limit.max_array_elements });
            std.process.exit(64);
        }
        opts.limit.max_variable_array_elements = parsed;
        return true;
    }
    if (std.mem.eql(u8, arg, "--max-memory-mb")) {
        const val_arg = args.next() orelse {
            try stderr.print("Error: --max-memory-mb requires a positive integer N\n", .{});
            std.process.exit(64);
        };
        const parsed = std.fmt.parseInt(u64, val_arg, 10) catch {
            try stderr.print("Error: invalid --max-memory-mb value '{s}'\n", .{val_arg});
            std.process.exit(64);
        };
        if (parsed == 0) {
            try stderr.print("Error: --max-memory-mb must be greater than 0\n", .{});
            std.process.exit(64);
        }
        const bytes = std.math.mul(u64, parsed, 1024 * 1024) catch {
            try stderr.print("Error: --max-memory-mb value '{s}' is out of range\n", .{val_arg});
            std.process.exit(64);
        };
        opts.limit.max_total_alloc_bytes = bytes;
        return true;
    }
    if (std.mem.eql(u8, arg, "--max-work-budget")) {
        opts.limit.max_work_units = try parsePositiveU64(args, "--max-work-budget", stderr);
        return true;
    }
    if (std.mem.eql(u8, arg, "--max-file-size-bytes")) {
        opts.limit.max_file_size_bytes = try parsePositiveU64(args, "--max-file-size-bytes", stderr);
        return true;
    }
    if (std.mem.eql(u8, arg, "--max-string-bytes")) {
        opts.limit.max_string_bytes = try parsePositiveU64(args, "--max-string-bytes", stderr);
        return true;
    }
    if (std.mem.eql(u8, arg, "--key-policy")) {
        const val_arg = args.next() orelse {
            try stderr.print("Error: --key-policy requires 'strict' or 'lenient'\n", .{});
            std.process.exit(64);
        };
        if (std.mem.eql(u8, val_arg, "strict")) {
            opts.limit.key_policy = .strict;
        } else if (std.mem.eql(u8, val_arg, "lenient")) {
            opts.limit.key_policy = .lenient;
        } else {
            try stderr.print("Error: invalid key-policy value '{s}'\n", .{val_arg});
            std.process.exit(64);
        }
        return true;
    }
    if (std.mem.eql(u8, arg, "--require-stable-file")) {
        opts.require_stable_file = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--emit-metrics")) {
        opts.emit_metrics = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--log-json")) {
        opts.emit_log = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--request-id")) {
        opts.request_id_arg = args.next() orelse {
            try stderr.print("Error: --request-id requires a value\n", .{});
            std.process.exit(64);
        };
        return true;
    }
    if (std.mem.eql(u8, arg, "--tenant-id")) {
        opts.tenant_id_arg = args.next() orelse {
            try stderr.print("Error: --tenant-id requires a value\n", .{});
            std.process.exit(64);
        };
        return true;
    }
    return false;
}

/// Shared source open/stat failure renderer (inspect and admit emit identical
/// bytes). Returns the legacy code for observability.
fn emitOpenFailure(
    e: reader_mod.OpenRegularFileError,
    path: []const u8,
    target_field_name: []const u8,
    format: OutputFormat,
    stdout_writer: anytype,
    stderr_writer: anytype,
) ![]const u8 {
    const is_stat_failure = e == error.StatFailed or e == error.NotRegularFile;
    const kind_error = if (e == error.NotRegularFile) "NotRegularFile" else @errorName(e);
    if (is_stat_failure) {
        const message = if (e == error.NotRegularFile) "Not a regular file" else "Failed to stat file";
        if (format == .json) {
            try stdout_writer.print(
                \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_STAT_FAILED","canonical_error_code":"{s}","message":"{s}"}}
                \\
            , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, kind_error, err_types.public_codes.file_stat_failed, message });
        } else {
            try stderr_writer.print("Error: {s} '{s}': {s}\n", .{ message, path, kind_error });
        }
        return "E_FILE_STAT_FAILED";
    }
    if (format == .json) {
        try stdout_writer.print(
            \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_OPEN_FAILED","canonical_error_code":"{s}","message":"Failed to open file"}}
            \\
        , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, kind_error, err_types.public_codes.file_open_failed });
    } else {
        try stderr_writer.print("Error: Failed to open file '{s}': {s}\n", .{ path, kind_error });
    }
    return "E_FILE_OPEN_FAILED";
}

/// Shared E_FILE_STAT_FAILED renderer for the stable-file paths (inspect and
/// admit emit identical bytes).
fn emitFileStatFailed(
    path: []const u8,
    target_field_name: []const u8,
    format: OutputFormat,
    stdout_writer: anytype,
    stderr_writer: anytype,
) !void {
    if (format == .json) {
        try stdout_writer.print(
            \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"FileStatFailed","error_code":"E_FILE_STAT_FAILED","canonical_error_code":"{s}","message":"Failed to stat file"}}
            \\
        , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.public_codes.file_stat_failed });
    } else {
        try stderr_writer.print("Error: Failed to stat file '{s}': FileStatFailed\n", .{path});
    }
}

/// Shared E_FileChangedDuringValidation rejection renderer (inspect + admit).
fn writeFileChangedRejection(
    stdout_writer: anytype,
    stderr_writer: anytype,
    profile_str: []const u8,
    target_field_name: []const u8,
    format: OutputFormat,
) !void {
    const finding = err_types.Finding{
        .code = "E_FileChangedDuringValidation",
        .message = "File identity changed while it was being validated (device, inode, size, or timestamps differ)",
        .severity = .reject,
        .stage = "stability",
        .category = .io,
    };
    switch (format) {
        .json => try writeRejectionJson(stdout_writer, profile_str, target_field_name, "FileChangedDuringValidation", &finding),
        .text => try writeRejectionText(stderr_writer, &finding),
    }
}

/// Shared quota-rejection renderer (inspect + admit).
fn emitQuotaReject(
    stdout_writer: anytype,
    stderr_writer: anytype,
    profile_str: []const u8,
    target_field_name: []const u8,
    format: OutputFormat,
    max_total_alloc_bytes: u64,
) !void {
    if (format == .json) {
        try stdout_writer.print(
            \\{{"schema_version":{d},"status":"REJECT","profile":"{s}","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"TotalAllocationLimitExceeded","error_code":"E_TotalAllocationLimitExceeded","canonical_error_code":"{s}","stage":"validator","findings":[{{"code":"E_TotalAllocationLimitExceeded","severity":"reject","message":"Configured memory allocation quota exceeded"}}]}}
            \\
        , .{ safegguf.json_schema_version, profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.publicCodeOf(error.TotalAllocationLimitExceeded) });
    } else {
        try stderr_writer.print("REJECT [E_TotalAllocationLimitExceeded] Error: Allocation quota exceeded ({d} bytes)\n", .{max_total_alloc_bytes});
    }
}

/// Shared host-OOM renderer (inspect + admit).
fn emitHostOom(
    stdout_writer: anytype,
    stderr_writer: anytype,
    target_field_name: []const u8,
    format: OutputFormat,
) !void {
    if (format == .json) {
        try stdout_writer.print(
            \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"OutOfMemory","error_code":"E_OUT_OF_MEMORY","canonical_error_code":"{s}","message":"Host system out of memory"}}
            \\
        , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.publicCodeOf(error.OutOfMemory) });
    } else {
        try stderr_writer.print("FATAL: Host system out of memory\n", .{});
    }
}

/// ERROR JSON for admit I/O failures (stdout). Field order matches inspect's
/// parser-stage IoError document; `stage` names the failing phase.
fn emitAdmitIoError(
    stdout_writer: anytype,
    profile_str: []const u8,
    target_field_name: []const u8,
    message: []const u8,
    stage: []const u8,
) !void {
    try stdout_writer.print(
        \\{{"schema_version":{d},"status":"ERROR","profile":"{s}","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"IoError","error_code":"E_IoError","canonical_error_code":"{s}","stage":"{s}","message":"{s}"}}
        \\
    , .{ safegguf.json_schema_version, profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.publicCodeOf(error.IoError), stage, message });
}

/// Canonical one-line attestation, byte-compatible with
/// deploy/k8s/attestation_handoff.sh: same field order and values, no
/// timestamps, `require_stable_file` always true, and only the digest-keyed
/// relative CAS name embedded (never a filesystem path).
fn renderAttestation(
    w: anytype,
    digest_hex: []const u8,
    size_bytes: u64,
    profile_str: []const u8,
    opts: CommonOptions,
    resolved_endian: std.builtin.Endian,
) !void {
    // Admission schema is independent of inspect's diagnostics schema. v2
    // changes relative_path to be relative to the supplied CAS directory.
    try w.print("{{\"schema_version\":{d},\"document_type\":\"safegguf-admission\",\"digest\":{{\"algorithm\":\"sha256\",\"value\":", .{safegguf.attestation_schema_version});
    try writeJsonString(w, digest_hex);
    try w.print("}},\"size_bytes\":{d},\"verdict\":{{\"status\":\"PASS\",\"validator_exit_code\":0}},\"validator\":{{\"version\":", .{size_bytes});
    try writeJsonString(w, build_info.version);
    try w.writeAll(",\"source_commit\":");
    try writeJsonString(w, build_info.source_commit);
    try w.writeAll(",\"profile\":");
    try writeJsonString(w, profile_str);
    try w.writeAll(",\"endian\":");
    try writeJsonString(w, if (opts.auto_endian) "auto" else @tagName(opts.endian));
    try w.writeAll(",\"resolved_endian\":");
    try writeJsonString(w, @tagName(resolved_endian));
    try w.writeAll(",\"zig_version\":");
    try writeJsonString(w, build_info.zig_version);
    try w.writeAll(",\"build_mode\":");
    try writeJsonString(w, build_info.build_mode);
    try w.writeAll(",\"target\":");
    try writeJsonString(w, build_info.target);
    try w.writeAll(",\"type_layout_source\":");
    try std.json.stringify(types.CompatibilityTarget{}, .{}, w);
    try w.writeAll(",\"limits\":{");
    // Emit every effective Limits field, including environment overrides and
    // fixed parser ceilings. New limit fields are captured automatically.
    inline for (@typeInfo(limits.Limits).Struct.fields, 0..) |field, i| {
        if (i > 0) try w.writeByte(',');
        try writeJsonString(w, field.name);
        try w.writeByte(':');
        try std.json.stringify(@field(opts.limit, field.name), .{}, w);
    }
    try w.writeAll(",\"require_stable_file\":true}},\"cas\":{\"relative_to\":\"cas-dir\",\"relative_path\":\"");
    try w.writeAll(digest_hex);
    try w.writeAll("\",\"sha256\":");
    try writeJsonString(w, digest_hex);
    try w.writeAll("}}\n");
}

/// Atomic document publish: unique temp file in the destination directory,
/// fsync, then rename over `final_name`. The temp is removed on failure; each
/// writer renames its own complete file, so concurrent runs cannot tear the
/// document.
fn writeFileAtomic(dir: std.fs.Dir, final_name: []const u8, bytes: []const u8) !void {
    var rand: [8]u8 = undefined;
    std.crypto.random.bytes(&rand);
    var name_buf: [160]u8 = undefined;
    const temp_name = std.fmt.bufPrint(&name_buf, ".{s}.{s}.tmp", .{ final_name, std.fmt.fmtSliceHexLower(&rand) }) catch return error.NameTooLong;
    const temp = try dir.createFile(temp_name, .{ .truncate = false, .exclusive = true });
    var temp_open = true;
    errdefer {
        if (temp_open) temp.close();
        dir.deleteFile(temp_name) catch {};
    }
    try temp.writeAll(bytes);
    try temp.sync();
    temp.close();
    temp_open = false;
    try dir.rename(temp_name, final_name);
}

/// Marks a published CAS entry read-only: POSIX 0444; Windows maps that to the
/// portable read-only attribute (mode bits do not exist there).
fn makePublishedReadOnly(file: std.fs.File) !void {
    if (builtin.os.tag == .windows) {
        try file.setPermissions(.{ .inner = .{ .attributes = std.os.windows.FILE_ATTRIBUTE_READONLY } });
    } else {
        try file.chmod(0o444);
    }
}

/// Private per-run staging state for `admit`: a mkdtemp-style 0700 directory
/// inside --cas-dir (random suffix, O_EXCL semantics) holding exactly one
/// fixed-name temp file created 0600 with O_EXCL. The file is streamed from
/// the source, hashed, validated through the same handle, and renamed into the
/// CAS; the directory itself is never a publication root.
const AdmitStage = struct {
    cas_dir: std.fs.Dir,
    dir_name_buf: [64]u8 = undefined,
    dir_name_len: usize = 0,
    file_name_buf: [96]u8 = undefined,
    file_name_len: usize = 0,
    file: ?std.fs.File = null,
    /// Set once the staged file has been renamed into the CAS: cleanup then
    /// removes only the now-empty staging directory, never the entry.
    published: bool = false,

    const file_basename = "model.gguf";

    fn init(cas_dir: std.fs.Dir) AdmitStage {
        return .{ .cas_dir = cas_dir };
    }

    fn dirName(self: *const AdmitStage) []const u8 {
        return self.dir_name_buf[0..self.dir_name_len];
    }

    fn fileName(self: *const AdmitStage) []const u8 {
        return self.file_name_buf[0..self.file_name_len];
    }

    fn create(self: *AdmitStage) !void {
        var attempt: usize = 0;
        while (attempt < 128) : (attempt += 1) {
            var rand: [8]u8 = undefined;
            std.crypto.random.bytes(&rand);
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, ".admit-stage-{s}", .{std.fmt.fmtSliceHexLower(&rand)}) catch unreachable;
            std.posix.mkdirat(self.cas_dir.fd, name, 0o700) catch |e| switch (e) {
                error.PathAlreadyExists => continue,
                else => return e,
            };
            @memcpy(self.dir_name_buf[0..name.len], name);
            self.dir_name_len = name.len;
            break;
        } else return error.PathAlreadyExists;
        const file_name = std.fmt.bufPrint(&self.file_name_buf, "{s}/{s}", .{ self.dirName(), file_basename }) catch unreachable;
        self.file_name_len = file_name.len;
        const create_flags: std.fs.File.CreateFlags = if (builtin.os.tag == .windows)
            .{ .read = true, .truncate = false, .exclusive = true }
        else
            .{ .read = true, .truncate = false, .exclusive = true, .mode = 0o600 };
        self.file = try self.cas_dir.createFile(self.fileName(), create_flags);
    }

    /// Closes the temp file and removes the staging directory (recursively
    /// before publication, empty-only after). Best-effort: cleanup must never
    /// change the exit code.
    fn cleanup(self: *AdmitStage) void {
        if (self.file) |f| {
            f.close();
            self.file = null;
        }
        if (self.dir_name_len == 0) return;
        if (self.published) {
            self.cas_dir.deleteDir(self.dirName()) catch {};
        } else {
            self.cas_dir.deleteTree(self.dirName()) catch {};
        }
        self.dir_name_len = 0;
    }
};

/// `safegguf admit`: single-process publish (admission document schema v2).
/// Copies the untrusted source
/// once into the private staging file inside --cas-dir, hashing the copy
/// stream inline; validates that same inode through its still-open descriptor
/// under a mandatory pre/post FileIdentity window; then atomically publishes
/// the bytes as `--cas-dir/<sha256>`, chmods the entry 0444, and writes the
/// canonical attestation plus `sha256sum -c` pin into --attestations-dir.
/// stdout on success is exactly the attestation bytes. Fail-closed: REJECT
/// paths publish nothing and remove the staging file; a failure after the CAS
/// rename leaves the orphan CAS entry in place and exits 74.
///
/// Residual (honest limit): FileIdentity bounds mutation of the staging inode
/// (dev/inode/size/mtime/ctime), but a writer inside the trust boundary that
/// can rewrite the 0600 temp file and restore its size and timestamps is not
/// detectable. The owned staging/CAS directories and files must be inaccessible to
/// untrusted writers. A privileged or same-identity writer can invalidate the
/// digest/verdict binding; descriptor validation alone does not prevent it.
fn runAdmit(
    args: *std.process.ArgIterator,
    allocator: std.mem.Allocator,
    stdout: anytype,
    stderr: anytype,
) anyerror!void {
    var common = CommonOptions{ .limit = limits.Limits.initFromEnv() };
    // admit's admission ceiling is explicit (16 GiB, the handoff script's
    // value) instead of inspect's unlimited default; the shared parser still
    // lets --max-file-size-bytes override it.
    common.limit.max_file_size_bytes = admit_default_max_file_size_bytes;

    const first_arg = args.next() orelse {
        try stderr.print("Error: Missing GGUF file path\n\n", .{});
        try printAdmitUsage(stderr);
        std.process.exit(64);
    };
    const src_path = resolvePositionalPath(args, first_arg) catch |e| {
        switch (e) {
            error.MissingAfterSeparator => try stderr.print("Error: Missing GGUF file path after '--'\n\n", .{}),
            error.DashLeading => try stderr.print("Error: file path '{s}' starts with '-' and requires a '--' separator\n\n", .{first_arg}),
        }
        try printAdmitUsage(stderr);
        std.process.exit(64);
    };

    var cas_dir_arg: ?[]const u8 = null;
    var attestations_dir_arg: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cas-dir")) {
            cas_dir_arg = args.next() orelse {
                try stderr.print("Error: --cas-dir requires a directory path\n", .{});
                std.process.exit(64);
            };
        } else if (std.mem.eql(u8, arg, "--attestations-dir")) {
            attestations_dir_arg = args.next() orelse {
                try stderr.print("Error: --attestations-dir requires a directory path\n", .{});
                std.process.exit(64);
            };
        } else if (try parseCommonFlag(args, arg, &common, stderr)) {
            // Shared validation/observability flag, already applied.
        } else {
            try stderr.print("Error: unknown argument '{s}'\n\n", .{arg});
            try printAdmitUsage(stderr);
            std.process.exit(64);
        }
    }
    const cas_dir_path = cas_dir_arg orelse {
        try stderr.print("Error: --cas-dir is required\n\n", .{});
        try printAdmitUsage(stderr);
        std.process.exit(64);
    };
    const attestations_dir_path = attestations_dir_arg orelse {
        try stderr.print("Error: --attestations-dir is required\n\n", .{});
        try printAdmitUsage(stderr);
        std.process.exit(64);
    };

    // Publication roots must already exist: admit never creates them, so a
    // mistyped path cannot silently become one (fail closed, exit 64).
    const cas_dir = std.fs.cwd().openDir(cas_dir_path, .{}) catch |e| {
        try stderr.print("Error: cannot open --cas-dir '{s}': {s}\n", .{ cas_dir_path, @errorName(e) });
        std.process.exit(64);
    };
    const attestations_dir = std.fs.cwd().openDir(attestations_dir_path, .{}) catch |e| {
        try stderr.print("Error: cannot open --attestations-dir '{s}': {s}\n", .{ attestations_dir_path, @errorName(e) });
        std.process.exit(64);
    };

    const profile_str = switch (common.profile) {
        .gguf_spec => "gguf-spec",
        .llama_cpp => "llama-cpp",
    };
    const target_field_name = switch (common.profile) {
        .llama_cpp => "compatibility_target",
        .gguf_spec => "type_layout_source",
    };

    var obs = RunObservability{
        .emit_metrics = common.emit_metrics,
        .emit_log = common.emit_log,
        .profile_str = profile_str,
        .request_start_ns = std.time.nanoTimestamp(),
    };
    obs.metrics.recordRequest();
    if (common.emit_log) {
        obs.setRequestId(common.request_id_arg);
        if (common.tenant_id_arg) |tenant_id| obs.setTenantId(tenant_id);
    }

    const opened = reader_mod.openRegularFile(src_path) catch |e| {
        const code = try emitOpenFailure(e, src_path, target_field_name, .json, stdout, stderr);
        obs.finish(74, .err, code, "io"); // EX_IOERR
    };
    const src = opened.file;
    obs.file_size = opened.size;

    // Admission ceiling, first enforcement: the source's stat size, mirroring
    // inspect's admission gate (same legacy code, category, stage, exit 2).
    if (opened.size > common.limit.max_file_size_bytes) {
        var admission_ctx = err_types.ParseContext{};
        admission_ctx.beginPhase("admission");
        try emitRejection(profile_str, target_field_name, error.FileTooLarge, &admission_ctx, .json, stdout, stderr);
        obs.finish(2, .reject, "E_FileTooLarge", "admission"); // REJECT
    }

    // Private staging: 0700 directory inside --cas-dir holding a single O_EXCL
    // 0600 temp file. Same filesystem as the CAS, so publication is an atomic
    // rename.
    var stage = AdmitStage.init(cas_dir);
    stage.create() catch {
        stage.cleanup();
        try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to create staging file", "staging");
        obs.finish(74, .err, "E_IoError", "staging"); // EX_IOERR
    };

    // Copy exactly once, hashing the copy stream: the digest names the bytes
    // that are validated, by construction (no second hash pass over a path).
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var copy_buf: [64 * 1024]u8 = undefined;
    var copied: u64 = 0;
    while (true) {
        const n = src.read(&copy_buf) catch {
            stage.cleanup();
            try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to read source file", "copy");
            obs.finish(74, .err, "E_IoError", "copy"); // EX_IOERR
        };
        if (n == 0) break;
        const n64: u64 = @intCast(n);
        // Admission ceiling, second enforcement: abort as soon as the copied
        // byte count would exceed the cap, so an oversized source is never
        // fully copied even when its stat size understated it.
        if (n64 > common.limit.max_file_size_bytes - copied) {
            stage.cleanup();
            var admission_ctx = err_types.ParseContext{};
            admission_ctx.beginPhase("admission");
            try emitRejection(profile_str, target_field_name, error.FileTooLarge, &admission_ctx, .json, stdout, stderr);
            obs.finish(2, .reject, "E_FileTooLarge", "admission"); // REJECT
        }
        stage.file.?.writeAll(copy_buf[0..n]) catch {
            stage.cleanup();
            try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to write staging file", "copy");
            obs.finish(74, .err, "E_IoError", "copy"); // EX_IOERR
        };
        hasher.update(copy_buf[0..n]);
        copied += n64;
    }
    stage.file.?.sync() catch {
        stage.cleanup();
        try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to sync staging file", "copy");
        obs.finish(74, .err, "E_IoError", "copy"); // EX_IOERR
    };

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const digest_hex: [64]u8 = std.fmt.bytesToHex(digest, .lower);

    obs.file_size = copied;
    // The structured log digest is the copy-stream digest; admit has no second
    // hash pass.
    obs.digest_hex = &digest_hex;

    // Mandatory stability window (not opt-in): the inode under validation is
    // the staged copy; capture before and re-verify before publication.
    const identity_before = reader_mod.FileIdentity.capture(stage.file.?) catch {
        stage.cleanup();
        try emitFileStatFailed(src_path, target_field_name, .json, stdout, stderr);
        obs.finish(74, .err, "E_FILE_STAT_FAILED", "stability"); // EX_IOERR
    };

    // Validate the staged inode through its still-open descriptor.
    var buffered_reader = reader_mod.BufferedReader.init(stage.file.?, copied);
    const r = buffered_reader.reader();
    var val = Validator.init(allocator, common.limit, common.profile);
    obs.val = &val;
    if (common.auto_endian) {
        val.endian = safegguf.parser.detectEndianness(r) orelse .little;
    } else {
        val.endian = common.endian;
    }
    var parse_ctx = err_types.ParseContext{};
    val.work_budget.ctx = &parse_ctx;
    obs.validation_start_ns = std.time.nanoTimestamp();
    var doc = val.validate(r) catch |e| {
        stage.cleanup();
        if (e == error.IoError) {
            try emitAdmitIoError(stdout, profile_str, target_field_name, "I/O error reading file stream", "parser");
            obs.finish(74, .err, "E_IoError", "parser"); // EX_IOERR
        }
        if (e == error.OutOfMemory) {
            if (val.isQuotaExceeded()) {
                try emitQuotaReject(stdout, stderr, profile_str, target_field_name, .json, common.limit.max_total_alloc_bytes);
                obs.finish(2, .reject, "E_TotalAllocationLimitExceeded", "validator");
            } else {
                try emitHostOom(stdout, stderr, target_field_name, .json);
                obs.finish(70, .err, "E_OUT_OF_MEMORY", if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator"); // EX_SOFTWARE
            }
        }
        // Rejection code for observability: same legacy spelling the JSON
        // finding carries (`E_<ZigName>`); a recorded canonical detail becomes
        // the bounded metric label.
        var code_buf: [64]u8 = undefined;
        const legacy_code = std.fmt.bufPrint(&code_buf, "E_{s}", .{@errorName(e)}) catch @errorName(e);
        const reject_stage = if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator";
        obs.reject_detail = parse_ctx.canonical_detail;
        try emitRejection(profile_str, target_field_name, e, &parse_ctx, .json, stdout, stderr);
        obs.finish(2, .reject, legacy_code, reject_stage); // REJECT
    };
    defer val.deinitDocument(&doc);

    // Re-verify the staged inode before publishing anything.
    identity_before.verifyUnchanged(stage.file.?) catch |e| switch (e) {
        error.FileChanged => {
            stage.cleanup();
            try writeFileChangedRejection(stdout, stderr, profile_str, target_field_name, .json);
            obs.finish(2, .reject, "E_FileChangedDuringValidation", "stability"); // REJECT
        },
        error.FileStatFailed => {
            stage.cleanup();
            try emitFileStatFailed(src_path, target_field_name, .json, stdout, stderr);
            obs.finish(74, .err, "E_FILE_STAT_FAILED", "stability"); // EX_IOERR
        },
    };

    // Publish: atomic rename inside --cas-dir, then mark the entry read-only.
    // The staging directory is removed as soon as the entry exists; failures
    // after this point keep the orphan CAS entry (never roll it back).
    cas_dir.rename(stage.fileName(), &digest_hex) catch {
        stage.cleanup();
        try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to publish CAS entry", "publish");
        obs.finish(74, .err, "E_IoError", "publish"); // EX_IOERR
    };
    stage.published = true;
    makePublishedReadOnly(stage.file.?) catch {
        stage.cleanup();
        try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to mark CAS entry read-only", "publish");
        obs.finish(74, .err, "E_IoError", "publish"); // EX_IOERR
    };
    stage.cleanup();

    // Canonical one-line admission v2 document. The handoff wrapper calls this
    // publisher directly, so its statement bytes cannot drift independently.
    var attestation = std.ArrayList(u8).init(allocator);
    defer attestation.deinit();
    try renderAttestation(attestation.writer(), &digest_hex, copied, profile_str, common, val.endian);
    var attestation_name_buf: [80]u8 = undefined;
    const attestation_name = std.fmt.bufPrint(&attestation_name_buf, "{s}.json", .{digest_hex}) catch unreachable;
    writeFileAtomic(attestations_dir, attestation_name, attestation.items) catch {
        try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to write attestation", "attestation");
        obs.finish(74, .err, "E_IoError", "attestation"); // EX_IOERR
    };

    // `sha256sum -c` pin file, same bytes as the script (digest twice).
    var pin_name_buf: [96]u8 = undefined;
    const pin_name = std.fmt.bufPrint(&pin_name_buf, "{s}.sha256", .{digest_hex}) catch unreachable;
    var pin_buf: [131]u8 = undefined;
    const pin_bytes = std.fmt.bufPrint(&pin_buf, "{s}  {s}\n", .{ digest_hex, digest_hex }) catch unreachable;
    writeFileAtomic(attestations_dir, pin_name, pin_bytes) catch {
        try emitAdmitIoError(stdout, profile_str, target_field_name, "Failed to write attestation pin", "attestation");
        obs.finish(74, .err, "E_IoError", "attestation"); // EX_IOERR
    };

    // stdout is exactly the attestation document.
    stdout.writeAll(attestation.items) catch {
        obs.finish(74, .err, "E_IoError", "stdout"); // EX_IOERR
    };
    obs.finish(0, .pass, "", "");
}

fn printVersion(writer: anytype) !void {
    try writer.print("SafeGGUF {s}\n", .{build_info.version});
    try writer.print("source_commit: {s}\n", .{build_info.source_commit});
    try writer.print("zig: {s}\n", .{build_info.zig_version});
    try writer.print("build_mode: {s}\n", .{build_info.build_mode});
    try writer.print("target: {s}\n", .{build_info.target});
    try writer.print("ggml_target: {s}\n", .{build_info.ggml_target});
    try writer.print("ggml_commit: {s}\n", .{build_info.ggml_commit});
}

fn printUsage(writer: anytype) !void {
    try writer.print("SafeGGUF v{s} - Memory-Safe GGUF v3 Structural & Arithmetic Validator\n", .{build_info.version});
    try writer.print("Usage: safegguf inspect <path_to_model.gguf> [options]\n", .{});
    try writer.print("       safegguf admit -- <model.gguf> --cas-dir <dir> --attestations-dir <dir> [options]\n", .{});
    try writer.print("       (admit publishes the validated bytes + canonical attestation; same validation/observability flags)\n", .{});
    try writer.print("Options:\n", .{});
    try writer.print("  --endian <little|big|auto>      Byte order (default: auto)\n", .{});
    try writer.print("  --format <text|json>            Output format (default: text)\n", .{});
    try writer.print("  --profile <gguf-spec|llama-cpp> Validation profile (default: llama-cpp):\n", .{});
    try writer.print("                                    gguf-spec: resource-bounded GGUF v3 structural safe subset\n", .{});
    try writer.print("                                    llama-cpp: ggml 0.23.0 safe pre-admission subset\n", .{});
    try writer.print("  --max-variable-array-elements <N> String/nested-array element sanity cap (default: {d})\n", .{(limits.Limits{}).max_variable_array_elements});
    try writer.print("  --max-file-size-bytes <N>       Reject files larger than N bytes before parsing (default: no limit)\n", .{});
    try writer.print("  --max-string-bytes <N>          Metadata key/string byte cap; relief flag (default: {d})\n", .{(limits.Limits{}).max_string_bytes});
    try writer.print("  --key-policy <strict|lenient>   Metadata key grammar; lenient admits '-' and uppercase (default: strict)\n", .{});
    try writer.print("  --require-stable-file           Reject the PASS verdict if the open file's dev/inode/size/mtime/ctime change during validation\n", .{});
    try writer.print("  --max-memory-mb <N>             Maximum allocation quota in MiB (default: 128)\n", .{});
    try writer.print("  --max-work-budget <N>           Maximum logical work units budget (default: 10000000)\n", .{});
    try writer.print("  --emit-metrics                  Emit per-run metrics JSON to stderr (stdout keeps the result document)\n", .{});
    try writer.print("  --log-json                      Emit one structured JSON log record to stderr (adds a SHA-256 file digest)\n", .{});
    try writer.print("  --request-id <id>               Request correlation id for --log-json (default: random per run)\n", .{});
    try writer.print("  --tenant-id <id>                Tenant id for --log-json; logged only as a SHA-256 pseudonym\n", .{});
    try writer.print("  --                              Separator required before a file path starting with '-'\n", .{});
    try writer.print("  --help, -h                      Display this help message and exit\n", .{});
    try writer.print("  --version                       Print version and build provenance and exit\n", .{});
}

fn printAdmitUsage(writer: anytype) !void {
    try writer.print("SafeGGUF v{s} - Memory-Safe GGUF v3 Structural & Arithmetic Validator\n", .{build_info.version});
    try writer.print("Usage: safegguf admit -- <model.gguf> --cas-dir <dir> --attestations-dir <dir> [options]\n", .{});
    try writer.print("Publishes validated bytes into a content-addressed store and writes the canonical\n", .{});
    try writer.print("attestation + sha256 pin for the same digest; stdout is the attestation document.\n", .{});
    try writer.print("Options:\n", .{});
    try writer.print("  --cas-dir <dir>                 Existing directory receiving validated/<sha256> (required)\n", .{});
    try writer.print("  --attestations-dir <dir>        Existing directory receiving <sha256>.json + <sha256>.sha256 (required)\n", .{});
    try writer.print("  --endian <little|big|auto>      Byte order (default: auto)\n", .{});
    try writer.print("  --profile <gguf-spec|llama-cpp> Validation profile (default: llama-cpp)\n", .{});
    try writer.print("  --max-variable-array-elements <N> String/nested-array element sanity cap (default: {d})\n", .{(limits.Limits{}).max_variable_array_elements});
    try writer.print("  --max-file-size-bytes <N>       Admission ceiling, checked before and during the copy (default: 17179869184)\n", .{});
    try writer.print("  --max-string-bytes <N>          Metadata key/string byte cap; relief flag (default: {d})\n", .{(limits.Limits{}).max_string_bytes});
    try writer.print("  --key-policy <strict|lenient>   Metadata key grammar; lenient admits '-' and uppercase (default: strict)\n", .{});
    try writer.print("  --require-stable-file           Always enforced by admit (accepted for inspect parity; bound in the attestation)\n", .{});
    try writer.print("  --max-memory-mb <N>             Maximum allocation quota in MiB (default: 128)\n", .{});
    try writer.print("  --max-work-budget <N>           Maximum logical work units budget (default: 10000000)\n", .{});
    try writer.print("  --emit-metrics                  Emit per-run metrics JSON to stderr (stdout keeps the attestation)\n", .{});
    try writer.print("  --log-json                      Emit one structured JSON log record to stderr (digest = copy-stream digest)\n", .{});
    try writer.print("  --request-id <id>               Request correlation id for --log-json (default: random per run)\n", .{});
    try writer.print("  --tenant-id <id>                Tenant id for --log-json; logged only as a SHA-256 pseudonym\n", .{});
    try writer.print("  --                              Separator required before a model path starting with '-'\n", .{});
    try writer.print("  --help, -h                      Display this help message and exit\n", .{});
    try writer.print("  --version                       Print version and build provenance and exit\n", .{});
}
