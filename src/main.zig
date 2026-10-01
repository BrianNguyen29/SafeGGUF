const std = @import("std");
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
    var auto_endian: bool = false;
    var format: OutputFormat = .text;
    var profile: types.Profile = .gguf_spec;
    var limit = limits.Limits.initFromEnv();
    var require_stable_file: bool = false;
    var emit_metrics: bool = false;
    var emit_log: bool = false;
    var request_id_arg: ?[]const u8 = null;
    var tenant_id_arg: ?[]const u8 = null;

    // The variable-array cap is a sub-limit: max_array_elements is checked
    // first, so an override above it could never take effect (contradictory).
    const max_variable_array_elements_ceiling = limit.max_array_elements;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--endian")) {
            const val_arg = args.next() orelse {
                try stderr.print("Error: --endian requires 'little', 'big', or 'auto'\n", .{});
                std.process.exit(64);
            };
            if (std.mem.eql(u8, val_arg, "big")) {
                endian = .big;
            } else if (std.mem.eql(u8, val_arg, "little")) {
                endian = .little;
            } else if (std.mem.eql(u8, val_arg, "auto")) {
                auto_endian = true;
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
        } else if (std.mem.eql(u8, arg, "--max-variable-array-elements")) {
            const val_arg = args.next() orelse {
                try stderr.print("Error: --max-variable-array-elements requires a positive integer N\n", .{});
                std.process.exit(64);
            };
            const parsed = std.fmt.parseInt(u64, val_arg, 10) catch {
                try stderr.print("Error: invalid --max-variable-array-elements value '{s}' (expected an integer in 1..{d})\n", .{ val_arg, max_variable_array_elements_ceiling });
                std.process.exit(64);
            };
            // Reject zero and contradictory values above the generic array cap;
            // not a budget bypass either way (work/scan/alloc budgets still
            // bound the actual parse cost).
            if (parsed == 0 or parsed > max_variable_array_elements_ceiling) {
                try stderr.print("Error: --max-variable-array-elements value {d} is out of range (expected 1..{d})\n", .{ parsed, max_variable_array_elements_ceiling });
                std.process.exit(64);
            }
            limit.max_variable_array_elements = parsed;
        } else if (std.mem.eql(u8, arg, "--max-memory-mb")) {
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
            limit.max_total_alloc_bytes = bytes;
        } else if (std.mem.eql(u8, arg, "--max-work-budget")) {
            const val_arg = args.next() orelse {
                try stderr.print("Error: --max-work-budget requires a positive integer N\n", .{});
                std.process.exit(64);
            };
            const parsed = std.fmt.parseInt(u64, val_arg, 10) catch {
                try stderr.print("Error: invalid --max-work-budget value '{s}'\n", .{val_arg});
                std.process.exit(64);
            };
            if (parsed == 0) {
                try stderr.print("Error: --max-work-budget must be greater than 0\n", .{});
                std.process.exit(64);
            }
            limit.max_work_units = parsed;
        } else if (std.mem.eql(u8, arg, "--max-file-size-bytes")) {
            const val_arg = args.next() orelse {
                try stderr.print("Error: --max-file-size-bytes requires a positive integer N\n", .{});
                std.process.exit(64);
            };
            const parsed = std.fmt.parseInt(u64, val_arg, 10) catch {
                try stderr.print("Error: invalid --max-file-size-bytes value '{s}'\n", .{val_arg});
                std.process.exit(64);
            };
            if (parsed == 0) {
                try stderr.print("Error: --max-file-size-bytes must be greater than 0\n", .{});
                std.process.exit(64);
            }
            limit.max_file_size_bytes = parsed;
        } else if (std.mem.eql(u8, arg, "--require-stable-file")) {
            require_stable_file = true;
        } else if (std.mem.eql(u8, arg, "--emit-metrics")) {
            emit_metrics = true;
        } else if (std.mem.eql(u8, arg, "--log-json")) {
            emit_log = true;
        } else if (std.mem.eql(u8, arg, "--request-id")) {
            request_id_arg = args.next() orelse {
                try stderr.print("Error: --request-id requires a value\n", .{});
                std.process.exit(64);
            };
        } else if (std.mem.eql(u8, arg, "--tenant-id")) {
            tenant_id_arg = args.next() orelse {
                try stderr.print("Error: --tenant-id requires a value\n", .{});
                std.process.exit(64);
            };
        } else {
            // Fail closed: reject unknown arguments immediately
            try stderr.print("Error: unknown argument '{s}'\n\n", .{arg});
            try printUsage(stderr);
            std.process.exit(64);
        }
    }

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

    const file = std.fs.cwd().openFile(file_path, .{}) catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_OPEN_FAILED","canonical_error_code":"{s}","message":"Failed to open file"}}
                \\
            , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, @errorName(e), err_types.public_codes.file_open_failed });
        } else {
            try stderr.print("Error: Failed to open file '{s}': {s}\n", .{ file_path, @errorName(e) });
        }
        obs.finish(74, .err, "E_FILE_OPEN_FAILED", "io"); // EX_IOERR
    };
    defer file.close();

    const stat = file.stat() catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_STAT_FAILED","canonical_error_code":"{s}","message":"Failed to stat file"}}
                \\
            , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, @errorName(e), err_types.public_codes.file_stat_failed });
        } else {
            try stderr.print("Error: Failed to stat file '{s}': {s}\n", .{ file_path, @errorName(e) });
        }
        obs.finish(74, .err, "E_FILE_STAT_FAILED", "io"); // EX_IOERR
    };

    obs.file_size = stat.size;

    // Non-regular path targets (directories, FIFOs, devices, sockets) have no
    // meaningful size for the sliding-window reader and would otherwise surface
    // as an opaque mid-parse I/O error; reject them up front on the existing
    // stat-failure path (exit 74, E_FILE_STAT_FAILED).
    if (stat.kind != .file) {
        const kind_error = "NotRegularFile";
        if (format == .json) {
            try stdout.print(
                \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_STAT_FAILED","canonical_error_code":"{s}","message":"Not a regular file"}}
                \\
            , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, kind_error, err_types.public_codes.file_stat_failed });
        } else {
            try stderr.print("Error: Not a regular file '{s}': {s}\n", .{ file_path, kind_error });
        }
        obs.finish(74, .err, "E_FILE_STAT_FAILED", "io"); // EX_IOERR
    }

    // Structured logging wants a content digest; computed here (opt-in only)
    // with an independent pread loop, so it cannot disturb the validation
    // reader. Failure leaves the digest empty - the log is diagnostic and must
    // never change the verdict.
    if (emit_log) obs.setDigest(file);

    // Optional stable-file check (--require-stable-file): snapshot the open
    // handle's identity before validation so it can be re-verified afterwards.
    // Off by default, so existing behavior is unchanged. The check operates on
    // the already-open handle (never re-opens by path) and bounds
    // dev/inode/size/mtime/ctime mutation; it is not cryptographic
    // immutability (see reader.FileIdentity for the exact limits).
    var stable_identity: ?reader_mod.FileIdentity = null;
    if (require_stable_file) {
        stable_identity = reader_mod.FileIdentity.capture(file) catch |e| {
            if (format == .json) {
                try stdout.print(
                    \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"{s}","error_code":"E_FILE_STAT_FAILED","canonical_error_code":"{s}","message":"Failed to stat file"}}
                    \\
                , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, @errorName(e), err_types.public_codes.file_stat_failed });
            } else {
                try stderr.print("Error: Failed to stat file '{s}': {s}\n", .{ file_path, @errorName(e) });
            }
            obs.finish(74, .err, "E_FILE_STAT_FAILED", "io"); // EX_IOERR
        };
    }

    // Sliding-window buffered reader to mitigate syscall-heavy DoS attacks
    var buffered_reader = reader_mod.BufferedReader.init(file, stat.size);
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
                if (format == .json) {
                    try stdout.print(
                        \\{{"schema_version":{d},"status":"REJECT","profile":"{s}","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"TotalAllocationLimitExceeded","error_code":"E_TotalAllocationLimitExceeded","canonical_error_code":"{s}","stage":"validator","findings":[{{"code":"E_TotalAllocationLimitExceeded","severity":"reject","message":"Configured memory allocation quota exceeded"}}]}}
                        \\
                    , .{ safegguf.json_schema_version, profile_str, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.publicCodeOf(error.TotalAllocationLimitExceeded) });
                } else {
                    try stderr.print("REJECT [E_TotalAllocationLimitExceeded] Error: Allocation quota exceeded ({d} bytes)\n", .{limit.max_total_alloc_bytes});
                }
                obs.finish(2, .reject, "E_TotalAllocationLimitExceeded", "validator");
            } else {
                if (format == .json) {
                    try stdout.print(
                        \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"OutOfMemory","error_code":"E_OUT_OF_MEMORY","canonical_error_code":"{s}","message":"Host system out of memory"}}
                        \\
                    , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.publicCodeOf(error.OutOfMemory) });
                } else {
                    try stderr.print("FATAL: Host system out of memory\n", .{});
                }
                obs.finish(70, .err, "E_OUT_OF_MEMORY", if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator"); // EX_SOFTWARE
            }
        }

        // Rejection code for observability: same legacy spelling the JSON/text
        // finding carries (`E_<ZigName>`); the bounded metric label is derived
        // from it by the metrics sink.
        var code_buf: [64]u8 = undefined;
        const legacy_code = std.fmt.bufPrint(&code_buf, "E_{s}", .{@errorName(e)}) catch @errorName(e);
        const stage = if (parse_ctx.stage.len > 0) parse_ctx.stage else "validator";
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
                const finding = err_types.Finding{
                    .code = "E_FileChangedDuringValidation",
                    .message = "File identity changed while it was being validated (device, inode, size, or timestamps differ)",
                    .severity = .reject,
                    .stage = "stability",
                    .category = .io,
                };
                switch (format) {
                    .json => try writeRejectionJson(stdout, profile_str, target_field_name, "FileChangedDuringValidation", &finding),
                    .text => try writeRejectionText(stderr, &finding),
                }
                obs.finish(2, .reject, "E_FileChangedDuringValidation", "stability"); // REJECT
            },
            error.FileStatFailed => {
                if (format == .json) {
                    try stdout.print(
                        \\{{"schema_version":{d},"status":"ERROR","{s}":{{"project":"ggml","version":"{s}","commit":"{s}"}},"error":"FileStatFailed","error_code":"E_FILE_STAT_FAILED","canonical_error_code":"{s}","message":"Failed to stat file"}}
                        \\
                    , .{ safegguf.json_schema_version, target_field_name, types.GGML_PINNED_VERSION, types.GGML_PINNED_COMMIT, err_types.public_codes.file_stat_failed });
                } else {
                    try stderr.print("Error: Failed to stat file '{s}': FileStatFailed\n", .{file_path});
                }
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

    /// Records the verdict, validation duration, and run budgets, then renders
    /// the requested JSON documents on stderr.
    fn conclude(self: *RunObservability, verdict: metrics_mod.Verdict, error_code: []const u8, stage: []const u8) void {
        const now = std.time.nanoTimestamp();
        self.metrics.recordVerdict(verdict);
        if (verdict == .reject and error_code.len > 0) self.metrics.recordRejectCode(error_code);
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
    const canonical = err_types.canonicalFromLegacy(f.code) orelse err_types.public_codes.unknown;
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
    try writer.print("Options:\n", .{});
    try writer.print("  --endian <little|big|auto>      Byte order (default: little)\n", .{});
    try writer.print("  --format <text|json>            Output format (default: text)\n", .{});
    try writer.print("  --profile <gguf-spec|llama-cpp> Validation profile (default: gguf-spec):\n", .{});
    try writer.print("                                    gguf-spec: resource-bounded GGUF v3 structural safe subset\n", .{});
    try writer.print("                                    llama-cpp: ggml 0.23.0 safe pre-admission subset\n", .{});
    try writer.print("  --max-variable-array-elements <N> String/nested-array element sanity cap (default: {d})\n", .{(limits.Limits{}).max_variable_array_elements});
    try writer.print("  --max-file-size-bytes <N>       Reject files larger than N bytes before parsing (default: no limit)\n", .{});
    try writer.print("  --require-stable-file           Reject the PASS verdict if the open file's dev/inode/size/mtime/ctime change during validation\n", .{});
    try writer.print("  --max-memory-mb <N>             Maximum allocation quota in MiB (default: 128)\n", .{});
    try writer.print("  --max-work-budget <N>           Maximum logical work units budget (default: 10000000)\n", .{});
    try writer.print("  --emit-metrics                  Emit per-run metrics JSON to stderr (stdout keeps the result document)\n", .{});
    try writer.print("  --log-json                      Emit one structured JSON log record to stderr (adds a SHA-256 file digest)\n", .{});
    try writer.print("  --request-id <id>               Request correlation id for --log-json (default: random per run)\n", .{});
    try writer.print("  --tenant-id <id>                Tenant id for --log-json; logged only as a SHA-256 pseudonym\n", .{});
    try writer.print("  --help, -h                      Display this help message and exit\n", .{});
    try writer.print("  --version                       Print version and build provenance and exit\n", .{});
}
