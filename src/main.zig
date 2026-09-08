const std = @import("std");
const safegguf = @import("safegguf");

const types = safegguf.types;
const parser = safegguf.parser;
const structural = safegguf.structural;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;

const OutputFormat = enum {
    text,
    json,
};

pub fn main() !void {
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

    var endian: std.builtin.Endian = .little;
    var format: OutputFormat = .text;
    var profile: types.Profile = .gguf_spec;
    const limit = limits.Limits{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--endian")) {
            const val = args.next() orelse {
                try stderr.print("Error: --endian requires 'little' or 'big'\n", .{});
                std.process.exit(64);
            };
            if (std.mem.eql(u8, val, "big")) {
                endian = .big;
            } else if (std.mem.eql(u8, val, "little")) {
                endian = .little;
            } else {
                try stderr.print("Error: invalid endian value '{s}'\n", .{val});
                std.process.exit(64);
            }
        } else if (std.mem.eql(u8, arg, "--format")) {
            const val = args.next() orelse {
                try stderr.print("Error: --format requires 'text' or 'json'\n", .{});
                std.process.exit(64);
            };
            if (std.mem.eql(u8, val, "json")) {
                format = .json;
            } else if (std.mem.eql(u8, val, "text")) {
                format = .text;
            } else {
                try stderr.print("Error: invalid format value '{s}'\n", .{val});
                std.process.exit(64);
            }
        } else if (std.mem.eql(u8, arg, "--profile")) {
            const val = args.next() orelse {
                try stderr.print("Error: --profile requires 'gguf-spec' or 'llama-cpp'\n", .{});
                std.process.exit(64);
            };
            if (std.mem.eql(u8, val, "gguf-spec")) {
                profile = .gguf_spec;
            } else if (std.mem.eql(u8, val, "llama-cpp")) {
                profile = .llama_cpp;
            } else {
                try stderr.print("Error: invalid profile value '{s}'\n", .{val});
                std.process.exit(64);
            }
        } else {
            // Fail closed: reject unknown arguments immediately
            try stderr.print("Error: unknown argument '{s}'\n\n", .{arg});
            try printUsage(stderr);
            std.process.exit(64);
        }
    }

    const file = std.fs.cwd().openFile(file_path, .{}) catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"status":"REJECT","error":"{s}","error_code":"E_FILE_OPEN_FAILED","message":"Failed to open file"}}
                \\
            , .{@errorName(e)});
        } else {
            try stderr.print("Error: Failed to open file '{s}': {s}\n", .{ file_path, @errorName(e) });
        }
        std.process.exit(74); // EX_IOERR
    };
    defer file.close();

    const stat = file.stat() catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"status":"REJECT","error":"{s}","error_code":"E_FILE_STAT_FAILED","message":"Failed to stat file"}}
                \\
            , .{@errorName(e)});
        } else {
            try stderr.print("Error: Failed to stat file '{s}': {s}\n", .{ file_path, @errorName(e) });
        }
        std.process.exit(74); // EX_IOERR
    };

    // Sliding-window buffered reader to mitigate syscall-heavy DoS attacks
    var buffered_reader = reader_mod.BufferedReader.init(file, stat.size);
    const r = buffered_reader.reader();

    // Global quota allocator covering all parser, metadata, and validator memory
    var quota_alloc = limits.QuotaAllocator.init(gpa.allocator(), limit.max_total_alloc_bytes);
    const allocator = quota_alloc.allocator();

    var work_budget = limits.WorkBudget.init(limit.max_work_units);

    const profile_str = switch (profile) {
        .gguf_spec => "gguf-spec",
        .llama_cpp => "llama-cpp",
    };

    var doc = parser.parseDocument(allocator, r, endian, limit, profile, &work_budget) catch |e| {
        if (e == error.IoError) {
            if (format == .json) {
                try stdout.print(
                    \\{{"status":"REJECT","profile":"{s}","error":"IoError","error_code":"E_IoError","stage":"parser","message":"I/O error reading file stream"}}
                    \\
                , .{profile_str});
            } else {
                try stderr.print("Error: I/O error reading file stream: {s}\n", .{@errorName(e)});
            }
            std.process.exit(74); // EX_IOERR
        }

        if (e == error.OutOfMemory) {
            if (quota_alloc.isQuotaExceeded()) {
                if (format == .json) {
                    try stdout.print(
                        \\{{"status":"REJECT","profile":"{s}","error":"TotalAllocationLimitExceeded","error_code":"E_TotalAllocationLimitExceeded","stage":"parser","findings":[{{"code":"E_TotalAllocationLimitExceeded","severity":"reject","message":"Configured memory allocation quota exceeded"}}]}}
                        \\
                    , .{profile_str});
                } else {
                    try stderr.print("REJECT [E_TotalAllocationLimitExceeded] Error: Allocation quota exceeded ({d} bytes)\n", .{limit.max_total_alloc_bytes});
                }
                std.process.exit(2);
            } else {
                try stderr.print("FATAL: Host system out of memory\n", .{});
                std.process.exit(70); // EX_SOFTWARE
            }
        }

        if (format == .json) {
            try stdout.print(
                \\{{"status":"REJECT","profile":"{s}","error":"{s}","error_code":"E_{s}","stage":"parser","findings":[{{"code":"E_{s}","severity":"reject","message":"Parser rejected malformed GGUF stream"}}]}}
                \\
            , .{ profile_str, @errorName(e), @errorName(e), @errorName(e) });
        } else {
            try stderr.print("REJECT [E_{s}] Error: {s}\n", .{ @errorName(e), @errorName(e) });
        }
        std.process.exit(2);
    };
    defer doc.deinit(allocator);

    structural.validateStructural(allocator, doc, profile, &work_budget) catch |e| {
        if (e == error.OutOfMemory) {
            if (quota_alloc.isQuotaExceeded()) {
                if (format == .json) {
                    try stdout.print(
                        \\{{"status":"REJECT","profile":"{s}","error":"TotalAllocationLimitExceeded","error_code":"E_TotalAllocationLimitExceeded","stage":"validation","version":{d},"file_size":{d},"findings":[{{"code":"E_TotalAllocationLimitExceeded","severity":"reject","message":"Configured memory allocation quota exceeded"}}]}}
                        \\
                    , .{ profile_str, doc.header.version, doc.file_size });
                } else {
                    try stderr.print("\nValidation: REJECT [E_TotalAllocationLimitExceeded]\n", .{});
                }
                std.process.exit(2);
            } else {
                try stderr.print("FATAL: Host system out of memory\n", .{});
                std.process.exit(70); // EX_SOFTWARE
            }
        }

        if (format == .json) {
            try stdout.print(
                \\{{"status":"REJECT","profile":"{s}","error":"{s}","error_code":"E_{s}","stage":"validation","version":{d},"file_size":{d},"findings":[{{"code":"E_{s}","severity":"reject","message":"Structural invariant violation"}}]}}
                \\
            , .{ profile_str, @errorName(e), @errorName(e), doc.header.version, doc.file_size, @errorName(e) });
        } else {
            try stderr.print("\nValidation: REJECT [E_{s}]\n", .{@errorName(e)});
        }
        std.process.exit(2);
    };

    if (format == .json) {
        const target_field_name = switch (profile) {
            .llama_cpp => "compatibility_target",
            .gguf_spec => "type_layout_source",
        };

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

fn printUsage(writer: anytype) !void {
    try writer.print("SafeGGUF v0.2.3 - Memory-Safe GGUF v3 Structural & Arithmetic Validator\n", .{});
    try writer.print("Usage: safegguf inspect <path_to_model.gguf> [--endian little|big] [--format text|json] [--profile gguf-spec|llama-cpp]\n", .{});
}
