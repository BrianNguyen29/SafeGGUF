const std = @import("std");
const safegguf = @import("safegguf");

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
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // program name
    const cmd = args.next() orelse {
        try printUsage(stderr);
        std.process.exit(1);
    };

    if (!std.mem.eql(u8, cmd, "inspect")) {
        try stderr.print("Unknown command: {s}\n", .{cmd});
        try printUsage(stderr);
        std.process.exit(1);
    }

    const file_path = args.next() orelse {
        try stderr.print("Error: Missing GGUF file path\n\n", .{});
        try printUsage(stderr);
        std.process.exit(1);
    };

    var endian: std.builtin.Endian = .little;
    var format: OutputFormat = .text;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--endian")) {
            const val = args.next() orelse {
                try stderr.print("Error: --endian requires 'little' or 'big'\n", .{});
                std.process.exit(1);
            };
            if (std.mem.eql(u8, val, "big")) {
                endian = .big;
            } else if (std.mem.eql(u8, val, "little")) {
                endian = .little;
            } else {
                try stderr.print("Error: invalid endian value '{s}'\n", .{val});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--format")) {
            const val = args.next() orelse {
                try stderr.print("Error: --format requires 'text' or 'json'\n", .{});
                std.process.exit(1);
            };
            if (std.mem.eql(u8, val, "json")) {
                format = .json;
            } else if (std.mem.eql(u8, val, "text")) {
                format = .text;
            } else {
                try stderr.print("Error: invalid format value '{s}'\n", .{val});
                std.process.exit(1);
            }
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
        std.process.exit(1);
    };
    defer file.close();

    const stat = try file.stat();
    const file_reader = reader_mod.FileReader.init(file, stat.size);
    const r = file_reader.reader();

    var doc = parser.parseDocument(allocator, r, endian, limits.Limits{}) catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"status":"REJECT","error":"{s}","error_code":"E_{s}","stage":"parser"}}
                \\
            , .{ @errorName(e), @errorName(e) });
        } else {
            try stderr.print("REJECT [E_{s}] Error: {s}\n", .{ @errorName(e), @errorName(e) });
        }
        std.process.exit(1);
    };
    defer doc.deinit(allocator);

    structural.validateStructural(allocator, doc) catch |e| {
        if (format == .json) {
            try stdout.print(
                \\{{"status":"REJECT","error":"{s}","error_code":"E_{s}","stage":"validation","version":{d},"file_size":{d}}}
                \\
            , .{ @errorName(e), @errorName(e), doc.header.version, doc.file_size });
        } else {
            try stderr.print("\nValidation: REJECT [E_{s}]\n", .{@errorName(e)});
        }
        std.process.exit(1);
    };

    if (format == .json) {
        try stdout.print(
            \\{{"status":"PASS","version":{d},"file_size":{d},"metadata_entries":{d},"tensors":{d},"alignment":{d},"tensor_data_offset":{d},"checks":{{"structural":"PASS","arithmetic":"PASS","bounds":"PASS","overlap":"PASS"}},"findings":[]}}
            \\
        , .{
            doc.header.version,
            doc.file_size,
            doc.header.metadata_kv_count,
            doc.header.tensor_count,
            doc.alignment,
            doc.tensor_data_base,
        });
    } else {
        try stdout.print("GGUF version: {d}\n", .{doc.header.version});
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
    try writer.print("SafeGGUF v0.2.0 - Memory-Safe GGUF v3 Structural & Arithmetic Validator\n", .{});
    try writer.print("Usage: safegguf inspect <path_to_model.gguf> [--endian little|big] [--format text|json]\n", .{});
}
