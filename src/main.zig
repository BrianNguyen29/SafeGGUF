const std = @import("std");
const safegguf = @import("safegguf");

const parser = safegguf.parser;
const structural = safegguf.structural;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();
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
        }
    }

    const file = std.fs.cwd().openFile(file_path, .{}) catch |e| {
        try stderr.print("Error: Failed to open file '{s}': {s}\n", .{ file_path, @errorName(e) });
        std.process.exit(1);
    };
    defer file.close();

    const stat = try file.stat();
    const file_reader = reader_mod.FileReader.init(file, stat.size);
    const r = file_reader.reader();

    const doc = parser.parseDocument(allocator, r, endian, limits.Limits{}) catch |e| {
        try stderr.print("REJECT [E_PARSE_FAILED] Error: {s}\n", .{@errorName(e)});
        std.process.exit(1);
    };
    defer {
        for (doc.tensors) |t| {
            allocator.free(t.name);
            allocator.free(t.dimensions);
        }
        allocator.free(doc.tensors);
    }

    try stdout.print("GGUF version: {d}\n", .{doc.header.version});
    try stdout.print("File size: {d} bytes\n", .{doc.file_size});
    try stdout.print("Metadata entries: {d}\n", .{doc.header.metadata_kv_count});
    try stdout.print("Tensors: {d}\n", .{doc.header.tensor_count});
    try stdout.print("Alignment: {d}\n", .{doc.alignment});
    try stdout.print("Tensor data offset: {d}\n", .{doc.tensor_data_base});

    structural.validateStructural(allocator, doc) catch |e| {
        try stderr.print("\nValidation: REJECT [E_{s}]\n", .{@errorName(e)});
        std.process.exit(1);
    };

    try stdout.print("\nValidation:\n", .{});
    try stdout.print("  structural: PASS\n", .{});
    try stdout.print("  arithmetic: PASS\n", .{});
    try stdout.print("  bounds: PASS\n", .{});
    try stdout.print("  overlap: PASS\n", .{});
}

fn printUsage(writer: anytype) !void {
    try writer.print("SafeGGUF v0.1.0 - Memory-Safe GGUF v3 Structural Validator\n", .{});
    try writer.print("Usage: safegguf inspect <path_to_model.gguf> [--endian little|big]\n", .{});
}
