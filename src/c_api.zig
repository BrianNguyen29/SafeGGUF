const std = @import("std");
const safegguf = @import("root.zig");

const types = safegguf.types;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;
const Validator = safegguf.Validator;

pub export fn safegguf_version() [*:0]const u8 {
    return "0.3.6";
}

fn validateInternal(
    file: std.fs.File,
    file_size: u64,
    profile_id: c_int,
    endian_id: c_int,
) c_int {
    const profile: types.Profile = switch (profile_id) {
        1 => .llama_cpp,
        else => .gguf_spec,
    };

    var buffered_reader = reader_mod.BufferedReader.init(file, file_size);
    const r = buffered_reader.reader();

    const endian: std.builtin.Endian = switch (endian_id) {
        1 => .big,
        2 => safegguf.parser.detectEndianness(r) orelse .little,
        else => .little,
    };

    const limit = limits.Limits.initFromEnv();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var val = Validator.init(gpa.allocator(), limit, profile);
    val.endian = endian;

    var doc = val.validate(r) catch |e| {
        return switch (e) {
            error.IoError => 74,
            error.OutOfMemory => if (val.quota_alloc.isQuotaExceeded()) 2 else 70,
            else => 2, // All validation rejections exit 2
        };
    };
    defer val.deinitDocument(&doc);

    return 0; // PASS
}

pub export fn safegguf_validate_path(
    path_ptr: ?[*:0]const u8,
    profile_id: c_int,
    endian_id: c_int,
) c_int {
    const ptr = path_ptr orelse return 64;
    const path_slice = std.mem.span(ptr);
    if (path_slice.len == 0 or path_slice.len > 4096) return 74;
    const file = std.fs.cwd().openFile(path_slice, .{}) catch return 74;
    defer file.close();

    const stat = file.stat() catch return 74;
    return validateInternal(file, stat.size, profile_id, endian_id);
}

pub export fn safegguf_validate_fd(
    handle_int: isize,
    profile_id: c_int,
    endian_id: c_int,
) c_int {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) {
        if (handle_int <= 0) return 74;
    } else {
        if (handle_int < 0) return 74;
    }

    const handle: std.fs.File.Handle = if (builtin.os.tag == .windows)
        @as(std.fs.File.Handle, @ptrFromInt(@as(usize, @bitCast(handle_int))))
    else
        @as(std.fs.File.Handle, @intCast(handle_int));

    const file = std.fs.File{ .handle = handle };
    const stat = file.stat() catch return 74;

    const orig_pos = file.getPos() catch null;
    defer {
        if (orig_pos) |pos| {
            file.seekTo(pos) catch {};
        }
    }

    return validateInternal(file, stat.size, profile_id, endian_id);
}
