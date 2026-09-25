const std = @import("std");
const safegguf = @import("root.zig");

const types = safegguf.types;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;
const Validator = safegguf.Validator;

pub export fn safegguf_version() [*:0]const u8 {
    return "0.3.7-dev";
}

pub const OptionsV1 = extern struct {
    struct_size: u32,
    profile: c_int,
    endian: c_int,
    max_alloc_bytes: u64,
    max_work_units: u64,
    max_scanned_bytes: u64,
    reserved: ?*anyopaque,
};

pub const Result = extern struct {
    exit_code: c_int,
    error_code: [64]u8,
    category: [32]u8,
    stage: [32]u8,
    message: [256]u8,
};

fn copyCString(dest: []u8, src: []const u8) void {
    @memset(dest, 0);
    const n = @min(src.len, dest.len - 1);
    @memcpy(dest[0..n], src[0..n]);
    dest[n] = 0;
}

fn populateResult(
    out_result: ?*Result,
    exit_code: c_int,
    err_code: []const u8,
    cat: []const u8,
    stage: []const u8,
    msg: []const u8,
) void {
    if (out_result) |res| {
        res.exit_code = exit_code;
        copyCString(&res.error_code, err_code);
        copyCString(&res.category, cat);
        copyCString(&res.stage, stage);
        copyCString(&res.message, msg);
    }
}

fn validateInternal(
    file: std.fs.File,
    file_size: u64,
    options: ?*const OptionsV1,
    profile_id: c_int,
    endian_id: c_int,
    out_result: ?*Result,
) c_int {
    // 1. Strict options validation if options struct is provided
    if (options) |opts| {
        if (opts.struct_size != @sizeOf(OptionsV1)) {
            populateResult(out_result, 64, "E_USAGE_INVALID_OPTIONS", "usage", "options", "Invalid struct_size in safegguf_options_v1_t");
            return 64;
        }
    }

    // 2. Strict enum validation (no silent fallback!)
    if (profile_id != 0 and profile_id != 1) {
        populateResult(out_result, 64, "E_USAGE_INVALID_PROFILE", "usage", "options", "Invalid profile_id: must be 0 (gguf-spec) or 1 (llama-cpp)");
        return 64;
    }
    if (endian_id != 0 and endian_id != 1 and endian_id != 2) {
        populateResult(out_result, 64, "E_USAGE_INVALID_ENDIAN", "usage", "options", "Invalid endian_id: must be 0 (little), 1 (big), or 2 (auto)");
        return 64;
    }

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

    // 3. Resource limits: start from env / defaults, then override with options if specified
    var lim = limits.Limits.initFromEnv();
    if (options) |opts| {
        if (opts.max_alloc_bytes > 0) lim.max_total_alloc_bytes = opts.max_alloc_bytes;
        if (opts.max_work_units > 0) lim.max_work_units = opts.max_work_units;
        if (opts.max_scanned_bytes > 0) lim.max_scanned_bytes = opts.max_scanned_bytes;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var val = Validator.init(gpa.allocator(), lim, profile);
    val.endian = endian;

    var doc = val.validate(r) catch |e| {
        const quota_hit = (e == error.OutOfMemory and val.quota_alloc.isQuotaExceeded());
        const exit_code: c_int = switch (e) {
            error.IoError => 74,
            error.OutOfMemory => if (quota_hit) 2 else 70,
            else => 2,
        };
        const cat = if (quota_hit) "resource" else @tagName(safegguf.error_types.categoryOf(e));
        const err_name = if (quota_hit) "TotalAllocationLimitExceeded" else @errorName(e);
        const msg = if (quota_hit) "Configured memory allocation quota exceeded" else safegguf.error_types.messageOf(e);
        populateResult(
            out_result,
            exit_code,
            err_name,
            cat,
            "validation",
            msg,
        );
        return exit_code;
    };
    defer val.deinitDocument(&doc);

    populateResult(out_result, 0, "", "", "", "Model strictly satisfies structural, arithmetic, and resource limits");
    return 0; // PASS
}

pub export fn safegguf_validate_path_v1(
    path_ptr: ?[*:0]const u8,
    options: ?*const OptionsV1,
    out_result: ?*Result,
) c_int {
    const ptr = path_ptr orelse {
        populateResult(out_result, 64, "E_USAGE_NULL_PATH", "usage", "input", "Target path pointer is NULL");
        return 64;
    };
    const path_slice = std.mem.span(ptr);
    if (path_slice.len == 0 or path_slice.len > 4096) {
        populateResult(out_result, 74, "E_IO_INVALID_PATH", "io", "input", "Path length is empty or exceeds 4096 bytes");
        return 74;
    }

    const profile_id = if (options) |o| o.profile else 1; // default llama-cpp
    const endian_id = if (options) |o| o.endian else 2;   // default auto

    const file = std.fs.cwd().openFile(path_slice, .{}) catch {
        populateResult(out_result, 74, "E_FILE_OPEN_FAILED", "io", "filesystem", "Failed to open file on disk");
        return 74;
    };
    defer file.close();

    const stat = file.stat() catch {
        populateResult(out_result, 74, "E_FILE_STAT_FAILED", "io", "filesystem", "Failed to query file metadata / stat");
        return 74;
    };

    return validateInternal(file, stat.size, options, profile_id, endian_id, out_result);
}

pub export fn safegguf_validate_fd_v1(
    handle_int: isize,
    options: ?*const OptionsV1,
    out_result: ?*Result,
) c_int {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) {
        if (handle_int <= 0) {
            populateResult(out_result, 74, "E_INVALID_HANDLE", "io", "descriptor", "Invalid Windows file handle");
            return 74;
        }
    } else {
        if (handle_int < 0) {
            populateResult(out_result, 74, "E_INVALID_FD", "io", "descriptor", "Invalid POSIX file descriptor");
            return 74;
        }
    }

    const handle: std.fs.File.Handle = if (builtin.os.tag == .windows)
        @as(std.fs.File.Handle, @ptrFromInt(@as(usize, @bitCast(handle_int))))
    else
        @as(std.fs.File.Handle, @intCast(handle_int));

    const file = std.fs.File{ .handle = handle };
    const stat = file.stat() catch {
        populateResult(out_result, 74, "E_FD_STAT_FAILED", "io", "descriptor", "Failed to fstat file descriptor");
        return 74;
    };

    const orig_pos = file.getPos() catch null;
    defer {
        if (orig_pos) |pos| {
            file.seekTo(pos) catch {};
        }
    }

    const profile_id = if (options) |o| o.profile else 1; // default llama-cpp
    const endian_id = if (options) |o| o.endian else 2;   // default auto

    return validateInternal(file, stat.size, options, profile_id, endian_id, out_result);
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
    return validateInternal(file, stat.size, null, profile_id, endian_id, null);
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

    return validateInternal(file, stat.size, null, profile_id, endian_id, null);
}
