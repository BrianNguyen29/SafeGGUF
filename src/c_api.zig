const std = @import("std");
const build_options = @import("build_options");
const safegguf = @import("root.zig");

const types = safegguf.types;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;
const Validator = safegguf.Validator;

const version_z: [:0]const u8 = std.fmt.comptimePrint("{s}", .{build_options.version});

pub export fn safegguf_version() [*:0]const u8 {
    return version_z.ptr;
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

fn validateOptions(options: ?*const OptionsV1, out_result: ?*Result) ?c_int {
    if (options) |opts| {
        if (opts.struct_size != @sizeOf(OptionsV1)) {
            populateResult(out_result, 64, "E_USAGE_INVALID_OPTIONS", "usage", "options", "Invalid struct_size in safegguf_options_v1_t");
            return 64;
        }
        if (opts.reserved != null) {
            populateResult(out_result, 64, "E_USAGE_INVALID_OPTIONS", "usage", "options", "Reserved field must be NULL in safegguf_options_v1_t");
            return 64;
        }
        if (opts.profile != 0 and opts.profile != 1) {
            populateResult(out_result, 64, "E_USAGE_INVALID_PROFILE", "usage", "options", "Invalid profile_id: must be 0 (gguf-spec) or 1 (llama-cpp)");
            return 64;
        }
        if (opts.endian != 0 and opts.endian != 1 and opts.endian != 2) {
            populateResult(out_result, 64, "E_USAGE_INVALID_ENDIAN", "usage", "options", "Invalid endian_id: must be 0 (little), 1 (big), or 2 (auto)");
            return 64;
        }
    }
    return null;
}

fn validateEnums(profile_id: c_int, endian_id: c_int, out_result: ?*Result) ?c_int {
    if (profile_id != 0 and profile_id != 1) {
        populateResult(out_result, 64, "E_USAGE_INVALID_PROFILE", "usage", "options", "Invalid profile_id: must be 0 (gguf-spec) or 1 (llama-cpp)");
        return 64;
    }
    if (endian_id != 0 and endian_id != 1 and endian_id != 2) {
        populateResult(out_result, 64, "E_USAGE_INVALID_ENDIAN", "usage", "options", "Invalid endian_id: must be 0 (little), 1 (big), or 2 (auto)");
        return 64;
    }
    return null;
}

fn validateInternal(
    file: std.fs.File,
    file_size: u64,
    options: ?*const OptionsV1,
    profile_id: c_int,
    endian_id: c_int,
    out_result: ?*Result,
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

    // Resource limits: start from env / defaults, then override with options if specified
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

/// Result of opening a path whose resolved target is a regular file.
const OpenedRegularFile = struct {
    file: std.fs.File,
    size: u64,
};

const OpenRegularFileError = error{
    /// open(2) / CreateFile failed (missing path, permissions, socket node, ...).
    OpenFailed,
    /// The opened descriptor could not be queried.
    StatFailed,
    /// The resolved target is not a regular file (directory, FIFO, socket,
    /// character/block device, ...).
    NotRegularFile,
};

/// Opens `path` and returns it only when the resolved target is a regular
/// file, mirroring the CLI's `stat.kind != .file` policy (src/main.zig).
///
/// Symlink policy: symlinks are followed, matching both the previous C ABI
/// behavior and the CLI (`std.fs.Dir.openFile` resolves links). The kind
/// decision applies to the resolved target, so a symlink to a regular model
/// is accepted while a symlink to a directory/FIFO/device is rejected.
/// O_NOFOLLOW is deliberately not used: CLI parity is defined on the resolved
/// target, and the non-blocking kind check makes the follow safe.
///
/// Blocking policy: on POSIX the open uses O_NONBLOCK so a FIFO with no
/// writer (or any target whose open would otherwise wait) returns immediately
/// and is then rejected by the kind check; O_NONBLOCK has no effect on
/// regular-file reads, so validation semantics are unchanged. O_NOCTTY avoids
/// acquiring a controlling terminal. The kind is taken from fstat on the
/// just-opened descriptor, so a concurrent path swap cannot bypass the policy.
fn openRegularFile(path: []const u8) OpenRegularFileError!OpenedRegularFile {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) {
        // Windows has no O_NONBLOCK equivalent for path opens; stat.kind is
        // still the regular-file decision (CLI parity; main.zig uses the same
        // kind check).
        const file = std.fs.cwd().openFile(path, .{}) catch return error.OpenFailed;
        errdefer file.close();
        const stat = file.stat() catch return error.StatFailed;
        if (stat.kind != .file) return error.NotRegularFile;
        return .{ .file = file, .size = stat.size };
    }
    const fd = std.posix.open(path, .{ .NONBLOCK = true, .NOCTTY = true, .CLOEXEC = true }, 0) catch return error.OpenFailed;
    const file = std.fs.File{ .handle = fd };
    errdefer file.close();
    const stat = file.stat() catch return error.StatFailed;
    if (stat.kind != .file) return error.NotRegularFile;
    return .{ .file = file, .size = stat.size };
}

/// Fstats a descriptor supplied by a foreign C caller. `std.posix.fstat`
/// treats EBADF as `unreachable` (a process abort), so an untrusted descriptor
/// must be proven open first: POSIX poll() reports POLLNVAL for closed or
/// out-of-range descriptors without touching them. Returns null when the
/// descriptor is invalid or the stat itself fails. Closing a descriptor
/// concurrently with the call remains the caller's contract violation; fd
/// ownership stays with the caller for the duration of the call.
fn fstatForeign(file: std.fs.File) ?std.fs.File.Stat {
    const builtin = @import("builtin");
    if (builtin.os.tag != .windows) {
        var fds = [1]std.posix.pollfd{.{ .fd = file.handle, .events = 0, .revents = 0 }};
        const ready = std.posix.poll(&fds, 0) catch return null;
        if (ready > 0 and (fds[0].revents & std.posix.POLL.NVAL) != 0) return null;
    }
    return file.stat() catch null;
}

pub export fn safegguf_validate_path_v1(
    path_ptr: ?[*:0]const u8,
    options: ?*const OptionsV1,
    out_result: ?*Result,
) c_int {
    // 1. Strict options validation FIRST before any filesystem or path checks!
    if (validateOptions(options, out_result)) |code| return code;

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
    const endian_id = if (options) |o| o.endian else 2; // default auto

    // Regular-file target policy (CLI parity, src/main.zig): non-regular path
    // targets have no meaningful size for the sliding-window reader and would
    // otherwise surface as an opaque mid-parse I/O error; reject them up front
    // on the stat-failure path (exit 74, E_FILE_STAT_FAILED).
    const opened = openRegularFile(path_slice) catch |e| {
        switch (e) {
            error.OpenFailed => populateResult(out_result, 74, "E_FILE_OPEN_FAILED", "io", "filesystem", "Failed to open file on disk"),
            error.StatFailed => populateResult(out_result, 74, "E_FILE_STAT_FAILED", "io", "filesystem", "Failed to query file metadata / stat"),
            error.NotRegularFile => populateResult(out_result, 74, "E_FILE_STAT_FAILED", "io", "filesystem", "Not a regular file"),
        }
        return 74;
    };
    defer opened.file.close();

    return validateInternal(opened.file, opened.size, options, profile_id, endian_id, out_result);
}

pub export fn safegguf_validate_fd_v1(
    handle_int: isize,
    options: ?*const OptionsV1,
    out_result: ?*Result,
) c_int {
    // 1. Strict options validation FIRST before any descriptor or filesystem checks!
    if (validateOptions(options, out_result)) |code| return code;

    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) {
        if (handle_int <= 0) {
            populateResult(out_result, 74, "E_INVALID_HANDLE", "io", "descriptor", "Invalid Windows file handle");
            return 74;
        }
    } else {
        // Descriptors are c_int-sized; out-of-range values cannot be open fds
        // and must not reach the handle conversion (which would trap).
        if (handle_int < 0 or handle_int > std.math.maxInt(std.fs.File.Handle)) {
            populateResult(out_result, 74, "E_INVALID_FD", "io", "descriptor", "Invalid POSIX file descriptor");
            return 74;
        }
    }

    const handle: std.fs.File.Handle = if (builtin.os.tag == .windows)
        @as(std.fs.File.Handle, @ptrFromInt(@as(usize, @bitCast(handle_int))))
    else
        @as(std.fs.File.Handle, @intCast(handle_int));

    const file = std.fs.File{ .handle = handle };
    const stat = fstatForeign(file) orelse {
        populateResult(out_result, 74, "E_FD_STAT_FAILED", "io", "descriptor", "Failed to fstat file descriptor");
        return 74;
    };

    // Regular-file target policy (CLI parity): fstat kind is the cross-platform
    // S_ISREG equivalent. Descriptors cannot name a symlink once opened with a
    // normal open; an O_PATH|O_NOFOLLOW fd that still resolves to one reports
    // .sym_link here and is rejected like any other non-regular target.
    if (stat.kind != .file) {
        populateResult(out_result, 74, "E_FD_STAT_FAILED", "io", "descriptor", "Not a regular file");
        return 74;
    }

    const orig_pos = file.getPos() catch null;
    defer {
        if (orig_pos) |pos| {
            file.seekTo(pos) catch {};
        }
    }

    const profile_id = if (options) |o| o.profile else 1; // default llama-cpp
    const endian_id = if (options) |o| o.endian else 2; // default auto

    return validateInternal(file, stat.size, options, profile_id, endian_id, out_result);
}

pub export fn safegguf_validate_path(
    path_ptr: ?[*:0]const u8,
    profile_id: c_int,
    endian_id: c_int,
) c_int {
    // 1. Strict enum validation FIRST!
    if (validateEnums(profile_id, endian_id, null)) |code| return code;

    const ptr = path_ptr orelse return 64;
    const path_slice = std.mem.span(ptr);
    if (path_slice.len == 0 or path_slice.len > 4096) return 74;

    // Same regular-file target policy as the v1 entry point (CLI parity).
    const opened = openRegularFile(path_slice) catch return 74;
    defer opened.file.close();
    return validateInternal(opened.file, opened.size, null, profile_id, endian_id, null);
}

pub export fn safegguf_validate_fd(
    handle_int: isize,
    profile_id: c_int,
    endian_id: c_int,
) c_int {
    // 1. Strict enum validation FIRST!
    if (validateEnums(profile_id, endian_id, null)) |code| return code;

    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) {
        if (handle_int <= 0) return 74;
    } else {
        if (handle_int < 0 or handle_int > std.math.maxInt(std.fs.File.Handle)) return 74;
    }

    const handle: std.fs.File.Handle = if (builtin.os.tag == .windows)
        @as(std.fs.File.Handle, @ptrFromInt(@as(usize, @bitCast(handle_int))))
    else
        @as(std.fs.File.Handle, @intCast(handle_int));

    const file = std.fs.File{ .handle = handle };
    const stat = fstatForeign(file) orelse return 74;

    // Same regular-file target policy as the v1 entry point (CLI parity).
    if (stat.kind != .file) return 74;

    const orig_pos = file.getPos() catch null;
    defer {
        if (orig_pos) |pos| {
            file.seekTo(pos) catch {};
        }
    }

    return validateInternal(file, stat.size, null, profile_id, endian_id, null);
}
