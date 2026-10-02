const std = @import("std");
const build_options = @import("build_options");
const safegguf = @import("safegguf");

const types = safegguf.types;
const reader_mod = safegguf.reader;
const limits = safegguf.limits;
const err_types = safegguf.error_types;
const Validator = safegguf.Validator;

const version_z: [:0]const u8 = std.fmt.comptimePrint("{s}", .{build_options.version});

pub export fn safegguf_version() [*:0]const u8 {
    return version_z.ptr;
}

/// Maps a result `error_code` (the implementation identifier emitted by this
/// ABI, e.g. "ArithmeticOverflow", or a compatibility code such as
/// "E_FILE_OPEN_FAILED") to its canonical `SGGUF_E_*` public code. Canonical
/// codes already in the namespace are returned unchanged. The returned pointer
/// is a static string and must not be freed; NULL and unmapped identifiers
/// return SGGUF_E_UNKNOWN.
pub export fn safegguf_canonical_error_code(error_code: ?[*:0]const u8) [*:0]const u8 {
    const unknown = safegguf.error_types.public_codes.unknown;
    const ptr = error_code orelse return unknown.ptr;
    const span = std.mem.span(ptr);
    if (safegguf.error_types.isPublicCode(span)) return ptr;
    const canonical = safegguf.error_types.canonicalFromLegacy(span) orelse return unknown.ptr;
    return canonical.ptr;
}

/// Resolves a `safegguf_result_t` to its canonical `SGGUF_E_*` code,
/// including the context-dependent detail the compatibility `error_code`
/// cannot carry: a rejection raised by the llama.cpp dimension-product guard
/// keeps the legacy `error_code` "CompatibilityViolation" (byte-for-byte)
/// while this accessor returns SGGUF_E_DIMENSION_OVERFLOW, distinguishing it
/// from a true checked-arithmetic wrap. For every other result this is
/// equivalent to `safegguf_canonical_error_code(result->error_code)`.
/// Canonical codes already in the namespace are resolved to their static
/// string; NULL and unmapped results return SGGUF_E_UNKNOWN. The returned
/// pointer is a static string that must not be freed.
pub export fn safegguf_result_canonical_error_code(result: ?*const Result) [*:0]const u8 {
    const unknown = err_types.public_codes.unknown;
    const res = result orelse return unknown.ptr;
    const code = std.mem.sliceTo(&res.error_code, 0);
    const message = std.mem.sliceTo(&res.message, 0);
    if (std.mem.eql(u8, code, "CompatibilityViolation") and
        std.mem.eql(u8, message, err_types.dimension_overflow_message))
    {
        return err_types.public_codes.dimension_overflow.ptr;
    }
    if (err_types.canonicalCodeRef(code)) |canonical| return canonical.ptr;
    const canonical = err_types.canonicalFromLegacy(code) orelse return unknown.ptr;
    return canonical.ptr;
}

/// Options layout as first shipped in v1 (48 bytes on LP64): the unchanged
/// prefix of the current `OptionsV1`. It exists only as the `struct_size`
/// contract old callers still satisfy; it is never dereferenced as a whole.
pub const OptionsV1Legacy = extern struct {
    struct_size: u32,
    profile: c_int,
    endian: c_int,
    max_alloc_bytes: u64,
    max_work_units: u64,
    max_scanned_bytes: u64,
    reserved: ?*anyopaque,
};

/// v1.1 options layout: the v1.0 prefix plus appended input-size and
/// stability controls. Retained as an accepted `struct_size` so callers
/// compiled against the v1.1 layout keep their contract; it is never
/// dereferenced as a whole.
pub const OptionsV1_1 = extern struct {
    struct_size: u32,
    profile: c_int,
    endian: c_int,
    max_alloc_bytes: u64,
    max_work_units: u64,
    max_scanned_bytes: u64,
    reserved: ?*anyopaque,
    max_file_size_bytes: u64,
    require_stable_file: u32,
};

/// Current v1.2 options layout: the v1.1 fields plus appended metadata
/// string-cap and key-policy relief controls. Appending fields keeps the ABI
/// backward compatible: callers pass the `struct_size` of the layout they were
/// compiled against, access to the appended fields is gated on that size, and
/// a legacy caller keeps the old defaults (unlimited input, stability off,
/// default string cap, strict key grammar). The caller owns the struct and
/// must keep it, and any `reserved` pointer it contains, valid only for the
/// duration of the call; the library neither retains nor frees it. Calls are
/// independent and thread-safe.
pub const OptionsV1 = extern struct {
    struct_size: u32,
    profile: c_int,
    endian: c_int,
    max_alloc_bytes: u64,
    max_work_units: u64,
    max_scanned_bytes: u64,
    reserved: ?*anyopaque,
    /// Admission ceiling in bytes for the input stream, checked before the
    /// first read. 0 = use the default (`Limits.max_file_size_bytes`,
    /// unlimited), preserving v1.0 behavior.
    max_file_size_bytes: u64,
    /// Input-stability control: 0 = off (default), 1 = require the opened
    /// file's identity (device/inode/size/mtime/ctime) to be unchanged across
    /// validation, otherwise REJECT (2) with E_FileChangedDuringValidation.
    require_stable_file: u32,
    /// Appended (v1.2): metadata key/string byte cap. 0 = use the env/default
    /// (`Limits.max_string_bytes`, 65536), preserving prior behavior for
    /// callers that zero the field.
    max_string_bytes: u64,
    /// Appended (v1.2): metadata key grammar policy. 0 = use the env/default
    /// (strict), 1 = strict, 2 = lenient.
    key_policy: u32,
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
        // struct_size gating: accept every shipped layout (v1.0, v1.1, and
        // the current v1.2) so callers compiled against an older header stay
        // valid. Unknown sizes stay fail-closed.
        const struct_size = opts.struct_size;
        if (struct_size != @sizeOf(OptionsV1Legacy) and
            struct_size != @sizeOf(OptionsV1_1) and
            struct_size != @sizeOf(OptionsV1))
        {
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
        // Appended fields are readable only when struct_size covers them; a
        // legacy caller has no such storage (validated above, so this is
        // exactly one of the known shipped sizes today).
        if (hasV11Controls(opts)) {
            if (opts.require_stable_file > 1) {
                populateResult(out_result, 64, "E_USAGE_INVALID_OPTIONS", "usage", "options", "Invalid require_stable_file: must be 0 (off) or 1 (require stable file)");
                return 64;
            }
        }
        if (hasV12Controls(opts)) {
            if (opts.key_policy > 2) {
                populateResult(out_result, 64, "E_USAGE_INVALID_OPTIONS", "usage", "options", "Invalid key_policy: must be 0 (use default), 1 (strict), or 2 (lenient)");
                return 64;
            }
        }
    }
    return null;
}

/// True when `opts.struct_size` covers the fields appended in v1.1. All other
/// sizes are rejected by `validateOptions` first, so this only distinguishes
/// legacy callers from callers that pass a v1.1-or-newer layout.
fn hasV11Controls(opts: *const OptionsV1) bool {
    return opts.struct_size >= @sizeOf(OptionsV1_1);
}

/// True when `opts.struct_size` covers the fields appended in v1.2. Reads of
/// `max_string_bytes` / `key_policy` must stay gated on this: a v1.1 caller's
/// struct ends before them.
fn hasV12Controls(opts: *const OptionsV1) bool {
    return opts.struct_size >= @sizeOf(OptionsV1);
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

    // Resource limits: start from env / defaults, then override with options if specified
    var lim = limits.Limits.initFromEnv();
    var require_stable_file = false;
    if (options) |opts| {
        if (opts.max_alloc_bytes > 0) lim.max_total_alloc_bytes = opts.max_alloc_bytes;
        if (opts.max_work_units > 0) lim.max_work_units = opts.max_work_units;
        if (opts.max_scanned_bytes > 0) lim.max_scanned_bytes = opts.max_scanned_bytes;
        if (hasV11Controls(opts)) {
            // 0 = use the default (unlimited), matching Limits' default and
            // preserving v1.0 behavior for callers that zero the field.
            if (opts.max_file_size_bytes > 0) lim.max_file_size_bytes = opts.max_file_size_bytes;
            require_stable_file = opts.require_stable_file != 0;
        }
        if (hasV12Controls(opts)) {
            // 0 = use the env/default (string cap 65536, strict key grammar),
            // preserving behavior for callers that zero the appended fields.
            if (opts.max_string_bytes > 0) lim.max_string_bytes = opts.max_string_bytes;
            switch (opts.key_policy) {
                1 => lim.key_policy = .strict,
                2 => lim.key_policy = .lenient,
                else => {},
            }
        }
    }

    // Opt-in stable-file check (require_stable_file): snapshot the open
    // handle's identity before the first read so it can be re-verified after a
    // PASS, mirroring the CLI's --require-stable-file. Off by default, so
    // legacy callers are unchanged. It fstats the already-open handle (never
    // re-opens by path) and bounds device/inode/size/mtime/ctime mutation; it
    // is not cryptographic immutability (see reader.FileIdentity).
    var stable_identity: ?reader_mod.FileIdentity = null;
    if (require_stable_file) {
        stable_identity = reader_mod.FileIdentity.capture(file) catch {
            populateResult(out_result, 74, "E_FILE_STAT_FAILED", "io", "filesystem", "Failed to query file metadata / stat");
            return 74;
        };
    }

    var buffered_reader = reader_mod.BufferedReader.init(file, file_size);
    const r = buffered_reader.reader();

    const endian: std.builtin.Endian = switch (endian_id) {
        1 => .big,
        2 => safegguf.parser.detectEndianness(r) orelse .little,
        else => .little,
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var val = Validator.init(gpa.allocator(), lim, profile);
    val.endian = endian;

    // Diagnostics channel: parse/structural raise sites snapshot their
    // position and any additive canonical detail (see
    // `error_types.public_codes.dimension_overflow`) into parse_ctx so a
    // rejection can be reported with full context, mirroring the CLI.
    var parse_ctx = err_types.ParseContext{};
    val.work_budget.ctx = &parse_ctx;

    var doc = val.validate(r) catch |e| {
        const quota_hit = (e == error.OutOfMemory and val.quota_alloc.isQuotaExceeded());
        const exit_code: c_int = switch (e) {
            error.IoError => 74,
            error.OutOfMemory => if (quota_hit) 2 else 70,
            else => 2,
        };
        const cat = if (quota_hit) "resource" else @tagName(safegguf.error_types.categoryOf(e));
        // Admission rejections surface the documented E_FileTooLarge code
        // (CLI taxonomy); other validator errors keep their bare @errorName.
        const err_name = if (quota_hit)
            "TotalAllocationLimitExceeded"
        else if (e == error.FileTooLarge)
            "E_FileTooLarge"
        else
            @errorName(e);
        // The legacy error_code stays byte-for-byte; the context-dependent
        // canonical detail is carried out-of-band by the result message and
        // resolved by safegguf_result_canonical_error_code().
        const msg = if (parse_ctx.canonical_detail != null)
            err_types.dimension_overflow_message
        else if (quota_hit)
            "Configured memory allocation quota exceeded"
        else
            safegguf.error_types.messageOf(e);
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

    // Stable-file mode: a PASS verdict must describe the bytes actually read,
    // so re-fstat the same handle and reject when any identity field moved
    // while the file was being validated, mirroring the CLI. Only the PASS
    // path needs the check: every failure path already exits non-zero for
    // this file.
    if (stable_identity) |before| {
        before.verifyUnchanged(file) catch |e| switch (e) {
            error.FileChanged => {
                populateResult(
                    out_result,
                    2,
                    "E_FileChangedDuringValidation",
                    "io",
                    "stability",
                    "File identity changed while it was being validated (device, inode, size, or timestamps differ)",
                );
                return 2; // REJECT
            },
            error.FileStatFailed => {
                populateResult(out_result, 74, "E_FILE_STAT_FAILED", "io", "filesystem", "Failed to query file metadata / stat");
                return 74; // EX_IOERR
            },
        };
    }

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
/// must not be handed to the wrapper: the raw fstat call is issued here and
/// every failure, EBADF included, maps to null instead of trapping. Returns
/// null when the descriptor is invalid or the stat itself fails. Closing a
/// descriptor concurrently with the call remains the caller's contract
/// violation; fd ownership stays with the caller for the duration of the call.
///
/// The previous implementation gated `file.stat()` with poll()/POLLNVAL, but
/// that gate is not portable: on macOS 14 a closed descriptor passes it (poll
/// does not reliably report POLLNVAL for it) and then reaches the wrapper's
/// EBADF `unreachable`, aborting the host process (observed in CI on the
/// fd-v1-closed probe while Linux returned 74). A direct fstat has no
/// platform-dependent readiness semantics and removes the probe-to-stat race
/// window as well.
fn fstatForeign(file: std.fs.File) ?std.fs.File.Stat {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows) {
        return file.stat() catch null;
    }
    var st = std.mem.zeroes(std.posix.Stat);
    // Mirrors the large-file ABI selection std.posix.fstat performs internally
    // (that constant is private to std); both symbols fill `std.posix.Stat`.
    const lfs64_abi = builtin.os.tag == .linux and builtin.link_libc and builtin.abi.isGnu();
    const fstat_sym = if (lfs64_abi) std.posix.system.fstat64 else std.posix.system.fstat;
    switch (std.posix.errno(fstat_sym(file.handle, &st))) {
        .SUCCESS => return std.fs.File.Stat.fromSystem(st),
        else => return null,
    }
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
