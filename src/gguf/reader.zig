const std = @import("std");
const builtin = @import("builtin");
const err = @import("error.zig");

pub const Reader = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    size: u64,

    pub const VTable = struct {
        readBytes: *const fn (ctx: *anyopaque, offset: u64, dest: []u8) err.ParseError!void,
    };

    pub fn readBytes(self: Reader, offset: u64, dest: []u8) err.ParseError!void {
        if (dest.len == 0) return;
        const end = std.math.add(u64, offset, dest.len) catch return err.ParseError.UnexpectedEof;
        if (end > self.size) return err.ParseError.UnexpectedEof;
        return self.vtable.readBytes(self.ptr, offset, dest);
    }

    pub fn readInt(self: Reader, comptime T: type, offset: u64, endian: std.builtin.Endian) err.ParseError!T {
        var buf: [@sizeOf(T)]u8 = undefined;
        try self.readBytes(offset, &buf);
        return std.mem.readInt(T, &buf, endian);
    }

    pub fn readFloat(self: Reader, comptime T: type, offset: u64, endian: std.builtin.Endian) err.ParseError!T {
        const IntType = switch (T) {
            f32 => u32,
            f64 => u64,
            else => @compileError("Unsupported float type"),
        };
        const raw = try self.readInt(IntType, offset, endian);
        return @bitCast(raw);
    }
};

pub const SliceReader = struct {
    data: []const u8,

    pub fn init(data: []const u8) SliceReader {
        return .{ .data = data };
    }

    pub fn reader(self: *const SliceReader) Reader {
        return Reader{
            .ptr = @constCast(@ptrCast(self)),
            .vtable = &vtable,
            .size = self.data.len,
        };
    }

    const vtable = Reader.VTable{
        .readBytes = readBytesImpl,
    };

    fn readBytesImpl(ctx: *anyopaque, offset: u64, dest: []u8) err.ParseError!void {
        const self: *const SliceReader = @ptrCast(@alignCast(ctx));
        const end = std.math.add(u64, offset, dest.len) catch return err.ParseError.UnexpectedEof;
        if (end > self.data.len) return err.ParseError.UnexpectedEof;
        @memcpy(dest, self.data[offset..end]);
    }
};

pub const FileReader = struct {
    file: std.fs.File,
    file_size: u64,
    /// Test-only instrumentation: count of underlying `preadAll` calls issued
    /// by this reader. Gated on `builtin.is_test`, so production binaries never
    /// write it (the increment compiles out; the field is only layout). The
    /// bench reads it to gate sliding-cache assertions without procfs.
    backend_reads: u64 = 0,

    pub fn init(file: std.fs.File, file_size: u64) FileReader {
        return .{ .file = file, .file_size = file_size };
    }

    pub fn reader(self: *FileReader) Reader {
        return Reader{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
            .size = self.file_size,
        };
    }

    const vtable = Reader.VTable{
        .readBytes = readBytesImpl,
    };

    fn readBytesImpl(ctx: *anyopaque, offset: u64, dest: []u8) err.ParseError!void {
        const self: *FileReader = @ptrCast(@alignCast(ctx));
        const n = self.file.preadAll(dest, offset) catch return err.ParseError.IoError;
        if (builtin.is_test) self.backend_reads += 1;
        if (n < dest.len) return err.ParseError.UnexpectedEof;
    }
};

/// BufferedReader maintains a 64KB sliding cache window to eliminate
/// individual pread syscalls during descriptor and metadata decoding.
pub const BufferedReader = struct {
    file: std.fs.File,
    file_size: u64,
    window_start: u64 = 0,
    window_len: usize = 0,
    window_buf: [65536]u8 = undefined,
    /// Test-only instrumentation: count of underlying `preadAll` calls issued
    /// (window slides plus large-read bypasses). Gated on `builtin.is_test`;
    /// see FileReader.backend_reads.
    backend_reads: u64 = 0,

    pub fn init(file: std.fs.File, file_size: u64) BufferedReader {
        return .{
            .file = file,
            .file_size = file_size,
            .window_start = 0,
            .window_len = 0,
        };
    }

    pub fn reader(self: *BufferedReader) Reader {
        return Reader{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
            .size = self.file_size,
        };
    }

    const vtable = Reader.VTable{
        .readBytes = readBytesImpl,
    };

    fn readBytesImpl(ctx: *anyopaque, offset: u64, dest: []u8) err.ParseError!void {
        const self: *BufferedReader = @ptrCast(@alignCast(ctx));

        // 1. Cache hit inside current sliding window
        if (self.window_len > 0 and offset >= self.window_start) {
            const rel_offset = offset - self.window_start;
            const rel_end = std.math.add(u64, rel_offset, dest.len) catch return err.ParseError.UnexpectedEof;
            if (rel_end <= self.window_len) {
                @memcpy(dest, self.window_buf[rel_offset..rel_end]);
                return;
            }
        }

        // 2. Large read bypassing cache
        if (dest.len >= self.window_buf.len) {
            const n = self.file.preadAll(dest, offset) catch return err.ParseError.IoError;
            if (builtin.is_test) self.backend_reads += 1;
            if (n < dest.len) return err.ParseError.UnexpectedEof;
            return;
        }

        // 3. Cache miss: slide window to offset and prefetch 64KB
        const remaining = std.math.sub(u64, self.file_size, offset) catch return err.ParseError.UnexpectedEof;
        self.window_start = offset;
        const to_read = @min(@as(u64, self.window_buf.len), remaining);
        const n = self.file.preadAll(self.window_buf[0..to_read], offset) catch return err.ParseError.IoError;
        if (builtin.is_test) self.backend_reads += 1;
        self.window_len = n;

        if (dest.len > self.window_len) return err.ParseError.UnexpectedEof;
        @memcpy(dest, self.window_buf[0..dest.len]);
    }
};

/// Coarse identity/metadata snapshot of an open file handle, backing the
/// optional stable-file check (`safegguf inspect --require-stable-file`):
/// capture before validation and verify the same handle after it. Any change
/// to device, inode, size, mtime or ctime is reported as `error.FileChanged`.
///
/// Scope and limits: this is a mutation-bounding check, not cryptographic
/// immutability. It fstats the already-open handle (never re-opens by path),
/// so it observes mutation of the exact inode being validated rather than
/// replacement of the path; content rewritten in place with the original size
/// and restored timestamps is indistinguishable and is not detected. A field
/// a platform does not expose (no device id on Windows) stays at its neutral
/// value on both sides of the comparison.
pub const FileIdentity = struct {
    /// Device identifier where the platform exposes one; 0 otherwise.
    dev: u64 = 0,
    inode: u64 = 0,
    size: u64 = 0,
    mtime_ns: i128 = 0,
    ctime_ns: i128 = 0,

    /// fstat snapshot of `file`. Windows has no `std.posix.fstat`, so the
    /// portable `File.stat()` fields are used there instead (no device id).
    pub fn capture(file: std.fs.File) error{FileStatFailed}!FileIdentity {
        if (builtin.os.tag == .windows) {
            const stat = file.stat() catch return error.FileStatFailed;
            return .{
                .inode = @intCast(stat.inode),
                .size = stat.size,
                .mtime_ns = stat.mtime,
                .ctime_ns = stat.ctime,
            };
        }
        const stat = std.posix.fstat(file.handle) catch return error.FileStatFailed;
        const portable = std.fs.File.Stat.fromSystem(stat);
        return .{
            .dev = @intCast(stat.dev),
            .inode = @intCast(portable.inode),
            .size = portable.size,
            .mtime_ns = portable.mtime,
            .ctime_ns = portable.ctime,
        };
    }

    pub fn eql(a: FileIdentity, b: FileIdentity) bool {
        return a.dev == b.dev and a.inode == b.inode and a.size == b.size and
            a.mtime_ns == b.mtime_ns and a.ctime_ns == b.ctime_ns;
    }

    /// Re-fstats `file` and returns `error.FileChanged` when any snapshot field
    /// moved since capture; `error.FileStatFailed` when the re-stat fails.
    pub fn verifyUnchanged(self: FileIdentity, file: std.fs.File) error{ FileStatFailed, FileChanged }!void {
        const after = try capture(file);
        if (!eql(self, after)) return error.FileChanged;
    }
};

/// Result of opening a path whose resolved target is a regular file.
pub const OpenedRegularFile = struct {
    file: std.fs.File,
    size: u64,
};

/// Shared open error set: the platform open errors plus the two post-open
/// checks. The CLI (src/main.zig) and the C ABI (src/c_api.zig) surface the
/// same target policy through `openRegularFile`.
pub const OpenRegularFileError = std.fs.File.OpenError || error{
    /// The opened descriptor could not be queried.
    StatFailed,
    /// The resolved target is not a regular file (directory, FIFO, socket,
    /// character/block device, ...).
    NotRegularFile,
};

/// Opens `path` and returns it only when the resolved target is a regular
/// file. Shared by the CLI (src/main.zig) and the C ABI (src/c_api.zig) so
/// both enforce the same target policy and the same blocking behavior.
///
/// Symlink policy: symlinks are followed (std.fs.Dir.openFile resolves links).
/// The kind decision applies to the resolved target, so a symlink to a regular
/// model is accepted while a symlink to a directory/FIFO/device is rejected.
/// O_NOFOLLOW is deliberately not used: parity is defined on the resolved
/// target, and the non-blocking kind check makes the follow safe.
///
/// Blocking policy: on POSIX the open uses O_NONBLOCK so a FIFO with no writer
/// (or any target whose open would otherwise wait) returns immediately and is
/// then rejected by the kind check; O_NONBLOCK has no effect on regular-file
/// reads, so validation semantics are unchanged. O_NOCTTY avoids acquiring a
/// controlling terminal. The kind is taken from fstat on the just-opened
/// descriptor, so a concurrent path swap cannot bypass the policy.
pub fn openRegularFile(path: []const u8) OpenRegularFileError!OpenedRegularFile {
    if (builtin.os.tag == .windows) {
        // Windows has no O_NONBLOCK equivalent for path opens; stat.kind is
        // still the regular-file decision.
        const file = std.fs.cwd().openFile(path, .{}) catch |e| return e;
        errdefer file.close();
        const stat = file.stat() catch return error.StatFailed;
        if (stat.kind != .file) return error.NotRegularFile;
        return .{ .file = file, .size = stat.size };
    }
    const fd = std.posix.open(path, .{ .NONBLOCK = true, .NOCTTY = true, .CLOEXEC = true }, 0) catch |e| return e;
    const file = std.fs.File{ .handle = fd };
    errdefer file.close();
    const stat = file.stat() catch return error.StatFailed;
    if (stat.kind != .file) return error.NotRegularFile;
    return .{ .file = file, .size = stat.size };
}
