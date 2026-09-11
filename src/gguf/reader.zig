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
        const end = offset + dest.len;
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
            if (rel_offset + dest.len <= self.window_len) {
                @memcpy(dest, self.window_buf[rel_offset .. rel_offset + dest.len]);
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
        self.window_start = offset;
        const to_read = @min(@as(u64, self.window_buf.len), self.file_size - offset);
        const n = self.file.preadAll(self.window_buf[0..to_read], offset) catch return err.ParseError.IoError;
        if (builtin.is_test) self.backend_reads += 1;
        self.window_len = n;

        if (dest.len > self.window_len) return err.ParseError.UnexpectedEof;
        @memcpy(dest, self.window_buf[0..dest.len]);
    }
};
