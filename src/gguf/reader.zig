const std = @import("std");
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

    pub fn init(file: std.fs.File, file_size: u64) FileReader {
        return .{ .file = file, .file_size = file_size };
    }

    pub fn reader(self: *const FileReader) Reader {
        return Reader{
            .ptr = @constCast(@ptrCast(self)),
            .vtable = &vtable,
            .size = self.file_size,
        };
    }

    const vtable = Reader.VTable{
        .readBytes = readBytesImpl,
    };

    fn readBytesImpl(ctx: *anyopaque, offset: u64, dest: []u8) err.ParseError!void {
        const self: *const FileReader = @ptrCast(@alignCast(ctx));
        const n = self.file.preadAll(dest, offset) catch return err.ParseError.IoError;
        if (n < dest.len) return err.ParseError.UnexpectedEof;
    }
};
