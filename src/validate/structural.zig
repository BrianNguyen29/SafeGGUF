const std = @import("std");
const err = @import("../gguf/error.zig");
const parser = @import("../gguf/parser.zig");
const arithmetic = @import("arithmetic.zig");

pub const TensorRange = struct {
    name: []const u8,
    start: u64,
    end: u64,
};

fn compareTensorRanges(ctx: void, a: TensorRange, b: TensorRange) bool {
    _ = ctx;
    return a.start < b.start;
}

pub fn validateStructural(allocator: std.mem.Allocator, doc: parser.Document) err.ParseError!void {
    if (doc.tensor_data_base % doc.alignment != 0) {
        return err.ParseError.InvalidAlignment;
    }

    if (doc.tensors.len == 0) return;

    const ranges = allocator.alloc(TensorRange, doc.tensors.len) catch return err.ParseError.OutOfMemory;
    defer allocator.free(ranges);

    for (doc.tensors, 0..) |tensor, i| {
        if (tensor.offset % doc.alignment != 0) {
            return err.ParseError.MisalignedTensor;
        }

        const abs_offset = try arithmetic.checkedAdd(doc.tensor_data_base, tensor.offset);
        const nbytes = try arithmetic.computeTensorBytes(tensor.dimensions, tensor.tensor_type);
        const end_offset = try arithmetic.checkedAdd(abs_offset, nbytes);

        if (end_offset > doc.file_size) {
            return err.ParseError.TensorOutOfBounds;
        }

        ranges[i] = TensorRange{
            .name = tensor.name,
            .start = abs_offset,
            .end = end_offset,
        };
    }

    std.mem.sort(TensorRange, ranges, {}, compareTensorRanges);

    var prev_end: u64 = 0;
    for (ranges, 0..) |range, i| {
        if (i > 0 and range.start < prev_end) {
            return err.ParseError.TensorOverlap;
        }
        prev_end = range.end;
    }
}
