const std = @import("std");
const err = @import("../gguf/error.zig");
const types = @import("../gguf/types.zig");
const parser = @import("../gguf/parser.zig");
const limits = @import("../gguf/limits.zig");
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

pub fn validateStructural(
    allocator: std.mem.Allocator,
    doc: parser.Document,
    profile: types.Profile,
    work_budget: *limits.WorkBudget,
) err.ParseError!void {
    if (doc.alignment == 0 or doc.alignment % 8 != 0) {
        return err.ParseError.InvalidAlignment;
    }
    if (profile == .llama_cpp and !std.math.isPowerOfTwo(doc.alignment)) {
        return err.ParseError.InvalidAlignment;
    }
    if (doc.tensor_data_base % doc.alignment != 0) {
        return err.ParseError.MisalignedTensor;
    }

    if (doc.tensors.len == 0) {
        if (profile == .gguf_spec and doc.tensor_data_base > doc.file_size) {
            return err.ParseError.UnexpectedEof;
        }
        return;
    }

    var seen_names = std.StringHashMap(void).init(allocator);
    defer seen_names.deinit();

    for (doc.tensors) |tensor| {
        try work_budget.consume(1);
        if (seen_names.contains(tensor.name)) {
            return err.ParseError.DuplicateTensorName;
        }
        seen_names.put(tensor.name, {}) catch return err.ParseError.OutOfMemory;
    }

    // Under llama.cpp profile: tensors must be strictly contiguous in descriptor order
    if (profile == .llama_cpp) {
        var expected_offset: u64 = 0;
        for (doc.tensors) |tensor| {
            try work_budget.consume(1);
            if (tensor.offset != expected_offset) {
                return err.ParseError.NonContiguousTensorOffset;
            }
            var element_product: u64 = 1;
            for (tensor.dimensions) |d| {
                if (d > @as(u64, std.math.maxInt(i64))) {
                    return err.ParseError.CompatibilityViolation;
                }
                if (@as(u64, std.math.maxInt(i64)) / d <= element_product) {
                    return err.ParseError.CompatibilityViolation;
                }
                element_product *= d;
            }
            const nbytes = try arithmetic.computeTensorBytes(tensor.dimensions, tensor.tensor_type);
            const unpadded_end = try arithmetic.checkedAdd(expected_offset, nbytes);
            expected_offset = try arithmetic.checkedAlignUp(unpadded_end, doc.alignment);
        }
        const required_file_end = try arithmetic.checkedAdd(doc.tensor_data_base, expected_offset);
        if (required_file_end > doc.file_size) {
            return err.ParseError.TensorOutOfBounds;
        }
    }

    const ranges = allocator.alloc(TensorRange, doc.tensors.len) catch return err.ParseError.OutOfMemory;
    defer allocator.free(ranges);

    for (doc.tensors, 0..) |tensor, i| {
        try work_budget.consume(1);
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

    // Charge sorting cost: O(N log2(N + 1))
    const n_tensors = doc.tensors.len;
    var log_factor: u64 = 1;
    if (n_tensors > 1) {
        log_factor = std.math.log2_int(usize, n_tensors) + 1;
    }
    const sort_units = std.math.mul(u64, n_tensors, log_factor) catch std.math.maxInt(u64);
    try work_budget.consume(sort_units);

    std.mem.sort(TensorRange, ranges, {}, compareTensorRanges);

    var prev_end: u64 = 0;
    for (ranges, 0..) |range, i| {
        try work_budget.consume(1);
        if (i > 0 and range.start < prev_end) {
            return err.ParseError.TensorOverlap;
        }
        prev_end = range.end;
    }
}
