const std = @import("std");
const types = @import("../gguf/types.zig");
const err = @import("../gguf/error.zig");

pub fn checkedAdd(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b) catch error.ArithmeticOverflow;
}

pub fn checkedMul(a: u64, b: u64) !u64 {
    return std.math.mul(u64, a, b) catch error.ArithmeticOverflow;
}

pub fn checkedDiv(a: u64, b: u64) !u64 {
    if (b == 0) return error.ArithmeticOverflow;
    return a / b;
}

pub fn checkedAlignUp(value: u64, alignment: u64) !u64 {
    if (alignment == 0 or alignment % 8 != 0) return error.InvalidAlignment;
    const remainder = value % alignment;
    if (remainder == 0) return value;
    return checkedAdd(value, alignment - remainder);
}

pub fn checkedProduct(dims: []const u64) !u64 {
    if (dims.len == 0) return error.InvalidDimensionCount;
    var product: u64 = 1;
    for (dims) |d| {
        if (d == 0) return error.ArithmeticOverflow;
        product = try checkedMul(product, d);
    }
    return product;
}

pub fn computeTensorBytes(dims: []const u64, tensor_type: u32) !u64 {
    const traits = types.getTypeTraits(tensor_type) orelse return error.InvalidTensorType;
    if (dims.len > 4) return error.InvalidDimensionCount;

    if (dims.len == 0) {
        // In llama.cpp / ggml, n_dims == 0 represents a scalar tensor (1 element)
        if (traits.block_size != 1) {
            return error.BlockDivisibilityViolation;
        }
        return traits.type_size;
    }

    // Invariant: Row/block divisibility (ne[0] must be divisible by block_size)
    if (dims[0] % traits.block_size != 0) {
        return error.BlockDivisibilityViolation;
    }

    const n_elements = try checkedProduct(dims);
    const n_blocks = try checkedDiv(n_elements, traits.block_size);
    const nbytes = try checkedMul(n_blocks, traits.type_size);
    return nbytes;
}
