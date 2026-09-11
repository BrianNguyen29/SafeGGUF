const std = @import("std");
const err = @import("error.zig");

/// Dual-toolchain shim: Zig 0.13 spells `std.mem.Allocator` vtable alignment as
/// `u8`; Zig 0.14+ uses `std.mem.Alignment`. The pinned production toolchain
/// remains 0.13.0; the coverage-fuzz lane (A5) compiles this module with the
/// fuzz-only 0.14.1 toolchain against the same source. No runtime behavior
/// differs on either toolchain.
const VtableAlignment = if (@hasDecl(std.mem, "Alignment")) std.mem.Alignment else u8;

pub const Limits = struct {
    max_tensors: u64 = 1_000_000,
    max_metadata_entries: u64 = 1_000_000,
    max_string_bytes: u64 = 65536,
    max_tensor_name_bytes: u64 = 64,
    max_dimensions: u32 = 4,
    max_array_elements: u64 = 10_000_000,
    /// Structural sanity ceiling for variable-length element arrays
    /// (array[string] / nested arrays). Real tokenizers exceed the former
    /// 100_000 bound: Qwen2 declares 151,936 tokens and Llama 3 ~128K, so the
    /// default must admit them. This is a fail-before-you-scan sanity bound,
    /// NOT the primary DoS control: max_work_units, max_scanned_bytes and
    /// max_total_alloc_bytes remain the budgets that bound actual resource use.
    max_variable_array_elements: u64 = 1_000_000,
    max_metadata_depth: u32 = 16,
    max_total_alloc_bytes: u64 = 128 * 1024 * 1024,
    max_work_units: u64 = 10_000_000,
    max_scanned_bytes: u64 = 256 * 1024 * 1024,
};

pub const WorkBudget = struct {
    max_work_units: u64 = 10_000_000,
    consumed_units: u64 = 0,
    max_scanned_bytes: u64 = 256 * 1024 * 1024,
    consumed_scanned_bytes: u64 = 0,
    /// Optional diagnostics channel: when non-null, parse/structural raise
    /// sites record a ParseContext snapshot before returning errors. This is
    /// the only mutable pointer already threaded into parseDocument and
    /// validateStructural, so it carries the Validator-held context without
    /// changing their signatures. Null for low-level (non-Validator) users.
    ctx: ?*err.ParseContext = null,

    pub fn init(max_units: u64) WorkBudget {
        return .{
            .max_work_units = max_units,
            .consumed_units = 0,
            .max_scanned_bytes = 256 * 1024 * 1024,
            .consumed_scanned_bytes = 0,
        };
    }

    pub fn initWithLimits(max_units: u64, max_bytes: u64) WorkBudget {
        return .{
            .max_work_units = max_units,
            .consumed_units = 0,
            .max_scanned_bytes = max_bytes,
            .consumed_scanned_bytes = 0,
        };
    }

    pub fn consume(self: *WorkBudget, units: u64) error{ResourceLimitExceeded}!void {
        const new_consumed = std.math.add(u64, self.consumed_units, units) catch return error.ResourceLimitExceeded;
        if (new_consumed > self.max_work_units) {
            return error.ResourceLimitExceeded;
        }
        self.consumed_units = new_consumed;
    }

    pub fn consumeBytes(self: *WorkBudget, bytes: u64) error{ResourceLimitExceeded}!void {
        const new_consumed = std.math.add(u64, self.consumed_scanned_bytes, bytes) catch return error.ResourceLimitExceeded;
        if (new_consumed > self.max_scanned_bytes) {
            return error.ResourceLimitExceeded;
        }
        self.consumed_scanned_bytes = new_consumed;
    }
};

/// QuotaAllocator strictly tracks live and peak memory allocation
/// and enforces a hard ceiling across all subsystem allocations.
pub const QuotaAllocator = struct {
    parent_allocator: std.mem.Allocator,
    max_bytes: u64,
    allocated_bytes: u64 = 0,
    peak_bytes: u64 = 0,
    quota_exceeded: bool = false,

    pub fn init(parent: std.mem.Allocator, max_bytes: u64) QuotaAllocator {
        return .{
            .parent_allocator = parent,
            .max_bytes = max_bytes,
        };
    }

    pub fn isQuotaExceeded(self: *const QuotaAllocator) bool {
        return self.quota_exceeded;
    }

    pub fn resetQuotaExceeded(self: *QuotaAllocator) void {
        self.quota_exceeded = false;
    }

    pub fn allocator(self: *QuotaAllocator) std.mem.Allocator {
        // Zig 0.14+ requires the `remap` vtable entry; 0.13 rejects it. The
        // conditional is comptime-known, so only the matching branch is
        // semantically analyzed on each toolchain.
        const vtable: *const std.mem.Allocator.VTable = if (comptime @hasField(std.mem.Allocator.VTable, "remap"))
            &.{ .alloc = alloc, .resize = resize, .free = free, .remap = remap }
        else
            &.{ .alloc = alloc, .resize = resize, .free = free };
        return .{
            .ptr = self,
            .vtable = vtable,
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: VtableAlignment, ret_addr: usize) ?[*]u8 {
        const self: *QuotaAllocator = @ptrCast(@alignCast(ctx));
        const new_total = std.math.add(u64, self.allocated_bytes, len) catch {
            self.quota_exceeded = true;
            return null;
        };
        if (new_total > self.max_bytes) {
            self.quota_exceeded = true;
            return null;
        }

        const result = self.parent_allocator.rawAlloc(len, ptr_align, ret_addr) orelse return null;
        self.allocated_bytes = new_total;
        if (self.allocated_bytes > self.peak_bytes) {
            self.peak_bytes = self.allocated_bytes;
        }
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: VtableAlignment, new_len: usize, ret_addr: usize) bool {
        const self: *QuotaAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len) {
            const diff = new_len - buf.len;
            const new_total = std.math.add(u64, self.allocated_bytes, diff) catch {
                self.quota_exceeded = true;
                return false;
            };
            if (new_total > self.max_bytes) {
                self.quota_exceeded = true;
                return false;
            }

            if (self.parent_allocator.rawResize(buf, buf_align, new_len, ret_addr)) {
                self.allocated_bytes = new_total;
                if (self.allocated_bytes > self.peak_bytes) {
                    self.peak_bytes = self.allocated_bytes;
                }
                return true;
            }
            return false;
        } else {
            const diff = buf.len - new_len;
            if (self.parent_allocator.rawResize(buf, buf_align, new_len, ret_addr)) {
                self.allocated_bytes -= diff;
                return true;
            }
            return false;
        }
    }

    /// Zig 0.14+ vtable entry: in-place resize with relocation allowed. This
    /// allocator never relocates (quota accounting would need to move), so it
    /// either resizes in place or reports "allocate + copy" via null.
    fn remap(ctx: *anyopaque, buf: []u8, buf_align: VtableAlignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        if (resize(ctx, buf, buf_align, new_len, ret_addr)) return buf.ptr;
        return null;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: VtableAlignment, ret_addr: usize) void {
        const self: *QuotaAllocator = @ptrCast(@alignCast(ctx));
        self.parent_allocator.rawFree(buf, buf_align, ret_addr);
        if (self.allocated_bytes >= buf.len) {
            self.allocated_bytes -= buf.len;
        } else {
            self.allocated_bytes = 0;
        }
    }
};
