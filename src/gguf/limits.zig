const std = @import("std");

pub const Limits = struct {
    max_tensors: u64 = 1_000_000,
    max_metadata_entries: u64 = 1_000_000,
    max_string_bytes: u64 = 65536,
    max_tensor_name_bytes: u64 = 64,
    max_dimensions: u32 = 4,
    max_array_elements: u64 = 10_000_000,
    max_variable_array_elements: u64 = 100_000,
    max_metadata_depth: u32 = 16,
    max_total_alloc_bytes: u64 = 128 * 1024 * 1024,
    max_work_units: u64 = 10_000_000,
};

pub const WorkBudget = struct {
    max_work_units: u64 = 10_000_000,
    consumed_units: u64 = 0,

    pub fn init(max_units: u64) WorkBudget {
        return .{
            .max_work_units = max_units,
            .consumed_units = 0,
        };
    }

    pub fn consume(self: *WorkBudget, units: u64) error{ResourceLimitExceeded}!void {
        const new_consumed = std.math.add(u64, self.consumed_units, units) catch return error.ResourceLimitExceeded;
        if (new_consumed > self.max_work_units) {
            return error.ResourceLimitExceeded;
        }
        self.consumed_units = new_consumed;
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
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
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

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
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

    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
        const self: *QuotaAllocator = @ptrCast(@alignCast(ctx));
        self.parent_allocator.rawFree(buf, buf_align, ret_addr);
        if (self.allocated_bytes >= buf.len) {
            self.allocated_bytes -= buf.len;
        } else {
            self.allocated_bytes = 0;
        }
    }
};
