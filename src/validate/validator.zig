const std = @import("std");
const types = @import("../gguf/types.zig");
const err = @import("../gguf/error.zig");
const limits = @import("../gguf/limits.zig");
const reader_mod = @import("../gguf/reader.zig");
const parser = @import("../gguf/parser.zig");
const structural = @import("structural.zig");

/// High-level GGUF Validator that automatically encapsulates and enforces
/// memory quotas and computational work budgets according to configured Limits.
pub const Validator = struct {
    parent_allocator: std.mem.Allocator,
    limits: limits.Limits,
    profile: types.Profile,
    endian: std.builtin.Endian = .little,
    quota_alloc: limits.QuotaAllocator,
    work_budget: limits.WorkBudget,

    pub fn init(
        parent_allocator: std.mem.Allocator,
        lim: limits.Limits,
        profile: types.Profile,
    ) Validator {
        return .{
            .parent_allocator = parent_allocator,
            .limits = lim,
            .profile = profile,
            .endian = .little,
            .quota_alloc = limits.QuotaAllocator.init(parent_allocator, lim.max_total_alloc_bytes),
            .work_budget = limits.WorkBudget.initWithLimits(lim.max_work_units, lim.max_scanned_bytes),
        };
    }

    /// Returns the managed QuotaAllocator's allocator interface
    pub fn allocator(self: *Validator) std.mem.Allocator {
        return self.quota_alloc.allocator();
    }

    /// Resets per-validation monotonic work/byte counters and transient quota flags,
    /// enabling a single Validator instance to be safely reused across multiple files.
    pub fn resetForValidation(self: *Validator) void {
        self.work_budget.consumed_units = 0;
        self.work_budget.consumed_scanned_bytes = 0;
        self.quota_alloc.resetQuotaExceeded();
    }

    /// Validates a GGUF file stream via Reader abstraction, strictly enforcing
    /// parser and structural invariants under managed resource budgets.
    pub fn validate(self: *Validator, r: reader_mod.Reader) err.ParseError!parser.Document {
        self.resetForValidation();
        const alloc = self.quota_alloc.allocator();
        var doc = try parser.parseDocument(alloc, r, self.endian, self.limits, self.profile, &self.work_budget);
        errdefer doc.deinit(alloc);

        try structural.validateStructural(alloc, doc, self.profile, &self.work_budget);
        return doc;
    }

    /// Safely frees allocations owned by a validated Document using the managed allocator
    pub fn deinitDocument(self: *Validator, doc: *parser.Document) void {
        doc.deinit(self.quota_alloc.allocator());
    }

    /// Returns true if the memory quota was exceeded during validation
    pub fn isQuotaExceeded(self: *const Validator) bool {
        return self.quota_alloc.isQuotaExceeded();
    }
};
