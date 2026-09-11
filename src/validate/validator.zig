const std = @import("std");
const types = @import("../gguf/types.zig");
const err = @import("../gguf/error.zig");
const limits = @import("../gguf/limits.zig");
const reader_mod = @import("../gguf/reader.zig");
const parser = @import("../gguf/parser.zig");
const structural = @import("structural.zig");

/// High-level GGUF Validator that automatically encapsulates and enforces
/// memory quotas and computational work budgets according to configured Limits.
///
/// Lifetime and threading contract:
///   * Sequential reuse: a single instance may validate many files one after
///     another; `validate()` resets per-validation counters and quota flags
///     via `resetForValidation()` on every call.
///   * No concurrent use: an instance is not thread-safe (mutable quota and
///     work-budget state, no internal locking); concurrent use from multiple
///     threads requires one Validator per thread or external synchronization.
///   * Document ownership: a `Document` returned by `validate()` must be freed
///     via `deinitDocument()` on the same Validator instance that produced it,
///     before that Validator is discarded; its allocations live in the
///     Validator-managed QuotaAllocator.
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
    /// enabling a single Validator instance to be reused sequentially across multiple
    /// files (never concurrently; see the lifetime contract on `Validator`).
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

    /// Safely frees allocations owned by a validated Document using the managed
    /// allocator. Must be called on the same Validator instance that produced the
    /// Document, before that Validator is discarded (see lifetime contract above).
    pub fn deinitDocument(self: *Validator, doc: *parser.Document) void {
        doc.deinit(self.quota_alloc.allocator());
    }

    /// Owned-document variant of `validate()`: returns a `Result` bundling the
    /// validated Document with the Validator-managed allocator it was built on,
    /// so the caller frees it via `Result.deinit()` instead of pairing the raw
    /// Document back with `deinitDocument()`. Reset, quota and work-budget
    /// behavior are identical to `validate()`.
    pub fn validateOwned(self: *Validator, r: reader_mod.Reader) err.ParseError!Result {
        return .{ .doc = try self.validate(r), .alloc = self.quota_alloc.allocator() };
    }

    /// Returns true if the memory quota was exceeded during validation
    pub fn isQuotaExceeded(self: *const Validator) bool {
        return self.quota_alloc.isQuotaExceeded();
    }
};

/// Ownership wrapper for a validated document, returned by
/// `Validator.validateOwned()` as an alternative to the raw
/// `Document` + `deinitDocument()` pairing (which remains supported).
///
/// `Result` carries the parsed `Document` together with the allocator interface
/// of the producing Validator's managed QuotaAllocator, so callers free the
/// document with `deinit()` alone and never need the correct
/// Document/allocator pairing.
///
/// Lifetime and threading contract (inherited from `Validator`, see there):
///   * The document's allocations live in the Validator-managed QuotaAllocator;
///     `deinit()` must be called while the producing Validator instance is still
///     alive, before that Validator is discarded.
///   * Call `deinit()` exactly once per `Result`; a double `deinit()` is a
///     double-free, same contract as the raw `Document`/`deinitDocument()` API.
///   * Sequential reuse, no concurrent use: `validateOwned()` performs the same
///     per-validation reset as `validate()`, and a `Result` is not thread-safe
///     nor independent of the producing Validator's quota/work state; one
///     Validator per thread or external synchronization.
pub const Result = struct {
    /// The validated document; inspect freely, but free only via `deinit()`.
    doc: parser.Document,
    /// Allocator captured from the producing Validator's QuotaAllocator;
    /// implementation detail of `deinit()`, not for other allocations.
    alloc: std.mem.Allocator,

    /// Frees all allocations owned by the validated document using the captured
    /// Validator-managed allocator (see lifetime contract above).
    pub fn deinit(self: *Result) void {
        self.doc.deinit(self.alloc);
    }
};
