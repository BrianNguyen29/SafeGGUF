const std = @import("std");
const types = @import("../gguf/types.zig");
const err = @import("../gguf/error.zig");
const limits = @import("../gguf/limits.zig");
const reader_mod = @import("../gguf/reader.zig");
const parser = @import("../gguf/parser.zig");
const structural = @import("structural.zig");

/// Shared validation core behind every Validator entry point: parse the stream,
/// then run structural validation, under one explicitly supplied
/// allocator + work-budget pair. `Validator.validate()` passes its borrowed,
/// Validator-inline state; `Validator.validateOwned()` passes a heap
/// `OwnedValidationState`, so both paths enforce identical parse, structural and
/// budget rules.
fn validateWith(
    alloc: std.mem.Allocator,
    work_budget: *limits.WorkBudget,
    lim: limits.Limits,
    profile: types.Profile,
    endian: std.builtin.Endian,
    r: reader_mod.Reader,
) err.ParseError!parser.Document {
    var doc = try parser.parseDocument(alloc, r, endian, lim, profile, work_budget);
    errdefer doc.deinit(alloc);

    try structural.validateStructural(alloc, doc, profile, work_budget);
    return doc;
}

/// High-level GGUF Validator that automatically encapsulates and enforces
/// memory quotas and computational work budgets according to configured Limits.
///
/// Lifetime and threading contract:
///   * Sequential reuse: a single instance may validate many files one after
///     another; `validate()` resets per-validation counters and quota flags via
///     `resetForValidation()` on every call. `validateOwned()` never allocates
///     from the Validator's own state (it validates through the heap state
///     owned by the returned `Result`), so the Validator's counters are not
///     charged by owned runs.
///   * No concurrent use: an instance is not thread-safe (mutable quota and
///     work-budget state, no internal locking); concurrent use from multiple
///     threads requires one Validator per thread or external synchronization.
///   * Borrowed documents: a `Document` returned by `validate()` must be freed
///     via `deinitDocument()` on the same Validator instance that produced it,
///     before that Validator is discarded; its allocations live in the
///     Validator-managed QuotaAllocator.
///   * Owned documents: a `Result` returned by `validateOwned()` owns its own
///     heap `OwnedValidationState` and is independent of the producing
///     Validator; free it via `Result.deinit()`.
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
    ///
    /// Borrowed path: the returned `Document` is allocated from the Validator's
    /// own QuotaAllocator, so it must be released with `deinitDocument()` on
    /// this same instance. Use `validateOwned()` for a self-contained result.
    pub fn validate(self: *Validator, r: reader_mod.Reader) err.ParseError!parser.Document {
        self.resetForValidation();
        return validateWith(self.quota_alloc.allocator(), &self.work_budget, self.limits, self.profile, self.endian, r);
    }

    /// Safely frees allocations owned by a validated Document using the managed
    /// allocator. Must be called on the same Validator instance that produced the
    /// Document, before that Validator is discarded (see lifetime contract above).
    /// Never pass a `Result.doc` here: owned results must be released with
    /// `Result.deinit()` (see `Result`).
    pub fn deinitDocument(self: *Validator, doc: *parser.Document) void {
        doc.deinit(self.quota_alloc.allocator());
    }

    /// Independent-ownership variant of `validate()`: validates the stream with
    /// a freshly heap-allocated `OwnedValidationState` created from this
    /// Validator's configuration (same Limits, endian, profile and diagnostics
    /// channel), never with the Validator's borrowed state. The returned
    /// `Result` owns that state, so it must be released with `Result.deinit()`
    /// and stays valid and freeable no matter what happens to this Validator
    /// afterwards (scope exit, move/copy, reuse, destruction).
    ///
    /// Quota and work budgets are enforced exactly as in `validate()`; the
    /// only diagnostic difference is that accounting lives in the `Result`'s
    /// own state instead of the Validator's.
    pub fn validateOwned(self: *Validator, r: reader_mod.Reader) err.ParseError!Result {
        // Diagnostic flag reset, mirroring `validate()`: the flag must describe
        // this call, and a failure to allocate the owned state itself is a host
        // OOM, not a quota rejection.
        self.quota_alloc.resetQuotaExceeded();

        const state = try self.parent_allocator.create(OwnedValidationState);
        state.* = OwnedValidationState.init(self.parent_allocator, self.limits, self.work_budget.ctx);

        const result = validateWith(state.allocator(), &state.work_budget, self.limits, self.profile, self.endian, r);
        // Diagnostics-only mirror of this run's quota outcome onto the
        // Validator: the document's bytes never touch `self.quota_alloc`, so
        // this is what keeps `isQuotaExceeded()` naming the most recent
        // validation (quota rejection vs host OOM) for owned runs too. Must be
        // read before the owned state is dropped on the error path.
        self.quota_alloc.quota_exceeded = state.quota_alloc.isQuotaExceeded();

        const doc = result catch |e| {
            state.destroy();
            return e;
        };
        return .{ .doc = doc, .state = state };
    }

    /// Returns true if the memory quota was exceeded by the most recent
    /// validation on this instance: the Validator's own QuotaAllocator for
    /// `validate()`, or the owned state's outcome mirrored by `validateOwned()`
    /// (whose document allocations never touch this Validator's quota).
    pub fn isQuotaExceeded(self: *const Validator) bool {
        return self.quota_alloc.isQuotaExceeded();
    }
};

/// Heap-stable per-validation resource state owned by a `Result`: an
/// independent `QuotaAllocator` (same configured ceiling as the producing
/// Validator, but its own accounting) plus the `WorkBudget` that the single
/// owned validation charged. Allocating it on the heap is what makes a `Result`
/// independent: the allocator interface captured by the document's allocations
/// points here instead of into the Validator struct, so it survives the
/// Validator leaving scope, moving, or being destroyed.
pub const OwnedValidationState = struct {
    /// Parent allocator used to release this state itself; deliberately not
    /// the quota allocator, which cannot track its own owner's storage. Like
    /// every std.mem.Allocator-provided value, it must outlive the state (and
    /// therefore the `Result` that owns it).
    parent_allocator: std.mem.Allocator,
    quota_alloc: limits.QuotaAllocator,
    work_budget: limits.WorkBudget,

    /// `parent_allocator` is the producing Validator's parent allocator;
    /// `diagnostics` carries over `WorkBudget.ctx` so parse/structural raise
    /// sites keep snapshotting context for owned validations (null is fine).
    pub fn init(
        parent_allocator: std.mem.Allocator,
        lim: limits.Limits,
        diagnostics: ?*err.ParseContext,
    ) OwnedValidationState {
        var work_budget = limits.WorkBudget.initWithLimits(lim.max_work_units, lim.max_scanned_bytes);
        work_budget.ctx = diagnostics;
        return .{
            .parent_allocator = parent_allocator,
            .quota_alloc = limits.QuotaAllocator.init(parent_allocator, lim.max_total_alloc_bytes),
            .work_budget = work_budget,
        };
    }

    /// Quota-enforcing allocator owning the document's allocations; free the
    /// document (and only the document) with this before `destroy()`.
    pub fn allocator(self: *OwnedValidationState) std.mem.Allocator {
        return self.quota_alloc.allocator();
    }

    /// Releases the state itself; the document must already be deinit()ed
    /// through `allocator()`.
    pub fn destroy(self: *OwnedValidationState) void {
        self.parent_allocator.destroy(self);
    }
};

/// Ownership wrapper for a validated document, returned by
/// `Validator.validateOwned()` as the self-contained counterpart to the raw
/// `Document` + `deinitDocument()` pairing (which remains fully supported).
///
/// `Result` owns everything its document needs: the parsed `Document` plus the
/// heap `OwnedValidationState` (quota allocator + work budget) whose allocator
/// produced those allocations. Callers therefore free the document with
/// `deinit()` alone and never need to re-pair a Document with the allocator
/// that built it.
///
/// Lifetime contract:
///   * The owned state lives on the heap and is referenced only by this
///     `Result`, so the document stays valid and `deinit()` stays correct after
///     the producing Validator leaves scope, is moved/copied, is reused for
///     further validations, or is destroyed.
///   * The only remaining requirement is the Validator's parent allocator
///     (e.g. `std.testing.allocator`): like every std.mem.Allocator-backed
///     value, it must outlive the `Result`.
///   * Release the document only through `deinit()`; passing `doc` to
///     `Validator.deinitDocument()` would free through the wrong accounting
///     path and leave the owned state behind.
///   * `deinit()` is idempotent: it clears the owned state, so a repeated call
///     is a no-op instead of a double free. Do not copy the struct and
///     deinit() both copies (each copy would still see a live state pointer).
///   * Threading: the owned state is private to this `Result` and never shared
///     with the Validator, so a live `Result` adds no shared mutable state; a
///     single `Result` must still be deinit()ed from one thread only.
///
/// B2 (F-06) API decision, recorded here as the code-level source of truth:
/// `validateOwned()`/`Result` is the independent-ownership API — the caller
/// frees through `Result.deinit()` and never re-pairs the document with the
/// producing allocator — while the legacy `validate()` + `deinitDocument()`
/// pair remains fully supported and unchanged. Ownership independence (heap
/// `OwnedValidationState` surviving the producing Validator, per
/// docs/remediation-f0209-exec-plan.md B2) is implemented as this additive
/// change: no entry-point signature change, no deprecation, no removal. The
/// only replaced member is `Result`'s former `alloc` field, which was
/// documented as a `deinit()` implementation detail rather than callable API.
pub const Result = struct {
    /// The validated document; inspect freely, but release only via `deinit()`.
    doc: parser.Document,
    /// Heap-stable state owning `doc`'s allocations. Implementation detail of
    /// `deinit()`, which clears it to null; never destroy it directly. Public
    /// only so callers can inspect the run's accounting, e.g.
    /// `state.?.quota_alloc.peak_bytes` or `state.?.work_budget.consumed_units`.
    state: ?*OwnedValidationState,

    /// Releases all allocations owned by the validated document through the
    /// owned state's allocator, then releases the state itself. After the first
    /// call this is a no-op (see lifetime contract above).
    pub fn deinit(self: *Result) void {
        const state = self.state orelse return;
        self.doc.deinit(state.allocator());
        state.destroy();
        self.state = null;
    }
};
