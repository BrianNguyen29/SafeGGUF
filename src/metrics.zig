//! Validator metrics counters (production-readiness plan §21).
//!
//! Counters are lock-free: every record is a single atomic RMW (`.monotonic`),
//! so a shared `Metrics` can be updated from several threads without a lock and
//! a single-run CLI pays nothing beyond the increment. The
//! `reject_by_error_code` label set is derived at comptime from the canonical
//! `SGGUF_E_*` namespace, so labels are bounded by construction: untrusted
//! identifiers (filenames, tensor names, metadata keys) can never become a
//! label, and an unmapped code is folded into `SGGUF_E_UNKNOWN`.
const std = @import("std");
const err = @import("gguf/error.zig");

/// Validation outcome class, mirroring the CLI exit-code contract:
/// pass (exit 0), reject (exit 2), err (exit 70/74; rendered as ERROR).
pub const Verdict = enum { pass, reject, err };

const Atomic = std.atomic.Value(u64);
const parse_error_variants = @typeInfo(err.ParseError).ErrorSet.?;

/// Upper bound on reject-label slots: one per `ParseError` variant, one per
/// legacy public-code mapping, plus the UNKNOWN bucket. Duplicate canonical
/// codes (legacy aliases of a `ParseError` code) are collapsed at comptime.
const max_reject_labels = parse_error_variants.len + err.legacy_public_codes.len + 1;

fn hasLabel(labels: []const []const u8, label: []const u8) bool {
    for (labels) |existing| {
        if (std.mem.eql(u8, existing, label)) return true;
    }
    return false;
}

/// Comptime label-set builder. `out` must hold `max_reject_labels` entries;
/// returns the number of unique labels written. Ordering is deterministic:
/// `ParseError` variant order, then legacy-only canonical codes, UNKNOWN last.
fn fillRejectLabels(out: *[max_reject_labels][]const u8) usize {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    inline for (parse_error_variants) |variant| {
        const e: err.ParseError = @field(err.ParseError, variant.name);
        const code = err.publicCodeOf(e);
        if (!hasLabel(out[0..n], code)) {
            out[n] = code;
            n += 1;
        }
    }
    for (err.legacy_public_codes) |entry| {
        if (!hasLabel(out[0..n], entry.canonical)) {
            out[n] = entry.canonical;
            n += 1;
        }
    }
    if (!hasLabel(out[0..n], err.public_codes.unknown)) {
        out[n] = err.public_codes.unknown;
        n += 1;
    }
    return n;
}

const reject_label_count: usize = blk: {
    var buf: [max_reject_labels][]const u8 = undefined;
    break :blk fillRejectLabels(&buf);
};

const reject_labels: [reject_label_count][]const u8 = blk: {
    var buf: [max_reject_labels][]const u8 = undefined;
    const n = fillRejectLabels(&buf);
    if (n != reject_label_count) @compileError("reject label count mismatch");
    var labels: [reject_label_count][]const u8 = undefined;
    for (buf[0..n], 0..) |label, i| labels[i] = label;
    break :blk labels;
};

comptime {
    // The defensive fallback in `recordRejectCode` indexes the last slot, so
    // UNKNOWN must be there.
    std.debug.assert(std.mem.eql(u8, reject_labels[reject_label_count - 1], err.public_codes.unknown));
}

/// Lock-free counter set for one validator process or run.
///
/// Field semantics when the same instance records several validations:
/// `requests_total` / verdict counts / `validation_seconds` / `work_units` /
/// `scanned_bytes` / `reject_by_error_code` accumulate, `file_bytes` is the
/// most recently recorded file size, and `peak_alloc_bytes` is the running
/// maximum.
pub const Metrics = struct {
    requests_total: Atomic = Atomic.init(0),
    pass_total: Atomic = Atomic.init(0),
    reject_total: Atomic = Atomic.init(0),
    error_total: Atomic = Atomic.init(0),
    /// Accumulated validator wall time; emitted as `validation_seconds`.
    validation_ns_total: Atomic = Atomic.init(0),
    file_bytes: Atomic = Atomic.init(0),
    peak_alloc_bytes: Atomic = Atomic.init(0),
    work_units: Atomic = Atomic.init(0),
    scanned_bytes: Atomic = Atomic.init(0),
    /// One atomic slot per canonical public code (comptime-bounded label set).
    reject_by_error_code: [reject_label_count]Atomic = [_]Atomic{Atomic.init(0)} ** reject_label_count,

    pub fn recordRequest(self: *Metrics) void {
        _ = self.requests_total.fetchAdd(1, .monotonic);
    }

    pub fn recordVerdict(self: *Metrics, verdict: Verdict) void {
        const counter = switch (verdict) {
            .pass => &self.pass_total,
            .reject => &self.reject_total,
            .err => &self.error_total,
        };
        _ = counter.fetchAdd(1, .monotonic);
    }

    /// Counts one rejection under a bounded label. `code` may be a canonical
    /// `SGGUF_E_*` code, a legacy CLI code (`E_*`), or a bare Zig error name;
    /// anything outside the canonical namespace is folded into
    /// `SGGUF_E_UNKNOWN` instead of becoming a label.
    pub fn recordRejectCode(self: *Metrics, code: []const u8) void {
        const canonical = if (err.isPublicCode(code)) code else err.canonicalFromLegacy(code) orelse err.public_codes.unknown;
        for (reject_labels, 0..) |label, i| {
            if (std.mem.eql(u8, label, canonical)) {
                _ = self.reject_by_error_code[i].fetchAdd(1, .monotonic);
                return;
            }
        }
        // Unreachable for every canonical code (the table is exhaustive);
        // keeps arbitrary input inside the bounded set instead of panicking.
        _ = self.reject_by_error_code[reject_label_count - 1].fetchAdd(1, .monotonic);
    }

    pub fn recordValidationNanos(self: *Metrics, nanos: u64) void {
        _ = self.validation_ns_total.fetchAdd(nanos, .monotonic);
    }

    pub fn recordBudgets(self: *Metrics, file_bytes: u64, peak_alloc_bytes: u64, work_units: u64, scanned_bytes: u64) void {
        self.file_bytes.store(file_bytes, .monotonic);
        _ = self.peak_alloc_bytes.fetchMax(peak_alloc_bytes, .monotonic);
        _ = self.work_units.fetchAdd(work_units, .monotonic);
        _ = self.scanned_bytes.fetchAdd(scanned_bytes, .monotonic);
    }

    /// Writes one JSON object carrying every required counter (plan §21 names)
    /// and the bounded `reject_by_error_code` label map, then terminates the
    /// line. Only labels with a non-zero count are emitted. The caller chooses
    /// the stream; the CLI reserves stdout for the result document.
    pub fn writeJson(self: *const Metrics, w: anytype) !void {
        var ws = std.json.writeStream(w, .{});
        try ws.beginObject();
        try writeU64Field(&ws, "requests_total", self.requests_total.load(.monotonic));
        try writeU64Field(&ws, "pass_total", self.pass_total.load(.monotonic));
        try writeU64Field(&ws, "reject_total", self.reject_total.load(.monotonic));
        try writeU64Field(&ws, "error_total", self.error_total.load(.monotonic));
        try ws.objectField("validation_seconds");
        try ws.write(nanosToSeconds(self.validation_ns_total.load(.monotonic)));
        try writeU64Field(&ws, "file_bytes", self.file_bytes.load(.monotonic));
        try writeU64Field(&ws, "peak_alloc_bytes", self.peak_alloc_bytes.load(.monotonic));
        try writeU64Field(&ws, "work_units", self.work_units.load(.monotonic));
        try writeU64Field(&ws, "scanned_bytes", self.scanned_bytes.load(.monotonic));
        try ws.objectField("reject_by_error_code");
        try ws.beginObject();
        for (reject_labels, 0..) |label, i| {
            const count = self.reject_by_error_code[i].load(.monotonic);
            if (count == 0) continue;
            try ws.objectField(label);
            try ws.write(count);
        }
        try ws.endObject();
        try ws.endObject();
        try w.writeByte('\n');
    }
};

fn writeU64Field(ws: anytype, name: []const u8, value: u64) !void {
    try ws.objectField(name);
    try ws.write(value);
}

fn nanosToSeconds(nanos: u64) f64 {
    return @as(f64, @floatFromInt(nanos)) / @as(f64, @floatFromInt(std.time.ns_per_s));
}
