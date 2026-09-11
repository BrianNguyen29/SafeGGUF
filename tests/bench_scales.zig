//! Resource-budget benchmark suite (assurance roadmap slice 14).
//!
//! Run via `zig build bench` (wired in build.zig, pinned to ReleaseSafe: wall-time
//! numbers are meaningless in Debug, and ReleaseSafe preserves the shipped
//! binary's checked-arithmetic posture).
//!
//! Output goes to stderr, never stdout: under `zig build` the test-runner owns
//! stdout for its binary status protocol, and benchmark rows written there
//! desync the build runner (the step hangs). Direct runs (`./test`) are
//! unaffected but keep the same stderr convention.
//!
//! Scales: tensor descriptors 10 / 1k / 10k / 100k / 1M, metadata keys 1k / 100k,
//! metadata strings totalling 256 MiB of scanned UTF-8 value bytes (4096 keys x
//! 64 KiB max-string values). The 1M-descriptor row raises `max_work_units` and
//! `max_total_alloc_bytes` above the defaults: the scale consumes ~25M work
//! units (> default 10M) and ~148 MiB peak validator memory (> default 128 MiB).
//!
//! Each scale is validated twice over the same generated file, once per reader
//! kind from src/gguf/reader.zig:
//!   * "direct"   - FileReader: one pread syscall per logical field read;
//!   * "buffered" - BufferedReader: 64 KiB sliding cache window.
//!
//! Reported metrics per row:
//!   wall            - validation wall time (generation is outside the timer);
//!   peak_alloc      - QuotaAllocator.peak_bytes (validator-managed memory);
//!   vmhwm           - process peak RSS from /proc/self/status (monotonic
//!                     high-water mark across the whole suite run; n/a off-Linux);
//!   logical_reads   - logical Reader.readBytes calls (CountingReader below);
//!   logical_bytes   - bytes requested through the Reader interface;
//!   backend_reads   - actual underlying preadAll calls, counted by the
//!                     builtin.is_test instrumentation in src/gguf/reader.zig
//!                     (deterministic, always available on every platform);
//!   read_syscalls   - procfs /proc/self/io "syscr" delta around the run.
//!                     Telemetry only -- never a gate: it is process-global,
//!                     includes non-validation reads and may be absent
//!                     (n/a off-Linux or with /proc restricted);
//!   work_units      - Validator WorkBudget.consumed_units;
//!   scanned_bytes   - Validator WorkBudget.consumed_scanned_bytes.
//!
//! Enforced gates (structural, stable across runners -- not runner-relative):
//!   * every generated document must PASS validation (header counts asserted);
//!   * logical read counts must be identical for both reader kinds;
//!   * buffered backend_reads <= file_size / (64 KiB - 4 KiB) + 64: a sliding
//!     cache miss can strand at most one 4 KiB UTF-8 scan chunk (the largest
//!     read the bench documents issue through the cache path) at the tail of
//!     the outgoing window, so each slide must advance the window by >= 60 KiB.
//!     Removing the sliding cache turns every logical read into a pread
//!     (~700k at the 100k-descriptor scale, ~7M at 1M) and trips this gate;
//!   * buffered backend_reads * 4 <= direct backend_reads whenever the direct
//!     row issued >= 1000 preads (the "sliding cache reduces syscalls" claim,
//!     head-to-head on the same file; observed ratios are >100x on the
//!     descriptor/key scales and ~18x on strings).
//!
//! Baselines (informational, runner-relative -- NOT gates):
//!   Local run 2026-09-11, WSL2 Linux, Zig 0.13.0, `zig build bench`
//!   (compile 26s + run 9s; read_syscalls n/a locally: /proc/self/io absent.
//!   The backend_reads gates above run on every platform; procfs telemetry is
//!   recorded where available):
//!     descriptors  10: direct 0.17ms   buffered 0.15ms   peak_alloc 1.4KiB
//!     descriptors  1k: direct 8.29ms   buffered 1.10ms   peak_alloc 148KiB
//!     descriptors 10k: direct 36.49ms  buffered 9.21ms   peak_alloc 1.3MiB
//!     descriptors 100k: direct 296.50ms buffered 61.81ms peak_alloc 13.4MiB  (700,005 logical reads)
//!     descriptors 1M:  direct 3685.42ms buffered 932.97ms peak_alloc 148.3MiB (7,000,005 logical reads)
//!     keys 1k:         direct 2.76ms   buffered 0.66ms   peak_alloc 63KiB
//!     keys 100k:       direct 211.35ms buffered 61.06ms  peak_alloc 3.9MiB   (400,005 logical reads)
//!     strings 256MiB:  direct 524.80ms buffered 526.60ms peak_alloc 258KiB   (81,925 logical reads)
//!   Wall times vary run-to-run (100k descriptors measured 260-670ms direct
//!   across local runs); treat these as a rough reference, not thresholds. The
//!   enforced gates above are the stable regression surface.

const std = @import("std");
const builtin = @import("builtin");
const safegguf = @import("safegguf");

const limits = safegguf.limits;
const reader_mod = safegguf.reader;
const types = safegguf.types;
const err = safegguf.error_types;

/// Sliding window size of src/gguf/reader.zig BufferedReader.
const window_bytes: u64 = 65536;

/// Largest read the bench documents issue through the buffered cache path:
/// the 4 KiB UTF-8 scan chunk in src/gguf/metadata.zig (keys, scalar values
/// and tensor names are all smaller). See expectCacheEffectiveness.
const max_cache_read: u64 = 4096;

/// 64 KiB block of repeating 2-byte UTF-8 sequences (U+00E9). Value lengths
/// are even, so every 4096-byte validateUtf8Stream chunk boundary splits a code
/// point half the time, exercising the carry logic at scale.
///
/// Filled at runtime instead of as a comptime const: with Zig 0.13.0 the 64 KiB
/// comptime array sends the ReleaseSafe compile into pathological LLVM memory
/// use (multi-GiB, OOM-killed); a runtime-filled local buffer is byte-identical.
const max_string_bytes_default: usize = 65536;

fn fillUtf8Block(b: *[max_string_bytes_default]u8) void {
    var i: usize = 0;
    while (i < b.len) : (i += 2) {
        b[i] = 0xC3;
        b[i + 1] = 0xA9;
    }
}

// ---------------------------------------------------------------------------
// Document generators (direct to file; zero-filled, structurally valid).
// ---------------------------------------------------------------------------

/// GGUF v3, no metadata, `tensor_count` F32 [16, 1] descriptors (64 B span each,
/// aligned 32-byte offsets), zeroed alignment padding and tensor-data region.
fn generateDescriptorDoc(dir: std.fs.Dir, tensor_count: u64) !std.fs.File {
    const file = try dir.createFile("descriptors.gguf", .{ .read = true });
    errdefer file.close();

    var bw = std.io.bufferedWriter(file.writer());
    const w = bw.writer();

    try w.writeAll(&types.MAGIC);
    try w.writeInt(u32, types.VERSION, .little);
    try w.writeInt(u64, tensor_count, .little);
    try w.writeInt(u64, 0, .little); // metadata kv count

    const tensor_span: u64 = 64; // 16 * 1 * sizeof(f32)
    var cur: u64 = 24; // magic(4) + version(4) + tensor_count(8) + kv_count(8)
    var name_buf: [64]u8 = undefined;

    var i: u64 = 0;
    while (i < tensor_count) : (i += 1) {
        const tname = try std.fmt.bufPrint(&name_buf, "blk.{d}.attn_q.weight", .{i});
        try w.writeInt(u64, tname.len, .little);
        try w.writeAll(tname);
        try w.writeInt(u32, 2, .little); // n_dims
        try w.writeInt(u64, 16, .little); // ne[0]
        try w.writeInt(u64, 1, .little); // ne[1]
        try w.writeInt(u32, 0, .little); // GGML F32
        try w.writeInt(u64, i * tensor_span, .little); // offset rel. to tensor_data_base
        cur += 40 + tname.len; // name_len(8) + name + n_dims(4) + dims(16) + type(4) + offset(8)
    }

    const pad: u64 = (32 - (cur % 32)) % 32;
    try w.writeByteNTimes(0, @intCast(pad));
    try w.writeByteNTimes(0, @intCast(tensor_count * tensor_span)); // tensor data region
    try bw.flush();
    return file;
}

/// GGUF v3, zero tensors, `kv_count` uint32 entries keyed "meta.key_NNNNNN".
/// Stresses key validation, dedup (StringHashMap) and per-entry allocations.
fn generateKeysDoc(dir: std.fs.Dir, kv_count: u64) !std.fs.File {
    const file = try dir.createFile("keys.gguf", .{ .read = true });
    errdefer file.close();

    var bw = std.io.bufferedWriter(file.writer());
    const w = bw.writer();

    try w.writeAll(&types.MAGIC);
    try w.writeInt(u32, types.VERSION, .little);
    try w.writeInt(u64, 0, .little); // tensor count
    try w.writeInt(u64, kv_count, .little);

    var cur: u64 = 24;
    var name_buf: [32]u8 = undefined;

    var i: u64 = 0;
    while (i < kv_count) : (i += 1) {
        const key = try std.fmt.bufPrint(&name_buf, "meta.key_{d:0>6}", .{i});
        try w.writeInt(u64, key.len, .little);
        try w.writeAll(key);
        try w.writeInt(u32, 4, .little); // MetadataType.uint32
        try w.writeInt(u32, @truncate(i), .little); // value
        cur += 8 + key.len + 4 + 4;
    }

    // Zero-tensor doc: tensor_data_base = alignUp(cur, 32) must be <= file_size.
    const pad: u64 = (32 - (cur % 32)) % 32;
    try w.writeByteNTimes(0, @intCast(pad));
    try bw.flush();
    return file;
}

/// GGUF v3, zero tensors, `kv_count` string entries with 64 KiB values, so the
/// total scanned value bytes are exactly 256 MiB at kv_count == 4096.
fn generateStringsDoc(dir: std.fs.Dir, kv_count: u64) !std.fs.File {
    const file = try dir.createFile("strings.gguf", .{ .read = true });
    errdefer file.close();

    var bw = std.io.bufferedWriter(file.writer());
    const w = bw.writer();

    var utf8_block: [max_string_bytes_default]u8 = undefined;
    fillUtf8Block(&utf8_block);

    try w.writeAll(&types.MAGIC);
    try w.writeInt(u32, types.VERSION, .little);
    try w.writeInt(u64, 0, .little); // tensor count
    try w.writeInt(u64, kv_count, .little);

    var cur: u64 = 24;
    var name_buf: [32]u8 = undefined;

    var i: u64 = 0;
    while (i < kv_count) : (i += 1) {
        const key = try std.fmt.bufPrint(&name_buf, "text.payload_{d:0>4}", .{i});
        try w.writeInt(u64, key.len, .little);
        try w.writeAll(key);
        try w.writeInt(u32, 8, .little); // MetadataType.string
        try w.writeInt(u64, utf8_block.len, .little);
        try w.writeAll(&utf8_block);
        cur += 8 + key.len + 4 + 8 + utf8_block.len;
    }

    const pad: u64 = (32 - (cur % 32)) % 32;
    try w.writeByteNTimes(0, @intCast(pad));
    try bw.flush();
    return file;
}

// ---------------------------------------------------------------------------
// Metric plumbing.
// ---------------------------------------------------------------------------

/// Reader decorator that counts logical readBytes calls and bytes, forwarding
/// to the wrapped FileReader/BufferedReader reader. Reader is a small copyable
/// vtable struct, so the inner reader is held by value.
const CountingReader = struct {
    inner: reader_mod.Reader,
    reads: u64 = 0,
    bytes: u64 = 0,

    fn reader(self: *CountingReader) reader_mod.Reader {
        return .{ .ptr = self, .vtable = &vtable, .size = self.inner.size };
    }

    const vtable = reader_mod.Reader.VTable{ .readBytes = readBytesImpl };

    fn readBytesImpl(ctx: *anyopaque, offset: u64, dest: []u8) err.ParseError!void {
        const self: *CountingReader = @ptrCast(@alignCast(ctx));
        self.reads += 1;
        self.bytes += dest.len;
        return self.inner.readBytes(offset, dest);
    }
};

const proc_available = builtin.os.tag == .linux;

fn procFieldValue(path: []const u8, field: []const u8) ?u64 {
    if (!proc_available) return null;
    var f = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer f.close();
    var buf: [4096]u8 = undefined;
    const n = f.readAll(&buf) catch return null;
    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t");
        if (std.mem.startsWith(u8, line, field)) {
            var rest = std.mem.trimLeft(u8, line[field.len..], " \t");
            const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
            return std.fmt.parseInt(u64, rest[0..end], 10) catch null;
        }
    }
    return null;
}

/// Count of read syscalls (read/pread) from procfs; each call costs +1 syscr.
fn currentSyscr() ?u64 {
    return procFieldValue("/proc/self/io", "syscr:");
}

fn currentVmHwmKb() ?u64 {
    return procFieldValue("/proc/self/status", "VmHWM:");
}

const RunMetrics = struct {
    reader_kind: []const u8,
    file_size: u64,
    wall_ns: u64,
    peak_alloc_bytes: u64,
    vmhwm_kb: ?u64,
    logical_reads: u64,
    logical_bytes: u64,
    backend_reads: u64,
    read_syscalls: ?u64,
    work_units: u64,
    scanned_bytes: u64,
};

fn runOnce(
    parent: std.mem.Allocator,
    file: std.fs.File,
    file_size: u64,
    buffered: bool,
    lim: limits.Limits,
    expected_tensors: u64,
    expected_kv: u64,
) !RunMetrics {
    var direct_reader = reader_mod.FileReader.init(file, file_size);
    var window_reader = reader_mod.BufferedReader.init(file, file_size);
    var counting = CountingReader{
        .inner = if (buffered) window_reader.reader() else direct_reader.reader(),
    };

    const syscr_before = currentSyscr();
    var timer = try std.time.Timer.start();

    var val = safegguf.Validator.init(parent, lim, .gguf_spec);
    var doc = try val.validate(counting.reader());

    const wall_ns = timer.read();
    const syscr_after = currentSyscr();

    try std.testing.expectEqual(expected_tensors, doc.header.tensor_count);
    try std.testing.expectEqual(expected_kv, doc.header.metadata_kv_count);

    val.deinitDocument(&doc);

    return .{
        .reader_kind = if (buffered) "buffered" else "direct",
        .file_size = file_size,
        .wall_ns = wall_ns,
        .peak_alloc_bytes = val.quota_alloc.peak_bytes,
        .vmhwm_kb = currentVmHwmKb(),
        .logical_reads = counting.reads,
        .logical_bytes = counting.bytes,
        .backend_reads = if (buffered) window_reader.backend_reads else direct_reader.backend_reads,
        .read_syscalls = if (syscr_before != null and syscr_after != null)
            syscr_after.? - syscr_before.?
        else
            null,
        .work_units = val.work_budget.consumed_units,
        .scanned_bytes = val.work_budget.consumed_scanned_bytes,
    };
}

fn sizeStr(buf: []u8, bytes: u64) []const u8 {
    if (bytes >= 1024 * 1024) {
        const whole = bytes / (1024 * 1024);
        const tenths = (bytes % (1024 * 1024)) * 10 / (1024 * 1024);
        return std.fmt.bufPrint(buf, "{d}.{d}MiB", .{ whole, tenths }) catch "err";
    }
    const whole = bytes / 1024;
    const tenths = (bytes % 1024) * 10 / 1024;
    return std.fmt.bufPrint(buf, "{d}.{d}KiB", .{ whole, tenths }) catch "err";
}

fn msStr(buf: []u8, ns: u64) []const u8 {
    const whole = ns / std.time.ns_per_ms;
    const hundredths = (ns % std.time.ns_per_ms) * 100 / std.time.ns_per_ms;
    return std.fmt.bufPrint(buf, "{d}.{d:0>2}ms", .{ whole, hundredths }) catch "err";
}

fn optNumStr(buf: []u8, v: ?u64) []const u8 {
    if (v) |x| return std.fmt.bufPrint(buf, "{d}", .{x}) catch "err";
    return "n/a";
}

fn optKbStr(buf: []u8, kb: ?u64) []const u8 {
    if (kb) |x| return std.fmt.bufPrint(buf, "{d}kB", .{x}) catch "err";
    return "n/a";
}

fn printRow(out: anytype, m: RunMetrics) !void {
    var b0: [32]u8 = undefined;
    var b1: [32]u8 = undefined;
    var b2: [32]u8 = undefined;
    var b3: [32]u8 = undefined;
    var b4: [32]u8 = undefined;
    var b5: [32]u8 = undefined;
    var b6: [32]u8 = undefined;
    try out.print(
        "  [{s:<8}] file={s} wall={s} peak_alloc={s} vmhwm={s} logical_reads={d} logical_bytes={s} backend_reads={d} read_syscalls={s} work_units={d} scanned_bytes={s}\n",
        .{
            m.reader_kind,
            sizeStr(&b0, m.file_size),
            msStr(&b1, m.wall_ns),
            sizeStr(&b2, m.peak_alloc_bytes),
            optKbStr(&b3, m.vmhwm_kb),
            m.logical_reads,
            sizeStr(&b4, m.logical_bytes),
            m.backend_reads,
            optNumStr(&b5, m.read_syscalls),
            m.work_units,
            sizeStr(&b6, m.scanned_bytes),
        },
    );
}

fn expectCacheEffectiveness(direct: RunMetrics, buffered: RunMetrics) !void {
    // Access-pattern bound, measured on instrumented backend reads (not
    // procfs): a cache miss strands at most one max_cache_read-sized read at
    // the tail of the outgoing window, so each slide must advance the 64 KiB
    // window by at least window_bytes - max_cache_read bytes. The +64 slack
    // covers the initial slide, per-document rounding and alignment.
    const slides_bound = buffered.file_size / (window_bytes - max_cache_read) + 64;
    try std.testing.expect(buffered.backend_reads <= slides_bound);

    // Head-to-head on the same file: once the direct reader issues enough
    // preads for the ratio to be meaningful, the sliding cache must cut
    // backend reads by at least 4x. A disabled or never-reusing cache turns
    // every logical read into a pread and trips this gate.
    if (direct.backend_reads >= 1000) {
        try std.testing.expect(buffered.backend_reads * 4 <= direct.backend_reads);
    }
}

/// Validates one generated file with both reader kinds and asserts the
/// structural sliding-cache gates.
fn benchFile(
    out: anytype,
    parent: std.mem.Allocator,
    file: std.fs.File,
    expected_tensors: u64,
    expected_kv: u64,
    lim: limits.Limits,
) !void {
    const size = (try file.stat()).size;
    try out.print("scale: tensors={d} kv={d}\n", .{ expected_tensors, expected_kv });

    const direct = try runOnce(parent, file, size, false, lim, expected_tensors, expected_kv);
    try printRow(out, direct);

    const buffered = try runOnce(parent, file, size, true, lim, expected_tensors, expected_kv);
    try printRow(out, buffered);

    try std.testing.expectEqual(direct.logical_reads, buffered.logical_reads);
    try expectCacheEffectiveness(direct, buffered);
}

// ---------------------------------------------------------------------------
// Benchmarks.
// ---------------------------------------------------------------------------

test "bench: tensor descriptor scales 10/1k/10k/100k/1M" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("Memory leak detected in bench");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const out = std.io.getStdErr().writer();
    try out.print("\n== tensor descriptor scales (gguf-spec, little endian) ==\n", .{});

    for ([_]u64{ 10, 1_000, 10_000, 100_000, 1_000_000 }) |n| {
        const file = try generateDescriptorDoc(tmp.dir, n);
        defer file.close();
        // The 1M row exceeds the default work-unit budget (~25 units/tensor ->
        // ~25M > 10M) and the 128 MiB alloc quota (~148 MiB); raise both for
        // this row only.
        const lim: limits.Limits = if (n >= 1_000_000) .{
            .max_work_units = 50_000_000,
            .max_total_alloc_bytes = 512 * 1024 * 1024,
        } else .{};
        try benchFile(out, gpa.allocator(), file, n, 0, lim);
    }
}

test "bench: metadata key scales 1k/100k" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("Memory leak detected in bench");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const out = std.io.getStdErr().writer();
    try out.print("\n== metadata key scales (gguf-spec, little endian) ==\n", .{});

    for ([_]u64{ 1_000, 100_000 }) |n| {
        const file = try generateKeysDoc(tmp.dir, n);
        defer file.close();
        try benchFile(out, gpa.allocator(), file, 0, n, limits.Limits{});
    }
}

test "bench: scanned strings scale (256 MiB of UTF-8 values)" {
    // 4096 keys x 64 KiB (Limits.max_string_bytes) = 268,435,456 value bytes.
    // max_scanned_bytes is raised above the 256 MiB default: the default quota
    // is exactly the target scan volume and the per-entry key/keylen overhead
    // would trip ResourceLimitExceeded; a benchmark row must PASS to measure.
    const lim = limits.Limits{ .max_scanned_bytes = 512 * 1024 * 1024 };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("Memory leak detected in bench");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const out = std.io.getStdErr().writer();
    try out.print("\n== scanned strings scale (gguf-spec, little endian) ==\n", .{});

    const file = try generateStringsDoc(tmp.dir, 4096);
    defer file.close();
    try benchFile(out, gpa.allocator(), file, 0, 4096, lim);
}
