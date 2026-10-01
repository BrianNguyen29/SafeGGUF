//! Structured JSON log record for one validation request (plan §22).
//!
//! The record is a closed field set: there is deliberately no field for a
//! model path, metadata value, prompt, or secret, so those values cannot reach
//! the log through this API. Tenant identifiers are accepted only as
//! pseudonyms (`pseudonymizeTenant`); the raw identifier is never stored in
//! the record. The caller chooses the stream - the CLI emits records on stderr
//! so stdout stays reserved for the result JSON.
const std = @import("std");

/// One request-level log line. Required fields (plan §22):
/// request_id, tenant hash/pseudonym, digest, file_size, profile, duration_ms,
/// verdict, error_code, stage, version, commit. Absent values are empty
/// strings, never placeholders reconstructed from untrusted data.
pub const LogRecord = struct {
    /// Correlation id for this validation request; written as given.
    request_id: []const u8 = "",
    /// SHA-256-derived tenant pseudonym (`pseudonymizeTenant`). Never the raw
    /// tenant identifier.
    tenant_id_hash: []const u8 = "",
    /// Content digest of the validated file (lowercase hex, SHA-256); empty
    /// when digest computation is disabled or failed.
    digest: []const u8 = "",
    file_size: u64 = 0,
    profile: []const u8 = "",
    duration_ms: u64 = 0,
    /// PASS / REJECT / ERROR.
    verdict: []const u8 = "",
    /// Emitted error code (`E_*`); empty for PASS.
    error_code: []const u8 = "",
    /// Validation stage ("parse", "structural", "stability", ...); empty when
    /// no stage applies (e.g. PASS).
    stage: []const u8 = "",
    version: []const u8 = "",
    commit: []const u8 = "",
};

/// Hex length of the tenant pseudonym: the SHA-256 digest truncated to its
/// first 16 bytes (128 bits), so the log does not carry a reversible id.
pub const tenant_hash_hex_len = 32;

/// Deterministic tenant pseudonym: SHA-256 over the raw identifier, truncated
/// to 16 bytes, lowercase hex. The raw identifier is consumed and discarded -
/// callers must log only the returned `out` buffer.
pub fn pseudonymizeTenant(tenant_id: []const u8, out: *[tenant_hash_hex_len]u8) []const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(tenant_id, &digest, .{});
    out.* = std.fmt.bytesToHex(digest[0..16], .lower);
    return out;
}

/// Writes `record` as one JSON object and terminates the line. Field names and
/// order are fixed here, matching the declared struct fields, so rendering and
/// redaction can be tested without a logger dependency.
pub fn writeJson(record: LogRecord, w: anytype) !void {
    var ws = std.json.writeStream(w, .{});
    try ws.beginObject();
    try writeStringField(&ws, "request_id", record.request_id);
    try writeStringField(&ws, "tenant_id_hash", record.tenant_id_hash);
    try writeStringField(&ws, "digest", record.digest);
    try ws.objectField("file_size");
    try ws.write(record.file_size);
    try writeStringField(&ws, "profile", record.profile);
    try ws.objectField("duration_ms");
    try ws.write(record.duration_ms);
    try writeStringField(&ws, "verdict", record.verdict);
    try writeStringField(&ws, "error_code", record.error_code);
    try writeStringField(&ws, "stage", record.stage);
    try writeStringField(&ws, "version", record.version);
    try writeStringField(&ws, "commit", record.commit);
    try ws.endObject();
    try w.writeByte('\n');
}

fn writeStringField(ws: anytype, name: []const u8, value: []const u8) !void {
    try ws.objectField(name);
    try ws.write(value);
}
