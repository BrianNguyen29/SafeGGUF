//! Compile-time build provenance, injected by `build.zig` through the
//! generated `build_options` module. Surfaced to users as
//! `safegguf --version`. Values derive from the source tree, toolchain, and
//! build options only (no wall-clock timestamp).
const build_options = @import("build_options");
const safegguf = @import("safegguf");

pub const version = build_options.version;
pub const source_commit = build_options.source_commit;
pub const zig_version = build_options.zig_version;
pub const build_mode = build_options.build_mode;
pub const target = build_options.target;

/// Pinned upstream type-table source (`ggml`) the validation profiles derive
/// from; single source of truth is src/gguf/types.zig.
pub const ggml_target = safegguf.types.GGML_PINNED_VERSION;
pub const ggml_commit = safegguf.types.GGML_PINNED_COMMIT;
