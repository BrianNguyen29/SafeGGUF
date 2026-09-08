pub const Limits = struct {
    max_metadata_entries: u64 = 1_000_000,
    max_tensors: u64 = 1_000_000,
    max_string_bytes: u64 = 16 * 1024 * 1024,
    max_array_elements: u64 = 10_000_000,
    max_dimensions: u32 = 4,
};
