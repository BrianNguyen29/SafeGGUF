pub const Profile = enum {
    gguf_spec,
    llama_cpp,
};

pub const Limits = struct {
    max_tensors: u64 = 1_000_000,
    max_metadata_entries: u64 = 1_000_000,
    max_string_bytes: u64 = 65536,
    max_tensor_name_bytes: u64 = 64,
    max_dimensions: u32 = 4,
    max_array_elements: u64 = 10_000_000,
    max_variable_array_elements: u64 = 100_000,
    max_metadata_depth: u32 = 8,
    max_total_alloc_bytes: u64 = 128 * 1024 * 1024,
    profile: Profile = .gguf_spec,
};
