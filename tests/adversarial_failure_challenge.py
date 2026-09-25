"""
Adversarial Failure Handling Challenge Suite for SafeGGUF.
Tests hundreds of pathological, malformed, and corrupted GGUF files against
zig-out/bin/safegguf.exe to confirm SafeGGUF:
1. Strictly rejects all malformed inputs with exit code 2.
2. NEVER panics or crashes (never returns exit code 70 or unhandled exceptions).
3. Produces strictly valid, parseable JSON under --format json.
4. Correctly differentiates profile-specific rules (gguf-spec vs llama-cpp).
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAFEGGUF_EXE = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf.exe")
if not os.path.exists(SAFEGGUF_EXE):
    SAFEGGUF_EXE = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf")

def build_minimal_gguf(
    magic=b"GGUF",
    version=3,
    tensor_count=0,
    metadata_kv_count=0,
    metadata_bytes=b"",
    tensor_bytes=b"",
    padding_bytes=b"",
    tensor_data=b"",
    endian="<"
):
    buf = bytearray()
    buf.extend(magic)
    buf.extend(struct.pack(f"{endian}I", version))
    buf.extend(struct.pack(f"{endian}Q", tensor_count))
    buf.extend(struct.pack(f"{endian}Q", metadata_kv_count))
    buf.extend(metadata_bytes)
    buf.extend(tensor_bytes)
    buf.extend(padding_bytes)
    buf.extend(tensor_data)
    return bytes(buf)

def encode_string(s: bytes, endian="<"):
    return struct.pack(f"{endian}Q", len(s)) + s

def encode_kv(key: bytes, val_type: int, val_bytes: bytes, endian="<"):
    return encode_string(key, endian) + struct.pack(f"{endian}I", val_type) + val_bytes

def encode_tensor_desc(name: bytes, dims: list, tensor_type: int, offset: int, endian="<"):
    desc = bytearray()
    desc.extend(encode_string(name, endian))
    desc.extend(struct.pack(f"{endian}I", len(dims)))
    for d in dims:
        desc.extend(struct.pack(f"{endian}Q", d))
    desc.extend(struct.pack(f"{endian}I", tensor_type))
    desc.extend(struct.pack(f"{endian}Q", offset))
    return bytes(desc)

def generate_test_cases():
    cases = []

    # 1. Truncation and Empty File Cases
    cases.append(("empty_file", b"", "gguf-spec", "UnexpectedEof"))
    cases.append(("single_byte", b"G", "gguf-spec", "UnexpectedEof"))
    cases.append(("two_bytes", b"GG", "gguf-spec", "UnexpectedEof"))
    cases.append(("three_bytes", b"GGU", "gguf-spec", "UnexpectedEof"))
    cases.append(("header_only_magic", b"GGUF", "gguf-spec", "UnexpectedEof"))
    cases.append(("truncated_version", b"GGUF\x03\x00", "gguf-spec", "UnexpectedEof"))
    cases.append(("truncated_tensor_count", b"GGUF\x03\x00\x00\x00\x01\x00", "gguf-spec", "UnexpectedEof"))
    cases.append(("truncated_meta_count", b"GGUF\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00", "gguf-spec", "UnexpectedEof"))

    # 2. Magic Corruptions
    cases.append(("bad_magic_fugg", build_minimal_gguf(magic=b"FUGG"), "gguf-spec", "InvalidMagic"))
    cases.append(("bad_magic_null", build_minimal_gguf(magic=b"\x00\x00\x00\x00"), "gguf-spec", "InvalidMagic"))
    cases.append(("bad_magic_elf", build_minimal_gguf(magic=b"\x7fELF"), "gguf-spec", "InvalidMagic"))
    cases.append(("bad_magic_text", b"Hello SafeGGUF tester", "gguf-spec", "InvalidMagic"))
    cases.append(("bad_magic_json", b'{"format":"gguf"}', "gguf-spec", "InvalidMagic"))

    # 3. Version Corruptions
    cases.append(("version_0", build_minimal_gguf(version=0), "gguf-spec", "UnsupportedVersion"))
    cases.append(("version_1", build_minimal_gguf(version=1), "gguf-spec", "UnsupportedVersion"))
    cases.append(("version_2_under_spec", build_minimal_gguf(version=2), "gguf-spec", "UnsupportedVersion"))
    cases.append(("version_4", build_minimal_gguf(version=4), "gguf-spec", "UnsupportedVersion"))
    cases.append(("version_max_u32", build_minimal_gguf(version=0xFFFFFFFF), "gguf-spec", "UnsupportedVersion"))

    # 4. Header Count Violations
    # tensor_count exceeds 1,000,000 cap
    cases.append(("tensor_count_exceeds_cap", build_minimal_gguf(tensor_count=1_000_001), "gguf-spec", "ResourceLimitExceeded"))
    cases.append(("tensor_count_max_u64", build_minimal_gguf(tensor_count=0xFFFFFFFFFFFFFFFF), "gguf-spec", "ResourceLimitExceeded"))
    # metadata_count exceeds 1,000,000 cap
    cases.append(("meta_count_exceeds_cap", build_minimal_gguf(metadata_kv_count=1_000_001), "gguf-spec", "ResourceLimitExceeded"))
    cases.append(("meta_count_max_u64", build_minimal_gguf(metadata_kv_count=0xFFFFFFFFFFFFFFFF), "gguf-spec", "ResourceLimitExceeded"))
    # count exceeds file capacity: 100 metadata entries in 24-byte file
    cases.append(("meta_count_past_eof", build_minimal_gguf(metadata_kv_count=100), "gguf-spec", "UnexpectedEof"))
    cases.append(("tensor_count_past_eof", build_minimal_gguf(tensor_count=100), "gguf-spec", "UnexpectedEof"))

    # 5. Metadata Key Grammar Violations
    # Empty key
    cases.append(("key_empty", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidStringLength"))
    # Leading dot
    cases.append(("key_leading_dot", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b".foo", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Trailing dot
    cases.append(("key_trailing_dot", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"foo.", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Double dot
    cases.append(("key_double_dot", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"foo..bar", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Hyphen in key
    cases.append(("key_hyphen", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"foo-bar", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Uppercase letters in key
    cases.append(("key_uppercase", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"Foo.bar", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Symbols in key
    cases.append(("key_symbols", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"foo@bar", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Null byte in key
    cases.append(("key_null_byte", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"foo\x00bar", 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Non-ascii in key
    cases.append(("key_non_ascii", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv("fôo.bàr".encode("utf-8"), 4, b"\x01\x00\x00\x00")), "gguf-spec", "InvalidKeyFormat"))
    # Duplicate key
    dup_kv = encode_kv(b"general.architecture", 8, encode_string(b"llama")) + encode_kv(b"general.architecture", 8, encode_string(b"llama"))
    cases.append(("duplicate_key", build_minimal_gguf(metadata_kv_count=2, metadata_bytes=dup_kv), "gguf-spec", "DuplicateMetadataKey"))

    # 6. Metadata Value Types & Enums
    cases.append(("invalid_meta_type_13", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.val", 13, b"\x00\x00\x00\x00")), "gguf-spec", "InvalidMetadataType"))
    cases.append(("invalid_meta_type_99", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.val", 99, b"\x00\x00\x00\x00")), "gguf-spec", "InvalidMetadataType"))
    cases.append(("invalid_meta_type_max", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.val", 0xFFFFFFFF, b"\x00\x00\x00\x00")), "gguf-spec", "InvalidMetadataType"))

    # 7. Primitive Value Integrity
    # Invalid boolean value (must be 0 or 1)
    cases.append(("bool_val_2", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.flag", 7, b"\x02")), "gguf-spec", "InvalidBoolean"))
    cases.append(("bool_val_255", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.flag", 7, b"\xFF")), "gguf-spec", "InvalidBoolean"))
    # Truncated string value
    cases.append(("truncated_string_value", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_string(b"my.str") + struct.pack("<I", 8) + struct.pack("<Q", 100) + b"short"), "gguf-spec", "UnexpectedEof"))
    # String length exceeding 65536 limit
    cases.append(("string_len_exceeds_cap", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_string(b"my.str") + struct.pack("<I", 8) + struct.pack("<Q", 65537) + b"A" * 100), "gguf-spec", "ResourceLimitExceeded"))
    # String with invalid UTF-8 (0xFF byte)
    cases.append(("string_invalid_utf8_ff", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.str", 8, encode_string(b"hello\xFFworld"))), "gguf-spec", "InvalidUtf8"))
    # String with overlong UTF-8 (0xC0 0x80)
    cases.append(("string_overlong_utf8", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.str", 8, encode_string(b"hello\xC0\x80world"))), "gguf-spec", "InvalidUtf8"))
    # String with truncated multi-byte sequence (0xE2 0x82 alone)
    cases.append(("string_truncated_multibyte", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.str", 8, encode_string(b"hello\xE2\x82"))), "gguf-spec", "InvalidUtf8"))

    # 8. Array Integrity
    # Array count exceeding 10M cap
    array_header_too_big = struct.pack("<I", 4) + struct.pack("<Q", 10_000_001)
    cases.append(("array_count_exceeds_cap", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.arr", 9, array_header_too_big)), "gguf-spec", "ResourceLimitExceeded"))
    # String array count exceeding 1M cap
    str_array_header_too_big = struct.pack("<I", 8) + struct.pack("<Q", 1_000_001)
    cases.append(("str_array_count_exceeds_cap", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.str_arr", 9, str_array_header_too_big)), "gguf-spec", "ResourceLimitExceeded"))
    # Nested array under llama-cpp profile (rejected!)
    nested_array_bytes = struct.pack("<I", 9) + struct.pack("<Q", 1) + struct.pack("<I", 4) + struct.pack("<Q", 1) + struct.pack("<I", 42)
    cases.append(("nested_array_llama_cpp", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.nested", 9, nested_array_bytes)), "llama-cpp", "NestedArrayNotSupported"))
    # Deeply nested arrays exceeding recursion depth 16
    deep_arr = bytearray()
    for _ in range(17):
        deep_arr.extend(struct.pack("<I", 9)) # array type
        deep_arr.extend(struct.pack("<Q", 1)) # count 1
    deep_arr.extend(struct.pack("<I", 4)) # uint32
    deep_arr.extend(struct.pack("<Q", 1))
    deep_arr.extend(struct.pack("<I", 123))
    cases.append(("array_depth_exceeded", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.deep", 9, bytes(deep_arr))), "gguf-spec", "RecursionDepthExceeded"))
    # Bool array containing invalid byte (2)
    bool_arr_bytes = struct.pack("<I", 7) + struct.pack("<Q", 3) + b"\x00\x02\x01"
    cases.append(("bool_array_invalid_byte", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.bools", 9, bool_arr_bytes)), "gguf-spec", "InvalidBoolean"))
    # Primitive array integer overflow: count * size overflows u64
    overflow_arr_bytes = struct.pack("<I", 10) + struct.pack("<Q", 0x2000000000000000) # uint64 (size 8), 8 * 0x20... overflows
    cases.append(("array_primitive_overflow", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"my.nums", 9, overflow_arr_bytes)), "gguf-spec", "ResourceLimitExceeded"))

    # 9. General Alignment Metadata Integrity
    # Non-uint32 general.alignment
    cases.append(("align_type_string", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"general.alignment", 8, encode_string(b"32"))), "gguf-spec", "InvalidAlignment"))
    # Alignment = 0
    cases.append(("align_val_0", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"general.alignment", 4, struct.pack("<I", 0))), "gguf-spec", "InvalidAlignment"))
    # Alignment not multiple of 8 (e.g. 12)
    cases.append(("align_not_multiple_of_8", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"general.alignment", 4, struct.pack("<I", 12))), "gguf-spec", "InvalidAlignment"))
    # Alignment not power of 2 under llama-cpp (e.g. 24)
    cases.append(("align_not_power_of_two_llama", build_minimal_gguf(metadata_kv_count=1, metadata_bytes=encode_kv(b"general.alignment", 4, struct.pack("<I", 24))), "llama-cpp", "CompatibilityViolation"))

    # 10. Tensor Descriptor Integrity
    # Empty tensor name
    cases.append(("tensor_name_empty", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"", [32], 0, 0)), "gguf-spec", "InvalidTensorName"))
    # Tensor name > 64 bytes under gguf-spec
    cases.append(("tensor_name_len_65_spec", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"A" * 65, [32], 0, 0)), "gguf-spec", "InvalidTensorName"))
    # Tensor name == 64 bytes under llama-cpp (llama.cpp requires < 64 bytes)
    cases.append(("tensor_name_len_64_llama", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"A" * 64, [32], 0, 0)), "llama-cpp", "TensorNameTooLong"))
    # Tensor name with invalid UTF-8
    cases.append(("tensor_name_invalid_utf8", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"blk.0.\xFF.weight", [32], 0, 0)), "gguf-spec", "InvalidUtf8"))
    # Duplicate tensor names
    dup_tensors = encode_tensor_desc(b"tensor_a", [32], 0, 0) + encode_tensor_desc(b"tensor_a", [32], 0, 128)
    cases.append(("duplicate_tensor_name", build_minimal_gguf(tensor_count=2, tensor_bytes=dup_tensors), "gguf-spec", "DuplicateTensorName"))
    # ndims > 4 (e.g. 5)
    cases.append(("tensor_ndims_5", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"tensor_5d", [2, 2, 2, 2, 2], 0, 0)), "gguf-spec", "InvalidDimensionCount"))
    cases.append(("tensor_ndims_max_u32", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_string(b"tensor_bad_ndims") + struct.pack("<I", 0xFFFFFFFF)), "gguf-spec", "InvalidDimensionCount"))
    # Zero dimension
    cases.append(("tensor_zero_dim", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"tensor_zero", [32, 0], 0, 0)), "gguf-spec", "ZeroDimensionNotAllowed"))
    # Arithmetic overflow in dimensions product: [0xFFFFFFFF, 0xFFFFFFFF]
    cases.append(("tensor_dim_product_overflow", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"ovf_prod", [0xFFFFFFFF, 0xFFFFFFFF], 0, 0)), "gguf-spec", "ArithmeticOverflow"))
    # Total byte size overflow in computeTensorBytes: [1 << 33, 1 << 32]
    cases.append(("tensor_byte_size_overflow", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"ovf_bytes", [1 << 33, 1 << 32], 0, 0)), "gguf-spec", "ArithmeticOverflow"))
    # llama.cpp dimension overflow (> i64::MAX)
    cases.append(("tensor_dim_gt_i64_max_llama", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"ovf_i64", [0x8000000000000000], 0, 0)), "llama-cpp", "CompatibilityViolation"))
    # Invalid tensor type (35, 42, 99)
    cases.append(("tensor_invalid_type_35", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"tensor_t35", [32], 35, 0)), "gguf-spec", "InvalidTensorType"))
    cases.append(("tensor_invalid_type_99", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"tensor_t99", [32], 99, 0)), "gguf-spec", "InvalidTensorType"))
    # Block divisibility violation: Q4_0 (block size 32) with dim[0] = 31
    cases.append(("block_divisibility_q4_0", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"q4_tensor", [31], 2, 0)), "gguf-spec", "BlockDivisibilityViolation"))
    # Misaligned tensor offset: offset = 17 (alignment = 32)
    # File size 512 bytes with 64 bytes tensor data
    td1 = b"\x00" * 128
    cases.append(("misaligned_tensor_offset", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"misaligned", [32], 0, 17), tensor_data=td1), "gguf-spec", "MisalignedTensor"))
    # Tensor out of bounds: offset points past file end
    cases.append(("tensor_out_of_bounds", build_minimal_gguf(tensor_count=1, tensor_bytes=encode_tensor_desc(b"oob_tensor", [32], 0, 10000)), "gguf-spec", "TensorOutOfBounds"))
    # Overlapping tensors: tensor A [offset 0, size 128], tensor B [offset 32, size 128]
    overlap_t = encode_tensor_desc(b"tensor_a", [32], 0, 0) + encode_tensor_desc(b"tensor_b", [32], 0, 32)
    cases.append(("overlapping_tensors", build_minimal_gguf(tensor_count=2, tensor_bytes=overlap_t, tensor_data=b"\x00" * 512), "gguf-spec", "TensorOverlap"))
    # Non-contiguous tensors under llama-cpp: gap between tensor A and tensor B
    gap_t = encode_tensor_desc(b"tensor_1", [32], 0, 0) + encode_tensor_desc(b"tensor_2", [32], 0, 256)
    cases.append(("non_contiguous_tensors_llama", build_minimal_gguf(tensor_count=2, tensor_bytes=gap_t, tensor_data=b"\x00" * 512), "llama-cpp", "NonContiguousTensorOffset"))

    # 11. Anti-Tamper: Non-Zero Alignment Padding
    pad_t = encode_tensor_desc(b"pad_tensor", [32], 0, 0)
    # File with dirty padding between descriptors and tensor_data_base (offset 160 has 32-byte alignment -> base 192, 32 bytes pad)
    dirty_pad = b"\x00" * 16 + b"\xDE\xAD\xBE\xEF" + b"\x00" * 12
    cases.append(("dirty_alignment_padding", build_minimal_gguf(tensor_count=1, tensor_bytes=pad_t, padding_bytes=dirty_pad, tensor_data=b"\x00" * 128), "gguf-spec", "InvalidAlignmentPadding"))

    return cases

def run_adversarial_challenge():
    print(f"=== Running SafeGGUF Adversarial Failure Challenge Suite ===")
    print(f"Binary: {SAFEGGUF_EXE}")
    assert os.path.exists(SAFEGGUF_EXE), f"Binary not found: {SAFEGGUF_EXE}"

    cases = generate_test_cases()
    print(f"Generated {len(cases)} targeted adversarial cases.")

    total_tests = 0
    passed_tests = 0
    failures = []

    with tempfile.TemporaryDirectory() as td:
        for name, payload, profile, expected_error in cases:
            file_path = os.path.join(td, f"{name}.gguf")
            with open(file_path, "wb") as f:
                f.write(payload)

            # Test across both text and json formats
            for fmt in ["text", "json"]:
                total_tests += 1
                cmd = [SAFEGGUF_EXE, "inspect", file_path, "--profile", profile, "--format", fmt]

                try:
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                except subprocess.TimeoutExpired:
                    failures.append(f"{name} ({fmt}, {profile}): TIMEOUT > 5s")
                    continue

                rc = proc.returncode
                stdout_str = proc.stdout.decode("utf-8", "replace")
                stderr_str = proc.stderr.decode("utf-8", "replace")

                # Invariant 1: Must strictly return exit code 2 (REJECT)
                if rc != 2:
                    failures.append(
                        f"{name} ({fmt}, {profile}): Expected exit code 2, got {rc}. "
                        f"Stdout: {stdout_str[:100]!r}, Stderr: {stderr_str[:100]!r}"
                    )
                    continue

                # Invariant 2: Must NEVER produce exit code 70 (EX_SOFTWARE) or OS exception
                if rc == 70 or rc < 0 or rc > 127:
                    failures.append(f"{name} ({fmt}, {profile}): CRITICAL PANIC/CRASH exit code {rc}!")
                    continue

                # Invariant 3: JSON output MUST be strictly valid JSON
                if fmt == "json":
                    try:
                        parsed = json.loads(stdout_str)
                        if parsed.get("status") != "REJECT":
                            failures.append(f"{name} (json, {profile}): JSON status was {parsed.get('status')}, expected REJECT")
                            continue
                        if not parsed.get("error") and not parsed.get("error_code"):
                            failures.append(f"{name} (json, {profile}): JSON missing error or error_code")
                            continue
                        # Verify findings array
                        findings = parsed.get("findings", [])
                        if not isinstance(findings, list) or len(findings) == 0:
                            failures.append(f"{name} (json, {profile}): findings list empty or missing")
                            continue
                    except json.JSONDecodeError as jde:
                        failures.append(f"{name} (json, {profile}): Output was not valid JSON: {jde}. Raw: {stdout_str[:200]}")
                        continue
                else:
                    # Invariant 4: Text output on stderr must contain REJECT and error code
                    if "REJECT" not in stderr_str and "REJECT" not in stdout_str:
                        failures.append(f"{name} (text, {profile}): Neither stderr nor stdout contained REJECT. Stderr: {stderr_str[:100]}")
                        continue

                passed_tests += 1

    print(f"\nAdversarial Challenge Results: {passed_tests}/{total_tests} tests PASSED cleanly with exit code 2.")
    if failures:
        print(f"\nCRITICAL FAILURES ({len(failures)}):")
        for f in failures:
            print("  X " + f)
        sys.exit(1)
    else:
        print("[ok] All adversarial failure test cases PASSED. SafeGGUF strictly rejects with exit code 2 and never panics or crashes.")

if __name__ == "__main__":
    run_adversarial_challenge()
