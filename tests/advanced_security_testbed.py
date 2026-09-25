#!/usr/bin/env python3
"""
Advanced Security Testbed for SafeGGUF (Milestone M2 / Requirement R2).

Automated adversary and differential test suite that:
1. Programmatically generates genuine malicious, malformed, and edge-case GGUF v3
   fixtures into tests/fixtures/security_testbed/.
2. Exercises AT LEAST 5 comprehensive security attack and differential scenarios:
   - Scenario 1: Arithmetic Overflow (u64 product, block count, byte accum, signed i64)
   - Scenario 2: Structural & Alignment Tampering (zero-padding anti-tamper, OOB, overlap, misalignment)
   - Scenario 3: Resource Exhaustion & Quota Caps (QuotaAllocator 128MB cap exit 2 not 70, WorkBudget, caps)
   - Scenario 4: Profile Decoupling Differential Testing (gguf-spec vs llama-cpp 4-axis divergence)
   - Scenario 5: Steganographic & Metadata Integrity Tampering (invalid UTF-8, overlong, type slots, grammar)
3. Verifies fail-closed guarantees:
   - All malicious cases strictly exit with code 2 (REJECT).
   - NEVER panics, crashes, or returns exit code 70 (EX_SOFTWARE) or OS exceptions.
   - Profile decoupling differential tests assert PASS (exit 0) under gguf-spec
     and REJECT (exit 2) under llama-cpp with exact compatibility error codes.
   - Structured JSON diagnostics conform strictly to SafeGGUF JSON schema.

Usage:
  python tests/advanced_security_testbed.py              # Generate + verify all
  python tests/advanced_security_testbed.py --generate-only
  python tests/advanced_security_testbed.py --verify-only
  python tests/advanced_security_testbed.py --scenario <1-5>
  python tests/advanced_security_testbed.py --json-report
  python tests/advanced_security_testbed.py --verbose
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
FIXTURES_DIR = os.path.join(SCRIPT_DIR, "fixtures", "security_testbed")
MANIFEST_PATH = os.path.join(FIXTURES_DIR, "manifest.json")


def find_safegguf_binary(override_path: Optional[str] = None) -> str:
    """Locates the compiled safegguf executable."""
    if override_path:
        if os.path.isfile(override_path):
            return os.path.abspath(override_path)
        raise FileNotFoundError(f"Specified binary not found: {override_path}")

    candidates = [
        os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf.exe"),
        os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    raise FileNotFoundError(
        f"SafeGGUF binary not found. Looked in: {candidates}. Run 'zig build' first."
    )


# ==============================================================================
# Binary GGUF Serialization Helpers
# ==============================================================================

def align_up(val: int, align: int) -> int:
    rem = val % align
    return val if rem == 0 else val + (align - rem)


def encode_string(s: bytes, endian: str = "<") -> bytes:
    return struct.pack(f"{endian}Q", len(s)) + s


def encode_kv(key: bytes, val_type: int, val_bytes: bytes, endian: str = "<") -> bytes:
    return encode_string(key, endian) + struct.pack(f"{endian}I", val_type) + val_bytes


def encode_tensor_desc(
    name: bytes,
    dims: List[int],
    tensor_type: int,
    offset: int,
    endian: str = "<"
) -> bytes:
    desc = bytearray()
    desc.extend(encode_string(name, endian))
    desc.extend(struct.pack(f"{endian}I", len(dims)))
    for d in dims:
        desc.extend(struct.pack(f"{endian}Q", d))
    desc.extend(struct.pack(f"{endian}I", tensor_type))
    desc.extend(struct.pack(f"{endian}Q", offset))
    return bytes(desc)


def build_gguf_raw(
    magic: bytes = b"GGUF",
    version: int = 3,
    tensor_count: int = 0,
    metadata_kv_count: int = 0,
    metadata_bytes: bytes = b"",
    tensor_bytes: bytes = b"",
    padding_bytes: bytes = b"",
    tensor_data: bytes = b"",
    endian: str = "<"
) -> bytes:
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


# ==============================================================================
# Fixture Generators (All 5 Scenarios)
# ==============================================================================

# --- Scenario 1: Arithmetic Overflow ---

def gen_s1_extreme_dims_product(path: str) -> None:
    """Extreme dimensions integer multiplication overflow exceeding u64::MAX."""
    # dims = [0xFFFFFFFFFFFFFFFF, 2] -> 0xFFFFFFFFFFFFFFFF * 2 overflows u64
    tensor = encode_tensor_desc(b"ovf_prod", [0xFFFFFFFFFFFFFFFF, 2], 0, 0)
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor)
    with open(path, "wb") as f:
        f.write(data)


def gen_s1_block_div_count(path: str) -> None:
    """Block count calculation overflow: n_blocks * type_size > u64::MAX."""
    # dims = [1 << 63], F32 (type 0, block_size 1, type_size 4).
    # n_elements = 1 << 63 (fits u64), n_blocks = 1 << 63 (fits u64),
    # nbytes = (1 << 63) * 4 overflows u64!
    tensor = encode_tensor_desc(b"ovf_block", [1 << 63], 0, 0)
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor)
    with open(path, "wb") as f:
        f.write(data)


def gen_s1_byte_accumulation(path: str) -> None:
    """Byte size accumulation exceeding u64::MAX in payload offset calculation."""
    # offset = 0xFFFFFFFFFFFFFF00, dims = [128] (512 bytes F32)
    # abs_offset = 64 + 0xFFFFFFFFFFFFFF00 = 0xFFFFFFFFFFFFFF40
    # end_offset = 0xFFFFFFFFFFFFFF40 + 0x200 overflows u64!
    tensor = encode_tensor_desc(b"ovf_accum", [128], 0, 0xFFFFFFFFFFFFFF00)
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor)
    with open(path, "wb") as f:
        f.write(data)


def gen_s1_signed_i64_dim(path: str) -> None:
    """Signed 64-bit overflow (dim > INT64_MAX) under llama-cpp profile."""
    # dim = 0x8000000000000000 (2^63 > INT64_MAX)
    tensor = encode_tensor_desc(b"ovf_sdim", [0x8000000000000000], 0, 0)
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor)
    with open(path, "wb") as f:
        f.write(data)


def gen_s1_signed_i64_product(path: str) -> None:
    """Signed 64-bit product overflow (> INT64_MAX) under llama-cpp profile."""
    # dims = [0x4000000000000000, 2] -> each <= INT64_MAX, but product is 2^63 > INT64_MAX
    tensor = encode_tensor_desc(b"ovf_sprod", [0x4000000000000000, 2], 0, 0)
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor)
    with open(path, "wb") as f:
        f.write(data)


# --- Scenario 2: Structural & Alignment Tampering ---

def gen_s2_padding_nonzero(path: str) -> None:
    """Zero-padding descriptor table tampering: Inject non-zero bytes (0xDE, 0xAD)."""
    tensor = encode_tensor_desc(b"pad_tensor", [32], 0, 0)
    # Header (24) + Tensor (8+10+4+8+4+8=42) = 66 bytes.
    # Align to 32 -> 96 bytes (30 bytes padding).
    hdr_len = 24 + len(tensor)
    data_base = align_up(hdr_len, 32)
    pad_len = data_base - hdr_len
    pad = bytearray(b"\x00" * pad_len)
    pad[pad_len // 2] = 0xDE
    pad[pad_len // 2 + 1] = 0xAD
    payload = b"\x00" * 128
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor, padding_bytes=bytes(pad), tensor_data=payload)
    with open(path, "wb") as f:
        f.write(data)


def gen_s2_padding_multichunk(path: str) -> None:
    """Multi-chunk zero-padding tampering crossing 256-byte inspection buffer."""
    # Set general.alignment = 512.
    meta = encode_kv(b"general.alignment", 4, struct.pack("<I", 512))
    tensor = encode_tensor_desc(b"pad_multi", [32], 0, 0)
    hdr_len = 24 + len(meta) + len(tensor)
    data_base = align_up(hdr_len, 512)
    pad_len = data_base - hdr_len
    pad = bytearray(b"\x00" * pad_len)
    # Inject dirty byte at index 300 (> 256 chunk boundary)
    pad[300] = 0xAA
    payload = b"\x00" * 128
    data = build_gguf_raw(
        metadata_kv_count=1,
        metadata_bytes=meta,
        tensor_count=1,
        tensor_bytes=tensor,
        padding_bytes=bytes(pad),
        tensor_data=payload
    )
    with open(path, "wb") as f:
        f.write(data)


def gen_s2_oob_offset(path: str) -> None:
    """Out-of-bounds offset: Tensor offset points beyond physical file size (aligned to 32)."""
    # Offset 1024 is aligned to 32 (1024 % 32 == 0), but total file size is ~256 bytes
    tensor = encode_tensor_desc(b"oob_tensor", [32], 0, 1024)
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor, tensor_data=b"\x00" * 64)
    with open(path, "wb") as f:
        f.write(data)


def gen_s2_overlapping_payload(path: str) -> None:
    """Overlapping tensor byte ranges in payload ([0..128) and [32..160))."""
    t1 = encode_tensor_desc(b"tensor_a", [32], 0, 0)   # 32*4 = 128 bytes
    t2 = encode_tensor_desc(b"tensor_b", [32], 0, 32)  # starts at 32 -> overlap!
    payload = b"\x00" * 512
    data = build_gguf_raw(tensor_count=2, tensor_bytes=t1 + t2, tensor_data=payload)
    with open(path, "wb") as f:
        f.write(data)


def gen_s2_misaligned_offset(path: str) -> None:
    """Misaligned tensor offset: offset is not a multiple of alignment."""
    # Alignment is 32, tensor offset is 17
    tensor = encode_tensor_desc(b"misaligned", [32], 0, 17)
    payload = b"\x00" * 256
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor, tensor_data=payload)
    with open(path, "wb") as f:
        f.write(data)


# --- Scenario 3: Resource Exhaustion & Quota Caps ---

def gen_s3_quota_alloc_ceiling_dos(path: str) -> None:
    """
    Allocation DoS: Exceed QuotaAllocator 128 MB default memory ceiling.
    Stream-writes 2,100 metadata keys of length 64,000 bytes.
    QuotaAllocator tracks allocated heap bytes; exceeding 128 MB sets quota_exceeded=true,
    caught by main.zig to exit code 2 (REJECT, E_TotalAllocationLimitExceeded) NOT 70 (host OOM).
    """
    kv_count = 2100
    key_len = 64000
    prefix_fmt = b"key_%06d_"
    padding = b"a" * (key_len - 11)

    with open(path, "wb") as f:
        f.write(b"GGUF" + struct.pack("<IQQ", 3, 0, kv_count))
        chunk = bytearray()
        for i in range(kv_count):
            k = (prefix_fmt % i) + padding
            chunk.extend(struct.pack("<Q", len(k)))
            chunk.extend(k)
            chunk.extend(struct.pack("<II", 4, 0))  # uint32, val = 0
            if len(chunk) >= 4 * 1024 * 1024:
                f.write(chunk)
                chunk.clear()
        if chunk:
            f.write(chunk)


def gen_s3_budget_units_exhaustion(path: str) -> None:
    """WorkBudget unit limit exhaustion: Array count exceeds 10,000,000 max_array_elements."""
    arr_header = struct.pack("<I", 4) + struct.pack("<Q", 10_000_001)
    meta = encode_kv(b"quota.huge_array", 9, arr_header)
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s3_budget_variable_array_cap(path: str) -> None:
    """Variable array element cap: string array count exceeds 1,000,000."""
    str_arr_header = struct.pack("<I", 8) + struct.pack("<Q", 1_000_001)
    meta = encode_kv(b"quota.var_array", 9, str_arr_header)
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s3_budget_string_len_cap(path: str) -> None:
    """String length cap: String length exceeds 65,536 max_string_bytes."""
    val_header = struct.pack("<Q", 65537) + b"A" * 64
    meta = encode_string(b"quota.long_string") + struct.pack("<I", 8) + val_header
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s3_budget_tensor_count_cap(path: str) -> None:
    """Tensor count cap: Header tensor_count exceeds 1,000,000 max_tensors."""
    data = build_gguf_raw(tensor_count=1_000_001)
    with open(path, "wb") as f:
        f.write(data)


# --- Scenario 4: Profile Decoupling Differential Testing ---

def gen_s4_diff_align_non_power_two(path: str) -> None:
    """
    Alignment multiple of 8 but not power-of-two (24).
    PASS under gguf-spec, REJECT under llama-cpp (E_CompatibilityViolation).
    """
    alignment = 24
    meta = encode_kv(b"general.alignment", 4, struct.pack("<I", alignment))
    tensor = encode_tensor_desc(b"tensor_a", [24], 0, 0)
    hdr_len = 24 + len(meta) + len(tensor)
    data_base = align_up(hdr_len, alignment)
    pad = b"\x00" * (data_base - hdr_len)
    payload = b"\x00" * 96  # 24 elements * 4 bytes
    data = build_gguf_raw(
        metadata_kv_count=1,
        metadata_bytes=meta,
        tensor_count=1,
        tensor_bytes=tensor,
        padding_bytes=pad,
        tensor_data=payload
    )
    with open(path, "wb") as f:
        f.write(data)


def gen_s4_diff_name_exact_64(path: str) -> None:
    """
    Tensor name length exactly 64 bytes.
    PASS under gguf-spec, REJECT under llama-cpp (E_TensorNameTooLong).
    """
    name_64 = b"a" * 64
    tensor = encode_tensor_desc(name_64, [32], 0, 0)
    hdr_len = 24 + len(tensor)
    data_base = align_up(hdr_len, 32)
    pad = b"\x00" * (data_base - hdr_len)
    payload = b"\x00" * 128
    data = build_gguf_raw(
        tensor_count=1,
        tensor_bytes=tensor,
        padding_bytes=pad,
        tensor_data=payload
    )
    with open(path, "wb") as f:
        f.write(data)


def gen_s4_diff_nested_array(path: str) -> None:
    """
    Nested metadata array (array of arrays).
    PASS under gguf-spec, REJECT under llama-cpp (E_NestedArrayNotSupported).
    """
    # outer array: element_type = array (9), count = 1
    # inner array: element_type = uint32 (4), count = 2, values = [10, 20]
    val = (
        struct.pack("<I", 9) + struct.pack("<Q", 1) +
        struct.pack("<I", 4) + struct.pack("<Q", 2) +
        struct.pack("<I", 10) + struct.pack("<I", 20)
    )
    meta = encode_kv(b"test.nested_arr", 9, val)
    hdr_len = 24 + len(meta)
    data_base = align_up(hdr_len, 32)
    pad = b"\x00" * (data_base - hdr_len)
    data = build_gguf_raw(
        metadata_kv_count=1,
        metadata_bytes=meta,
        padding_bytes=pad
    )
    with open(path, "wb") as f:
        f.write(data)


def gen_s4_diff_non_contiguous_gap(path: str) -> None:
    """
    Non-contiguous tensors with an aligned gap between them.
    PASS under gguf-spec, REJECT under llama-cpp (E_NonContiguousTensorOffset).
    """
    # Tensor 1: offset 0, size 32 bytes
    # Tensor 2: offset 64 (gap of 32 bytes), size 32 bytes
    t1 = encode_tensor_desc(b"tensor_1", [8], 0, 0)
    t2 = encode_tensor_desc(b"tensor_2", [8], 0, 64)
    hdr_len = 24 + len(t1) + len(t2)
    data_base = align_up(hdr_len, 32)
    pad = b"\x00" * (data_base - hdr_len)
    payload = b"\x00" * 128  # covers up to offset 96
    data = build_gguf_raw(
        tensor_count=2,
        tensor_bytes=t1 + t2,
        padding_bytes=pad,
        tensor_data=payload
    )
    with open(path, "wb") as f:
        f.write(data)


# --- Scenario 5: Steganographic & Metadata Integrity Tampering ---

def gen_s5_stego_invalid_utf8_tensor_name(path: str) -> None:
    """Invalid UTF-8 byte (0xFF) injected into tensor descriptor name."""
    tname = b"blk.0.\xFF.weight"
    tensor = encode_tensor_desc(tname, [32], 0, 0)
    data = build_gguf_raw(tensor_count=1, tensor_bytes=tensor)
    with open(path, "wb") as f:
        f.write(data)


def gen_s5_stego_invalid_utf8_meta_val(path: str) -> None:
    """Invalid UTF-8 byte (0xFF) injected into metadata string value."""
    meta = encode_kv(b"test.str", 8, encode_string(b"hello\xFFworld"))
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s5_stego_overlong_utf8_nul(path: str) -> None:
    """Steganographic overlong multi-byte UTF-8 sequence (0xC0 0x80 for NUL)."""
    meta = encode_kv(b"test.stego", 8, encode_string(b"secret\xC0\x80payload"))
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s5_stego_truncated_utf8_seq(path: str) -> None:
    """Truncated multi-byte UTF-8 sequence (0xE2 0x82 missing continuation byte)."""
    meta = encode_kv(b"test.trunc", 8, encode_string(b"prefix\xE2\x82"))
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s5_stego_invalid_meta_type_99(path: str) -> None:
    """Tampered metadata value type slot: unknown enum 99 (valid range 0..12)."""
    meta = encode_kv(b"test.bad_type", 99, struct.pack("<I", 0))
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s5_stego_invalid_meta_type_255(path: str) -> None:
    """Tampered metadata value type slot: out-of-range byte 255."""
    meta = encode_kv(b"test.bad_type_255", 255, struct.pack("<I", 0))
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


def gen_s5_stego_tampered_key_grammar(path: str) -> None:
    """Tampered metadata key grammar violating strict lower_snake_case dot separation."""
    bad_key = b"bad-key..Name_With_Uppercase"
    meta = encode_kv(bad_key, 4, struct.pack("<I", 1))
    data = build_gguf_raw(metadata_kv_count=1, metadata_bytes=meta)
    with open(path, "wb") as f:
        f.write(data)


# ==============================================================================
# Comprehensive Test Registry
# ==============================================================================

FIXTURES_SPEC = [
    # Scenario 1: Arithmetic Overflow
    {
        "id": "s1-extreme-dims-product",
        "scenario": 1,
        "scenario_name": "Arithmetic Overflow",
        "filename": "scenario1_overflow_extreme_dims_product.gguf",
        "description": "Extreme dimensions integer multiplication overflow exceeding u64::MAX",
        "generator": gen_s1_extreme_dims_product,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_ArithmeticOverflow",
            },
            {
                "profile": "llama-cpp",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_CompatibilityViolation",
            },
        ],
    },
    {
        "id": "s1-block-div-count",
        "scenario": 1,
        "scenario_name": "Arithmetic Overflow",
        "filename": "scenario1_overflow_block_div_count.gguf",
        "description": "Block count calculation overflow: n_blocks * type_size > u64::MAX",
        "generator": gen_s1_block_div_count,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_ArithmeticOverflow",
            },
        ],
    },
    {
        "id": "s1-byte-accumulation",
        "scenario": 1,
        "scenario_name": "Arithmetic Overflow",
        "filename": "scenario1_overflow_byte_accumulation.gguf",
        "description": "Byte size accumulation exceeding u64::MAX in payload offset calculation",
        "generator": gen_s1_byte_accumulation,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_ArithmeticOverflow",
            },
        ],
    },
    {
        "id": "s1-signed-i64-dim",
        "scenario": 1,
        "scenario_name": "Arithmetic Overflow",
        "filename": "scenario1_overflow_signed_i64_dim.gguf",
        "description": "Signed 64-bit overflow (dim > INT64_MAX) under llama-cpp profile",
        "generator": gen_s1_signed_i64_dim,
        "tests": [
            {
                "profile": "llama-cpp",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_CompatibilityViolation",
            },
        ],
    },
    {
        "id": "s1-signed-i64-product",
        "scenario": 1,
        "scenario_name": "Arithmetic Overflow",
        "filename": "scenario1_overflow_signed_i64_product.gguf",
        "description": "Signed 64-bit product overflow (> INT64_MAX) under llama-cpp profile",
        "generator": gen_s1_signed_i64_product,
        "tests": [
            {
                "profile": "llama-cpp",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_CompatibilityViolation",
            },
        ],
    },

    # Scenario 2: Structural & Alignment Tampering
    {
        "id": "s2-padding-nonzero",
        "scenario": 2,
        "scenario_name": "Structural & Alignment Tampering",
        "filename": "scenario2_tamper_padding_nonzero.gguf",
        "description": "Zero-padding descriptor table tampering: Inject non-zero bytes (0xDE, 0xAD)",
        "generator": gen_s2_padding_nonzero,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidAlignmentPadding",
            },
        ],
    },
    {
        "id": "s2-padding-multichunk",
        "scenario": 2,
        "scenario_name": "Structural & Alignment Tampering",
        "filename": "scenario2_tamper_padding_multichunk.gguf",
        "description": "Multi-chunk zero-padding tampering crossing 256-byte inspection buffer",
        "generator": gen_s2_padding_multichunk,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidAlignmentPadding",
            },
        ],
    },
    {
        "id": "s2-oob-offset",
        "scenario": 2,
        "scenario_name": "Structural & Alignment Tampering",
        "filename": "scenario2_tamper_oob_offset.gguf",
        "description": "Out-of-bounds offset: Tensor offset points beyond physical file size",
        "generator": gen_s2_oob_offset,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_TensorOutOfBounds",
            },
        ],
    },
    {
        "id": "s2-overlapping-payload",
        "scenario": 2,
        "scenario_name": "Structural & Alignment Tampering",
        "filename": "scenario2_tamper_overlapping_payload.gguf",
        "description": "Overlapping tensor byte ranges in payload ([0..128) and [32..160))",
        "generator": gen_s2_overlapping_payload,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_TensorOverlap",
            },
        ],
    },
    {
        "id": "s2-misaligned-offset",
        "scenario": 2,
        "scenario_name": "Structural & Alignment Tampering",
        "filename": "scenario2_tamper_misaligned_offset.gguf",
        "description": "Misaligned tensor offset: offset is not a multiple of alignment",
        "generator": gen_s2_misaligned_offset,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_MisalignedTensor",
            },
        ],
    },

    # Scenario 3: Resource Exhaustion & Quota Caps
    {
        "id": "s3-quota-alloc-ceiling-dos",
        "scenario": 3,
        "scenario_name": "Resource Exhaustion & Quota Caps",
        "filename": "scenario3_quota_alloc_ceiling_dos.gguf",
        "description": "Allocation DoS: Exceed QuotaAllocator 128 MB default memory ceiling",
        "generator": gen_s3_quota_alloc_ceiling_dos,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_TotalAllocationLimitExceeded",
            },
        ],
    },
    {
        "id": "s3-budget-units-exhaustion",
        "scenario": 3,
        "scenario_name": "Resource Exhaustion & Quota Caps",
        "filename": "scenario3_budget_units_exhaustion.gguf",
        "description": "WorkBudget unit limit exhaustion (array count > 10,000,000)",
        "generator": gen_s3_budget_units_exhaustion,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_ResourceLimitExceeded",
            },
        ],
    },
    {
        "id": "s3-budget-variable-array-cap",
        "scenario": 3,
        "scenario_name": "Resource Exhaustion & Quota Caps",
        "filename": "scenario3_budget_variable_array_cap.gguf",
        "description": "Variable array element cap: string array count exceeds 1,000,000",
        "generator": gen_s3_budget_variable_array_cap,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_ResourceLimitExceeded",
            },
        ],
    },
    {
        "id": "s3-budget-string-len-cap",
        "scenario": 3,
        "scenario_name": "Resource Exhaustion & Quota Caps",
        "filename": "scenario3_budget_string_len_cap.gguf",
        "description": "String length cap: String length exceeds 65,536 max_string_bytes",
        "generator": gen_s3_budget_string_len_cap,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_ResourceLimitExceeded",
            },
        ],
    },
    {
        "id": "s3-budget-tensor-count-cap",
        "scenario": 3,
        "scenario_name": "Resource Exhaustion & Quota Caps",
        "filename": "scenario3_budget_tensor_count_cap.gguf",
        "description": "Tensor count cap: Header tensor_count exceeds 1,000,000 max_tensors",
        "generator": gen_s3_budget_tensor_count_cap,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_ResourceLimitExceeded",
            },
        ],
    },

    # Scenario 4: Profile Decoupling Differential Testing
    {
        "id": "s4-diff-align-non-power-two",
        "scenario": 4,
        "scenario_name": "Profile Decoupling Differential Testing",
        "filename": "scenario4_diff_align_non_power_two.gguf",
        "description": "Alignment multiple of 8 but not power-of-two (24)",
        "generator": gen_s4_diff_align_non_power_two,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 0,
                "expected_status": "PASS",
                "expected_error": None,
            },
            {
                "profile": "llama-cpp",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_CompatibilityViolation",
            },
        ],
    },
    {
        "id": "s4-diff-name-exact-64",
        "scenario": 4,
        "scenario_name": "Profile Decoupling Differential Testing",
        "filename": "scenario4_diff_name_exact_64.gguf",
        "description": "Tensor name length exactly 64 bytes",
        "generator": gen_s4_diff_name_exact_64,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 0,
                "expected_status": "PASS",
                "expected_error": None,
            },
            {
                "profile": "llama-cpp",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_TensorNameTooLong",
            },
        ],
    },
    {
        "id": "s4-diff-nested-array",
        "scenario": 4,
        "scenario_name": "Profile Decoupling Differential Testing",
        "filename": "scenario4_diff_nested_array.gguf",
        "description": "Nested metadata array (array of arrays)",
        "generator": gen_s4_diff_nested_array,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 0,
                "expected_status": "PASS",
                "expected_error": None,
            },
            {
                "profile": "llama-cpp",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_NestedArrayNotSupported",
            },
        ],
    },
    {
        "id": "s4-diff-non-contiguous-gap",
        "scenario": 4,
        "scenario_name": "Profile Decoupling Differential Testing",
        "filename": "scenario4_diff_non_contiguous_gap.gguf",
        "description": "Non-contiguous tensors with an aligned gap between them",
        "generator": gen_s4_diff_non_contiguous_gap,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 0,
                "expected_status": "PASS",
                "expected_error": None,
            },
            {
                "profile": "llama-cpp",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_NonContiguousTensorOffset",
            },
        ],
    },

    # Scenario 5: Steganographic & Metadata Integrity Tampering
    {
        "id": "s5-stego-invalid-utf8-tensor-name",
        "scenario": 5,
        "scenario_name": "Steganographic & Metadata Integrity Tampering",
        "filename": "scenario5_stego_invalid_utf8_tensor_name.gguf",
        "description": "Invalid UTF-8 byte (0xFF) injected into tensor descriptor name",
        "generator": gen_s5_stego_invalid_utf8_tensor_name,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidUtf8",
            },
        ],
    },
    {
        "id": "s5-stego-invalid-utf8-meta-val",
        "scenario": 5,
        "scenario_name": "Steganographic & Metadata Integrity Tampering",
        "filename": "scenario5_stego_invalid_utf8_meta_val.gguf",
        "description": "Invalid UTF-8 byte (0xFF) injected into metadata string value",
        "generator": gen_s5_stego_invalid_utf8_meta_val,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidUtf8",
            },
        ],
    },
    {
        "id": "s5-stego-overlong-utf8-nul",
        "scenario": 5,
        "scenario_name": "Steganographic & Metadata Integrity Tampering",
        "filename": "scenario5_stego_overlong_utf8_nul.gguf",
        "description": "Steganographic overlong multi-byte UTF-8 sequence (0xC0 0x80 for NUL)",
        "generator": gen_s5_stego_overlong_utf8_nul,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidUtf8",
            },
        ],
    },
    {
        "id": "s5-stego-truncated-utf8-seq",
        "scenario": 5,
        "scenario_name": "Steganographic & Metadata Integrity Tampering",
        "filename": "scenario5_stego_truncated_utf8_seq.gguf",
        "description": "Truncated multi-byte UTF-8 sequence (0xE2 0x82 missing continuation byte)",
        "generator": gen_s5_stego_truncated_utf8_seq,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidUtf8",
            },
        ],
    },
    {
        "id": "s5-stego-invalid-meta-type-99",
        "scenario": 5,
        "scenario_name": "Steganographic & Metadata Integrity Tampering",
        "filename": "scenario5_stego_invalid_meta_type_99.gguf",
        "description": "Tampered metadata value type slot: unknown enum 99 (valid range 0..12)",
        "generator": gen_s5_stego_invalid_meta_type_99,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidMetadataType",
            },
        ],
    },
    {
        "id": "s5-stego-invalid-meta-type-255",
        "scenario": 5,
        "scenario_name": "Steganographic & Metadata Integrity Tampering",
        "filename": "scenario5_stego_invalid_meta_type_255.gguf",
        "description": "Tampered metadata value type slot: out-of-range byte 255",
        "generator": gen_s5_stego_invalid_meta_type_255,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidMetadataType",
            },
        ],
    },
    {
        "id": "s5-stego-tampered-key-grammar",
        "scenario": 5,
        "scenario_name": "Steganographic & Metadata Integrity Tampering",
        "filename": "scenario5_stego_tampered_key_grammar.gguf",
        "description": "Tampered metadata key grammar violating strict lower_snake_case dot separation",
        "generator": gen_s5_stego_tampered_key_grammar,
        "tests": [
            {
                "profile": "gguf-spec",
                "expected_rc": 2,
                "expected_status": "REJECT",
                "expected_error": "E_InvalidKeyFormat",
            },
        ],
    },
]


# ==============================================================================
# Fixture Generation and Manifest
# ==============================================================================

def generate_all_fixtures(selected_scenario: Optional[int] = None) -> List[Dict]:
    """Generates test cases and updates the manifest."""
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    manifest_entries = []

    print(f"[*] Generating fixtures in {FIXTURES_DIR}...")
    for spec in FIXTURES_SPEC:
        if selected_scenario and spec["scenario"] != selected_scenario:
            continue

        file_path = os.path.join(FIXTURES_DIR, spec["filename"])
        t0 = time.time()
        spec["generator"](file_path)
        gen_time = time.time() - t0

        size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        print(f"  [+] Scenario {spec['scenario']}: {spec['filename']} ({size:,} bytes, {gen_time:.3f}s)")

        manifest_entries.append({
            "id": spec["id"],
            "scenario": spec["scenario"],
            "scenario_name": spec["scenario_name"],
            "filename": spec["filename"],
            "description": spec["description"],
            "size_bytes": size,
            "sha256": file_hash,
            "tests": spec["tests"],
        })

    manifest = {
        "title": "SafeGGUF Advanced Security Testbed Manifest (Milestone M2)",
        "version": "1.0.0",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_fixtures": len(manifest_entries),
        "fixtures": manifest_entries,
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"[*] Manifest written to {MANIFEST_PATH} ({len(manifest_entries)} fixtures)")
    return manifest_entries


# ==============================================================================
# Test Execution and Verification Engine
# ==============================================================================

def run_test_case(
    bin_path: str,
    fixture_path: str,
    profile: str,
    fmt: str,
    timeout: int = 15
) -> Tuple[int, str, str, float]:
    """Executes safegguf inspect against fixture and returns (rc, stdout, stderr, elapsed)."""
    cmd = [bin_path, "inspect", fixture_path, "--profile", profile, "--format", fmt]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        elapsed = time.time() - t0
        stdout_str = proc.stdout.decode("utf-8", "replace")
        stderr_str = proc.stderr.decode("utf-8", "replace")
        return proc.returncode, stdout_str, stderr_str, elapsed
    except subprocess.TimeoutExpired:
        return -1, "", f"Execution timed out (> {timeout}s)", time.time() - t0


def verify_all_fixtures(
    bin_path: str,
    selected_scenario: Optional[int] = None,
    formats: List[str] = ["text", "json"],
    verbose: bool = False,
    quiet: bool = False
) -> Tuple[List[Dict], List[str]]:
    """Runs all fixture test permutations and asserts security invariants."""
    results = []
    failures = []

    if not quiet:
        print(f"\n[*] Executing security tests against: {bin_path}")
        print(f"[*] Formats: {formats}")

    for spec in FIXTURES_SPEC:
        if selected_scenario and spec["scenario"] != selected_scenario:
            continue

        file_path = os.path.join(FIXTURES_DIR, spec["filename"])
        if not os.path.exists(file_path):
            failures.append(f"Fixture missing: {file_path}. Run with --generate-only first.")
            continue

        for test_config in spec["tests"]:
            profile = test_config["profile"]
            expected_rc = test_config["expected_rc"]
            expected_status = test_config["expected_status"]
            expected_error = test_config["expected_error"]

            for fmt in formats:
                rc, stdout_str, stderr_str, elapsed = run_test_case(
                    bin_path, file_path, profile, fmt
                )

                test_id = f"S{spec['scenario']}_{spec['filename']}_{profile}_{fmt}"
                passed = True
                failure_reasons = []

                # Invariant 1: Return code must strictly match expected (2 for reject, 0 for pass)
                if rc != expected_rc:
                    passed = False
                    failure_reasons.append(
                        f"Expected exit code {expected_rc}, got {rc}"
                    )

                # Invariant 2: Under NO circumstances should binary exit 70 (software panic) or crash
                if rc == 70 or rc < 0 or rc > 127:
                    passed = False
                    failure_reasons.append(
                        f"CRITICAL HOST PANIC/CRASH exit code {rc}"
                    )

                actual_error_code = None

                # Invariant 3: Format-specific diagnostic validation
                if fmt == "json":
                    try:
                        parsed = json.loads(stdout_str)
                        status = parsed.get("status")
                        actual_error_code = parsed.get("error_code")

                        if status != expected_status:
                            passed = False
                            failure_reasons.append(
                                f"JSON status '{status}' != expected '{expected_status}'"
                            )

                        if expected_status == "REJECT":
                            if not actual_error_code:
                                passed = False
                                failure_reasons.append("JSON missing error_code")
                            elif expected_error and actual_error_code != expected_error:
                                passed = False
                                failure_reasons.append(
                                    f"JSON error_code '{actual_error_code}' != expected '{expected_error}'"
                                )

                            findings = parsed.get("findings", [])
                            if not isinstance(findings, list) or len(findings) == 0:
                                passed = False
                                failure_reasons.append("JSON findings list empty or missing")
                            elif expected_error:
                                has_code = any(f.get("code") == expected_error for f in findings)
                                if not has_code:
                                    passed = False
                                    failure_reasons.append(
                                        f"findings list did not contain code '{expected_error}'"
                                    )
                        else:  # PASS
                            checks = parsed.get("checks", {})
                            if checks.get("structural") != "PASS":
                                passed = False
                                failure_reasons.append("JSON checks.structural != PASS")

                    except json.JSONDecodeError as jde:
                        passed = False
                        failure_reasons.append(f"Invalid JSON emitted on stdout: {jde}")
                else:  # text format
                    if expected_status == "REJECT":
                        combined_output = stderr_str + " " + stdout_str
                        if "REJECT" not in combined_output:
                            passed = False
                            failure_reasons.append("Neither stderr nor stdout contained 'REJECT'")
                        if expected_error and expected_error not in combined_output:
                            passed = False
                            failure_reasons.append(
                                f"Expected error code '{expected_error}' not in stderr"
                            )
                        # Extract actual error code from "REJECT [E_...]"
                        if "[" in combined_output and "]" in combined_output:
                            try:
                                actual_error_code = combined_output.split("[")[1].split("]")[0]
                            except Exception:
                                actual_error_code = "UNKNOWN"
                    else:  # PASS
                        if "Result: PASS" not in stdout_str:
                            passed = False
                            failure_reasons.append("'Result: PASS' not found in text output")

                res_entry = {
                    "test_id": test_id,
                    "scenario": spec["scenario"],
                    "scenario_name": spec["scenario_name"],
                    "filename": spec["filename"],
                    "profile": profile,
                    "format": fmt,
                    "exit_code": rc,
                    "expected_exit_code": expected_rc,
                    "status": "PASS" if passed else "FAIL",
                    "expected_error": expected_error or "N/A",
                    "actual_error": actual_error_code or ("NONE" if expected_status == "PASS" else "UNKNOWN"),
                    "elapsed_sec": round(elapsed, 4),
                    "failure_reasons": failure_reasons,
                }
                results.append(res_entry)

                if not passed:
                    failures.append(
                        f"FAIL [{test_id}]: {'; '.join(failure_reasons)}\n"
                        f"  Stdout: {stdout_str[:120]!r}\n  Stderr: {stderr_str[:120]!r}"
                    )
                    status_str = "\033[91mFAIL\033[0m"
                else:
                    status_str = "\033[92mOK\033[0m"

                if verbose or not passed:
                    print(
                        f"  [{status_str}] S{spec['scenario']} {spec['filename']} "
                        f"({profile}, {fmt}) -> rc={rc}, err={res_entry['actual_error']} ({elapsed:.3f}s)"
                    )

    return results, failures


# ==============================================================================
# Reporting and Tables
# ==============================================================================

def print_summary_table(results: List[Dict]) -> None:
    """Prints a structured ASCII table summarizing test execution."""
    header = (
        f"{'Scenario':<10} | {'Fixture Filename':<40} | {'Profile':<9} | {'Fmt':<4} | "
        f"{'RC':<3} | {'Expected Error':<30} | {'Actual Error':<30} | {'Status'}"
    )
    divider = "-" * len(header)
    print("\n" + divider)
    print("SAFEEGUF ADVANCED SECURITY TESTBED EXECUTION RESULTS")
    print(divider)
    print(header)
    print(divider)

    for r in results:
        status_label = "[PASS]" if r["status"] == "PASS" else "[FAIL]"
        print(
            f"S{r['scenario']:<9} | {r['filename'][:39]:<40} | {r['profile']:<9} | {r['format']:<4} | "
            f"{r['exit_code']:<3} | {r['expected_error']:<30} | {r['actual_error']:<30} | {status_label}"
        )
    print(divider)


def print_differential_matrix(results: List[Dict]) -> None:
    """Prints the 4-axis profile decoupling differential matrix."""
    print("\n" + "=" * 80)
    print("SCENARIO 4: PROFILE DECOUPLING DIFFERENTIAL MATRIX (gguf-spec vs llama-cpp)")
    print("=" * 80)
    headers = f"{'Differential Feature Axis':<32} | {'gguf-spec Profile':<20} | {'llama-cpp Profile':<24}"
    print(headers)
    print("-" * 80)

    features = [
        ("Alignment: Non-Power-of-2 (24)", "scenario4_diff_align_non_power_two.gguf"),
        ("Tensor Name: Exactly 64 Bytes", "scenario4_diff_name_exact_64.gguf"),
        ("Metadata: Nested Array of Arrays", "scenario4_diff_nested_array.gguf"),
        ("Layout: Non-Contiguous Gaps", "scenario4_diff_non_contiguous_gap.gguf"),
    ]

    for label, fname in features:
        spec_res = [r for r in results if r["filename"] == fname and r["profile"] == "gguf-spec" and r["format"] == "json"]
        llama_res = [r for r in results if r["filename"] == fname and r["profile"] == "llama-cpp" and r["format"] == "json"]

        spec_str = f"Exit {spec_res[0]['exit_code']} (PASS)" if spec_res and spec_res[0]['exit_code'] == 0 else "FAIL"
        llama_str = (
            f"Exit {llama_res[0]['exit_code']} ({llama_res[0]['actual_error']})"
            if llama_res and llama_res[0]['exit_code'] == 2 else "FAIL"
        )

        print(f"{label:<32} | {spec_str:<20} | {llama_str:<24}")
    print("=" * 80)


# ==============================================================================
# Main Entry Point
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SafeGGUF Advanced Security Testbed (M2 / R2)"
    )
    parser.add_argument("--bin", type=str, default=None, help="Path to safegguf binary")
    parser.add_argument("--generate-only", action="store_true", help="Generate fixtures and manifest only")
    parser.add_argument("--verify-only", action="store_true", help="Run verification without regenerating")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4, 5], default=None, help="Run specific scenario")
    parser.add_argument("--format", choices=["text", "json", "all"], default="all", help="Output formats to test")
    parser.add_argument("--json-report", action="store_true", help="Output execution results as JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose test execution logs")

    args = parser.parse_args()

    bin_path = None
    if not args.generate_only:
        try:
            bin_path = find_safegguf_binary(args.bin)
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # Step 1: Generate fixtures
    if not args.verify_only:
        generate_all_fixtures(selected_scenario=args.scenario)

    if args.generate_only:
        print("[*] Fixture generation complete.")
        return 0

    # Step 2: Verification
    fmts = ["text", "json"] if args.format == "all" else [args.format]
    t0 = time.time()
    results, failures = verify_all_fixtures(
        bin_path,
        selected_scenario=args.scenario,
        formats=fmts,
        verbose=args.verbose,
        quiet=args.json_report
    )
    total_time = time.time() - t0

    if args.json_report:
        report = {
            "title": "SafeGGUF Advanced Security Testbed Execution Report",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "binary": bin_path,
            "total_tests": len(results),
            "passed": len(results) - len(failures),
            "failed": len(failures),
            "duration_sec": round(total_time, 3),
            "results": results,
            "failures": failures,
        }
        print(json.dumps(report, indent=2))
        return 1 if failures else 0

    # Display human-readable reports
    print_summary_table(results)
    if not args.scenario or args.scenario == 4:
        print_differential_matrix(results)

    passed_count = len(results) - len(failures)
    print(f"\nExecution Summary: {passed_count}/{len(results)} tests PASSED in {total_time:.2f}s.")

    if failures:
        print(f"\n\033[91mFAILED: {len(failures)} test assertions failed:\033[0m")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("\033[92m[SUCCESS] All SafeGGUF advanced security scenarios verified with full integrity.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
