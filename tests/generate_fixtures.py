import os
import struct

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
os.makedirs(DIR, exist_ok=True)

def align_up(val, align):
    rem = val % align
    return val if rem == 0 else val + (align - rem)

def build_valid():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 2)
    b += struct.pack("<Q", 1)

    key = b"general.architecture"
    b += struct.pack("<Q", len(key))
    b += key
    b += struct.pack("<I", 8)  # string
    val = b"llama"
    b += struct.pack("<Q", len(val))
    b += val

    t0_name = b"token_embd.weight"
    b += struct.pack("<Q", len(t0_name))
    b += t0_name
    b += struct.pack("<I", 2)  # 2 dims
    b += struct.pack("<Q", 32)
    b += struct.pack("<Q", 2)
    b += struct.pack("<I", 2)  # Q4_0
    b += struct.pack("<Q", 0)  # offset 0

    t1_name = b"output.weight"
    b += struct.pack("<Q", len(t1_name))
    b += t1_name
    b += struct.pack("<I", 1)  # 1 dim
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)  # F32
    b += struct.pack("<Q", 64) # offset 64

    data_base = align_up(len(b), 32)
    pad = data_base - len(b)
    b += b"\x00" * pad
    b += b"\xAA" * 256

    with open(os.path.join(DIR, "valid.gguf"), "wb") as f:
        f.write(b)

def build_type40_false_pass():
    # User-demonstrated concrete false-PASS regression:
    # 1 tensor, dims [64], type 40 (NVFP4, upstream block 64, type_size 36).
    # Descriptor ends at byte 57, tensor_data_base = 64.
    # Expected size: (64/64)*36 = 36 bytes. End offset = 100 bytes.
    # Truncated file size = 84 bytes (missing 16 bytes).
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    t_name = b"x"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 64)
    b += struct.pack("<I", 40) # NVFP4
    b += struct.pack("<Q", 0)  # offset 0

    data_base = align_up(len(b), 32) # 64
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 20 # Truncated payload: only 20 bytes instead of 36! Total len = 84 bytes.

    with open(os.path.join(DIR, "type40_truncated_false_pass.gguf"), "wb") as f:
        f.write(b)

def build_overflow():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    t_name = b"blk.0.attn_q.weight"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 2)
    b += struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
    b += struct.pack("<Q", 2)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 0)

    with open(os.path.join(DIR, "overflow.gguf"), "wb") as f:
        f.write(b)

def build_bounds():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    t_name = b"test"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 1024)

    with open(os.path.join(DIR, "out_of_bounds.gguf"), "wb") as f:
        f.write(b)

def build_overlap():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 2)
    b += struct.pack("<Q", 0)

    t0 = b"t0"
    b += struct.pack("<Q", len(t0))
    b += t0
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 0)

    t1 = b"t1"
    b += struct.pack("<Q", len(t1))
    b += t1
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 0)

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 256

    with open(os.path.join(DIR, "overlap.gguf"), "wb") as f:
        f.write(b)

def build_duplicate_tensor():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 2)
    b += struct.pack("<Q", 0)

    for offset in [0, 128]:
        t = b"same_name"
        b += struct.pack("<Q", len(t))
        b += t
        b += struct.pack("<I", 1)
        b += struct.pack("<Q", 32)
        b += struct.pack("<I", 0)
        b += struct.pack("<Q", offset)

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 256

    with open(os.path.join(DIR, "duplicate_tensor.gguf"), "wb") as f:
        f.write(b)

def build_duplicate_key():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 0)
    b += struct.pack("<Q", 2)

    for _ in range(2):
        k = b"general.architecture"
        b += struct.pack("<Q", len(k))
        b += k
        b += struct.pack("<I", 8)  # string
        v = b"llama"
        b += struct.pack("<Q", len(v))
        b += v

    with open(os.path.join(DIR, "duplicate_key.gguf"), "wb") as f:
        f.write(b)

def build_invalid_key():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 0)
    b += struct.pack("<Q", 1)

    k = b"InvalidKeyWithUppercase"
    b += struct.pack("<Q", len(k))
    b += k
    b += struct.pack("<I", 8)
    v = b"test"
    b += struct.pack("<Q", len(v))
    b += v

    with open(os.path.join(DIR, "invalid_key.gguf"), "wb") as f:
        f.write(b)

def build_hyphen_key():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 0)
    b += struct.pack("<Q", 1)

    k = b"general.model-architecture" # hyphen not allowed in lower_snake_case
    b += struct.pack("<Q", len(k))
    b += k
    b += struct.pack("<I", 8)
    v = b"test"
    b += struct.pack("<Q", len(v))
    b += v

    with open(os.path.join(DIR, "hyphen_key.gguf"), "wb") as f:
        f.write(b)

def build_alloc_dos():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1000000)  # 1M tensors in 32 bytes
    b += struct.pack("<Q", 0)

    with open(os.path.join(DIR, "alloc_dos_tensor.gguf"), "wb") as f:
        f.write(b)

def build_invalid_bool():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 0)
    b += struct.pack("<Q", 1)

    k = b"general.bool_val"
    b += struct.pack("<Q", len(k))
    b += k
    b += struct.pack("<I", 7) # bool
    b += b"\xFF" # Invalid boolean value (must be 0 or 1)

    with open(os.path.join(DIR, "invalid_bool.gguf"), "wb") as f:
        f.write(b)

def build_removed_slot():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    t_name = b"test"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 31) # Slot 31 is removed/deprecated
    b += struct.pack("<Q", 0)

    with open(os.path.join(DIR, "removed_type_slot31.gguf"), "wb") as f:
        f.write(b)

def build_gap():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 2)
    b += struct.pack("<Q", 0)

    # Tensor 0: 32 elements F32 = 128 bytes, offset 0
    t0 = b"t0"
    b += struct.pack("<Q", len(t0))
    b += t0
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 0)

    # Tensor 1: 32 elements F32 = 128 bytes, offset 256 (gap of 128 bytes from 128 to 256)
    t1 = b"t1"
    b += struct.pack("<Q", len(t1))
    b += t1
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 256)

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 512

    with open(os.path.join(DIR, "gap.gguf"), "wb") as f:
        f.write(b)

def build_nested_array():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 0)
    b += struct.pack("<Q", 1)

    k = b"general.nested_arr"
    b += struct.pack("<Q", len(k))
    b += k
    b += struct.pack("<I", 9) # ARRAY
    b += struct.pack("<I", 9) # inner type ARRAY
    b += struct.pack("<Q", 1) # 1 outer element
    b += struct.pack("<I", 4) # inner inner type INT32
    b += struct.pack("<Q", 1) # 1 inner element
    b += struct.pack("<i", 42)

    # Pad to default alignment (32) so header padding is valid
    pad_len = (32 - (len(b) % 32)) % 32
    b += b"\x00" * pad_len

    with open(os.path.join(DIR, "nested_array.gguf"), "wb") as f:
        f.write(b)

def build_name_64():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    # 64-byte name: exact limit in spec (<=64), but >= 64 in llama.cpp
    t_name = b"a" * 64
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 0)

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 128

    with open(os.path.join(DIR, "name_64.gguf"), "wb") as f:
        f.write(b)

def build_v2():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 2) # Version 2
    b += struct.pack("<Q", 0)
    b += struct.pack("<Q", 1)

    k = b"general.architecture"
    b += struct.pack("<Q", len(k))
    b += k
    b += struct.pack("<I", 8)
    v = b"llama"
    b += struct.pack("<Q", len(v))
    b += v

    with open(os.path.join(DIR, "version_2.gguf"), "wb") as f:
        f.write(b)

def build_llama_cpp_overflow():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 2)
    b += struct.pack("<Q", 0)

    # Tensor 0: 8 elements F32 = 32 bytes, offset 0
    t0 = b"t0"
    b += struct.pack("<Q", len(t0))
    b += t0
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 8)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 0)

    # Tensor 1: 2305843009213693951 elements F64 (8 bytes each -> nbytes = UINT64_MAX - 7), offset 32
    # 32 + (UINT64_MAX - 7) overflows u64!
    t1 = b"t1"
    b += struct.pack("<Q", len(t1))
    b += t1
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 2305843009213693951)
    b += struct.pack("<I", 28) # F64
    b += struct.pack("<Q", 32)

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 64

    with open(os.path.join(DIR, "llama_cpp_overflow.gguf"), "wb") as f:
        f.write(b)

def build_scalar():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    t_name = b"scalar"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 0) # n_dims == 0
    b += struct.pack("<I", 0) # F32 -> 4 bytes
    b += struct.pack("<Q", 0)

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 32

    with open(os.path.join(DIR, "scalar.gguf"), "wb") as f:
        f.write(b)

def build_truncated_final_padding():
    # Concrete false-PASS regression (HIGH-01):
    # 1 scalar tensor (F32, 4 bytes), alignment 32.
    # Required aligned end for llama.cpp contiguous load is data_base + 32.
    # File is truncated right after 4 bytes of payload (missing trailing 28 bytes of padding).
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    t_name = b"scalar"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 0) # n_dims == 0
    b += struct.pack("<I", 0) # F32 -> 4 bytes
    b += struct.pack("<Q", 0) # offset 0

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\xAA" * 4 # Missing 28 bytes of padding!

    with open(os.path.join(DIR, "truncated_final_padding.gguf"), "wb") as f:
        f.write(b)

def build_zero_dimension():
    # Deliberate divergence: SafeGGUF rejects explicit zero dimensions (E_ZeroDimensionNotAllowed).
    # Upstream ggml treats 0-element tensors as trivially representable (PASS).
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1) # 1 tensor
    b += struct.pack("<Q", 0) # 0 metadata

    t_name = b"zero_dim"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 1) # n_dims == 1
    b += struct.pack("<Q", 0) # dim[0] == 0 (zero dimension!)
    b += struct.pack("<I", 0) # F32
    b += struct.pack("<Q", 0) # offset 0

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 32

    with open(os.path.join(DIR, "zero_dimension.gguf"), "wb") as f:
        f.write(b)

def build_empty_tensor_name():
    # Deliberate divergence: SafeGGUF enforces non-empty tensor names 1 <= len <= 64 (E_InvalidTensorName).
    # Upstream ggml only checks name.length() >= GGML_MAX_NAME (64), so it accepts len == 0 (PASS).
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1) # 1 tensor
    b += struct.pack("<Q", 0) # 0 metadata

    # empty tensor name: length 0
    b += struct.pack("<Q", 0)
    b += struct.pack("<I", 1) # n_dims == 1
    b += struct.pack("<Q", 1) # dim[0] == 1
    b += struct.pack("<I", 0) # F32
    b += struct.pack("<Q", 0) # offset 0

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 32

    with open(os.path.join(DIR, "empty_tensor_name.gguf"), "wb") as f:
        f.write(b)

def build_big_endian_v3():
    # Valid GGUF v3 file encoded entirely in big-endian.
    # Passes gguf-spec --endian big, rejected by llama-cpp (CompatibilityViolation) on little-endian hosts.
    b = bytearray()
    b += b"GGUF"
    b += struct.pack(">I", 3) # Version 3
    b += struct.pack(">Q", 1) # 1 tensor
    b += struct.pack(">Q", 1) # 1 metadata

    # Metadata: general.architecture = "llama"
    key = b"general.architecture"
    b += struct.pack(">Q", len(key))
    b += key
    b += struct.pack(">I", 8) # GGUF_TYPE_STRING
    val = b"llama"
    b += struct.pack(">Q", len(val))
    b += val

    # Tensor: "weight", 1x8 F32 (32 bytes)
    t_name = b"weight"
    b += struct.pack(">Q", len(t_name))
    b += t_name
    b += struct.pack(">I", 1) # 1 dim
    b += struct.pack(">Q", 8) # 8 elements
    b += struct.pack(">I", 0) # F32
    b += struct.pack(">Q", 0) # offset 0

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 32 # 32 bytes data

    with open(os.path.join(DIR, "big_endian_v3.gguf"), "wb") as f:
        f.write(b)

def build_nonzero_header_padding():
    # GGUF v3 requires alignment padding between descriptors and data to be 0x00.
    # Non-zero bytes (e.g. 0xFF) in this padding must be rejected with InvalidAlignmentPadding.
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1)
    b += struct.pack("<Q", 0)

    t_name = b"weight"
    b += struct.pack("<Q", len(t_name))
    b += t_name
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 8)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 0)

    data_base = align_up(len(b), 32)
    pad_len = data_base - len(b)
    assert pad_len > 0, "Must have non-zero padding"
    b += b"\xFF" * pad_len # Non-zero padding!
    b += b"\x00" * 32

    with open(os.path.join(DIR, "nonzero_header_padding.gguf"), "wb") as f:
        f.write(b)

def build_truncated_header_padding_zero_tensors():
    # Exactly 24 bytes: magic(4), version(4), tensor_count(8)=0, metadata_count(8)=0
    # Missing 8 bytes of zero alignment padding up to default 32-byte alignment
    b = bytearray(b"GGUF")
    b += struct.pack("<IQQ", 3, 0, 0)
    assert len(b) == 24
    with open(os.path.join(DIR, "truncated_header_padding_zero_tensors.gguf"), "wb") as f:
        f.write(b)

def build_signed_dim_overflow():
    # 1 tensor with dimension 0x8000000000000000 (> INT64_MAX)
    b = bytearray(b"GGUF")
    b += struct.pack("<IQQ", 3, 1, 0)
    name = "dim_overflow"
    b += struct.pack("<Q", len(name))
    b += name.encode("utf-8")
    b += struct.pack("<I", 1) # 1 dim
    b += struct.pack("<Q", 0x8000000000000000) # > INT64_MAX
    b += struct.pack("<I", 0) # F32
    b += struct.pack("<Q", 0) # offset 0
    pad_len = (32 - (len(b) % 32)) % 32
    b += b"\x00" * pad_len
    with open(os.path.join(DIR, "signed_dim_overflow.gguf"), "wb") as f:
        f.write(b)

def build_element_product_overflow():
    # 1 tensor with 2 dimensions [0x4000000000000000, 2], product >= INT64_MAX
    b = bytearray(b"GGUF")
    b += struct.pack("<IQQ", 3, 1, 0)
    name = "prod_overflow"
    b += struct.pack("<Q", len(name))
    b += name.encode("utf-8")
    b += struct.pack("<I", 2) # 2 dims
    b += struct.pack("<Q", 0x4000000000000000) # dim 0
    b += struct.pack("<Q", 2) # dim 1
    b += struct.pack("<I", 0) # F32
    b += struct.pack("<Q", 0) # offset 0
    pad_len = (32 - (len(b) % 32)) % 32
    b += b"\x00" * pad_len
    with open(os.path.join(DIR, "element_product_overflow.gguf"), "wb") as f:
        f.write(b)


if __name__ == "__main__":
    build_valid()
    build_type40_false_pass()
    build_overflow()
    build_bounds()
    build_overlap()
    build_duplicate_tensor()
    build_duplicate_key()
    build_invalid_key()
    build_hyphen_key()
    build_alloc_dos()
    build_invalid_bool()
    build_removed_slot()
    build_gap()
    build_nested_array()
    build_name_64()
    build_v2()
    build_llama_cpp_overflow()
    build_scalar()
    build_truncated_final_padding()
    build_zero_dimension()
    build_empty_tensor_name()
    build_big_endian_v3()
    build_nonzero_header_padding()
    build_truncated_header_padding_zero_tensors()
    build_signed_dim_overflow()
    build_element_product_overflow()

    # Populate seed corpus directory for fuzzing
    corpus_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    import shutil
    for fname in os.listdir(DIR):
        if fname.endswith(".gguf"):
            shutil.copyfile(os.path.join(DIR, fname), os.path.join(corpus_dir, fname))

    print("All fixtures and seed corpus generated successfully.")
