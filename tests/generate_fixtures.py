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
    print("All fixtures generated successfully.")
