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

def build_alloc_dos():
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1000000)  # 1M tensors in 32 bytes
    b += struct.pack("<Q", 0)

    with open(os.path.join(DIR, "alloc_dos_tensor.gguf"), "wb") as f:
        f.write(b)

if __name__ == "__main__":
    build_valid()
    build_overflow()
    build_bounds()
    build_overlap()
    build_duplicate_tensor()
    build_duplicate_key()
    build_invalid_key()
    build_alloc_dos()
    print("All fixtures generated successfully.")
