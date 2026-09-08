import struct

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
    b += struct.pack("<I", 8)
    val = b"llama"
    b += struct.pack("<Q", len(val))
    b += val

    t0_name = b"token_embd.weight"
    b += struct.pack("<Q", len(t0_name))
    b += t0_name
    b += struct.pack("<I", 2)
    b += struct.pack("<Q", 32)
    b += struct.pack("<Q", 2)
    b += struct.pack("<I", 2)
    b += struct.pack("<Q", 0)

    t1_name = b"output.weight"
    b += struct.pack("<Q", len(t1_name))
    b += t1_name
    b += struct.pack("<I", 1)
    b += struct.pack("<Q", 32)
    b += struct.pack("<I", 0)
    b += struct.pack("<Q", 64)

    data_base = align_up(len(b), 32)
    pad = data_base - len(b)
    b += b"\x00" * pad
    b += b"\xAA" * 192

    with open("/home/uong_guyen/work/agent-infrastructure/safegguf/tests/fixtures/valid.gguf", "wb") as f:
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

    with open("/home/uong_guyen/work/agent-infrastructure/safegguf/tests/fixtures/overflow.gguf", "wb") as f:
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

    with open("/home/uong_guyen/work/agent-infrastructure/safegguf/tests/fixtures/out_of_bounds.gguf", "wb") as f:
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

    with open("/home/uong_guyen/work/agent-infrastructure/safegguf/tests/fixtures/overlap.gguf", "wb") as f:
        f.write(b)

build_valid()
build_overflow()
build_bounds()
build_overlap()
print("All fixtures generated successfully.")
