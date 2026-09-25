#!/usr/bin/env python3
"""
Adversarial Endianness Challenge Suite for SafeGGUF.
Empirical verification of:
1. Auto-detect endianness (--endian auto) on Big-Endian and Little-Endian models under gguf-spec and llama-cpp profiles.
2. Explicit endianness flags (--endian little, --endian big).
3. Adversarial inputs: truncated magic/headers, mutated magic bytes (including 1-bit flips and reversed FUGG),
   invalid version fields (out of bounds, negative, dirty middle bytes), non-GGUF files.
4. Synthesized Big-Endian v2 model validation.
5. Big-Endian structural and arithmetic exploit mutations (u64 overflow, tampered padding, duplicate keys).
6. Malformed CLI flag handling and error contracts.
7. Strict fail-closed verification: zero crashes, zero panics, strict exit code contract.
"""

import os
import sys
import json
import struct
import subprocess
import tempfile
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")

# Locate safegguf binary
BINARY = os.path.join(ROOT, "zig-out", "bin", "safegguf")
if sys.platform == "win32":
    if not BINARY.endswith(".exe") and os.path.exists(BINARY + ".exe"):
        BINARY += ".exe"
    elif os.path.exists(BINARY + ".exe"):
        BINARY += ".exe"

if not os.path.exists(BINARY):
    print(f"Error: safegguf binary not found at {BINARY}", file=sys.stderr)
    sys.exit(1)

test_count = 0
fail_count = 0

def run_cmd(*args, env=None):
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run(
        [BINARY] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=merged_env
    )
    return proc.returncode, proc.stdout, proc.stderr

def assert_test(condition, desc):
    global test_count, fail_count
    test_count += 1
    if not condition:
        fail_count += 1
        print(f"  [FAIL] {desc}", file=sys.stderr)
        return False
    return True

def align_up(offset, alignment):
    return (offset + alignment - 1) & ~(alignment - 1)


# ==============================================================================
# 1. Target Fixture Matrix across Endianness and Profiles
# ==============================================================================
def test_endian_fixtures():
    print("[1] Testing target fixtures across endianness flags and profiles...")
    big_v3 = os.path.join(FIXTURES, "big_endian_v3.gguf")
    valid_le = os.path.join(FIXTURES, "valid.gguf")
    v2_le = os.path.join(FIXTURES, "version_2.gguf")

    # A. big_endian_v3.gguf
    # 1. auto + gguf-spec => PASS (0)
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 0 and "Result: PASS" in out, "big_endian_v3 --endian auto --profile gguf-spec exits 0")

    # 2. auto + gguf-spec JSON => PASS (0)
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "auto", "--profile", "gguf-spec", "--format", "json")
    if assert_test(rc == 0, "big_endian_v3 --endian auto --profile gguf-spec (json) exits 0"):
        d = json.loads(out)
        assert_test(d["status"] == "PASS" and d["profile"] == "gguf-spec" and d["version"] == 3, "JSON contains valid PASS payload for big_endian_v3")

    # 3. auto + llama-cpp => REJECT (2) [CompatibilityViolation]
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "auto", "--profile", "llama-cpp")
    assert_test(rc == 2 and ("E_CompatibilityViolation" in out or "E_CompatibilityViolation" in err), "big_endian_v3 --endian auto --profile llama-cpp exits 2 (CompatibilityViolation)")

    # 4. auto + llama-cpp JSON => REJECT (2)
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "auto", "--profile", "llama-cpp", "--format", "json")
    if assert_test(rc == 2, "big_endian_v3 --endian auto --profile llama-cpp (json) exits 2"):
        d = json.loads(out)
        assert_test(d["status"] == "REJECT" and d["category"] == "compatibility", "JSON contains REJECT with compatibility category")

    # 5. big explicit + gguf-spec => PASS (0)
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "big", "--profile", "gguf-spec")
    assert_test(rc == 0 and "Result: PASS" in out, "big_endian_v3 --endian big --profile gguf-spec exits 0")

    # 6. big explicit + llama-cpp => REJECT (2)
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "big", "--profile", "llama-cpp")
    assert_test(rc == 2 and ("E_CompatibilityViolation" in out or "E_CompatibilityViolation" in err), "big_endian_v3 --endian big --profile llama-cpp exits 2")

    # 7. little explicit + gguf-spec on big_endian_v3 => REJECT (2) [UnsupportedVersion]
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "little", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_UnsupportedVersion" in err, "big_endian_v3 --endian little --profile gguf-spec exits 2 (UnsupportedVersion)")

    # 8. little explicit + llama-cpp on big_endian_v3 => REJECT (2) [UnsupportedVersion]
    rc, out, err = run_cmd("inspect", big_v3, "--endian", "little", "--profile", "llama-cpp")
    assert_test(rc == 2 and "E_UnsupportedVersion" in err, "big_endian_v3 --endian little --profile llama-cpp exits 2 (UnsupportedVersion)")

    # B. valid.gguf (Little Endian v3)
    # 9. auto + gguf-spec => PASS (0)
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 0 and "Result: PASS" in out, "valid.gguf --endian auto --profile gguf-spec exits 0")

    # 10. auto + llama-cpp => PASS (0)
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "auto", "--profile", "llama-cpp")
    assert_test(rc == 0 and "Result: PASS" in out, "valid.gguf --endian auto --profile llama-cpp exits 0")

    # 11. little explicit + gguf-spec => PASS (0)
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "little", "--profile", "gguf-spec")
    assert_test(rc == 0 and "Result: PASS" in out, "valid.gguf --endian little --profile gguf-spec exits 0")

    # 12. little explicit + llama-cpp => PASS (0)
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "little", "--profile", "llama-cpp")
    assert_test(rc == 0 and "Result: PASS" in out, "valid.gguf --endian little --profile llama-cpp exits 0")

    # 13. big explicit + gguf-spec on valid.gguf => REJECT (2) [UnsupportedVersion]
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "big", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_UnsupportedVersion" in err, "valid.gguf --endian big --profile gguf-spec exits 2 (UnsupportedVersion)")

    # 14. big explicit + llama-cpp on valid.gguf => REJECT (2) [CompatibilityViolation]
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "big", "--profile", "llama-cpp")
    assert_test(rc == 2 and ("E_CompatibilityViolation" in out or "E_CompatibilityViolation" in err), "valid.gguf --endian big --profile llama-cpp exits 2 (CompatibilityViolation)")

    # C. version_2.gguf (Little Endian v2)
    # Under gguf-spec, only v3 is permitted, so v2 is REJECTED (2) [E_UnsupportedVersion]
    rc, out, err = run_cmd("inspect", v2_le, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_UnsupportedVersion" in err, "version_2.gguf --endian auto --profile gguf-spec exits 2 (E_UnsupportedVersion)")

    # Under llama-cpp, v2 is supported, so with auto-detected little-endian it PASSES (0)
    rc, out, err = run_cmd("inspect", v2_le, "--endian", "auto", "--profile", "llama-cpp")
    assert_test(rc == 0 and "Result: PASS" in out, "version_2.gguf --endian auto --profile llama-cpp exits 0")

    # 17. big explicit + gguf-spec on version_2.gguf => REJECT (2)
    rc, out, err = run_cmd("inspect", v2_le, "--endian", "big", "--profile", "gguf-spec")
    assert_test(rc == 2, "version_2.gguf --endian big --profile gguf-spec exits 2")

    # 18. big explicit + llama-cpp on version_2.gguf => REJECT (2)
    rc, out, err = run_cmd("inspect", v2_le, "--endian", "big", "--profile", "llama-cpp")
    assert_test(rc == 2, "version_2.gguf --endian big --profile llama-cpp exits 2")


# ==============================================================================
# 2. Synthesized Big-Endian v2 Model
# ==============================================================================
def test_big_endian_v2(tmp_dir):
    print("[2] Synthesizing and testing Big-Endian GGUF v2 model...")
    # Build Big-Endian v2 model
    # GGUF v2 has 64-bit tensor_count and 64-bit metadata_kv_count just like v3, but version is 2
    b = bytearray()
    b += b"GGUF"
    b += struct.pack(">I", 2) # Version 2 in Big-Endian
    b += struct.pack(">Q", 1) # 1 tensor
    b += struct.pack(">Q", 1) # 1 metadata entry

    # Metadata
    k = b"general.architecture"
    b += struct.pack(">Q", len(k))
    b += k
    b += struct.pack(">I", 8) # GGUF_TYPE_STRING
    v = b"llama"
    b += struct.pack(">Q", len(v))
    b += v

    # Tensor
    tname = b"tensor_v2"
    b += struct.pack(">Q", len(tname))
    b += tname
    b += struct.pack(">I", 1) # 1 dim
    b += struct.pack(">Q", 16) # 16 elements
    b += struct.pack(">I", 0) # F32
    b += struct.pack(">Q", 0) # offset 0

    data_base = align_up(len(b), 32)
    b += b"\x00" * (data_base - len(b))
    b += b"\x00" * 64 # tensor payload

    be_v2_path = os.path.join(tmp_dir, "big_endian_v2.gguf")
    with open(be_v2_path, "wb") as f:
        f.write(b)

    # 1. auto + gguf-spec => REJECT (2) [UnsupportedVersion, because gguf-spec only accepts v3]
    rc, out, err = run_cmd("inspect", be_v2_path, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_UnsupportedVersion" in err, "big_endian_v2 --endian auto --profile gguf-spec exits 2 (UnsupportedVersion)")

    # 2. auto + llama-cpp => REJECT (2) [CompatibilityViolation, because BE rejected on LE host]
    rc, out, err = run_cmd("inspect", be_v2_path, "--endian", "auto", "--profile", "llama-cpp")
    assert_test(rc == 2 and ("E_CompatibilityViolation" in out or "E_CompatibilityViolation" in err), "big_endian_v2 --endian auto --profile llama-cpp exits 2 (CompatibilityViolation)")

    # 3. big explicit + gguf-spec => REJECT (2) [UnsupportedVersion]
    rc, out, err = run_cmd("inspect", be_v2_path, "--endian", "big", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_UnsupportedVersion" in err, "big_endian_v2 --endian big --profile gguf-spec exits 2 (UnsupportedVersion)")

    # 4. big explicit + llama-cpp => REJECT (2) [CompatibilityViolation]
    rc, out, err = run_cmd("inspect", be_v2_path, "--endian", "big", "--profile", "llama-cpp")
    assert_test(rc == 2 and ("E_CompatibilityViolation" in out or "E_CompatibilityViolation" in err), "big_endian_v2 --endian big --profile llama-cpp exits 2 (CompatibilityViolation)")

    # 5. little explicit + gguf-spec => REJECT (2)
    rc, out, err = run_cmd("inspect", be_v2_path, "--endian", "little", "--profile", "gguf-spec")
    assert_test(rc == 2, "big_endian_v2 --endian little --profile gguf-spec exits 2")


# ==============================================================================
# 3. Truncated Magic & Boundary Slices under --endian auto
# ==============================================================================
def test_truncation_under_auto_endian(tmp_dir):
    print("[3] Testing truncation slices (0..64 bytes) with --endian auto...")
    valid_le = os.path.join(FIXTURES, "valid.gguf")
    big_v3 = os.path.join(FIXTURES, "big_endian_v3.gguf")

    for fixture_name, fixture_path in [("valid_le", valid_le), ("big_v3", big_v3)]:
        with open(fixture_path, "rb") as f:
            full_data = f.read()

        # Test every single byte length from 0 to 40
        for length in range(0, min(45, len(full_data))):
            trunc_path = os.path.join(tmp_dir, f"trunc_{fixture_name}_{length}.gguf")
            with open(trunc_path, "wb") as f:
                f.write(full_data[:length])

            # Text format
            rc, out, err = run_cmd("inspect", trunc_path, "--endian", "auto", "--profile", "gguf-spec")
            assert_test(rc == 2, f"{fixture_name} trunc len={length} --endian auto exits 2 (got {rc})")
            assert_test("REJECT" in err or "REJECT" in out or "Error:" in err, f"{fixture_name} trunc len={length} diagnostic emitted")

            # JSON format
            rc, out, err = run_cmd("inspect", trunc_path, "--endian", "auto", "--profile", "gguf-spec", "--format", "json")
            assert_test(rc == 2, f"{fixture_name} trunc len={length} json --endian auto exits 2")
            try:
                d = json.loads(out)
                assert_test(d["status"] == "REJECT", f"{fixture_name} trunc len={length} json status is REJECT")
            except Exception as e:
                assert_test(False, f"{fixture_name} trunc len={length} JSON parse failed: {e}; out: {out}")


# ==============================================================================
# 4. Mutated Magic Bytes & Reversed Magic ("FUGG")
# ==============================================================================
def test_mutated_magic(tmp_dir):
    print("[4] Testing mutated and reversed magic bytes with --endian auto...")
    valid_le = os.path.join(FIXTURES, "valid.gguf")
    with open(valid_le, "rb") as f:
        base_data = f.read()

    magic_cases = [
        (b"FUGG", "Reversed magic FUGG (little endian thinking swapped)"),
        (b"gguf", "Lowercase gguf"),
        (b"GGU\x00", "Null-terminated GGU"),
        (b"\x00GGU", "Shifted null GGU"),
        (b"G\x00UF", "Internal null G\\0UF"),
        (b"\xff\xff\xff\xff", "All 0xFF magic"),
        (b"\x00\x00\x00\x00", "All 0x00 magic"),
        (b"RIFF", "RIFF header"),
        (b"%PDF", "PDF header"),
        (b"\x7fELF", "ELF magic"),
        (b"PK\x03\x04", "ZIP magic"),
        (b"\x89PNG", "PNG magic"),
    ]

    for magic, desc in magic_cases:
        mutated = magic + base_data[4:]
        p = os.path.join(tmp_dir, "magic_test.gguf")
        with open(p, "wb") as f:
            f.write(mutated)

        rc, out, err = run_cmd("inspect", p, "--endian", "auto", "--profile", "gguf-spec")
        assert_test(rc == 2 and "E_InvalidMagic" in err, f"Magic {desc} fails with E_InvalidMagic (exit 2)")

        # Verify JSON
        rc, out, err = run_cmd("inspect", p, "--endian", "auto", "--profile", "gguf-spec", "--format", "json")
        assert_test(rc == 2, f"Magic {desc} JSON exits 2")
        d = json.loads(out)
        assert_test(d["status"] == "REJECT" and d["error_code"] == "E_InvalidMagic", f"Magic {desc} JSON has E_InvalidMagic")

    # Bit-flip fuzzing of magic: test every 1-bit flip in the 4-byte magic
    print("  Testing 32 single-bit flips of GGUF magic...")
    for byte_idx in range(4):
        for bit in range(8):
            magic_arr = bytearray(b"GGUF")
            magic_arr[byte_idx] ^= (1 << bit)
            mutated = bytes(magic_arr) + base_data[4:]
            p = os.path.join(tmp_dir, "bitflip_magic.gguf")
            with open(p, "wb") as f:
                f.write(mutated)

            rc, out, err = run_cmd("inspect", p, "--endian", "auto", "--profile", "gguf-spec")
            assert_test(rc == 2, f"Magic bitflip [{byte_idx}:{bit}] exits 2")


# ==============================================================================
# 5. Invalid / Boundary Version Fields
# ==============================================================================
def test_invalid_versions(tmp_dir):
    print("[5] Testing invalid/boundary version fields with --endian auto...")
    valid_le = os.path.join(FIXTURES, "valid.gguf")
    with open(valid_le, "rb") as f:
        base_data = f.read()

    version_cases = [
        (struct.pack("<I", 0), "LE Version 0"),
        (struct.pack(">I", 0), "BE Version 0"),
        (struct.pack("<I", 1), "LE Version 1"),
        (struct.pack(">I", 1), "BE Version 1"),
        (struct.pack("<I", 4), "LE Version 4"),
        (struct.pack(">I", 4), "BE Version 4"),
        (struct.pack("<I", 5), "LE Version 5"),
        (struct.pack("<I", 0xFFFFFFFF), "Version 0xFFFFFFFF (-1)"),
        (struct.pack("<I", 0x80000000), "Version 0x80000000 (signed negative)"),
        (struct.pack(">I", 0x80000000), "BE Version 0x80000000"),
        (b"\x02\x00\x00\x02", "Ambiguous: 0x02 on both ends"),
        (b"\x03\x00\x00\x03", "Ambiguous: 0x03 on both ends"),
        (b"\x02\x00\x00\x03", "Conflicting: 2 LE, 3 BE"),
        (b"\x03\x00\x00\x02", "Conflicting: 3 LE, 2 BE"),
        (b"\x00\x02\x00\x00", "Dirty middle byte (idx 1 = 2)"),
        (b"\x00\x00\x02\x00", "Dirty middle byte (idx 2 = 2)"),
        (b"\x00\x03\x00\x00", "Dirty middle byte (idx 1 = 3)"),
        (b"\x00\x00\x03\x00", "Dirty middle byte (idx 2 = 3)"),
        (b"\x03\x01\x00\x00", "LE v3 with dirty byte 1"),
        (b"\x00\x01\x00\x03", "BE v3 with dirty byte 1"),
        (b"\x00\x00\x00\x00", "All zero version"),
        (b"\xff\xff\xff\xff", "All 0xff version"),
    ]

    for ver_bytes, desc in version_cases:
        mutated = base_data[:4] + ver_bytes + base_data[8:]
        p = os.path.join(tmp_dir, "ver_test.gguf")
        with open(p, "wb") as f:
            f.write(mutated)

        # Test both profiles with --endian auto
        for prof in ["gguf-spec", "llama-cpp"]:
            rc, out, err = run_cmd("inspect", p, "--endian", "auto", "--profile", prof)
            assert_test(rc == 2, f"Version case '{desc}' ({prof}) exits 2 (got {rc})")
            assert_test("E_UnsupportedVersion" in err or "REJECT" in err or "E_CompatibilityViolation" in out, f"Version case '{desc}' emits rejection")


# ==============================================================================
# 6. Non-GGUF Files and Random Noise
# ==============================================================================
def test_non_gguf_files(tmp_dir):
    print("[6] Testing non-GGUF files and noise streams with --endian auto...")

    # 1. 0-byte file
    empty_p = os.path.join(tmp_dir, "empty.gguf")
    with open(empty_p, "wb") as f:
        pass
    rc, out, err = run_cmd("inspect", empty_p, "--endian", "auto")
    assert_test(rc == 2, "Empty (0-byte) file with --endian auto exits 2")

    # 2. Text file
    txt_p = os.path.join(tmp_dir, "plain.txt")
    with open(txt_p, "wb") as f:
        f.write(b"Hello world, this is not a GGUF model!\n" * 10)
    rc, out, err = run_cmd("inspect", txt_p, "--endian", "auto")
    assert_test(rc == 2 and "E_InvalidMagic" in err, "Text file with --endian auto exits 2 (E_InvalidMagic)")

    # 3. All zeros (1 KB, 64 KB)
    for sz in [1024, 65536]:
        z_p = os.path.join(tmp_dir, f"zeros_{sz}.gguf")
        with open(z_p, "wb") as f:
            f.write(b"\x00" * sz)
        rc, out, err = run_cmd("inspect", z_p, "--endian", "auto")
        assert_test(rc == 2, f"All-zeros ({sz} bytes) with --endian auto exits 2")

    # 4. All 0xFF (1 KB, 64 KB)
    for sz in [1024, 65536]:
        ff_p = os.path.join(tmp_dir, f"ff_{sz}.gguf")
        with open(ff_p, "wb") as f:
            f.write(b"\xff" * sz)
        rc, out, err = run_cmd("inspect", ff_p, "--endian", "auto")
        assert_test(rc == 2, f"All-0xFF ({sz} bytes) with --endian auto exits 2")

    # 5. Deterministic pseudo-random streams
    import random
    rng = random.Random(0xDEADBEEF)
    for sz in [16, 64, 512, 4096, 65536]:
        rnd_p = os.path.join(tmp_dir, f"random_{sz}.gguf")
        noise = rng.randbytes(sz)
        with open(rnd_p, "wb") as f:
            f.write(noise)
        rc, out, err = run_cmd("inspect", rnd_p, "--endian", "auto")
        assert_test(rc == 2, f"Pseudo-random noise ({sz} bytes) with --endian auto exits 2")


# ==============================================================================
# 7. Big-Endian Semantic Exploit & Tampering Attacks
# ==============================================================================
def test_big_endian_adversarial_tampering(tmp_dir):
    print("[7] Testing Big-Endian semantic exploits & structural tampering...")

    # Helper to generate a baseline Big-Endian GGUF v3 model bytes
    def make_be_model(tensor_count=1, kv_count=1, tensor_dim=8, tensor_offset=0, pad_byte=0):
        b = bytearray()
        b += b"GGUF"
        b += struct.pack(">I", 3)
        b += struct.pack(">Q", tensor_count)
        b += struct.pack(">Q", kv_count)

        # Metadata: general.architecture = "llama"
        if kv_count > 0:
            k = b"general.architecture"
            b += struct.pack(">Q", len(k))
            b += k
            b += struct.pack(">I", 8) # GGUF_TYPE_STRING
            val = b"llama"
            b += struct.pack(">Q", len(val))
            b += val

        # Tensor: "weight", 1x(tensor_dim) F32
        if tensor_count > 0:
            tname = b"weight"
            b += struct.pack(">Q", len(tname))
            b += tname
            b += struct.pack(">I", 1) # 1 dim
            b += struct.pack(">Q", tensor_dim)
            b += struct.pack(">I", 0) # F32
            b += struct.pack(">Q", tensor_offset)

        data_base = align_up(len(b), 32)
        pad_len = data_base - len(b)
        b += bytes([pad_byte]) * pad_len
        b += b"\x00" * 32 # tensor data
        return b

    # Attack 1: BE Tensor count u64 max (0xFFFFFFFFFFFFFFFF)
    b1 = bytearray()
    b1 += b"GGUF"
    b1 += struct.pack(">I", 3)
    b1 += struct.pack(">Q", 0xFFFFFFFFFFFFFFFF)
    b1 += struct.pack(">Q", 0)
    p1 = os.path.join(tmp_dir, "be_tensor_count_overflow.gguf")
    with open(p1, "wb") as f:
        f.write(b1)
    rc, out, err = run_cmd("inspect", p1, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2, "BE tensor_count=u64_max exits 2")

    # Attack 2: BE Metadata KV count u64 max
    b2 = bytearray()
    b2 += b"GGUF"
    b2 += struct.pack(">I", 3)
    b2 += struct.pack(">Q", 0)
    b2 += struct.pack(">Q", 0xFFFFFFFFFFFFFFFF)
    p2 = os.path.join(tmp_dir, "be_kv_count_overflow.gguf")
    with open(p2, "wb") as f:
        f.write(b2)
    rc, out, err = run_cmd("inspect", p2, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2, "BE kv_count=u64_max exits 2")

    # Attack 3: BE Dimension product overflow (2 dims: 2^33 * 2^33 overflows u64)
    b3 = bytearray()
    b3 += b"GGUF"
    b3 += struct.pack(">I", 3)
    b3 += struct.pack(">Q", 1)
    b3 += struct.pack(">Q", 0)
    tname = b"overflow_tensor"
    b3 += struct.pack(">Q", len(tname))
    b3 += tname
    b3 += struct.pack(">I", 2) # 2 dims
    b3 += struct.pack(">Q", 0x200000000) # 2^33
    b3 += struct.pack(">Q", 0x200000000) # 2^33
    b3 += struct.pack(">I", 0) # F32
    b3 += struct.pack(">Q", 0)
    p3 = os.path.join(tmp_dir, "be_dim_overflow.gguf")
    with open(p3, "wb") as f:
        f.write(b3)
    rc, out, err = run_cmd("inspect", p3, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2 and ("E_DimProductOverflow" in err or "E_TotalByteSizeOverflow" in err or "REJECT" in err), "BE dim product overflow exits 2")

    # Attack 4: BE Non-zero alignment padding tampering
    b4 = make_be_model(pad_byte=0xAA)
    p4 = os.path.join(tmp_dir, "be_nonzero_padding.gguf")
    with open(p4, "wb") as f:
        f.write(b4)
    rc, out, err = run_cmd("inspect", p4, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_InvalidAlignmentPadding" in err, "BE non-zero alignment padding exits 2 (E_InvalidAlignmentPadding)")

    # Attack 5: BE Tensor data offset far beyond file size
    b5 = make_be_model(tensor_offset=0x10000000)
    p5 = os.path.join(tmp_dir, "be_tensor_offset_oob.gguf")
    with open(p5, "wb") as f:
        f.write(b5)
    rc, out, err = run_cmd("inspect", p5, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_TensorOutOfBounds" in err, "BE tensor offset OOB exits 2 (E_TensorOutOfBounds)")

    # Attack 6: BE Zero-dimension tensor
    b6 = make_be_model(tensor_dim=0)
    p6 = os.path.join(tmp_dir, "be_zero_dim.gguf")
    with open(p6, "wb") as f:
        f.write(b6)
    rc, out, err = run_cmd("inspect", p6, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_ZeroDimension" in err, "BE tensor_dim=0 exits 2 (E_ZeroDimension)")

    # Attack 7: BE Duplicate metadata keys
    b7 = bytearray()
    b7 += b"GGUF"
    b7 += struct.pack(">I", 3)
    b7 += struct.pack(">Q", 0)
    b7 += struct.pack(">Q", 2)
    for _ in range(2):
        k = b"general.architecture"
        b7 += struct.pack(">Q", len(k))
        b7 += k
        b7 += struct.pack(">I", 8)
        val = b"llama"
        b7 += struct.pack(">Q", len(val))
        b7 += val
    p7 = os.path.join(tmp_dir, "be_dup_key.gguf")
    with open(p7, "wb") as f:
        f.write(b7)
    rc, out, err = run_cmd("inspect", p7, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2 and "E_DuplicateMetadataKey" in err, "BE duplicate key exits 2 (E_DuplicateMetadataKey)")

    # Attack 8: BE Huge string length claim (0xFFFFFFFFFFFFFFFF)
    b8 = bytearray()
    b8 += b"GGUF"
    b8 += struct.pack(">I", 3)
    b8 += struct.pack(">Q", 0)
    b8 += struct.pack(">Q", 1)
    k8 = b"test_key"
    b8 += struct.pack(">Q", len(k8))
    b8 += k8
    b8 += struct.pack(">I", 8) # string
    b8 += struct.pack(">Q", 0xFFFFFFFFFFFFFFFF) # string len max
    p8 = os.path.join(tmp_dir, "be_huge_string.gguf")
    with open(p8, "wb") as f:
        f.write(b8)
    rc, out, err = run_cmd("inspect", p8, "--endian", "auto", "--profile", "gguf-spec")
    assert_test(rc == 2, "BE string len=u64_max exits 2")


# ==============================================================================
# 8. Malformed CLI Flag & I/O Error Contracts
# ==============================================================================
def test_cli_flags_and_io():
    print("[8] Testing malformed CLI flag values and IO contracts...")
    valid_le = os.path.join(FIXTURES, "valid.gguf")

    # Missing arg for --endian
    rc, out, err = run_cmd("inspect", valid_le, "--endian")
    assert_test(rc == 64 and "Error: --endian requires 'little', 'big', or 'auto'" in err, "--endian without argument exits 64 with exact message")

    # Invalid string values
    invalid_endians = ["", "middle", "BIG", "AUTO", "LITTLE", "big-endian", "0", "1", "2", "none", "unknown", "a" * 500]
    for val in invalid_endians:
        rc, out, err = run_cmd("inspect", valid_le, "--endian", val)
        assert_test(rc == 64 and f"Error: invalid endian value '{val}'" in err, f"--endian '{val[:10]}' exits 64")

    # Flag order / overriding:
    # 1. --endian big followed by --endian auto: auto_endian becomes true, auto-detect succeeds (0)
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "big", "--endian", "auto")
    assert_test(rc == 0, "--endian big followed by --endian auto resolves to auto (PASS)")

    # 2. --endian auto followed by --endian big on LE file:
    # Note: auto_endian remains set, so it auto-detects and passes (exit 0) without crashing.
    rc, out, err = run_cmd("inspect", valid_le, "--endian", "auto", "--endian", "big")
    assert_test(rc in [0, 2], "--endian auto followed by --endian big exits safely without crash")

    # Non-existent file with --endian auto => 74
    rc, out, err = run_cmd("inspect", "path/to/non_existent_file.gguf", "--endian", "auto")
    assert_test(rc == 74, "Non-existent file with --endian auto exits 74")

    # Non-existent file with --endian auto in JSON => 74
    rc, out, err = run_cmd("inspect", "path/to/non_existent_file.gguf", "--endian", "auto", "--format", "json")
    assert_test(rc == 74, "Non-existent file (JSON) with --endian auto exits 74")


def main():
    print(f"=== SafeGGUF Adversarial Endianness Challenge Suite ===")
    print(f"Target Binary: {BINARY}")
    tmp_dir = tempfile.mkdtemp(prefix="safegguf_endian_adv_")
    try:
        test_endian_fixtures()
        test_big_endian_v2(tmp_dir)
        test_truncation_under_auto_endian(tmp_dir)
        test_mutated_magic(tmp_dir)
        test_invalid_versions(tmp_dir)
        test_non_gguf_files(tmp_dir)
        test_big_endian_adversarial_tampering(tmp_dir)
        test_cli_flags_and_io()

        print("\n" + "=" * 60)
        print(f"Adversarial Challenge Results: {test_count - fail_count}/{test_count} tests PASSED.")
        if fail_count > 0:
            print(f"CRITICAL FAILURE: {fail_count} tests failed!", file=sys.stderr)
            sys.exit(1)
        else:
            print("ALL ADVERSARIAL ENDIANNESS CHALLENGES PASSED (100% Fail-Closed, 0 Crashes).")
            sys.exit(0)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
