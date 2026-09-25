"""
Truncation and Boundary Stress Harness for SafeGGUF.
Tests:
1. Every byte truncation (0 to len(valid.gguf)) must safely reject with exit code 2
   when truncated (< 384 bytes) or pass when complete (>= 384 bytes), never crash/panic.
2. 4096-byte chunk boundary UTF-8 carry-over stress:
   - Valid 4-byte UTF-8 split across 4096-byte boundary.
   - Invalid UTF-8 split across 4096-byte boundary (e.g. truncated continuation byte).
3. Random noise / high-entropy stream fuzzing (500 iterations of pure random bytes of sizes 0 to 65536).
"""

import json
import os
import random
import struct
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAFEGGUF_EXE = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf.exe")
if not os.path.exists(SAFEGGUF_EXE):
    SAFEGGUF_EXE = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf")

VALID_GGUF = os.path.join(REPO_ROOT, "tests", "fixtures", "valid.gguf")

def test_every_byte_truncation():
    print("--- 1. Testing Every-Byte Truncation on valid.gguf ---")
    with open(VALID_GGUF, "rb") as f:
        valid_bytes = f.read()

    total_len = len(valid_bytes)
    # Exact required length of valid.gguf is 384 bytes (192 base + 64 offset + 128 F32 bytes).
    # Remaining 64 bytes are trailing padding.
    exact_fit_len = 384
    print(f"valid.gguf size: {total_len} bytes, exact-fit minimum size: {exact_fit_len} bytes")

    with tempfile.TemporaryDirectory() as td:
        tmp_file = os.path.join(td, "truncated.gguf")
        for trunc_len in range(0, total_len + 1):
            with open(tmp_file, "wb") as f:
                f.write(valid_bytes[:trunc_len])

            for fmt in ["text", "json"]:
                cmd = [SAFEGGUF_EXE, "inspect", tmp_file, "--format", fmt]
                res = subprocess.run(cmd, capture_output=True, text=True)
                rc = res.returncode

                expected_rc = 2 if trunc_len < exact_fit_len else 0

                if rc != expected_rc:
                    print(f"FAIL at truncation length {trunc_len} ({fmt}): Expected exit code {expected_rc}, got {rc}")
                    print(f"Stdout: {res.stdout[:100]}")
                    print(f"Stderr: {res.stderr[:100]}")
                    return False

                # Assert no panic or crash
                assert rc in (0, 2), f"Unexpected exit code {rc} at length {trunc_len}"

                if fmt == "json":
                    try:
                        data = json.loads(res.stdout)
                        expected_status = "REJECT" if trunc_len < exact_fit_len else "PASS"
                        assert data.get("status") == expected_status
                    except Exception as e:
                        print(f"FAIL at truncation length {trunc_len} (json): Invalid JSON: {e}")
                        return False

    print(f"[ok] Passed all {total_len + 1} truncation slices (0..{total_len}):")
    print(f"     Lengths 0..{exact_fit_len - 1} strictly returned exit code 2 (REJECT).")
    print(f"     Lengths {exact_fit_len}..{total_len} strictly returned exit code 0 (PASS).")
    print(f"     Zero crashes, zero panics, valid JSON on all runs.")
    return True

def test_utf8_chunk_boundary():
    print("\n--- 2. Testing 4KB UTF-8 Chunk Boundary Carry-Over ---")
    def make_gguf_with_string(str_val: bytes):
        header = bytearray(b"GGUF")
        header.extend(struct.pack("<I", 3)) # v3
        header.extend(struct.pack("<Q", 0)) # 0 tensors
        header.extend(struct.pack("<Q", 1)) # 1 kv
        key = b"test.desc"
        header.extend(struct.pack("<Q", len(key)))
        header.extend(key)
        header.extend(struct.pack("<I", 8)) # string type
        header.extend(struct.pack("<Q", len(str_val)))
        header.extend(str_val)
        cur = len(header)
        rem = cur % 32
        if rem != 0:
            header.extend(b"\x00" * (32 - rem))
        return bytes(header)

    # Sub-case A: Valid 4-byte UTF-8 character crossing 4096-byte chunk boundary
    valid_str = b"A" * 4095 + b"\xF0\x9F\x98\x80" + b"B" * 100
    valid_payload = make_gguf_with_string(valid_str)

    # Sub-case B: Corrupted multi-byte UTF-8 character across boundary
    invalid_str = b"A" * 4095 + b"\xF0\x9F" + b" " + b"B" * 100
    invalid_payload = make_gguf_with_string(invalid_str)

    with tempfile.TemporaryDirectory() as td:
        p_a = os.path.join(td, "valid_boundary.gguf")
        with open(p_a, "wb") as f:
            f.write(valid_payload)
        res_a = subprocess.run([SAFEGGUF_EXE, "inspect", p_a], capture_output=True, text=True)
        if res_a.returncode != 0:
            print(f"FAIL valid UTF-8 boundary case: returncode {res_a.returncode}")
            print(f"Stderr: {res_a.stderr}")
            return False
        print("[ok] Valid UTF-8 crossing 4KB boundary passed validation (exit 0).")

        p_b = os.path.join(td, "invalid_boundary.gguf")
        with open(p_b, "wb") as f:
            f.write(invalid_payload)
        for fmt in ["text", "json"]:
            res_b = subprocess.run([SAFEGGUF_EXE, "inspect", p_b, "--format", fmt], capture_output=True, text=True)
            if res_b.returncode != 2:
                print(f"FAIL invalid UTF-8 boundary case ({fmt}): returncode {res_b.returncode}")
                print(f"Stderr: {res_b.stderr}")
                return False
            if fmt == "json":
                data = json.loads(res_b.stdout)
                assert data["error"] == "InvalidUtf8"
        print("[ok] Corrupted UTF-8 crossing 4KB boundary cleanly rejected with exit code 2 (E_InvalidUtf8).")

    return True

def test_random_noise_streams():
    print("\n--- 3. Testing Random High-Entropy Noise Streams (500 samples) ---")
    random.seed(1337)
    with tempfile.TemporaryDirectory() as td:
        tmp_file = os.path.join(td, "noise.gguf")
        for i in range(500):
            sz = random.choice([0, 1, 2, 3, 4, 8, 16, 24, 32, 64, 128, 256, 1024, 4096, 16384, 65536])
            if sz > 0:
                data = bytearray(random.getrandbits(8) for _ in range(sz))
                if random.random() < 0.2:
                    data[0:4] = b"GGUF"
                payload = bytes(data)
            else:
                payload = b""

            with open(tmp_file, "wb") as f:
                f.write(payload)

            res = subprocess.run([SAFEGGUF_EXE, "inspect", tmp_file, "--format", "json"], capture_output=True, text=True)
            rc = res.returncode
            if rc != 2:
                print(f"FAIL on noise sample {i} (size {sz}): returncode {rc}")
                print(f"Stdout: {res.stdout[:100]}")
                print(f"Stderr: {res.stderr[:100]}")
                return False

            try:
                d = json.loads(res.stdout)
                assert d.get("status") == "REJECT"
            except Exception as e:
                print(f"FAIL on noise sample {i}: Invalid JSON: {e}")
                return False

    print("[ok] Passed all 500 random noise streams with exit code 2 and valid JSON.")
    return True

def main():
    if not test_every_byte_truncation():
        sys.exit(1)
    if not test_utf8_chunk_boundary():
        sys.exit(1)
    if not test_random_noise_streams():
        sys.exit(1)
    print("\n[ok] ALL TRUNCATION AND BOUNDARY STRESS TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
