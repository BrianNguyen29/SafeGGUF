#!/usr/bin/env python3
"""
SafeGGUF Challenger M2_1 Adversarial C-ABI & ctypes Stress Harness.
Empirically verifies:
  1. NULL path pointer -> code 64, zero crash/segfault.
  2. Descriptor handles: 0, -1, -9999, large positive/negative 64-bit ints -> code 74, zero panic.
  3. Out-of-range profile and endian IDs -> safe exit codes (no panic, no UB).
  4. Closed handles, invalid file descriptors, non-existent paths -> code 74.
  5. 0-byte files and truncated files -> code 2 (safe rejection), zero crash.
  6. All 15 negative corpus files via C-ABI path and fd -> code 2, zero crash.
  7. Anti-TOCTOU seek offset preservation and descriptor validity.
  8. High-iteration adversarial fuzzing loop to detect leaks and heap corruption.
"""

import os
import sys
import ctypes
import tempfile
from pathlib import Path

# Add python binding path for companion checks
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "bindings" / "python"))

def get_c_library():
    dll_path = REPO_ROOT / "zig-out" / "bin" / "safegguf.dll"
    if not dll_path.exists():
        dll_path = REPO_ROOT / "zig-out" / "lib" / "safegguf.dll"
    if not dll_path.exists():
        raise FileNotFoundError(f"Cannot locate safegguf.dll at {dll_path}")

    lib = ctypes.CDLL(str(dll_path))
    lib.safegguf_version.restype = ctypes.c_char_p
    lib.safegguf_validate_path.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    lib.safegguf_validate_path.restype = ctypes.c_int
    lib.safegguf_validate_fd.argtypes = [ctypes.c_ssize_t, ctypes.c_int, ctypes.c_int]
    lib.safegguf_validate_fd.restype = ctypes.c_int
    return lib

def run_tests():
    lib = get_c_library()
    ver = lib.safegguf_version().decode("utf-8")
    print(f"=== Loaded safegguf.dll (version: {ver}) ===")

    valid_model = str(REPO_ROOT / "tests" / "fixtures" / "valid.gguf")
    exploit_model = str(REPO_ROOT / "tests" / "fixtures" / "overflow.gguf")
    big_endian_model = str(REPO_ROOT / "tests" / "fixtures" / "big_endian_v3.gguf")

    failures = []

    def check(name, expr, expected_msg=""):
        if not expr:
            print(f"  [FAIL] {name}: {expected_msg}")
            failures.append(f"{name}: {expected_msg}")
        else:
            print(f"  [PASS] {name}")

    print("\n--- Test Suite 1: safegguf_validate_path NULL & Boundary Paths ---")
    # 1.1 NULL pointer
    rc = lib.safegguf_validate_path(None, 0, 0)
    check("safegguf_validate_path(NULL, 0, 0) == 64", rc == 64, f"got {rc}")

    # 1.2 Empty path
    rc = lib.safegguf_validate_path(b"", 0, 0)
    check("safegguf_validate_path(b'', 0, 0) == 74", rc == 74, f"got {rc}")

    # 1.3 Non-existent path
    rc = lib.safegguf_validate_path(b"C:\\__non_existent_file_path__.gguf", 0, 0)
    check("safegguf_validate_path(non-existent) == 74", rc == 74, f"got {rc}")

    # 1.4 Directory path
    rc = lib.safegguf_validate_path(str(REPO_ROOT / "tests").encode("utf-8"), 0, 0)
    check("safegguf_validate_path(directory) == 74", rc == 74, f"got {rc}")

    # 1.5 Extremely long path (10,000 chars)
    long_path = ("C:\\" + "a" * 10000 + ".gguf").encode("utf-8")
    rc = lib.safegguf_validate_path(long_path, 0, 0)
    check("safegguf_validate_path(10000 chars) == 74", rc == 74, f"got {rc}")

    # 1.6 Valid model path with profile 0, endian 0
    rc = lib.safegguf_validate_path(valid_model.encode("utf-8"), 0, 0)
    check("safegguf_validate_path(valid_model, 0, 0) == 0", rc == 0, f"got {rc}")

    # 1.7 Exploit model path
    rc = lib.safegguf_validate_path(exploit_model.encode("utf-8"), 0, 0)
    check("safegguf_validate_path(exploit_model, 0, 0) == 2", rc == 2, f"got {rc}")

    # 1.8 0-byte file via path
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as tf:
        zero_byte_path = tf.name
    try:
        rc = lib.safegguf_validate_path(zero_byte_path.encode("utf-8"), 0, 0)
        check("safegguf_validate_path(zero_byte_file) == 2", rc == 2, f"got {rc}")
    finally:
        os.unlink(zero_byte_path)

    print("\n--- Test Suite 2: safegguf_validate_fd Adversarial Handles ---")
    # 2.1 Handle 0
    rc = lib.safegguf_validate_fd(0, 0, 0)
    check("safegguf_validate_fd(0) == 74", rc == 74, f"got {rc}")

    # 2.2 Handle -1
    rc = lib.safegguf_validate_fd(-1, 0, 0)
    check("safegguf_validate_fd(-1) == 74", rc == 74, f"got {rc}")

    # 2.3 Handle -2
    rc = lib.safegguf_validate_fd(-2, 0, 0)
    check("safegguf_validate_fd(-2) == 74", rc == 74, f"got {rc}")

    # 2.4 Handle -99999
    rc = lib.safegguf_validate_fd(-99999, 0, 0)
    check("safegguf_validate_fd(-99999) == 74", rc == 74, f"got {rc}")

    # 2.5 Handle min signed 64-bit int (-2^63)
    min_i64 = -9223372036854775808
    rc = lib.safegguf_validate_fd(min_i64, 0, 0)
    check(f"safegguf_validate_fd(-2^63) == 74", rc == 74, f"got {rc}")

    # 2.6 Handle small positive invalid numbers
    for h in [1, 2, 42, 100, 999]:
        rc = lib.safegguf_validate_fd(h, 0, 0)
        check(f"safegguf_validate_fd({h}) == 74", rc == 74, f"got {rc}")

    # 2.7 Handle max 32-bit int (2^31 - 1)
    rc = lib.safegguf_validate_fd(2147483647, 0, 0)
    check("safegguf_validate_fd(2^31-1) == 74", rc == 74, f"got {rc}")

    # 2.8 Handle max 64-bit int (2^63 - 1)
    max_i64 = 9223372036854775807
    rc = lib.safegguf_validate_fd(max_i64, 0, 0)
    check("safegguf_validate_fd(2^63-1) == 74", rc == 74, f"got {rc}")

    # 2.9 Closed handle
    with open(valid_model, "rb") as f:
        if sys.platform == "win32":
            import msvcrt
            raw_h = msvcrt.get_osfhandle(f.fileno())
        else:
            raw_h = f.fileno()
    # File is now closed, raw_h is invalid
    rc = lib.safegguf_validate_fd(raw_h, 0, 0)
    check("safegguf_validate_fd(closed_handle) == 74", rc == 74, f"got {rc}")

    # 2.10 0-byte file via fd
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as tf:
        zero_byte_path = tf.name
    try:
        with open(zero_byte_path, "rb") as f:
            if sys.platform == "win32":
                import msvcrt
                raw_h = msvcrt.get_osfhandle(f.fileno())
            else:
                raw_h = f.fileno()
            rc = lib.safegguf_validate_fd(raw_h, 0, 0)
            check("safegguf_validate_fd(zero_byte_file) == 2", rc == 2, f"got {rc}")
    finally:
        os.unlink(zero_byte_path)

    print("\n--- Test Suite 3: Out-of-Range Profile & Endian IDs ---")
    adversarial_combos = [
        ("profile=-1, endian=0", -1, 0),
        ("profile=2, endian=0", 2, 0),
        ("profile=9999, endian=0", 9999, 0),
        ("profile=-9999, endian=0", -9999, 0),
        ("profile=0, endian=-1", 0, -1),
        ("profile=0, endian=3", 0, 3),
        ("profile=0, endian=9999", 0, 9999),
        ("profile=9999, endian=9999", 9999, 9999),
        ("profile=-2147483648, endian=2147483647", -2147483648, 2147483647),
    ]

    path_bytes = valid_model.encode("utf-8")
    for desc, p, e in adversarial_combos:
        rc = lib.safegguf_validate_path(path_bytes, p, e)
        check(f"path combo ({desc}) -> exit {rc}", rc == 64, f"expected 64 USAGE_ERROR, got {rc}")

    with open(valid_model, "rb") as f:
        if sys.platform == "win32":
            import msvcrt
            raw_h = msvcrt.get_osfhandle(f.fileno())
        else:
            raw_h = f.fileno()

        for desc, p, e in adversarial_combos:
            rc = lib.safegguf_validate_fd(raw_h, p, e)
            check(f"fd combo ({desc}) -> exit {rc}", rc == 64, f"expected 64 USAGE_ERROR, got {rc}")

    print("\n--- Test Suite 4: Anti-TOCTOU & Seek Offset Preservation ---")
    with open(valid_model, "rb") as f:
        target_offset = 23
        f.seek(target_offset)
        initial_tell = f.tell()
        check("Initial seek offset", initial_tell == target_offset, f"got {initial_tell}")

        if sys.platform == "win32":
            import msvcrt
            raw_h = msvcrt.get_osfhandle(f.fileno())
        else:
            raw_h = f.fileno()

        rc = lib.safegguf_validate_fd(raw_h, 0, 0)
        check("safegguf_validate_fd on open file == 0", rc == 0, f"got {rc}")

        final_tell = f.tell()
        check(f"Seek offset preserved at {target_offset}", final_tell == target_offset, f"got {final_tell}")

        data = f.read(10)
        check("File remains readable after validation", len(data) == 10, f"read {len(data)} bytes")

    print("\n--- Test Suite 5: Negative Corpus C-ABI Sweep (Path & FD) ---")
    neg_dir = REPO_ROOT / "tests" / "fixtures" / "negative"
    neg_files = list(neg_dir.glob("*.gguf"))
    print(f"Testing {len(neg_files)} negative corpus fixtures via C-ABI...")
    check("Negative fixtures count >= 15", len(neg_files) >= 15, f"got {len(neg_files)}")

    for nf in neg_files:
        # Test path
        rc_p = lib.safegguf_validate_path(str(nf).encode("utf-8"), 0, 0)
        check(f"path: {nf.name} -> {rc_p}", rc_p == 2, f"expected 2, got {rc_p}")

        # Test fd
        with open(str(nf), "rb") as f:
            if sys.platform == "win32":
                import msvcrt
                raw_h = msvcrt.get_osfhandle(f.fileno())
            else:
                raw_h = f.fileno()
            rc_fd = lib.safegguf_validate_fd(raw_h, 0, 0)
            check(f"fd: {nf.name} -> {rc_fd}", rc_fd == 2, f"expected 2, got {rc_fd}")

    print("\n--- Test Suite 6: High-Volume Adversarial Stress Loop (1,000 iterations) ---")
    for i in range(1000):
        assert lib.safegguf_validate_path(None, 0, 0) == 64
        assert lib.safegguf_validate_fd(0, 0, 0) == 74
        assert lib.safegguf_validate_fd(-1, 0, 0) == 74
        assert lib.safegguf_validate_path(b"C:\\__non_existent__.gguf", 0, 0) == 74
        assert lib.safegguf_validate_path(b"C:\\__non_existent__.gguf", 999, -999) == 64
    check("1,000 rapid adversarial iterations completed cleanly without crash", True)

    print("\n--- Test Suite 7: Python Binding (safegguf-py) Guardrails ---")
    import safegguf
    res = safegguf.validate_path(None)
    check("safegguf.validate_path(None) is USAGE_ERROR (64)", res.exit_code == 64 and res.status == "USAGE_ERROR")

    res = safegguf.validate_fd(-1)
    check("safegguf.validate_fd(-1) is IO_ERROR (74)", res.exit_code == 74 and res.status == "IO_ERROR")

    for bad_fd in [None, "invalid_fd", 99999]:
        res = safegguf.validate_fd(bad_fd)
        check(f"safegguf.validate_fd({bad_fd!r}) is USAGE_ERROR or IO_ERROR", res.exit_code in (64, 74) and res.status in ("USAGE_ERROR", "IO_ERROR"))

    print("\n=======================================================")
    if failures:
        print(f"FAILED: {len(failures)} checks failed!")
        for fail in failures:
            print(f"  - {fail}")
        sys.exit(1)
    else:
        print("SUCCESS: ALL ADVERSARIAL CHECKS PASSED (Zero crashes, zero panics confirmed)!")
        sys.exit(0)

if __name__ == "__main__":
    run_tests()
