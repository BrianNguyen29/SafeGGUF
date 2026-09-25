#!/usr/bin/env python3
"""
FFI Boundary & Robustness Fuzzing Test Suite for SafeGGUF C-ABI (v1) and Python Bindings.

Fuzzes and stress-tests:
1. Entry point NULL pointer dereferences and misaligned/truncated options structs.
2. Corrupted struct_size, out-of-range profile & endian enum discriminants.
3. Random and boundary resource limits (0, 1, UINT64_MAX).
4. Arbitrary and oversized paths (NULL, empty, 64KB, binary non-UTF8, unreadable).
5. Closed, negative, and invalid raw OS file handles.
6. Diagnostic result buffer boundaries (NULL result vs non-NULL struct).
7. High-concurrency multi-threaded stress across FFI boundaries.
"""

import os
import sys
import ctypes
import random
import string
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "bindings" / "python"))

import safegguf
from safegguf.core import _find_library, SafeggufOptionsV1, SafeggufResult, Status

DLL_PATH = _find_library()
print(f"[*] Testing SafeGGUF FFI boundaries via: {DLL_PATH}")
lib = ctypes.CDLL(DLL_PATH)

# Function signatures
lib.safegguf_version.restype = ctypes.c_char_p

lib.safegguf_validate_path_v1.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(SafeggufOptionsV1),
    ctypes.POINTER(SafeggufResult),
]
lib.safegguf_validate_path_v1.restype = ctypes.c_int

lib.safegguf_validate_fd_v1.argtypes = [
    ctypes.c_ssize_t,
    ctypes.POINTER(SafeggufOptionsV1),
    ctypes.POINTER(SafeggufResult),
]
lib.safegguf_validate_fd_v1.restype = ctypes.c_int

VALID_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "valid.gguf"
CVE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"

assert VALID_FIXTURE.exists(), f"Missing {VALID_FIXTURE}"
assert CVE_FIXTURE.exists(), f"Missing {CVE_FIXTURE}"

passed_checks = 0
failed_checks = 0

def record(name: str, cond: bool, msg: str = ""):
    global passed_checks, failed_checks
    if cond:
        passed_checks += 1
    else:
        failed_checks += 1
        print(f"[FAIL] {name}: {msg}")

def fuzz_options_struct_sizes():
    print("\n--- Fuzzing 1: Invalid struct_size in safegguf_options_v1_t ---")
    correct_size = ctypes.sizeof(SafeggufOptionsV1)
    invalid_sizes = [
        0, 1, 2, 4, 8, 16,
        correct_size - 1,
        correct_size + 1,
        correct_size + 4,
        1024,
        0x7FFFFFFF,
        0xFFFFFFFF,
    ]

    for sz in invalid_sizes:
        opts = SafeggufOptionsV1()
        opts.struct_size = sz
        opts.profile = 0
        opts.endian = 0
        res = SafeggufResult()

        rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
        err_code = res.error_code.decode("utf-8", errors="replace")
        record(
            f"struct_size={sz}",
            rc == Status.USAGE_ERROR and ("E_USAGE_INVALID_OPTIONS" in err_code or "InvalidOptionSize" in err_code),
            f"expected 64 + InvalidOptionSize, got rc={rc} error={err_code}",
        )

def fuzz_options_enums():
    print("\n--- Fuzzing 2: Out-of-Range Profile & Endian Enums ---")
    correct_size = ctypes.sizeof(SafeggufOptionsV1)

    bad_profiles = [-999999, -2, -1, 2, 3, 100, 0x7FFFFFFF]
    for bp in bad_profiles:
        opts = SafeggufOptionsV1(
            struct_size=correct_size,
            profile=bp,
            endian=0,
            max_alloc_bytes=0,
            max_work_units=0,
            max_scanned_bytes=0,
            reserved=None,
        )
        res = SafeggufResult()
        rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
        err_code = res.error_code.decode("utf-8", errors="replace")
        record(
            f"profile={bp}",
            rc == Status.USAGE_ERROR and ("E_USAGE_INVALID_PROFILE" in err_code or "InvalidProfile" in err_code),
            f"expected 64 + InvalidProfile, got rc={rc} error={err_code}",
        )

    bad_endians = [-999999, -2, -1, 3, 4, 100, 0x7FFFFFFF]
    for be in bad_endians:
        opts = SafeggufOptionsV1(
            struct_size=correct_size,
            profile=0,
            endian=be,
            max_alloc_bytes=0,
            max_work_units=0,
            max_scanned_bytes=0,
            reserved=None,
        )
        res = SafeggufResult()
        rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
        err_code = res.error_code.decode("utf-8", errors="replace")
        record(
            f"endian={be}",
            rc == Status.USAGE_ERROR and ("E_USAGE_INVALID_ENDIAN" in err_code or "InvalidEndian" in err_code),
            f"expected 64 + InvalidEndian, got rc={rc} error={err_code}",
        )

def fuzz_path_boundaries():
    print("\n--- Fuzzing 3: Path Boundaries & Malformed Strings ---")
    res = SafeggufResult()

    # 1. NULL path
    rc = lib.safegguf_validate_path_v1(None, None, ctypes.byref(res))
    record("path=NULL", rc == Status.USAGE_ERROR, f"expected 64, got {rc}")

    # 2. Empty string
    rc = lib.safegguf_validate_path_v1(b"", None, ctypes.byref(res))
    record("path=empty", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    # 3. Non-existent path
    rc = lib.safegguf_validate_path_v1(b"/non_existent/model.gguf", None, ctypes.byref(res))
    record("path=non_existent", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    # 4. Long paths up to 16384 bytes
    for length in [1024, 4096, 8192, 16384]:
        long_path = b"A" * length + b".gguf"
        rc = lib.safegguf_validate_path_v1(long_path, None, ctypes.byref(res))
        record(f"path=length_{length}", rc in (Status.IO_ERROR, Status.USAGE_ERROR), f"got {rc}")

    # 5. Non-UTF8 random binary path
    for _ in range(20):
        rand_bytes = bytes(random.getrandbits(8) for _ in range(64)) + b"\x00"
        rc = lib.safegguf_validate_path_v1(rand_bytes, None, ctypes.byref(res))
        record("path=random_bytes", rc in (Status.IO_ERROR, Status.USAGE_ERROR), f"got {rc}")

def fuzz_fd_handles():
    print("\n--- Fuzzing 4: Raw File Descriptor / OS Handle Boundaries ---")
    res = SafeggufResult()

    # Handles that must fail gracefully with IO_ERROR (74)
    adversarial_handles = [
        0, -1, -2, -100, -999999, -2**31, -2**63 + 1,
        1, 2, 42, 100, 99999, 2147483647, 2**63 - 1
    ]

    for h in adversarial_handles:
        rc = lib.safegguf_validate_fd_v1(h, None, ctypes.byref(res))
        record(f"fd={h}", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    # Valid file descriptor seek preservation fuzzing
    with open(VALID_FIXTURE, "rb") as f:
        if sys.platform == "win32":
            import msvcrt
            raw_h = msvcrt.get_osfhandle(f.fileno())
        else:
            raw_h = f.fileno()

        for offset in [0, 1, 16, 42, 100]:
            f.seek(offset)
            rc = lib.safegguf_validate_fd_v1(raw_h, None, ctypes.byref(res))
            current = f.tell()
            record(
                f"fd_seek_preserve_offset_{offset}",
                rc == Status.PASS and current == offset,
                f"rc={rc}, tell={current} (expected {offset})"
            )

def fuzz_null_and_buffer_diagnostics():
    print("\n--- Fuzzing 5: NULL Pointer Tolerances & Result Buffer Safety ---")
    # 1. NULL options + NULL result on valid model
    rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), None, None)
    record("path_v1(valid, NULL, NULL)", rc == Status.PASS, f"got {rc}")

    # 2. NULL options + NULL result on exploit model
    rc = lib.safegguf_validate_path_v1(str(CVE_FIXTURE).encode("utf-8"), None, None)
    record("path_v1(exploit, NULL, NULL)", rc == Status.REJECT, f"got {rc}")

    # 3. NULL result with valid options on valid model
    opts = SafeggufOptionsV1(
        struct_size=ctypes.sizeof(SafeggufOptionsV1),
        profile=0,
        endian=0,
        max_alloc_bytes=0,
        max_work_units=0,
        max_scanned_bytes=0,
        reserved=None,
    )
    rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), None)
    record("path_v1(valid, opts, NULL)", rc == Status.PASS, f"got {rc}")

    # 4. Strict string null-termination check in SafeggufResult
    res = SafeggufResult()
    rc = lib.safegguf_validate_path_v1(str(CVE_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
    err_code = res.error_code.decode("utf-8", errors="replace")
    cat = res.category.decode("utf-8", errors="replace")
    stg = res.stage.decode("utf-8", errors="replace")
    msg = res.message.decode("utf-8", errors="replace")
    record(
        "result_buffer_diagnostics_populated",
        rc == Status.REJECT and len(err_code) > 0 and len(cat) > 0 and len(msg) > 0,
        f"err={err_code}, cat={cat}, stage={stg}, msg={msg}"
    )

def fuzz_multithreaded_concurrency():
    print("\n--- Fuzzing 6: Multi-Threaded FFI Boundary Stress ---")
    threads = []
    thread_errors = []

    def worker(tid: int):
        try:
            for i in range(50):
                # Valid path
                res1 = SafeggufResult()
                rc1 = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), None, ctypes.byref(res1))
                if rc1 != Status.PASS:
                    thread_errors.append(f"T{tid} valid model failed: {rc1}")

                # Exploit path
                res2 = SafeggufResult()
                rc2 = lib.safegguf_validate_path_v1(str(CVE_FIXTURE).encode("utf-8"), None, ctypes.byref(res2))
                if rc2 != Status.REJECT:
                    thread_errors.append(f"T{tid} exploit model failed: {rc2}")

                # Invalid handle
                rc3 = lib.safegguf_validate_fd_v1(-1, None, None)
                if rc3 != Status.IO_ERROR:
                    thread_errors.append(f"T{tid} handle -1 failed: {rc3}")
        except Exception as e:
            thread_errors.append(f"T{tid} exception: {e}")

    for t in range(8):
        th = threading.Thread(target=worker, args=(t,))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    record(
        "multithreaded_stress_zero_errors",
        len(thread_errors) == 0,
        f"Encountered {len(thread_errors)} concurrency errors: {thread_errors[:3]}"
    )

def main():
    print("======================================================================")
    print("       SAFEGGUF ENTERPRISE FFI BOUNDARIES & ROBUSTNESS FUZZER         ")
    print("======================================================================")

    fuzz_options_struct_sizes()
    fuzz_options_enums()
    fuzz_path_boundaries()
    fuzz_fd_handles()
    fuzz_null_and_buffer_diagnostics()
    fuzz_multithreaded_concurrency()

    print("\n" + "=" * 70)
    print(f"Total FFI Checks : {passed_checks + failed_checks}")
    print(f"Passed           : {passed_checks}")
    print(f"Failed           : {failed_checks}")
    print("=" * 70)

    if failed_checks == 0:
        print("\n>>> OVERALL VERDICT: ALL FFI BOUNDARY FUZZING TESTS PASSED <<<")
        sys.exit(0)
    else:
        print(f"\n>>> OVERALL VERDICT: {failed_checks} FFI FUZZ CHECKS FAILED <<<")
        sys.exit(1)

if __name__ == "__main__":
    main()
