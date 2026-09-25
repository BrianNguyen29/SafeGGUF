#!/usr/bin/env python3
"""
Deep Stress and Edge Case Verification Harness for Milestone 2 Retry.
Empirically challenges:
1. Exact path length boundary transitions (4095, 4096, 4097, 32767, 32768, 65536, 100000).
2. Advanced surrogate varieties (high surrogate, low surrogate, unpaired sequences, surrogate pairs).
3. Extreme integer boundaries for file descriptors (-2**128 to +2**128, bool subclasses).
4. High-concurrency contention on shared descriptors with concurrent seek/read assertions.
5. C-ABI direct boundary invocation for 32768-byte path (verifying elimination of wide-path panic).
"""

import os
import sys
import threading
import concurrent.futures
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "bindings" / "python"))

import safegguf
from safegguf import Status, Profile, Endian, ValidationResult

VALID_GGUF = repo_root / "tests" / "fixtures" / "valid.gguf"
CVE_GGUF = repo_root / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"

results = []

def record(name: str, passed: bool, detail: str = ""):
    status_str = "PASS" if passed else "FAIL"
    print(f"[{status_str}] {name}: {detail}")
    results.append((name, passed, detail))

def test_path_boundaries():
    print("\n--- Deep Probe 1: Path Length Exact Boundaries ---")
    lib = safegguf.core._get_lib()

    lengths_to_test = [
        0, 1, 10, 255, 260, 4095, 4096, 4097, 8192, 16384, 32767, 32768, 65536, 100000
    ]

    for length in lengths_to_test:
        path_str = "A" * length + ".gguf" if length > 0 else ""
        # 1. Python binding test
        try:
            res = safegguf.validate_path(path_str)
            py_pass = isinstance(res, ValidationResult) and res.exit_code == 74
            record(f"py_validate_path_len_{length}", py_pass, f"res={res}")
        except Exception as e:
            record(f"py_validate_path_len_{length}", False, f"Raised exception: {e}")

        # 2. C-ABI direct test
        try:
            path_bytes = ("B" * length).encode("utf-8")
            rc = lib.safegguf_validate_path(path_bytes, 0, 0)
            c_pass = (rc == 74)
            record(f"c_abi_validate_path_len_{length}", c_pass, f"rc={rc}")
        except Exception as e:
            record(f"c_abi_validate_path_len_{length}", False, f"C-ABI call crashed: {e}")

def test_surrogates_deep():
    print("\n--- Deep Probe 2: Surrogate Codepoints and Encoding Variations ---")
    surrogate_cases = [
        ("lone_high_ud800", "model_\ud800.gguf"),
        ("lone_low_udc00", "model_\udc00.gguf"),
        ("lone_high_udbff", "model_\udbff.gguf"),
        ("lone_low_udfff", "model_\udfff.gguf"),
        ("interleaved_surrogates", "a\ud800b\udc00c\ud801d\udc01.gguf"),
        ("surrogate_at_end", "valid_path_\ud800"),
        ("surrogate_at_start", "\ud800_valid_path.gguf"),
    ]

    for name, s in surrogate_cases:
        try:
            res = safegguf.validate_path(s)
            record(f"surrogate_{name}", isinstance(res, ValidationResult) and res.exit_code == 74, f"res={res}")
        except Exception as e:
            record(f"surrogate_{name}", False, f"Raised exception: {e}")

    # Test raw bytes with invalid utf-8 sequences
    invalid_bytes = [
        ("invalid_utf8_ff", b"\xff\xff\xff.gguf"),
        ("invalid_utf8_c3_28", b"\xc3\x28.gguf"),
        ("invalid_utf8_e0_a0", b"\xe0\xa0\x80.gguf"),
    ]
    for name, b in invalid_bytes:
        try:
            res = safegguf.validate_path(b)
            # Either 74 (IO error file not found) or rejected, but no exception
            record(f"raw_bytes_{name}", isinstance(res, ValidationResult) and res.exit_code in (2, 74), f"res={res}")
        except Exception as e:
            record(f"raw_bytes_{name}", False, f"Raised exception: {e}")

def test_extreme_fd_integers():
    print("\n--- Deep Probe 3: Extreme Integer FD Safety ---")
    class BoolSubclass(int):
        pass

    extreme_values = [
        ("neg_2_pow_64", -(2**64)),
        ("pos_2_pow_64", 2**64),
        ("neg_2_pow_128", -(2**128)),
        ("pos_2_pow_128", 2**128),
        ("neg_2_pow_256", -(2**256)),
        ("pos_2_pow_256", 2**256),
    ]

    for name, val in extreme_values:
        try:
            res = safegguf.validate_fd(val)
            record(f"extreme_fd_{name}", isinstance(res, ValidationResult) and res.exit_code == 74, f"res={res}")
        except Exception as e:
            record(f"extreme_fd_{name}", False, f"Raised exception: {e}")

    # Subclasses of int
    try:
        custom_int = BoolSubclass(42)
        res = safegguf.validate_fd(custom_int)
        record("custom_int_subclass", isinstance(res, ValidationResult) and res.exit_code in (64, 74), f"res={res}")
    except Exception as e:
        record("custom_int_subclass", False, f"Raised exception: {e}")

def test_high_concurrency_shared_fd():
    print("\n--- Deep Probe 4: High Concurrency Shared FD Contention ---")
    shared_fd = os.open(str(VALID_GGUF), os.O_RDONLY)
    try:
        base_offset = 128
        os.lseek(shared_fd, base_offset, os.SEEK_SET)

        def worker(idx):
            prof = "gguf-spec" if idx % 2 == 0 else "llama-cpp"
            for _ in range(15):
                res = safegguf.validate_fd(shared_fd, profile=prof)
                if not res.is_valid or res.exit_code != 0:
                    return False, f"Worker {idx} got {res}"
            return True, "OK"

        workers_count = 32
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers_count) as executor:
            futures = [executor.submit(worker, i) for i in range(workers_count)]
            results_list = [f.result() for f in futures]

        all_workers_passed = all(r[0] for r in results_list)
        final_offset = os.lseek(shared_fd, 0, os.SEEK_CUR)
        offset_preserved = (final_offset == base_offset)

        record("concurrency_32_threads_shared_fd", all_workers_passed, f"Total 480 calls across 32 threads")
        record("concurrency_32_threads_offset_preserved", offset_preserved, f"final_offset={final_offset} expected={base_offset}")

        # Post read
        chunk = os.read(shared_fd, 32)
        record("concurrency_32_threads_post_read", len(chunk) == 32, f"read {len(chunk)} bytes")
    finally:
        os.close(shared_fd)

def main():
    print("======================================================================")
    print("  SAFEGGUF CHALLENGER M2 RETRY DEEP STRESS HARNESS")
    print("======================================================================")

    test_path_boundaries()
    test_surrogates_deep()
    test_extreme_fd_integers()
    test_high_concurrency_shared_fd()

    total = len(results)
    passed = sum(1 for _, p, _ in results if p)
    failed = total - passed

    print("\n======================================================================")
    print(f"DEEP STRESS SUMMARY: Total={total}, Passed={passed}, Failed={failed}")
    print("======================================================================")

    if failed > 0:
        print("\nFailures:")
        for name, p, detail in results:
            if not p:
                print(f"  [FAIL] {name}: {detail}")
        sys.exit(1)
    else:
        print("\nAll deep stress tests PASSED cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    main()
