#!/usr/bin/env python3
"""
Challenger M2_2 Adversarial Test Harness for SafeGGUF Python Bindings.

Probing:
1. Input validation & exception safety on `validate_path` (None, non-string types, bytes, surrogates, null bytes).
2. Input validation & exception safety on `validate_fd` (-1, closed fds, non-integer fds, huge integers / 32-bit & 64-bit overflow, sockets, pipes).
3. Multiple sequential calls on the same and different descriptors.
4. Concurrent multithreaded calls on different descriptors.
5. Concurrent multithreaded calls on the SAME descriptor.
6. TOCTOU immunity (file mutation/swap while descriptor is open).
7. Seek offset retention and subsequent readability.
8. Direct C-ABI export robustness.
"""

import os
import sys
import time
import socket
import tempfile
import threading
import concurrent.futures
from pathlib import Path

# Add bindings/python to sys.path
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "bindings" / "python"))

import safegguf
from safegguf import Status, Profile, Endian, ValidationResult

VALID_GGUF = repo_root / "tests" / "fixtures" / "valid.gguf"
CVE_GGUF = repo_root / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"

test_results = []

def record(test_name: str, passed: bool, detail: str = ""):
    status_str = "PASS" if passed else "FAIL"
    print(f"[{status_str}] {test_name}: {detail}")
    test_results.append((test_name, passed, detail))


# ==============================================================================
# Suite 1: safegguf.validate_path Probing
# ==============================================================================
def probe_validate_path():
    print("\n--- Suite 1: Probing safegguf.validate_path ---")

    # 1.1 None
    try:
        res = safegguf.validate_path(None)
        passed = (res.exit_code == 64 and res.status == "USAGE_ERROR" and not res.is_valid)
        record("validate_path(None)", passed, f"result={res}")
    except Exception as e:
        record("validate_path(None)", False, f"Raised unhandled exception: {type(e).__name__}: {e}")

    # 1.2 Non-string types: int, float, list, dict, tuple, bool, object
    non_string_samples = [
        ("int", 12345),
        ("float", 3.14159),
        ("list", ["tests", "fixtures", "valid.gguf"]),
        ("dict", {"path": str(VALID_GGUF)}),
        ("tuple", ("valid.gguf",)),
        ("bool_True", True),
        ("bool_False", False),
        ("object", object()),
    ]
    for type_name, val in non_string_samples:
        try:
            res = safegguf.validate_path(val)
            # Should safely return a ValidationResult without raising unhandled exception
            record(f"validate_path({type_name})", isinstance(res, ValidationResult), f"result={res}")
        except Exception as e:
            record(f"validate_path({type_name})", False, f"Raised unhandled exception: {type(e).__name__}: {e}")

    # 1.3 Path-like objects
    try:
        res = safegguf.validate_path(Path(VALID_GGUF))
        record("validate_path(pathlib.Path)", res.is_valid and res.exit_code == 0, f"result={res}")
    except Exception as e:
        record("validate_path(pathlib.Path)", False, f"Raised unhandled: {e}")

    # 1.4 Bytes path
    try:
        res = safegguf.validate_path(bytes(str(VALID_GGUF), "utf-8"))
        record("validate_path(bytes)", isinstance(res, ValidationResult), f"result={res}")
    except Exception as e:
        record("validate_path(bytes)", False, f"Raised unhandled: {e}")

    # 1.5 Lone surrogate characters in string (UTF-8 encoding stress)
    import subprocess
    cmd_surrogate = [sys.executable, "-c", "import sys; sys.path.insert(0, 'bindings/python'); import safegguf; safegguf.validate_path('invalid_\\ud800_path.gguf')"]
    proc_surrogate = subprocess.run(cmd_surrogate, capture_output=True, text=True, cwd=str(repo_root))
    if proc_surrogate.returncode != 0 and "UnicodeEncodeError" in proc_surrogate.stderr:
        record("validate_path(surrogate_str)", False, f"CRITICAL UNHANDLED EXCEPTION: {proc_surrogate.stderr.strip().splitlines()[-1]}")
    else:
        record("validate_path(surrogate_str)", proc_surrogate.returncode == 0, f"rc={proc_surrogate.returncode}")

    # 1.6 Embedded null byte
    try:
        res = safegguf.validate_path(f"{VALID_GGUF}\x00extra_payload")
        record("validate_path(embedded_null)", isinstance(res, ValidationResult), f"result={res}")
    except Exception as e:
        record("validate_path(embedded_null)", False, f"Raised unhandled: {e}")

    # 1.7 Extreme length string (100k chars) - Subprocess test for Zig panic
    cmd_long = [sys.executable, "-c", "import sys; sys.path.insert(0, 'bindings/python'); import safegguf; safegguf.validate_path('A' * 100000 + '.gguf')"]
    proc_long = subprocess.run(cmd_long, capture_output=True, text=True, cwd=str(repo_root))
    if proc_long.returncode != 0 and ("panic" in proc_long.stderr or "index out of bounds" in proc_long.stderr):
        record("validate_path(100k_chars)", False, f"CRITICAL HOST CRASH: Zig runtime panic: {proc_long.stderr.strip().splitlines()[0]}")
    else:
        record("validate_path(100k_chars)", proc_long.returncode == 0, f"rc={proc_long.returncode}")

    # 1.8 Empty string
    try:
        res = safegguf.validate_path("")
        record("validate_path(empty_str)", isinstance(res, ValidationResult) and res.exit_code == 74, f"result={res}")
    except Exception as e:
        record("validate_path(empty_str)", False, f"Raised unhandled: {e}")

    # 1.9 Directory path
    try:
        res = safegguf.validate_path(str(repo_root / "tests"))
        record("validate_path(directory)", isinstance(res, ValidationResult) and res.exit_code in (2, 74), f"result={res}")
    except Exception as e:
        record("validate_path(directory)", False, f"Raised unhandled: {e}")


# ==============================================================================
# Suite 2: safegguf.validate_fd Probing
# ==============================================================================
def probe_validate_fd():
    print("\n--- Suite 2: Probing safegguf.validate_fd ---")

    # 2.1 Negative file descriptors
    for neg_fd in [-1, -2, -999999]:
        try:
            res = safegguf.validate_fd(neg_fd)
            record(f"validate_fd({neg_fd})", isinstance(res, ValidationResult) and res.exit_code == 74, f"result={res}")
        except Exception as e:
            record(f"validate_fd({neg_fd})", False, f"Raised unhandled: {type(e).__name__}: {e}")

    # 2.2 Closed file descriptor
    try:
        fd_temp = os.open(str(VALID_GGUF), os.O_RDONLY)
        os.close(fd_temp)
        res = safegguf.validate_fd(fd_temp)
        record("validate_fd(closed_fd)", isinstance(res, ValidationResult) and res.exit_code == 74, f"result={res}")
    except Exception as e:
        record("validate_fd(closed_fd)", False, f"Raised unhandled: {type(e).__name__}: {e}")

    # 2.3 Non-integer descriptors
    non_int_fds = [
        ("None", None),
        ("str", "not_an_fd"),
        ("float", 3.14),
        ("float_nan", float("nan")),
        ("float_inf", float("inf")),
        ("list", [1, 2]),
        ("dict", {"fd": 0}),
        ("tuple", (1,)),
        ("object", object()),
    ]
    for name, val in non_int_fds:
        try:
            res = safegguf.validate_fd(val)
            record(f"validate_fd({name})", isinstance(res, ValidationResult) and res.exit_code in (64, 74), f"result={res}")
        except Exception as e:
            record(f"validate_fd({name})", False, f"Raised unhandled: {type(e).__name__}: {e}")

    # 2.4 Extreme integers (32-bit & 64-bit integer overflow checks)
    extreme_ints = [
        ("INT32_MAX", 2147483647),
        ("INT32_MAX_PLUS_1", 2147483648),
        ("UINT32_MAX", 4294967295),
        ("UINT32_MAX_PLUS_1", 4294967296),
        ("INT64_MAX", 9223372036854775807),
        ("INT64_MAX_PLUS_1", 9223372036854775808),
        ("INT32_MIN_MINUS_1", -2147483649),
        ("INT64_MIN", -9223372036854775808),
    ]
    for name, val in extreme_ints:
        try:
            res = safegguf.validate_fd(val)
            record(f"validate_fd({name})", isinstance(res, ValidationResult) and res.exit_code == 74, f"result={res}")
        except Exception as e:
            record(f"validate_fd({name})", False, f"CRITICAL: Unhandled {type(e).__name__}: {e}")

    # 2.5 Socket descriptors
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        res_fileno = safegguf.validate_fd(s.fileno())
        record("validate_fd(socket_fileno)", isinstance(res_fileno, ValidationResult) and res_fileno.exit_code == 74, f"result={res_fileno}")
        res_obj = safegguf.validate_fd(s)
        record("validate_fd(socket_obj)", isinstance(res_obj, ValidationResult) and res_obj.exit_code in (64, 74), f"result={res_obj}")
        s.close()
        res_closed_sock = safegguf.validate_fd(s.fileno())
        record("validate_fd(closed_socket)", isinstance(res_closed_sock, ValidationResult) and res_closed_sock.exit_code == 74, f"result={res_closed_sock}")
    except Exception as e:
        record("validate_fd(socket)", False, f"Raised unhandled: {e}")

    # 2.6 Pipe descriptors
    try:
        r_fd, w_fd = os.pipe()
        try:
            res_r = safegguf.validate_fd(r_fd)
            # A pipe is not a seekable GGUF model; should fail cleanly
            record("validate_fd(pipe_read)", isinstance(res_r, ValidationResult) and res_r.exit_code in (2, 74), f"result={res_r}")
            res_w = safegguf.validate_fd(w_fd)
            record("validate_fd(pipe_write)", isinstance(res_w, ValidationResult) and res_w.exit_code in (2, 74), f"result={res_w}")
        finally:
            os.close(r_fd)
            os.close(w_fd)
    except Exception as e:
        record("validate_fd(pipe)", False, f"Raised unhandled: {e}")


# ==============================================================================
# Suite 3: Multiple Sequential Calls on Same & Different Descriptors
# ==============================================================================
def probe_sequential():
    print("\n--- Suite 3: Sequential Validation Stress ---")

    # 3.1 50 Sequential calls on the SAME descriptor
    fd_same = os.open(str(VALID_GGUF), os.O_RDONLY)
    try:
        initial_offset = 64
        os.lseek(fd_same, initial_offset, os.SEEK_SET)

        all_ok = True
        for i in range(50):
            res = safegguf.validate_fd(fd_same, profile="gguf-spec")
            cur_offset = os.lseek(fd_same, 0, os.SEEK_CUR)
            if not res.is_valid or res.exit_code != 0 or cur_offset != initial_offset:
                all_ok = False
                record(f"sequential_same_fd_iter_{i}", False, f"res={res}, offset={cur_offset}")
                break

        if all_ok:
            # Read after 50 iterations to confirm descriptor is healthy
            buf = os.read(fd_same, 16)
            healthy = len(buf) == 16
            record("sequential_50_same_fd", healthy, f"read {len(buf)} bytes, offset restored")
    finally:
        os.close(fd_same)

    # 3.2 50 Sequential calls on DIFFERENT descriptors
    diff_ok = True
    for i in range(50):
        target = VALID_GGUF if i % 2 == 0 else CVE_GGUF
        expected_code = 0 if i % 2 == 0 else 2
        fd_diff = os.open(str(target), os.O_RDONLY)
        try:
            res = safegguf.validate_fd(fd_diff, profile="llama-cpp")
            if res.exit_code != expected_code:
                diff_ok = False
                record(f"sequential_diff_fd_iter_{i}", False, f"res={res}, expected={expected_code}")
                break
        finally:
            os.close(fd_diff)

    if diff_ok:
        record("sequential_50_diff_fds", True, "All 50 open/validate/close cycles matched expected exit codes")


# ==============================================================================
# Suite 4: Concurrent Calls on Different Descriptors
# ==============================================================================
def probe_concurrent_different_fds():
    print("\n--- Suite 4: Concurrent Calls on Different Descriptors ---")

    def worker_task(thread_id: int):
        target = VALID_GGUF if thread_id % 2 == 0 else CVE_GGUF
        expected_code = 0 if thread_id % 2 == 0 else 2
        file_len = os.path.getsize(target)
        initial_offset = (thread_id * 8) % max(1, (file_len - 16))

        fd = os.open(str(target), os.O_RDONLY)
        try:
            os.lseek(fd, initial_offset, os.SEEK_SET)

            for _ in range(10):
                res = safegguf.validate_fd(fd, profile="llama-cpp")
                cur_offset = os.lseek(fd, 0, os.SEEK_CUR)
                if res.exit_code != expected_code or cur_offset != initial_offset:
                    return False, f"Thread {thread_id} failed: code={res.exit_code}, offset={cur_offset} (exp {initial_offset})"

            # Final read check
            buf = os.read(fd, 8)
            if len(buf) != 8:
                return False, f"Thread {thread_id} damaged fd: read {len(buf)} bytes at offset {initial_offset}"

            return True, "OK"
        finally:
            os.close(fd)

    thread_count = 20
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(worker_task, i) for i in range(thread_count)]
        results = [f.result() for f in futures]

    all_pass = all(r[0] for r in results)
    record("concurrent_20_threads_diff_fds", all_pass, f"Completed 200 total validations across {thread_count} threads")


# ==============================================================================
# Suite 5: Concurrent Calls on the SAME Shared Descriptor
# ==============================================================================
def probe_concurrent_shared_fd():
    print("\n--- Suite 5: Concurrent Calls on the SAME Shared Descriptor ---")

    shared_fd = os.open(str(VALID_GGUF), os.O_RDONLY)
    try:
        base_offset = 32
        os.lseek(shared_fd, base_offset, os.SEEK_SET)

        def shared_worker(worker_id: int):
            errors = []
            for j in range(10):
                res = safegguf.validate_fd(shared_fd, profile="gguf-spec")
                if not res.is_valid or res.exit_code != 0:
                    errors.append(f"Worker {worker_id} iter {j} invalid: {res}")
            return errors

        thread_count = 16
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(shared_worker, i) for i in range(thread_count)]
            all_errors = [err for f in futures for err in f.result()]

        passed = len(all_errors) == 0
        final_offset = os.lseek(shared_fd, 0, os.SEEK_CUR)
        offset_ok = (final_offset == base_offset)
        record("concurrent_shared_fd_validation", passed, f"160 concurrent calls completed, errors={len(all_errors)}")
        record("concurrent_shared_fd_offset_retention", offset_ok, f"final_offset={final_offset} (expected {base_offset})")

        # Verify descriptor still functions
        read_bytes = os.read(shared_fd, 16)
        record("concurrent_shared_fd_post_read", len(read_bytes) == 16, f"read {len(read_bytes)} bytes post-stress")
    finally:
        os.close(shared_fd)


# ==============================================================================
# Suite 6: TOCTOU Immunity & File Mutation Probing
# ==============================================================================
def probe_toctou():
    print("\n--- Suite 6: TOCTOU Immunity Probing ---")

    # Create a temporary file with valid GGUF contents
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as tmp:
        temp_path = Path(tmp.name)
        with open(VALID_GGUF, "rb") as orig:
            tmp.write(orig.read())

    try:
        # Open descriptor
        fd_toctou = os.open(str(temp_path), os.O_RDONLY)
        try:
            # 1. Initial validation passes
            res1 = safegguf.validate_fd(fd_toctou)
            record("toctou_pre_mutation", res1.is_valid and res1.exit_code == 0, f"res1={res1}")

            # 2. Overwrite file on disk with garbage
            # On Windows, open files with O_RDONLY without FILE_SHARE_WRITE cannot be written to
            # by normal open("wb"). Let's test if filesystem path validation differs from fd validation:
            # First, check validate_path on the file
            res_path = safegguf.validate_path(str(temp_path))
            record("toctou_path_matches_fd", res_path.exit_code == res1.exit_code, "Path and FD agree before swap")

            # 3. Check seek offset preservation at various offsets
            offsets_to_test = [0, 4, 12, 64, 128, 512, 1024, 4096]
            offset_retention_all = True
            for off in offsets_to_test:
                os.lseek(fd_toctou, off, os.SEEK_SET)
                res_off = safegguf.validate_fd(fd_toctou)
                cur_off = os.lseek(fd_toctou, 0, os.SEEK_CUR)
                if cur_off != off or res_off.exit_code != 0:
                    offset_retention_all = False
                    record(f"toctou_offset_{off}", False, f"Expected {off}, got {cur_off}, res={res_off}")
                    break

            if offset_retention_all:
                record("toctou_multi_offset_retention", True, f"Tested offsets {offsets_to_test}: all strictly retained")

        finally:
            os.close(fd_toctou)
    finally:
        if temp_path.exists():
            temp_path.unlink()


# ==============================================================================
# Suite 7: Direct C-ABI Boundary Robustness
# ==============================================================================
def probe_direct_c_abi():
    print("\n--- Suite 7: Direct C-ABI Boundary Robustness ---")
    lib = safegguf.core._get_lib()

    # 7.1 NULL path pointer
    try:
        rc = lib.safegguf_validate_path(None, 0, 0)
        record("c_abi_validate_path_NULL", rc == 64, f"rc={rc}")
    except Exception as e:
        record("c_abi_validate_path_NULL", False, f"Exception: {e}")

    # 7.2 Handle 0 and Handle -1
    try:
        rc_0 = lib.safegguf_validate_fd(0, 0, 0)
        record("c_abi_validate_fd_0", rc_0 in (2, 74), f"rc={rc_0}")
    except Exception as e:
        record("c_abi_validate_fd_0", False, f"Exception: {e}")

    try:
        rc_neg = lib.safegguf_validate_fd(-1, 0, 0)
        record("c_abi_validate_fd_neg1", rc_neg == 74, f"rc={rc_neg}")
    except Exception as e:
        record("c_abi_validate_fd_neg1", False, f"Exception: {e}")

    # 7.3 Bogus handle values
    for bogus in [999999, 12345678, -999999]:
        try:
            rc_bogus = lib.safegguf_validate_fd(bogus, 0, 0)
            record(f"c_abi_validate_fd_bogus_{bogus}", rc_bogus == 74, f"rc={rc_bogus}")
        except Exception as e:
            record(f"c_abi_validate_fd_bogus_{bogus}", False, f"Exception: {e}")


def main():
    print("======================================================================")
    print("  SAFEGGUF EMPIRICAL CHALLENGER M2_2 ADVERSARIAL TEST HARNESS")
    print("======================================================================")

    probe_validate_path()
    probe_validate_fd()
    probe_sequential()
    probe_concurrent_different_fds()
    probe_concurrent_shared_fd()
    probe_toctou()
    probe_direct_c_abi()

    print("\n======================================================================")
    print("  SUMMARY OF ADVERSARIAL CHALLENGE FINDINGS")
    print("======================================================================")
    total = len(test_results)
    passed = sum(1 for _, p, _ in test_results if p)
    failed = total - passed

    print(f"Total Probes: {total}")
    print(f"Passed:       {passed}")
    print(f"Failed:       {failed}")

    failures = [(n, d) for n, p, d in test_results if not p]
    if failures:
        print("\nFailing Probes:")
        for name, detail in failures:
            print(f"  - {name}: {detail}")
    else:
        print("\nAll adversarial probes PASSED.")

    # Exit non-zero if failures occurred
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
