"""
Forensic Adversarial Audit Harness for SafeGGUF C-ABI and Python Bindings (M2).
Designed by Forensic Auditor M2 to stress-test boundary invariants, memory safety,
and anti-tampering behaviors without relying on worker-authored harnesses.
"""

import sys
import os
import ctypes
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "bindings" / "python"))

import safegguf
from safegguf import Status, Profile, Endian, core

def run_c_abi_direct_tests(dll_path: str):
    print(f"\n[+] Probing raw C-ABI DLL directly: {dll_path}")
    lib = ctypes.CDLL(dll_path)

    # Function signatures
    lib.safegguf_version.restype = ctypes.c_char_p
    lib.safegguf_validate_path.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    lib.safegguf_validate_path.restype = ctypes.c_int
    lib.safegguf_validate_fd.argtypes = [ctypes.c_ssize_t, ctypes.c_int, ctypes.c_int]
    lib.safegguf_validate_fd.restype = ctypes.c_int

    # 1. Version check
    ver = lib.safegguf_version().decode("utf-8")
    print(f"    Version returned: {ver}")
    assert ver == "0.3.6", f"Expected version 0.3.6, got {ver}"

    # 2. safegguf_validate_path NULL checks
    print("    [Test 1] Passing NULL pointer to safegguf_validate_path...")
    rc_null = lib.safegguf_validate_path(None, 0, 0)
    print(f"             Result: {rc_null}")
    assert rc_null == 64, f"Expected 64 for NULL path, got {rc_null}"

    print("    [Test 2] Passing empty string to safegguf_validate_path...")
    rc_empty = lib.safegguf_validate_path(b"", 0, 0)
    print(f"             Result: {rc_empty}")
    assert rc_empty == 74, f"Expected 74 (IO error) for empty path, got {rc_empty}"

    print("    [Test 3] Passing non-existent file to safegguf_validate_path...")
    rc_nonexist = lib.safegguf_validate_path(b"this_file_definitely_does_not_exist_12345.gguf", 0, 0)
    print(f"             Result: {rc_nonexist}")
    assert rc_nonexist == 74, f"Expected 74 for missing file, got {rc_nonexist}"

    print("    [Test 4] Passing massive string (5000 chars) to safegguf_validate_path...")
    long_path = (b"a" * 5000) + b".gguf"
    rc_long = lib.safegguf_validate_path(long_path, 0, 0)
    print(f"             Result: {rc_long}")
    assert rc_long == 74, f"Expected 74 for overflowing path, got {rc_long}"

    # 3. safegguf_validate_fd Handle Safety
    print("    [Test 5] Direct handle 0 to safegguf_validate_fd (Windows null handle check)...")
    rc_zero = lib.safegguf_validate_fd(0, 0, 0)
    print(f"             Result: {rc_zero}")
    assert rc_zero == 74, f"Expected 74 for handle 0, got {rc_zero}"

    print("    [Test 6] Direct negative handles (-1, -100, -999999)...")
    for neg in [-1, -100, -999999]:
        rc_neg = lib.safegguf_validate_fd(neg, 0, 0)
        assert rc_neg == 74, f"Expected 74 for handle {neg}, got {rc_neg}"
    print("             Negative handles all safely returned 74.")

    print("    [Test 7] Direct invalid pseudo-handles (e.g. 0xDEADBEEF)...")
    rc_bogus = lib.safegguf_validate_fd(0x7FFFFFF0, 0, 0)
    print(f"             Result: {rc_bogus}")
    assert rc_bogus == 74, f"Expected 74 for bogus handle, got {rc_bogus}"

    # 4. Valid and Exploit models through C-ABI
    valid_file = REPO_ROOT / "tests" / "fixtures" / "valid.gguf"
    cve_file = REPO_ROOT / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"

    print("    [Test 8] Direct C-ABI validate valid model...")
    rc_v = lib.safegguf_validate_path(str(valid_file).encode("utf-8"), 0, 0)
    assert rc_v == 0, f"Expected 0 for valid model, got {rc_v}"
    print("             Valid model passed (0).")

    print("    [Test 9] Direct C-ABI validate CVE exploit model...")
    rc_cve = lib.safegguf_validate_path(str(cve_file).encode("utf-8"), 1, 0)
    assert rc_cve == 2, f"Expected 2 for CVE exploit, got {rc_cve}"
    print("             CVE exploit safely rejected (2).")

    print("    [Test 10] Direct C-ABI validate_fd with valid file and seek state test...")
    fd = os.open(str(valid_file), os.O_RDONLY)
    try:
        if sys.platform == "win32":
            import msvcrt
            handle = msvcrt.get_osfhandle(fd)
        else:
            handle = fd
        os.lseek(fd, 25, os.SEEK_SET)
        assert os.lseek(fd, 0, os.SEEK_CUR) == 25
        rc_fd_v = lib.safegguf_validate_fd(handle, 0, 0)
        assert rc_fd_v == 0, f"Expected 0 for valid fd, got {rc_fd_v}"
        assert os.lseek(fd, 0, os.SEEK_CUR) == 25, "Offset changed by C-ABI call!"
        data = os.read(fd, 4)
        assert len(data) == 4, "Unable to read after validate_fd!"
    finally:
        os.close(fd)
    print("             C-ABI validate_fd seek offset preserved at 25 and file remains readable.")


def run_python_wrapper_adversarial_tests():
    print("\n[+] Probing Python Binding API safegguf wrapper...")

    # 1. validate_path edge cases
    print("    [PyTest 1] validate_path(None)...")
    res = safegguf.validate_path(None)
    assert res.exit_code == 64
    assert res.status == "USAGE_ERROR"
    assert not res
    print("               Passed.")

    print("    [PyTest 2] validate_path with Path object...")
    valid_file = REPO_ROOT / "tests" / "fixtures" / "valid.gguf"
    res = safegguf.validate_path(valid_file)
    assert res.exit_code == 0
    assert bool(res) is True
    print("               Passed.")

    # 2. validate_fd edge cases
    print("    [PyTest 3] validate_fd(-1)...")
    res = safegguf.validate_fd(-1)
    assert res.exit_code == 74
    assert res.status == "IO_ERROR"
    print("               Passed.")

    print("    [PyTest 4] validate_fd with closed descriptor...")
    fd = os.open(str(valid_file), os.O_RDONLY)
    os.close(fd)
    res = safegguf.validate_fd(fd)
    assert res.exit_code == 74
    assert res.status == "IO_ERROR"
    print("               Passed.")

    print("    [PyTest 5] validate_fd invalid types (None, 'foo', 3.14)...")
    for bad_val in [None, "invalid_fd", 3.14]:
        try:
            res = safegguf.validate_fd(bad_val)
            assert res.exit_code == 74
            assert res.status == "IO_ERROR"
        except Exception as e:
            raise AssertionError(f"Unexpected exception for {bad_val}: {e}")
    print("               All invalid types gracefully returned IO_ERROR (74).")

    print("    [PyTest 6] Multi-turn TOCTOU simulation with interleaved reads and seeks...")
    fd = os.open(str(valid_file), os.O_RDONLY)
    try:
        # Seek to 42
        os.lseek(fd, 42, os.SEEK_SET)
        r1 = safegguf.validate_fd(fd)
        assert r1.exit_code == 0
        assert os.lseek(fd, 0, os.SEEK_CUR) == 42

        # Read 10 bytes -> pos 52
        b1 = os.read(fd, 10)
        assert len(b1) == 10
        assert os.lseek(fd, 0, os.SEEK_CUR) == 52

        # Re-validate
        r2 = safegguf.validate_fd(fd)
        assert r2.exit_code == 0
        assert os.lseek(fd, 0, os.SEEK_CUR) == 52

        # Read 10 more bytes -> pos 62
        b2 = os.read(fd, 10)
        assert len(b2) == 10
        assert os.lseek(fd, 0, os.SEEK_CUR) == 62
    finally:
        os.close(fd)
    print("               Multi-turn TOCTOU simulation passed.")


def run_negative_corpus_through_cabi():
    print("\n[+] Probing full negative corpus through C-ABI...")
    neg_dir = REPO_ROOT / "tests" / "fixtures" / "negative"
    fixtures = list(neg_dir.glob("*.gguf"))
    print(f"    Found {len(fixtures)} negative fixtures to test via C-ABI.")
    assert len(fixtures) >= 15, f"Expected at least 15 negative fixtures, found {len(fixtures)}"

    for f in fixtures:
        res = safegguf.validate_path(f, profile="gguf-spec")
        assert res.exit_code == 2, f"Fixture {f.name} did NOT reject! Exit code: {res.exit_code}"
    print(f"    All {len(fixtures)} negative fixtures strictly rejected with exit code 2.")


def main():
    print("=== STARTING INDEPENDENT FORENSIC C-ABI AUDIT ===")
    dll_path = core._find_library()
    run_c_abi_direct_tests(dll_path)
    run_python_wrapper_adversarial_tests()
    run_negative_corpus_through_cabi()
    print("\n=== ALL FORENSIC AUDIT CHECKS PASSED WITH ZERO VIOLATIONS ===")

if __name__ == "__main__":
    main()
