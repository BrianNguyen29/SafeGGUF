import os
import sys
from pathlib import Path

# Add bindings/python to sys.path
repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root / "bindings" / "python"))

import safegguf
from safegguf import Status, Profile, Endian

def main():
    print(f"Testing SafeGGUF Python Binding (Engine version: {safegguf.version()})...")
    assert safegguf.version() == "0.3.6", f"Unexpected version: {safegguf.version()}"

    valid_file = repo_root / "tests" / "fixtures" / "valid.gguf"
    cve_file = repo_root / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"
    kv_dos_file = repo_root / "tests" / "fixtures" / "negative" / "synthetic-alloc-kv-count-dos.gguf"

    # 1. Path-based validation on valid fixture
    print("  1. Testing validate_path on valid model...")
    res_valid = safegguf.validate_path(str(valid_file), profile="gguf-spec")
    assert res_valid.is_valid is True, f"Expected valid model to pass, got: {res_valid}"
    assert res_valid.exit_code == 0, f"Expected exit code 0, got: {res_valid.exit_code}"
    assert res_valid.status == "PASS", f"Expected PASS status, got: {res_valid.status}"
    print("     [PASS] Valid model passed.")

    # 2. Path-based validation on CVE exploit fixture
    print("  2. Testing validate_path on exploit model...")
    res_cve = safegguf.validate_path(str(cve_file), profile="llama-cpp")
    assert res_cve.is_valid is False, f"Expected CVE exploit model to reject, got: {res_cve}"
    assert res_cve.exit_code == 2, f"Expected exit code 2, got: {res_cve.exit_code}"
    assert res_cve.status == "REJECT", f"Expected REJECT status, got: {res_cve.status}"
    print("     [PASS] Malformed/exploit model safely rejected with exit code 2.")

    # 3. Path-based validation with None (Usage Error 64)
    print("  3. Testing validate_path(None) error handling...")
    res_none = safegguf.validate_path(None)
    assert res_none.is_valid is False, f"Expected None path to fail, got: {res_none}"
    assert res_none.exit_code == 64, f"Expected exit code 64 (USAGE_ERROR), got: {res_none.exit_code}"
    assert res_none.status == "USAGE_ERROR", f"Expected USAGE_ERROR status, got: {res_none.status}"
    print("     [PASS] validate_path(None) returned USAGE_ERROR (64).")

    # 4. Direct C-ABI call with NULL path pointer (Zero panic / Access Violation check)
    print("  4. Testing direct C-ABI safegguf_validate_path(NULL)...")
    lib = safegguf.core._get_lib()
    rc_c_null = lib.safegguf_validate_path(None, 0, 0)
    assert rc_c_null == 64, f"Expected direct C NULL path to return 64, got {rc_c_null}"
    print("     [PASS] C-ABI NULL path pointer safely returned 64 without crash.")

    # 5. File Descriptor validation on valid fixture
    print("  5. Testing validate_fd on valid model...")
    fd_valid = os.open(str(valid_file), os.O_RDONLY)
    try:
        res_fd = safegguf.validate_fd(fd_valid, profile="gguf-spec")
        assert res_fd.is_valid is True, f"Expected fd validation to pass, got: {res_fd}"
        assert res_fd.exit_code == 0, f"Expected exit code 0, got: {res_fd.exit_code}"
        assert res_fd.status == "PASS", f"Expected PASS status, got: {res_fd.status}"
    finally:
        os.close(fd_valid)
    print("     [PASS] File descriptor validation on valid model passed.")

    # 6. File Descriptor validation on exploit models (anti-TOCTOU exploit rejection)
    print("  6. Testing validate_fd on exploit models...")
    fd_cve = os.open(str(cve_file), os.O_RDONLY)
    try:
        res_cve_fd = safegguf.validate_fd(fd_cve, profile="llama-cpp")
        assert res_cve_fd.is_valid is False, f"Expected exploit fd to reject, got: {res_cve_fd}"
        assert res_cve_fd.exit_code == 2, f"Expected exit code 2, got: {res_cve_fd.exit_code}"
        assert res_cve_fd.status == "REJECT", f"Expected REJECT status, got: {res_cve_fd.status}"
    finally:
        os.close(fd_cve)

    if kv_dos_file.exists():
        fd_dos = os.open(str(kv_dos_file), os.O_RDONLY)
        try:
            res_dos_fd = safegguf.validate_fd(fd_dos, profile="llama-cpp")
            assert res_dos_fd.is_valid is False, f"Expected DOS fd to reject, got: {res_dos_fd}"
            assert res_dos_fd.exit_code == 2, f"Expected exit code 2, got: {res_dos_fd.exit_code}"
        finally:
            os.close(fd_dos)
    print("     [PASS] Exploit models safely rejected via file descriptor with exit code 2.")

    # 7. File Descriptor validation with invalid descriptors (-1, closed fd)
    print("  7. Testing validate_fd with invalid descriptors (-1, closed fd)...")
    res_neg_fd = safegguf.validate_fd(-1)
    assert res_neg_fd.exit_code == 74, f"Expected exit code 74 on fd=-1, got: {res_neg_fd.exit_code}"
    assert res_neg_fd.status == "IO_ERROR", f"Expected IO_ERROR status, got: {res_neg_fd.status}"

    # Closed descriptor test
    fd_closed = os.open(str(valid_file), os.O_RDONLY)
    os.close(fd_closed)
    res_closed_fd = safegguf.validate_fd(fd_closed)
    assert res_closed_fd.exit_code == 74, f"Expected exit code 74 on closed fd, got: {res_closed_fd.exit_code}"
    assert res_closed_fd.status == "IO_ERROR", f"Expected IO_ERROR status, got: {res_closed_fd.status}"
    print("     [PASS] Invalid descriptors (-1, closed fd) cleanly returned IO_ERROR (74).")

    # 8. Direct C-ABI call with invalid handles (handle=0, handle=-1)
    print("  8. Testing direct C-ABI safegguf_validate_fd with handle 0 and -1...")
    rc_fd_zero = lib.safegguf_validate_fd(0, 0, 0)
    assert rc_fd_zero == 74, f"Expected direct C handle 0 to return 74, got {rc_fd_zero}"

    rc_fd_neg = lib.safegguf_validate_fd(-1, 0, 0)
    assert rc_fd_neg == 74, f"Expected direct C handle -1 to return 74, got {rc_fd_neg}"
    print("     [PASS] C-ABI handle 0 and -1 safely returned 74 without panic or crash.")

    # 9. TOCTOU Resistance Verification (fd remains open, readable, seek offset unchanged)
    print("  9. Testing TOCTOU Resistance (descriptor preserved, seek offset unmodified, readable)...")
    fd_toctou = os.open(str(valid_file), os.O_RDONLY)
    try:
        # Set a non-zero seek position
        probe_offset = 12
        os.lseek(fd_toctou, probe_offset, os.SEEK_SET)
        before_offset = os.lseek(fd_toctou, 0, os.SEEK_CUR)
        assert before_offset == probe_offset, f"Precondition failed: offset is {before_offset}"

        # Perform validation on the open descriptor
        res_toctou = safegguf.validate_fd(fd_toctou, profile="gguf-spec")
        assert res_toctou.is_valid is True, f"Validation failed: {res_toctou}"
        assert res_toctou.exit_code == 0, f"Expected exit code 0, got: {res_toctou.exit_code}"

        # Assert seek offset is completely unchanged (preadAll used under the hood)
        after_offset = os.lseek(fd_toctou, 0, os.SEEK_CUR)
        assert after_offset == before_offset, (
            f"TOCTOU violation: file offset was modified from {before_offset} to {after_offset}"
        )

        # Assert descriptor is still open and readable
        read_bytes = os.read(fd_toctou, 8)
        assert len(read_bytes) == 8, f"Descriptor damaged or unreadable: read {len(read_bytes)} bytes"
        new_offset = os.lseek(fd_toctou, 0, os.SEEK_CUR)
        assert new_offset == probe_offset + 8, f"Unexpected post-read offset: {new_offset}"
    finally:
        os.close(fd_toctou)
    print("     [PASS] TOCTOU resistance verified: fd unchanged, offset untouched, fully readable.")

    # 10. Non-existent file error handling
    print("  10. Testing non-existent file error handling...")
    res_missing = safegguf.validate_path("non_existent_file.gguf")
    assert res_missing.exit_code == 74, f"Expected exit code 74 (IO error), got: {res_missing.exit_code}"
    assert res_missing.status == "IO_ERROR", f"Expected IO_ERROR status, got: {res_missing.status}"
    print("      [PASS] Non-existent file handled cleanly with exit code 74.")

    print("\nAll Python binding tests passed successfully! (10/10 suites passed)")

if __name__ == "__main__":
    main()
