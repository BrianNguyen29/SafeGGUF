import os
import sys
import ctypes
from pathlib import Path

# Add bindings/python to sys.path
repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root / "bindings" / "python"))

import safegguf
from safegguf import Status, Profile, Endian

def main():
    print(f"Testing SafeGGUF Python Binding (Engine version: {safegguf.version()})...")
    assert safegguf.version().startswith("0.3."), f"Unexpected version: {safegguf.version()}"

    valid_file = repo_root / "tests" / "fixtures" / "valid.gguf"
    cve_file = repo_root / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"
    kv_dos_file = repo_root / "tests" / "fixtures" / "negative" / "synthetic-alloc-kv-count-dos.gguf"

    # 1. Path-based validation on valid fixture
    print("  1. Testing validate_path on valid model...")
    res_valid = safegguf.validate_path(str(valid_file), profile="gguf-spec")
    assert res_valid.is_valid is True, f"Expected valid model to pass, got: {res_valid}"
    assert res_valid.exit_code == 0, f"Expected exit code 0, got: {res_valid.exit_code}"
    assert res_valid.status == "PASS", f"Expected PASS status, got: {res_valid.status}"
    assert res_valid.error_code == "", f"Expected empty error_code on pass, got: {res_valid.error_code}"
    print("     [PASS] Valid model passed.")

    # 2. Path-based validation on CVE exploit fixture + structured diagnostics
    print("  2. Testing validate_path on exploit model with structured diagnostics...")
    res_cve = safegguf.validate_path(str(cve_file), profile="llama-cpp")
    assert res_cve.is_valid is False, f"Expected CVE exploit model to reject, got: {res_cve}"
    assert res_cve.exit_code == 2, f"Expected exit code 2, got: {res_cve.exit_code}"
    assert res_cve.status == "REJECT", f"Expected REJECT status, got: {res_cve.status}"
    assert res_cve.error_code == "ArithmeticOverflow", f"Expected ArithmeticOverflow, got {res_cve.error_code}"
    assert res_cve.category == "arithmetic", f"Expected arithmetic category, got {res_cve.category}"
    assert len(res_cve.message) > 0, f"Expected non-empty diagnostic message"
    print(f"     [PASS] Malformed/exploit model safely rejected (code={res_cve.error_code}, cat={res_cve.category}).")

    # 3. Path-based validation with None (Usage Error 64)
    print("  3. Testing validate_path(None) error handling...")
    res_none = safegguf.validate_path(None)
    assert res_none.is_valid is False, f"Expected None path to fail, got: {res_none}"
    assert res_none.exit_code == 64, f"Expected exit code 64 (USAGE_ERROR), got: {res_none.exit_code}"
    assert res_none.status == "USAGE_ERROR", f"Expected USAGE_ERROR status, got: {res_none.status}"
    assert res_none.category == "usage", f"Expected usage category, got {res_none.category}"
    print("     [PASS] validate_path(None) returned USAGE_ERROR (64).")

    # 4. Strict argument validation on invalid profile and endian
    print("  4. Testing strict argument validation on invalid profile / endian...")
    res_bad_prof = safegguf.validate_path(str(valid_file), profile="invalid_profile_name")
    assert res_bad_prof.exit_code == 64, f"Expected 64 on invalid profile, got {res_bad_prof.exit_code}"
    assert res_bad_prof.status == "USAGE_ERROR"

    res_bad_end = safegguf.validate_path(str(valid_file), endian="invalid_endian")
    assert res_bad_end.exit_code == 64, f"Expected 64 on invalid endian, got {res_bad_end.exit_code}"
    assert res_bad_end.status == "USAGE_ERROR"
    print("     [PASS] Invalid profile / endian rejected early with USAGE_ERROR (64).")

    # 5. Direct C-ABI call: strict enum validation (no silent fallback!)
    print("  5. Testing direct C-ABI strict enum validation (profile=99, endian=99)...")
    lib = safegguf.core._get_lib()
    rc_c_null = lib.safegguf_validate_path(None, 0, 0)
    assert rc_c_null == 64, f"Expected direct C NULL path to return 64, got {rc_c_null}"

    rc_bad_prof_c = lib.safegguf_validate_path(str(valid_file).encode("utf-8"), 99, 0)
    assert rc_bad_prof_c == 64, f"Expected invalid profile 99 to return 64, got {rc_bad_prof_c}"

    rc_bad_end_c = lib.safegguf_validate_path(str(valid_file).encode("utf-8"), 0, 99)
    assert rc_bad_end_c == 64, f"Expected invalid endian 99 to return 64, got {rc_bad_end_c}"
    print("     [PASS] C-ABI strict validation: invalid profile/endian strictly returns 64 without silent fallback.")

    # 6. Direct C-ABI v1 validation with options and structured result
    print("  6. Testing direct C-ABI safegguf_validate_path_v1 with structured result...")
    opts = safegguf.core.SafeggufOptionsV1(
        struct_size=ctypes.sizeof(safegguf.core.SafeggufOptionsV1),
        profile=1,
        endian=2,
        max_alloc_bytes=0,
        max_work_units=0,
        max_scanned_bytes=0,
        reserved=None,
    )
    result = safegguf.core.SafeggufResult()
    rc_v1 = lib.safegguf_validate_path_v1(str(cve_file).encode("utf-8"), ctypes.byref(opts), ctypes.byref(result))
    assert rc_v1 == 2, f"Expected rc 2, got {rc_v1}"
    assert result.exit_code == 2
    assert result.error_code.decode("utf-8") == "ArithmeticOverflow"
    assert result.category.decode("utf-8") == "arithmetic"
    print("     [PASS] safegguf_validate_path_v1 populated structured result.")

    # 7. File Descriptor validation on valid fixture
    print("  7. Testing validate_fd on valid model...")
    fd_valid = os.open(str(valid_file), os.O_RDONLY)
    try:
        res_fd = safegguf.validate_fd(fd_valid, profile="gguf-spec")
        assert res_fd.is_valid is True, f"Expected fd validation to pass, got: {res_fd}"
        assert res_fd.exit_code == 0, f"Expected exit code 0, got: {res_fd.exit_code}"
        assert res_fd.status == "PASS", f"Expected PASS status, got: {res_fd.status}"
    finally:
        os.close(fd_valid)
    print("     [PASS] File descriptor validation on valid model passed.")

    # 8. File Descriptor validation on exploit models (anti-TOCTOU exploit rejection)
    print("  8. Testing validate_fd on exploit models...")
    fd_cve = os.open(str(cve_file), os.O_RDONLY)
    try:
        res_cve_fd = safegguf.validate_fd(fd_cve, profile="llama-cpp")
        assert res_cve_fd.is_valid is False, f"Expected exploit fd to reject, got: {res_cve_fd}"
        assert res_cve_fd.exit_code == 2, f"Expected exit code 2, got: {res_cve_fd.exit_code}"
        assert res_cve_fd.status == "REJECT", f"Expected REJECT status, got: {res_cve_fd.status}"
        assert res_cve_fd.error_code == "ArithmeticOverflow"
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

    # 9. File Descriptor validation with invalid descriptors (-1, closed fd)
    print("  9. Testing validate_fd with invalid descriptors (-1, closed fd)...")
    res_neg_fd = safegguf.validate_fd(-1)
    assert res_neg_fd.exit_code == 74, f"Expected exit code 74 on fd=-1, got: {res_neg_fd.exit_code}"
    assert res_neg_fd.status == "IO_ERROR", f"Expected IO_ERROR status, got: {res_neg_fd.status}"

    fd_closed = os.open(str(valid_file), os.O_RDONLY)
    os.close(fd_closed)
    res_closed_fd = safegguf.validate_fd(fd_closed)
    assert res_closed_fd.exit_code == 74, f"Expected exit code 74 on closed fd, got: {res_closed_fd.exit_code}"
    assert res_closed_fd.status == "IO_ERROR", f"Expected IO_ERROR status, got: {res_closed_fd.status}"
    print("     [PASS] Invalid descriptors (-1, closed fd) cleanly returned IO_ERROR (74).")

    # 10. Direct C-ABI call with invalid handles (handle=0, handle=-1)
    print("  10. Testing direct C-ABI safegguf_validate_fd with handle 0 and -1...")
    rc_fd_zero = lib.safegguf_validate_fd(0, 0, 0)
    assert rc_fd_zero == 74, f"Expected direct C handle 0 to return 74, got {rc_fd_zero}"

    rc_fd_neg = lib.safegguf_validate_fd(-1, 0, 0)
    assert rc_fd_neg == 74, f"Expected direct C handle -1 to return 74, got {rc_fd_neg}"
    print("      [PASS] C-ABI handle 0 and -1 safely returned 74 without panic or crash.")

    # 11. Per-call resource limits override
    print("  11. Testing per-call resource limit override...")
    # Setting a strict memory limit (128 bytes) must fail with TotalAllocationLimitExceeded
    res_limit = safegguf.validate_path(str(valid_file), max_alloc_bytes=128)
    assert res_limit.exit_code == 2, f"Expected exit code 2 on resource limit exceeded, got: {res_limit.exit_code}"
    assert res_limit.category == "resource", f"Expected resource category, got: {res_limit.category}"
    assert res_limit.error_code == "TotalAllocationLimitExceeded", f"Expected TotalAllocationLimitExceeded, got: {res_limit.error_code}"
    print("      [PASS] Per-call resource limit override correctly triggered quota rejection.")

    # 12. TOCTOU Resistance Verification (fd remains open, readable, seek offset unchanged)
    print("  12. Testing TOCTOU Resistance (descriptor preserved, seek offset unmodified, readable)...")
    fd_toctou = os.open(str(valid_file), os.O_RDONLY)
    try:
        probe_offset = 12
        os.lseek(fd_toctou, probe_offset, os.SEEK_SET)
        before_offset = os.lseek(fd_toctou, 0, os.SEEK_CUR)
        assert before_offset == probe_offset, f"Precondition failed: offset is {before_offset}"

        res_toctou = safegguf.validate_fd(fd_toctou, profile="gguf-spec")
        assert res_toctou.is_valid is True, f"Validation failed: {res_toctou}"
        assert res_toctou.exit_code == 0, f"Expected exit code 0, got: {res_toctou.exit_code}"

        after_offset = os.lseek(fd_toctou, 0, os.SEEK_CUR)
        assert after_offset == before_offset, (
            f"TOCTOU violation: file offset was modified from {before_offset} to {after_offset}"
        )

        read_bytes = os.read(fd_toctou, 8)
        assert len(read_bytes) == 8, f"Descriptor damaged or unreadable: read {len(read_bytes)} bytes"
        new_offset = os.lseek(fd_toctou, 0, os.SEEK_CUR)
        assert new_offset == probe_offset + 8, f"Unexpected post-read offset: {new_offset}"
    finally:
        os.close(fd_toctou)
    print("      [PASS] TOCTOU resistance verified: fd unchanged, offset untouched, fully readable.")

    # 13. Non-existent file error handling
    print("  13. Testing non-existent file error handling...")
    res_missing = safegguf.validate_path("non_existent_file.gguf")
    assert res_missing.exit_code == 74, f"Expected exit code 74 (IO error), got: {res_missing.exit_code}"
    assert res_missing.status == "IO_ERROR", f"Expected IO_ERROR status, got: {res_missing.status}"
    print("      [PASS] Non-existent file handled cleanly with exit code 74.")

    print("\nAll Python binding tests passed successfully! (13/13 suites passed)")

if __name__ == "__main__":
    main()
