import os
import sys
import ctypes
import ctypes.util
import tempfile
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

    # 14. Integer limit hardening: invalid values fail before any native call
    print("  14. Testing resource-limit and control validation (no ctypes wrapping)...")
    invalid_limits = [-1, -2, 2**64, 2**65, 2**200, True, False, 1.0, "128"]
    limit_params = (
        "max_alloc_bytes",
        "max_work_units",
        "max_scanned_bytes",
        "max_file_size_bytes",
    )
    invalid_flags = [-1, 2, 3, 2**64, 1.0, 0.0, "1", b"1", None, [], ()]

    for bad in invalid_limits:
        try:
            safegguf.core._parse_u64_limit("max_alloc_bytes", bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"_parse_u64_limit accepted invalid value: {bad!r}")

    for good in (0, 1, 128, 2**64 - 1):
        assert safegguf.core._parse_u64_limit("max_alloc_bytes", good) == good

    for bad in invalid_flags:
        try:
            safegguf.core._parse_flag("require_stable_file", bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"_parse_flag accepted invalid value: {bad!r}")

    for good in (True, False, 0, 1):
        assert safegguf.core._parse_flag("require_stable_file", good) == int(good)

    native_calls = []
    original_get_lib = safegguf.core._get_lib

    def _spy_get_lib():
        native_calls.append(True)
        return original_get_lib()

    safegguf.core._get_lib = _spy_get_lib
    try:
        for bad in invalid_limits:
            for param in limit_params:
                res_bad = safegguf.validate_path(str(valid_file), **{param: bad})
                assert res_bad.exit_code == 64, (
                    f"Expected 64 for {param}={bad!r}, got {res_bad.exit_code}"
                )
                assert res_bad.status == "USAGE_ERROR", f"Expected USAGE_ERROR for {param}={bad!r}"
                assert res_bad.category == "usage", f"Expected usage category for {param}={bad!r}"
                assert res_bad.error_code == "E_USAGE_INVALID_LIMIT", (
                    f"Expected E_USAGE_INVALID_LIMIT for {param}={bad!r}, got {res_bad.error_code}"
                )
                assert param in res_bad.message, (
                    f"Diagnostic message should name {param}: {res_bad.message!r}"
                )

        for bad in invalid_flags:
            res_bad_flag = safegguf.validate_path(str(valid_file), require_stable_file=bad)
            assert res_bad_flag.exit_code == 64, (
                f"Expected 64 for require_stable_file={bad!r}, got {res_bad_flag.exit_code}"
            )
            assert res_bad_flag.status == "USAGE_ERROR", f"Expected USAGE_ERROR for {bad!r}"
            assert res_bad_flag.category == "usage", f"Expected usage category for {bad!r}"
            assert res_bad_flag.error_code == "E_USAGE_INVALID_LIMIT", (
                f"Expected E_USAGE_INVALID_LIMIT for require_stable_file={bad!r}, "
                f"got {res_bad_flag.error_code}"
            )
            assert "require_stable_file" in res_bad_flag.message, (
                f"Diagnostic message should name require_stable_file: {res_bad_flag.message!r}"
            )

        fd_limits = os.open(str(valid_file), os.O_RDONLY)
        try:
            for bad in invalid_limits:
                for param in limit_params:
                    res_bad_fd = safegguf.validate_fd(fd_limits, **{param: bad})
                    assert res_bad_fd.exit_code == 64, (
                        f"Expected 64 for validate_fd {param}={bad!r}, got {res_bad_fd.exit_code}"
                    )
                    assert res_bad_fd.error_code == "E_USAGE_INVALID_LIMIT"
                    assert param in res_bad_fd.message

            for bad in invalid_flags:
                res_bad_fd_flag = safegguf.validate_fd(fd_limits, require_stable_file=bad)
                assert res_bad_fd_flag.exit_code == 64, (
                    f"Expected 64 for validate_fd require_stable_file={bad!r}, "
                    f"got {res_bad_fd_flag.exit_code}"
                )
                assert res_bad_fd_flag.error_code == "E_USAGE_INVALID_LIMIT"
        finally:
            os.close(fd_limits)
    finally:
        safegguf.core._get_lib = original_get_lib

    assert native_calls == [], (
        f"Native library invoked for invalid limits {native_calls!r}; validation must reject first"
    )

    # Boundary values are passed through unwrapped: UINT64_MAX is a valid
    # (permissive) quota, while a strict quota still reaches the engine.
    res_max_limit = safegguf.validate_path(str(valid_file), max_alloc_bytes=2**64 - 1)
    assert res_max_limit.exit_code == 0, f"Expected UINT64_MAX limit to be accepted, got {res_max_limit}"
    res_strict_limit = safegguf.validate_path(str(valid_file), max_alloc_bytes=128)
    assert res_strict_limit.error_code == "TotalAllocationLimitExceeded", (
        f"Expected strict limit to reach the engine, got {res_strict_limit}"
    )
    print("     [PASS] Invalid limits rejected pre-native; valid boundaries reach the engine unwrapped.")

    # 15. Native library discovery hardening: CWD must never be searched
    print("  15. Testing native library discovery hardening (no CWD search)...")
    genuine_lib = safegguf.core._find_library()

    def _is_under(path_value, root):
        try:
            return os.path.commonpath(
                [os.path.realpath(path_value), os.path.realpath(root)]
            ) == os.path.realpath(root)
        except ValueError:
            return False

    with tempfile.TemporaryDirectory(prefix="safegguf-cwd-hijack-") as tmp:
        attacker_root = Path(tmp)
        fake_lib_names = (
            "libsafegguf.so", "safegguf.so",
            "libsafegguf.dylib", "safegguf.dylib",
            "safegguf.dll", "libsafegguf.dll",
        )
        for sub in ("bin", "lib"):
            decoy_dir = attacker_root / "zig-out" / sub
            decoy_dir.mkdir(parents=True, exist_ok=True)
            for name in fake_lib_names:
                (decoy_dir / name).write_bytes(b"decoy: never load")

        original_env = os.environ.pop("SAFEGGUF_LIB_PATH", None)
        original_module_file = safegguf.core.__file__
        original_cwd = os.getcwd()
        os.chdir(attacker_root)
        # Simulate an installed package: package/source-tree candidates are
        # absent, so the only remaining discovery inputs are the CWD and the
        # admin-managed system paths.
        safegguf.core.__file__ = str(
            attacker_root / "elsewhere" / "bindings" / "python" / "safegguf" / "core.py"
        )
        try:
            hijacked = None
            try:
                hijacked = safegguf.core._find_library()
            except FileNotFoundError:
                pass
            if hijacked is not None and os.path.isabs(hijacked):
                assert not _is_under(hijacked, attacker_root), (
                    f"CWD library hijack: discovery returned attacker-controlled path {hijacked}"
                )

            attacker_decoy = attacker_root / "zig-out" / "lib" / fake_lib_names[0]
            bad_env_values = [
                str(attacker_decoy.relative_to(attacker_root)),      # relative decoy
                str(attacker_root / "zig-out" / "lib"),              # directory
                str(attacker_root / "missing" / attacker_decoy.name),  # missing file
            ]
            for bad_env in bad_env_values:
                os.environ["SAFEGGUF_LIB_PATH"] = bad_env
                try:
                    safegguf.core._find_library()
                except FileNotFoundError:
                    pass
                else:
                    raise AssertionError(f"Invalid SAFEGGUF_LIB_PATH was accepted: {bad_env!r}")

            # A valid absolute explicit path still works and wins over the CWD.
            if os.path.isabs(genuine_lib):
                os.environ["SAFEGGUF_LIB_PATH"] = genuine_lib
                assert os.path.realpath(safegguf.core._find_library()) == os.path.realpath(genuine_lib)

            # The system install path still works, resolved without CWD search.
            os.environ.pop("SAFEGGUF_LIB_PATH", None)
            original_find_library = ctypes.util.find_library
            ctypes.util.find_library = (
                lambda name: genuine_lib
                if name in ("safegguf", "safegguf.dll", "libsafegguf.dll")
                else None
            )
            try:
                system_lib = safegguf.core._find_library()
                assert os.path.realpath(system_lib) == os.path.realpath(genuine_lib), (
                    f"System discovery returned unexpected path: {system_lib}"
                )
            finally:
                ctypes.util.find_library = original_find_library
        finally:
            safegguf.core.__file__ = original_module_file
            os.chdir(original_cwd)
            if original_env is not None:
                os.environ["SAFEGGUF_LIB_PATH"] = original_env
            else:
                os.environ.pop("SAFEGGUF_LIB_PATH", None)

    assert os.path.realpath(safegguf.core._find_library()) == os.path.realpath(genuine_lib), (
        "Discovery did not return to the genuine library after the adversarial run"
    )
    print("     [PASS] CWD decoys never loaded; explicit/system discovery still works.")

    # 16. Extended control: inclusive max_file_size_bytes admission ceiling
    print("  16. Testing max_file_size_bytes admission ceiling (path + fd)...")
    valid_size = os.path.getsize(valid_file)
    assert valid_size > 1, f"Fixture too small for boundary tests: {valid_size} bytes"

    res_unlimited = safegguf.validate_path(
        str(valid_file), profile="gguf-spec", max_file_size_bytes=0
    )
    assert res_unlimited.is_valid is True, (
        f"max_file_size_bytes=0 must keep the engine default, got {res_unlimited}"
    )

    res_exact = safegguf.validate_path(
        str(valid_file), profile="gguf-spec", max_file_size_bytes=valid_size
    )
    assert res_exact.is_valid is True, (
        f"Inclusive ceiling must admit a file exactly at the limit, got {res_exact}"
    )

    res_max = safegguf.validate_path(
        str(valid_file), profile="gguf-spec", max_file_size_bytes=2**64 - 1
    )
    assert res_max.is_valid is True, f"UINT64_MAX ceiling must admit the fixture, got {res_max}"

    res_under = safegguf.validate_path(
        str(valid_file), profile="gguf-spec", max_file_size_bytes=valid_size - 1
    )
    assert res_under.exit_code == 2, f"Ceiling below file size must REJECT, got {res_under}"
    assert res_under.status == "REJECT", f"Expected REJECT status, got {res_under.status}"
    assert res_under.error_code == "E_FileTooLarge", (
        f"Expected E_FileTooLarge, got {res_under.error_code}"
    )
    assert res_under.category == "resource", f"Expected resource category, got {res_under.category}"

    fd_admission = os.open(str(valid_file), os.O_RDONLY)
    try:
        res_fd_exact = safegguf.validate_fd(
            fd_admission, profile="gguf-spec", max_file_size_bytes=valid_size
        )
        assert res_fd_exact.is_valid is True, (
            f"fd inclusive ceiling must admit the file, got {res_fd_exact}"
        )

        res_fd_under = safegguf.validate_fd(
            fd_admission, profile="gguf-spec", max_file_size_bytes=valid_size - 1
        )
        assert res_fd_under.exit_code == 2, f"fd ceiling below file size must REJECT, got {res_fd_under}"
        assert res_fd_under.error_code == "E_FileTooLarge", (
            f"Expected E_FileTooLarge via fd, got {res_fd_under.error_code}"
        )
        assert res_fd_under.category == "resource"
    finally:
        os.close(fd_admission)
    print("     [PASS] Inclusive size ceiling enforced via path and fd; too-small ceilings reject with E_FileTooLarge.")

    # 17. Extended control: require_stable_file opt-in
    print("  17. Testing require_stable_file opt-in (bool / int 0/1)...")
    for flag in (True, 1):
        res_stable = safegguf.validate_path(
            str(valid_file), profile="gguf-spec", require_stable_file=flag
        )
        assert res_stable.is_valid is True, (
            f"Stable file must pass with require_stable_file={flag!r}, got {res_stable}"
        )

    for flag in (False, 0):
        res_off = safegguf.validate_path(
            str(valid_file), profile="gguf-spec", require_stable_file=flag
        )
        assert res_off.is_valid is True, f"Stability off must pass, got {res_off}"

    fd_stable = os.open(str(valid_file), os.O_RDONLY)
    try:
        res_fd_stable = safegguf.validate_fd(
            fd_stable, profile="gguf-spec", require_stable_file=True
        )
        assert res_fd_stable.is_valid is True, f"fd stable validation must pass, got {res_fd_stable}"
    finally:
        os.close(fd_stable)

    res_combined = safegguf.validate_path(
        str(valid_file),
        profile="gguf-spec",
        max_file_size_bytes=valid_size,
        require_stable_file=True,
    )
    assert res_combined.is_valid is True, (
        f"Combined controls must pass on the valid fixture, got {res_combined}"
    )
    print("     [PASS] require_stable_file accepts bool/0/1, validates a stable file, and composes with the ceiling.")

    # 18. Legacy native library: runtime detection and fail-closed controls
    print("  18. Testing runtime extended-ABI detection and legacy-library fail-closed behavior...")
    assert safegguf.core._native_supports_extended_options(lib) is True, (
        "Loaded native library does not expose the extended v1 options layout; rebuild the v1.1 C ABI"
    )

    original_supports_extended = safegguf.core._native_supports_extended_options
    safegguf.core._native_supports_extended_options = lambda _lib: False
    try:
        # Without appended controls the v1.0 struct_size keeps a legacy library usable.
        res_legacy_plain = safegguf.validate_path(str(valid_file), profile="gguf-spec")
        assert res_legacy_plain.is_valid is True, (
            f"Legacy-layout call without controls must still pass, got {res_legacy_plain}"
        )

        fd_legacy_plain = os.open(str(valid_file), os.O_RDONLY)
        try:
            res_legacy_fd_plain = safegguf.validate_fd(fd_legacy_plain, profile="gguf-spec")
            assert res_legacy_fd_plain.is_valid is True, (
                f"Legacy-layout fd call without controls must still pass, got {res_legacy_fd_plain}"
            )
        finally:
            os.close(fd_legacy_plain)

        legacy_requests = (
            {"max_file_size_bytes": valid_size},
            {"require_stable_file": True},
            {"max_file_size_bytes": 1, "require_stable_file": 1},
        )
        for kwargs in legacy_requests:
            res_legacy = safegguf.validate_path(str(valid_file), profile="gguf-spec", **kwargs)
            assert res_legacy.is_valid is False, (
                f"Set controls must never silently PASS on a legacy library: {kwargs!r} -> {res_legacy}"
            )
            assert res_legacy.exit_code == 64, (
                f"Expected USAGE_ERROR (64) for {kwargs!r} on a legacy library, "
                f"got {res_legacy.exit_code}"
            )
            assert res_legacy.status == "USAGE_ERROR", f"Expected USAGE_ERROR, got {res_legacy.status}"
            assert res_legacy.error_code == "E_USAGE_UNSUPPORTED_OPTIONS", (
                f"Expected E_USAGE_UNSUPPORTED_OPTIONS, got {res_legacy.error_code}"
            )
            assert res_legacy.category == "usage", f"Expected usage category, got {res_legacy.category}"
            assert res_legacy.stage == "options", f"Expected options stage, got {res_legacy.stage}"
            assert "legacy" in res_legacy.message, (
                f"Diagnostic must explain the legacy native library: {res_legacy.message!r}"
            )

        fd_legacy_controls = os.open(str(valid_file), os.O_RDONLY)
        try:
            res_legacy_fd = safegguf.validate_fd(
                fd_legacy_controls, profile="gguf-spec", max_file_size_bytes=valid_size
            )
            assert res_legacy_fd.exit_code == 64, (
                f"fd controls must fail closed on a legacy library, got {res_legacy_fd}"
            )
            assert res_legacy_fd.error_code == "E_USAGE_UNSUPPORTED_OPTIONS"
        finally:
            os.close(fd_legacy_controls)
    finally:
        safegguf.core._native_supports_extended_options = original_supports_extended

    # The cache was never invalidated, so the real library stays recognized.
    assert safegguf.core._native_supports_extended_options(lib) is True
    res_after_restore = safegguf.validate_path(
        str(valid_file),
        profile="gguf-spec",
        max_file_size_bytes=valid_size,
        require_stable_file=True,
    )
    assert res_after_restore.is_valid is True, (
        f"Controls must work after the legacy simulation, got {res_after_restore}"
    )
    print("     [PASS] Legacy libraries fail closed on set controls, no-control calls stay usable, detection restores.")

    print("\nAll Python binding tests passed successfully! (18/18 suites passed)")

if __name__ == "__main__":
    main()
