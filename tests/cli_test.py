import json
import os
import subprocess
import sys

BINARY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zig-out", "bin", "safegguf")
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

def run_cli(*args):
    cmd = [BINARY] + list(args)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    return proc.returncode, proc.stdout, proc.stderr

def test_positive():
    print("Running positive tests...")

    # 1. Valid file default
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"))
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout, f"Missing PASS: {stdout}"

    # 2. Valid file JSON (gguf-spec profile emits type_layout_source)
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"), "--format", "json")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    data = json.loads(stdout)
    assert data["status"] == "PASS"
    assert data["profile"] == "gguf-spec"
    assert "type_layout_source" in data
    assert data["type_layout_source"]["project"] == "ggml"
    assert data["type_layout_source"]["version"] == "0.23.0"
    assert data["checks"]["structural"] == "PASS"
    assert data["checks"]["arithmetic"] == "PASS"

    # 3. Valid file JSON under llama-cpp profile (emits compatibility_target)
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"), "--profile", "llama-cpp", "--format", "json")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    data_llama = json.loads(stdout)
    assert data_llama["status"] == "PASS"
    assert data_llama["profile"] == "llama-cpp"
    assert "compatibility_target" in data_llama
    assert data_llama["compatibility_target"]["project"] == "ggml"

    # 4. Gap file under gguf-spec
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "gap.gguf"), "--profile", "gguf-spec")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    # 5. Nested array under gguf-spec
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "nested_array.gguf"), "--profile", "gguf-spec")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    # 6. 64-byte name under gguf-spec
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "name_64.gguf"), "--profile", "gguf-spec")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    # 7. Version 2 under llama-cpp
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "version_2.gguf"), "--profile", "llama-cpp")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    # 9. Big-endian v3 under gguf-spec profile with --endian big
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "big_endian_v3.gguf"), "--endian", "big", "--profile", "gguf-spec")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    # 8. Scalar tensor (n_dims == 0) under both profiles
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "scalar.gguf"), "--profile", "llama-cpp")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "scalar.gguf"), "--profile", "gguf-spec")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    print("  ✓ All positive tests passed.")

def test_negative_validation():
    print("Running negative validation tests (must exit code 2)...")

    rejections = [
        # Boundary: zero dimension under both profiles
        (["inspect", os.path.join(FIXTURES, "zero_dimension.gguf")], "E_ZeroDimensionNotAllowed"),
        # Boundary: empty tensor name under both profiles
        (["inspect", os.path.join(FIXTURES, "empty_tensor_name.gguf")], "E_InvalidTensorName"),
        # P0 regression: contiguous offset addition overflow under llama-cpp
        (["inspect", os.path.join(FIXTURES, "llama_cpp_overflow.gguf"), "--profile", "llama-cpp"], "E_ArithmeticOverflow"),
        # P0 regression: truncated final tensor padding under llama-cpp (HIGH-01)
        (["inspect", os.path.join(FIXTURES, "truncated_final_padding.gguf"), "--profile", "llama-cpp"], "E_TensorOutOfBounds"),
        # Compatibility violation: non-native big-endian under llama-cpp
        (["inspect", os.path.join(FIXTURES, "big_endian_v3.gguf"), "--endian", "big", "--profile", "llama-cpp"], "E_CompatibilityViolation"),
        # Invalid alignment zero-padding
        (["inspect", os.path.join(FIXTURES, "nonzero_header_padding.gguf"), "--profile", "gguf-spec"], "E_InvalidAlignmentPadding"),
        (["inspect", os.path.join(FIXTURES, "nonzero_header_padding.gguf"), "--profile", "llama-cpp"], "E_InvalidAlignmentPadding"),
        # NVFP4 truncated file (regression)
        (["inspect", os.path.join(FIXTURES, "type40_truncated_false_pass.gguf")], "E_TensorOutOfBounds"),
        # Non-contiguous offset under llama-cpp
        (["inspect", os.path.join(FIXTURES, "gap.gguf"), "--profile", "llama-cpp"], "E_NonContiguousTensorOffset"),
        # Nested array under llama-cpp
        (["inspect", os.path.join(FIXTURES, "nested_array.gguf"), "--profile", "llama-cpp"], "E_NestedArrayNotSupported"),
        # 64-byte tensor name under llama-cpp
        (["inspect", os.path.join(FIXTURES, "name_64.gguf"), "--profile", "llama-cpp"], "E_TensorNameTooLong"),
        # Version 2 under gguf-spec
        (["inspect", os.path.join(FIXTURES, "version_2.gguf"), "--profile", "gguf-spec"], "E_UnsupportedVersion"),
        # Malformed files
        (["inspect", os.path.join(FIXTURES, "overflow.gguf")], "E_ArithmeticOverflow"),
        (["inspect", os.path.join(FIXTURES, "out_of_bounds.gguf")], "E_TensorOutOfBounds"),
        (["inspect", os.path.join(FIXTURES, "overlap.gguf")], "E_TensorOverlap"),
        (["inspect", os.path.join(FIXTURES, "duplicate_tensor.gguf")], "E_DuplicateTensorName"),
        (["inspect", os.path.join(FIXTURES, "duplicate_key.gguf")], "E_DuplicateMetadataKey"),
        (["inspect", os.path.join(FIXTURES, "invalid_key.gguf")], "E_InvalidKeyFormat"),
        (["inspect", os.path.join(FIXTURES, "hyphen_key.gguf")], "E_InvalidKeyFormat"),
        (["inspect", os.path.join(FIXTURES, "invalid_bool.gguf")], "E_InvalidBoolean"),
        (["inspect", os.path.join(FIXTURES, "removed_type_slot31.gguf")], "E_InvalidTensorType"),
        (["inspect", os.path.join(FIXTURES, "alloc_dos_tensor.gguf")], "E_UnexpectedEof"),
    ]

    for args, expected_err in rejections:
        rc, stdout, stderr = run_cli(*args)
        assert rc == 2, f"Expected returncode 2 (Validation REJECT) for {args}, got {rc}\nStdout: {stdout}\nStderr: {stderr}"
        assert expected_err in stderr, f"Expected error {expected_err} in stderr for {args}, got: {stderr}"

    print("  ✓ All negative validation tests passed with exit code 2.")

def test_negative_json():
    print("Running negative JSON formatting tests (must exit code 2 and emit valid JSON)...")

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "gap.gguf"), "--profile", "llama-cpp", "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data = json.loads(stdout)
    assert data["status"] == "REJECT"
    assert data["profile"] == "llama-cpp"
    assert data["error_code"] == "E_NonContiguousTensorOffset"
    assert len(data["findings"]) > 0
    assert data["findings"][0]["severity"] == "reject"

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "llama_cpp_overflow.gguf"), "--profile", "llama-cpp", "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data_ov = json.loads(stdout)
    assert data_ov["status"] == "REJECT"
    assert data_ov["error_code"] == "E_ArithmeticOverflow"

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "overflow.gguf"), "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data = json.loads(stdout)
    assert data["status"] == "REJECT"
    assert data["error_code"] == "E_ArithmeticOverflow"

    print("  ✓ All negative JSON tests passed.")

def test_usage_and_flags():
    print("Running usage and flag validation tests (must exit code 64)...")

    bad_invocations = [
        [],
        ["unknown_subcommand"],
        ["inspect"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--unknown-flag"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--profile", "invalid-profile"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--format", "yaml"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--endian", "middle"],
    ]

    for args in bad_invocations:
        rc, stdout, stderr = run_cli(*args)
        assert rc == 64, f"Expected returncode 64 (EX_USAGE) for {args}, got {rc}\nStdout: {stdout}\nStderr: {stderr}"

    print("  ✓ All usage tests passed with exit code 64.")

def test_io_error():
    print("Running IO error tests (must exit code 74)...")

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "non_existent_file.gguf"))
    assert rc == 74, f"Expected returncode 74 (EX_IOERR), got {rc}\nStdout: {stdout}\nStderr: {stderr}"

    print("  ✓ IO error tests passed with exit code 74.")

def test_help():
    print("Running CLI help contract tests (must exit code 0)...")
    for flag in ["--help", "-h", "help"]:
        rc, stdout, stderr = run_cli(flag)
        assert rc == 0, f"Expected returncode 0 for {flag}, got {rc}"
        output = stdout + stderr
        assert "SafeGGUF v0.3.2" in output, f"Version missing in help: {output}"
        assert "--profile <gguf-spec|llama-cpp>" in output, f"Accurate profile flag missing in help: {output}"
        assert "default: little" in output, f"Default little endian missing in help: {output}"
        assert "--format <text|json>" in output
    print("  ✓ All help contract tests passed with exit code 0.")

if __name__ == "__main__":
    if not os.path.exists(BINARY):
        print(f"Error: binary {BINARY} does not exist. Run zig build first.")
        sys.exit(1)

    test_positive()
    test_negative_validation()
    test_negative_json()
    test_usage_and_flags()
    test_io_error()
    test_help()
    print("\nAll CLI end-to-end integration tests PASSED successfully!")
