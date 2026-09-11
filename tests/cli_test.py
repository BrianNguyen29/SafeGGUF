import json
import os
import struct
import subprocess
import sys

BINARY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zig-out", "bin", "safegguf")
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# Pinned ggml provenance carried by every JSON output (PASS/REJECT/ERROR).
# Emitted as "compatibility_target" under --profile llama-cpp and as
# "type_layout_source" under gguf-spec.
GGML_PROVENANCE = {"project": "ggml", "version": "0.23.0", "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"}

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
    assert data["type_layout_source"] == GGML_PROVENANCE
    assert data["checks"]["structural"] == "PASS"
    assert data["checks"]["arithmetic"] == "PASS"

    # 3. Valid file JSON under llama-cpp profile (emits compatibility_target)
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"), "--profile", "llama-cpp", "--format", "json")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    data_llama = json.loads(stdout)
    assert data_llama["status"] == "PASS"
    assert data_llama["profile"] == "llama-cpp"
    assert "compatibility_target" in data_llama
    assert data_llama["compatibility_target"] == GGML_PROVENANCE

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

    # 10. Truncated header padding with zero tensors under llama-cpp profile (PASS like upstream)
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "truncated_header_padding_zero_tensors.gguf"), "--profile", "llama-cpp")
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
        # Truncated zero-tensor padding rejected under gguf-spec
        (["inspect", os.path.join(FIXTURES, "truncated_header_padding_zero_tensors.gguf"), "--profile", "gguf-spec"], "E_UnexpectedEof"),
        # Signed dimension overflow (> INT64_MAX) under llama-cpp
        (["inspect", os.path.join(FIXTURES, "signed_dim_overflow.gguf"), "--profile", "llama-cpp"], "E_CompatibilityViolation"),
        # Element product overflow (>= INT64_MAX) under llama-cpp
        (["inspect", os.path.join(FIXTURES, "element_product_overflow.gguf"), "--profile", "llama-cpp"], "E_CompatibilityViolation"),
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
    # Provenance accompanies REJECT JSON (llama-cpp profile field name).
    assert data["compatibility_target"] == GGML_PROVENANCE
    assert len(data["findings"]) > 0
    assert data["findings"][0]["severity"] == "reject"

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "llama_cpp_overflow.gguf"), "--profile", "llama-cpp", "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data_ov = json.loads(stdout)
    assert data_ov["status"] == "REJECT"
    assert data_ov["error_code"] == "E_ArithmeticOverflow"
    assert data_ov["compatibility_target"] == GGML_PROVENANCE

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "overflow.gguf"), "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data = json.loads(stdout)
    assert data["status"] == "REJECT"
    assert data["error_code"] == "E_ArithmeticOverflow"
    # Provenance accompanies REJECT JSON (gguf-spec profile field name).
    assert data["type_layout_source"] == GGML_PROVENANCE

    print("  ✓ All negative JSON tests passed.")

def test_rich_rejection_context():
    print("Running rich rejection context tests (slice 11 findings)...")

    # Canonical: non-contiguous tensor offset under llama-cpp (JSON) carries
    # category, stage, tensor identity, and actual vs expected offset.
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "gap.gguf"), "--profile", "llama-cpp", "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data = json.loads(stdout)
    assert data["status"] == "REJECT"
    assert data["error_code"] == "E_NonContiguousTensorOffset"
    assert data["category"] == "compatibility"
    assert data["stage"] == "structural"
    assert data["tensor_index"] == 1
    assert data["tensor"] == "t1"
    assert data["offset"] == 256
    assert data["expected_offset"] == 128
    f0 = data["findings"][0]
    assert f0["code"] == "E_NonContiguousTensorOffset"
    assert f0["severity"] == "reject"
    assert f0["message"] == "Tensor offsets are not strictly contiguous (llama.cpp layout)"
    assert f0["message"] != "Validator rejected untrusted GGUF stream"
    assert f0["category"] == "compatibility"
    assert f0["stage"] == "structural"
    assert f0["tensor_index"] == 1
    assert f0["tensor"] == "t1"
    assert f0["offset"] == 256
    assert f0["expected_offset"] == 128
    assert "Validator rejected untrusted GGUF stream" not in stdout

    # Parse-stage finding carries the offending metadata key (JSON).
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "invalid_key.gguf"), "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data = json.loads(stdout)
    assert data["error_code"] == "E_InvalidKeyFormat"
    assert data["category"] == "format"
    assert data["stage"] == "parse"
    assert data["key"] == "InvalidKeyWithUppercase"
    assert data["findings"][0]["key"] == "InvalidKeyWithUppercase"

    # Arithmetic category is surfaced for checked-arithmetic rejections (JSON).
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "overflow.gguf"), "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data = json.loads(stdout)
    assert data["error_code"] == "E_ArithmeticOverflow"
    assert data["category"] == "arithmetic"

    # Text emission carries the same context for the canonical case.
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "gap.gguf"), "--profile", "llama-cpp")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    assert "E_NonContiguousTensorOffset" in stderr
    assert "stage: structural" in stderr
    assert "category: compatibility" in stderr
    assert "tensor_index: 1" in stderr
    assert "tensor: t1" in stderr
    assert "offset: 256" in stderr
    assert "expected_offset: 128" in stderr
    assert "Validator rejected untrusted GGUF stream" not in stderr

    print("  ✓ All rich rejection context tests passed.")

def write_variable_array_fixture(path, count):
    """Writes a minimal metadata-only GGUF v3 whose single metadata entry is
    `tokenizer.ggml.tokens: array[string]` with `count` ASCII tokens."""
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)  # version
    b += struct.pack("<Q", 0)  # tensor_count
    b += struct.pack("<Q", 1)  # metadata_kv_count

    key = b"tokenizer.ggml.tokens"
    b += struct.pack("<Q", len(key))
    b += key
    b += struct.pack("<I", 9)  # MetadataType.array
    b += struct.pack("<I", 8)  # MetadataType.string
    b += struct.pack("<Q", count)
    for i in range(count):
        token = ("tok%d" % i).encode("ascii")
        b += struct.pack("<Q", len(token))
        b += token

    pad = (32 - (len(b) % 32)) % 32
    b += b"\x00" * pad
    with open(path, "wb") as f:
        f.write(b)

def test_variable_array_cap_override():
    print("Running variable-array cap override tests (F-01 flag contract)...")

    fixture_path = os.path.join(FIXTURES, "variable_array_11.gguf")

    try:
        write_variable_array_fixture(fixture_path, 11)

        # 1. Default cap (1,000,000) admits the fixture.
        rc, stdout, stderr = run_cli("inspect", fixture_path)
        assert rc == 0, f"Expected 0, got {rc}: {stderr}"
        assert "Result: PASS" in stdout, f"Missing PASS: {stdout}"

        # 2. Override at the exact element count still admits it.
        rc, stdout, stderr = run_cli("inspect", fixture_path, "--max-variable-array-elements", "11")
        assert rc == 0, f"Expected 0, got {rc}: {stderr}"
        assert "Result: PASS" in stdout, f"Missing PASS: {stdout}"

        # 3. Override below the element count rejects as a local policy/resource
        #    limit (exit 2), distinct from a format rejection.
        rc, stdout, stderr = run_cli("inspect", fixture_path, "--max-variable-array-elements", "10", "--format", "json")
        assert rc == 2, f"Expected 2, got {rc}: {stdout} {stderr}"
        data = json.loads(stdout)
        assert data["status"] == "REJECT"
        assert data["error_code"] == "E_ResourceLimitExceeded"
        assert data["category"] == "resource"
        assert data["findings"][0]["code"] == "E_ResourceLimitExceeded"

        # 4. Text output mirrors the same code.
        rc, stdout, stderr = run_cli("inspect", fixture_path, "--max-variable-array-elements", "10")
        assert rc == 2, f"Expected 2, got {rc}: {stdout} {stderr}"
        assert "E_ResourceLimitExceeded" in stderr, f"Missing resource error: {stderr}"

        print("  ✓ Variable-array cap override tests passed.")
    finally:
        # This scratch fixture is not registered in differential.py's
        # EXPECTED_MATRIX; remove it so later fixture sweeps stay clean.
        if os.path.exists(fixture_path):
            os.remove(fixture_path)

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
        # F-01: --max-variable-array-elements fail-closed value contract
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "0"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "-1"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "abc"],
        # u64 max + 1 (parse overflow) and one above the generic 10M array cap
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "18446744073709551616"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "10000001"],
    ]

    for args in bad_invocations:
        rc, stdout, stderr = run_cli(*args)
        assert rc == 64, f"Expected returncode 64 (EX_USAGE) for {args}, got {rc}\nStdout: {stdout}\nStderr: {stderr}"

    print("  ✓ All usage tests passed with exit code 64.")

def test_io_error():
    print("Running IO error tests (must exit code 74)...")

    # 1. Plain text IO error
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "non_existent_file.gguf"))
    assert rc == 74, f"Expected returncode 74 (EX_IOERR), got {rc}\nStdout: {stdout}\nStderr: {stderr}"

    # 2. JSON formatted IO error: status must be ERROR (not REJECT)
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "non_existent_file.gguf"), "--format", "json")
    assert rc == 74, f"Expected returncode 74 (EX_IOERR), got {rc}\nStdout: {stdout}\nStderr: {stderr}"
    data = json.loads(stdout)
    assert data["status"] == "ERROR", f"Expected status ERROR, got {data['status']}"
    assert data["error_code"] == "E_FILE_OPEN_FAILED"
    # Provenance accompanies ERROR JSON too (default gguf-spec profile).
    assert data["type_layout_source"] == GGML_PROVENANCE

    print("  ✓ IO error tests passed with exit code 74 and status ERROR.")

def test_help():
    print("Running CLI help contract tests (must exit code 0)...")
    for flag in ["--help", "-h", "help"]:
        rc, stdout, stderr = run_cli(flag)
        assert rc == 0, f"Expected returncode 0 for {flag}, got {rc}"
        output = stdout + stderr
        assert "SafeGGUF v0.3.5" in output, f"Version missing in help: {output}"
        assert "--profile <gguf-spec|llama-cpp>" in output, f"Accurate profile flag missing in help: {output}"
        assert "default: little" in output, f"Default little endian missing in help: {output}"
        assert "--format <text|json>" in output
        assert "--max-variable-array-elements <N>" in output, f"Variable-array cap flag missing in help: {output}"
        assert "default: 1000000" in output, f"Variable-array cap default missing in help: {output}"
    print("  ✓ All help contract tests passed with exit code 0.")

if __name__ == "__main__":
    if not os.path.exists(BINARY):
        print(f"Error: binary {BINARY} does not exist. Run zig build first.")
        sys.exit(1)

    test_positive()
    test_negative_validation()
    test_negative_json()
    test_rich_rejection_context()
    test_variable_array_cap_override()
    test_usage_and_flags()
    test_io_error()
    test_help()
    print("\nAll CLI end-to-end integration tests PASSED successfully!")
