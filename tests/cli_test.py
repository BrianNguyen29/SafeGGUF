import json
import os
import struct
import subprocess
import sys
from pathlib import Path

BINARY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zig-out", "bin", "safegguf")
if sys.platform == "win32" and not BINARY.endswith(".exe") and os.path.exists(BINARY + ".exe"):
    BINARY += ".exe"
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SOURCE_VERSION = (Path(__file__).resolve().parents[1] / "VERSION").read_text().strip()

# Pinned ggml provenance carried by every JSON output (PASS/REJECT/ERROR).
# Emitted as "compatibility_target" under --profile llama-cpp and as
# "type_layout_source" under gguf-spec.
GGML_PROVENANCE = {"project": "ggml", "version": "0.23.0", "commit": "e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"}

def run_cli(*args, env=None):
    cmd = [BINARY] + list(args)
    full_env = None
    if env is not None:
        full_env = os.environ.copy()
        full_env.update(env)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10, env=full_env)
    return proc.returncode, proc.stdout, proc.stderr

def test_positive():
    print("Running positive tests...")

    # 1. Valid file default
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"))
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    assert "Result: PASS" in stdout, f"Missing PASS: {stdout}"

    # 2. Valid file JSON (default profile: llama-cpp emits compatibility_target)
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"), "--format", "json")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    data = json.loads(stdout)
    assert data["status"] == "PASS"
    assert data["profile"] == "llama-cpp"
    assert "compatibility_target" in data
    assert data["compatibility_target"] == GGML_PROVENANCE
    assert data["checks"]["structural"] == "PASS"
    assert data["checks"]["arithmetic"] == "PASS"

    # 2b. Valid file JSON under gguf-spec profile (emits type_layout_source)
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"), "--profile", "gguf-spec", "--format", "json")
    assert rc == 0, f"Expected 0, got {rc}: {stderr}"
    data_spec = json.loads(stdout)
    assert data_spec["status"] == "PASS"
    assert data_spec["profile"] == "gguf-spec"
    assert data_spec["type_layout_source"] == GGML_PROVENANCE

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

    print("  [ok] All positive tests passed.")

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
        # Malformed files (default profile is llama-cpp; contiguity checks run first)
        (["inspect", os.path.join(FIXTURES, "overflow.gguf")], "E_CompatibilityViolation"),
        (["inspect", os.path.join(FIXTURES, "out_of_bounds.gguf")], "E_NonContiguousTensorOffset"),
        (["inspect", os.path.join(FIXTURES, "overlap.gguf")], "E_NonContiguousTensorOffset"),
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

    print("  [ok] All negative validation tests passed with exit code 2.")

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

    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "overflow.gguf"), "--profile", "gguf-spec", "--format", "json")
    assert rc == 2, f"Expected returncode 2, got {rc}"
    data = json.loads(stdout)
    assert data["status"] == "REJECT"
    assert data["error_code"] == "E_ArithmeticOverflow"
    # Provenance accompanies REJECT JSON (gguf-spec profile field name).
    assert data["type_layout_source"] == GGML_PROVENANCE

    print("  [ok] All negative JSON tests passed.")

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
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "overflow.gguf"), "--profile", "gguf-spec", "--format", "json")
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

    print("  [ok] All rich rejection context tests passed.")

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

        print("  [ok] Variable-array cap override tests passed.")
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
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--endian"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--endian", "middle"],
        # F-01: --max-variable-array-elements fail-closed value contract
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "0"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "-1"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "abc"],
        # u64 max + 1 (parse overflow) and one above the generic 10M array cap
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "18446744073709551616"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-variable-array-elements", "10000001"],
        # Resource limit flags validation
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-memory-mb"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-memory-mb", "0"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-memory-mb", "-1"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-memory-mb", "abc"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-memory-mb", "17592186044416"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-memory-mb", "18446744073709551615"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-memory-mb", "18446744073709551616"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-work-budget"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-work-budget", "0"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-work-budget", "-1"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-work-budget", "abc"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-work-budget", "18446744073709551616"],
        # P0-1 relief-flag value contracts (defaults stay fail-closed)
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-string-bytes"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-string-bytes", "0"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-string-bytes", "-1"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-string-bytes", "abc"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--max-string-bytes", "18446744073709551616"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--key-policy"],
        ["inspect", os.path.join(FIXTURES, "valid.gguf"), "--key-policy", "bogus"],
    ]

    for args in bad_invocations:
        rc, stdout, stderr = run_cli(*args)
        assert rc == 64, f"Expected returncode 64 (EX_USAGE) for {args}, got {rc}\nStdout: {stdout}\nStderr: {stderr}"

    # Verify specific error messages
    rc, stdout, stderr = run_cli("inspect", os.path.join(FIXTURES, "valid.gguf"), "--endian")
    assert rc == 64
    assert "Error: --endian requires 'little', 'big', or 'auto'" in stderr

    print("  [ok] All usage tests passed with exit code 64.")

def test_fail_closed_arg_and_open_regressions():
    print("Running fail-closed regressions (dash paths, '--', FIFO open, digest gate order)...")

    valid = os.path.join(FIXTURES, "valid.gguf")
    dash_probe = "-safegguf-dash-arg-probe.gguf"

    # 1. A dash-leading positional path is a usage error without '--'; the
    #    top-level help contract (exit 0) is unchanged.
    rc, stdout, stderr = run_cli("inspect", "-h")
    assert rc == 64, f"Expected 64 for 'inspect -h', got {rc}\nStdout: {stdout}\nStderr: {stderr}"
    rc, stdout, stderr = run_cli("inspect", dash_probe)
    assert rc == 64, f"Expected 64 for a dash-leading path, got {rc}\nStdout: {stdout}\nStderr: {stderr}"
    rc, stdout, stderr = run_cli("--help")
    assert rc == 0, f"Expected 0 for top-level --help, got {rc}"

    # 2. '--' admits a dash-leading path: it is opened (and fails closed as a
    #    missing file), instead of being read as a flag.
    rc, stdout, stderr = run_cli("inspect", "--", dash_probe, "--format", "json")
    assert rc == 74, f"Expected 74 for '-- {dash_probe}', got {rc}: {stderr}"
    data = json.loads(stdout)
    assert data["error_code"] == "E_FILE_OPEN_FAILED", data

    # 3. Non-regular path targets must not block: a FIFO with no writer is
    #    rejected immediately (exit 74, E_FILE_STAT_FAILED), not left hanging
    #    in open(2). os.mkfifo is POSIX-only.
    if hasattr(os, "mkfifo"):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            fifo_path = os.path.join(td, "target.gguf")
            os.mkfifo(fifo_path)
            rc, stdout, stderr = run_cli("inspect", fifo_path, "--format", "json")
            assert rc == 74, f"Expected 74 for FIFO, got {rc}: {stderr}"
            data = json.loads(stdout)
            assert data["error_code"] == "E_FILE_STAT_FAILED", data

    # 4. The --max-file-size-bytes admission gate runs before the --log-json
    #    digest: an oversized input rejects with an empty digest, so the log
    #    can never describe bytes the validator did not admit.
    rc, stdout, stderr = run_cli("inspect", valid, "--max-file-size-bytes", "1", "--format", "json", "--log-json")
    assert rc == 2, f"Expected 2 for oversized input, got {rc}: {stdout} {stderr}"
    data = json.loads(stdout)
    assert data["error_code"] == "E_FileTooLarge", data
    assert data["stage"] == "admission", data
    log_record = json.loads(stderr.strip().splitlines()[-1])
    assert log_record["error_code"] == "E_FileTooLarge", log_record
    assert log_record["stage"] == "admission", log_record
    assert log_record["digest"] == "", f"digest computed before the admission gate: {log_record}"

    print("  [ok] Fail-closed argument, open, and digest-order regressions passed.")

def write_oversize_string_fixture(path, value_len):
    """Writes a minimal metadata-only GGUF v3 whose single metadata entry is
    `big.string: string` with `value_len` ASCII bytes (default cap is 65536)."""
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 0)  # tensor_count
    b += struct.pack("<Q", 1)  # metadata_kv_count

    key = b"big.string"
    b += struct.pack("<Q", len(key))
    b += key
    b += struct.pack("<I", 8)  # MetadataType.string
    value = b"a" * value_len
    b += struct.pack("<Q", len(value))
    b += value

    pad = (32 - (len(b) % 32)) % 32
    b += b"\x00" * pad
    with open(path, "wb") as f:
        f.write(b)

def test_relief_flags_and_canonical_split():
    print("Running P0-1/P0-3 relief-flag and canonical-detail tests...")

    # 1. Key grammar: hyphen/uppercase keys reject by default, pass under the
    #    explicit lenient relief policy.
    for fixture in ("hyphen_key.gguf", "invalid_key.gguf"):
        path = os.path.join(FIXTURES, fixture)
        rc, stdout, stderr = run_cli("inspect", path)
        assert rc == 2, f"Expected default strict REJECT for {fixture}, got {rc}: {stderr}"
        assert "E_InvalidKeyFormat" in stderr, f"Expected E_InvalidKeyFormat for {fixture}: {stderr}"
        rc, stdout, stderr = run_cli("inspect", path, "--key-policy", "lenient")
        assert rc == 0, f"Expected lenient PASS for {fixture}, got {rc}: {stderr}"

    # 2. String cap: oversize value rejects by default, passes when the cap is
    #    explicitly raised.
    oversize_path = os.path.join(FIXTURES, "oversize_string_tmp.gguf")
    try:
        write_oversize_string_fixture(oversize_path, 70000)
        rc, stdout, stderr = run_cli("inspect", oversize_path, "--format", "json")
        assert rc == 2, f"Expected default REJECT for oversize string, got {rc}: {stdout}"
        data = json.loads(stdout)
        assert data["error_code"] == "E_ResourceLimitExceeded", data
        rc, stdout, stderr = run_cli("inspect", oversize_path, "--max-string-bytes", "80000")
        assert rc == 0, f"Expected relief PASS for oversize string, got {rc}: {stderr}"
        rc, stdout, stderr = run_cli(
            "inspect", oversize_path, env={"SAFEGGUF_MAX_STRING_BYTES": "80000"}
        )
        assert rc == 0, f"Expected env relief PASS for oversize string, got {rc}: {stderr}"
    finally:
        if os.path.exists(oversize_path):
            os.remove(oversize_path)

    # 3. Canonical split: the dimension-product guard keeps the legacy
    #    E_CompatibilityViolation code while its canonical code names the
    #    specific cause, distinct from a true checked-arithmetic wrap.
    rc, stdout, stderr = run_cli(
        "inspect", os.path.join(FIXTURES, "element_product_overflow.gguf"),
        "--profile", "llama-cpp", "--format", "json",
    )
    assert rc == 2, f"Expected 2, got {rc}: {stdout}"
    data = json.loads(stdout)
    assert data["error_code"] == "E_CompatibilityViolation", data
    assert data["canonical_error_code"] == "SGGUF_E_DIMENSION_OVERFLOW", data
    assert data["category"] == "compatibility", data

    rc, stdout, stderr = run_cli(
        "inspect", os.path.join(FIXTURES, "llama_cpp_overflow.gguf"),
        "--profile", "llama-cpp", "--format", "json",
    )
    assert rc == 2, f"Expected 2, got {rc}: {stdout}"
    data = json.loads(stdout)
    assert data["error_code"] == "E_ArithmeticOverflow", data
    assert data["canonical_error_code"] == "SGGUF_E_ARITHMETIC_OVERFLOW", data

    print("  [ok] P0-1/P0-3 relief-flag and canonical-detail tests passed.")

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
    # Provenance accompanies ERROR JSON too (default llama-cpp profile).
    assert data["compatibility_target"] == GGML_PROVENANCE

    # 3. Non-regular path target (a directory) must fail closed as an IO error
    #    instead of surfacing as an opaque mid-parse read failure. Windows
    #    rejects directory opens earlier, hence the two accepted error codes.
    rc, stdout, stderr = run_cli("inspect", FIXTURES, "--format", "json")
    assert rc == 74, f"Expected returncode 74 (EX_IOERR) for a directory path, got {rc}\nStdout: {stdout}\nStderr: {stderr}"
    data = json.loads(stdout)
    assert data["status"] == "ERROR", f"Expected status ERROR, got {data['status']}"
    assert data["error_code"] in ("E_FILE_STAT_FAILED", "E_FILE_OPEN_FAILED"), data
    assert data["compatibility_target"] == GGML_PROVENANCE

    print("  [ok] IO error tests passed with exit code 74 and status ERROR.")

def test_help():
    print("Running CLI help contract tests (must exit code 0)...")
    for flag in ["--help", "-h", "help"]:
        rc, stdout, stderr = run_cli(flag)
        assert rc == 0, f"Expected returncode 0 for {flag}, got {rc}"
        output = stdout + stderr
        assert f"SafeGGUF v{SOURCE_VERSION} -" in output, f"Version missing in help: {output}"
        assert "--endian <little|big|auto>" in output, f"Accurate endian flag missing in help: {output}"
        assert "--profile <gguf-spec|llama-cpp>" in output, f"Accurate profile flag missing in help: {output}"
        assert "default: auto" in output, f"Default auto endian missing in help: {output}"
        assert "default: llama-cpp" in output, f"Default llama-cpp profile missing in help: {output}"
        assert "--format <text|json>" in output
        assert "--max-variable-array-elements <N>" in output, f"Variable-array cap flag missing in help: {output}"
        assert "default: 1000000" in output, f"Variable-array cap default missing in help: {output}"
        assert "--max-string-bytes <N>" in output, f"String-cap relief flag missing in help: {output}"
        assert "--key-policy <strict|lenient>" in output, f"Key-policy relief flag missing in help: {output}"
    print("  [ok] All help contract tests passed with exit code 0.")

def test_endian_auto():
    print("Running auto-detect endianness tests (--endian auto)...")
    big_endian_fixture = os.path.join(FIXTURES, "big_endian_v3.gguf")

    # 1. Big-Endian model with --endian auto under gguf-spec profile: PASS (code 0)
    rc, stdout, stderr = run_cli("inspect", big_endian_fixture, "--endian", "auto", "--profile", "gguf-spec")
    assert rc == 0, f"Expected 0 for --endian auto under gguf-spec, got {rc}: {stderr}"
    assert "Result: PASS" in stdout, f"Missing PASS in output: {stdout}"

    # 2. Big-Endian model with --endian auto under gguf-spec profile in JSON format: PASS (code 0)
    rc, stdout, stderr = run_cli("inspect", big_endian_fixture, "--endian", "auto", "--profile", "gguf-spec", "--format", "json")
    assert rc == 0, f"Expected 0 for JSON --endian auto under gguf-spec, got {rc}: {stderr}"
    data = json.loads(stdout)
    assert data["status"] == "PASS"
    assert data["profile"] == "gguf-spec"

    # 3. Big-Endian model with --endian auto under llama-cpp profile: REJECT (code 2)
    # Upstream ggml / llama.cpp profile enforces host native byte order
    rc, stdout, stderr = run_cli("inspect", big_endian_fixture, "--endian", "auto", "--profile", "llama-cpp")
    assert rc == 2, f"Expected 2 for --endian auto under llama-cpp, got {rc}: {stdout} {stderr}"
    assert "E_CompatibilityViolation" in stdout or "E_CompatibilityViolation" in stderr

    # 4. Big-Endian model with --endian auto under llama-cpp profile in JSON format: REJECT (code 2)
    rc, stdout, stderr = run_cli("inspect", big_endian_fixture, "--endian", "auto", "--profile", "llama-cpp", "--format", "json")
    assert rc == 2, f"Expected 2 for JSON --endian auto under llama-cpp, got {rc}: {stdout} {stderr}"
    data_llama = json.loads(stdout)
    assert data_llama["status"] == "REJECT"
    assert data_llama["category"] == "compatibility"

    # 5. Little-Endian model with --endian auto under both profiles: PASS (code 0)
    valid_fixture = os.path.join(FIXTURES, "valid.gguf")
    rc, stdout, stderr = run_cli("inspect", valid_fixture, "--endian", "auto", "--profile", "gguf-spec")
    assert rc == 0, f"Expected 0 for --endian auto on valid.gguf (gguf-spec), got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    rc, stdout, stderr = run_cli("inspect", valid_fixture, "--endian", "auto", "--profile", "llama-cpp")
    assert rc == 0, f"Expected 0 for --endian auto on valid.gguf (llama-cpp), got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    print("  [ok] Auto-detect endianness tests passed.")

def test_resource_limits():
    print("Running resource limits tests (--max-work-budget, --max-memory-mb, SAFEGGUF_MAX_*)...")
    valid_fixture = os.path.join(FIXTURES, "valid.gguf")

    # 1. --max-work-budget CLI flag override
    rc, stdout, stderr = run_cli("inspect", valid_fixture, "--max-work-budget", "1")
    assert rc == 2, f"Expected 2 for --max-work-budget 1, got {rc}: {stdout} {stderr}"
    assert "E_ResourceLimitExceeded" in stderr

    rc, stdout, stderr = run_cli("inspect", valid_fixture, "--max-work-budget", "10000000")
    assert rc == 0, f"Expected 0 for --max-work-budget 10000000, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    # 2. SAFEGGUF_MAX_WORK_BUDGET environment variable override
    rc, stdout, stderr = run_cli("inspect", valid_fixture, env={"SAFEGGUF_MAX_WORK_BUDGET": "1"})
    assert rc == 2, f"Expected 2 for SAFEGGUF_MAX_WORK_BUDGET=1, got {rc}: {stdout} {stderr}"
    assert "E_ResourceLimitExceeded" in stderr

    rc, stdout, stderr = run_cli("inspect", valid_fixture, env={"SAFEGGUF_MAX_WORK_BUDGET": "10000000"})
    assert rc == 0, f"Expected 0 for SAFEGGUF_MAX_WORK_BUDGET=10000000, got {rc}: {stderr}"
    assert "Result: PASS" in stdout

    # 3. Create a temporary fixture allocating ~1.8 MB to test memory quota overrides
    mem_fixture_path = os.path.join(FIXTURES, "temp_mem_test.gguf")
    try:
        num_keys = 30
        key_len = 60000
        b = bytearray()
        b += b"GGUF"
        b += struct.pack("<IQQ", 3, 0, num_keys)
        for i in range(num_keys):
            k = f"key_{i:04d}_".encode("ascii") + b"a" * (key_len - 9)
            b += struct.pack("<Q", len(k))
            b += k
            b += struct.pack("<II", 4, 0)
        pad = (32 - (len(b) % 32)) % 32
        b += b"\x00" * pad
        with open(mem_fixture_path, "wb") as f:
            f.write(b)

        # 3a. --max-memory-mb 1 -> REJECT (exit 2, E_TotalAllocationLimitExceeded)
        rc, stdout, stderr = run_cli("inspect", mem_fixture_path, "--max-memory-mb", "1")
        assert rc == 2, f"Expected 2 for --max-memory-mb 1, got {rc}: {stdout} {stderr}"
        assert "E_TotalAllocationLimitExceeded" in stderr

        # 3b. --max-memory-mb 5 -> PASS (exit 0)
        rc, stdout, stderr = run_cli("inspect", mem_fixture_path, "--max-memory-mb", "5")
        assert rc == 0, f"Expected 0 for --max-memory-mb 5, got {rc}: {stderr}"
        assert "Result: PASS" in stdout

        # 3c. SAFEGGUF_MAX_MEMORY_MB=1 -> REJECT (exit 2, E_TotalAllocationLimitExceeded)
        rc, stdout, stderr = run_cli("inspect", mem_fixture_path, env={"SAFEGGUF_MAX_MEMORY_MB": "1"})
        assert rc == 2, f"Expected 2 for SAFEGGUF_MAX_MEMORY_MB=1, got {rc}: {stdout} {stderr}"
        assert "E_TotalAllocationLimitExceeded" in stderr

        # 3d. SAFEGGUF_MAX_MEMORY_MB=5 -> PASS (exit 0)
        rc, stdout, stderr = run_cli("inspect", mem_fixture_path, env={"SAFEGGUF_MAX_MEMORY_MB": "5"})
        assert rc == 0, f"Expected 0 for SAFEGGUF_MAX_MEMORY_MB=5, got {rc}: {stderr}"
        assert "Result: PASS" in stdout

    finally:
        if os.path.exists(mem_fixture_path):
            os.remove(mem_fixture_path)

    print("  [ok] Resource limits and environment variable tests passed.")

def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def test_admit_publish_and_script_byte_identity():
    print("Running admit publication tests (layout, attestation bytes, stdout identity)...")
    import hashlib
    import shutil
    import tempfile

    valid = os.path.join(FIXTURES, "valid.gguf")
    digest = sha256_file(valid)

    with tempfile.TemporaryDirectory() as td:
        cas = os.path.join(td, "validated")
        att = os.path.join(td, "attestations")
        os.makedirs(cas)
        os.makedirs(att)

        # 1. Happy path: publish + attest + pin, stdout is exactly the
        #    attestation document.
        rc, stdout, stderr = run_cli(
            "admit", "--", valid, "--cas-dir", cas, "--attestations-dir", att,
            "--log-json",
        )
        assert rc == 0, f"Expected 0, got {rc}: {stderr}"
        cas_entry = os.path.join(cas, digest)
        att_json = os.path.join(att, digest + ".json")
        pin = os.path.join(att, digest + ".sha256")
        assert os.path.isfile(cas_entry), f"CAS entry missing: {os.listdir(cas)}"
        assert open(cas_entry, "rb").read() == open(valid, "rb").read(), "CAS bytes differ from source"
        assert open(att_json, "rb").read() == stdout.encode(), "stdout is not the attestation bytes"
        assert open(pin, "rb").read() == (digest + "  " + digest + "\n").encode(), "pin bytes differ"
        if os.name != "nt":
            import stat as stat_mod
            assert stat_mod.S_IMODE(os.stat(cas_entry).st_mode) == 0o444, "CAS entry not 0444"

        data = json.loads(stdout)
        assert data["schema_version"] == 2, data
        assert data["document_type"] == "safegguf-admission", data
        assert data["digest"] == {"algorithm": "sha256", "value": digest}, data
        assert data["size_bytes"] == os.path.getsize(valid), data
        assert data["verdict"] == {"status": "PASS", "validator_exit_code": 0}, data
        assert data["validator"]["profile"] == "llama-cpp", data
        assert data["validator"]["limits"] == {
            "max_tensors": 1000000,
            "max_metadata_entries": 1000000,
            "max_string_bytes": 65536,
            "key_policy": "strict",
            "max_tensor_name_bytes": 64,
            "max_dimensions": 4,
            "max_array_elements": 10000000,
            "max_variable_array_elements": 1000000,
            "max_metadata_depth": 16,
            "max_total_alloc_bytes": 134217728,
            "max_work_units": 10000000,
            "max_scanned_bytes": 268435456,
            "max_file_size_bytes": 17179869184,
            "require_stable_file": True,
        }, data
        assert data["cas"] == {
            "relative_to": "cas-dir",
            "relative_path": digest,
            "sha256": digest,
        }, data
        assert data["validator"]["version"], data
        assert data["validator"]["source_commit"], data
        assert data["validator"]["endian"] == "auto", data
        assert data["validator"]["resolved_endian"] == sys.byteorder, data
        assert data["validator"]["type_layout_source"] == GGML_PROVENANCE, data

        # --log-json digest is the copy-stream digest.
        log_record = json.loads(stderr.strip().splitlines()[-1])
        assert log_record["digest"] == digest, log_record
        assert log_record["verdict"] == "PASS", log_record

        # No staging leftovers.
        assert not [n for n in os.listdir(cas) if n.startswith(".admit-stage")], os.listdir(cas)

        # 2. Byte-identical to the K8s handoff script for the same input
        #    (POSIX + bash only; the script needs mktemp/sha256sum/awk).
        script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "deploy", "k8s", "attestation_handoff.sh",
        )
        if sys.platform != "win32" and shutil.which("bash") and os.path.isfile(script):
            work = os.path.join(td, "script-work")
            env = os.environ.copy()
            env["PATH"] = os.path.dirname(BINARY) + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(
                ["bash", script, valid, work],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=60, env=env,
            )
            assert proc.returncode == 0, f"script failed rc={proc.returncode}: {proc.stderr}"
            assert open(os.path.join(work, "attestations", digest + ".json"), "rb").read() == \
                open(att_json, "rb").read(), "attestation differs from script bytes"
            assert open(os.path.join(work, "validated", digest), "rb").read() == \
                open(cas_entry, "rb").read(), "CAS bytes differ from script"
            assert open(os.path.join(work, "attestations", digest + ".sha256"), "rb").read() == \
                open(pin, "rb").read(), "pin bytes differ from script"

        # 3. --max-file-size-bytes override is bound into the attestation.
        cas2 = os.path.join(td, "validated2")
        att2 = os.path.join(td, "attestations2")
        os.makedirs(cas2)
        os.makedirs(att2)
        rc, stdout, stderr = run_cli(
            "admit", "--", valid, "--cas-dir", cas2, "--attestations-dir", att2,
            "--max-file-size-bytes", "1048576",
        )
        assert rc == 0, f"Expected 0, got {rc}: {stderr}"
        data2 = json.loads(stdout)
        assert data2["validator"]["limits"]["max_file_size_bytes"] == 1048576, data2

    print("  [ok] admit publication, layout, and script byte-identity tests passed.")

def test_nul_tensor_names():
    print("Running NUL tensor identity regressions...")
    for filename in ("nul_tensor_alias.gguf", "nul_tensor_name.gguf"):
        path = os.path.join(FIXTURES, filename)
        rc, out, _ = run_cli("inspect", path, "--format", "json")
        assert rc == 2 and json.loads(out)["error_code"] == "E_InvalidTensorName", out
        assert run_cli("inspect", path, "--profile", "gguf-spec")[0] == 0
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cas = os.path.join(td, "objects")
            att = os.path.join(td, "statements")
            os.mkdir(cas)
            os.mkdir(att)
            rc, out, _ = run_cli("admit", path, "--cas-dir", cas, "--attestations-dir", att)
            assert rc == 2 and json.loads(out)["error_code"] == "E_InvalidTensorName", out
            assert os.listdir(cas) == [] and os.listdir(att) == []
    assert run_cli("inspect", os.path.join(FIXTURES, "tensor_name_control.gguf"))[0] == 0


def test_admit_effective_policy():
    print("Running admission policy binding, replay, and arbitrary CAS-directory tests...")
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        cas = os.path.join(td, "objects")
        att = os.path.join(td, "statements")
        os.mkdir(cas)
        os.mkdir(att)
        path = os.path.join(FIXTURES, "hyphen_key.gguf")
        env = {"SAFEGGUF_MAX_ALLOC_BYTES": "8388608", "SAFEGGUF_MAX_WORK_UNITS": "12345",
               "SAFEGGUF_MAX_SCANNED_BYTES": "54321", "SAFEGGUF_KEY_POLICY": "lenient",
               "SAFEGGUF_MAX_STRING_BYTES": "131072"}
        rc, out, _ = run_cli("admit", path, "--cas-dir", cas, "--attestations-dir", att,
                             "--max-variable-array-elements", "100", env=env)
        assert rc == 0, out
        data = json.loads(out)
        policy = data["validator"]
        lim = policy["limits"]
        assert lim["key_policy"] == "lenient" and lim["max_string_bytes"] == 131072, lim
        assert lim["max_total_alloc_bytes"] == 8388608 and lim["max_work_units"] == 12345, lim
        assert lim["max_scanned_bytes"] == 54321 and lim["max_variable_array_elements"] == 100, lim
        assert data["cas"]["relative_to"] == "cas-dir", data
        object_path = os.path.join(cas, data["cas"]["relative_path"])
        assert os.path.isfile(object_path) and sha256_file(object_path) == data["digest"]["value"]
        # Default strict policy rejects the admitted object; recorded policy replays PASS.
        assert run_cli("inspect", object_path, "--key-policy", "strict")[0] == 2
        replay_env = {"SAFEGGUF_MAX_ALLOC_BYTES": str(lim["max_total_alloc_bytes"]),
                      "SAFEGGUF_MAX_WORK_UNITS": str(lim["max_work_units"]),
                      "SAFEGGUF_MAX_SCANNED_BYTES": str(lim["max_scanned_bytes"])}
        assert run_cli("inspect", object_path, "--profile", policy["profile"],
                       "--endian", policy["resolved_endian"], "--key-policy", lim["key_policy"],
                       "--max-string-bytes", str(lim["max_string_bytes"]),
                       "--max-variable-array-elements", str(lim["max_variable_array_elements"]),
                       "--max-file-size-bytes", str(lim["max_file_size_bytes"]),
                       "--require-stable-file", env=replay_env)[0] == 0
        # Explicit endian and CLI policy override are captured as effective values.
        rc, out, _ = run_cli("admit", os.path.join(FIXTURES, "big_endian_v3.gguf"),
                             "--cas-dir", cas, "--attestations-dir", att,
                             "--profile", "gguf-spec", "--endian", "big",
                             "--key-policy", "strict", env=env)
        assert rc == 0, out
        policy = json.loads(out)["validator"]
        assert policy["endian"] == policy["resolved_endian"] == "big", policy
        assert policy["limits"]["key_policy"] == "strict", policy


def test_admit_reject_and_size_cap():
    print("Running admit reject/size-cap tests (nothing published)...")
    import tempfile

    valid = os.path.join(FIXTURES, "valid.gguf")

    # 1. Validation REJECT: exit 2, REJECT JSON, no CAS/attestation/staging.
    with tempfile.TemporaryDirectory() as td:
        cas = os.path.join(td, "validated")
        att = os.path.join(td, "attestations")
        os.makedirs(cas)
        os.makedirs(att)
        rc, stdout, stderr = run_cli(
            "admit", "--", os.path.join(FIXTURES, "gap.gguf"),
            "--cas-dir", cas, "--attestations-dir", att, "--profile", "llama-cpp",
        )
        assert rc == 2, f"Expected 2, got {rc}: {stdout} {stderr}"
        data = json.loads(stdout)
        assert data["status"] == "REJECT", data
        assert data["error_code"] == "E_NonContiguousTensorOffset", data
        assert os.listdir(cas) == [], os.listdir(cas)
        assert os.listdir(att) == [], os.listdir(att)

    # 2. Pre-copy stat gate: an oversized source rejects at admission with
    #    nothing published.
    with tempfile.TemporaryDirectory() as td:
        cas = os.path.join(td, "validated")
        att = os.path.join(td, "attestations")
        os.makedirs(cas)
        os.makedirs(att)
        rc, stdout, stderr = run_cli(
            "admit", "--", valid, "--cas-dir", cas, "--attestations-dir", att,
            "--max-file-size-bytes", "1",
        )
        assert rc == 2, f"Expected 2, got {rc}: {stdout} {stderr}"
        data = json.loads(stdout)
        assert data["error_code"] == "E_FileTooLarge", data
        assert data["stage"] == "admission", data
        assert os.listdir(cas) == [] and os.listdir(att) == []

    # 3. Streaming gate: a regular file whose stat size (0) understates its
    #    readable content must abort at cap+1, not copy the whole stream.
    #    /proc/<pid>/status is such a file on Linux; on other platforms the
    #    stat gate above is the portable cap contract.
    proc_status = "/proc/self/status"
    if sys.platform.startswith("linux") and os.path.isfile(proc_status) and os.path.getsize(proc_status) == 0:
        with tempfile.TemporaryDirectory() as td:
            cas = os.path.join(td, "validated")
            att = os.path.join(td, "attestations")
            os.makedirs(cas)
            os.makedirs(att)
            rc, stdout, stderr = run_cli(
                "admit", "--", proc_status, "--cas-dir", cas, "--attestations-dir", att,
                "--max-file-size-bytes", "100",
            )
            assert rc == 2, f"Expected streaming abort rc 2, got {rc}: {stdout} {stderr}"
            data = json.loads(stdout)
            assert data["error_code"] == "E_FileTooLarge", data
            assert data["stage"] == "admission", data
            assert os.listdir(cas) == [] and os.listdir(att) == []

    print("  [ok] admit reject and size-cap tests passed with nothing published.")

def test_admit_usage_and_dash_paths():
    print("Running admit usage/dash-path tests (must exit 64/74 fail-closed)...")
    import tempfile

    valid = os.path.join(FIXTURES, "valid.gguf")
    dash_probe = "-admit-dash-arg-probe.gguf"

    with tempfile.TemporaryDirectory() as td:
        cas = os.path.join(td, "validated")
        att = os.path.join(td, "attestations")
        os.makedirs(cas)
        os.makedirs(att)
        not_a_dir = os.path.join(td, "not-a-dir")
        with open(not_a_dir, "w") as f:
            f.write("x")

        bad_invocations = [
            ["admit"],
            ["admit", "--", valid],  # missing both dirs
            ["admit", "--", valid, "--cas-dir", cas],
            ["admit", "--", valid, "--attestations-dir", att],
            ["admit", "--", valid, "--cas-dir"],
            ["admit", "--", valid, "--attestations-dir"],
            ["admit", "--", valid, "--cas-dir", cas, "--attestations-dir", att, "--format", "json"],
            ["admit", "--", valid, "--cas-dir", cas, "--attestations-dir", att, "--unknown-flag"],
            ["admit", "--", valid, "--cas-dir", cas, "--attestations-dir", att, "--endian", "middle"],
            ["admit", "--", valid, "--cas-dir", cas, "--attestations-dir", att, "--key-policy", "bogus"],
            ["admit", dash_probe, "--cas-dir", cas, "--attestations-dir", att],
            ["admit", "--help"],
            ["admit", "--", valid, "--cas-dir", os.path.join(td, "missing"), "--attestations-dir", att],
            ["admit", "--", valid, "--cas-dir", not_a_dir, "--attestations-dir", att],
        ]
        for args in bad_invocations:
            rc, stdout, stderr = run_cli(*args)
            assert rc == 64, f"Expected 64 for {args}, got {rc}: {stdout} {stderr}"

        # `--` admits a dash-leading path: it is opened and fails closed as a
        # missing file (exit 74), never parsed as a flag.
        rc, stdout, stderr = run_cli("admit", "--", dash_probe, "--cas-dir", cas, "--attestations-dir", att)
        assert rc == 74, f"Expected 74 for '-- {dash_probe}', got {rc}: {stderr}"
        data = json.loads(stdout)
        assert data["error_code"] == "E_FILE_OPEN_FAILED", data

        # Missing/directory/FIFO sources are I/O errors (74), not usage errors.
        rc, stdout, stderr = run_cli("admit", "--", os.path.join(FIXTURES, "nope.gguf"), "--cas-dir", cas, "--attestations-dir", att)
        assert rc == 74, f"Expected 74 for missing source, got {rc}"
        rc, stdout, stderr = run_cli("admit", "--", FIXTURES, "--cas-dir", cas, "--attestations-dir", att)
        assert rc == 74, f"Expected 74 for directory source, got {rc}"
        if hasattr(os, "mkfifo"):
            fifo = os.path.join(td, "fifo.gguf")
            os.mkfifo(fifo)
            rc, stdout, stderr = run_cli("admit", "--", fifo, "--cas-dir", cas, "--attestations-dir", att)
            assert rc == 74, f"Expected 74 for FIFO source, got {rc}"
            data = json.loads(stdout)
            assert data["error_code"] == "E_FILE_STAT_FAILED", data

        assert os.listdir(cas) == [], os.listdir(cas)

    print("  [ok] admit usage/dash-path tests passed.")

def test_admit_orphan_cas_on_attestation_failure():
    print("Running admit orphan-CAS-on-attestation-failure test (exit 74, CAS kept)...")
    import tempfile

    valid = os.path.join(FIXTURES, "valid.gguf")
    digest = sha256_file(valid)

    with tempfile.TemporaryDirectory() as td:
        cas = os.path.join(td, "validated")
        att = os.path.join(td, "attestations")
        os.makedirs(cas)
        os.makedirs(att)
        # Block the attestation rename with a directory at the final name: the
        # CAS publish succeeds, the attestation write fails.
        os.makedirs(os.path.join(att, digest + ".json"))

        rc, stdout, stderr = run_cli("admit", "--", valid, "--cas-dir", cas, "--attestations-dir", att)
        assert rc == 74, f"Expected 74, got {rc}: {stdout} {stderr}"
        data = json.loads(stdout)
        assert data["status"] == "ERROR", data
        assert data["error_code"] == "E_IoError", data
        assert data["stage"] == "attestation", data

        # The orphan CAS entry is kept and complete; no pin, no temp leftovers.
        cas_entry = os.path.join(cas, digest)
        assert os.path.isfile(cas_entry), "orphan CAS entry was rolled back"
        assert open(cas_entry, "rb").read() == open(valid, "rb").read()
        assert not os.path.isfile(os.path.join(att, digest + ".sha256"))
        leftovers = [n for n in os.listdir(att) if n.endswith(".tmp")]
        assert leftovers == [], leftovers
        assert not [n for n in os.listdir(cas) if n.startswith(".admit-stage")], os.listdir(cas)

    print("  [ok] admit orphan-CAS test passed.")

def test_admit_inspect_parity():
    print("Running admit/inspect shared-defaults parity tests...")
    import tempfile

    cases = [
        ("valid.gguf", [], 0, None),
        ("gap.gguf", ["--profile", "llama-cpp"], 2, "E_NonContiguousTensorOffset"),
        ("hyphen_key.gguf", [], 2, "E_InvalidKeyFormat"),
        ("hyphen_key.gguf", ["--key-policy", "lenient"], 0, None),
        ("version_2.gguf", ["--profile", "gguf-spec"], 2, "E_UnsupportedVersion"),
        ("version_2.gguf", [], 0, None),
        ("valid.gguf", ["--max-work-budget", "1"], 2, "E_ResourceLimitExceeded"),
        ("big_endian_v3.gguf", ["--endian", "auto", "--profile", "gguf-spec"], 0, None),
        ("element_product_overflow.gguf", ["--profile", "llama-cpp"], 2, "E_CompatibilityViolation"),
    ]
    for fixture, flags, want_rc, want_code in cases:
        path = os.path.join(FIXTURES, fixture)
        rc_i, out_i, err_i = run_cli("inspect", path, "--format", "json", *flags)
        assert rc_i == want_rc, f"inspect {fixture} {flags}: expected {want_rc}, got {rc_i}: {err_i}"
        with tempfile.TemporaryDirectory() as td:
            cas = os.path.join(td, "validated")
            att = os.path.join(td, "attestations")
            os.makedirs(cas)
            os.makedirs(att)
            rc_a, out_a, err_a = run_cli("admit", "--", path, "--cas-dir", cas, "--attestations-dir", att, *flags)
            assert rc_a == want_rc, f"admit {fixture} {flags}: expected {want_rc}, got {rc_a}: {err_a}"
            if want_code is not None:
                assert json.loads(out_i)["error_code"] == want_code, (fixture, flags, out_i)
                assert json.loads(out_a)["error_code"] == want_code, (fixture, flags, out_a)

    # Environment-sourced defaults are shared too (SAFEGGUF_KEY_POLICY).
    hyphen = os.path.join(FIXTURES, "hyphen_key.gguf")
    rc_i, _, _ = run_cli("inspect", hyphen, env={"SAFEGGUF_KEY_POLICY": "lenient"})
    with tempfile.TemporaryDirectory() as td:
        cas = os.path.join(td, "validated")
        att = os.path.join(td, "attestations")
        os.makedirs(cas)
        os.makedirs(att)
        rc_a, _, _ = run_cli(
            "admit", "--", hyphen, "--cas-dir", cas, "--attestations-dir", att,
            env={"SAFEGGUF_KEY_POLICY": "lenient"},
        )
    assert rc_i == 0 and rc_a == 0, (rc_i, rc_a)

    print("  [ok] admit/inspect parity tests passed.")

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
    test_relief_flags_and_canonical_split()
    test_io_error()
    test_help()
    test_endian_auto()
    test_resource_limits()
    test_fail_closed_arg_and_open_regressions()
    test_admit_publish_and_script_byte_identity()
    test_admit_reject_and_size_cap()
    test_admit_usage_and_dash_paths()
    test_admit_orphan_cas_on_attestation_failure()
    test_admit_inspect_parity()
    test_nul_tensor_names()
    test_admit_effective_policy()
    print("\nAll CLI end-to-end integration tests PASSED successfully!")
