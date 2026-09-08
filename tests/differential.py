"""
True Differential Testing Harness for SafeGGUF vs Upstream ggml 0.23.0
Compares acceptance verdicts between SafeGGUF (--profile llama-cpp)
and the compiled upstream ggml oracle (commit e91ded11bdcd78c42f9c8d3978ff6686eb4c1226).
"""

import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SAFEGGUF_BIN = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf")
ORACLE_BIN = os.path.join(SCRIPT_DIR, "oracle", "ggml_oracle")
FIXTURES_DIR = os.path.join(SCRIPT_DIR, "fixtures")

# Explicit, full expected matrix for all fixtures across:
# (SafeGGUF llama-cpp, Upstream --load-data, Upstream --no-load, Description/Rationale)
EXPECTED_MATRIX = {
    "truncated_header_padding_zero_tensors.gguf": (
        "PASS", "PASS", "PASS",
        "SafeGGUF llama-cpp mirrors upstream zero-tensor non-seek; gguf-spec strictly rejects.",
    ),
    "signed_dim_overflow.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Upstream ggml and SafeGGUF llama-cpp reject dimensions > INT64_MAX.",
    ),
    "element_product_overflow.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Upstream ggml and SafeGGUF llama-cpp reject total elements >= INT64_MAX.",
    ),
    "big_endian_v3.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Upstream ggml rejects non-native endianness; SafeGGUF enforces native under llama-cpp",
    ),
    "alloc_dos_tensor.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Allocation DoS tensor exceeds bounds/limits",
    ),
    "duplicate_key.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Duplicate metadata key rejected",
    ),
    "duplicate_tensor.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Duplicate tensor name rejected",
    ),
    "empty_tensor_name.gguf": (
        "REJECT", "PASS", "PASS",
        "SafeGGUF enforces non-empty tensor names (1 <= len <= 64). Upstream accepts len == 0.",
    ),
    "gap.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Non-contiguous tensor offsets rejected under llama-cpp profile",
    ),
    "hyphen_key.gguf": (
        "REJECT", "PASS", "PASS",
        "SafeGGUF enforces strict lower_snake_case without hyphens. Upstream accepts hyphens.",
    ),
    "invalid_bool.gguf": (
        "REJECT", "PASS", "PASS",
        "SafeGGUF enforces strict boolean bytes (0x00 or 0x01). Upstream accepts any non-zero.",
    ),
    "invalid_key.gguf": (
        "REJECT", "PASS", "PASS",
        "SafeGGUF enforces strict lower_snake_case key grammar. Upstream accepts uppercase.",
    ),
    "llama_cpp_overflow.gguf": (
        "REJECT", "PASS", "PASS",
        "SafeGGUF checked arithmetic prevents u64 overflow. Upstream GGML_PAD wraps to 0.",
    ),
    "name_64.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Tensor name >= 64 characters rejected",
    ),
    "nested_array.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Nested metadata arrays rejected under llama-cpp profile",
    ),
    "nonzero_header_padding.gguf": (
        "REJECT", "PASS", "PASS",
        "SafeGGUF strictly enforces GGUF zero-padding requirement; upstream ggml skips padding unverified.",
    ),
    "out_of_bounds.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Tensor data bounds exceed file size",
    ),
    "overflow.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Tensor dimension product arithmetic overflow",
    ),
    "overlap.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Overlapping tensor byte spans rejected",
    ),
    "removed_type_slot31.gguf": (
        "REJECT", "REJECT", "REJECT",
        "Deprecated/removed GGML type slot 31 rejected",
    ),
    "scalar.gguf": (
        "PASS", "PASS", "PASS",
        "Scalar tensor (n_dims == 0, 1 element) valid across SafeGGUF and upstream",
    ),
    "truncated_final_padding.gguf": (
        "REJECT", "REJECT", "PASS",
        "Trailing padding missing: SafeGGUF and upstream load reject; no-load passes (HIGH-01)",
    ),
    "type40_truncated_false_pass.gguf": (
        "REJECT", "REJECT", "PASS",
        "Truncated tensor data: SafeGGUF and upstream load reject; no-load passes",
    ),
    "valid.gguf": (
        "PASS", "PASS", "PASS",
        "Canonical valid GGUF file passes all checks",
    ),
    "version_2.gguf": (
        "PASS", "PASS", "PASS",
        "GGUF v2 file passes backward-compatible llama-cpp loader",
    ),
    "zero_dimension.gguf": (
        "REJECT", "PASS", "PASS",
        "SafeGGUF rejects explicit 0-element dimensions (E_ZeroDimensionNotAllowed). Upstream accepts.",
    ),
}

def ensure_binaries():
    if not os.path.exists(SAFEGGUF_BIN):
        print(f"SafeGGUF binary not found at {SAFEGGUF_BIN}. Running zig build...")
        subprocess.check_call(["zig", "build", "-Doptimize=ReleaseSafe"], cwd=REPO_ROOT)

    if not os.path.exists(ORACLE_BIN):
        print(f"Building upstream ggml oracle via {os.path.join(SCRIPT_DIR, 'build_oracle.sh')}...")
        subprocess.check_call([os.path.join(SCRIPT_DIR, "build_oracle.sh")], cwd=REPO_ROOT)

def assert_oracle_identity():
    proc = subprocess.run([ORACLE_BIN, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    out = proc.stdout.strip()
    print(f"Oracle runtime identity: {out.replace(chr(10), ', ')}")
    assert "ggml_version: 0.23.0" in out, f"Unexpected ggml_version: {out}"
    assert "ggml_commit: e91ded1" in out, f"Unexpected ggml_commit: {out}"

def run_safegguf(path: str):
    cmd = [SAFEGGUF_BIN, "inspect", path, "--profile", "llama-cpp"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1, "Execution timed out after 10s" 

    # Strict POSIX exit taxonomy
    if proc.returncode == 0:
        verdict = "PASS"
    elif proc.returncode == 2:
        verdict = "REJECT"
    elif proc.returncode < 0:
        verdict = f"CRASH(SIG{-proc.returncode})"
    else:
        verdict = f"INTERNAL_ERROR({proc.returncode})"

    return verdict, proc.returncode, proc.stderr.strip()

def run_oracle(path: str, mode: str):
    cmd = [ORACLE_BIN, mode, path]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1

    # Strict oracle exit taxonomy: only exit 2 represents validation failure. Exit 1 is usage/IO error.
    if proc.returncode == 0:
        verdict = "PASS"
    elif proc.returncode == 2:
        verdict = "REJECT"
    elif proc.returncode < 0:
        verdict = f"CRASH(SIG{-proc.returncode})"
    else:
        verdict = f"ERROR({proc.returncode})"

    return verdict, proc.returncode

def main():
    print("=== SafeGGUF vs Upstream ggml 0.23.0 True Differential Validation ===")
    ensure_binaries()
    assert_oracle_identity()

    fixtures = sorted([f for f in os.listdir(FIXTURES_DIR) if f.endswith(".gguf")])
    if not fixtures:
        print("Error: No test fixtures found. Run generate_fixtures.py first.")
        sys.exit(1)

    print(f"Loaded {len(fixtures)} fixtures from {FIXTURES_DIR}\n")
    print(f"{'Fixture':<34} | {'SafeGGUF':<8} | {'Upstream Load':<13} | {'Upstream NoLoad':<15} | {'Verdict'}")
    print("-" * 105)

    failures = []
    for f in fixtures:
        if f not in EXPECTED_MATRIX:
            failures.append(f"Fixture '{f}' has no entry in EXPECTED_MATRIX! All fixtures must be explicitly verified.")
            continue

        exp_safe, exp_up_load, exp_up_noload, rationale = EXPECTED_MATRIX[f]
        path = os.path.join(FIXTURES_DIR, f)
        safe_verdict, safe_rc, safe_err = run_safegguf(path)
        up_load_verdict, up_load_rc = run_oracle(path, "--load-data")
        up_noload_verdict, up_noload_rc = run_oracle(path, "--no-load")

        # Check for unexpected crashes or internal errors
        if safe_verdict not in ("PASS", "REJECT"):
            failures.append(f"{f}: SafeGGUF crashed or internal error! Verdict={safe_verdict}, Stderr={safe_err}")
        if up_load_verdict not in ("PASS", "REJECT"):
            failures.append(f"{f}: Upstream Load crashed! Verdict={up_load_verdict}")
        if up_noload_verdict not in ("PASS", "REJECT"):
            failures.append(f"{f}: Upstream NoLoad crashed! Verdict={up_noload_verdict}")

        # Assert full 3-column matrix against expected specifications
        mismatch = False
        if safe_verdict != exp_safe:
            failures.append(f"{f}: SafeGGUF verdict mismatch! Expected {exp_safe}, got {safe_verdict} (rc={safe_rc}). Stderr: {safe_err}")
            mismatch = True
        if up_load_verdict != exp_up_load:
            failures.append(f"{f}: Upstream Load verdict mismatch! Expected {exp_up_load}, got {up_load_verdict} (rc={up_load_rc})")
            mismatch = True
        if up_noload_verdict != exp_up_noload:
            failures.append(f"{f}: Upstream NoLoad verdict mismatch! Expected {exp_up_noload}, got {up_noload_verdict} (rc={up_noload_rc})")
            mismatch = True

        if mismatch:
            status_note = "MISMATCH FAILURE"
        elif safe_verdict != up_load_verdict or safe_verdict != up_noload_verdict:
            status_note = f"DOCUMENTED DIVERGENCE ({rationale[:40]}...)"
        else:
            status_note = "MATCH (100% UNANIMOUS)"

        print(f"{f:<34} | {safe_verdict:<8} | {up_load_verdict:<13} | {up_noload_verdict:<15} | {status_note}")

    print("-" * 105)
    if failures:
        print("\nDIFFERENTIAL FAILURES DETECTED:")
        for fail in failures:
            print("  X " + fail)
        sys.exit(1)

    print(f"\n✓ True Differential Test Suite PASSED! All {len(fixtures)} fixtures verified with full 3-column assertions against upstream ggml 0.23.0.")

if __name__ == "__main__":
    main()
