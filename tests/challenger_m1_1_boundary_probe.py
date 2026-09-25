#!/usr/bin/env python3
"""
Challenger M1_1 Gen 2: Empirical Boundary & Stress Probe Harness
Adversarial Verification for SafeGGUF CLI Argument Parsing & Resource Boundaries

Focus:
1. Exhaustive testing of --max-memory-mb across u64 arithmetic boundaries,
   specifically 2^44-1 (17592186044415), 2^44 (17592186044416),
   2^64-1 (18446744073709551615), 2^64 (18446744073709551616), etc.
2. Sign permutations, floating-point representations, strings, malformed syntax.
3. Cross-flag interactions (--format, --endian, --profile, --max-work-budget).
4. Functional quota exhaustion (exit 2 vs exit 64 vs exit 70).
5. Comprehensive fixture testing (BE v3, v2, CVE overflow, negative corpus).
6. Verification of ZERO crashes, ZERO panics, and exact return codes.
"""

import os
import sys
import subprocess
import struct
import tempfile
import random

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(ROOT_DIR, "zig-out", "bin", "safegguf.exe" if sys.platform == "win32" else "safegguf")
FIXTURES_DIR = os.path.join(ROOT_DIR, "tests", "fixtures")
VALID_GGUF = os.path.join(FIXTURES_DIR, "valid.gguf")

results = []

def record(test_id, name, passed, expected, actual, stderr=""):
    results.append({
        "id": test_id,
        "name": name,
        "passed": passed,
        "expected": expected,
        "actual": actual,
        "stderr": stderr.strip()[:100]
    })
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] #{test_id:03d} {name} -> exp={expected}, act={actual} {f'({stderr.strip()[:60]})' if stderr else ''}")

def run_cli(*args, env=None, timeout=10):
    cmd = [BINARY] + list(args)
    full_env = None
    if env is not None:
        full_env = os.environ.copy()
        full_env.update(env)
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env=full_env
    )
    return proc.returncode, proc.stdout, proc.stderr

def check_no_panic(stderr, stdout=""):
    low_err = stderr.lower()
    low_out = stdout.lower()
    forbidden = ["panic", "segmentation fault", "access violation", "unhandled exception", "integer overflow"]
    for word in forbidden:
        if word in low_err or word in low_out:
            return False
    return True

def run_suite():
    print(f"======================================================================")
    print(f"CHALLENGER M1_1 GEN 2: EMPIRICAL BOUNDARY PROBE HARNESS")
    print(f"Target Binary: {BINARY}")
    print(f"======================================================================\n")

    if not os.path.exists(BINARY):
        print(f"FATAL: Binary does not exist at {BINARY}")
        sys.exit(1)
    if not os.path.exists(VALID_GGUF):
        print(f"FATAL: Valid fixture does not exist at {VALID_GGUF}")
        sys.exit(1)

    t_idx = 1

    # -------------------------------------------------------------------------
    # SUITE 1: Arithmetic & Power-of-Two Boundaries for --max-memory-mb
    # -------------------------------------------------------------------------
    print("--- SUITE 1: Arithmetic & Power-of-Two Boundaries ---")
    
    # Critical boundary definitions:
    # 2^44 = 17592186044416 (overflow point for parsed * 1024 * 1024 in u64)
    # 2^44 - 1 = 17592186044415 (largest value where parsed * 1048576 <= 2^64-1)
    # 2^64 = 18446744073709551616 (overflow point for u64 parseInt)
    # 2^64 - 1 = 18446744073709551615 (largest u64)

    boundary_cases = [
        # (val_str, expected_rc, check_err_msg, description)
        ("1", 0, None, "Minimum positive integer (1 MB)"),
        ("128", 0, None, "Default limit value (128 MB)"),
        ("1024", 0, None, "1 GB (1024 MB)"),
        ("1048576", 0, None, "1 TB (1048576 MB = 2^20 MB)"),
        (str(2**31 - 1), 0, None, "2^31 - 1 MB (2147483647)"),
        (str(2**31), 0, None, "2^31 MB (2147483648)"),
        (str(2**32 - 1), 0, None, "2^32 - 1 MB (4294967295)"),
        (str(2**32), 0, None, "2^32 MB (4294967296)"),
        (str(2**43), 0, None, "2^43 MB (8796093022208)"),
        (str(2**44 - 2), 0, None, "2^44 - 2 MB (17592186044414)"),
        (str(2**44 - 1), 0, None, "EXACT UPPER BOUND: 2^44 - 1 MB (17592186044415)"),
        (str(2**44), 64, "out of range", "EXACT OVERFLOW BOUND: 2^44 MB (17592186044416)"),
        (str(2**44 + 1), 64, "out of range", "2^44 + 1 MB (17592186044417)"),
        ("18446744073709", 64, "out of range", "Vulnerability probe value (~1.84e13 > 2^44)"),
        ("100000000000000", 64, "out of range", "10^14 MB"),
        (str(2**60), 64, "out of range", "2^60 MB"),
        (str(2**63 - 1), 64, "out of range", "2^63 - 1 MB (i64 max)"),
        (str(2**63), 64, "out of range", "2^63 MB"),
        (str(2**64 - 2), 64, "out of range", "2^64 - 2 MB"),
        (str(2**64 - 1), 64, "out of range", "EXACT u64 MAX: 2^64 - 1 MB (18446744073709551615)"),
        (str(2**64), 64, "invalid --max-memory-mb", "EXACT u64 OVERFLOW: 2^64 MB (18446744073709551616)"),
        (str(2**64 + 1), 64, "invalid --max-memory-mb", "2^64 + 1 MB (18446744073709551617)"),
        (str(2**65), 64, "invalid --max-memory-mb", "2^65 MB"),
        (str(2**128), 64, "invalid --max-memory-mb", "2^128 MB"),
        (str(10**100), 64, "invalid --max-memory-mb", "10^100 MB (100 digits)"),
        ("9" * 1000, 64, "invalid --max-memory-mb", "1000 digits of 9"),
    ]

    for val_str, exp_rc, exp_msg, desc in boundary_cases:
        rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", val_str)
        passed = (rc == exp_rc) and check_no_panic(err, out)
        if exp_msg:
            passed = passed and (exp_msg in err)
        record(t_idx, f"Boundary: {desc}", passed, exp_rc, rc, err)
        t_idx += 1

    # -------------------------------------------------------------------------
    # SUITE 2: Negative Numbers, Signed Representation & Zero
    # -------------------------------------------------------------------------
    print("\n--- SUITE 2: Negative Numbers, Sign Representations & Zero ---")
    
    zero_and_negative_cases = [
        ("0", 64, "must be greater than 0", "Zero (0)"),
        ("00", 64, "must be greater than 0", "Double zero (00)"),
        ("000000000000", 64, "must be greater than 0", "Padded zeros"),
        ("-0", 64, "must be greater than 0", "Negative zero (-0)"),
        ("-1", 64, "invalid --max-memory-mb", "Negative one (-1)"),
        ("-2", 64, "invalid --max-memory-mb", "Negative two (-2)"),
        ("-100", 64, "invalid --max-memory-mb", "Negative 100 (-100)"),
        ("-17592186044415", 64, "invalid --max-memory-mb", "Negative sub-boundary (-17592186044415)"),
        ("-17592186044416", 64, "invalid --max-memory-mb", "Negative overflow bound (-17592186044416)"),
        (str(-2**63), 64, "invalid --max-memory-mb", "Negative i64 min (-9223372036854775808)"),
        ("-18446744073709551615", 64, "invalid --max-memory-mb", "Negative u64 max (-18446744073709551615)"),
        ("-18446744073709551616", 64, "invalid --max-memory-mb", "Negative u64 overflow (-18446744073709551616)"),
        ("+0", 64, "must be greater than 0", "Positive zero (+0)"),
        ("+1", 0, None, "Explicit positive (+1)"),
        ("+17592186044415", 0, None, "Explicit positive boundary (+17592186044415)"),
        ("+17592186044416", 64, "out of range", "Explicit positive overflow (+17592186044416)"),
    ]

    for val_str, exp_rc, exp_msg, desc in zero_and_negative_cases:
        rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", val_str)
        passed = (rc == exp_rc) and check_no_panic(err, out)
        if exp_msg:
            passed = passed and (exp_msg in err)
        record(t_idx, f"Sign/Zero: {desc}", passed, exp_rc, rc, err)
        t_idx += 1

    # -------------------------------------------------------------------------
    # SUITE 3: Non-Numeric, Floating Point, Formatting & Malformed Strings
    # -------------------------------------------------------------------------
    print("\n--- SUITE 3: Non-Numeric, Floating Point & Malformed Strings ---")

    malformed_cases = [
        ("", 64, "invalid --max-memory-mb", "Empty string"),
        (" ", 64, "invalid --max-memory-mb", "Single space"),
        ("   ", 64, "invalid --max-memory-mb", "Multiple spaces"),
        ("\t", 64, "invalid --max-memory-mb", "Tab character"),
        ("\n", 64, "invalid --max-memory-mb", "Newline character"),
        (" 100", 64, "invalid --max-memory-mb", "Leading whitespace"),
        ("100 ", 64, "invalid --max-memory-mb", "Trailing whitespace"),
        ("100MB", 64, "invalid --max-memory-mb", "Unit suffix 'MB'"),
        ("100M", 64, "invalid --max-memory-mb", "Unit suffix 'M'"),
        ("100MiB", 64, "invalid --max-memory-mb", "Unit suffix 'MiB'"),
        ("100 gb", 64, "invalid --max-memory-mb", "Unit suffix 'gb' with space"),
        ("0x10", 64, "invalid --max-memory-mb", "Hex prefix (0x10)"),
        ("0XFF", 64, "invalid --max-memory-mb", "Hex uppercase (0XFF)"),
        ("0b1010", 64, "invalid --max-memory-mb", "Binary prefix (0b1010)"),
        ("0o77", 64, "invalid --max-memory-mb", "Octal prefix (0o77)"),
        ("1.0", 64, "invalid --max-memory-mb", "Floating point 1.0"),
        ("1.5", 64, "invalid --max-memory-mb", "Floating point 1.5"),
        ("0.5", 64, "invalid --max-memory-mb", "Floating point 0.5"),
        (".5", 64, "invalid --max-memory-mb", "Leading dot .5"),
        ("1e6", 64, "invalid --max-memory-mb", "Scientific notation 1e6"),
        ("1e+6", 64, "invalid --max-memory-mb", "Scientific notation 1e+6"),
        ("1e-2", 64, "invalid --max-memory-mb", "Scientific notation 1e-2"),
        ("NaN", 64, "invalid --max-memory-mb", "Literal 'NaN'"),
        ("Inf", 64, "invalid --max-memory-mb", "Literal 'Inf'"),
        ("Infinity", 64, "invalid --max-memory-mb", "Literal 'Infinity'"),
        ("-Infinity", 64, "invalid --max-memory-mb", "Literal '-Infinity'"),
        ("null", 64, "invalid --max-memory-mb", "Literal 'null'"),
        ("undefined", 64, "invalid --max-memory-mb", "Literal 'undefined'"),
        ("true", 64, "invalid --max-memory-mb", "Literal 'true'"),
        ("false", 64, "invalid --max-memory-mb", "Literal 'false'"),
        ("abc", 64, "invalid --max-memory-mb", "Alpha string 'abc'"),
        ("12abc34", 64, "invalid --max-memory-mb", "Alpha-numeric embedded '12abc34'"),
        ("; rm -rf /", 64, "invalid --max-memory-mb", "Command injection string"),
        ("%s%s%s%s%n", 64, "invalid --max-memory-mb", "Format string probe"),
        ("\\0", 64, "invalid --max-memory-mb", "Escaped null"),
        ("9" * 10000, 64, "invalid --max-memory-mb", "10,000-character string buffer stress"),
    ]

    for val_str, exp_rc, exp_msg, desc in malformed_cases:
        rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", val_str)
        passed = (rc == exp_rc) and check_no_panic(err, out)
        if exp_msg:
            passed = passed and (exp_msg in err)
        record(t_idx, f"Malformed: {desc}", passed, exp_rc, rc, err)
        t_idx += 1

    # -------------------------------------------------------------------------
    # SUITE 4: Flag Position, Missing Arguments & Parsing Order
    # -------------------------------------------------------------------------
    print("\n--- SUITE 4: Missing Arguments & Flag Placement ---")

    # Missing value for --max-memory-mb at end
    rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb")
    passed = (rc == 64) and ("requires a positive integer" in err) and check_no_panic(err, out)
    record(t_idx, "Missing arg: trailing --max-memory-mb", passed, 64, rc, err)
    t_idx += 1

    # Another flag consumed as value: --max-memory-mb --format json
    rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", "--format", "json")
    passed = (rc == 64) and ("invalid --max-memory-mb" in err) and check_no_panic(err, out)
    record(t_idx, "Consumes next flag: --max-memory-mb --format json", passed, 64, rc, err)
    t_idx += 1

    # Pre-path flag placement: inspect --max-memory-mb 128 valid.gguf
    # Expect exit 64 because '128' is an unknown command-line argument
    rc, out, err = run_cli("inspect", "--max-memory-mb", "128", VALID_GGUF)
    passed = (rc == 64) and ("unknown argument" in err) and check_no_panic(err, out)
    record(t_idx, "Pre-path flag placement: inspect --max-memory-mb 128 <file>", passed, 64, rc, err)
    t_idx += 1

    # Duplicate flags: last wins or earlier fails?
    # Both valid
    rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", "100", "--max-memory-mb", "200")
    passed = (rc == 0) and check_no_panic(err, out)
    record(t_idx, "Duplicate flags: --max-memory-mb 100 --max-memory-mb 200", passed, 0, rc, err)
    t_idx += 1

    # Valid followed by invalid
    rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", "100", "--max-memory-mb", "17592186044416")
    passed = (rc == 64) and ("out of range" in err) and check_no_panic(err, out)
    record(t_idx, "Duplicate flags: valid then overflow (100 then 2^44)", passed, 64, rc, err)
    t_idx += 1

    # Invalid followed by valid (fails fast on first invalid)
    rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", "17592186044416", "--max-memory-mb", "100")
    passed = (rc == 64) and ("out of range" in err) and check_no_panic(err, out)
    record(t_idx, "Duplicate flags: overflow then valid (2^44 then 100)", passed, 64, rc, err)
    t_idx += 1

    # -------------------------------------------------------------------------
    # SUITE 5: Cross-Flag Matrix Interactions
    # -------------------------------------------------------------------------
    print("\n--- SUITE 5: Cross-Flag Matrix Interactions ---")

    matrix_cases = [
        # Sub-boundary (17592186044415 -> rc 0) and Overflow bound (17592186044416 -> rc 64)
        (["--format", "json"], "17592186044415", 0, "JSON format with 2^44 - 1"),
        (["--format", "json"], "17592186044416", 64, "JSON format with 2^44"),
        (["--format", "json"], "18446744073709551615", 64, "JSON format with 2^64 - 1"),
        (["--format", "json"], "18446744073709551616", 64, "JSON format with 2^64"),

        (["--endian", "auto"], "17592186044415", 0, "Endian auto with 2^44 - 1"),
        (["--endian", "auto"], "17592186044416", 64, "Endian auto with 2^44"),
        (["--endian", "big"], "17592186044415", 2, "Endian big on LE file with 2^44 - 1 (REJECT exit 2)"),
        (["--endian", "big"], "17592186044416", 64, "Endian big on LE file with 2^44 (USAGE exit 64)"),

        (["--profile", "llama-cpp"], "17592186044415", 0, "Profile llama-cpp with 2^44 - 1"),
        (["--profile", "llama-cpp"], "17592186044416", 64, "Profile llama-cpp with 2^44"),
        (["--profile", "gguf-spec"], "17592186044415", 0, "Profile gguf-spec with 2^44 - 1"),
        (["--profile", "gguf-spec"], "17592186044416", 64, "Profile gguf-spec with 2^44"),

        (["--max-work-budget", "10000000"], "17592186044415", 0, "Work-budget 10M with 2^44 - 1"),
        (["--max-work-budget", "10000000"], "17592186044416", 64, "Work-budget 10M with 2^44"),
        (["--max-work-budget", "18446744073709551615"], "17592186044415", 0, "Max u64 work-budget with 2^44 - 1"),
        (["--max-work-budget", "18446744073709551616"], "17592186044415", 64, "Overflow work-budget with 2^44 - 1"),

        (["--max-variable-array-elements", "1000000"], "17592186044415", 0, "Variable array 1M with 2^44 - 1"),
        (["--max-variable-array-elements", "1000000"], "17592186044416", 64, "Variable array 1M with 2^44"),
    ]

    for extra_flags, mem_val, exp_rc, desc in matrix_cases:
        args = ["inspect", VALID_GGUF] + extra_flags + ["--max-memory-mb", mem_val]
        rc, out, err = run_cli(*args)
        passed = (rc == exp_rc) and check_no_panic(err, out)
        record(t_idx, f"Matrix: {desc}", passed, exp_rc, rc, err)
        t_idx += 1

    # -------------------------------------------------------------------------
    # SUITE 6: Functional Memory Quota & Diverse Model Fixtures
    # -------------------------------------------------------------------------
    print("\n--- SUITE 6: Functional Memory Quota & Diverse Model Fixtures ---")

    # 1. Non-existent file with valid --max-memory-mb -> exit 74 (IOERR)
    rc, out, err = run_cli("inspect", "tests/fixtures/non_existent_file.gguf", "--max-memory-mb", "17592186044415")
    passed = (rc == 74) and check_no_panic(err, out)
    record(t_idx, "Non-existent file with valid 2^44-1 (IOERR)", passed, 74, rc, err)
    t_idx += 1

    # 2. Non-existent file with overflow --max-memory-mb -> exit 64 (fails before file open)
    rc, out, err = run_cli("inspect", "tests/fixtures/non_existent_file.gguf", "--max-memory-mb", "17592186044416")
    passed = (rc == 64) and ("out of range" in err) and check_no_panic(err, out)
    record(t_idx, "Non-existent file with overflow 2^44 (fails fast at flag)", passed, 64, rc, err)
    t_idx += 1

    # 3. Known negative fixture with valid 2^44-1 -> exit 2 (REJECT, safe rejection)
    neg_fixture = os.path.join(FIXTURES_DIR, "alloc_dos_tensor.gguf")
    if os.path.exists(neg_fixture):
        rc, out, err = run_cli("inspect", neg_fixture, "--max-memory-mb", "17592186044415")
        passed = (rc == 2) and check_no_panic(err, out)
        record(t_idx, "Negative fixture with 2^44-1 memory limit (must exit 2 REJECT)", passed, 2, rc, err)
        t_idx += 1

        # 4. Known negative fixture with overflow 2^44 -> exit 64 (rejected at flag)
        rc, out, err = run_cli("inspect", neg_fixture, "--max-memory-mb", "17592186044416")
        passed = (rc == 64) and ("out of range" in err) and check_no_panic(err, out)
        record(t_idx, "Negative fixture with 2^44 memory limit (rejected at flag exit 64)", passed, 64, rc, err)
        t_idx += 1

    # 5. Big-Endian V3 fixture
    be_fixture = os.path.join(FIXTURES_DIR, "big_endian_v3.gguf")
    if os.path.exists(be_fixture):
        rc, out, err = run_cli("inspect", be_fixture, "--endian", "auto", "--max-memory-mb", "17592186044415")
        passed = (rc == 0) and check_no_panic(err, out)
        record(t_idx, "BE v3 fixture with --endian auto and 2^44-1 (PASS exit 0)", passed, 0, rc, err)
        t_idx += 1

        rc, out, err = run_cli("inspect", be_fixture, "--endian", "auto", "--max-memory-mb", "17592186044416")
        passed = (rc == 64) and ("out of range" in err) and check_no_panic(err, out)
        record(t_idx, "BE v3 fixture with --endian auto and 2^44 (USAGE exit 64)", passed, 64, rc, err)
        t_idx += 1

    # 6. Version 2 fixture (admitted under llama-cpp profile)
    v2_fixture = os.path.join(FIXTURES_DIR, "version_2.gguf")
    if os.path.exists(v2_fixture):
        rc, out, err = run_cli("inspect", v2_fixture, "--profile", "llama-cpp", "--max-memory-mb", "17592186044415")
        passed = (rc == 0) and check_no_panic(err, out)
        record(t_idx, "GGUF v2 fixture with --profile llama-cpp and 2^44-1 (PASS exit 0)", passed, 0, rc, err)
        t_idx += 1

        rc, out, err = run_cli("inspect", v2_fixture, "--profile", "llama-cpp", "--max-memory-mb", "17592186044416")
        passed = (rc == 64) and ("out of range" in err) and check_no_panic(err, out)
        record(t_idx, "GGUF v2 fixture with --profile llama-cpp and 2^44 (USAGE exit 64)", passed, 64, rc, err)
        t_idx += 1

    # 7. CVE arithmetic overflow scenario fixture
    cve_fixture = os.path.join(FIXTURES_DIR, "security_testbed", "scenario1_dimension_arithmetic_overflow.gguf")
    if os.path.exists(cve_fixture):
        rc, out, err = run_cli("inspect", cve_fixture, "--max-memory-mb", "17592186044415")
        passed = (rc == 2) and check_no_panic(err, out)
        record(t_idx, "CVE arithmetic overflow fixture with 2^44-1 (REJECT exit 2)", passed, 2, rc, err)
        t_idx += 1

        rc, out, err = run_cli("inspect", cve_fixture, "--max-memory-mb", "17592186044416")
        passed = (rc == 64) and ("out of range" in err) and check_no_panic(err, out)
        record(t_idx, "CVE arithmetic overflow fixture with 2^44 (USAGE exit 64)", passed, 64, rc, err)
        t_idx += 1

    # 8. Dynamic fixture creating high memory allocation to verify QuotaAllocator trigger (exit 2)
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as tf:
        temp_path = tf.name
    try:
        # Create a ~1.8 MB metadata fixture with valid lowercase keys
        b = bytearray()
        b += b"GGUF"
        b += struct.pack("<IQQ", 3, 0, 30)
        prefix_fmt = "k_%05d_"
        for i in range(30):
            k = (prefix_fmt % i).encode("ascii") + b"x" * 60000
            b += struct.pack("<Q", len(k))
            b += k
            b += struct.pack("<II", 4, 0)
        pad = (32 - (len(b) % 32)) % 32
        b += b"\x00" * pad
        with open(temp_path, "wb") as f:
            f.write(b)

        # Insufficient quota: --max-memory-mb 1 on 1.8MB model -> exit 2 (E_TotalAllocationLimitExceeded)
        rc, out, err = run_cli("inspect", temp_path, "--max-memory-mb", "1")
        passed = (rc == 2) and ("E_TotalAllocationLimitExceeded" in err) and check_no_panic(err, out)
        record(t_idx, "Functional quota exhaustion: --max-memory-mb 1 on 1.8MB model (exit 2, NOT 70)", passed, 2, rc, err)
        t_idx += 1

        # Sufficient quota: --max-memory-mb 5 on 1.8MB model -> exit 0
        rc, out, err = run_cli("inspect", temp_path, "--max-memory-mb", "5")
        passed = (rc == 0) and check_no_panic(err, out)
        record(t_idx, "Sufficient quota: --max-memory-mb 5 on 1.8MB model (exit 0 PASS)", passed, 0, rc, err)
        t_idx += 1

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # -------------------------------------------------------------------------
    # SUITE 7: Pseudo-Random & Mutational Boundary Fuzzing
    # -------------------------------------------------------------------------
    print("\n--- SUITE 7: Pseudo-Random & Mutational Boundary Fuzzing ---")

    random.seed(0x5AFE660F)
    fuzz_passes = 0
    fuzz_total = 50

    for i in range(fuzz_total):
        # Generate random mutations around boundary points
        choice = random.choice([
            "sub_2_44", "over_2_44", "over_2_64", "random_string", "random_negative"
        ])

        if choice == "sub_2_44":
            delta = random.randint(1, 1000000)
            val = str((2**44 - 1) - delta)
            exp_rc = 0
        elif choice == "over_2_44":
            delta = random.randint(0, 1000000)
            val = str(2**44 + delta)
            exp_rc = 64
        elif choice == "over_2_64":
            delta = random.randint(0, 1000000)
            val = str(2**64 + delta)
            exp_rc = 64
        elif choice == "random_negative":
            val = str(-random.randint(1, 2**64))
            exp_rc = 64
        else: # random_string
            chars = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
            val = "".join(random.choice(chars) for _ in range(random.randint(1, 20)))
            exp_rc = 64

        rc, out, err = run_cli("inspect", VALID_GGUF, "--max-memory-mb", val)
        ok = (rc == exp_rc) and check_no_panic(err, out)
        if ok:
            fuzz_passes += 1
        else:
            print(f"  [FUZZ FAIL] val='{val[:30]}': exp={exp_rc}, got={rc}, err={err.strip()[:60]}")

    record(t_idx, f"Fuzzing sweep: {fuzz_total} randomized boundary inputs", fuzz_passes == fuzz_total, fuzz_total, fuzz_passes)
    t_idx += 1

    # -------------------------------------------------------------------------
    # FINAL RECAP
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("FINAL SUMMARY REPORT")
    print("=" * 70)
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r["passed"])
    failed_tests = total_tests - passed_tests
    print(f"Total Tests Run: {total_tests}")
    print(f"Total Passed:    {passed_tests}")
    print(f"Total Failed:    {failed_tests}")

    if failed_tests > 0:
        print("\nFAILING TESTS:")
        for r in results:
            if not r["passed"]:
                print(f"  [FAIL] #{r['id']} {r['name']}: expected={r['expected']}, got={r['actual']}")
        return False
    else:
        print("\nALL ADVERSARIAL AND BOUNDARY TESTS PASSED WITH ZERO CRASHES AND ZERO PANICS!")
        return True

if __name__ == "__main__":
    success = run_suite()
    sys.exit(0 if success else 1)
