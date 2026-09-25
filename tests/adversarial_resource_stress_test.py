#!/usr/bin/env python3
"""
Adversarial Resource Limit & Boundary Stress Test Suite for SafeGGUF
Author: Challenger M1_2 (Empirical Adversarial Reviewer)

Tests:
1. CLI flags --max-memory-mb and --max-work-budget:
   - Valid boundaries (1, 10000000)
   - Invalid boundaries (0, -1, non-numeric strings -> exit 64)
   - Extreme boundaries and overflow analysis
2. Environment variables SAFEGGUF_MAX_MEMORY_MB and SAFEGGUF_MAX_WORK_BUDGET:
   - Low thresholds on valid models -> exit 2 REJECT (never 70 OOM)
   - High thresholds -> exit 0 PASS
   - Malformed/invalid env vars fallback safely to default limits
3. QuotaAllocator host OOM (exit 70) resistance across malicious fixtures
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import time

BINARY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zig-out", "bin", "safegguf")
if sys.platform == "win32" and not BINARY.endswith(".exe") and os.path.exists(BINARY + ".exe"):
    BINARY += ".exe"

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
NEGATIVE_DIR = os.path.join(FIXTURES_DIR, "negative")
SECURITY_DIR = os.path.join(FIXTURES_DIR, "security_testbed")
VALID_GGUF = os.path.join(FIXTURES_DIR, "valid.gguf")

test_results = []

def record(test_name, passed, detail=""):
    test_results.append({
        "name": test_name,
        "passed": passed,
        "detail": detail
    })
    status_str = "PASS" if passed else "FAIL"
    print(f"[{status_str}] {test_name}: {detail}")

def run_cmd(*args, env=None, timeout=15):
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

def create_metadata_fixture(path, num_keys, key_len):
    """Creates a valid GGUF file with arbitrary metadata size for quota testing."""
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<IQQ", 3, 0, num_keys)
    prefix_fmt = "k_%05d_"
    for i in range(num_keys):
        prefix = (prefix_fmt % i).encode("ascii")
        k = prefix + b"x" * max(0, key_len - len(prefix))
        b += struct.pack("<Q", len(k))
        b += k
        b += struct.pack("<II", 4, 0)  # uint32, val = 0
    pad = (32 - (len(b) % 32)) % 32
    b += b"\x00" * pad
    with open(path, "wb") as f:
        f.write(b)

def run_tests():
    print(f"Running SafeGGUF Resource Boundary & Stress Harness on {BINARY}...\n")
    if not os.path.exists(BINARY):
        print(f"FATAL: Binary not found at {BINARY}")
        sys.exit(1)

    # =========================================================================
    # PART 1: CLI Flags Boundary & Stress Testing
    # =========================================================================
    print("=== PART 1: CLI Flags Boundary & Stress Testing ===")

    # 1.1 Valid Boundary Values
    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-memory-mb", "1")
    record("CLI: --max-memory-mb 1 on valid.gguf", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-memory-mb", "10000000")
    record("CLI: --max-memory-mb 10000000 on valid.gguf", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-work-budget", "1")
    record("CLI: --max-work-budget 1 on valid.gguf (exceeds budget)", rc == 2 and "E_ResourceLimitExceeded" in err, f"rc={rc}, err={err.strip()[:60]}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-work-budget", "10000000")
    record("CLI: --max-work-budget 10000000 on valid.gguf", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-memory-mb", "10000000", "--max-work-budget", "10000000")
    record("CLI: Combined high boundaries (10M MB + 10M work)", rc == 0, f"rc={rc}")

    # 1.2 Invalid Boundary Values (must exit 64 EX_USAGE)
    invalid_flag_cases = [
        ("--max-memory-mb", "0", "zero memory"),
        ("--max-memory-mb", "-1", "negative memory"),
        ("--max-memory-mb", "abc", "non-numeric string memory"),
        ("--max-memory-mb", "", "empty string memory"),
        ("--max-work-budget", "0", "zero work budget"),
        ("--max-work-budget", "-1", "negative work budget"),
        ("--max-work-budget", "abc", "non-numeric string work budget"),
        ("--max-work-budget", "", "empty string work budget"),
    ]
    for flag, val, desc in invalid_flag_cases:
        args = ["inspect", VALID_GGUF, flag]
        if val != "":
            args.append(val)
        else:
            args.append("")
        rc, out, err = run_cmd(*args)
        record(f"CLI invalid: {flag} '{val}' ({desc})", rc == 64, f"rc={rc}, err={err.strip()[:60]}")

    # Missing argument cases
    for flag in ["--max-memory-mb", "--max-work-budget"]:
        rc, out, err = run_cmd("inspect", VALID_GGUF, flag)
        record(f"CLI missing arg: {flag}", rc == 64, f"rc={rc}, err={err.strip()[:60]}")

    # Overflow in parseInt (> u64 max)
    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-memory-mb", "18446744073709551616")
    record("CLI overflow parse: --max-memory-mb 18446744073709551616", rc == 64, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-work-budget", "18446744073709551616")
    record("CLI overflow parse: --max-work-budget 18446744073709551616", rc == 64, f"rc={rc}")

    # 1.3 Vulnerability Probe: Arithmetic overflow in parsed * 1024 * 1024
    # Value fits in u64, but parsed * 1048576 overflows u64
    rc, out, err = run_cmd("inspect", VALID_GGUF, "--max-memory-mb", "18446744073709")
    is_vulnerable = (rc == 1 or "panic: integer overflow" in err or "panic" in err)
    record("VULNERABILITY PROBE: --max-memory-mb 18446744073709 unchecked mul overflow",
           not is_vulnerable,
           f"rc={rc} (CRASH/PANIC exit code 1 if vulnerable: {err.strip()[:80]})")

    # =========================================================================
    # PART 2: Environment Variables Testing
    # =========================================================================
    print("\n=== PART 2: Environment Variables Testing ===")

    # 2.1 Low thresholds on valid models -> expect exit 2 REJECT
    # SAFEGGUF_MAX_WORK_BUDGET=1 on valid.gguf
    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_WORK_BUDGET": "1"})
    record("ENV: SAFEGGUF_MAX_WORK_BUDGET=1 on valid.gguf", rc == 2 and "E_ResourceLimitExceeded" in err, f"rc={rc}, err={err.strip()[:60]}")

    # SAFEGGUF_MAX_ALLOC_BYTES=1 on valid.gguf
    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_ALLOC_BYTES": "1"})
    record("ENV: SAFEGGUF_MAX_ALLOC_BYTES=1 on valid.gguf", rc == 2 and "E_TotalAllocationLimitExceeded" in err, f"rc={rc}, err={err.strip()[:60]}")

    # Create a 1.8 MB valid fixture to test SAFEGGUF_MAX_MEMORY_MB=1
    temp_mem_path = os.path.join(FIXTURES_DIR, "temp_challenger_mem_test.gguf")
    try:
        create_metadata_fixture(temp_mem_path, num_keys=30, key_len=60000)

        # SAFEGGUF_MAX_MEMORY_MB=1 on 1.8 MB fixture (exceeds 1MB cap -> exit 2)
        rc, out, err = run_cmd("inspect", temp_mem_path, env={"SAFEGGUF_MAX_MEMORY_MB": "1"})
        record("ENV: SAFEGGUF_MAX_MEMORY_MB=1 on 1.8MB fixture", rc == 2 and "E_TotalAllocationLimitExceeded" in err, f"rc={rc}, err={err.strip()[:60]}")

        # SAFEGGUF_MAX_MEMORY_MB=5 on 1.8 MB fixture (sufficient -> exit 0)
        rc, out, err = run_cmd("inspect", temp_mem_path, env={"SAFEGGUF_MAX_MEMORY_MB": "5"})
        record("ENV: SAFEGGUF_MAX_MEMORY_MB=5 on 1.8MB fixture", rc == 0, f"rc={rc}")

        # CLI flag --max-memory-mb 1 on 1.8MB fixture
        rc, out, err = run_cmd("inspect", temp_mem_path, "--max-memory-mb", "1")
        record("CLI: --max-memory-mb 1 on 1.8MB fixture", rc == 2 and "E_TotalAllocationLimitExceeded" in err, f"rc={rc}")

        # CLI flag --max-memory-mb 5 on 1.8MB fixture
        rc, out, err = run_cmd("inspect", temp_mem_path, "--max-memory-mb", "5")
        record("CLI: --max-memory-mb 5 on 1.8MB fixture", rc == 0, f"rc={rc}")

    finally:
        if os.path.exists(temp_mem_path):
            os.remove(temp_mem_path)

    # 2.2 High thresholds on valid models -> expect exit 0 PASS
    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_WORK_BUDGET": "10000000"})
    record("ENV: SAFEGGUF_MAX_WORK_BUDGET=10000000 on valid.gguf", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_MEMORY_MB": "1000"})
    record("ENV: SAFEGGUF_MAX_MEMORY_MB=1000 on valid.gguf", rc == 0, f"rc={rc}")

    # 2.3 Fallback and Resiliency: Malformed environment variables
    # Must fallback safely to default without crash or failure
    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_MEMORY_MB": "0"})
    record("ENV fallback: SAFEGGUF_MAX_MEMORY_MB=0 (defaults to 128MB)", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_MEMORY_MB": "-1"})
    record("ENV fallback: SAFEGGUF_MAX_MEMORY_MB=-1 (defaults to 128MB)", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_MEMORY_MB": "non_numeric"})
    record("ENV fallback: SAFEGGUF_MAX_MEMORY_MB=non_numeric (defaults to 128MB)", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_WORK_BUDGET": "0"})
    record("ENV fallback: SAFEGGUF_MAX_WORK_BUDGET=0 (defaults to 10M)", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_WORK_BUDGET": "-1"})
    record("ENV fallback: SAFEGGUF_MAX_WORK_BUDGET=-1 (defaults to 10M)", rc == 0, f"rc={rc}")

    rc, out, err = run_cmd("inspect", VALID_GGUF, env={"SAFEGGUF_MAX_WORK_BUDGET": "non_numeric"})
    record("ENV fallback: SAFEGGUF_MAX_WORK_BUDGET=non_numeric (defaults to 10M)", rc == 0, f"rc={rc}")

    # =========================================================================
    # PART 3: QuotaAllocator Host OOM (Exit 70) Prevention
    # =========================================================================
    print("\n=== PART 3: QuotaAllocator Host OOM Prevention ===")

    # 3.1 134 MB DoS Bomb fixture (scenario3_quota_alloc_ceiling_dos.gguf)
    s3_dos = os.path.join(SECURITY_DIR, "scenario3_quota_alloc_ceiling_dos.gguf")
    if os.path.exists(s3_dos):
        rc, out, err = run_cmd("inspect", s3_dos)
        record("QuotaAllocator DoS Bomb: scenario3_quota_alloc_ceiling_dos.gguf",
               rc == 2 and "E_TotalAllocationLimitExceeded" in err and rc != 70,
               f"rc={rc} (NEVER exit 70)")
    else:
        print(f"Skipping {s3_dos} (not found)")

    # 3.2 Negative corpus allocation stress fixtures
    negative_corpus_alloc_files = [
        "synthetic-alloc-key-string-len-dos.gguf",
        "synthetic-alloc-kv-count-dos.gguf",
        "synthetic-metadata-array-count-dos.gguf"
    ]
    for fname in negative_corpus_alloc_files:
        fpath = os.path.join(NEGATIVE_DIR, fname)
        if os.path.exists(fpath):
            rc, out, err = run_cmd("inspect", fpath)
            record(f"Negative corpus: {fname}", rc == 2 and rc != 70, f"rc={rc} (NEVER exit 70)")

    # 3.3 Sweep ALL 15 negative corpus files to ensure NO host OOM (exit 70)
    print("\nScanning all files in tests/fixtures/negative/...")
    negative_files = [os.path.join(NEGATIVE_DIR, f) for f in os.listdir(NEGATIVE_DIR) if f.endswith(".gguf")]
    all_neg_rejected_properly = True
    any_host_oom = False
    for nf in negative_files:
        rc, out, err = run_cmd("inspect", nf)
        if rc == 70:
            any_host_oom = True
        if rc != 2:
            all_neg_rejected_properly = False
    record(f"Negative Corpus Full Sweep ({len(negative_files)} files) exit 2 and NEVER 70",
           all_neg_rejected_properly and not any_host_oom,
           f"all_rejected={all_neg_rejected_properly}, host_oom_detected={any_host_oom}")

    # 3.4 Sweep ALL security testbed files
    print("\nScanning all files in tests/fixtures/security_testbed/...")
    sec_files = [os.path.join(SECURITY_DIR, f) for f in os.listdir(SECURITY_DIR) if f.endswith(".gguf")]
    all_sec_safe = True
    sec_oom = False
    for sf in sec_files:
        rc, out, err = run_cmd("inspect", sf)
        if rc == 70:
            sec_oom = True
            all_sec_safe = False
    record(f"Security Testbed Full Sweep ({len(sec_files)} files) ZERO host OOM (exit 70)",
           not sec_oom,
           f"sec_oom={sec_oom}")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n================== SUMMARY ==================")
    total = len(test_results)
    passed = sum(1 for t in test_results if t["passed"])
    failed = total - passed
    print(f"Total Tests: {total}")
    print(f"Passed:      {passed}")
    print(f"Failed:      {failed}")

    if failed > 0:
        print("\nFailures:")
        for t in test_results:
            if not t["passed"]:
                print(f"  - {t['name']}: {t['detail']}")
    print("=============================================\n")

    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
