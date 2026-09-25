"""
Adversarial stress and edge-case challenge harness for Challenger M1_2 Gen 2.
Empirically tests boundaries, overflows, environment fallbacks, IO errors,
and flag permutations against SafeGGUF.
"""

import os
import subprocess
import sys

BIN = os.path.abspath(r".\zig-out\bin\safegguf.exe")
VALID_GGUF = os.path.abspath(r"tests/fixtures/valid.gguf")
EXPLOIT_GGUF = os.path.abspath(r"tests/fixtures/negative/cve-2025-53630-cumulative-overflow.gguf")

passed = 0
failed = 0

def test(name, cmd, expected_rc, env=None, check_stderr=None):
    global passed, failed
    base_env = os.environ.copy()
    if env:
        base_env.update(env)
    res = subprocess.run(cmd, capture_output=True, text=True, env=base_env)
    
    ok = (res.returncode == expected_rc)
    if check_stderr and check_stderr not in res.stderr:
        ok = False
        
    if ok:
        print(f"  [PASS] {name} (rc={res.returncode})")
        passed += 1
    else:
        print(f"  [FAIL] {name} (expected rc={expected_rc}, got rc={res.returncode})")
        if res.stdout:
            print(f"         stdout: {res.stdout.strip()[:150]}")
        if res.stderr:
            print(f"         stderr: {res.stderr.strip()[:150]}")
        failed += 1

print(f"Testing SafeGGUF executable: {BIN}")
print("==================================================")
print("SECTION 1: Exact Bit Boundary Checks on --max-memory-mb")
print("==================================================")

# 2^44 - 1: valid memory, should PASS (rc=0)
test("--max-memory-mb 2^44-1 (17592186044415)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "17592186044415"], 0)

# 2^44: first overflow, must EX_USAGE (rc=64)
test("--max-memory-mb 2^44 (17592186044416)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "17592186044416"], 64, check_stderr="out of range")

# 2^44 + 1: must EX_USAGE (rc=64)
test("--max-memory-mb 2^44+1 (17592186044417)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "17592186044417"], 64, check_stderr="out of range")

# 2^64 - 1: max u64, must EX_USAGE (rc=64)
test("--max-memory-mb 2^64-1 (18446744073709551615)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "18446744073709551615"], 64, check_stderr="out of range")

# 2^64: u64 parse overflow, must EX_USAGE (rc=64)
test("--max-memory-mb 2^64 (18446744073709551616)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "18446744073709551616"], 64, check_stderr="invalid --max-memory-mb value")

# 2^65: large parse overflow, must EX_USAGE (rc=64)
test("--max-memory-mb 2^65 (36893488147419103232)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "36893488147419103232"], 64, check_stderr="invalid --max-memory-mb value")

# Zero values
test("--max-memory-mb 0", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "0"], 64, check_stderr="must be greater than 0")
test("--max-memory-mb 0000", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "0000"], 64, check_stderr="must be greater than 0")

# Leading zeros on positive number
test("--max-memory-mb 000128 (leading zeros)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "000128"], 0)

# Hex / Octal / Float / Noise
test("--max-memory-mb 0x80 (hex)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "0x80"], 64)
test("--max-memory-mb 128.5 (float)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "128.5"], 64)
test("--max-memory-mb 1e6 (sci)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "1e6"], 64)

print("\n==================================================")
print("SECTION 2: Exact Bit Boundary Checks on --max-work-budget")
print("==================================================")

# Zero work budget
test("--max-work-budget 0", 
     [BIN, "inspect", VALID_GGUF, "--max-work-budget", "0"], 64, check_stderr="must be greater than 0")

# 1 work budget (exceeds budget -> rc=2 REJECT)
test("--max-work-budget 1 (exceeded on valid)", 
     [BIN, "inspect", VALID_GGUF, "--max-work-budget", "1"], 2)

# Max u64 budget: 18446744073709551615 (valid -> rc=0)
test("--max-work-budget 2^64-1 (18446744073709551615)", 
     [BIN, "inspect", VALID_GGUF, "--max-work-budget", "18446744073709551615"], 0)

# 2^64 parse overflow (rc=64)
test("--max-work-budget 2^64 (18446744073709551616)", 
     [BIN, "inspect", VALID_GGUF, "--max-work-budget", "18446744073709551616"], 64)

print("\n==================================================")
print("SECTION 3: Flag Ordering and Contract Adherence")
print("==================================================")

# Strict positional syntax contract: positional file path must precede options
test("Positional contract enforcement (flags before file must fail with rc=64)", 
     [BIN, "inspect", "--max-memory-mb", "64", VALID_GGUF], 64)

test("Options strictly after file path (valid invocation)", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "64"], 0)

test("Multiple options after file: --max-memory-mb 64 --max-work-budget 1000000", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "64", "--max-work-budget", "1000000"], 0)

test("Overriding flags: --max-memory-mb 1 --max-memory-mb 1000", 
     [BIN, "inspect", VALID_GGUF, "--max-memory-mb", "1", "--max-memory-mb", "1000"], 0)

test("Unknown flag: --bogus-flag", 
     [BIN, "inspect", VALID_GGUF, "--bogus-flag"], 64, check_stderr="unknown argument")

print("\n==================================================")
print("SECTION 4: Environment Variable Overflow Immunity")
print("==================================================")

# Environment variables must NEVER crash, they fallback cleanly to defaults
test("ENV SAFEGGUF_MAX_MEMORY_MB=17592186044416 (overflow fallback)", 
     [BIN, "inspect", VALID_GGUF], 0, env={"SAFEGGUF_MAX_MEMORY_MB": "17592186044416"})

test("ENV SAFEGGUF_MAX_MEMORY_MB=18446744073709551615 (u64 max overflow fallback)", 
     [BIN, "inspect", VALID_GGUF], 0, env={"SAFEGGUF_MAX_MEMORY_MB": "18446744073709551615"})

test("ENV SAFEGGUF_MAX_MEMORY_MB=18446744073709551616 (parse overflow fallback)", 
     [BIN, "inspect", VALID_GGUF], 0, env={"SAFEGGUF_MAX_MEMORY_MB": "18446744073709551616"})

test("ENV SAFEGGUF_MAX_WORK_BUDGET=18446744073709551616 (parse overflow fallback)", 
     [BIN, "inspect", VALID_GGUF], 0, env={"SAFEGGUF_MAX_WORK_BUDGET": "18446744073709551616"})

test("ENV SAFEGGUF_MAX_ALLOC_BYTES=18446744073709551616 (parse overflow fallback)", 
     [BIN, "inspect", VALID_GGUF], 0, env={"SAFEGGUF_MAX_ALLOC_BYTES": "18446744073709551616"})

print("\n==================================================")
print("SECTION 5: File IO and Failure Modes (EX_IOERR = 74)")
print("==================================================")

test("Non-existent file", 
     [BIN, "inspect", "tests/fixtures/non_existent_file_12345.gguf"], 74)

test("Directory path instead of file", 
     [BIN, "inspect", "tests/fixtures"], 74)

# Create an empty file
empty_path = os.path.abspath(r"tests/fixtures/adversarial_empty.gguf")
with open(empty_path, "wb") as f:
    pass

try:
    test("Zero-byte file (must reject with rc=2, E_UnexpectedEof)", 
         [BIN, "inspect", empty_path], 2)
finally:
    if os.path.exists(empty_path):
        os.remove(empty_path)

print("\n==================================================")
print("SECTION 6: Adversarial Rejection Stability on Exploit")
print("==================================================")

test("Exploit file with normal options (rc=2)", 
     [BIN, "inspect", EXPLOIT_GGUF], 2)

test("Exploit file with high memory & budget (rc=2)", 
     [BIN, "inspect", EXPLOIT_GGUF, "--max-memory-mb", "10000", "--max-work-budget", "100000000"], 2)

test("Exploit file with json output (rc=2)", 
     [BIN, "inspect", EXPLOIT_GGUF, "--format", "json"], 2)

test("Exploit file with llama-cpp profile (rc=2)", 
     [BIN, "inspect", EXPLOIT_GGUF, "--profile", "llama-cpp"], 2)

print("\n==================================================")
print(f"FINAL CHALLENGE SUMMARY: {passed} PASSED, {failed} FAILED")
print("==================================================")

if failed > 0:
    sys.exit(1)
sys.exit(0)
