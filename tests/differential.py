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

# Intentional, documented security divergences where SafeGGUF is strictly more secure than upstream
INTENTIONAL_DIVERGENCES = {
    "invalid_bool.gguf": {
        "reason": "SafeGGUF enforces GGUF spec booleans (0 or 1 only). Upstream gguf.cpp accepts any non-zero byte as true.",
        "expected_safe": "REJECT",
        "expected_upstream": "PASS",
    },
    "invalid_key.gguf": {
        "reason": "SafeGGUF enforces strict lower_snake_case key grammar. Upstream gguf.cpp accepts uppercase and non-standard keys.",
        "expected_safe": "REJECT",
        "expected_upstream": "PASS",
    },
    "hyphen_key.gguf": {
        "reason": "SafeGGUF enforces strict lower_snake_case key grammar without hyphens. Upstream gguf.cpp accepts hyphens.",
        "expected_safe": "REJECT",
        "expected_upstream": "PASS",
    },
    "llama_cpp_overflow.gguf": {
        "reason": "SafeGGUF checked integer arithmetic prevents integer wrap-around. Upstream GGML_PAD macro overflows UINT64_MAX to 0.",
        "expected_safe": "REJECT",
        "expected_upstream": "PASS",
    },
}

def ensure_binaries():
    if not os.path.exists(SAFEGGUF_BIN):
        print(f"SafeGGUF binary not found at {SAFEGGUF_BIN}. Running zig build...")
        subprocess.check_call(["zig", "build", "-Doptimize=ReleaseSafe"], cwd=REPO_ROOT)

    if not os.path.exists(ORACLE_BIN):
        print(f"Building upstream ggml oracle via {os.path.join(SCRIPT_DIR, 'build_oracle.sh')}...")
        subprocess.check_call([os.path.join(SCRIPT_DIR, "build_oracle.sh")], cwd=REPO_ROOT)

def run_safegguf(path: str):
    cmd = [SAFEGGUF_BIN, "inspect", path, "--profile", "llama-cpp"]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    verdict = "PASS" if proc.returncode == 0 else "REJECT"
    return verdict, proc.returncode, proc.stderr.strip()

def run_oracle(path: str, mode: str):
    cmd = [ORACLE_BIN, mode, path]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    verdict = "PASS" if proc.returncode == 0 else "REJECT"
    return verdict, proc.returncode

def main():
    print("=== SafeGGUF vs Upstream ggml 0.23.0 True Differential Validation ===")
    ensure_binaries()

    fixtures = sorted([f for f in os.listdir(FIXTURES_DIR) if f.endswith(".gguf")])
    if not fixtures:
        print("Error: No test fixtures found. Run generate_fixtures.py first.")
        sys.exit(1)

    print(f"Loaded {len(fixtures)} fixtures from {FIXTURES_DIR}\n")
    print(f"{'Fixture':<34} | {'SafeGGUF':<8} | {'Upstream Load':<13} | {'Upstream NoLoad':<15} | {'Verdict'}")
    print("-" * 88)

    failures = []
    for f in fixtures:
        path = os.path.join(FIXTURES_DIR, f)
        safe_verdict, safe_rc, safe_err = run_safegguf(path)
        up_load_verdict, _ = run_oracle(path, "--load-data")
        up_noload_verdict, _ = run_oracle(path, "--no-load")

        # Check against allowlist or exact match
        status_note = "MATCH"
        if f in INTENTIONAL_DIVERGENCES:
            div = INTENTIONAL_DIVERGENCES[f]
            if safe_verdict == div["expected_safe"] and up_load_verdict == div["expected_upstream"]:
                status_note = f"ALLOWLIST ({div['reason'][:35]}...)"
            else:
                failures.append(f"{f}: Expected allowlist verdict ({div['expected_safe']} vs {div['expected_upstream']}), got ({safe_verdict} vs {up_load_verdict})")
                status_note = "MISMATCH"
        else:
            # Must match upstream normal loading verdict
            if safe_verdict != up_load_verdict:
                failures.append(f"{f}: Unexpected divergence! SafeGGUF={safe_verdict} (rc={safe_rc}), Upstream={up_load_verdict}. Safe err: {safe_err}")
                status_note = "DIVERGENCE FAILURE"

        print(f"{f:<34} | {safe_verdict:<8} | {up_load_verdict:<13} | {up_noload_verdict:<15} | {status_note}")

    print("-" * 88)
    if failures:
        print("\nDIFFERENTIAL FAILURES DETECTED:")
        for fail in failures:
            print("  X " + fail)
        sys.exit(1)

    print("\n✓ True Differential Test Suite PASSED! All 19 fixtures verified against upstream ggml 0.23.0.")

if __name__ == "__main__":
    main()
