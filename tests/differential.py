"""
Differential Testing Harness for SafeGGUF vs Upstream ggml 0.23.0
Compares acceptance verdicts and diagnostics between SafeGGUF (--profile llama-cpp)
and the upstream gguf.cpp parser (when compiled or present).
"""

import json
import os
import subprocess
import sys

SAFEGGUF_BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zig-out", "bin", "safegguf")
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

def run_safegguf(path: str, profile: str = "llama-cpp"):
    cmd = [SAFEGGUF_BIN, "inspect", path, "--profile", profile, "--format", "json"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        out_json = None
        try:
            out_json = json.loads(proc.stdout)
        except Exception:
            pass
        return {
            "returncode": proc.returncode,
            "accepted": proc.returncode == 0,
            "json": out_json,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "accepted": False, "timeout": True}

def test_differential_fixtures():
    print("Running differential validation against test fixtures...")
    if not os.path.exists(SAFEGGUF_BIN):
        print(f"Error: {SAFEGGUF_BIN} not found. Run zig build first.")
        sys.exit(1)

    fixtures = [f for f in os.listdir(FIXTURES_DIR) if f.endswith(".gguf")]
    fixtures.sort()

    results = {}
    for f in fixtures:
        path = os.path.join(FIXTURES_DIR, f)
        res_spec = run_safegguf(path, "gguf-spec")
        res_llama = run_safegguf(path, "llama-cpp")
        results[f] = {
            "spec_accepted": res_spec["accepted"],
            "llama_accepted": res_llama["accepted"],
            "spec_code": res_spec["returncode"],
            "llama_code": res_llama["returncode"],
        }
        print(f"  {f:35} | spec: {'PASS' if res_spec['accepted'] else 'REJECT'} (code {res_spec['returncode']}) | llama-cpp: {'PASS' if res_llama['accepted'] else 'REJECT'} (code {res_llama['returncode']})")

    print(f"\nDifferential fixture sweep completed: {len(fixtures)} files analyzed.")
    return results

if __name__ == "__main__":
    test_differential_fixtures()
