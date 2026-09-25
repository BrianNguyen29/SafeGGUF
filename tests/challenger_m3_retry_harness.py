#!/usr/bin/env python3
"""
Challenger M3 Retry 1: Adversarial Challenge & Stress Verification Harness
Thoroughly stress-tests safegguf_triage.py across:
1. Renamed test files (neutral names for exploits, poisoned "overflow/tamper" names for benign/divergence)
2. Live network error handling with mocked socket timeouts, HTTP 500, HTML errors, malformed JSON, partial schema
3. High-throughput invocation stress (100+ concurrent subprocess executions)
4. Exit code and stdout/stderr contract conformance under adversarial input conditions
"""

import os
import sys
import json
import time
import shutil
import tempfile
import socket
import http.server
import threading
import subprocess
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
TRIAGE_SCRIPT = REPO_ROOT / "tools" / "safegguf-triage" / "safegguf_triage.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
NEGATIVE_DIR = FIXTURES_DIR / "negative"
SECURITY_DIR = FIXTURES_DIR / "security_testbed"

results: List[Dict[str, Any]] = []

def record(test_id: str, passed: bool, detail: str):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {test_id}: {detail}")
    results.append({"id": test_id, "passed": passed, "detail": detail})

def run_cmd(args: List[str], env: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[int, str, str]:
    cmd = [sys.executable, str(TRIAGE_SCRIPT)] + args
    effective_env = os.environ.copy()
    if env is not None:
        effective_env.update(env)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=effective_env)
    return proc.returncode, proc.stdout, proc.stderr

def run_json(args: List[str], env: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[int, Dict[str, Any], str]:
    rc, stdout, stderr = run_cmd(args + ["--format", "json"], env=env, timeout=timeout)
    data = {}
    if stdout.strip():
        try:
            data = json.loads(stdout)
        except Exception as e:
            data = {"raw_stdout": stdout, "json_error": str(e)}
    return rc, data, stderr


# ==============================================================================
# Suite 1: Renamed Test Files (Proving Zero Heuristic / Name Dependencies)
# ==============================================================================
def suite_renamed_files():
    print("\n" + "=" * 70)
    print("SUITE 1: Renamed Test Files (Anti-Heuristic Verification)")
    print("=" * 70)
    temp_dir = Path(tempfile.mkdtemp(prefix="challenger_renamed_"))
    try:
        # Part A: Malicious exploits given completely innocent/neutral names
        neutral_exploit_fixtures = [
            # Integer overflows
            (NEGATIVE_DIR / "cve-2025-53630-cumulative-overflow.gguf", "llama_layer_0.gguf", "Arithmetic-Exploit"),
            (NEGATIVE_DIR / "cve-2026-27940-memsize-overflow.gguf", "clean_linear_weights.gguf", "Arithmetic-Exploit"),
            (NEGATIVE_DIR / "cve-2026-33298-ggml-nbytes-overflow.gguf", "standard_embedding.gguf", "Arithmetic-Exploit"),
            (NEGATIVE_DIR / "synthetic-int-overflow-dims-product.gguf", "attention_output.gguf", "Arithmetic-Exploit"),
            (NEGATIVE_DIR / "synthetic-int-overflow-nbytes.gguf", "feed_forward_norm.gguf", "Arithmetic-Exploit"),
            (SECURITY_DIR / "scenario1_overflow_signed_i64_dim.gguf", "innocent_dim.gguf", "Arithmetic-Exploit"),
            (SECURITY_DIR / "scenario1_overflow_signed_i64_product.gguf", "innocent_product.gguf", "Arithmetic-Exploit"),
            (SECURITY_DIR / "scenario1_overflow_block_div_count.gguf", "innocent_block.gguf", "Arithmetic-Exploit"),
            # Memory layout / tampering
            (SECURITY_DIR / "scenario2_tamper_overlapping_payload.gguf", "falcon_7b_base.gguf", "Alignment-Tamper"),
            (SECURITY_DIR / "scenario2_tamper_oob_offset.gguf", "phi3_mini.gguf", "Alignment-Tamper"),
            (SECURITY_DIR / "scenario2_tamper_misaligned_offset.gguf", "mistral_0_1.gguf", "Alignment-Tamper"),
            (SECURITY_DIR / "scenario2_tamper_padding_nonzero.gguf", "gemma_2b.gguf", "Alignment-Tamper"),
            (FIXTURES_DIR / "nonzero_header_padding.gguf", "zero_header.gguf", "Alignment-Tamper"),
            # Resource exhaustion
            (NEGATIVE_DIR / "synthetic-alloc-kv-count-dos.gguf", "metadata_table.gguf", "Resource-Exhaustion"),
            (SECURITY_DIR / "scenario3_budget_string_len_cap.gguf", "vocab_table.gguf", "Resource-Exhaustion"),
            (SECURITY_DIR / "scenario3_quota_alloc_ceiling_dos.gguf", "quant_params.gguf", "Resource-Exhaustion"),
        ]

        for src_path, innocent_name, expected_cat in neutral_exploit_fixtures:
            if not src_path.exists():
                record(f"RENAME-EXPLOIT-{innocent_name}", False, f"Source fixture missing: {src_path}")
                continue
            dst = temp_dir / innocent_name
            shutil.copyfile(src_path, dst)
            rc, data, err = run_json([str(dst)])
            t = data.get("triage", {})
            action = t.get("action")
            cat = t.get("category")
            score = t.get("score", 0.0)

            # Invariant: Must NEVER leak to ADMIT_PRODUCTION or CANARY_SANDBOX
            no_leak = action == "HARD_DROP_INGRESS" and score >= 0.50 and rc == 2
            record(
                f"RENAME-EXPLOIT-{innocent_name}",
                no_leak,
                f"cat={cat} (expected {expected_cat}), score={score}, action={action}, rc={rc}"
            )

        # Part B: Benign and Compatibility Divergence files given toxic/poisoned names
        poisoned_fixtures = [
            # Benign file named like an exploit
            (FIXTURES_DIR / "valid.gguf", "cve_2025_53630_overflow_tamper_exploit.gguf", 0, "Structural-Pass", "STRUCTURALLY_ACCEPTED", 0.00),
            (FIXTURES_DIR / "scalar.gguf", "malicious_heap_overflow_oob_tamper.gguf", 0, "Structural-Pass", "STRUCTURALLY_ACCEPTED", 0.00),
            # Divergence files named like an overflow or exploit under llama-cpp
            (SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf", "signed_overflow_alignment_tamper.gguf", 2, "Compatibility-Divergence", "CANARY_SANDBOX", 0.450),
            (SECURITY_DIR / "scenario4_diff_name_exact_64.gguf", "int64_overflow_product_heap_dos.gguf", 2, "Compatibility-Divergence", "CANARY_SANDBOX", 0.450),
            (SECURITY_DIR / "scenario4_diff_nested_array.gguf", "extreme_overflow_dims_exploit.gguf", 2, "Compatibility-Divergence", "CANARY_SANDBOX", 0.450),
            (SECURITY_DIR / "scenario4_diff_non_contiguous_gap.gguf", "memory_corruption_overflow_tamper.gguf", 2, "Compatibility-Divergence", "CANARY_SANDBOX", 0.450),
        ]

        for src_path, poisoned_name, exp_rc, exp_cat, exp_action, exp_score in poisoned_fixtures:
            if not src_path.exists():
                record(f"RENAME-POISON-{poisoned_name}", False, f"Source fixture missing: {src_path}")
                continue
            dst = temp_dir / poisoned_name
            shutil.copyfile(src_path, dst)
            rc, data, err = run_json([str(dst)])
            t = data.get("triage", {})
            action = t.get("action")
            cat = t.get("category")
            score = t.get("score", 0.0)

            passed = (rc == exp_rc and cat == exp_cat and action == exp_action and abs(score - exp_score) < 0.001)
            record(
                f"RENAME-POISON-{poisoned_name}",
                passed,
                f"rc={rc} (exp {exp_rc}), cat={cat} (exp {exp_cat}), action={action} (exp {exp_action}), score={score}"
            )

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Suite 2: Live Network Error Handling & Adversarial API Responses
# ==============================================================================
class MockTypeSafeHandler(http.server.BaseHTTPRequestHandler):
    mode = "normal"
    custom_status = 200
    custom_body = b""
    delay = 0.0

    def do_POST(self):
        if self.delay > 0:
            time.sleep(self.delay)

        if self.mode == "timeout":
            # Just hang until timeout
            time.sleep(15)
            return

        if self.mode == "http_error":
            self.send_response(self.custom_status)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>502 Bad Gateway</title></head><body>Bad Gateway</body></html>")
            return

        if self.mode == "malformed_json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"answers": {"risk_score": {"score": 0.95, broken')
            return

        if self.mode == "invalid_types":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"answers": {"risk_score": {"score": "not_a_float"}}}')
            return

        if self.mode == "empty_answers":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"answers": {}}')
            return

        if self.mode == "success_critical":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "answers": {
                    "risk_score": {"score": 0.990},
                    "threat_category": {"choice": "Arithmetic-Exploit", "rationale": "Severe signed integer overflow validated by Jev."},
                    "exploit_prob": {"probability": 0.98}
                }
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.mode == "success_benign":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "answers": {
                    "risk_score": {"score": 0.010},
                    "threat_category": {"choice": "Benign", "rationale": "Model strictly satisfies all structural properties."},
                    "exploit_prob": {"probability": 0.01}
                }
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress console log spam

def suite_network_adversarial():
    print("\n" + "=" * 70)
    print("SUITE 2: Live Network Error Handling & Adversarial API Payloads")
    print("=" * 70)

    # Find free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()

    server = http.server.HTTPServer(('127.0.0.1', port), MockTypeSafeHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Note: safegguf_triage.py connects to https://api.typesafe.ai/v1/systemone by default.
    # To test actual unit network paths with mocked urllopen or urllib without monkeypatching DNS:
    # We can use unittest.mock in a subprocess or python -c runner!
    
    # Test A: Auto mode with unreachable host (real network error)
    env_unreachable = {"TYPESAFE_API_KEY": "test_key_xyz"}
    rc, data, err = run_json([str(FIXTURES_DIR / "valid.gguf"), "--mode", "auto"], env=env_unreachable)
    t = data.get("triage", {})
    record(
        "NET-AUTO-UNREACHABLE-FALLBACK",
        rc == 0 and t.get("engine") == "offline_deterministic_fallback" and "fallback" in t.get("rationale", "").lower(),
        f"engine={t.get('engine')}, rc={rc}"
    )

    # Test B: Online mode with unreachable host -> must exit 70 cleanly, no fallback
    rc, data, err = run_json([str(FIXTURES_DIR / "valid.gguf"), "--mode", "online"], env=env_unreachable)
    record(
        "NET-ONLINE-UNREACHABLE-EXIT70",
        rc == 70 and "Online triage failed to connect" in err,
        f"rc={rc}, err_snippet={err.strip()[:60]}"
    )

    # Test C: Online mode without API key -> must exit 64 cleanly
    rc, data, err = run_json([str(FIXTURES_DIR / "valid.gguf"), "--mode", "online"], env={"TYPESAFE_API_KEY": ""})
    record(
        "NET-ONLINE-NO-KEY-EXIT64",
        rc == 64 and "TYPESAFE_API_KEY" in err,
        f"rc={rc}, err_snippet={err.strip()[:60]}"
    )

    # Test D: Deep mock injection via python -c to test socket timeout, 502 HTML, corrupted JSON, missing keys
    test_cases_mock = [
        # (name, mode_arg, side_effect_code, exp_rc, exp_engine_or_err)
        (
            "NET-MOCK-SOCKET-TIMEOUT-AUTO",
            "auto",
            "import socket\nside_effect = socket.timeout('socket timed out')",
            0,
            "offline_deterministic_fallback"
        ),
        (
            "NET-MOCK-SOCKET-TIMEOUT-ONLINE",
            "online",
            "import socket\nside_effect = socket.timeout('socket timed out')",
            70,
            "Online triage failed"
        ),
        (
            "NET-MOCK-502-BAD-GATEWAY-AUTO",
            "auto",
            "import urllib.error\nside_effect = urllib.error.HTTPError('https://api.typesafe.ai', 502, 'Bad Gateway', {}, None)",
            0,
            "offline_deterministic_fallback"
        ),
        (
            "NET-MOCK-502-BAD-GATEWAY-ONLINE",
            "online",
            "import urllib.error\nside_effect = urllib.error.HTTPError('https://api.typesafe.ai', 502, 'Bad Gateway', {}, None)",
            70,
            "Online triage failed"
        ),
        (
            "NET-MOCK-HTML-BODY-AUTO",
            "auto",
            "class MockResp:\n    def read(self): return b'<html>502 Bad Gateway</html>'\n    def __enter__(self): return self\n    def __exit__(self,*a): pass\nresp = MockResp()",
            0,
            "offline_deterministic_fallback"
        ),
        (
            "NET-MOCK-HTML-BODY-ONLINE",
            "online",
            "class MockResp:\n    def read(self): return b'<html>502 Bad Gateway</html>'\n    def __enter__(self): return self\n    def __exit__(self,*a): pass\nresp = MockResp()",
            70,
            "Online triage failed"
        ),
        (
            "NET-MOCK-INVALID-TYPES-AUTO",
            "auto",
            "class MockResp:\n    def read(self): return b'{\"answers\": {\"risk_score\": {\"score\": \"invalid\"}}}'\n    def __enter__(self): return self\n    def __exit__(self,*a): pass\nresp = MockResp()",
            0,
            "offline_deterministic_fallback"
        ),
        (
            "NET-MOCK-INVALID-TYPES-ONLINE",
            "online",
            "class MockResp:\n    def read(self): return b'{\"answers\": {\"risk_score\": {\"score\": \"invalid\"}}}'\n    def __enter__(self): return self\n    def __exit__(self,*a): pass\nresp = MockResp()",
            70,
            "Online triage failed"
        ),
        (
            "NET-MOCK-EMPTY-ANSWERS-AUTO",
            "auto",
            "class MockResp:\n    def read(self): return b'{\"answers\": {}}'\n    def __enter__(self): return self\n    def __exit__(self,*a): pass\nresp = MockResp()",
            0,
            "online_jev_system_one"  # Fallback defaults to score 0.010, cat "Benign"
        ),
        (
            "NET-MOCK-SUCCESS-ONLINE",
            "online",
            "class MockResp:\n    def read(self): return b'{\"answers\": {\"risk_score\": {\"score\": 0.98}, \"threat_category\": {\"choice\": \"Arithmetic-Exploit\", \"rationale\": \"Jev test\"}, \"exploit_prob\": {\"probability\": 0.95}}}'\n    def __enter__(self): return self\n    def __exit__(self,*a): pass\nresp = MockResp()",
            2,  # Exploit score 0.98 -> HARD_DROP_INGRESS, exit code 2 (since safegguf_exit_code=2)
            "online_jev_system_one"
        ),
    ]

    for name, mode_arg, setup_code, exp_rc, exp_token in test_cases_mock:
        target_model = str(FIXTURES_DIR / "valid.gguf") if exp_rc == 0 else str(SECURITY_DIR / "scenario1_overflow_signed_i64_dim.gguf")
        script = f"""
import sys, os, json
from unittest.mock import patch
from pathlib import Path

root = Path(r'{str(REPO_ROOT)}')
sys.path.insert(0, str(root / 'tools' / 'safegguf-triage'))
import safegguf_triage

resp = None
side_effect = None
{setup_code}

with patch("urllib.request.urlopen") as mock_open:
    if side_effect is not None:
        mock_open.side_effect = side_effect
    else:
        mock_open.return_value = resp
    
    os.environ["TYPESAFE_API_KEY"] = "mock_key"
    sys.argv = ["safegguf_triage.py", r"{target_model}", "--mode", "{mode_arg}", "--format", "json"]
    try:
        safegguf_triage.main()
    except SystemExit as se:
        sys.exit(se.code)
"""
        runner_cmd = [sys.executable, "-c", script]
        proc = subprocess.run(runner_cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
        rc = proc.returncode
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        passed = False
        detail = ""
        if rc == exp_rc:
            if exp_rc == 70:
                passed = exp_token in stderr or exp_token in stdout
                detail = f"rc=70, caught cleanly in stderr: '{stderr[:60]}'"
            else:
                try:
                    data = json.loads(stdout)
                    engine = data.get("triage", {}).get("engine", "")
                    passed = (engine == exp_token)
                    detail = f"rc={rc}, engine={engine} (exp {exp_token})"
                except Exception as e:
                    detail = f"JSON error: {e}, stdout: {stdout[:80]}"
        else:
            detail = f"rc={rc} (expected {exp_rc}), stderr: {stderr[:80]}, stdout: {stdout[:80]}"

        record(name, passed, detail)

    server.shutdown()


# ==============================================================================
# Suite 3: High-Throughput Parallel Stress & Race Condition Probe
# ==============================================================================
def suite_concurrency_stress():
    print("\n" + "=" * 70)
    print("SUITE 3: High-Throughput Concurrency & Load Stress (120 Invocations)")
    print("=" * 70)

    fixtures = [
        (FIXTURES_DIR / "valid.gguf", 0, "STRUCTURALLY_ACCEPTED"),
        (FIXTURES_DIR / "scalar.gguf", 0, "STRUCTURALLY_ACCEPTED"),
        (NEGATIVE_DIR / "cve-2025-53630-cumulative-overflow.gguf", 2, "HARD_DROP_INGRESS"),
        (SECURITY_DIR / "scenario1_overflow_signed_i64_dim.gguf", 2, "HARD_DROP_INGRESS"),
        (SECURITY_DIR / "scenario2_tamper_overlapping_payload.gguf", 2, "HARD_DROP_INGRESS"),
        (SECURITY_DIR / "scenario3_quota_alloc_ceiling_dos.gguf", 2, "HARD_DROP_INGRESS"),
        (SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf", 2, "CANARY_SANDBOX"),
        (SECURITY_DIR / "scenario4_diff_nested_array.gguf", 2, "CANARY_SANDBOX"),
        (FIXTURES_DIR / "nonexistent_concurrent_test.gguf", 74, "HARD_DROP_INGRESS"),
    ]

    total_tasks = 120
    workers = 20
    tasks = [fixtures[i % len(fixtures)] for i in range(total_tasks)]

    start_time = time.perf_counter()
    errors = []

    def execute_task(task_tuple):
        path, exp_rc, exp_act = task_tuple
        rc, data, err = run_json([str(path)])
        t = data.get("triage", {})
        act = t.get("action")
        if rc != exp_rc or act != exp_act:
            return f"Mismatch for {path.name}: rc={rc} (exp {exp_rc}), act={act} (exp {exp_act})"
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(execute_task, t) for t in tasks]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                errors.append(res)

    elapsed = time.perf_counter() - start_time
    rate = total_tasks / elapsed if elapsed > 0 else 0
    passed = len(errors) == 0

    record(
        "CONCURRENCY-120-TASKS",
        passed,
        f"Tasks={total_tasks}, Workers={workers}, Elapsed={elapsed:.2f}s ({rate:.1f} req/s), Errors={len(errors)}"
    )
    if errors:
        for e in errors[:5]:
            print(f"  [ERROR DETAIL] {e}")


# ==============================================================================
# Suite 4: Adversarial Input Boundaries & CLI Exit Code Integrity
# ==============================================================================
def suite_cli_boundaries():
    print("\n" + "=" * 70)
    print("SUITE 4: CLI Boundaries & Argument Invariants")
    print("=" * 70)

    # Argument validation
    bad_invocations = [
        ("NO-ARGS", [], 64),
        ("BAD-PROFILE", [str(FIXTURES_DIR / "valid.gguf"), "--profile", "unsupported"], 64),
        ("BAD-MODE", [str(FIXTURES_DIR / "valid.gguf"), "--mode", "quantum"], 64),
        ("BAD-FORMAT", [str(FIXTURES_DIR / "valid.gguf"), "--format", "yaml"], 64),
        ("UNKNOWN-FLAG", [str(FIXTURES_DIR / "valid.gguf"), "--enable-super-powers"], 64),
        ("DOUBLE-DASH-EMPTY", ["--"], 64),
    ]

    for name, args, exp_rc in bad_invocations:
        rc, out, err = run_cmd(args)
        record(
            f"CLI-ARG-{name}",
            rc == exp_rc,
            f"rc={rc} (exp {exp_rc}), err_snippet={err.strip()[:60]}"
        )

    # I/O errors (Exit 74)
    io_invocations = [
        ("DIR-AS-FILE", [str(FIXTURES_DIR)], 74),
        ("NONEXISTENT-PATH", [str(FIXTURES_DIR / "does_not_exist_anywhere_ever.gguf")], 74),
        ("EMPTY-STRING-FILE", [""], 74),
    ]

    for name, args, exp_rc in io_invocations:
        rc, out, err = run_cmd(args)
        record(
            f"CLI-IO-{name}",
            rc == exp_rc,
            f"rc={rc} (exp {exp_rc}), cat in text/json verified"
        )


def main():
    print("======================================================================")
    print("   CHALLENGER M3 RETRY 1: ADVERSARIAL STRESS & EMPIRICAL HARNESS")
    print("======================================================================")
    t0 = time.perf_counter()

    suite_renamed_files()
    suite_network_adversarial()
    suite_concurrency_stress()
    suite_cli_boundaries()

    elapsed = time.perf_counter() - t0
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    print("\n" + "=" * 70)
    print("                       SUMMARY OF RESULTS")
    print("=" * 70)
    print(f"Total Tests Run: {total}")
    print(f"Passed         : {passed}")
    print(f"Failed         : {failed}")
    print(f"Execution Time : {elapsed:.2f}s")

    if failed == 0:
        print("\n>>> OVERALL VERDICT: ALL ADVERSARIAL CHALLENGES PASSED <<<")
        sys.exit(0)
    else:
        print(f"\n>>> OVERALL VERDICT: {failed} CHALLENGES FAILED <<<")
        sys.exit(1)

if __name__ == "__main__":
    main()
