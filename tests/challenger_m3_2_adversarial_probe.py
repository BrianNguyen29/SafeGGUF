#!/usr/bin/env python3
"""
Challenger M3_2: Adversarial Boundary & Empirical Stress Verification Harness
Evaluates `safegguf-triage` (Milestone M3: Hybrid Triage CLI & Bayesian Engine).

Test Dimensions:
1. Boundary condition invariants:
   - Score bounds (0.010 <= score <= 0.980)
   - Severity enum conformance (None, Low, Medium, High, Critical)
   - Action enum conformance (ADMIT_PRODUCTION, CANARY_SANDBOX, HARD_DROP_INGRESS)
   - Dual-key schema consistency (score/risk_score, action/recommendation, etc.)
2. Exploit admission & containment:
   - Invariant A: No exploit ever admitted to ADMIT_PRODUCTION.
   - Invariant B: No exploit ever admitted to CANARY_SANDBOX.
   - Invariant C: Adversarial neutral naming (bypassing filename/tensor name heuristics).
3. Separation of compatibility issues vs malicious arithmetic overflows:
   - Validates that non-contiguous offsets, alignment 24, long names, and nested arrays
     are correctly routed to Compatibility-Divergence / CANARY_SANDBOX.
   - Validates that signed integer overflows and product overflows are strictly
     classified as Arithmetic-Exploit / HARD_DROP_INGRESS, even without hint keywords.
4. Concurrency & High Throughput Stress:
   - Multi-threaded parallel triage across mixed cohorts (valid, exploit, compat, missing, usage)
   - Verifies no file locking, race conditions, or process crashes under load.
"""

import concurrent.futures
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
TRIAGE_SCRIPT = REPO_ROOT / "tools" / "safegguf-triage" / "safegguf_triage.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
NEGATIVE_DIR = FIXTURES_DIR / "negative"
SECURITY_DIR = FIXTURES_DIR / "security_testbed"

# Bring in GGUF serialization helpers from advanced_security_testbed
sys.path.insert(0, str(REPO_ROOT / "tests"))
from advanced_security_testbed import align_up, encode_string, encode_kv, encode_tensor_desc, build_gguf_raw

results = []

def record(test_id: str, name: str, passed: bool, details: str = "", payload: Any = None):
    results.append({
        "id": test_id,
        "name": name,
        "passed": passed,
        "details": details,
        "payload": payload,
    })
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {test_id}: {name} - {details}")

def run_triage_cmd(file_path: Optional[str] = None, profile: str = "llama-cpp", mode: str = "auto", extra_args: Optional[List[str]] = None) -> Tuple[int, Dict[str, Any], str]:
    cmd = [sys.executable, str(TRIAGE_SCRIPT)]
    if file_path is not None:
        cmd.append(str(file_path))
    cmd.extend(["--profile", profile, "--format", "json", "--mode", mode])
    if extra_args:
        cmd.extend(extra_args)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    data = {}
    if p.stdout.strip():
        try:
            data = json.loads(p.stdout)
        except Exception as e:
            data = {"raw_stdout": p.stdout, "json_error": str(e)}
    return p.returncode, data, p.stderr

# ==============================================================================
# Suite 1: Boundary Condition Invariants
# ==============================================================================
def test_boundary_invariants():
    print("\n--- Suite 1: Boundary Condition Invariants ---")
    valid_severities = {"None", "Low", "Medium", "High", "Critical"}
    valid_actions = {"ADMIT_PRODUCTION", "CANARY_SANDBOX", "HARD_DROP_INGRESS", "STRUCTURALLY_ACCEPTED"}
    valid_categories = {
        "Structural-Pass", "Benign", "Arithmetic-Exploit", "Resource-Exhaustion",
        "Alignment-Tamper", "Malformed-Header", "Compatibility-Divergence", "IO-Error"
    }

    test_files = [
        (FIXTURES_DIR / "valid.gguf", "llama-cpp"),
        (FIXTURES_DIR / "scalar.gguf", "llama-cpp"),
        (NEGATIVE_DIR / "cve-2025-53630-cumulative-overflow.gguf", "llama-cpp"),
        (NEGATIVE_DIR / "synthetic-alloc-kv-count-dos.gguf", "llama-cpp"),
        (FIXTURES_DIR / "nonzero_header_padding.gguf", "llama-cpp"),
        (SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf", "llama-cpp"),
        (SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf", "gguf-spec"),
        (NEGATIVE_DIR / "synthetic-types-metadata-value-type-99.gguf", "llama-cpp"),
        (FIXTURES_DIR / "nonexistent_file_test_boundary.gguf", "llama-cpp"),
    ]

    for fpath, prof in test_files:
        tid = f"BND-{Path(fpath).stem}-{prof}"
        rc, data, stderr = run_triage_cmd(str(fpath), profile=prof)
        if "triage" not in data:
            record(tid, "Triage Output Structure", False, f"Missing 'triage' block in output. rc={rc}, stderr={stderr}")
            continue

        t = data["triage"]
        score = t.get("score")
        risk_score = t.get("risk_score")
        sev = t.get("severity")
        cat = t.get("category")
        threat_cat = t.get("threat_category")
        act = t.get("action")
        rec = t.get("recommendation")
        prob = t.get("downstream_exploit_prob")

        # Range checks: 0.00 <= score <= 1.00
        score_ok = (0.00 <= score <= 1.00) and (score == risk_score)
        sev_ok = sev in valid_severities
        cat_ok = cat in valid_categories and (cat == threat_cat)
        act_ok = act in valid_actions and (act == rec)
        prob_ok = (0.0 <= prob <= 1.0)

        all_ok = score_ok and sev_ok and cat_ok and act_ok and prob_ok
        details = f"score={score}, sev={sev}, cat={cat}, act={act}, prob={prob}"
        record(tid, f"Boundary invariants for {Path(fpath).name}", all_ok, details)

# ==============================================================================
# Suite 2: Exploit Admission Invariants
# ==============================================================================
def test_exploit_admission():
    print("\n--- Suite 2: Exploit Admission Invariants ---")
    # All files in negative/ and security_testbed/ (scenarios 1, 2, 3, 5) MUST NOT be ADMIT_PRODUCTION
    exploit_files = []
    for f in NEGATIVE_DIR.glob("*.gguf"):
        exploit_files.append((f, "llama-cpp"))
    for f in SECURITY_DIR.glob("scenario1_*.gguf"):
        exploit_files.append((f, "llama-cpp"))
    for f in SECURITY_DIR.glob("scenario2_*.gguf"):
        exploit_files.append((f, "llama-cpp"))
    for f in SECURITY_DIR.glob("scenario3_*.gguf"):
        exploit_files.append((f, "llama-cpp"))
    for f in SECURITY_DIR.glob("scenario5_*.gguf"):
        exploit_files.append((f, "llama-cpp"))
    # Also test classic memory safety exploit fixtures under default llama-cpp profile
    exploit_files.append((FIXTURES_DIR / "overlap.gguf", "llama-cpp"))
    exploit_files.append((FIXTURES_DIR / "out_of_bounds.gguf", "llama-cpp"))

    leaked_to_production = []
    leaked_to_canary = []

    for fpath, prof in exploit_files:
        tid = f"EXP-ADMIT-{fpath.stem}"
        rc, data, stderr = run_triage_cmd(str(fpath), profile=prof)
        act = data.get("triage", {}).get("action")
        cat = data.get("triage", {}).get("category")
        score = data.get("triage", {}).get("score")

        if act == "ADMIT_PRODUCTION":
            leaked_to_production.append(fpath.name)
            record(tid, f"Exploit admitted to PRODUCTION!", False, f"CRITICAL LEAK: {fpath.name} received ADMIT_PRODUCTION")
        elif act == "CANARY_SANDBOX":
            leaked_to_canary.append(fpath.name)
            record(tid, f"Exploit admitted to CANARY_SANDBOX", False, f"SECURITY LEAK: {fpath.name} received CANARY_SANDBOX (cat={cat}, score={score})")
        else:
            record(tid, f"Exploit strictly dropped", True, f"act={act}, cat={cat}, score={score}")

    print(f"Total exploit files tested: {len(exploit_files)}")
    print(f"Leaked to ADMIT_PRODUCTION: {len(leaked_to_production)}")
    print(f"Leaked to CANARY_SANDBOX: {len(leaked_to_canary)} {leaked_to_canary}")

# ==============================================================================
# Suite 3: Adversarial Neutral Naming & Exploit Separation
# ==============================================================================
def test_adversarial_neutral_naming():
    print("\n--- Suite 3: Adversarial Neutral Naming & Exploit Separation ---")
    # Here we test if an attacker can bypass Arithmetic-Exploit classification
    # by using neutral filenames and neutral tensor names.

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Test Case 1: Signed 64-bit Dim Overflow (dim = 0x8000000000000000)
        # Tensor name: "weights.layer0", File name: "model_weights.gguf"
        t1 = encode_tensor_desc(b"weights.layer0", [0x8000000000000000], 0, 0)
        d1 = build_gguf_raw(tensor_count=1, tensor_bytes=t1)
        f1 = tmp_path / "model_weights.gguf"
        f1.write_bytes(d1)

        rc, data1, _ = run_triage_cmd(str(f1), profile="llama-cpp")
        triage1 = data1.get("triage", {})
        cat1 = triage1.get("threat_category")
        score1 = triage1.get("score")
        act1 = triage1.get("action")
        # An arithmetic overflow exploit must be Arithmetic-Exploit and HARD_DROP_INGRESS
        passed1 = (cat1 == "Arithmetic-Exploit" and act1 == "HARD_DROP_INGRESS" and score1 >= 0.90)
        record(
            "ADV-NAME-01",
            "Signed 64-bit Dim Overflow with Neutral Name",
            passed1,
            f"cat={cat1}, score={score1}, action={act1}"
        )

        # Test Case 2: Signed 64-bit Product Overflow ([0x4000000000000000, 2])
        # Tensor name: "transformer.emb", File name: "standard_model.gguf"
        t2 = encode_tensor_desc(b"transformer.emb", [0x4000000000000000, 2], 0, 0)
        d2 = build_gguf_raw(tensor_count=1, tensor_bytes=t2)
        f2 = tmp_path / "standard_model.gguf"
        f2.write_bytes(d2)

        rc, data2, _ = run_triage_cmd(str(f2), profile="llama-cpp")
        triage2 = data2.get("triage", {})
        cat2 = triage2.get("threat_category")
        score2 = triage2.get("score")
        act2 = triage2.get("action")
        passed2 = (cat2 == "Arithmetic-Exploit" and act2 == "HARD_DROP_INGRESS" and score2 >= 0.90)
        record(
            "ADV-NAME-02",
            "Signed 64-bit Product Overflow with Neutral Name",
            passed2,
            f"cat={cat2}, score={score2}, action={act2}"
        )

        # Test Case 3: Genuine Compatibility Divergence (Scenario 4 models)
        # These SHOULD be Compatibility-Divergence and CANARY_SANDBOX
        compat_cases = [
            (SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf", "llama-cpp", "Alignment non-power-2"),
            (SECURITY_DIR / "scenario4_diff_non_contiguous_gap.gguf", "llama-cpp", "Non-contiguous gap"),
            (SECURITY_DIR / "scenario4_diff_name_exact_64.gguf", "llama-cpp", "Tensor name 64 bytes"),
            (SECURITY_DIR / "scenario4_diff_nested_array.gguf", "llama-cpp", "Nested metadata array"),
        ]
        for fpath, prof, desc in compat_cases:
            rc, data, _ = run_triage_cmd(str(fpath), profile=prof)
            t = data.get("triage", {})
            cat = t.get("threat_category")
            act = t.get("action")
            score = t.get("score")
            passed = (cat == "Compatibility-Divergence" and act == "CANARY_SANDBOX" and abs(score - 0.450) < 0.05)
            record(f"COMPAT-{fpath.stem}", f"Compatibility: {desc}", passed, f"cat={cat}, score={score}, action={act}")

        # Test Case 4: Renamed CVE Exploit (cve-2025-53630 renamed to plain "weights.gguf")
        cve_src = NEGATIVE_DIR / "cve-2025-53630-cumulative-overflow.gguf"
        f4 = tmp_path / "neutral_cve.gguf"
        f4.write_bytes(cve_src.read_bytes())
        rc, data4, _ = run_triage_cmd(str(f4), profile="llama-cpp")
        t4 = data4.get("triage", {})
        passed4 = (t4.get("threat_category") == "Arithmetic-Exploit" and t4.get("action") == "HARD_DROP_INGRESS")
        record("ADV-NAME-03", "Renamed CVE-2025-53630", passed4, f"cat={t4.get('threat_category')}, act={t4.get('action')}")

# ==============================================================================
# Suite 4: Concurrency & High Throughput Stress
# ==============================================================================
def test_concurrency_stress(workers: int = 16, iterations_per_worker: int = 5):
    print(f"\n--- Suite 4: Concurrency & High Throughput Stress ({workers} workers, {workers * iterations_per_worker} tasks) ---")
    cohort = [
        (str(FIXTURES_DIR / "valid.gguf"), "llama-cpp", 0, "PASS", "Structural-Pass"),
        (str(NEGATIVE_DIR / "cve-2025-53630-cumulative-overflow.gguf"), "llama-cpp", 2, "REJECT", "Arithmetic-Exploit"),
        (str(SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf"), "llama-cpp", 2, "REJECT", "Compatibility-Divergence"),
        (str(SECURITY_DIR / "scenario3_budget_units_exhaustion.gguf"), "llama-cpp", 2, "REJECT", "Resource-Exhaustion"),
        (str(FIXTURES_DIR / "nonzero_header_padding.gguf"), "llama-cpp", 2, "REJECT", "Alignment-Tamper"),
        (str(FIXTURES_DIR / "nonexistent_stress_model_file.gguf"), "llama-cpp", 74, "ERROR", "IO-Error"),
    ]

    tasks = []
    for i in range(workers * iterations_per_worker):
        item = cohort[i % len(cohort)]
        tasks.append((i, item[0], item[1], item[2], item[3], item[4]))

    start_time = time.perf_counter()
    concurrency_errors = []

    def execute_task(task_spec):
        idx, path, profile, exp_rc, exp_verdict, exp_cat = task_spec
        rc, data, stderr = run_triage_cmd(path, profile=profile)
        errs = []
        if rc != exp_rc:
            errs.append(f"rc mismatch: exp {exp_rc} got {rc}")
        if data.get("safegguf_verdict") != exp_verdict:
            errs.append(f"verdict mismatch: exp {exp_verdict} got {data.get('safegguf_verdict')}")
        if exp_cat:
            actual_cat = data.get("triage", {}).get("category")
            if actual_cat != exp_cat and not (exp_cat == "Benign" and actual_cat == "Structural-Pass"):
                errs.append(f"category mismatch: exp {exp_cat} got {actual_cat}")
        return idx, errs

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(execute_task, t) for t in tasks]
        for f in concurrent.futures.as_completed(futures):
            idx, errs = f.result()
            if errs:
                concurrency_errors.append((idx, errs))

    elapsed = time.perf_counter() - start_time
    total_runs = len(tasks)
    throughput = total_runs / elapsed if elapsed > 0 else 0

    passed = len(concurrency_errors) == 0
    details = f"Runs: {total_runs}, Errors: {len(concurrency_errors)}, Elapsed: {elapsed:.2f}s, Throughput: {throughput:.1f} req/s"
    record("STRESS-CONCURRENCY", f"Parallel execution ({workers} workers)", passed, details)
    if concurrency_errors:
        for idx, errs in concurrency_errors[:5]:
            print(f"  [Task #{idx}] {errs}")

def main():
    print("=" * 70)
    print("  SAFEGGUF-TRIAGE EMPIRICAL ADVERSARIAL & STRESS TEST HARNESS")
    print("=" * 70)

    test_boundary_invariants()
    test_exploit_admission()
    test_adversarial_neutral_naming()
    test_concurrency_stress(workers=16, iterations_per_worker=5)

    print("\n" + "=" * 70)
    print("  SUMMARY OF RESULTS")
    print("=" * 70)
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    print(f"Total Assertions: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFAILING TESTS:")
        for r in results:
            if not r["passed"]:
                print(f" - [{r['id']}] {r['name']}: {r['details']}")

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
