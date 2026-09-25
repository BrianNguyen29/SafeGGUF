#!/usr/bin/env python3
"""
tests/test_triage.py - Comprehensive Test Suite for safegguf-triage CLI & Bayesian Engine.

Covers Milestone M3 / Requirement R3:
1. Benign Model Admission (score ~0.010, Benign, ADMIT_PRODUCTION, exit 0)
2. Arithmetic Exploit Rejection (score ~0.980, Arithmetic-Exploit, HARD_DROP_INGRESS, exit 2)
3. Resource Exhaustion & Quota Caps (score >= 0.750, Resource-Exhaustion, HARD_DROP_INGRESS, exit 2)
4. Alignment & Zero-Padding Tampering (score >= 0.720, Alignment-Tamper, HARD_DROP_INGRESS, exit 2)
5. Malformed Header & Grammar Violations (score >= 0.520, Malformed-Header, HARD_DROP_INGRESS, exit 2)
6. Compatibility Divergence & Canary Sandboxing (score ~0.450, Compatibility-Divergence, CANARY_SANDBOX, exit 2)
7. I/O Error Contract & Exit Code 74 Contract (EX_IOERR, exit 74)
8. Engine Fallback Resilience (Air-Gapped Offline Mode vs Online Fallback)
9. Dual Output Formatting (JSON Schema Conformance & ASCII Text Dashboard)
10. CLI Usage, Flag Parsing, and Exit Code 64 (EX_USAGE, exit 64)
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
TRIAGE_SCRIPT = REPO_ROOT / "tools" / "safegguf-triage" / "safegguf_triage.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
NEGATIVE_DIR = FIXTURES_DIR / "negative"
SECURITY_DIR = FIXTURES_DIR / "security_testbed"


def run_triage(
    file_path: Optional[str] = None,
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    fmt: Optional[str] = "json",
    extra_args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    cmd = [sys.executable, str(TRIAGE_SCRIPT)]
    if file_path is not None:
        cmd.append(str(file_path))
    if profile:
        cmd.extend(["--profile", profile])
    if mode:
        cmd.extend(["--mode", mode])
    if fmt:
        cmd.extend(["--format", fmt])
    if extra_args:
        cmd.extend(extra_args)

    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=run_env)
    return p.returncode, p.stdout, p.stderr


class TestTriageBenign(unittest.TestCase):
    """Suite 1: Benign & Valid GGUF Models"""

    def test_canonical_valid_model(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "PASS")
        self.assertEqual(data["safegguf_exit_code"], 0)
        t = data["triage"]
        self.assertAlmostEqual(t["risk_score"], 0.010, delta=0.040)
        self.assertEqual(t["threat_category"], "Benign")
        self.assertEqual(t["severity"], "None")
        self.assertEqual(t["recommendation"], "ADMIT_PRODUCTION")
        self.assertLessEqual(t["downstream_exploit_prob"], 0.05)

    def test_scalar_tensor_model(self):
        fixture = FIXTURES_DIR / "scalar.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "PASS")
        self.assertEqual(data["safegguf_exit_code"], 0)
        self.assertEqual(data["triage"]["threat_category"], "Benign")
        self.assertEqual(data["triage"]["recommendation"], "ADMIT_PRODUCTION")

    def test_profile_divergent_valid_under_gguf_spec(self):
        fixture = SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="gguf-spec")
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "PASS")
        self.assertEqual(data["safegguf_exit_code"], 0)
        self.assertEqual(data["triage"]["threat_category"], "Benign")
        self.assertEqual(data["triage"]["recommendation"], "ADMIT_PRODUCTION")


class TestTriageArithmeticExploits(unittest.TestCase):
    """Suite 2: Arithmetic Integer Overflow Exploits"""

    def test_cve_2025_53630_cumulative_overflow(self):
        fixture = NEGATIVE_DIR / "cve-2025-53630-cumulative-overflow.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="llama-cpp")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["error_code"], "E_ArithmeticOverflow")
        t = data["triage"]
        self.assertGreaterEqual(t["risk_score"], 0.950)
        self.assertEqual(t["threat_category"], "Arithmetic-Exploit")
        self.assertEqual(t["severity"], "Critical")
        self.assertGreaterEqual(t["downstream_exploit_prob"], 0.90)
        self.assertEqual(t["recommendation"], "HARD_DROP_INGRESS")

    def test_cve_2026_27940_memsize_overflow(self):
        fixture = NEGATIVE_DIR / "cve-2026-27940-memsize-overflow.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="llama-cpp")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Arithmetic-Exploit")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")

    def test_cve_2026_33298_ggml_nbytes_overflow(self):
        fixture = NEGATIVE_DIR / "cve-2026-33298-ggml-nbytes-overflow.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="gguf-spec")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Arithmetic-Exploit")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")

    def test_block_div_count_overflow(self):
        fixture = SECURITY_DIR / "scenario1_overflow_block_div_count.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="llama-cpp")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Arithmetic-Exploit")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")


class TestTriageResourceExhaustion(unittest.TestCase):
    """Suite 3: Memory Quota & WorkBudget Exhaustion Attacks"""

    def test_quota_allocator_ceiling_dos(self):
        fixture = SECURITY_DIR / "scenario3_quota_alloc_ceiling_dos.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["error_code"], "E_TotalAllocationLimitExceeded")
        t = data["triage"]
        self.assertGreaterEqual(t["risk_score"], 0.750)
        self.assertEqual(t["threat_category"], "Resource-Exhaustion")
        self.assertEqual(t["severity"], "High")
        self.assertEqual(t["recommendation"], "HARD_DROP_INGRESS")

    def test_budget_units_exhaustion(self):
        fixture = SECURITY_DIR / "scenario3_budget_units_exhaustion.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Resource-Exhaustion")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")

    def test_synthetic_alloc_kv_count_dos(self):
        fixture = NEGATIVE_DIR / "synthetic-alloc-kv-count-dos.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Resource-Exhaustion")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")


class TestTriageAlignmentTamper(unittest.TestCase):
    """Suite 4: Structural & Zero-Padding Tampering"""

    def test_nonzero_header_padding(self):
        fixture = FIXTURES_DIR / "nonzero_header_padding.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["error_code"], "E_InvalidAlignmentPadding")
        t = data["triage"]
        self.assertGreaterEqual(t["risk_score"], 0.720)
        self.assertEqual(t["threat_category"], "Alignment-Tamper")
        self.assertEqual(t["recommendation"], "HARD_DROP_INGRESS")

    def test_tamper_padding_nonzero(self):
        fixture = SECURITY_DIR / "scenario2_tamper_padding_nonzero.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Alignment-Tamper")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")

    def test_tamper_padding_multichunk(self):
        fixture = SECURITY_DIR / "scenario2_tamper_padding_multichunk.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Alignment-Tamper")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")

    def test_overlap_tensor_spec(self):
        fixture = FIXTURES_DIR / "overlap.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="gguf-spec")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["error_code"], "E_TensorOverlap")
        self.assertEqual(data["triage"]["threat_category"], "Alignment-Tamper")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")


class TestTriageMalformedHeader(unittest.TestCase):
    """Suite 5: Malformed Headers & Steganography"""

    def test_invalid_metadata_value_type(self):
        fixture = NEGATIVE_DIR / "synthetic-types-metadata-value-type-99.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["error_code"], "E_InvalidMetadataType")
        t = data["triage"]
        self.assertGreaterEqual(t["risk_score"], 0.500)
        self.assertEqual(t["threat_category"], "Malformed-Header")
        self.assertEqual(t["recommendation"], "HARD_DROP_INGRESS")

    def test_invalid_tensor_type(self):
        fixture = NEGATIVE_DIR / "synthetic-types-invalid-tensor-type-43.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Malformed-Header")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")

    def test_invalid_utf8_metadata(self):
        fixture = NEGATIVE_DIR / "synthetic-metadata-invalid-utf8-value.gguf"
        rc, stdout, stderr = run_triage(str(fixture))
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        self.assertEqual(data["triage"]["threat_category"], "Malformed-Header")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")


class TestTriageCompatibilityDivergence(unittest.TestCase):
    """Suite 6: Profile Decoupling & Compatibility Divergence"""

    def test_non_power_two_alignment_under_llama_cpp(self):
        fixture = SECURITY_DIR / "scenario4_diff_align_non_power_two.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="llama-cpp")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        t = data["triage"]
        self.assertEqual(t["threat_category"], "Compatibility-Divergence")
        self.assertAlmostEqual(t["risk_score"], 0.450, delta=0.050)
        self.assertEqual(t["recommendation"], "CANARY_SANDBOX")

    def test_non_contiguous_gap_under_llama_cpp(self):
        fixture = SECURITY_DIR / "scenario4_diff_non_contiguous_gap.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="llama-cpp")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        t = data["triage"]
        self.assertEqual(t["threat_category"], "Compatibility-Divergence")
        self.assertEqual(t["recommendation"], "CANARY_SANDBOX")

    def test_tensor_name_exact_64_under_llama_cpp(self):
        fixture = SECURITY_DIR / "scenario4_diff_name_exact_64.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="llama-cpp")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        t = data["triage"]
        self.assertEqual(t["threat_category"], "Compatibility-Divergence")
        self.assertEqual(t["recommendation"], "CANARY_SANDBOX")

    def test_nested_array_under_llama_cpp(self):
        fixture = SECURITY_DIR / "scenario4_diff_nested_array.gguf"
        rc, stdout, stderr = run_triage(str(fixture), profile="llama-cpp")
        self.assertEqual(rc, 2, f"Expected rc 2, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "REJECT")
        t = data["triage"]
        self.assertEqual(t["threat_category"], "Compatibility-Divergence")
        self.assertEqual(t["recommendation"], "CANARY_SANDBOX")


class TestTriageIoErrors(unittest.TestCase):
    """Suite 7: File System & I/O Error Handling (Exit 74)"""

    def test_nonexistent_file(self):
        fake_path = FIXTURES_DIR / "definitely_non_existent_model_12345.gguf"
        rc, stdout, stderr = run_triage(str(fake_path))
        self.assertEqual(rc, 74, f"Expected exit code 74 (EX_IOERR), got {rc}. Stderr: {stderr}")
        self.assertTrue(stdout.strip(), "Expected stdout with triage JSON report")
        data = json.loads(stdout)
        self.assertEqual(data["safegguf_verdict"], "ERROR")
        self.assertEqual(data["safegguf_exit_code"], 74)
        self.assertEqual(data["triage"]["threat_category"], "IO-Error")
        self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")


class TestTriageModesAndFallback(unittest.TestCase):
    """Suite 8: Online Mode vs Offline Air-Gapped Fallback"""

    def test_auto_fallback_without_api_key(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        clean_env = {k: v for k, v in os.environ.items() if k != "TYPESAFE_API_KEY"}
        rc, stdout, stderr = run_triage(str(fixture), mode="auto", env=clean_env)
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["triage"]["engine"], "offline_bayesian_rule_engine")

    def test_explicit_offline_mode(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        rc, stdout, stderr = run_triage(str(fixture), mode="offline")
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["triage"]["engine"], "offline_bayesian_rule_engine")

    def test_online_mode_without_api_key_fails_cleanly(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        clean_env = {k: v for k, v in os.environ.items() if k != "TYPESAFE_API_KEY"}
        rc, stdout, stderr = run_triage(str(fixture), mode="online", env=clean_env)
        self.assertEqual(rc, 64, f"Expected rc 64, got {rc}")
        self.assertIn("TYPESAFE_API_KEY", stderr)

    def test_auto_fallback_with_unreachable_api(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        env = {"TYPESAFE_API_KEY": "sk-unreachable-test-key"}
        rc, stdout, stderr = run_triage(str(fixture), mode="auto", env=env)
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data["triage"]["engine"], "offline_bayesian_fallback")
        self.assertIn("fallback to offline Bayesian engine", data["triage"]["rationale"])

    def test_online_mode_with_unreachable_api_fails_cleanly(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        env = {"TYPESAFE_API_KEY": "sk-unreachable-test-key"}
        rc, stdout, stderr = run_triage(str(fixture), mode="online", env=env)
        self.assertEqual(rc, 70, f"Expected rc 70 on unreachable online API, got {rc}. Stderr: {stderr}")
        self.assertIn("Online triage failed", stderr)

    def test_online_mode_with_mock_api_success(self):
        from unittest.mock import patch, MagicMock
        sys.path.insert(0, str(TRIAGE_SCRIPT.parent))
        import safegguf_triage

        mock_resp_json = {
            "model": "jev-latest",
            "answers": {
                "risk_score": {"score": 0.02, "confidence": 0.99},
                "threat_category": {"choice": "Benign", "rationale": "Model verified safe by Jev System One."},
                "exploit_prob": {"probability": 0.01}
            }
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_resp_json).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = safegguf_triage.online_jev_triage({"status": "PASS", "exit_code": 0}, api_key="sk-test-mock-key")
            self.assertEqual(res["engine"], "online_jev_system_one")
            self.assertEqual(res["threat_category"], "Benign")
            self.assertEqual(res["action"], "ADMIT_PRODUCTION")
            self.assertAlmostEqual(res["risk_score"], 0.02)


class TestTriageOutputFormats(unittest.TestCase):
    """Suite 9: JSON Schema Conformance & ASCII Text Dashboard"""

    def test_json_schema_completeness(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        rc, stdout, stderr = run_triage(str(fixture), fmt="json")
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        data = json.loads(stdout)
        required_top = ["file", "profile", "safegguf_verdict", "safegguf_exit_code", "error_code", "triage"]
        for k in required_top:
            self.assertIn(k, data)

        required_triage = ["engine", "risk_score", "severity", "threat_category", "downstream_exploit_prob", "recommendation", "rationale"]
        for k in required_triage:
            self.assertIn(k, data["triage"])

    def test_text_dashboard_output(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        rc, stdout, stderr = run_triage(str(fixture), fmt="text")
        self.assertEqual(rc, 0, f"Expected rc 0, got {rc}. Stderr: {stderr}")
        self.assertIn("SAFEGGUF MODEL ADMISSION TRIAGE REPORT", stdout)
        self.assertIn("Risk Score", stdout)
        self.assertIn("Threat Category", stdout)
        self.assertIn("Admission Action", stdout)
        self.assertIn("ADMIT_PRODUCTION", stdout)


class TestTriageCliUsage(unittest.TestCase):
    """Suite 10: Argument Validation & Exit 64 (EX_USAGE)"""

    def test_unknown_argument(self):
        fixture = FIXTURES_DIR / "valid.gguf"
        rc, stdout, stderr = run_triage(str(fixture), extra_args=["--invalid-flag"])
        self.assertEqual(rc, 64, f"Expected rc 64 on unknown arg, got {rc}")

    def test_missing_file_argument(self):
        rc, stdout, stderr = run_triage(file_path=None, fmt=None)
        self.assertEqual(rc, 64, f"Expected rc 64 on missing file, got {rc}")

    def test_help_argument(self):
        rc, stdout, stderr = run_triage(extra_args=["--help"], fmt=None)
        self.assertEqual(rc, 0, f"Expected rc 0 on --help, got {rc}")
        self.assertIn("usage:", stdout.lower())


class TestTriageEdgeCasesAndRobustness(unittest.TestCase):
    """Suite 11: Edge Cases, Malformed Payloads & Heuristic Immunity"""

    def test_zero_byte_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f_path = f.name
        try:
            rc, stdout, stderr = run_triage(f_path)
            self.assertEqual(rc, 2)
            data = json.loads(stdout)
            self.assertEqual(data["safegguf_verdict"], "REJECT")
            self.assertEqual(data["triage"]["threat_category"], "Malformed-Header")
            self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_invalid_magic_bytes(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as f:
            f.write(b"BADF\x03\x00\x00\x00\x00\x00\x00\x00")
            f_path = f.name
        try:
            rc, stdout, stderr = run_triage(f_path)
            self.assertEqual(rc, 2)
            data = json.loads(stdout)
            self.assertEqual(data["safegguf_verdict"], "REJECT")
            self.assertEqual(data["triage"]["threat_category"], "Malformed-Header")
            self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_directory_path_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            rc, stdout, stderr = run_triage(td)
            self.assertEqual(rc, 74)
            data = json.loads(stdout)
            self.assertEqual(data["safegguf_verdict"], "ERROR")
            self.assertEqual(data["triage"]["threat_category"], "IO-Error")
            self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")

    def test_adversarial_rename_padding_tamper_to_overflow(self):
        import tempfile, shutil
        src = FIXTURES_DIR / "nonzero_header_padding.gguf"
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "padding_tamper_overflow.gguf"
            shutil.copyfile(src, fake)
            rc, stdout, stderr = run_triage(str(fake))
            self.assertEqual(rc, 2)
            data = json.loads(stdout)
            # Must remain Alignment-Tamper despite 'overflow' in name
            self.assertEqual(data["triage"]["threat_category"], "Alignment-Tamper")
            self.assertEqual(data["triage"]["recommendation"], "HARD_DROP_INGRESS")
            self.assertEqual(data["triage"]["risk_score"], 0.720)

    def test_adversarial_rename_nested_array_to_overflow(self):
        import tempfile, shutil
        src = SECURITY_DIR / "scenario4_diff_nested_array.gguf"
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "nested_array_overflow.gguf"
            shutil.copyfile(src, fake)
            rc, stdout, stderr = run_triage(str(fake), profile="llama-cpp")
            self.assertEqual(rc, 2)
            data = json.loads(stdout)
            # Must remain Compatibility-Divergence despite 'overflow' in name
            self.assertEqual(data["triage"]["threat_category"], "Compatibility-Divergence")
            self.assertEqual(data["triage"]["recommendation"], "CANARY_SANDBOX")
            self.assertEqual(data["triage"]["risk_score"], 0.450)



if __name__ == "__main__":
    unittest.main()
