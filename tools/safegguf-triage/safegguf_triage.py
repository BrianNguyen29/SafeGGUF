#!/usr/bin/env python3
"""
safegguf-triage: Production Hybrid Model Admission & Semantic Security Triage Tool.

Integrates SafeGGUF deterministic verification with TypeSafe Jev (System One) semantic
risk scoring. Supports seamless automatic fallback to the Offline Deterministic Bayesian
Engine for air-gapped, zero-cloud production environments.
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

def find_safegguf_binary() -> str:
    env_bin = os.environ.get("SAFEGGUF_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    repo_root = Path(__file__).resolve().parents[2]
    candidates = [
        repo_root / "zig-out" / "bin" / "safegguf.exe",
        repo_root / "zig-out" / "bin" / "safegguf",
        Path.cwd() / "zig-out" / "bin" / "safegguf.exe",
        Path.cwd() / "zig-out" / "bin" / "safegguf",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    # Search in PATH
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        for name in ["safegguf.exe", "safegguf"]:
            cand = Path(path_dir) / name
            if cand.exists():
                return str(cand)

    raise FileNotFoundError("SafeGGUF binary not found. Build with 'zig build' or set SAFEGGUF_BIN.")

def run_safegguf(binary: str, file_path: str, profile: str = "llama-cpp") -> Dict[str, Any]:
    cmd = [binary, "inspect", str(file_path), "--profile", profile, "--format", "json", "--endian", "auto"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        stdout = proc.stdout.strip()
        data = {}
        if stdout:
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                data = {"raw_stdout": stdout}
        if not data and proc.stderr:
            data = {"error": proc.stderr.strip(), "message": proc.stderr.strip()}
        data["exit_code"] = proc.returncode
        try:
            p = Path(file_path)
            if p.is_file():
                data["file_size"] = p.stat().st_size
        except Exception:
            pass
        return data
    except Exception as e:
        return {
            "exit_code": 74,
            "status": "ERROR",
            "error": str(e),
            "error_code": "E_SUBPROCESS_FAILED",
            "message": str(e)
        }

def offline_bayesian_triage(safegguf_res: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic rule-based triage engine for air-gapped environments.
    Maps structured SafeGGUF diagnostics to validated risk scoring.
    Does NOT infer model trust or semantic safety: PASS yields STRUCTURALLY_ACCEPTED.
    """
    exit_code = safegguf_res.get("exit_code", 2)
    err_code = safegguf_res.get("error_code", "") or ""
    category = safegguf_res.get("category", "") or ""
    msg = safegguf_res.get("message", "") or ""

    if exit_code == 0:
        return {
            "engine": "deterministic_rule_classifier",
            "structural_verdict": "STRUCTURALLY_ACCEPTED",
            "score": 0.00,
            "risk_score": 0.00,
            "risk_band": "None",
            "severity": "None",
            "category": "Structural-Pass",
            "threat_category": "Structural-Pass",
            "noul": 0.00,
            "downstream_exploit_prob": 0.00,
            "action": "STRUCTURALLY_ACCEPTED",
            "recommendation": "STRUCTURALLY_ACCEPTED",
            "rationale": "Model strictly satisfies structural, arithmetic, and resource limits. Semantic and weight safety must be verified by downstream admission policy."
        }

    if exit_code == 74 or "FILE_OPEN" in err_code or err_code == "E_FILE_OPEN_FAILED":
        return {
            "engine": "deterministic_rule_classifier",
            "structural_verdict": "REJECT",
            "score": 0.500,
            "risk_score": 0.500,
            "risk_band": "High",
            "severity": "High",
            "category": "IO-Error",
            "threat_category": "IO-Error",
            "noul": 0.500,
            "downstream_exploit_prob": 0.500,
            "action": "HARD_DROP_INGRESS",
            "recommendation": "HARD_DROP_INGRESS",
            "rationale": f"I/O or filesystem error encountered: {err_code or msg or 'E_FILE_OPEN_FAILED'}."
        }

    # Extract structured diagnostic context
    findings = safegguf_res.get("findings", [])
    first_finding = findings[0] if (isinstance(findings, list) and findings and isinstance(findings[0], dict)) else {}

    key = safegguf_res.get("key") or first_finding.get("key")
    tensor = safegguf_res.get("tensor") or first_finding.get("tensor")
    tensor_index = safegguf_res.get("tensor_index") if safegguf_res.get("tensor_index") is not None else first_finding.get("tensor_index")

    offset = safegguf_res.get("offset") if safegguf_res.get("offset") is not None else first_finding.get("offset")
    expected_offset = safegguf_res.get("expected_offset") if safegguf_res.get("expected_offset") is not None else first_finding.get("expected_offset")
    alignment = safegguf_res.get("alignment") if safegguf_res.get("alignment") is not None else first_finding.get("alignment")
    if alignment is None:
        alignment = 32

    file_size = safegguf_res.get("file_size")
    if file_size is None and safegguf_res.get("file"):
        try:
            fp = Path(safegguf_res["file"])
            if fp.is_file():
                file_size = fp.stat().st_size
        except Exception:
            pass

    has_tensor_context = (tensor is not None) or (tensor_index is not None) or ("dims" in safegguf_res)
    if not has_tensor_context and isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict) and (f.get("tensor") is not None or f.get("tensor_index") is not None):
                has_tensor_context = True
                break

    # Branch 1: Deep diagnosis of E_CompatibilityViolation
    if err_code == "E_CompatibilityViolation":
        if has_tensor_context:
            score = 0.980
            sev = "Critical"
            cat = "Arithmetic-Exploit"
            noul = 0.95
            rationale = "Signed 64-bit arithmetic overflow during tensor dimension/product validation."
        elif key == "general.alignment" or "alignment" in str(msg).lower():
            score = 0.450
            sev = "Medium"
            cat = "Compatibility-Divergence"
            noul = 0.40
            rationale = "Non-power-of-two alignment divergence (allowed under gguf-spec, rejected under llama-cpp)."
        else:
            diag_text = (str(msg) + " " + " ".join(str(f.get("message", "")) for f in findings if isinstance(f, dict))).lower()
            if any(k in diag_text for k in ["dims", "tensor", "int64", "dim", "product", "bytes", "overflow"]):
                score = 0.980
                sev = "Critical"
                cat = "Arithmetic-Exploit"
                noul = 0.95
                rationale = "Arithmetic overflow detected in tensor geometry diagnostics."
            else:
                score = 0.450
                sev = "Medium"
                cat = "Compatibility-Divergence"
                noul = 0.40
                rationale = "Upstream compatibility invariant divergence."

    # Branch 2: Genuine arithmetic integer overflow exploits
    elif (
        "Arithmetic" in err_code
        or "Overflow" in err_code
        or category == "arithmetic"
        or "BlockDivisibility" in err_code
    ):
        score = 0.980
        sev = "Critical"
        cat = "Arithmetic-Exploit"
        noul = 0.95
        rationale = f"Arithmetic overflow or integer exploit detected ({err_code})."

    # Branch 3: Resource exhaustion and quota ceilings
    elif (
        "Allocation" in err_code
        or "Quota" in err_code
        or "Resource" in err_code
        or category == "resource"
        or "Recursion" in err_code
    ):
        score = 0.750
        sev = "High"
        cat = "Resource-Exhaustion"
        noul = 0.70
        rationale = f"Resource exhaustion or quota ceiling exceeded ({err_code})."

    # Branch 4: Deep diagnosis of E_NonContiguousTensorOffset
    elif err_code == "E_NonContiguousTensorOffset" or "NonContiguous" in err_code:
        if offset is not None and expected_offset is not None and offset < expected_offset:
            score = 0.720
            sev = "High"
            cat = "Alignment-Tamper"
            noul = 0.65
            rationale = f"Tensor payload overlap detected: offset {offset} < expected {expected_offset}."
        elif file_size is not None and offset is not None and offset > file_size:
            score = 0.720
            sev = "High"
            cat = "Alignment-Tamper"
            noul = 0.65
            rationale = f"Out-of-bounds tensor offset detected: offset {offset} exceeds file size {file_size}."
        elif alignment is not None and offset is not None and offset % alignment != 0:
            score = 0.720
            sev = "High"
            cat = "Alignment-Tamper"
            noul = 0.65
            rationale = f"Misaligned tensor offset: offset {offset} is not divisible by alignment {alignment}."
        elif (
            offset is not None
            and expected_offset is not None
            and offset > expected_offset
            and (alignment is None or offset % alignment == 0)
            and (file_size is None or offset <= file_size)
        ):
            score = 0.450
            sev = "Medium"
            cat = "Compatibility-Divergence"
            noul = 0.40
            rationale = f"Non-contiguous aligned tensor gap (offset {offset} > expected {expected_offset})."
        else:
            score = 0.450
            sev = "Medium"
            cat = "Compatibility-Divergence"
            noul = 0.40
            rationale = f"Non-contiguous tensor offset ({err_code})."

    # Branch 5: Structural alignment and zero-padding tampering
    elif (
        "Padding" in err_code
        or "Misaligned" in err_code
        or "Overlap" in err_code
        or "OutOfBounds" in err_code
        or "Alignment" in err_code
    ):
        score = 0.720
        sev = "High"
        cat = "Alignment-Tamper"
        noul = 0.65
        rationale = f"Structural alignment or zero-padding tampering detected ({err_code})."

    # Branch 6: Compatibility divergence
    elif (
        category == "compatibility"
        or "Compatibility" in err_code
        or "NestedArray" in err_code
        or "TooLong" in err_code
    ):
        score = 0.450
        sev = "Medium"
        cat = "Compatibility-Divergence"
        noul = 0.40
        rationale = f"Compatibility divergence detected ({err_code})."

    # Branch 7: Malformed headers, syntax errors, and steganography
    else:
        score = 0.520
        sev = "Medium"
        cat = "Malformed-Header"
        noul = 0.42
        rationale = f"Rejected by SafeGGUF with error code '{err_code}' in category '{category}'."

    rec = "HARD_DROP_INGRESS" if score >= 0.50 else "CANARY_SANDBOX"

    return {
        "engine": "deterministic_rule_classifier",
        "structural_verdict": "REJECT",
        "score": score,
        "risk_score": score,
        "risk_band": sev,
        "severity": sev,
        "category": cat,
        "threat_category": cat,
        "noul": score,
        "downstream_exploit_prob": score,
        "action": rec,
        "recommendation": rec,
        "rationale": rationale,
    }

def online_jev_triage(safegguf_res: Dict[str, Any], api_key: str, allow_fallback: bool = True) -> Dict[str, Any]:
    """
    Online TypeSafe Jev System One evaluation when API key is present.
    Dispatches live HTTP POST request to TypeSafe API endpoint over verified TLS.
    If allow_fallback is True (auto mode) and network call fails,
    gracefully falls back to offline deterministic rule classifier with engine 'offline_deterministic_fallback'.
    If allow_fallback is False (online mode) and network call fails,
    raises ConnectionError.
    """
    import urllib.request
    import urllib.error
    import ssl

    req_data = {
        "model": "jev-latest",
        "state": safegguf_res,
        "questions": {
            "risk_score": {"primitive": "score", "dimension": "security_risk_severity"},
            "threat_category": {
                "primitive": "choice",
                "options": [
                    "Structural-Pass",
                    "Malformed-Header",
                    "Arithmetic-Exploit",
                    "Resource-Exhaustion",
                    "Alignment-Tamper",
                    "Compatibility-Divergence",
                    "IO-Error",
                ],
            },
            "exploit_prob": {"primitive": "noul", "condition": "exploits_downstream_runtime"},
        },
    }
    body = json.dumps(req_data).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "SafeGGUF-Triage/1.0",
    }
    req = urllib.request.Request(
        "https://api.typesafe.ai/v1/systemone",
        data=body,
        headers=headers,
        method="POST",
    )
    # Enforce verified TLS certificate validation
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            answers = res_json.get("answers", {})
            score = float(answers.get("risk_score", {}).get("score", 0.010))
            cat = str(answers.get("threat_category", {}).get("choice", "Structural-Pass"))
            noul = float(answers.get("exploit_prob", {}).get("probability", 0.01))

            if score < 0.15:
                sev = "None"
                rec = "STRUCTURALLY_ACCEPTED"
            elif score < 0.35:
                sev = "Low"
                rec = "STRUCTURALLY_ACCEPTED"
            elif score < 0.65:
                sev = "Medium"
                rec = "CANARY_SANDBOX"
            elif score < 0.85:
                sev = "High"
                rec = "HARD_DROP_INGRESS"
            else:
                sev = "Critical"
                rec = "HARD_DROP_INGRESS"

            return {
                "engine": "online_jev_system_one",
                "structural_verdict": "STRUCTURALLY_ACCEPTED" if score < 0.20 else "REJECT",
                "score": score,
                "risk_score": score,
                "risk_band": sev,
                "severity": sev,
                "category": cat,
                "threat_category": cat,
                "noul": score,
                "downstream_exploit_prob": score,
                "action": rec,
                "recommendation": rec,
                "rationale": answers.get("threat_category", {}).get("rationale", "Evaluated by online TypeSafe Jev System One model."),
            }
    except Exception as exc:
        if not allow_fallback:
            raise ConnectionError(f"Online triage failed to connect to TypeSafe Jev API: {exc}") from exc
        fallback = offline_bayesian_triage(safegguf_res)
        fallback["engine"] = "offline_deterministic_fallback"
        fallback["rationale"] = f"Online API call failed ({type(exc).__name__}: {exc}); fallback to offline rule classifier: " + fallback.get("rationale", "")
        return fallback

def triage_model(file_path: str, profile: str = "llama-cpp", mode: str = "auto") -> Dict[str, Any]:
    binary = find_safegguf_binary()
    raw_res = run_safegguf(binary, file_path, profile=profile)
    raw_res["file"] = str(file_path)

    api_key = os.environ.get("TYPESAFE_API_KEY")
    if mode == "online":
        if not api_key:
            raise ValueError("Mode 'online' selected but TYPESAFE_API_KEY environment variable is not set.")
        triage_info = online_jev_triage(raw_res, api_key, allow_fallback=False)
    elif mode == "offline":
        triage_info = offline_bayesian_triage(raw_res)
    else:  # auto
        if api_key:
            triage_info = online_jev_triage(raw_res, api_key, allow_fallback=True)
        else:
            triage_info = offline_bayesian_triage(raw_res)

    exit_code = raw_res.get("exit_code", 2)
    err_code = raw_res.get("error_code") or ""
    if exit_code == 0:
        verdict = "PASS"
    elif exit_code in (64, 70, 74) or "FILE_OPEN" in err_code:
        verdict = "ERROR"
    else:
        verdict = "REJECT"

    return {
        "file": str(file_path),
        "profile": profile,
        "safegguf_verdict": verdict,
        "safegguf_exit_code": exit_code,
        "error_code": raw_res.get("error_code"),
        "triage": triage_info,
    }

class TriageArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"error: {message}\n")
        sys.exit(64)

def main():
    parser = TriageArgumentParser(description="SafeGGUF Hybrid Admission & Semantic Triage Tool")
    parser.add_argument("file", help="Path to GGUF model file")
    parser.add_argument("--profile", choices=["llama-cpp", "gguf-spec"], default="llama-cpp", help="Validation profile (default: llama-cpp)")
    parser.add_argument("--mode", choices=["auto", "online", "offline"], default="auto", help="Triage mode (default: auto)")
    parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format (default: text)")

    args = parser.parse_args()

    try:
        report = triage_model(args.file, profile=args.profile, mode=args.mode)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(64)
    except ConnectionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(70)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(64)


    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        t = report["triage"]
        print("=" * 65)
        print("          SAFEGGUF MODEL ADMISSION TRIAGE REPORT")
        print("=" * 65)
        print(f"Target File         : {report['file']}")
        print(f"Profile             : {report['profile']}")
        print(f"SafeGGUF Verdict    : {report['safegguf_verdict']} (Exit Code {report['safegguf_exit_code']})")
        if report.get("error_code"):
            print(f"Error Code          : {report['error_code']}")
        print("-" * 65)
        print(f"Triage Engine       : {t['engine']}")
        print(f"Risk Score          : {t['risk_score']:.3f} ({t['severity']})")
        print(f"Risk Band           : {t.get('risk_band', t['severity'])}")
        print(f"Threat Category     : {t['threat_category']}")
        print(f"Admission Action    : >>> {t['recommendation']} <<<")
        print(f"Rationale           : {t['rationale']}")
        print("=" * 65)

    raw_exit = report.get("safegguf_exit_code", 2)
    sys.exit(raw_exit if raw_exit in (0, 2, 64, 70, 74) else 2)

if __name__ == "__main__":
    main()

