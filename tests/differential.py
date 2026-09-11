"""
True Differential Testing Harness for SafeGGUF vs Upstream ggml Oracle.

Compares acceptance verdicts between SafeGGUF (--profile llama-cpp) and the
compiled upstream ggml oracle. By default the pinned oracle builds from ggml
v0.23.0 at commit e91ded11bdcd78c42f9c8d3978ff6686eb4c1226 (Oracle A,
blocking); --oracle <path> points the same sweep at the rolling canary oracle
(Oracle B, built by tests/build_oracle.sh --name rolling) without touching
Oracle A.

Besides the hand-written fixtures in tests/fixtures/, the harness also sweeps
the systematically generated differential matrix from tests/differential_matrix.py
(tests/fixtures/matrix/, roadmap issue #7) when it has been generated.

--report-json <path> emits the machine-readable drift report (schema_version 1,
F-09 §56): type drift is compared first (§55), then verdict divergences are
classified against the pinned EXPECTED_MATRIX baseline (§57).
"""

import argparse
import json
import os
import subprocess
import sys
import time

import differential_matrix
import test_oracle_types

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
        "SafeGGUF deliberately enforces the GGUF specification's zero-padding requirement (required padding must be 0x00 bytes to the next alignment boundary) as an anti-tamper safe-subset invariant; upstream ggml aligns without checking byte contents.",
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

# Roadmap issue #7: wire in the systematically generated differential matrix
# (all 35 active GGML types x boundary shapes + n_dims/alignment/metadata
# boundaries). Generated entries are marked by the "matrix/" key prefix and a
# "[GENERATED]" rationale prefix; see tests/differential_matrix.py.
EXPECTED_MATRIX.update(differential_matrix.generated_expected_entries())

def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--oracle", metavar="PATH", default=ORACLE_BIN,
                        help="oracle binary to test (default: pinned %(default)s)")
    parser.add_argument("--report-json", metavar="PATH", default=None,
                        help="write the machine-readable drift report (schema_version 1)")
    return parser.parse_args()

def ensure_binaries(custom_oracle):
    if not os.path.exists(SAFEGGUF_BIN):
        print(f"SafeGGUF binary not found at {SAFEGGUF_BIN}. Running zig build...")
        subprocess.check_call(["zig", "build", "-Doptimize=ReleaseSafe"], cwd=REPO_ROOT)

    if not os.path.exists(ORACLE_BIN):
        if custom_oracle:
            print(f"Error: custom oracle binary not found at {ORACLE_BIN}")
            sys.exit(1)
        print(f"Building upstream ggml oracle via {os.path.join(SCRIPT_DIR, 'build_oracle.sh')}...")
        subprocess.check_call([os.path.join(SCRIPT_DIR, "build_oracle.sh")], cwd=REPO_ROOT)

def oracle_version_output():
    proc = subprocess.run([ORACLE_BIN, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    out = proc.stdout.strip()
    print(f"Oracle runtime identity: {out.replace(chr(10), ', ')}")
    return out

def assert_oracle_identity():
    out = oracle_version_output()
    assert "ggml_version: 0.23.0" in out, f"Unexpected ggml_version: {out}"
    assert "ggml_commit: e91ded1" in out, f"Unexpected ggml_commit: {out}"
    return out

def parse_identity(out):
    info = {}
    for line in out.splitlines():
        key, _, value = line.partition(":")
        info[key.strip()] = value.strip()
    return info

def repo_sha():
    try:
        proc = subprocess.run(["git", "-C", REPO_ROOT, "rev-parse", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None

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

def dump_oracle_types():
    """Run `oracle --dump-types` and parse the type traits table."""
    proc = subprocess.run([ORACLE_BIN, "--dump-types"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"oracle --dump-types failed (rc={proc.returncode}): {proc.stderr.strip()}")
    lines = proc.stdout.strip().splitlines()
    if not lines or lines[0] != "TYPE_TRAITS_BEGIN" or lines[-1] != "TYPE_TRAITS_END":
        raise RuntimeError(f"malformed oracle --dump-types output: {proc.stdout[:200]!r}")
    types = {}
    for line in lines[1:-1]:
        first_comma = line.find(",")
        t_id = int(line[:first_comma])
        rest = line[first_comma + 1:]
        parts = rest.rsplit(",", 2)
        types[t_id] = {"name": parts[0], "block_size": int(parts[1]), "type_size": int(parts[2])}
    return types

def compare_type_tables(oracle_types):
    """Type drift first (F-09 §55): compare the oracle slot table against
    SafeGGUF's pinned table and report new/removed/renamed/changed slots."""
    _, safegguf = test_oracle_types.parse_safegguf_traits()
    drift = {
        "oracle_slot_count": len(oracle_types),
        "safegguf_type_count": len(safegguf),
        "new_types": [],
        "removed_types": [],
        "renamed_types": [],
        "changed_block_sizes": [],
        "changed_type_sizes": [],
    }
    for t_id in sorted(oracle_types):
        up = oracle_types[t_id]
        if up["block_size"] <= 0 or up["type_size"] <= 0:
            if t_id in safegguf:
                drift["removed_types"].append({
                    "id": t_id,
                    "oracle_name": up["name"],
                    "safegguf_name": safegguf[t_id]["name"],
                })
            continue
        if t_id not in safegguf:
            drift["new_types"].append({
                "id": t_id,
                "name": up["name"],
                "block_size": up["block_size"],
                "type_size": up["type_size"],
            })
            continue
        safe = safegguf[t_id]
        if safe["name"].lower() != up["name"].lower():
            drift["renamed_types"].append({
                "id": t_id,
                "safegguf_name": safe["name"],
                "oracle_name": up["name"],
            })
        if safe["block_size"] != up["block_size"]:
            drift["changed_block_sizes"].append({
                "id": t_id, "name": up["name"],
                "safegguf": safe["block_size"], "oracle": up["block_size"],
            })
        if safe["type_size"] != up["type_size"]:
            drift["changed_type_sizes"].append({
                "id": t_id, "name": up["name"],
                "safegguf": safe["type_size"], "oracle": up["type_size"],
            })
    return drift

def print_type_drift(drift):
    categories = ("new_types", "removed_types", "renamed_types",
                  "changed_block_sizes", "changed_type_sizes")
    total = sum(len(drift[c]) for c in categories)
    if total == 0:
        print("Type drift: none (oracle type table matches the SafeGGUF pinned table).")
        return
    print(f"Type drift detected ({total} entries):")
    for category in categories:
        for entry in drift[category]:
            print(f"  {category}: {entry}")

def classify_divergence(safe_verdict, up_verdict):
    """F-09 §57 divergence semantics."""
    if safe_verdict == "REJECT" and up_verdict == "PASS":
        return "intentional safe subset or compatibility false reject"
    if safe_verdict == "PASS" and up_verdict == "REJECT":
        return "possible safe false accept or upstream tightening"
    return "agreement"

def oracle_label():
    base = os.path.basename(ORACLE_BIN)
    if base == "ggml_oracle":
        return "pinned"
    if base.startswith("ggml_oracle_"):
        return base[len("ggml_oracle_"):]
    return "custom"

def write_report(path, report):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(f"Wrote differential report to {path}")

def main():
    args = parse_args()
    global ORACLE_BIN
    custom_oracle = os.path.abspath(args.oracle) != ORACLE_BIN
    ORACLE_BIN = os.path.abspath(args.oracle)

    header_target = "Upstream ggml 0.23.0" if not custom_oracle else "Upstream ggml (rolling oracle)"
    print(f"=== SafeGGUF vs {header_target} True Differential Validation ===")
    ensure_binaries(custom_oracle)

    if custom_oracle:
        version_text = oracle_version_output()
    else:
        version_text = assert_oracle_identity()
    identity = parse_identity(version_text)

    # Type drift first (§55): catches upstream format evolution even when the
    # fixture matrix cannot generate the new type.
    type_drift = None
    oracle_errors = []
    try:
        type_drift = compare_type_tables(dump_oracle_types())
        print_type_drift(type_drift)
    except (RuntimeError, ValueError) as exc:
        print(f"WARNING: type drift comparison failed: {exc}")
        oracle_errors.append({"stage": "type_drift", "message": str(exc)})

    fixtures = sorted([f for f in os.listdir(FIXTURES_DIR) if f.endswith(".gguf")])
    matrix_dir = os.path.join(FIXTURES_DIR, "matrix")
    if os.path.isdir(matrix_dir):
        fixtures += ["matrix/" + f for f in sorted(os.listdir(matrix_dir)) if f.endswith(".gguf")]
    else:
        print("Note: generated matrix not found; run `python tests/differential_matrix.py` to include it.\n")
    fixtures.sort()
    if not fixtures:
        print("Error: No test fixtures found. Run generate_fixtures.py first.")
        sys.exit(1)

    generated_count = sum(1 for f in fixtures if f.startswith(differential_matrix.MATRIX_PREFIX))
    print(f"Loaded {len(fixtures)} fixtures from {FIXTURES_DIR} "
          f"({len(fixtures) - generated_count} hand-written + {generated_count} generated matrix)\n")
    print(f"{'Fixture':<44} | {'SafeGGUF':<8} | {'Upstream Load':<13} | {'Upstream NoLoad':<15} | {'Verdict'}")
    print("-" * 115)

    failures = []
    new_divergences = []
    resolved_divergences = []
    safe_reject_upstream_accept = []
    safe_accept_upstream_reject = []
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

        # Classify actual divergences against the pinned EXPECTED_MATRIX
        # baseline for the report (§56/§57); does not change pass/fail logic.
        mode_results = (
            ("load-data", up_load_verdict, up_load_rc, exp_up_load),
            ("no-load", up_noload_verdict, up_noload_rc, exp_up_noload),
        )
        if safe_verdict not in ("PASS", "REJECT"):
            oracle_errors.append({
                "fixture": f,
                "stage": "safegguf",
                "verdict": safe_verdict,
                "rc": safe_rc,
                "stderr": safe_err,
            })
        for mode, up_verdict, up_rc, exp_up in mode_results:
            if up_verdict not in ("PASS", "REJECT"):
                oracle_errors.append({
                    "fixture": f,
                    "stage": f"upstream {mode}",
                    "verdict": up_verdict,
                    "rc": up_rc,
                })
                continue
            if safe_verdict not in ("PASS", "REJECT"):
                continue
            actual_divergence = safe_verdict != up_verdict
            expected_divergence = exp_safe != exp_up
            if actual_divergence:
                entry = {
                    "fixture": f,
                    "mode": mode,
                    "safe": safe_verdict,
                    "upstream": up_verdict,
                    "classification": classify_divergence(safe_verdict, up_verdict),
                }
                if safe_verdict == "REJECT":
                    safe_reject_upstream_accept.append(entry)
                else:
                    safe_accept_upstream_reject.append(entry)
            if actual_divergence and not expected_divergence:
                new_divergences.append({
                    "fixture": f,
                    "mode": mode,
                    "safe": safe_verdict,
                    "upstream": up_verdict,
                    "expected_safe": exp_safe,
                    "expected_upstream": exp_up,
                    "classification": classify_divergence(safe_verdict, up_verdict),
                })
            elif expected_divergence and not actual_divergence:
                resolved_divergences.append({
                    "fixture": f,
                    "mode": mode,
                    "expected_safe": exp_safe,
                    "expected_upstream": exp_up,
                })

        if mismatch:
            status_note = "MISMATCH FAILURE"
        elif safe_verdict != up_load_verdict or safe_verdict != up_noload_verdict:
            status_note = f"DOCUMENTED DIVERGENCE ({rationale[:40]}...)"
        else:
            status_note = "MATCH (100% UNANIMOUS)"

        print(f"{f:<44} | {safe_verdict:<8} | {up_load_verdict:<13} | {up_noload_verdict:<15} | {status_note}")

    print("-" * 115)
    print(f"Divergences vs pinned baseline: new={len(new_divergences)}, "
          f"resolved={len(resolved_divergences)}, "
          f"safe REJECT/upstream PASS={len(safe_reject_upstream_accept)}, "
          f"safe PASS/upstream REJECT={len(safe_accept_upstream_reject)}")
    if oracle_errors:
        print(f"Oracle errors: {len(oracle_errors)}")

    if args.report_json:
        write_report(args.report_json, {
            "schema_version": 1,
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "oracle_name": oracle_label(),
            "oracle_path": ORACLE_BIN,
            "upstream_version": identity.get("ggml_version"),
            "upstream_sha": identity.get("ggml_commit"),
            "safegguf_sha": repo_sha(),
            "fixture_count": len(fixtures),
            "new_type_ids": sorted(t["id"] for t in (type_drift or {}).get("new_types", [])),
            "type_drift": type_drift,
            "new_divergences": new_divergences,
            "resolved_divergences": resolved_divergences,
            "safe_accept_upstream_reject": safe_accept_upstream_reject,
            "safe_reject_upstream_accept": safe_reject_upstream_accept,
            "oracle_errors": oracle_errors,
            "baseline_mismatches": failures,
        })

    if failures:
        print("\nDIFFERENTIAL FAILURES DETECTED:")
        for fail in failures:
            print("  X " + fail)
        sys.exit(1)

    print(f"\n✓ True Differential Test Suite PASSED! All {len(fixtures)} fixtures verified with full 3-column "
          f"assertions against upstream ggml {identity.get('ggml_version', '0.23.0')} "
          f"({len(fixtures) - generated_count} hand-written + {generated_count} generated matrix).")

if __name__ == "__main__":
    main()
