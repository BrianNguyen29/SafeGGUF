"""
Rolling-upstream canary driver (F-09, Oracle B).

Resolves the moving upstream ggml default branch to exactly one full commit
SHA, builds the rolling oracle from that SHA through tests/build_oracle.sh
(isolated cache .cache/oracle/rolling/<sha>/ and binary
tests/oracle/ggml_oracle_rolling), then runs tests/differential.py with
--oracle <rolling> --report-json <path>, so the rolling type table is compared
before the pinned fixture matrix is swept.

Pinned Oracle A (tests/oracle/ggml_oracle, ggml v0.23.0 e91ded11...) is never
touched or silently replaced.

Policy (§57/§58):
  - Divergences are report-only: they never fail this driver; the JSON report
    and readable summary carry the signal, and the workflow publishes both.
  - The rolling baseline is never auto-updated: a human reviews the report and
    changes the pinned contract/baseline only through an explicit commit.
  - Only infrastructure failures (SHA resolution, oracle build, oracle identity,
    differential run without a report) exit non-zero, so the canary may
    legitimately go red without blocking PRs.

Usage:
  python tests/canary_drift.py [--ref <full-40-hex-sha>]
      [--upstream-url <git-url>] [--report <json-path>] [--summary <md-path>]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
BUILD_ORACLE = os.path.join(SCRIPT_DIR, "build_oracle.sh")
DIFFERENTIAL = os.path.join(SCRIPT_DIR, "differential.py")
ROLLING_BIN = os.path.join(SCRIPT_DIR, "oracle", "ggml_oracle_rolling")
UPSTREAM_URL = "https://github.com/ggml-org/ggml.git"
UPSTREAM_BRANCH_REF = "refs/heads/master"
DEFAULT_REPORT = os.path.join(REPO_ROOT, ".cache", "canary", "upstream-canary-report.json")
DEFAULT_SUMMARY = os.path.join(REPO_ROOT, ".cache", "canary", "upstream-canary-summary.md")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_LISTED = 20  # readable summary caps long categories; the JSON report is complete


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ref", default=None,
                        help="full 40-hex upstream commit SHA (default: resolve refs/heads/master once)")
    parser.add_argument("--upstream-url", default=UPSTREAM_URL,
                        help="upstream ggml git URL (default: %(default)s)")
    parser.add_argument("--report", default=DEFAULT_REPORT,
                        help="JSON drift report path (default: %(default)s)")
    parser.add_argument("--summary", default=DEFAULT_SUMMARY,
                        help="readable summary path (default: %(default)s)")
    return parser.parse_args()


def now_utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def repo_sha():
    try:
        proc = subprocess.run(["git", "-C", REPO_ROOT, "rev-parse", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def resolve_upstream_sha(url):
    """Resolve the moving default branch to one full SHA (never report 'master')."""
    proc = subprocess.run(["git", "ls-remote", url, UPSTREAM_BRANCH_REF],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git ls-remote {url} {UPSTREAM_BRANCH_REF} failed (rc={proc.returncode}): {proc.stderr.strip()}")
    fields = proc.stdout.split()
    sha = fields[0].lower() if fields else ""
    if not SHA_RE.match(sha):
        raise RuntimeError(f"git ls-remote returned no full commit SHA: {proc.stdout.strip()!r}")
    return sha


def oracle_identity(path):
    proc = subprocess.run([path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"{path} --version failed (rc={proc.returncode}): {proc.stderr.strip()}")
    info = {}
    for line in proc.stdout.strip().splitlines():
        key, _, value = line.partition(":")
        info[key.strip()] = value.strip()
    return info


def sha_matches(resolved_sha, reported_sha):
    reported = (reported_sha or "").lower()
    return bool(reported) and (resolved_sha.startswith(reported) or reported.startswith(resolved_sha))


def write_json(path, payload):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def write_text(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def fallback_report(sha, oracle_errors, note):
    return {
        "schema_version": 1,
        "generated_utc": now_utc(),
        "oracle_name": "rolling",
        "oracle_path": ROLLING_BIN,
        "upstream_version": None,
        "upstream_sha": sha,
        "oracle_reported_commit": None,
        "safegguf_sha": repo_sha(),
        "fixture_count": 0,
        "new_type_ids": [],
        "type_drift": None,
        "new_divergences": [],
        "resolved_divergences": [],
        "safe_accept_upstream_reject": [],
        "safe_reject_upstream_accept": [],
        "oracle_errors": oracle_errors,
        "baseline_mismatches": [],
        "canary_note": note,
    }


def format_summary(sha, identity, report, differential_rc, note):
    lines = []
    lines.append("# Upstream canary report (rolling Oracle B)")
    lines.append("")
    lines.append(f"- generated_utc: {report.get('generated_utc') or now_utc()}")
    lines.append(f"- resolved upstream sha: {sha or 'unresolved'}")
    lines.append(f"- upstream version: {identity.get('ggml_version', 'unknown')}")
    lines.append(f"- upstream commit: {identity.get('ggml_commit', 'unknown')}")
    lines.append(f"- safegguf sha: {report.get('safegguf_sha') or repo_sha()}")
    lines.append(f"- rolling oracle: {report.get('oracle_path', ROLLING_BIN)}")
    if differential_rc is not None:
        lines.append(f"- differential.py exit code: {differential_rc} (nonzero never fails the canary)")
    if note:
        lines.append(f"- note: {note}")
    lines.append("")

    drift = report.get("type_drift")
    lines.append("## Type drift (rolling oracle vs SafeGGUF pinned table)")
    if not drift:
        lines.append("- comparison unavailable (see oracle errors)")
    else:
        keys = ("new_types", "removed_types", "renamed_types",
                "changed_block_sizes", "changed_type_sizes")
        total = sum(len(drift.get(k, [])) for k in keys)
        if total == 0:
            lines.append("- none")
        else:
            for key in keys:
                entries = drift.get(key, [])
                if not entries:
                    continue
                lines.append(f"- {key}: {len(entries)}")
                for entry in entries[:MAX_LISTED]:
                    lines.append(f"  - {json.dumps(entry, sort_keys=True)}")
                if len(entries) > MAX_LISTED:
                    lines.append(f"  - ... and {len(entries) - MAX_LISTED} more (see JSON report)")
    lines.append("")

    lines.append("## Divergences vs pinned baseline (report-only)")
    categories = (
        ("new_divergences", "new divergences"),
        ("resolved_divergences", "resolved divergences"),
        ("safe_reject_upstream_accept",
         "safe REJECT / upstream PASS (intentional subset or false reject)"),
        ("safe_accept_upstream_reject",
         "safe PASS / upstream REJECT (possible false accept or upstream tightening)"),
        ("baseline_mismatches", "baseline mismatches"),
        ("oracle_errors", "oracle errors"),
    )
    for key, label in categories:
        entries = report.get(key) or []
        lines.append(f"- {label}: {len(entries)}")
        for entry in entries[:MAX_LISTED]:
            lines.append(f"  - {entry if isinstance(entry, str) else json.dumps(entry, sort_keys=True)}")
        if len(entries) > MAX_LISTED:
            lines.append(f"  - ... and {len(entries) - MAX_LISTED} more (see JSON report)")
    lines.append("")

    lines.append("## Baseline policy")
    lines.append("No automatic baseline update: review this report and make any pinned-contract/")
    lines.append("baseline change as an explicit commit (§58). Oracle A stays blocking and unchanged.")
    return "\n".join(lines) + "\n"


def finish(report_path, summary_path, sha, identity, report, differential_rc, note):
    summary = format_summary(sha, identity, report, differential_rc, note)
    write_text(summary_path, summary)
    print()
    print(summary)
    print(f"Canary report: {report_path}")
    print(f"Canary summary: {summary_path}")


def main():
    args = parse_args()
    report_path = os.path.abspath(args.report)
    summary_path = os.path.abspath(args.summary)

    # 1. Resolve the floating upstream default branch to one exact full SHA.
    if args.ref:
        sha = args.ref.strip().lower()
        if not SHA_RE.match(sha):
            print(f"error: --ref must be a full 40-hex commit SHA (got {args.ref!r}); refusing floating refs")
            return 2
        print(f"Using operator-provided upstream commit {sha}.")
    else:
        try:
            sha = resolve_upstream_sha(args.upstream_url)
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            print(f"error: could not resolve {UPSTREAM_BRANCH_REF}: {exc}")
            report = fallback_report(None, [{"stage": "resolve_upstream", "message": str(exc)}],
                                     "upstream resolution failed")
            write_json(report_path, report)
            finish(report_path, summary_path, None, {}, report, None, report["canary_note"])
            return 1
        print(f"Resolved {UPSTREAM_BRANCH_REF} to {sha}.")

    # 2. Build Oracle B at exactly that SHA (isolated cache/binary).
    build_rc = subprocess.run(["bash", BUILD_ORACLE, "--name", "rolling", "--ref", sha],
                              cwd=REPO_ROOT).returncode
    if build_rc != 0:
        report = fallback_report(
            sha, [{"stage": "build_rolling_oracle", "message": f"tests/build_oracle.sh exited {build_rc}"}],
            "rolling oracle build failed")
        write_json(report_path, report)
        finish(report_path, summary_path, sha, {}, report, None, report["canary_note"])
        return 1

    # 3. Verify the binary really is the resolved commit before testing it.
    try:
        identity = oracle_identity(ROLLING_BIN)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        report = fallback_report(
            sha, [{"stage": "rolling_oracle_identity", "message": str(exc)}],
            "rolling oracle identity check failed")
        write_json(report_path, report)
        finish(report_path, summary_path, sha, {}, report, None, report["canary_note"])
        return 1
    if not sha_matches(sha, identity.get("ggml_commit")):
        message = (f"rolling oracle reports ggml_commit {identity.get('ggml_commit')!r} "
                   f"which does not match the resolved upstream SHA {sha}")
        report = fallback_report(sha, [{"stage": "rolling_oracle_identity", "message": message}],
                                 "rolling oracle identity mismatch")
        write_json(report_path, report)
        finish(report_path, summary_path, sha, identity, report, None, report["canary_note"])
        return 1
    print(f"Rolling oracle identity: ggml_version={identity.get('ggml_version')} "
          f"ggml_commit={identity.get('ggml_commit')}")

    # 4. Run the type-drift-first differential sweep with the rolling oracle.
    differential_rc = subprocess.run(
        [sys.executable, DIFFERENTIAL, "--oracle", ROLLING_BIN, "--report-json", report_path],
        cwd=REPO_ROOT).returncode

    if not os.path.exists(report_path):
        report = fallback_report(
            sha,
            [{"stage": "differential_run",
              "message": f"tests/differential.py exited {differential_rc} without writing {report_path}"}],
            "differential run produced no report")
        write_json(report_path, report)
        finish(report_path, summary_path, sha, identity, report, differential_rc, report["canary_note"])
        return 1

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    # The report records the exact full SHA (never "master"); the short commit
    # string the oracle was compiled with is kept separately for traceability.
    report["upstream_sha"] = sha
    report["oracle_reported_commit"] = identity.get("ggml_commit")
    write_json(report_path, report)
    note = (f"differential.py exited {differential_rc}; divergences are report-only for the canary"
            if differential_rc != 0 else None)
    finish(report_path, summary_path, sha, identity, report, differential_rc, note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
