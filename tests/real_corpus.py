"""
Real-world corpus runner (F-04 / B1): manifest-driven, advisory.

The manifest (tests/real-corpus-manifest.json) ships EMPTY by design: URLs,
sha256 digests, sizes and licenses must never be invented. With no entries the
runner exits 0 vacuously with a clear note, so the advisory workflow stays
green until a maintainer supplies approved immutable entries.

Pipeline per entry (plan sections 12/14/15):
  schema validate -> tier select -> bounded streaming download to a temp file
  (sha256 computed as bytes arrive; the declared Content-Length is never
  trusted) -> size + hash verify -> atomic promote to
  .cache/real-corpus/<sha256>.gguf -> `safegguf inspect --format json` for
  every expected_profile key -> verdict compare -> JSON report.

Failure taxonomy (a network outage is never a compatibility regression):

  DOWNLOAD_ERROR            network/IO failure while fetching (advisory; with
                            --tolerate-download-errors it is reported as an
                            entry skip and does not fail the run)
  SIZE_MISMATCH             downloaded bytes != manifest size (Content-Length ignored)
  HASH_MISMATCH             streamed sha256 != manifest sha256 (fails closed; no promote)
  SAFEGGUF_ERROR            exit code outside the {0 PASS, 2 REJECT} contract
  EXPECTED_RESULT_MISMATCH  validator verdict != expected_profile verdict
  PASS                      validator verdict matched the expectation

Exit status: 0 = every selected entry matched its expectations (or nothing was
selected / the manifest is empty, or - with --tolerate-download-errors - only
download errors occurred); 1 = at least one failure or a manifest schema error.
Gate exception: --tolerate-download-errors downgrades DOWNLOAD_ERROR to a
reported skip (exit 0) so network outages never block CI; size/hash/verdict
mismatches and Safegguf CLI errors still fail. A JSON report is written even
for an empty manifest.

Run:  python tests/real_corpus.py [--tier 1] [--report PATH]
      python tests/real_corpus.py --tier all
      python tests/real_corpus.py --tolerate-download-errors   # CI gate mode
Verification needs the ReleaseSafe binary at zig-out/bin/safegguf only when the
manifest selects entries (zig build -Doptimize=ReleaseSafe).
"""

import argparse
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SAFEGGUF_BIN = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf")
MANIFEST_PATH = os.path.join(SCRIPT_DIR, "real-corpus-manifest.json")
CACHE_DIR = os.path.join(REPO_ROOT, ".cache", "real-corpus")
DEFAULT_REPORT = os.path.join(CACHE_DIR, "real-corpus-report.json")

PROFILES = ("gguf-spec", "llama-cpp")
VERDICTS = ("pass", "reject")
TIERS = (1, 2)

REQUIRED_ENTRY_FIELDS = ("name", "url", "sha256", "size", "license", "tier", "expected_profile")

STATUS_PASS = "PASS"
STATUS_DOWNLOAD_ERROR = "DOWNLOAD_ERROR"
STATUS_SIZE_MISMATCH = "SIZE_MISMATCH"
STATUS_HASH_MISMATCH = "HASH_MISMATCH"
STATUS_SAFEGGUF_ERROR = "SAFEGGUF_ERROR"
STATUS_EXPECTED_RESULT_MISMATCH = "EXPECTED_RESULT_MISMATCH"

CHUNK_BYTES = 1024 * 1024
USER_AGENT = "safegguf-real-corpus/1"
DEFAULT_TIMEOUT = 60  # seconds per download and per CLI invocation
# Bounded download (plan section 14): at most this many bytes are streamed per
# entry regardless of any declared Content-Length. Tier 1 entries must fit this
# budget; larger tier 2 runs should raise it explicitly.
DEFAULT_MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024  # 1 GiB


class DownloadError(Exception):
    """Network/IO failure or budget exhaustion while fetching; never a compat finding."""


class SizeMismatch(Exception):
    """Downloaded byte count differs from the manifest's declared size."""


class HashMismatch(Exception):
    """Streamed sha256 differs from the manifest sha256; fails closed."""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Real-world corpus runner (F-04/B1): verified downloads + validator verdict compare"
    )
    parser.add_argument("--manifest", default=MANIFEST_PATH,
                        help="manifest path (default: %(default)s)")
    parser.add_argument("--tier", choices=("1", "2", "all"), default="1",
                        help="manifest tier to run, or 'all' (default: %(default)s)")
    parser.add_argument("--report", default=DEFAULT_REPORT,
                        help="JSON report path (default: %(default)s)")
    parser.add_argument("--binary", default=SAFEGGUF_BIN,
                        help="safegguf binary to evaluate with (default: %(default)s)")
    parser.add_argument("--max-download-bytes", type=int, default=DEFAULT_MAX_DOWNLOAD_BYTES,
                        help="per-entry streaming download cap in bytes (default: %(default)s)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="seconds per download and per CLI invocation (default: %(default)s)")
    parser.add_argument("--tolerate-download-errors", action="store_true",
                        help="gate mode: report DOWNLOAD_ERROR entries as skipped and exit 0; "
                             "size/hash/verdict mismatches and CLI errors still fail "
                             "(default: off, every non-PASS fails)")
    return parser.parse_args()


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_entries(entries):
    """Return schema errors; a non-empty list means fail closed before any download."""
    errors = []
    names = set()
    digests = set()
    for i, entry in enumerate(entries):
        label = "entries[%d]" % i
        if not isinstance(entry, dict):
            errors.append(label + ": entry must be a JSON object")
            continue
        missing = [field for field in REQUIRED_ENTRY_FIELDS if field not in entry]
        if missing:
            errors.append(label + ": missing field(s) " + ", ".join(missing))
            continue

        name = entry["name"]
        if not isinstance(name, str) or not name.strip():
            errors.append(label + ": 'name' must be a non-empty string")
        elif name in names:
            errors.append(label + ": duplicate 'name' " + name)
        else:
            names.add(name)

        url = entry["url"]
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            errors.append(label + ": 'url' must be an immutable http(s) URL")

        sha = entry["sha256"]
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha):
            errors.append(label + ": 'sha256' must be 64 hex characters")
        elif sha.lower() in digests:
            errors.append(label + ": duplicate 'sha256' " + sha.lower())
        else:
            digests.add(sha.lower())

        size = entry["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            errors.append(label + ": 'size' must be a positive integer (bytes)")

        license_id = entry["license"]
        if not isinstance(license_id, str) or not license_id.strip():
            errors.append(label + ": 'license' must be a non-empty verified identifier")

        tier = entry["tier"]
        if isinstance(tier, bool) or not isinstance(tier, int) or tier not in TIERS:
            errors.append(label + ": 'tier' must be 1 or 2")

        expected = entry["expected_profile"]
        if not isinstance(expected, dict) or not expected:
            errors.append(label + ": 'expected_profile' must be a non-empty object {profile: pass|reject}")
        else:
            unknown = sorted(p for p in expected if p not in PROFILES)
            bad = sorted(p for p, v in expected.items() if v not in VERDICTS)
            if unknown:
                errors.append(label + ": unknown profile key(s) " + ", ".join(unknown))
            if bad:
                errors.append(label + ": expected verdict for " + ", ".join(bad) + " must be pass|reject")
    return errors


def cache_path_for(digest):
    return os.path.join(CACHE_DIR, digest + ".gguf")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def download_bounded(url, dest_dir, max_bytes, timeout):
    """Stream `url` into a temp file under dest_dir, hashing as bytes arrive.

    Returns (tmp_path, sha256_hex, bytes_read); the caller owns tmp_path. The
    declared Content-Length is ignored entirely: only bytes actually read count
    toward the cap. Raises DownloadError on network/IO failure or cap overflow.
    """
    fd, tmp_path = tempfile.mkstemp(prefix="download-", suffix=".part", dir=dest_dir)
    os.close(fd)
    digest = hashlib.sha256()
    total = 0
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with open(tmp_path, "wb") as out:
                while True:
                    chunk = response.read(CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise DownloadError(
                            "download exceeded --max-download-bytes budget (%d bytes)" % max_bytes
                        )
                    digest.update(chunk)
                    out.write(chunk)
    except DownloadError:
        remove(tmp_path)
        raise
    except (OSError, http.client.HTTPException) as exc:
        remove(tmp_path)
        raise DownloadError("%s: %s" % (type(exc).__name__, exc))
    return tmp_path, digest.hexdigest(), total


def remove(path):
    if os.path.exists(path):
        os.remove(path)


def download_to_cache(entry, max_bytes, timeout):
    """Return (path, cache_state) for a verified entry file.

    A cache hit is a size + streamed-sha256 match on the existing
    .cache/real-corpus/<sha256>.gguf; a mismatch is reported as "corrupt",
    discarded and re-fetched. Fresh downloads are verified against the manifest
    before the atomic promote, so only verified bytes ever land at the cache
    path. Raises DownloadError/SizeMismatch/HashMismatch.
    """
    dest = cache_path_for(entry["sha256"])
    state = "miss"
    if os.path.exists(dest):
        if os.path.getsize(dest) == entry["size"] and sha256_file(dest) == entry["sha256"]:
            return dest, "hit"
        state = "corrupt"
        os.remove(dest)

    tmp_path, digest, total = download_bounded(entry["url"], CACHE_DIR, max_bytes, timeout)
    if total != entry["size"]:
        remove(tmp_path)
        raise SizeMismatch("downloaded %d bytes, manifest declares %d" % (total, entry["size"]))
    if digest != entry["sha256"]:
        remove(tmp_path)
        raise HashMismatch("streamed sha256 %s != manifest %s" % (digest, entry["sha256"]))
    os.replace(tmp_path, dest)  # atomic promote: verified bytes only
    return dest, state


def cli_diagnostics(stdout, stderr):
    """Compact CLI context: JSON fields when present, bounded text otherwise."""
    keys = ("error_code", "category", "stage", "tensor_index", "tensor",
            "expected_offset", "key", "message")
    for text in (stdout, stderr):
        text = (text or "").strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except ValueError:
            continue
        if isinstance(payload, dict):
            found = {k: payload[k] for k in keys if k in payload}
            if "message" in found and isinstance(found["message"], str):
                found["message"] = found["message"][:300]
            return found
    combined = (stderr or stdout or "").strip()
    return {"message": combined[:300]} if combined else {}


def run_validator(binary, path, profile, timeout):
    cmd = [binary, "inspect", path, "--format", "json", "--profile", profile]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"verdict": "error", "exit_code": None, "diagnostics": {"message": "CLI timed out"}}
    except OSError as exc:
        return {"verdict": "error", "exit_code": None,
                "diagnostics": {"message": "cannot run %s: %s" % (binary, exc)}}
    if proc.returncode == 0:
        verdict = "pass"
    elif proc.returncode == 2:
        verdict = "reject"
    else:
        verdict = "error"
    return {"verdict": verdict, "exit_code": proc.returncode,
            "diagnostics": cli_diagnostics(proc.stdout, proc.stderr)}


def evaluate_entry(entry, args):
    result = {
        "name": entry["name"],
        "url": entry["url"],
        "sha256": entry["sha256"],
        "size": entry["size"],
        "license": entry["license"],
        "tier": entry["tier"],
        "expected_profile": dict(entry["expected_profile"]),
        "cache": None,
        "profiles": {},
    }
    try:
        path, cache_state = download_to_cache(entry, args.max_download_bytes, args.timeout)
    except DownloadError as exc:
        result.update(status=STATUS_DOWNLOAD_ERROR, detail=str(exc))
        return result
    except SizeMismatch as exc:
        result.update(status=STATUS_SIZE_MISMATCH, detail=str(exc))
        return result
    except HashMismatch as exc:
        result.update(status=STATUS_HASH_MISMATCH, detail=str(exc))
        return result
    result["cache"] = cache_state

    saw_error = False
    saw_mismatch = False
    for profile in sorted(entry["expected_profile"]):
        expected = entry["expected_profile"][profile]
        run = run_validator(args.binary, path, profile, args.timeout)
        compared = {
            "expected": expected,
            "verdict": run["verdict"],
            "exit_code": run["exit_code"],
            "match": run["verdict"] == expected,
            "diagnostics": run["diagnostics"],
        }
        if run["verdict"] == "error":
            saw_error = True
        elif not compared["match"]:
            saw_mismatch = True
        result["profiles"][profile] = compared

    if saw_error:
        result["status"] = STATUS_SAFEGGUF_ERROR
    elif saw_mismatch:
        result["status"] = STATUS_EXPECTED_RESULT_MISMATCH
    else:
        result["status"] = STATUS_PASS
    return result


def write_report(path, payload):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def base_report(args, entries, selected, results, counts, note=None, schema_errors=None):
    payload = {
        "description": ("Real-world corpus runner report (F-04/B1); advisory lane, "
                        "findings never block CI."),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "manifest": os.path.abspath(args.manifest),
        "tier": args.tier,
        "binary": args.binary,
        "max_download_bytes": args.max_download_bytes,
        "entries_total": len(entries),
        "entries_selected": len(selected),
        "entries_skipped": len(entries) - len(selected),
        "tolerate_download_errors": args.tolerate_download_errors,
        "counts": counts,
        "results": results,
    }
    if note:
        payload["note"] = note
    if schema_errors:
        payload["schema_errors"] = schema_errors
    return payload


def print_results(results):
    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
        print("  [%s] %s" % (result["status"], result["name"]))
        for profile in sorted(result["profiles"]):
            compared = result["profiles"][profile]
            print("      %-10s expected %-6s got %-6s (exit %s) match=%s" % (
                profile, compared["expected"], compared["verdict"],
                compared["exit_code"], compared["match"]))
        if "detail" in result:
            print("      detail: %s" % result["detail"])
    return counts


def main():
    args = parse_args()
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ValueError) as exc:
        print("Error: cannot read manifest %s: %s" % (args.manifest, exc), file=sys.stderr)
        return 1
    if not isinstance(manifest, dict):
        print("Error: manifest root must be a JSON object", file=sys.stderr)
        return 1
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        print("Error: manifest 'entries' must be an array", file=sys.stderr)
        return 1

    schema_errors = validate_entries(entries)
    if schema_errors:
        print("Error: manifest schema invalid (%d problem(s)); failing closed:" % len(schema_errors),
              file=sys.stderr)
        for error in schema_errors:
            print("  - " + error, file=sys.stderr)
        write_report(args.report, base_report(args, entries, [], [], {}, schema_errors=schema_errors))
        return 1

    selected = [entry for entry in entries if args.tier == "all" or entry["tier"] == int(args.tier)]
    if not selected:
        note = ("manifest has no entries; nothing to run (vacuous pass by design - "
                "supply approved immutable entries)") if not entries else (
                "no manifest entries match tier %s; nothing to run" % args.tier)
        write_report(args.report, base_report(args, entries, selected, [], {}, note=note))
        print("real-corpus: " + note)
        print("real-corpus: report written to " + args.report)
        return 0

    if not os.path.exists(args.binary):
        print("Error: binary %s does not exist. Run: zig build -Doptimize=ReleaseSafe" % args.binary,
              file=sys.stderr)
        return 1

    print("real-corpus: %d/%d entries selected (tier %s), evaluating against %s" % (
        len(selected), len(entries), args.tier, args.binary))
    os.makedirs(CACHE_DIR, exist_ok=True)
    results = [evaluate_entry(entry, args) for entry in selected]
    counts = print_results(results)

    # --tolerate-download-errors is a network-outage exception, not a laxer
    # compatibility contract: every other non-PASS status still fails the run.
    tolerated = counts.get(STATUS_DOWNLOAD_ERROR, 0) if args.tolerate_download_errors else 0
    note = None
    if tolerated:
        note = ("%d/%d entries skipped after download errors (--tolerate-download-errors); "
                "network failures are not compatibility findings" % (tolerated, len(results)))

    report_path = args.report
    write_report(report_path, base_report(args, entries, selected, results, counts, note=note))
    print("real-corpus: report written to " + report_path)

    failed = sorted(status for status, count in counts.items() if status != STATUS_PASS and count)
    if args.tolerate_download_errors:
        failed = [status for status in failed if status != STATUS_DOWNLOAD_ERROR]
    if failed:
        print("FAILED: %s" % ", ".join("%s x%d" % (s, counts[s]) for s in failed), file=sys.stderr)
        return 1
    if tolerated:
        print("real-corpus: %d/%d entries skipped on download error(s); no compatibility finding" % (
            tolerated, len(results)))
    print("real-corpus: all %d selected entries matched their expected verdicts" % (len(results) - tolerated))
    return 0


if __name__ == "__main__":
    sys.exit(main())
