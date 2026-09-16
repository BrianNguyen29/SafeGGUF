"""
Real-world corpus runner (F-04 / B1): manifest-driven gate with coverage floors.

The manifest (tests/real-corpus-manifest.json) holds maintainer-approved
immutable entries only: URLs, sha256 digests, sizes and licenses must never be
invented. Entries carry a tier, selected with --tier:

  tier 1  nightly-bounded corpus of small models (~0.5-1.1 GiB total); runs in
          the blocking PR/release gate (.github/workflows/ci.yml) and in the
          nightly advisory lane (.github/workflows/real-corpus.yml);
          per-entry download default 1 GiB
  tier 2  weekly/manual corpus of larger models; run explicitly with --tier 2;
          per-entry download default 6 GiB
  all     every tier; the floors then apply to the union of verified entries

A run can never PASS vacuously: exit 0 requires the coverage floors to be met
by successfully verified entries (size + sha256 verified and every
expected_profile verdict matched).

Pipeline per entry (plan sections 12/14/15):
  schema validate -> tier select -> per-tier bounded streaming download to a
  temp file (sha256 computed as bytes arrive; the declared Content-Length is
  never trusted) -> size + hash verify -> atomic promote to
  .cache/real-corpus/<sha256>.gguf -> `safegguf inspect --format json`
  (with `--endian big` when the entry declares that byte order) for every
  expected_profile key -> verdict compare -> JSON report.

Failure taxonomy (a network outage is never a compatibility regression):

  DOWNLOAD_ERROR            network/IO failure while fetching (never PASS; with
                            --tolerate-download-errors it yields NEUTRAL)
  SIZE_MISMATCH             downloaded bytes != manifest size (Content-Length ignored)
  HASH_MISMATCH             streamed sha256 != manifest sha256 (fails closed; no promote)
  SAFEGGUF_ERROR            exit code outside the {0 PASS, 2 REJECT} contract
  EXPECTED_RESULT_MISMATCH  validator verdict != expected_profile verdict
  PASS                      validator verdict matched the expectation

Coverage floors (0 files tested can never PASS):
  --min-successful-entries N  at least N entries must have verified and matched
                              (default: the manifest coverage_floors value for the
                              selected tier, else the built-in fallback 2; explicit
                              values < 1 are rejected)
  --min-successful-bytes N    at least N verified bytes must come from
                              successful entries (default: the manifest
                              coverage_floors value for the selected tier, else the
                              built-in fallback 0 = disabled)

  The manifest declares documented per-tier minimums in its top-level
  coverage_floors object ({"1": {"min_successful_entries": N,
  "min_successful_bytes": B}, ...}); they take precedence over the built-in
  fallbacks and make shrinking the corpus an explicit, auditable manifest edit:
  a tier-1 floor of N entries means a run in which only a single entry remains
  can never PASS. Explicit --min-successful-* flags still win. For --tier all
  the floors of the tiers holding selected entries are summed. A floor above
  that tier's entry count or declared bytes is a manifest schema error: a floor
  that can never be met fails closed before any download.

Exit status (the JSON report mirrors status/exit_code/coverage):
  0  PASS          every selected entry matched and both floors are met
  1  FAIL          any size/hash/verdict mismatch, Safegguf CLI error, manifest
                   schema error, coverage floor miss, or a download error while
                   --tolerate-download-errors is off (fail-closed default)
  3  INCONCLUSIVE  NEUTRAL: tolerated network-only failure - no real finding,
                   but at least one selected entry could not be verified

Gate policy: the PR lane runs with --tolerate-download-errors and accepts
0 | 3; the release lane runs fail-closed (no flag) so an outage, a skipped
entry or a missed floor always blocks a release. Size/hash/verdict mismatches
and Safegguf CLI errors fail in every mode. A JSON report is written for every
outcome, including an empty manifest.

Run:  python tests/real_corpus.py [--tier 1] [--report PATH]
      python tests/real_corpus.py --tier 2           # larger weekly/manual corpus
      python tests/real_corpus.py --tier all
      python tests/real_corpus.py --tolerate-download-errors   # PR gate mode
      python tests/real_corpus.py --min-successful-entries 5 --min-successful-bytes 10000000
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
ENDIANNESS = ("little", "big")
TIERS = (1, 2)

REQUIRED_ENTRY_FIELDS = ("name", "url", "sha256", "size", "license", "tier", "expected_profile")

STATUS_PASS = "PASS"
STATUS_DOWNLOAD_ERROR = "DOWNLOAD_ERROR"
STATUS_SIZE_MISMATCH = "SIZE_MISMATCH"
STATUS_HASH_MISMATCH = "HASH_MISMATCH"
STATUS_SAFEGGUF_ERROR = "SAFEGGUF_ERROR"
STATUS_EXPECTED_RESULT_MISMATCH = "EXPECTED_RESULT_MISMATCH"

# Run-level outcome (report status + process exit code). Exit 0 is reserved for
# a fully verified run with the coverage floors met; a run with 0 verified
# entries can never exit 0. Exit 3 is the NEUTRAL/inconclusive gate outcome for
# tolerated network-only failures, distinct from both PASS and FAIL.
RUN_STATUS_PASS = "pass"
RUN_STATUS_FAIL = "fail"
RUN_STATUS_INCONCLUSIVE = "inconclusive"
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCONCLUSIVE = 3

CHUNK_BYTES = 1024 * 1024
USER_AGENT = "safegguf-real-corpus/1"
DEFAULT_TIMEOUT = 60  # seconds per download and per CLI invocation
# Bounded download (plan section 14): at most this many bytes are streamed per
# entry regardless of any declared Content-Length. The bound is per tier: tier 1
# (blocking gate, nightly-bounded) stays at 1 GiB, tier 2 (weekly/manual lane
# for larger models, e.g. >2 GiB files) gets 6 GiB - still a hard bound, and
# explicit --max-download-bytes overrides both.
DEFAULT_MAX_DOWNLOAD_BYTES_BY_TIER = {
    1: 1024 * 1024 * 1024,      # 1 GiB
    2: 6 * 1024 * 1024 * 1024,  # 6 GiB
}
# Built-in coverage-floor fallback. It applies only when the manifest declares
# no coverage_floors for the selected tier and no explicit --min-successful-*
# flag is given; the fallback entry floor is 2 so a single entry can never PASS.
DEFAULT_MIN_SUCCESSFUL_ENTRIES = 2
DEFAULT_MIN_SUCCESSFUL_BYTES = 0


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
    parser.add_argument("--max-download-bytes", type=int, default=None,
                        help="per-entry streaming download cap in bytes, overriding the "
                             "per-tier defaults (tier 1: %d, tier 2: %d)"
                             % (DEFAULT_MAX_DOWNLOAD_BYTES_BY_TIER[1],
                                DEFAULT_MAX_DOWNLOAD_BYTES_BY_TIER[2]))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="seconds per download and per CLI invocation (default: %(default)s)")
    parser.add_argument("--min-successful-entries", type=int, default=None,
                        help="coverage floor: minimum successfully verified entries required "
                             "for PASS (default: the manifest coverage_floors value for the "
                             "selected tier, else built-in %d; values < 1 are rejected so that "
                             "0 files tested can never PASS)" % DEFAULT_MIN_SUCCESSFUL_ENTRIES)
    parser.add_argument("--min-successful-bytes", type=int, default=None,
                        help="coverage floor: minimum successfully verified bytes required for "
                             "PASS (default: the manifest coverage_floors value for the selected "
                             "tier, else built-in %d = disabled)" % DEFAULT_MIN_SUCCESSFUL_BYTES)
    parser.add_argument("--tolerate-download-errors", action="store_true",
                        help="PR gate mode: a network-only failure makes the run INCONCLUSIVE "
                             "(exit 3, report status 'inconclusive') instead of failing; a "
                             "download error can never produce PASS, and size/hash/verdict "
                             "mismatches and CLI errors still fail (default: off, fail closed)")
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

        if "endian" in entry:
            endian = entry["endian"]
            if endian not in ENDIANNESS:
                errors.append(label + ": 'endian' must be little|big when present")

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


FLOOR_FIELDS = ("min_successful_entries", "min_successful_bytes")


def validate_coverage_floors(floors, entries):
    """Return schema/consistency errors for the optional coverage_floors block.

    A non-empty list fails the run closed before any download. Consistency is
    checked against the manifest population so a floor that can never be met
    (more entries or bytes than the tier declares) is caught as a manifest bug
    instead of silently failing every run.
    """
    errors = []
    if floors is None:
        return errors
    if not isinstance(floors, dict):
        return ["coverage_floors: must be a JSON object keyed by tier ('1', '2')"]

    population = {}
    declared_bytes = {}
    for entry in entries:
        tier = entry["tier"]
        population[tier] = population.get(tier, 0) + 1
        declared_bytes[tier] = declared_bytes.get(tier, 0) + entry["size"]

    for key, spec in sorted(floors.items()):
        label = "coverage_floors[%s]" % key
        if key not in ("1", "2"):
            errors.append(label + ": unknown tier key (expected '1' or '2')")
            continue
        tier = int(key)
        if not isinstance(spec, dict):
            errors.append(label + ": floor must be an object with " + ", ".join(FLOOR_FIELDS))
            continue
        missing = [field for field in FLOOR_FIELDS if field not in spec]
        extra = sorted(set(spec) - set(FLOOR_FIELDS))
        if missing:
            errors.append(label + ": missing field(s) " + ", ".join(missing))
        if extra:
            errors.append(label + ": unknown field(s) " + ", ".join(extra))
        if missing:
            continue
        entries_floor = spec["min_successful_entries"]
        if isinstance(entries_floor, bool) or not isinstance(entries_floor, int) or entries_floor < 1:
            errors.append(label + ": 'min_successful_entries' must be an integer >= 1")
        elif entries_floor > population.get(tier, 0):
            errors.append(label + ": 'min_successful_entries' %d exceeds the %d tier-%d entr%s in the manifest"
                          % (entries_floor, population.get(tier, 0), tier,
                             "y" if population.get(tier, 0) == 1 else "ies"))
        bytes_floor = spec["min_successful_bytes"]
        if isinstance(bytes_floor, bool) or not isinstance(bytes_floor, int) or bytes_floor < 0:
            errors.append(label + ": 'min_successful_bytes' must be an integer >= 0")
        elif bytes_floor > declared_bytes.get(tier, 0):
            errors.append(label + ": 'min_successful_bytes' %d exceeds the %d declared tier-%d bytes"
                          % (bytes_floor, declared_bytes.get(tier, 0), tier))
    return errors


def resolve_floors(manifest, args, entries):
    """Effective floors + provenance for the selected tier.

    Precedence per floor value: explicit CLI flag > manifest coverage_floors for
    the selected tier(s) > built-in fallback. For --tier all the floors of every
    tier holding selected entries are summed, so the union run has to meet the
    combined minimum.
    """
    floors = manifest.get("coverage_floors") or {}
    if args.tier == "all":
        tiers = sorted({entry["tier"] for entry in entries}) or sorted(TIERS)
    else:
        tiers = [int(args.tier)]

    base_entries = 0
    base_bytes = 0
    tier_sources = []
    for tier in tiers:
        spec = floors.get(str(tier))
        if spec is None:
            base_entries += DEFAULT_MIN_SUCCESSFUL_ENTRIES
            base_bytes += DEFAULT_MIN_SUCCESSFUL_BYTES
            tier_sources.append("tier %d built-in fallback" % tier)
        else:
            base_entries += spec["min_successful_entries"]
            base_bytes += spec["min_successful_bytes"]
            tier_sources.append("tier %d manifest coverage_floors" % tier)
    manifest_source = " + ".join(tier_sources)

    if args.min_successful_entries is not None:
        entries_floor = args.min_successful_entries
        entries_source = "cli --min-successful-entries"
    else:
        entries_floor = base_entries
        entries_source = manifest_source
    if args.min_successful_bytes is not None:
        bytes_floor = args.min_successful_bytes
        bytes_source = "cli --min-successful-bytes"
    else:
        bytes_floor = base_bytes
        bytes_source = manifest_source

    return {
        "min_successful_entries": entries_floor,
        "min_successful_bytes": bytes_floor,
        "floors_source": "entries: %s; bytes: %s" % (entries_source, bytes_source),
    }


def download_cap_for(entry, args):
    """Per-entry streaming cap: explicit CLI override, else the entry's tier default."""
    if args.max_download_bytes is not None:
        return args.max_download_bytes
    return DEFAULT_MAX_DOWNLOAD_BYTES_BY_TIER[entry["tier"]]


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


def run_validator(binary, path, profile, endian, timeout):
    cmd = [binary, "inspect", path, "--format", "json", "--profile", profile]
    if endian is not None:
        cmd += ["--endian", endian]
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
        "endian": entry.get("endian", "little"),
        "download_cap": download_cap_for(entry, args),
        "cache": None,
        "profiles": {},
    }
    try:
        path, cache_state = download_to_cache(entry, result["download_cap"], args.timeout)
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
    declared_endian = entry["endian"] if "endian" in entry else None
    for profile in sorted(entry["expected_profile"]):
        expected = entry["expected_profile"][profile]
        run = run_validator(args.binary, path, profile, declared_endian, args.timeout)
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


def base_report(args, entries, selected, results, counts, run, schema_errors=None):
    payload = {
        "description": ("Real-world corpus runner report (F-04/B1); status pass|fail|inconclusive, "
                        "exit_code 0|1|3; a run with 0 verified entries never passes. coverage holds "
                        "the effective floors (floors_source: cli | manifest coverage_floors | built-in "
                        "fallback); each result records its per-tier download_cap."),
        "status": run["status"],
        "exit_code": run["exit_code"],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "manifest": os.path.abspath(args.manifest),
        "tier": args.tier,
        "binary": args.binary,
        "max_download_bytes": args.max_download_bytes,
        "max_download_bytes_by_tier": {str(tier): cap
                                       for tier, cap in sorted(DEFAULT_MAX_DOWNLOAD_BYTES_BY_TIER.items())},
        "entries_total": len(entries),
        "entries_selected": len(selected),
        "entries_skipped": len(entries) - len(selected),
        "tolerate_download_errors": args.tolerate_download_errors,
        "coverage": run["coverage"],
        "counts": counts,
        "results": results,
    }
    if run.get("note"):
        payload["note"] = run["note"]
    if schema_errors:
        payload["schema_errors"] = schema_errors
    return payload


def print_results(results):
    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
        suffix = "" if result.get("endian", "little") == "little" else " (endian=%s)" % result["endian"]
        print("  [%s] %s%s" % (result["status"], result["name"], suffix))
        for profile in sorted(result["profiles"]):
            compared = result["profiles"][profile]
            print("      %-10s expected %-6s got %-6s (exit %s) match=%s" % (
                profile, compared["expected"], compared["verdict"],
                compared["exit_code"], compared["match"]))
        if "detail" in result:
            print("      detail: %s" % result["detail"])
    return counts


def coverage_summary(floors, results):
    """Verified coverage against the resolved floors.

    Only PASS entries count as successful: an entry reaches PASS only after its
    bytes were size + sha256 verified and every expected_profile verdict matched.
    `floors` is the resolve_floors() result (effective values + provenance).
    """
    successful = [result for result in results if result["status"] == STATUS_PASS]
    successful_entries = len(successful)
    successful_bytes = sum(result["size"] for result in successful)
    return {
        "successful_entries": successful_entries,
        "successful_bytes": successful_bytes,
        "min_successful_entries": floors["min_successful_entries"],
        "min_successful_bytes": floors["min_successful_bytes"],
        "floors_source": floors["floors_source"],
        "floors_met": (successful_entries >= floors["min_successful_entries"]
                       and successful_bytes >= floors["min_successful_bytes"]),
    }


def run_outcome(status, exit_code, coverage, note=None):
    """Bundle the run-level gate verdict that is written to the JSON report."""
    return {"status": status, "exit_code": exit_code, "coverage": coverage, "note": note}


def classify_run(args, results, counts, coverage):
    """Gate contract: exit 0 PASS / 1 FAIL / 3 INCONCLUSIVE (NEUTRAL) + report note.

    FAIL dominates: size/hash mismatches, verdict mismatches, Safegguf CLI errors
    and schema problems always fail, and a download error also fails unless
    --tolerate-download-errors is set (fail-closed default). With the flag, a
    network-only failure is NEUTRAL (exit 3): the run never becomes PASS without
    floors met by verified entries. Floors are checked last because a tolerated
    network skip explains an unmet floor, while real findings are never excused.
    """
    real_failures = sorted(status for status, count in counts.items()
                           if status not in (STATUS_PASS, STATUS_DOWNLOAD_ERROR) and count)
    if real_failures:
        detail = ", ".join("%s x%d" % (status, counts[status]) for status in real_failures)
        return run_outcome(RUN_STATUS_FAIL, EXIT_FAIL, coverage, note="real finding(s): " + detail)

    download_errors = counts.get(STATUS_DOWNLOAD_ERROR, 0)
    if download_errors and not args.tolerate_download_errors:
        return run_outcome(RUN_STATUS_FAIL, EXIT_FAIL, coverage, note=(
            "%d/%d entries failed to download; failing closed without "
            "--tolerate-download-errors" % (download_errors, len(results))))
    if download_errors:
        return run_outcome(RUN_STATUS_INCONCLUSIVE, EXIT_INCONCLUSIVE, coverage, note=(
            "%d/%d entries skipped after download errors (--tolerate-download-errors); "
            "network failures are not compatibility findings and can never PASS"
            % (download_errors, len(results))))

    if not coverage["floors_met"]:
        shortfalls = []
        if coverage["successful_entries"] < coverage["min_successful_entries"]:
            shortfalls.append("successful entries %d < %d"
                              % (coverage["successful_entries"], coverage["min_successful_entries"]))
        if coverage["successful_bytes"] < coverage["min_successful_bytes"]:
            shortfalls.append("successful bytes %d < %d"
                              % (coverage["successful_bytes"], coverage["min_successful_bytes"]))
        return run_outcome(RUN_STATUS_FAIL, EXIT_FAIL, coverage,
                           note="coverage floor not met: " + ", ".join(shortfalls))
    return run_outcome(RUN_STATUS_PASS, EXIT_PASS, coverage)


def fallback_floors(args):
    """Effective floors usable when the manifest cannot supply them (schema errors)."""
    entries_floor = (args.min_successful_entries if args.min_successful_entries is not None
                     else DEFAULT_MIN_SUCCESSFUL_ENTRIES)
    bytes_floor = (args.min_successful_bytes if args.min_successful_bytes is not None
                   else DEFAULT_MIN_SUCCESSFUL_BYTES)
    return {
        "min_successful_entries": entries_floor,
        "min_successful_bytes": bytes_floor,
        "floors_source": "fallback (manifest floors unusable)",
    }


def main():
    args = parse_args()
    if ((args.min_successful_entries is not None and args.min_successful_entries < 1)
            or (args.min_successful_bytes is not None and args.min_successful_bytes < 0)):
        print("Error: coverage floors must satisfy --min-successful-entries >= 1 and "
              "--min-successful-bytes >= 0 (0 files tested can never PASS)", file=sys.stderr)
        return EXIT_FAIL
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ValueError) as exc:
        print("Error: cannot read manifest %s: %s" % (args.manifest, exc), file=sys.stderr)
        return EXIT_FAIL
    if not isinstance(manifest, dict):
        print("Error: manifest root must be a JSON object", file=sys.stderr)
        return EXIT_FAIL
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        print("Error: manifest 'entries' must be an array", file=sys.stderr)
        return EXIT_FAIL

    schema_errors = validate_entries(entries)
    if not schema_errors:
        schema_errors = validate_coverage_floors(manifest.get("coverage_floors"), entries)
    if schema_errors:
        print("Error: manifest schema invalid (%d problem(s)); failing closed:" % len(schema_errors),
              file=sys.stderr)
        for error in schema_errors:
            print("  - " + error, file=sys.stderr)
        run = run_outcome(RUN_STATUS_FAIL, EXIT_FAIL, coverage_summary(fallback_floors(args), []),
                          note="manifest schema invalid; no entries evaluated")
        write_report(args.report, base_report(args, entries, [], [], {}, run,
                                              schema_errors=schema_errors))
        return EXIT_FAIL

    floors = resolve_floors(manifest, args, entries)
    selected = [entry for entry in entries if args.tier == "all" or entry["tier"] == int(args.tier)]
    if not selected:
        if not entries:
            note = ("manifest has no entries; nothing to run - 0 files tested can never PASS "
                    "(floor: %d successful entries, %d bytes, source: %s); supply approved "
                    "immutable entries" % (floors["min_successful_entries"], floors["min_successful_bytes"],
                                           floors["floors_source"]))
        else:
            note = ("no manifest entries match tier %s; nothing to run - "
                    "0 files tested can never PASS" % args.tier)
        run = run_outcome(RUN_STATUS_FAIL, EXIT_FAIL, coverage_summary(floors, []), note=note)
        write_report(args.report, base_report(args, entries, selected, [], {}, run))
        print("real-corpus: " + note)
        print("real-corpus: report written to " + args.report)
        print("FAILED: coverage floor not met (0 files tested)", file=sys.stderr)
        return EXIT_FAIL

    if not os.path.exists(args.binary):
        print("Error: binary %s does not exist. Run: zig build -Doptimize=ReleaseSafe" % args.binary,
              file=sys.stderr)
        return EXIT_FAIL

    print("real-corpus: %d/%d entries selected (tier %s), evaluating against %s" % (
        len(selected), len(entries), args.tier, args.binary))
    os.makedirs(CACHE_DIR, exist_ok=True)
    results = [evaluate_entry(entry, args) for entry in selected]
    counts = print_results(results)

    coverage = coverage_summary(floors, results)
    run = classify_run(args, results, counts, coverage)
    write_report(args.report, base_report(args, entries, selected, results, counts, run))
    print("real-corpus: report written to " + args.report)

    if run["status"] == RUN_STATUS_PASS:
        print("real-corpus: PASS - all %d selected entries matched their expected verdicts; "
              "coverage floors met (%d entries / %d bytes; source: %s)"
              % (len(results), coverage["successful_entries"], coverage["successful_bytes"],
                 coverage["floors_source"]))
    elif run["status"] == RUN_STATUS_INCONCLUSIVE:
        print("real-corpus: INCONCLUSIVE (exit %d, neutral) - %s" % (run["exit_code"], run["note"]))
    else:
        print("FAILED: %s" % run["note"], file=sys.stderr)
    return run["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
