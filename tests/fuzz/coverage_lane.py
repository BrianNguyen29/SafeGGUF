#!/usr/bin/env python3
"""Bounded coverage-guided fuzz lane driver for SafeGGUF (A5, Zig 0.14.1).

Wraps `zig build --fuzz <step>` for each profile x endian target under a hard
time budget and parses the built-in fuzzer artifacts:

  <cache>/v/<digest>  coverage bitmap (std.Build.Fuzz.abi.SeenPcsHeader):
                      n_runs, unique_runs, pcs_len + seen bitset + pc addrs
  <cache>/f/<test>/N  corpus entries written by the engine whenever an input
                      increases coverage; the highest index is the mmapped
                      current input (also the crash candidate)

Policy (mirrors the nightly mutation lane; see tests/fuzz/README.md):
  * persistence is coverage-driven only - inputs are never kept because they
    PASS; malformed inputs are high-value;
  * persisted corpus <= 10,000 entries / 256 MiB, sha256-deduped, oldest
    entries pruned first;
  * every incident carries a taxonomy class. `validator_crash` is only
    assigned to a proven target-process crash (fatal signal, or a panic /
    fuzzer-worker-crash marker with a nonzero exit) whose stack touches
    production source, or whose input a deterministic standalone replay
    confirms; a proven crash with no attributable frame is `unknown_crash`
    until such a replay promotes it. `engine_crash` (Zig built-in fuzzer
    frames), `timeout` (startup/stall) and `oom` (OOM markers, or a SIGKILLed
    worker) are unchanged. Harness/setup/infrastructure failures - a missing
    required seed corpus (`tests/corpus`, see fuzz_cov_target.zig `loadSeeds`),
    FileNotFound, a failed build, or an unexpected non-crash exit - are
    `setup_*` and are never reported as validator crashes. Every incident also
    carries a repro status (`repro_confirmed`, `repro_not_confirmed`,
    `repro_timeout`, `repro_not_attempted`);
  * validator crashes, unknown crashes, timeouts and OOM incidents preserve
    the original input (and a repro-validated minimized prefix when the replay
    confirms a crash) + metadata under tests/fuzz-artifacts/coverage-fuzz/ and
    fail the lane; setup failures fail the lane without fabricating a crash
    artifact;
  * an engine-internal crash inside Zig 0.14.1's built-in fuzzer (top frames
    are lib/fuzzer.zig) whose recovered input does not reproduce is preserved
    as an advisory `engine_crash` artifact and does not fail the lane;
  * every incident JSON additionally carries the strict schema fields `layer`,
    `taxonomy`, `repro_status`, `input_sha256`, `commit`, `toolchain`,
    `command`, `stderr_tail` and `first_failing_frame`.

History (advisory trend, never a gate): every run appends one compact record
(executions, unique inputs, covered paths, corpus growth, incident taxonomy
and repro outcomes) to `coverage_history.json`, reports the delta against the
previous record in the summary (JSON + text) and keeps the last
`MAX_HISTORY_RUNS` records. Coverage is commit-relative, so deltas are
reported, never enforced. When the trend file is lost (cache miss) it is
rebuilt from the compact records embedded in the previous
`coverage_summary.json`, or from the previous summary's totals alone; the
workflow additionally recovers both files from the latest uploaded artifact.

The lane is advisory (nightly): it is complementary to `zig build fuzz` (0.13
corpus sweep) and the deterministic mutation campaigns, never a replacement.
"""

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))

DEFAULT_CACHE_ROOT = os.path.join(REPO_ROOT, ".cache", "coverage-fuzz")
DEFAULT_CORPUS_DIR = os.path.join(DEFAULT_CACHE_ROOT, "corpus")
DEFAULT_ARTIFACTS_DIR = os.path.join(REPO_ROOT, "tests", "fuzz-artifacts", "coverage-fuzz")

TARGETS = [
    {"step": "fuzz-cov-gguf-spec-little", "profile": "gguf-spec", "endian": "little", "kind": "required"},
    {"step": "fuzz-cov-gguf-spec-big", "profile": "gguf-spec", "endian": "big", "kind": "required"},
    {"step": "fuzz-cov-llama-cpp-little", "profile": "llama-cpp", "endian": "little", "kind": "required"},
    {"step": "fuzz-cov-llama-cpp-big", "profile": "llama-cpp", "endian": "big", "kind": "smoke"},
]

WEB_UP_MARKER = b"web interface listening"
CRASH_MARKERS = (
    b"all fuzz workers crashed",
    b"Segmentation fault",
    b"panic:",
    b"failed with error",
)
# Lowercase substrings that identify an out-of-memory incident in the lane log
# (Zig panic/OOM messages and allocator failures).
OOM_MARKERS = (
    b"outofmemory",
    b"out of memory",
    b"cannot allocate memory",
    b"memory allocation failed",
)

# A proven target-process crash needs a fatal signal (negative exit status) or
# one of these markers with a nonzero exit; ordinary failed-build/test text is
# not crash proof (see crash_proven).
CRASH_PROOF_MARKERS = (
    b"panic:",
    b"segmentation fault",
    b"all fuzz workers crashed",
)
# Harness/setup failure signatures that must never be reported as a crash.
FILE_NOT_FOUND_MARKERS = (
    b"filenotfound",
    b"file not found",
    b"no such file or directory",
)
BUILD_FAILURE_MARKERS = (
    b"compilation errors",
    b"the following command failed",
    b"unable to build",
    b"build failed",
)

# Incident taxonomy (one class per non-ok target run): crash classes, runtime
# conditions, and setup/infrastructure classes that must never masquerade as
# validator crashes (see classify_incident).
TAXONOMY_VALIDATOR_CRASH = "validator_crash"
TAXONOMY_ENGINE_CRASH = "engine_crash"
TAXONOMY_UNKNOWN_CRASH = "unknown_crash"
TAXONOMY_TIMEOUT = "timeout"
TAXONOMY_OOM = "oom"
TAXONOMY_SETUP_MISSING_CORPUS = "setup_missing_corpus"
TAXONOMY_SETUP_FILE_NOT_FOUND = "setup_file_not_found"
TAXONOMY_SETUP_BUILD_FAILURE = "setup_build_failure"
TAXONOMY_SETUP_ERROR = "setup_error"

CRASH_TAXONOMIES = (TAXONOMY_VALIDATOR_CRASH, TAXONOMY_ENGINE_CRASH,
                    TAXONOMY_UNKNOWN_CRASH)
SETUP_TAXONOMIES = (TAXONOMY_SETUP_MISSING_CORPUS,
                    TAXONOMY_SETUP_FILE_NOT_FOUND,
                    TAXONOMY_SETUP_BUILD_FAILURE, TAXONOMY_SETUP_ERROR)
INCIDENT_TAXONOMIES = (CRASH_TAXONOMIES + (TAXONOMY_TIMEOUT, TAXONOMY_OOM)
                       + SETUP_TAXONOMIES)
# Layer an incident is attributable to (strict incident JSON `layer` field).
INCIDENT_LAYERS = ("setup", "validator", "engine", "runtime", "unknown")
# Strict fields every incident JSON carries; both artifact writers spread
# incident_schema() so the shape cannot drift.
REQUIRED_INCIDENT_FIELDS = (
    "layer", "taxonomy", "repro_status", "input_sha256", "commit",
    "toolchain", "command", "stderr_tail", "first_failing_frame",
)


def stack_top_frames(blob, limit=12):
    """Top-of-trace frames: up to `limit` non-blank lines after the first
    crash marker. Shared by crash classification and artifact metadata."""
    lines = blob.decode("utf-8", "replace").splitlines()
    for i, line in enumerate(lines):
        if "Segmentation fault" not in line and "panic:" not in line:
            continue
        frames = []
        for frame in lines[i + 1:i + 1 + limit]:
            frame = frame.strip()
            if not frame:
                break
            frames.append(frame[:200])
        return frames
    return []


def crash_site(blob):
    """Classify a crash trace: 'engine' when the top frame is Zig's built-in
    fuzzer runtime, 'validator' when safegguf src/tests frames are on top,
    'unknown' otherwise. An 'unknown' site is never labeled validator_crash
    without a confirmed standalone repro (see classify_incident)."""
    for frame in stack_top_frames(blob):
        if "lib/fuzzer.zig" in frame or "lib/Build/Fuzz" in frame:
            return "engine"
        if "/src/" in frame or "/tests/" in frame:
            return "validator"
    return "unknown"


def has_oom_marker(blob):
    lower = blob.lower()
    return any(marker in lower for marker in OOM_MARKERS)


def has_file_not_found_marker(blob):
    lower = blob.lower()
    return any(marker in lower for marker in FILE_NOT_FOUND_MARKERS)


def has_build_failure_marker(blob):
    lower = blob.lower()
    return any(marker in lower for marker in BUILD_FAILURE_MARKERS)


def crash_proven(blob, rc):
    """True only when the target process demonstrably crashed: a fatal signal
    (negative exit status) or an explicit crash marker with a nonzero exit.
    Ordinary nonzero exits (failed build, test error, ...) are not proof."""
    if rc is not None and rc < 0:
        return True
    if rc in (0, None):
        return False
    lower = blob.lower()
    return any(marker in lower for marker in CRASH_PROOF_MARKERS)


def classify_incident(blob, rc, required_corpus_present=True):
    """(taxonomy, crash_site) for one non-ok target run, strict precedence:
    OOM, then harness/setup/infrastructure, then proven crashes.

    `tests/corpus` is required by tests/fuzz_cov_target.zig `loadSeeds`, so
    when it is absent the run can only have failed setup - never validator.
    FileNotFound and failed-build signatures are `setup_*` as well. A proven
    crash is `validator_crash` only with production-source frames; a proven
    crash with no attributable frame stays `unknown_crash` until
    save_crash_artifact promotes it on a confirmed standalone repro."""
    site = crash_site(blob)
    if has_oom_marker(blob):
        return TAXONOMY_OOM, site
    if not required_corpus_present:
        return TAXONOMY_SETUP_MISSING_CORPUS, site
    if not crash_proven(blob, rc):
        if has_file_not_found_marker(blob):
            return TAXONOMY_SETUP_FILE_NOT_FOUND, site
        if has_build_failure_marker(blob):
            return TAXONOMY_SETUP_BUILD_FAILURE, site
        return TAXONOMY_SETUP_ERROR, site
    if has_build_failure_marker(blob) and site != "validator":
        # A failed or crashed build toolchain is infrastructure, not a target
        # process validator crash.
        return TAXONOMY_SETUP_BUILD_FAILURE, site
    if site == "validator":
        return TAXONOMY_VALIDATOR_CRASH, site
    if site == "engine":
        return TAXONOMY_ENGINE_CRASH, site
    return TAXONOMY_UNKNOWN_CRASH, site


def incident_layer(taxonomy):
    """Layer an incident is attributable to (strict incident JSON field):
    setup_* -> setup, validator_crash -> validator, engine_crash -> engine,
    timeout/oom -> runtime, anything else -> unknown."""
    if taxonomy in SETUP_TAXONOMIES:
        return "setup"
    if taxonomy == TAXONOMY_VALIDATOR_CRASH:
        return "validator"
    if taxonomy == TAXONOMY_ENGINE_CRASH:
        return "engine"
    if taxonomy in (TAXONOMY_TIMEOUT, TAXONOMY_OOM):
        return "runtime"
    return "unknown"


def first_failing_frame(blob):
    """First attributable failure line for an incident: the top crash frame
    when a crash trace exists, else the first error/panic line (setup
    failures have no stack), else None."""
    frames = stack_top_frames(blob)
    if frames:
        return frames[0]
    for line in blob.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and ("error" in line.lower() or "panic" in line.lower()):
            return line[:200]
    return None


def incident_schema(taxonomy, repro_status, input_sha256, command, blob,
                     toolchain, commit):
    """Strict incident JSON fields every artifact writer must carry."""
    return {
        "layer": incident_layer(taxonomy),
        "taxonomy": taxonomy,
        "repro_status": repro_status,
        "input_sha256": input_sha256,
        "commit": commit,
        "toolchain": toolchain,
        "command": command,
        "stderr_tail": blob[-STDERR_TAIL_BYTES:].decode("utf-8", "replace"),
        "first_failing_frame": first_failing_frame(blob),
    }


MAX_CORPUS_ENTRIES = 10_000
MAX_CORPUS_BYTES = 256 * 1024 * 1024
MAX_REPRO_CALLS = 24
REPRO_TIMEOUT = 300
FUZZ_SEED = 0  # std.testing.fuzz RNG seed, kept deterministic by the harness
STDERR_TAIL_BYTES = 4000  # stderr_tail/log_excerpt evidence window

# Repro statuses for a recovered incident input; the constants are the status
# values used across results, summaries and history records.
REPRO_STATUSES = ("repro_confirmed", "repro_not_confirmed",
                  "repro_timeout", "repro_not_attempted")

SUMMARY_FILE = "coverage_summary.json"
HISTORY_FILE = "coverage_history.json"
HISTORY_SCHEMA_VERSION = "safegguf-coverage-fuzz-history/2"
MAX_HISTORY_RUNS = 90
RECENT_RUNS_IN_SUMMARY = 10  # compact records embedded for cache-miss rebuilds
HISTORY_NOTE = ("advisory trend state; restored/saved through the "
                "coverage-fuzz-history-* actions/cache entry, rebuilt from the "
                "previous coverage_summary.json or the latest uploaded artifact "
                "when the cache misses, never a gate")

# Aggregate fields diffed against the previous run's record; coverage is
# commit-relative, so these deltas are informational only.
DELTA_FIELDS = (
    "n_runs",
    "unique_runs",
    "covered_pcs",
    "coverage_pct",
    "promoted",
    "corpus_entries",
    "corpus_bytes",
    "crash_artifacts",
    "validator_crashes",
    "engine_crashes",
    "unknown_crashes",
    "setup_failures",
    "advisory_crashes",
    "timeouts",
    "ooms",
    "repro_confirmed",
    "repro_not_confirmed",
    "repro_timeout",
    "repro_not_attempted",
    "failed_targets",
)


def log(msg):
    print("[coverage-lane] " + msg, flush=True)


def popcount(value):
    try:
        return value.bit_count()
    except AttributeError:  # Python < 3.10
        return bin(value).count("1")


def utcstamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_log(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def has_marker(blob):
    return any(marker in blob for marker in CRASH_MARKERS)


def stop_group(proc, grace=10):
    """SIGINT then SIGKILL the whole process group (build runner + workers)."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass


def read_n_runs(cache_dir):
    """Cheap liveness probe: max n_runs across <cache>/v/<digest> headers."""
    vdir = os.path.join(cache_dir, "v")
    if not os.path.isdir(vdir):
        return 0
    total = 0
    for name in os.listdir(vdir):
        try:
            with open(os.path.join(vdir, name), "rb") as f:
                blob = f.read(24)
            if len(blob) == 24:
                total = max(total, struct.unpack_from("<Q", blob, 0)[0])
        except (OSError, struct.error):
            continue
    return total


def parse_coverage(cache_dir):
    """Parse every <cache>/v/<digest> SeenPcsHeader bitmap."""
    vdir = os.path.join(cache_dir, "v")
    if not os.path.isdir(vdir):
        return None
    best = None
    for name in sorted(os.listdir(vdir)):
        path = os.path.join(vdir, name)
        try:
            with open(path, "rb") as f:
                blob = f.read()
            if len(blob) < 24:
                continue
            n_runs, unique_runs, pcs_len = struct.unpack_from("<QQQ", blob, 0)
            n_bits = (pcs_len + 63) // 64
            expected = 24 + n_bits * 8 + pcs_len * 8
            if len(blob) < expected:
                continue
            bits = blob[24:24 + n_bits * 8]
            covered = 0
            for i in range(n_bits):
                covered += popcount(int.from_bytes(bits[i * 8:(i + 1) * 8], "little"))
            entry = {
                "digest": name,
                "n_runs": n_runs,
                "unique_runs": unique_runs,
                "pcs_len": pcs_len,
                "covered_pcs": covered,
                "coverage_pct": round(100.0 * covered / pcs_len, 3) if pcs_len else 0.0,
                "coverage_file_bytes": len(blob),
            }
            if best is None or entry["n_runs"] > best["n_runs"]:
                best = entry
        except (OSError, struct.error):
            continue
    return best


def find_corpus_dir(cache_dir):
    fdir = os.path.join(cache_dir, "f")
    if not os.path.isdir(fdir):
        return None
    candidates = [os.path.join(fdir, n) for n in sorted(os.listdir(fdir))]
    candidates = [c for c in candidates if os.path.isdir(c)]
    if not candidates:
        return None
    # One target per cache dir; if several, prefer the one with entries.
    candidates.sort(key=lambda c: len(os.listdir(c)), reverse=True)
    return candidates[0]


def list_corpus_entries(corpus_dir):
    entries = []
    for name in os.listdir(corpus_dir):
        path = os.path.join(corpus_dir, name)
        if os.path.isfile(path):
            try:
                entries.append((int(name), path))
            except ValueError:
                continue
    entries.sort()
    return entries


def run_bounded(args, target, budget, artifacts_dir, global_cache_dir):
    """Run one `zig build --fuzz <step>` under a budget. Returns a result dict."""
    cache_dir = os.path.join(args.cache_root, "cache-" + target["step"])
    os.makedirs(cache_dir, exist_ok=True)
    # Keep compiled artifacts (fast reruns) but start with a clean coverage
    # file and corpus dir so per-run stats and crash recovery are unambiguous.
    shutil.rmtree(os.path.join(cache_dir, "v"), ignore_errors=True)
    shutil.rmtree(os.path.join(cache_dir, "f"), ignore_errors=True)

    corpus_target_dir = os.path.join(args.corpus_dir, target["step"])
    env = os.environ.copy()
    if os.path.isdir(corpus_target_dir):
        env["SAFEGGUF_COV_FUZZ_SEEDS"] = corpus_target_dir

    log_path = os.path.join(artifacts_dir, target["step"] + ".log")
    argv = [
        args.zig, "build", "--fuzz", target["step"],
        "--cache-dir", cache_dir,
        "--global-cache-dir", global_cache_dir,
    ]
    command = shlex.join(argv)
    log("target %s: fuzzing for up to %ds (cache %s)" % (target["step"], budget, cache_dir))
    result = {
        "step": target["step"],
        "profile": target["profile"],
        "endian": target["endian"],
        "host_endian": sys.byteorder,
        "seed": FUZZ_SEED,
        "budget_seconds": budget,
        "status": "ok",
        "taxonomy": None,
        "advisory": False,
        "detail": "",
        "rc": None,
        "coverage": None,
        "corpus_files": 0,
        "promoted": 0,
        "crash_artifact": None,
        "crash_site": None,
        "stack_top_frames": [],
        "repro_status": None,
        "repro_calls": 0,
        "log": os.path.basename(log_path),
    }

    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(
            argv, cwd=REPO_ROOT, env=env, stdout=log_file, stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        start_deadline = time.monotonic() + args.startup_timeout
        started = False
        while time.monotonic() < start_deadline:
            if proc.poll() is not None:
                break
            if WEB_UP_MARKER in read_log(log_path):
                started = True
                break
            time.sleep(0.25)

        early_exit = False
        crash_marked = False
        if proc.poll() is not None:
            early_exit = True
        elif not started:
            stop_group(proc)
            result["status"] = "timeout"
            result["taxonomy"] = "timeout"
            result["detail"] = "fuzz mode did not start within %ds (taxonomy=timeout)" % args.startup_timeout
        else:
            fuzz_deadline = time.monotonic() + budget
            last_progress = time.monotonic()
            last_runs = read_n_runs(cache_dir)
            stalled = False
            while time.monotonic() < fuzz_deadline:
                if proc.poll() is not None:
                    early_exit = True
                    break
                if has_marker(read_log(log_path)):
                    crash_marked = True
                    try:
                        proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        stop_group(proc)
                    break
                if time.monotonic() - last_progress > args.stall_seconds:
                    stalled = True
                    break
                runs = read_n_runs(cache_dir)
                if runs > last_runs:
                    last_runs = runs
                    last_progress = time.monotonic()
                time.sleep(0.25)
            if stalled:
                stop_group(proc)
                blob = read_log(log_path)
                result["taxonomy"] = TAXONOMY_OOM if has_oom_marker(blob) else TAXONOMY_TIMEOUT
                result["status"] = result["taxonomy"]
                result["crash_site"] = crash_site(blob)
                result["stack_top_frames"] = stack_top_frames(blob)
                result["detail"] = "no fuzz progress for %ds%s" % (
                    args.stall_seconds,
                    "; OOM markers in lane log (taxonomy=oom)"
                    if result["taxonomy"] == TAXONOMY_OOM
                    else " (hang suspected; taxonomy=timeout)")
            elif proc.poll() is None:
                stop_group(proc)

        result["rc"] = proc.returncode
        blob = read_log(log_path)
        required_corpus_present = os.path.isdir(
            os.path.join(REPO_ROOT, "tests", "corpus"))
        if crash_marked or has_marker(blob):
            result["taxonomy"], result["crash_site"] = classify_incident(
                blob, result["rc"], required_corpus_present)
            result["status"] = result["taxonomy"]
            result["stack_top_frames"] = stack_top_frames(blob)
            result["detail"] = "fuzz worker crash marker in lane log (taxonomy=%s site=%s)" % (
                result["taxonomy"], result["crash_site"])
        elif result["status"] == "ok" and early_exit:
            if proc.returncode == 0:
                result["status"] = "failed"
                result["detail"] = "fuzz build exited 0 before the time budget"
            elif has_oom_marker(blob) or proc.returncode in (-signal.SIGKILL, 137):
                # No crash marker and no frame: an externally SIGKILLed worker on
                # CI is most likely the kernel OOM killer, so classify as oom.
                result["status"] = TAXONOMY_OOM
                result["taxonomy"] = TAXONOMY_OOM
                result["crash_site"] = crash_site(blob)
                result["stack_top_frames"] = stack_top_frames(blob)
                result["detail"] = ("fuzz build exited early with rc=%s; no crash trace, "
                                    "SIGKILL/OOM marker (taxonomy=oom)" % proc.returncode)
            else:
                result["taxonomy"], result["crash_site"] = classify_incident(
                    blob, proc.returncode, required_corpus_present)
                result["status"] = result["taxonomy"]
                result["stack_top_frames"] = stack_top_frames(blob)
                result["detail"] = "fuzz build exited early with rc=%s (taxonomy=%s site=%s)" % (
                    proc.returncode, result["taxonomy"], result["crash_site"])

    result["coverage"] = parse_coverage(cache_dir)
    corpus_dir = find_corpus_dir(cache_dir)
    entries = []
    if corpus_dir is not None:
        entries = list_corpus_entries(corpus_dir)
        result["corpus_files"] = len(entries)
    if result["status"] in CRASH_TAXONOMIES:
        site = result["crash_site"] or "unknown"
        if entries:
            artifact, repro_status, repro_calls, taxonomy = save_crash_artifact(
                args, target, entries, cache_dir, log_path, result["taxonomy"], site,
                command=command,
            )
            result["crash_artifact"] = artifact
            result["repro_status"] = repro_status
            result["repro_calls"] = repro_calls
            if taxonomy != result["taxonomy"]:
                # unknown_crash + deterministic standalone repro => validator.
                result["detail"] += (
                    "; deterministic standalone repro confirmed: reclassified %s -> %s"
                    % (result["taxonomy"], taxonomy))
                result["taxonomy"] = taxonomy
                result["status"] = taxonomy
            if site == "engine" and repro_status == "repro_not_confirmed":
                # Spontaneous Zig 0.14.1 built-in fuzzer instability: the crash
                # is in lib/fuzzer.zig and the recovered input does not replay,
                # so it is not a SafeGGUF defect. Keep the artifact but do not
                # fail the advisory lane.
                result["advisory"] = True
                result["detail"] = (
                    "advisory: Zig 0.14.1 built-in fuzzer engine crash "
                    "(top frames in lib/fuzzer.zig); repro_status=%s" % repro_status)
            else:
                result["detail"] += "; repro_status=%s" % repro_status
        else:
            result["crash_artifact"] = save_crash_without_input(
                args, target, log_path, result["taxonomy"], site, command=command)
            result["repro_status"] = "repro_not_attempted"
    elif result["status"] in (TAXONOMY_TIMEOUT, TAXONOMY_OOM):
        # Replaying a possibly-hanging or OOM-triggering input is not attempted;
        # the original input (when one exists) is preserved unminimized.
        result["repro_status"] = "repro_not_attempted"
        if entries:
            artifact, repro_status, repro_calls, _ = save_crash_artifact(
                args, target, entries, cache_dir, log_path, result["taxonomy"],
                result["crash_site"] or "unknown", attempt_repro=False,
                command=command,
            )
            result["crash_artifact"] = artifact
            result["repro_status"] = repro_status
            result["repro_calls"] = repro_calls
    if corpus_dir is not None:
        result["promoted"] = promote_corpus(corpus_dir, entries, args.corpus_dir, target["step"])
    return result


def save_crash_without_input(args, target, log_path, taxonomy, site, command=None):
    """Incident during the seed smoke pass: no f/ entry exists, keep the log."""
    base = "crash-%s-%s" % (target["step"], utcstamp())
    blob = read_log(log_path)
    version = zig_version(args.zig)
    commit = git_commit()
    meta = {
        "kind": "coverage_fuzz_crash_no_input",
        **incident_schema(taxonomy, "repro_not_attempted", None, command, blob,
                          "zig " + version, commit),
        "target": target["step"],
        "profile": target["profile"],
        "endian": target["endian"],
        "host_endian": sys.byteorder,
        "seed": FUZZ_SEED,
        "crash_site": site,
        "stack_top_frames": stack_top_frames(blob),
        "repro_calls": 0,
        "sha": None,
        "sizes": None,
        "engine": "zig built-in fuzzer (std.testing.fuzz, Zig 0.14.1)",
        "zig_version": version,
        "git_commit": commit,
        "platform": platform.platform(),
        "detail": "crash before/without a recoverable corpus entry (seed smoke pass); see log",
        "log": os.path.basename(log_path),
        "log_excerpt": blob[-STDERR_TAIL_BYTES:].decode("utf-8", "replace"),
        "repro_command": ("rerun the lane target; a persisted seed is the likely input "
                          "(tests/fuzz/coverage_lane.py --targets %s)" % target["step"]),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    name = base + ".json"
    with open(os.path.join(args.artifacts_dir, name), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    log("target %s: %s (no recoverable input) metadata %s" % (target["step"], taxonomy, name))
    return name


def promote_corpus(corpus_dir, entries, persist_root, step):
    """Copy coverage-increasing entries (all but the current input) into the
    persisted corpus, content-addressed by sha256; prune to the lane caps."""
    target_dir = os.path.join(persist_root, step)
    os.makedirs(target_dir, exist_ok=True)
    existing = set(os.listdir(target_dir))
    promoted = 0
    # The highest index is the current (mmapped) input, not a corpus entry.
    for _, path in entries[:-1]:
        digest = sha256_file(path) + ".gguf"
        if digest in existing:
            continue
        shutil.copy2(path, os.path.join(target_dir, digest))
        existing.add(digest)
        promoted += 1
    prune_corpus(persist_root)
    return promoted


def prune_corpus(persist_root):
    infos = []
    for root, _dirs, files in os.walk(persist_root):
        for name in files:
            path = os.path.join(root, name)
            try:
                infos.append((os.path.getmtime(path), os.path.getsize(path), path))
            except OSError:
                continue
    infos.sort()
    total = sum(size for _, size, _ in infos)
    while (len(infos) > MAX_CORPUS_ENTRIES or total > MAX_CORPUS_BYTES) and infos:
        _, size, path = infos.pop(0)
        total -= size
        try:
            os.remove(path)
        except OSError:
            pass


def corpus_inventory(persist_root):
    count = 0
    size = 0
    for root, _dirs, files in os.walk(persist_root):
        for name in files:
            try:
                size += os.path.getsize(os.path.join(root, name))
                count += 1
            except OSError:
                continue
    return {"dir": persist_root, "entries": count, "bytes": size}


def repro_verdict(args, path, target, global_cache_dir, repro_cache_dir):
    """Replay one input through `zig build fuzz-cov-repro`.

    Returns ``(verdict, blob)`` with verdict ``repro_confirmed`` (the replay
    crashed or hung), ``repro_not_confirmed`` (clean exit) or
    ``repro_timeout`` (replay exceeded REPRO_TIMEOUT)."""
    env = os.environ.copy()
    env["SAFEGGUF_COV_FUZZ_REPRO"] = path
    env["SAFEGGUF_COV_FUZZ_PROFILE"] = target["profile"]
    env["SAFEGGUF_COV_FUZZ_ENDIAN"] = target["endian"]
    try:
        proc = subprocess.run(
            [args.zig, "build", "fuzz-cov-repro",
             "--cache-dir", repro_cache_dir,
             "--global-cache-dir", global_cache_dir],
            cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=REPRO_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "repro_timeout", b"repro timed out"
    blob = proc.stdout or b""
    if proc.returncode < 0 or b"panic:" in blob or b"Segmentation fault" in blob:
        return "repro_confirmed", blob
    return "repro_not_confirmed", blob


def save_crash_artifact(args, target, entries, cache_dir, log_path, taxonomy, site,
                        attempt_repro=True, command=None):
    """original + repro-validated minimized input + metadata for one incident.

    Returns ``(artifact_name, repro_status, repro_calls, taxonomy)`` where
    ``repro_status`` is one of REPRO_STATUSES and ``taxonomy`` is final: a
    proven crash with no attributable frame (`unknown_crash`) is promoted to
    `validator_crash` when the standalone replay confirms the input.
    ``attempt_repro`` is False for timeout/oom incidents, where replaying a
    possibly-hanging input is not attempted and the original is preserved
    unminimized."""
    stamp = utcstamp()
    base = "crash-%s-%s" % (target["step"], stamp)
    global_cache_dir = os.path.join(args.cache_root, "zig-global")
    repro_cache_dir = os.path.join(args.cache_root, "cache-repro-" + target["step"])

    _, current_path = entries[-1]
    with open(current_path, "rb") as f:
        original = f.read()
    original_path = os.path.join(args.artifacts_dir, base + ".gguf")
    with open(original_path, "wb") as f:
        f.write(original)
    original_sha = sha256_file(original_path)

    def probe_is_bad(data):
        probe = os.path.join(args.artifacts_dir, base + ".probe")
        try:
            with open(probe, "wb") as f:
                f.write(data)
            verdict, _ = repro_verdict(args, probe, target, global_cache_dir, repro_cache_dir)
        finally:
            try:
                os.remove(probe)
            except OSError:
                pass
        return verdict != "repro_not_confirmed"

    minimized_path = None
    minimized_sha = None
    minimized_size = None
    repro_calls = 0
    repro_status = "repro_not_attempted"
    if attempt_repro:
        minimization = "repro did not confirm the recovered candidate; original preserved"
        repro_status, _ = repro_verdict(args, original_path, target, global_cache_dir, repro_cache_dir)
        repro_calls = 1
        if repro_status == "repro_confirmed":
            # The engine pads corpus/current-input files to mmap capacity (input
            # length is not persisted in Zig 0.14.1), so trim NUL padding first but
            # only keep the trim if the repro still crashes on it.
            candidate = original.rstrip(b"\x00") or original
            if candidate != original:
                repro_calls += 1
                if not probe_is_bad(candidate):
                    candidate = original
            lo, hi = 1, len(candidate)
            # Bounded prefix-truncation search: find the smallest crashing prefix.
            # Invariant: `hi` is a known-crashing length; when the call budget is
            # exhausted the search state may be unconfirmed, so re-check `lo` once
            # and fall back to the full recovered candidate if needed.
            while lo < hi and repro_calls < MAX_REPRO_CALLS:
                mid = (lo + hi) // 2
                repro_calls += 1
                if probe_is_bad(candidate[:mid]):
                    hi = mid
                else:
                    lo = mid + 1
            minimized = candidate
            if lo < len(candidate) and repro_calls < MAX_REPRO_CALLS:
                repro_calls += 1
                if probe_is_bad(candidate[:lo]):
                    minimized = candidate[:lo]
            if len(minimized) < len(original):
                minimized_path = os.path.join(args.artifacts_dir, base + "-minimized.gguf")
                with open(minimized_path, "wb") as f:
                    f.write(minimized)
                minimized_sha = sha256_file(minimized_path)
                minimized_size = len(minimized)
                minimization = ("repro-validated trailing-NUL trim + prefix truncation "
                                "(%d -> %d bytes, %d repro calls)" % (len(original), len(minimized), repro_calls))
            else:
                minimization = ("repro confirmed the recovered input but minimization did not shrink "
                                "it (%d bytes, %d repro calls)" % (len(original), repro_calls))
        elif repro_status == "repro_timeout":
            # A hanging replay would make every minimization probe time out, so
            # keep the original and leave rendering the verdict to the humans.
            minimization = ("repro exceeded %ds; minimization skipped, original preserved"
                            % REPRO_TIMEOUT)
    else:
        minimization = "repro not attempted for taxonomy=%s; original preserved" % taxonomy
    if (attempt_repro and taxonomy == TAXONOMY_UNKNOWN_CRASH
            and repro_status == "repro_confirmed"):
        # A proven crash with no attributable frame is a validator crash only
        # when the deterministic standalone replay confirms the input.
        taxonomy = TAXONOMY_VALIDATOR_CRASH
    log("target %s: %s artifact %s (%s)" % (target["step"], taxonomy, base, minimization))

    blob = read_log(log_path)
    version = zig_version(args.zig)
    commit = git_commit()
    meta = {
        "kind": "coverage_fuzz_crash",
        **incident_schema(taxonomy, repro_status, original_sha, command, blob,
                          "zig " + version, commit),
        "target": target["step"],
        "profile": target["profile"],
        "endian": target["endian"],
        "host_endian": sys.byteorder,
        "seed": FUZZ_SEED,
        "crash_site": site,
        "stack_top_frames": stack_top_frames(blob),
        "repro_calls": repro_calls,
        "engine": "zig built-in fuzzer (std.testing.fuzz, Zig 0.14.1)",
        "zig_version": version,
        "compiler": "zig " + str(version),
        "git_commit": commit,
        "platform": platform.platform(),
        "sanitizers": "Debug safety checks + GeneralPurposeAllocator leak panic (no ASan/UBSan runtime)",
        "coverage": parse_coverage(cache_dir),
        "file": os.path.basename(original_path),
        "sha": {"original": original_sha, "minimized": minimized_sha},
        "sizes": {"original": len(original), "minimized": minimized_size},
        "minimized_file": os.path.basename(minimized_path) if minimized_path else None,
        "minimization": minimization,
        "log": os.path.basename(log_path),
        "log_excerpt": blob[-STDERR_TAIL_BYTES:].decode("utf-8", "replace"),
        "repro_command": (
            "SAFEGGUF_COV_FUZZ_REPRO=%s SAFEGGUF_COV_FUZZ_PROFILE=%s "
            "SAFEGGUF_COV_FUZZ_ENDIAN=%s zig build fuzz-cov-repro"
            % (os.path.relpath(original_path, REPO_ROOT), target["profile"], target["endian"])
        ),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(args.artifacts_dir, base + ".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return os.path.basename(original_path), repro_status, repro_calls, taxonomy


def zig_version(zig):
    try:
        return subprocess.run([zig, "version"], capture_output=True, text=True,
                              timeout=30).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def git_commit():
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              timeout=10, cwd=REPO_ROOT)
        return proc.stdout.strip() if proc.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def as_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def read_json_object(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def write_json(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")


def summary_totals(summary):
    """Aggregate one run: executions, unique coverage inputs, covered paths,
    corpus growth, incident taxonomy and repro outcomes."""
    totals = {
        "targets": 0,
        "n_runs": 0,
        "unique_runs": 0,
        "covered_pcs": 0,
        "pcs_len": 0,
        "coverage_pct": 0.0,
        "promoted": 0,
        "corpus_entries": 0,
        "corpus_bytes": 0,
        "crash_artifacts": 0,
        "validator_crashes": 0,
        "engine_crashes": 0,
        "unknown_crashes": 0,
        "setup_failures": 0,
        "advisory_crashes": 0,
        "timeouts": 0,
        "ooms": 0,
        "repro_confirmed": 0,
        "repro_not_confirmed": 0,
        "repro_timeout": 0,
        "repro_not_attempted": 0,
        "failed_targets": 0,
    }
    for r in summary.get("targets") or []:
        if not isinstance(r, dict):
            continue
        cov = r.get("coverage") or {}
        totals["targets"] += 1
        for key in ("n_runs", "unique_runs", "covered_pcs", "pcs_len"):
            totals[key] += as_int(cov.get(key))
        totals["promoted"] += as_int(r.get("promoted"))
        if r.get("crash_artifact"):
            totals["crash_artifacts"] += 1
        status = r.get("status")
        if status == "validator_crash":
            totals["validator_crashes"] += 1
        elif status == "engine_crash":
            totals["engine_crashes"] += 1
        elif status == "unknown_crash":
            totals["unknown_crashes"] += 1
        elif status in SETUP_TAXONOMIES:
            totals["setup_failures"] += 1
        elif status == "timeout":
            totals["timeouts"] += 1
        elif status == "oom":
            totals["ooms"] += 1
        elif status == "failed":
            totals["failed_targets"] += 1
        if r.get("advisory"):
            totals["advisory_crashes"] += 1
        repro = r.get("repro_status")
        if repro in REPRO_STATUSES:
            totals[repro] += 1
    if totals["pcs_len"]:
        totals["coverage_pct"] = round(100.0 * totals["covered_pcs"] / totals["pcs_len"], 3)
    corpus = summary.get("corpus") or {}
    totals["corpus_entries"] = as_int(corpus.get("entries"))
    totals["corpus_bytes"] = as_int(corpus.get("bytes"))
    return totals


def build_run_record(summary):
    """Compact per-run trend record appended to coverage_history.json."""
    targets = {}
    for r in summary.get("targets") or []:
        if not isinstance(r, dict) or not r.get("step"):
            continue
        cov = r.get("coverage") or {}
        targets[r["step"]] = {
            "profile": r.get("profile"),
            "endian": r.get("endian"),
            "status": r.get("status"),
            "taxonomy": r.get("taxonomy"),
            "crash_site": r.get("crash_site"),
            "repro_status": r.get("repro_status"),
            "repro_calls": r.get("repro_calls"),
            "advisory": bool(r.get("advisory")),
            "stack_top_frames": (r.get("stack_top_frames") or [])[:5],
            "n_runs": cov.get("n_runs"),
            "unique_runs": cov.get("unique_runs"),
            "covered_pcs": cov.get("covered_pcs"),
            "pcs_len": cov.get("pcs_len"),
            "coverage_pct": cov.get("coverage_pct"),
            "corpus_files": r.get("corpus_files"),
            "promoted": r.get("promoted"),
        }
    return {
        "generated_at": summary.get("generated_at"),
        "git_commit": summary.get("git_commit"),
        "zig_version": summary.get("zig_version"),
        "budget_seconds": summary.get("budget_seconds"),
        "wall_seconds": summary.get("wall_seconds"),
        "advisory": True,
        "totals": summary_totals(summary),
        "targets": targets,
    }


def embedded_history_runs(summary):
    """Compact records embedded in a previous coverage_summary.json, used to
    rebuild the trend file after a lost cache entry."""
    if not isinstance(summary, dict):
        return []
    hist = summary.get("history")
    if not isinstance(hist, dict):
        return []
    runs = hist.get("recent_runs")
    if not isinstance(runs, list):
        return []
    return [r for r in runs if isinstance(r, dict) and isinstance(r.get("totals"), dict)]


def seed_history_runs(args):
    """Existing trend records for this run: history file first, then the
    previous summary's embedded records, then the previous summary's totals as
    a single baseline record. Returns ``(runs, source)``; ``runs`` may be
    empty. Both fallbacks keep multi-run history alive across a cache miss."""
    doc = read_json_object(os.path.join(args.artifacts_dir, HISTORY_FILE))
    if doc is not None:
        runs = [r for r in doc.get("runs") or []
                if isinstance(r, dict) and isinstance(r.get("totals"), dict)]
        if runs:
            return runs, "history file"
    summary = read_json_object(os.path.join(args.artifacts_dir, SUMMARY_FILE))
    runs = embedded_history_runs(summary)
    if runs:
        return runs, "previous summary (history file missing)"
    if summary is not None:
        record = build_run_record(summary)
        if record["generated_at"]:
            return [record], "previous summary baseline (history file missing)"
    return [], "no previous record"


def record_history(args, summary):
    """Append this run to coverage_history.json, return (doc, previous, current)."""
    path = os.path.join(args.artifacts_dir, HISTORY_FILE)
    runs, source = seed_history_runs(args)
    previous = runs[-1] if runs else None
    current = build_run_record(summary)
    runs.append(current)
    del runs[:-MAX_HISTORY_RUNS]
    doc = {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "generated_at": summary["generated_at"],
        "note": HISTORY_NOTE,
        "runs_recorded": len(runs),
        "runs": runs,
    }
    write_json(path, doc)
    log("history: %s holds %d run(s) from %s%s" % (
        path, len(runs), source,
        "" if previous is not None else " - no previous record to diff"))
    return doc, previous, current


def field_delta(field, previous, current):
    prev, cur = previous.get(field), current.get(field)
    if isinstance(prev, bool) or not isinstance(prev, (int, float)):
        return None
    if isinstance(cur, bool) or not isinstance(cur, (int, float)):
        return None
    diff = cur - prev
    return round(diff, 3) if isinstance(diff, float) else diff


def history_block(doc, previous, current, commit, prev_targets, cur_targets):
    """Advisory delta block embedded in coverage_summary.json."""
    delta = None
    targets_delta = {}
    previous_info = None
    if previous is not None:
        prev_totals = previous.get("totals") or {}
        delta = {field: field_delta(field, prev_totals, current["totals"]) for field in DELTA_FIELDS}
        for step, cur in current["targets"].items():
            prev = (previous.get("targets") or {}).get(step) or {}
            targets_delta[step] = {
                field: field_delta(field, prev, cur)
                for field in ("n_runs", "covered_pcs", "coverage_pct")
            }
        previous_info = {
            "generated_at": previous.get("generated_at"),
            "git_commit": previous.get("git_commit"),
            "same_commit": previous.get("git_commit") == commit,
            "target_set_changed": prev_targets != cur_targets,
        }
    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "file": HISTORY_FILE,
        "runs_recorded": doc["runs_recorded"],
        "note": ("advisory only: computed from the cached history file, rebuilt from the "
                 "previous summary when the cache misses, never a gate"),
        "previous": previous_info,
        "delta": delta,
        "targets_delta": targets_delta,
        "recent_coverage_pct": [r["totals"].get("coverage_pct") for r in doc["runs"][-5:]],
        "recent_runs": doc["runs"][-RECENT_RUNS_IN_SUMMARY:],
    }


def delta_text(field, delta, label=None):
    value = delta.get(field)
    name = label or field
    if value is None:
        return "%s=n/a" % name
    return "%s=%+g" % (name, value)


def history_lines(hist):
    """Human-readable delta/trend lines (shared by .txt and the step summary)."""
    head = "history: record #%d of %d (%s)" % (
        hist["runs_recorded"], MAX_HISTORY_RUNS, hist["file"])
    if hist.get("previous") is None:
        return [head + "; recorded as baseline - no previous record to diff"]
    previous = hist["previous"]
    notes = []
    if not previous.get("same_commit"):
        notes.append("commit changed - deltas are commit-relative")
    if previous.get("target_set_changed"):
        notes.append("target set changed")
    suffix = (" (" + "; ".join(notes) + ")") if notes else ""
    delta = hist.get("delta") or {}
    lines = [
        head + "; previous %s @ %s%s" % (
            previous.get("generated_at"),
            (previous.get("git_commit") or "unknown")[:7], suffix),
        "delta coverage: " + " ".join(
            delta_text(f, delta, label) for f, label in (
                ("covered_pcs", "edges"), ("coverage_pct", "pct"))),
        "delta search: " + " ".join(
            delta_text(f, delta, label) for f, label in (
                ("n_runs", "executions"), ("unique_runs", "unique_inputs"))),
        "delta corpus: " + " ".join(
            delta_text(f, delta) for f in ("corpus_entries", "corpus_bytes", "promoted")),
        "delta incidents: " + " ".join(
            delta_text(f, delta) for f in ("crash_artifacts", "validator_crashes",
                                           "engine_crashes", "unknown_crashes",
                                           "setup_failures", "advisory_crashes",
                                           "timeouts", "ooms", "failed_targets")),
        "delta repro: " + " ".join(
            delta_text(f, delta) for f in ("repro_confirmed", "repro_not_confirmed",
                                           "repro_timeout", "repro_not_attempted")),
    ]
    recent = [v for v in (hist.get("recent_coverage_pct") or []) if v is not None]
    if len(recent) > 1:
        lines.append("trend: coverage_pct over the last %d run(s), oldest first: %s"
                     % (len(recent), " ".join("%.3f" % v for v in recent)))
    return lines


def target_delta_text(targets_delta, step):
    delta = (targets_delta or {}).get(step) or {}
    parts = []
    for field, label in (("n_runs", "d_runs"), ("covered_pcs", "d_edges"), ("coverage_pct", "d_pct")):
        value = delta.get(field)
        if value is not None:
            parts.append("%s=%+g" % (label, value))
    return (" " + " ".join(parts)) if parts else ""


def write_summary(args, results, started):
    """Write coverage_summary.json/.txt and append this run to the history file."""
    inventory = corpus_inventory(args.corpus_dir)
    advisory = [r["step"] for r in results if r.get("advisory")]
    summary = {
        "schema_version": "safegguf-coverage-fuzz/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit(),
        "zig_version": zig_version(args.zig),
        "advisory": True,
        "advisory_engine_crashes": advisory,
        "note": ("coverage lane is advisory (nightly); production toolchain stays 0.13.0, "
                 "pinned oracle/differential and mutation campaigns are unchanged; "
                 "incidents carry taxonomy validator_crash | engine_crash | unknown_crash | "
                 "timeout | oom | setup_* plus a repro status; validator_crash requires proof "
                 "of a target-process crash with production frames or a deterministic repro, "
                 "setup_* failures are never reported as validator crashes, and only "
                 "non-reproducing engine-internal Zig 0.14.1 fuzzer crashes are advisory "
                 "(they do not fail the lane)"),
        "budget_seconds": args.budget_seconds,
        "wall_seconds": round(time.monotonic() - started, 1),
        "seed_corpus": os.path.join(REPO_ROOT, "tests", "corpus"),
        "sanitizers": ("Debug safety checks (bounds/overflow/UB) + GeneralPurposeAllocator "
                       "leak panic; Zig built-in fuzzer has no ASan/UBSan runtime"),
        "rng": "zig built-in fuzzer DefaultPrng seeded with 0 (deterministic mutation order)",
        "platform": platform.platform(),
        "corpus": inventory,
        "targets": results,
    }
    # The previous record is read (history file, else the previous summary) before
    # this run's files are overwritten; deltas are trend-only and never a gate.
    os.makedirs(args.artifacts_dir, exist_ok=True)
    doc, previous, current = record_history(args, summary)
    summary["history"] = history_block(
        doc, previous, current, summary["git_commit"],
        sorted((previous or {}).get("targets") or {}), sorted(current["targets"]),
    )
    json_path = os.path.join(args.artifacts_dir, SUMMARY_FILE)
    write_json(json_path, summary)

    lines = [
        "SafeGGUF coverage fuzz summary (advisory, Zig %s)" % summary["zig_version"],
        "commit: %s" % summary["git_commit"],
        "generated: %s" % summary["generated_at"],
        "budget: %ss (wall %ss)" % (summary["budget_seconds"], summary["wall_seconds"]),
        "corpus: %d entries / %d bytes" % (inventory["entries"], inventory["bytes"]),
    ]
    lines.extend(history_lines(summary["history"]))
    lines.append("")
    for r in results:
        cov = r["coverage"] or {}
        incident = ""
        if r.get("taxonomy"):
            incident = " taxonomy=%s site=%s repro=%s calls=%s" % (
                r["taxonomy"], r.get("crash_site") or "?",
                r.get("repro_status") or "?", r.get("repro_calls", 0))
        if r["crash_artifact"]:
            incident += " artifact=%s" % r["crash_artifact"]
        lines.append(
            "%-28s %-16s runs=%-9s unique=%-9s edges=%s/%s (%.2f%%) corpus=%d promoted=%d%s%s" % (
                r["step"], r["status"], cov.get("n_runs", "?"), cov.get("unique_runs", "?"),
                cov.get("covered_pcs", "?"), cov.get("pcs_len", "?"), cov.get("coverage_pct", 0.0),
                r["corpus_files"], r["promoted"], incident,
                target_delta_text(summary["history"].get("targets_delta"), r["step"]),
            )
        )
        if r["detail"]:
            lines.append("    detail: %s" % r["detail"])
    text_path = os.path.join(args.artifacts_dir, "coverage_summary.txt")
    with open(text_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log("summary written: %s" % json_path)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zig", default="zig",
                        help="Zig 0.14.1 executable (default: zig from PATH)")
    parser.add_argument("--budget-seconds", type=int, default=1800,
                        help="total fuzzing budget for the required targets (default: 1800)")
    parser.add_argument("--smoke-seconds", type=int, default=300,
                        help="budget for the optional llama-cpp/big smoke target (default: 300)")
    parser.add_argument("--startup-timeout", type=int, default=600,
                        help="seconds allowed for build + fuzz mode startup (default: 600)")
    parser.add_argument("--stall-seconds", type=int, default=300,
                        help="abort a target when n_runs stops advancing for this long (default: 300)")
    parser.add_argument("--cache-root", default=DEFAULT_CACHE_ROOT,
                        help="lane cache root (default: .cache/coverage-fuzz)")
    parser.add_argument("--corpus-dir", default=None,
                        help="persisted corpus dir (default: <cache-root>/corpus)")
    parser.add_argument("--artifacts", default=DEFAULT_ARTIFACTS_DIR,
                        help="artifact dir (default: tests/fuzz-artifacts/coverage-fuzz)")
    parser.add_argument("--targets", nargs="+", default=None,
                        help="subset of step names to run (default: all four)")
    parser.add_argument("--keep-going", action="store_true",
                        help="continue with later targets after a crash")
    args = parser.parse_args()

    if args.corpus_dir is None:
        args.corpus_dir = DEFAULT_CORPUS_DIR
    args.artifacts_dir = args.artifacts
    os.makedirs(args.artifacts_dir, exist_ok=True)
    os.makedirs(args.corpus_dir, exist_ok=True)
    os.makedirs(args.cache_root, exist_ok=True)
    global_cache_dir = os.path.join(args.cache_root, "zig-global")
    os.makedirs(global_cache_dir, exist_ok=True)

    selected = TARGETS
    if args.targets:
        wanted = set(args.targets)
        selected = [t for t in TARGETS if t["step"] in wanted]
        missing = wanted - {t["step"] for t in selected}
        if missing:
            parser.error("unknown targets: %s" % ", ".join(sorted(missing)))

    required = [t for t in selected if t["kind"] == "required"]
    smoke = [t for t in selected if t["kind"] == "smoke"]
    per_required = max(1, (args.budget_seconds - (args.smoke_seconds if smoke else 0)) // max(1, len(required)))
    budgets = {t["step"]: (args.smoke_seconds if t["kind"] == "smoke" else per_required) for t in selected}

    started = time.monotonic()
    results = []
    exit_code = 0
    for target in selected:
        result = run_bounded(args, target, budgets[target["step"]], args.artifacts_dir, global_cache_dir)
        results.append(result)
        log("target %s: status=%s taxonomy=%s repro=%s promoted=%d" % (
            target["step"], result["status"], result.get("taxonomy") or "-",
            result.get("repro_status") or "-", result["promoted"]))
        if result["status"] != "ok" and not result.get("advisory"):
            exit_code = 1
            if not args.keep_going:
                break

    write_summary(args, results, started)
    advisory = [r["step"] for r in results if r.get("advisory")]
    if exit_code != 0:
        log("lane FAILED: validator/unknown crash, setup/infra failure, timeout, OOM or "
            "unexpected engine exit; see %s" % args.artifacts_dir)
    elif advisory:
        log("lane OK with advisory engine crashes (repro_status=repro_not_confirmed, "
            "did not fail lane): %s" % ", ".join(advisory))
    else:
        log("lane OK")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
