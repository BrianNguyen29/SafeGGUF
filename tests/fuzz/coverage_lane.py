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
  * a harness crash preserves original + repro-validated minimized input +
    metadata under tests/fuzz-artifacts/coverage-fuzz/ and fails the lane;
  * an engine-internal crash inside Zig 0.14.1's built-in fuzzer (top frames
    are lib/fuzzer.zig) whose recovered input does not reproduce is preserved
    as an advisory `engine_crash` artifact and does not fail the lane.

The lane is advisory (nightly): it is complementary to `zig build fuzz` (0.13
corpus sweep) and the deterministic mutation campaigns, never a replacement.
"""

import argparse
import hashlib
import json
import os
import platform
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


def crash_site(blob):
    """Classify a crash trace: 'engine' when the top frame is Zig's built-in
    fuzzer runtime, 'harness' when safegguf src/tests frames are on top,
    'unknown' otherwise."""
    lines = blob.decode("utf-8", "replace").splitlines()
    for i, line in enumerate(lines):
        if "Segmentation fault" not in line and "panic:" not in line:
            continue
        for frame in lines[i + 1:i + 12]:
            if "lib/fuzzer.zig" in frame or "lib/Build/Fuzz" in frame:
                return "engine"
            if "/src/" in frame or "/tests/" in frame:
                return "harness"
        break
    return "unknown"

MAX_CORPUS_ENTRIES = 10_000
MAX_CORPUS_BYTES = 256 * 1024 * 1024
MAX_REPRO_CALLS = 24
REPRO_TIMEOUT = 300


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
    log("target %s: fuzzing for up to %ds (cache %s)" % (target["step"], budget, cache_dir))
    result = {
        "step": target["step"],
        "profile": target["profile"],
        "endian": target["endian"],
        "budget_seconds": budget,
        "status": "ok",
        "detail": "",
        "rc": None,
        "coverage": None,
        "corpus_files": 0,
        "promoted": 0,
        "crash_artifact": None,
        "crash_site": None,
        "crash_reproduced": None,
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
            result["status"] = "failed"
            result["detail"] = "fuzz mode did not start within %ds" % args.startup_timeout
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
                result["status"] = "failed"
                result["detail"] = "no fuzz progress for %ds (possible hang/OOM)" % args.stall_seconds
            elif proc.poll() is None:
                stop_group(proc)

        result["rc"] = proc.returncode
        blob = read_log(log_path)
        if crash_marked or has_marker(blob):
            result["status"] = "crash"
            result["crash_site"] = crash_site(blob)
            result["detail"] = "fuzz worker crash marker in lane log (site=%s)" % result["crash_site"]
        elif result["status"] == "ok" and early_exit:
            if proc.returncode == 0:
                result["status"] = "failed"
                result["detail"] = "fuzz build exited 0 before the time budget"
            else:
                result["status"] = "crash"
                result["crash_site"] = crash_site(blob)
                result["detail"] = "fuzz build exited early with rc=%s (site=%s)" % (
                    proc.returncode, result["crash_site"])

    result["coverage"] = parse_coverage(cache_dir)
    corpus_dir = find_corpus_dir(cache_dir)
    entries = []
    if corpus_dir is not None:
        entries = list_corpus_entries(corpus_dir)
        result["corpus_files"] = len(entries)
    if result["status"] == "crash":
        site = result["crash_site"] or "unknown"
        if entries:
            artifact, reproduced = save_crash_artifact(
                args, target, entries, cache_dir, log_path, site
            )
            result["crash_artifact"] = artifact
            result["crash_reproduced"] = reproduced
            if site == "engine" and not reproduced:
                # Spontaneous Zig 0.14.1 built-in fuzzer instability: the crash
                # is in lib/fuzzer.zig and the recovered input does not replay,
                # so it is not a SafeGGUF defect. Keep the artifact but do not
                # fail the advisory lane.
                result["status"] = "engine_crash"
                result["detail"] = (
                    "advisory: Zig 0.14.1 built-in fuzzer engine crash "
                    "(top frames in lib/fuzzer.zig); recovered input did not reproduce"
                )
            elif not reproduced:
                result["detail"] += "; recovered input did not reproduce"
        else:
            result["crash_artifact"] = save_crash_without_input(args, target, log_path, site)
    if corpus_dir is not None:
        result["promoted"] = promote_corpus(corpus_dir, entries, args.corpus_dir, target["step"])
    return result


def save_crash_without_input(args, target, log_path, site):
    """Crash during the seed smoke pass: no f/ entry exists, keep the log."""
    base = "crash-%s-%s" % (target["step"], utcstamp())
    meta = {
        "kind": "coverage_fuzz_crash_no_input",
        "target": target["step"],
        "profile": target["profile"],
        "endian": target["endian"],
        "crash_site": site,
        "engine": "zig built-in fuzzer (std.testing.fuzz, Zig 0.14.1)",
        "zig_version": zig_version(args.zig),
        "git_commit": git_commit(),
        "platform": platform.platform(),
        "detail": "crash before/without a recoverable corpus entry (seed smoke pass); see log",
        "log": os.path.basename(log_path),
        "log_excerpt": read_log(log_path)[-4000:].decode("utf-8", "replace"),
        "repro_command": ("rerun the lane target; a persisted seed is the likely input "
                          "(tests/fuzz/coverage_lane.py --targets %s)" % target["step"]),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    name = base + ".json"
    with open(os.path.join(args.artifacts_dir, name), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    log("target %s: CRASH (no recoverable input) metadata %s" % (target["step"], name))
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


def repro_is_bad(args, path, target, global_cache_dir, repro_cache_dir):
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
        return True, b"repro timed out"
    blob = proc.stdout or b""
    crashed = proc.returncode < 0 or b"panic:" in blob or b"Segmentation fault" in blob
    return crashed, blob


def save_crash_artifact(args, target, entries, cache_dir, log_path, site):
    """original + repro-validated minimized input + metadata for one crash.

    Returns ``(artifact_name, reproduced)`` where ``reproduced`` says whether
    ``zig build fuzz-cov-repro`` re-crashed on the recovered input."""
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

    def probe_is_bad(data):
        probe = os.path.join(args.artifacts_dir, base + ".probe")
        try:
            with open(probe, "wb") as f:
                f.write(data)
            bad, _ = repro_is_bad(args, probe, target, global_cache_dir, repro_cache_dir)
        finally:
            try:
                os.remove(probe)
            except OSError:
                pass
        return bad

    minimized_path = None
    minimization = "repro did not confirm the recovered candidate; original preserved"
    reproduced, _ = repro_is_bad(args, original_path, target, global_cache_dir, repro_cache_dir)
    if reproduced:
        calls = 1
        # The engine pads corpus/current-input files to mmap capacity (input
        # length is not persisted in Zig 0.14.1), so trim NUL padding first but
        # only keep the trim if the repro still crashes on it.
        candidate = original.rstrip(b"\x00") or original
        if candidate != original:
            calls += 1
            if not probe_is_bad(candidate):
                candidate = original
        lo, hi = 1, len(candidate)
        # Bounded prefix-truncation search: find the smallest crashing prefix.
        # Invariant: `hi` is a known-crashing length; when the call budget is
        # exhausted the search state may be unconfirmed, so re-check `lo` once
        # and fall back to the full recovered candidate if needed.
        while lo < hi and calls < MAX_REPRO_CALLS:
            mid = (lo + hi) // 2
            calls += 1
            if probe_is_bad(candidate[:mid]):
                hi = mid
            else:
                lo = mid + 1
        minimized = candidate
        if lo < len(candidate) and calls < MAX_REPRO_CALLS:
            calls += 1
            if probe_is_bad(candidate[:lo]):
                minimized = candidate[:lo]
        if len(minimized) < len(original):
            minimized_path = os.path.join(args.artifacts_dir, base + "-minimized.gguf")
            with open(minimized_path, "wb") as f:
                f.write(minimized)
            minimization = ("repro-validated trailing-NUL trim + prefix truncation "
                            "(%d -> %d bytes, %d repro calls)" % (len(original), len(minimized), calls))
        else:
            minimization = ("repro confirmed the recovered input but minimization did not shrink "
                            "it (%d bytes, %d repro calls)" % (len(original), calls))
    log("target %s: CRASH artifact %s (%s)" % (target["step"], base, minimization))

    meta = {
        "kind": "coverage_fuzz_crash",
        "target": target["step"],
        "profile": target["profile"],
        "endian": target["endian"],
        "crash_site": site,
        "reproduced": reproduced,
        "engine": "zig built-in fuzzer (std.testing.fuzz, Zig 0.14.1)",
        "zig_version": zig_version(args.zig),
        "compiler": "zig " + str(zig_version(args.zig)),
        "git_commit": git_commit(),
        "platform": platform.platform(),
        "sanitizers": "Debug safety checks + GeneralPurposeAllocator leak panic (no ASan/UBSan runtime)",
        "coverage": parse_coverage(cache_dir),
        "file": os.path.basename(original_path),
        "minimized_file": os.path.basename(minimized_path) if minimized_path else None,
        "minimization": minimization,
        "original_size": len(original),
        "minimized_size": os.path.getsize(minimized_path) if minimized_path else None,
        "log": os.path.basename(log_path),
        "log_excerpt": read_log(log_path)[-4000:].decode("utf-8", "replace"),
        "repro_command": (
            "SAFEGGUF_COV_FUZZ_REPRO=%s SAFEGGUF_COV_FUZZ_PROFILE=%s "
            "SAFEGGUF_COV_FUZZ_ENDIAN=%s zig build fuzz-cov-repro"
            % (os.path.relpath(original_path, REPO_ROOT), target["profile"], target["endian"])
        ),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(args.artifacts_dir, base + ".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return os.path.basename(original_path), reproduced


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


def write_summary(args, results, started):
    inventory = corpus_inventory(args.corpus_dir)
    engine_crashes = [r["step"] for r in results if r["status"] == "engine_crash"]
    summary = {
        "schema_version": "safegguf-coverage-fuzz/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_commit(),
        "zig_version": zig_version(args.zig),
        "advisory": True,
        "advisory_engine_crashes": engine_crashes,
        "note": ("coverage lane is advisory (nightly); production toolchain stays 0.13.0, "
                 "pinned oracle/differential and mutation campaigns are unchanged; "
                 "engine-internal Zig 0.14.1 fuzzer crashes whose inputs do not reproduce "
                 "are preserved as artifacts but do not fail the lane"),
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
    os.makedirs(args.artifacts_dir, exist_ok=True)
    json_path = os.path.join(args.artifacts_dir, "coverage_summary.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")

    lines = [
        "SafeGGUF coverage fuzz summary (advisory, Zig %s)" % summary["zig_version"],
        "commit: %s" % summary["git_commit"],
        "generated: %s" % summary["generated_at"],
        "budget: %ss (wall %ss)" % (summary["budget_seconds"], summary["wall_seconds"]),
        "corpus: %d entries / %d bytes" % (inventory["entries"], inventory["bytes"]),
        "",
    ]
    for r in results:
        cov = r["coverage"] or {}
        crash_info = ""
        if r["crash_artifact"]:
            repro = {True: "yes", False: "no", None: "n/a"}[r.get("crash_reproduced")]
            crash_info = " crash=%s site=%s repro=%s" % (
                r["crash_artifact"], r.get("crash_site") or "?", repro)
        lines.append(
            "%-28s %-12s runs=%-9s unique=%-9s edges=%s/%s (%.2f%%) corpus=%d promoted=%d%s" % (
                r["step"], r["status"], cov.get("n_runs", "?"), cov.get("unique_runs", "?"),
                cov.get("covered_pcs", "?"), cov.get("pcs_len", "?"), cov.get("coverage_pct", 0.0),
                r["corpus_files"], r["promoted"], crash_info,
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
        log("target %s: status=%s promoted=%d" % (target["step"], result["status"], result["promoted"]))
        if result["status"] not in ("ok", "engine_crash"):
            exit_code = 1
            if not args.keep_going:
                break

    write_summary(args, results, started)
    advisory = [r["step"] for r in results if r["status"] == "engine_crash"]
    if exit_code != 0:
        log("lane FAILED: crash or unexpected engine exit; see %s" % args.artifacts_dir)
    elif advisory:
        log("lane OK with advisory engine crashes (did not fail lane): %s" % ", ".join(advisory))
    else:
        log("lane OK")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
