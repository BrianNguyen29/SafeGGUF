"""
High-Throughput Mutation Fuzzer for SafeGGUF.
Mutates the seed corpus with bitflips, byte overwrites, chunk deletions,
splicing, and boundary value injections, then validates that SafeGGUF
never crashes, never panics, and strictly returns binary exit codes (0 or 2).
"""

import argparse
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SAFEGGUF_BIN = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf")
CORPUS_DIR = os.path.join(SCRIPT_DIR, "corpus")
ARTIFACTS_DIR = os.path.join(SCRIPT_DIR, "fuzz-artifacts")

def save_failing_artifact(artifacts_dir: str, seed: int, iteration: int, profile: str, payload: bytearray, kind: str, detail: str, exit_code: int, stderr_text: str):
    os.makedirs(artifacts_dir, exist_ok=True)
    base = f"crash-seed{seed}-iter{iteration}"
    bin_path = os.path.join(artifacts_dir, f"{base}.gguf")
    meta_path = os.path.join(artifacts_dir, f"{base}.json")
    with open(bin_path, "wb") as bf:
        bf.write(payload)

    git_commit = "unknown"
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=2)
        if proc.returncode == 0:
            git_commit = proc.stdout.strip()
    except Exception:
        pass

    meta = {
        "kind": kind,
        "detail": detail,
        "seed": seed,
        "iteration": iteration,
        "profile": profile,
        "payload_size": len(payload),
        "exit_code": exit_code,
        "stderr_excerpt": stderr_text[:200] if stderr_text else "",
        "git_commit": git_commit,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "file": f"{base}.gguf"
    }
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)
    print(f"  --> Preserved failing artifact: {bin_path} and {meta_path}")
    return bin_path, meta_path


INTERESTING_INTEGERS = [
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 255, 256,
    0x7FFF, 0x8000, 0xFFFF,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
]

def mutate(data: bytearray, all_corpus: list) -> bytearray:
    buf = bytearray(data)
    if not buf:
        return bytearray(b"GGUF\x03\x00\x00\x00")

    num_ops = random.randint(1, 4)
    for _ in range(num_ops):
        op = random.choice([
            "bitflip", "byte_flip", "byte_insert", "byte_delete",
            "int_overwrite", "splice", "truncate", "shuffle_chunk"
        ])
        if op == "bitflip" and len(buf) > 0:
            idx = random.randrange(len(buf))
            buf[idx] ^= (1 << random.randrange(8))
        elif op == "byte_flip" and len(buf) > 0:
            idx = random.randrange(len(buf))
            buf[idx] = random.randrange(256)
        elif op == "byte_insert" and len(buf) < 100000:
            idx = random.randrange(len(buf) + 1)
            count = random.randint(1, 16)
            buf[idx:idx] = bytearray(random.getrandbits(8) for _ in range(count))
        elif op == "byte_delete" and len(buf) > 8:
            idx = random.randrange(len(buf) - 4)
            count = random.randint(1, min(16, len(buf) - idx))
            del buf[idx:idx + count]
        elif op == "int_overwrite" and len(buf) >= 8:
            val = random.choice(INTERESTING_INTEGERS)
            width = random.choice([2, 4, 8])
            if len(buf) >= width:
                idx = random.randrange(len(buf) - width + 1)
                endian = random.choice(["<", ">"])
                fmt = f"{endian}{'H' if width == 2 else ('I' if width == 4 else 'Q')}"
                buf[idx:idx + width] = struct.pack(fmt, val & ((1 << (width * 8)) - 1))
        elif op == "splice" and len(all_corpus) > 1 and len(buf) > 4:
            other = random.choice(all_corpus)
            if len(other) > 4:
                idx = random.randrange(len(buf))
                o_idx = random.randrange(len(other) - 4)
                o_len = random.randint(1, min(32, len(other) - o_idx))
                buf[idx:idx] = other[o_idx:o_idx + o_len]
        elif op == "truncate" and len(buf) > 4:
            new_len = random.randint(1, len(buf) - 1)
            buf = buf[:new_len]
        elif op == "shuffle_chunk" and len(buf) > 8:
            idx = random.randrange(len(buf) - 8)
            chunk_len = random.randint(2, min(16, len(buf) - idx))
            chunk = list(buf[idx:idx + chunk_len])
            random.shuffle(chunk)
            buf[idx:idx + chunk_len] = bytes(chunk)

    return buf

def main():
    parser = argparse.ArgumentParser(description="SafeGGUF Mutation Fuzzer")
    parser.add_argument("--iterations", type=int, default=2000, help="Number of mutations to test (default: 2000)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--test-crash-handler", action="store_true", help="Run synthetic failure test to verify crash persistence")
    args = parser.parse_args()

    if args.test_crash_handler:
        print("Running synthetic crash persistence self-test...")
        with tempfile.TemporaryDirectory() as td:
            dummy_payload = bytearray(b"GGUF\x03\x00\x00\x00_SYNTHETIC_CRASH_PAYLOAD")
            bp, mp = save_failing_artifact(td, 999, 1, "test-profile", dummy_payload, "SYNTHETIC_CRASH", "Test crash assertion", -11, "Segmentation fault (core dumped)")
            assert os.path.exists(bp), f"Binary artifact not found: {bp}"
            assert os.path.exists(mp), f"Metadata JSON artifact not found: {mp}"
            with open(mp, "r", encoding="utf-8") as mf:
                data = json.load(mf)
            assert data["kind"] == "SYNTHETIC_CRASH"
            assert data["seed"] == 999
            assert data["exit_code"] == -11
            assert data["payload_size"] == len(dummy_payload)
            with open(bp, "rb") as bf:
                read_payload = bf.read()
            assert read_payload == dummy_payload
        print("✓ Synthetic crash persistence self-test PASSED successfully!")
        sys.exit(0)

    random.seed(args.seed)

    if not os.path.exists(SAFEGGUF_BIN):
        print(f"SafeGGUF binary not found at {SAFEGGUF_BIN}. Running zig build...")
        subprocess.check_call(["zig", "build", "-Doptimize=ReleaseSafe"], cwd=REPO_ROOT)

    corpus_files = sorted([os.path.join(CORPUS_DIR, f) for f in os.listdir(CORPUS_DIR) if f.endswith(".gguf")])
    if not corpus_files:
        print("Error: No corpus files found. Run generate_fixtures.py first.")
        sys.exit(1)

    corpus_data = []
    for cf in corpus_files:
        with open(cf, "rb") as f:
            corpus_data.append(bytearray(f.read()))

    print(f"=== SafeGGUF Mutation Fuzz Campaign ({args.iterations} iterations, {len(corpus_data)} seed files) ===")

    start_time = time.time()
    pass_count = 0
    reject_count = 0
    failures = []

    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as tmp_f:
        tmp_path = tmp_f.name

    try:
        profiles = ["gguf-spec", "llama-cpp"]
        for i in range(1, args.iterations + 1):
            seed_buf = random.choice(corpus_data)
            mutated_buf = mutate(seed_buf, corpus_data)

            with open(tmp_path, "wb") as f:
                f.write(mutated_buf)

            for profile in profiles:
                cmd = [SAFEGGUF_BIN, "inspect", tmp_path, "--profile", profile]

                try:
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                except subprocess.TimeoutExpired:
                    msg = f"Iteration {i}: Timeout (> 5s) on profile {profile} (size={len(mutated_buf)})"
                    failures.append(msg)
                    save_failing_artifact(ARTIFACTS_DIR, args.seed, i, profile, mutated_buf, "TIMEOUT", msg, -1, "Timed out after 5s")
                    break

                rc = proc.returncode
                if rc == 0:
                    pass_count += 1
                elif rc == 2:
                    reject_count += 1
                elif rc < 0:
                    msg = f"Iteration {i}: CRASH with signal {-rc} on profile {profile} (size={len(mutated_buf)})"
                    failures.append(msg)
                    stderr_text = proc.stderr.decode("utf-8", "replace")[:200]
                    save_failing_artifact(ARTIFACTS_DIR, args.seed, i, profile, mutated_buf, f"CRASH_SIG{-rc}", msg, rc, stderr_text)
                    break
                else:
                    stderr_text = proc.stderr.decode("utf-8", "replace")[:200]
                    msg = f"Iteration {i}: Unexpected exit code {rc} on profile {profile} (Stderr: {stderr_text[:100]})"
                    failures.append(msg)
                    save_failing_artifact(ARTIFACTS_DIR, args.seed, i, profile, mutated_buf, f"UNEXPECTED_EXIT_{rc}", msg, rc, stderr_text)
                    break

            if failures:
                break

            if i % 500 == 0 or i == args.iterations:
                elapsed = time.time() - start_time
                total_exec = pass_count + reject_count
                rate = total_exec / elapsed if elapsed > 0 else 0
                print(f"  [{i}/{args.iterations}] ({total_exec} executions) PASS: {pass_count}, REJECT: {reject_count} ({rate:.1f} exec/s)")

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    elapsed = time.time() - start_time
    total_exec = pass_count + reject_count
    print(f"\nCompleted {args.iterations} mutation iterations ({total_exec} executions across both profiles) in {elapsed:.2f}s")

    if failures:
        print("\nFUZZING FAILURES DETECTED:")
        for fail in failures:
            print("  X " + fail)
        sys.exit(1)

    print("✓ Mutation Fuzzing PASSED! Zero crashes, zero unhandled errors, strict exit codes.")

if __name__ == "__main__":
    main()
