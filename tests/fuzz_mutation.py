"""
High-Throughput Mutation Fuzzer for SafeGGUF.
Mutates the seed corpus with bitflips, byte overwrites, chunk deletions,
splicing, and boundary value injections, then validates that SafeGGUF
never crashes, never panics, and strictly returns binary exit codes (0 or 2).
"""

import argparse
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
    args = parser.parse_args()

    random.seed(args.seed)

    if not os.path.exists(SAFEGGUF_BIN):
        print(f"SafeGGUF binary not found at {SAFEGGUF_BIN}. Running zig build...")
        subprocess.check_call(["zig", "build", "-Doptimize=ReleaseSafe"], cwd=REPO_ROOT)

    corpus_files = [os.path.join(CORPUS_DIR, f) for f in os.listdir(CORPUS_DIR) if f.endswith(".gguf")]
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

            profile = profiles[i % len(profiles)]
            cmd = [SAFEGGUF_BIN, "inspect", tmp_path, "--profile", profile]

            try:
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            except subprocess.TimeoutExpired:
                failures.append(f"Iteration {i}: Timeout (> 5s) on profile {profile} (size={len(mutated_buf)})")
                break

            rc = proc.returncode
            if rc == 0:
                pass_count += 1
            elif rc == 2:
                reject_count += 1
            elif rc < 0:
                failures.append(f"Iteration {i}: CRASH with signal {-rc} on profile {profile} (size={len(mutated_buf)})")
                break
            else:
                failures.append(f"Iteration {i}: Unexpected exit code {rc} on profile {profile} (Stderr: {proc.stderr.decode('utf-8', 'replace')[:100]})")
                break

            if i % 500 == 0 or i == args.iterations:
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                print(f"  [{i}/{args.iterations}] PASS: {pass_count}, REJECT: {reject_count} ({rate:.1f} exec/s)")

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    elapsed = time.time() - start_time
    print(f"\nCompleted {args.iterations} mutation fuzzing iterations in {elapsed:.2f}s")

    if failures:
        print("\nFUZZING FAILURES DETECTED:")
        for fail in failures:
            print("  X " + fail)
        sys.exit(1)

    print("✓ Mutation Fuzzing PASSED! Zero crashes, zero unhandled errors, strict exit codes.")

if __name__ == "__main__":
    main()
