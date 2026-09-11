"""
Independent arbitrary-precision (Python bigint) oracle for SafeGGUF checked arithmetic.

Phase 1 (pure oracle, no binary needed):
  * re-derives the pinned ggml 0.23.0 type table from src/gguf/types.zig
    (the same table tests/test_oracle_types.py pins against the upstream
    C oracle; no upstream binary is required here)
  * generates tens of thousands of deterministic tuples (fixed-seed LCG)
  * for checkedAlignUp / checkedProduct / computeTensorBytes and the
    llama-cpp contiguous-offset chain it computes the exact result with
    Python bigints (u64 overflow is impossible in Python, which makes it a
    sound oracle) and asserts:
      - alignUp(x, a) >= x, result % a == 0, idempotent, overflow exactly
        when the exact result exceeds u64
      - product / nbytes overflow classification is exact (no silent wrap)
      - shared oracle vectors also asserted by tests/validator_test.zig

Phase 2 (implementation cross-check through the CLI):
  * builds deterministic GGUF files whose tensor data regions are sized
    exactly by the Python oracle and runs zig-out/bin/safegguf on them:
      - exact-fit file        -> PASS (exit 0)
      - same file, one byte short of the oracle-computed end -> REJECT
        (exit 2, TensorOutOfBounds): any drift in computeTensorBytes /
        checkedAlignUp / checkedAdd would flip the verdict
      - two-tensor llama-cpp file whose second offset is the oracle
        alignUp(n1, alignment) -> PASS only if SafeGGUF's checkedAlignUp
        matches the oracle exactly (contiguity is enforced)
      - product / byte-count overflow descriptors -> REJECT (exit 2,
        ArithmeticOverflow)

Dependencies: phase 2 needs the ReleaseSafe binary at zig-out/bin/safegguf
(same contract as tests/cli_test.py; run `zig build -Doptimize=ReleaseSafe`
first). No C oracle / build_oracle.sh involved.

Run: python tests/arithmetic_oracle.py
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
TYPES_ZIG = os.path.join(REPO_ROOT, "src", "gguf", "types.zig")
BINARY = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf")

U64_MAX = (1 << 64) - 1

# Same LCG constants as tests/validator_test.zig (nextRandomU64 / stress test).
_LCG_A = 6364136223846793005
_LCG_C = 1442695040888963407


class LCG:
    def __init__(self, seed):
        self.state = seed & U64_MAX

    def next(self):
        self.state = (self.state * _LCG_A + _LCG_C) & U64_MAX
        return self.state


# ---------------------------------------------------------------------------
# Oracles (Python bigints; classification mirrors the documented contract)
# ---------------------------------------------------------------------------

def oracle_align_up(x, a):
    """checkedAlignUp: InvalidAlignment / ArithmeticOverflow / ("ok", value)."""
    if a == 0 or a % 8 != 0:
        return ("InvalidAlignment", None)
    rem = x % a
    value = x if rem == 0 else x + (a - rem)
    if value > U64_MAX:
        return ("ArithmeticOverflow", None)
    return ("ok", value)


def oracle_product(dims):
    """checkedProduct: InvalidDimensionCount / ArithmeticOverflow / ("ok", value)."""
    if len(dims) == 0:
        return ("InvalidDimensionCount", None)
    product = 1
    for d in dims:
        if d == 0:
            return ("ArithmeticOverflow", None)
        product *= d
        if product > U64_MAX:
            return ("ArithmeticOverflow", None)
    return ("ok", product)


def oracle_tensor_bytes(dims, ttype, table):
    """computeTensorBytes with the exact classification order of the Zig code:
    traits lookup -> n_dims bound -> scalar -> row divisibility -> product
    -> block division -> byte count."""
    traits = table.get(ttype)
    if traits is None:
        return ("InvalidTensorType", None)
    if len(dims) > 4:
        return ("InvalidDimensionCount", None)
    if len(dims) == 0:
        if traits["block_size"] != 1:
            return ("BlockDivisibilityViolation", None)
        return ("ok", traits["type_size"])
    if dims[0] % traits["block_size"] != 0:
        return ("BlockDivisibilityViolation", None)
    status, product = oracle_product(dims)
    if status != "ok":
        return (status, None)
    nbytes = (product // traits["block_size"]) * traits["type_size"]
    if nbytes > U64_MAX:
        return ("ArithmeticOverflow", None)
    return ("ok", nbytes)


def parse_type_table():
    """Parse the pinned TypeTraits table out of src/gguf/types.zig (same
    source-parsing approach as tests/test_oracle_types.py)."""
    with open(TYPES_ZIG, "r") as f:
        content = f.read()
    table = {}
    in_traits = False
    for line in content.splitlines():
        if "pub fn getTypeTraits" in line:
            in_traits = True
            continue
        if in_traits:
            stripped = line.strip()
            if stripped.startswith("};"):
                break
            m = re.match(
                r"(\d+)\s*=>\s*TypeTraits\{\s*\.name\s*=\s*\"([^\"]+)\",\s*"
                r"\.block_size\s*=\s*(\d+),\s*\.type_size\s*=\s*(\d+)\s*\},",
                stripped,
            )
            if m:
                table[int(m.group(1))] = {
                    "name": m.group(2),
                    "block_size": int(m.group(3)),
                    "type_size": int(m.group(4)),
                }
    assert len(table) == 35, f"expected 35 pinned active type traits, parsed {len(table)}"
    return table


def pick_dim(lcg):
    """Same value distribution as the u128 sweep in tests/validator_test.zig:
    small / medium / huge / zero buckets."""
    pick = lcg.next() % 4
    if pick == 0:
        return 1 + lcg.next() % 256
    if pick == 1:
        return 256 + lcg.next() % 8192
    if pick == 2:
        return U64_MAX - lcg.next() % 4096
    return 0


# ---------------------------------------------------------------------------
# Phase 1: pure-oracle invariant sweep
# ---------------------------------------------------------------------------

def run_phase1(table):
    # Shared vectors: must match the constants asserted in tests/validator_test.zig.
    shared_vectors = [
        (((64, 10), 2), ("ok", 360)),
        (((256, 2), 8), ("ok", 544)),
        (((4096, 11008), 12), ("ok", 25_362_432)),
        (((U64_MAX - 31,), 8), ("ArithmeticOverflow", None)),
        (((U64_MAX // 2, 5), 0), ("ArithmeticOverflow", None)),
        (((1 << 32, 1 << 33), 0), ("ArithmeticOverflow", None)),
    ]
    for (dims, ttype), expected in shared_vectors:
        got = oracle_tensor_bytes(dims, ttype, table)
        assert got == expected, f"shared vector {dims}/{ttype}: oracle said {got}, expected {expected}"
    print(f"  shared oracle vectors: {len(shared_vectors)} OK (mirrors validator_test.zig)")

    # alignUp sweep: boundary hits + LCG randoms per alignment.
    alignments = [8, 16, 24, 32, 64, 128, 256, 512, 1024, 4096, 8192, 65536, 1 << 20, 1 << 31, 1 << 63]
    lcg = LCG(0x243F6A8885A308D3)
    align_fit = align_overflow = 0
    for a in alignments:
        boundaries = sorted({0, 1, 7, 8, 9, 31, 32, 33, a - 1, a, a + 1,
                             U64_MAX // 2, U64_MAX // 2 + 1,
                             U64_MAX - 4096, U64_MAX - 8, U64_MAX - 7, U64_MAX - 1, U64_MAX})
        samples = boundaries + [lcg.next() for _ in range(2500)]
        for x in samples:
            status, value = oracle_align_up(x, a)
            if status == "ArithmeticOverflow":
                # Overflow iff the exact result exceeds u64: classification is exact.
                exact = x + (a - x % a) if x % a else x
                assert exact > U64_MAX
                align_overflow += 1
            else:
                assert status == "ok" and value >= x
                assert value % a == 0
                assert oracle_align_up(value, a) == ("ok", value)  # idempotent
                align_fit += 1
    for bad_a in [0, 1, 3, 7, 9, 12, (1 << 31) + 1]:
        assert oracle_align_up(16, bad_a) == ("InvalidAlignment", None)
    assert align_fit > 0 and align_overflow > 0
    print(f"  alignUp: {align_fit} fit / {align_overflow} overflow tuples OK")

    # checkedProduct sweep: zero / empty / wrapping classification.
    lcg = LCG(0x9E3779B97F4A7C15)
    prod_ok = prod_zero = prod_overflow = prod_empty = 0
    for _ in range(12288):
        n_dims = lcg.next() % 6  # 0..5
        dims = [pick_dim(lcg) for _ in range(n_dims)]
        status, value = oracle_product(dims)
        if status == "InvalidDimensionCount":
            prod_empty += 1
        elif status == "ArithmeticOverflow":
            if any(d == 0 for d in dims):
                prod_zero += 1
            else:
                # Exact product must really exceed u64 (no silent wrap).
                exact = 1
                for d in dims:
                    exact *= d
                assert exact > U64_MAX
                prod_overflow += 1
        else:
            assert value < 2 ** 64
            exact = 1
            for d in dims:
                exact *= d
            assert value == exact
            prod_ok += 1
    assert prod_ok > 0 and prod_zero > 0 and prod_overflow > 0 and prod_empty > 0
    print(f"  product: {prod_ok} ok / {prod_zero} zero / {prod_overflow} overflow / {prod_empty} empty tuples OK")

    # computeTensorBytes sweep across valid + invalid type ids.
    valid_types = sorted(table.keys())
    invalid_types = [4, 5, 31, 32, 33, 36, 37, 38, 43, 44, U64_MAX % (2 ** 32)]
    lcg = LCG(0xBB67AE8584CAA73B)
    tb_counts = {"ok": 0, "InvalidTensorType": 0, "InvalidDimensionCount": 0,
                 "BlockDivisibilityViolation": 0, "ArithmeticOverflow": 0}
    for _ in range(24576):
        if lcg.next() % 16 == 0:
            ttype = invalid_types[lcg.next() % len(invalid_types)]
        else:
            ttype = valid_types[lcg.next() % len(valid_types)]
        n_dims = lcg.next() % 6  # 0..5 (len 5 -> InvalidDimensionCount)
        dims = [pick_dim(lcg) for _ in range(n_dims)]
        status, value = oracle_tensor_bytes(dims, ttype, table)
        tb_counts[status] += 1
        if status == "ok":
            assert value > 0
    for required in ["ok", "InvalidTensorType", "InvalidDimensionCount",
                     "BlockDivisibilityViolation", "ArithmeticOverflow"]:
        assert tb_counts[required] > 0, f"tensor sweep never produced {required}"
    print(f"  tensorBytes: {sum(tb_counts.values())} tuples OK, classification counts {tb_counts}")

    # llama-cpp contiguous-offset chain: offset' = alignUp(offset + nbytes, alignment).
    lcg = LCG(0xA0761D6478BD642F)
    chain_ok = chain_overflow = chain_div = 0
    for _ in range(4096):
        expected = 0
        aborted = None
        hostile = lcg.next() % 32 == 0  # rare hostile tensor exercises abort paths
        for _t in range(2 + lcg.next() % 4):
            ttype = valid_types[lcg.next() % len(valid_types)]
            if hostile:
                dims = [pick_dim(lcg) for _ in range(1 + lcg.next() % 3)]
            else:
                # Rows are a block multiple, remaining dims small: chain completes.
                block = table[ttype]["block_size"]
                dims = [block * (1 + lcg.next() % 64)]
                dims += [1 + lcg.next() % 64 for _ in range(lcg.next() % 3)]
            status, nbytes = oracle_tensor_bytes(dims, ttype, table)
            if status == "BlockDivisibilityViolation":
                aborted = "div"
                break
            if status != "ok":
                # ArithmeticOverflow (zero dimension or u64 wrap) aborts the chain.
                aborted = "overflow"
                break
            unpadded = expected + nbytes
            if unpadded > U64_MAX:
                aborted = "overflow"
                break
            status, expected = oracle_align_up(unpadded, 32)
            if status != "ok":
                aborted = "overflow"
                break
            assert expected % 32 == 0 and expected >= unpadded
        if aborted is None:
            chain_ok += 1
        elif aborted == "overflow":
            chain_overflow += 1
        else:
            chain_div += 1
    assert chain_ok > 0
    assert chain_overflow > 0 or chain_div > 0
    print(f"  contiguous chain: {chain_ok} ok / {chain_overflow} overflow / {chain_div} divisibility chains OK")


# ---------------------------------------------------------------------------
# Phase 2: implementation cross-check through the CLI
# ---------------------------------------------------------------------------

def run_cli(path, *extra):
    proc = subprocess.run(
        [BINARY, "inspect", path, *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
    )
    return proc.returncode, proc.stdout


def build_gguf(tensors, alignment=32):
    """Deterministic GGUF v3 blob with descriptors and zero padding up to the
    oracle-computed tensor data base. Returns (base, blob)."""
    out = bytearray()
    out += b"GGUF"
    out += struct.pack("<I", 3)                      # version 3
    out += struct.pack("<Q", len(tensors))           # tensor count
    out += struct.pack("<Q", 0)                      # metadata kv count
    for name, dims, ttype, offset in tensors:
        name_bytes = name.encode("ascii")
        out += struct.pack("<Q", len(name_bytes)) + name_bytes
        out += struct.pack("<I", len(dims))
        for d in dims:
            out += struct.pack("<Q", d)
        out += struct.pack("<I", ttype)
        out += struct.pack("<Q", offset)
    status, base = oracle_align_up(len(out), alignment)
    assert status == "ok", f"alignUp({len(out)}, {alignment}) unexpectedly {status}"
    out += b"\x00" * (base - len(out))
    return base, bytes(out)


def write_case(directory, name, data):
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def expect_pass(path, profile):
    rc, stdout = run_cli(path, "--format", "json", "--profile", profile)
    data = json.loads(stdout)
    assert rc == 0 and data["status"] == "PASS", \
        f"expected PASS ({profile}), got rc={rc}: {stdout.strip()}"

def expect_reject(path, profile, expected_error):
    rc, stdout = run_cli(path, "--format", "json", "--profile", profile)
    data = json.loads(stdout)
    assert rc == 2 and data["status"] == "REJECT", \
        f"expected REJECT ({profile}), got rc={rc}: {stdout.strip()}"
    assert data["error"] == expected_error, \
        f"expected {expected_error}, got {data['error']}: {stdout.strip()}"


def run_phase2(table):
    assert os.path.exists(BINARY), (
        f"ReleaseSafe binary missing at {BINARY}: run `zig build -Doptimize=ReleaseSafe` first "
        "(same dependency as tests/cli_test.py)"
    )
    # llama-cpp cross-checks require native (little) endianness, enforced by parser.
    assert sys.byteorder == "little", "llama-cpp CLI cross-checks require a little-endian host"

    single_tensor_cases = [
        ((64, 10), 2),        # Q4_0  -> 360
        ((256, 2), 8),        # Q8_0  -> 544
        ((64, 10), 0),        # F32   -> 2560
        ((1,), 1),            # F16   -> 2
        ((3,), 27),           # I64   -> 24
        ((), 0),              # scalar F32 -> 4
        ((), 24),             # scalar I8  -> 1
        ((32, 5), 39),        # MXFP4 -> 85
        ((64, 64, 4), 40),    # NVFP4 -> 9216
        ((128, 3), 41),       # Q1_0  -> 54
    ]
    # Two-tensor llama-cpp chains: T2.offset = oracle alignUp(nb1, 32).
    chain_cases = [
        (((64, 10), 2), ((1,), 1)),     # nb1=360, off2=384, end=416
        (((96, 7), 8), ((3,), 27)),     # nb1=714, off2=736, end=768
    ]
    overflow_cases = [
        ((1 << 63, 4), 0),              # product 2^65
        ((U64_MAX - 31,), 8),           # (2^59-1) blocks * 34 bytes > u64
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        checked = 0
        for dims, ttype in single_tensor_cases:
            status, nbytes = oracle_tensor_bytes(dims, ttype, table)
            assert status == "ok", f"case {dims}/{ttype} unexpectedly {status}"
            _, blob = build_gguf([("t", dims, ttype, 0)])
            expect_pass(write_case(tmp_dir, "exact.gguf", blob + b"\x00" * nbytes), "gguf-spec")
            expect_reject(write_case(tmp_dir, "trunc.gguf", blob + b"\x00" * (nbytes - 1)),
                          "gguf-spec", "TensorOutOfBounds")
            checked += 2
        print(f"  single-tensor exact-fit / one-byte-short: {checked} CLI cross-checks OK")

        chain_checked = 0
        for (dims1, t1), (dims2, t2) in chain_cases:
            status, nb1 = oracle_tensor_bytes(dims1, t1, table)
            assert status == "ok"
            status, nb2 = oracle_tensor_bytes(dims2, t2, table)
            assert status == "ok"
            _, off2 = oracle_align_up(nb1, 32)
            _, chain_end = oracle_align_up(off2 + nb2, 32)
            _, blob = build_gguf([("t0", dims1, t1, 0), ("t1", dims2, t2, off2)])
            expect_pass(write_case(tmp_dir, "chain.gguf", blob + b"\x00" * chain_end), "llama-cpp")
            expect_reject(write_case(tmp_dir, "chain_trunc.gguf", blob + b"\x00" * (chain_end - 1)),
                          "llama-cpp", "TensorOutOfBounds")
            chain_checked += 2
        print(f"  llama-cpp alignUp chain: {chain_checked} CLI cross-checks OK")

        for dims, ttype in overflow_cases:
            status, _ = oracle_tensor_bytes(dims, ttype, table)
            assert status == "ArithmeticOverflow", f"case {dims}/{ttype} unexpectedly {status}"
            _, blob = build_gguf([("t", dims, ttype, 0)])
            expect_reject(write_case(tmp_dir, "overflow.gguf", blob), "gguf-spec", "ArithmeticOverflow")
        print(f"  overflow classification: {len(overflow_cases)} CLI cross-checks OK")


def main():
    print("Arithmetic bigint oracle (independent, arbitrary precision)...")
    table = parse_type_table()
    print(f"  parsed {len(table)} pinned type traits from src/gguf/types.zig")
    run_phase1(table)
    print("Phase 2: cross-checking the compiled implementation via CLI...")
    run_phase2(table)
    print("Arithmetic oracle: OK")


if __name__ == "__main__":
    main()
