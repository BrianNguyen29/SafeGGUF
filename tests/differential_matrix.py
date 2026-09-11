"""
Systematic generated differential matrix (roadmap issue #7).

Replaces hand-written fixture authoring for boundary coverage by generating a
deterministic matrix of fixtures covering:

  1. All 35 active GGML types (pinned ggml 0.23.0 table, mirrors
     src/gguf/types.zig getTypeTraits) x 6 shape variants:
       min_row, multi_block, block_minus_1, block_plus_1,
       trunc_exact, trunc_padded
     e.g. Q4_0: 31 reject / 32 pass / 33 reject / 64 pass.
  2. n_dims 0..5 + UINT32_MAX boundaries, and dimension-value boundaries
     (1, INT64_MAX-1, INT64_MAX, INT64_MAX+1, UINT64_MAX).
  3. Alignment values 0/1/7/8/16/24/32/40/64, max power-of-two u32 (2^31),
     and a wrong-typed general.alignment key.
  4. Metadata scalar/empty key/empty string/1-element array/max array count/
     oversize key/truncated value/bad enum type/nested arrays.

Expected verdicts are derived from the pinned upstream ggml 0.23.0 gguf.cpp
(verified against the compiled oracle and the source in .cache/ggml-upstream):

  - ne[0] must be a multiple of ggml_blck_size (descriptor-phase check, both
    load and no-load modes reject).
  - A zero-element tensor (ne[0] == 0 with block_size 1) is accepted by
    upstream as a zero-byte tensor; SafeGGUF rejects explicit zero dims
    (documented divergence).
  - general.alignment must be a power of two and non-zero (upstream accepts
    alignment 1; SafeGGUF additionally requires a multiple of 8).
  - load-data reads exactly the PADDED data blob (sum of GGML_PAD(nbytes,
    alignment)), so any file ending before the padded end rejects; no-load
    never reads the blob and only parses header/keys/descriptors.
  - Keys and strings are capped at GGUF_MAX_STRING_LENGTH (1 GiB) upstream;
    SafeGGUF caps at 65536 bytes (documented divergence).

Output: tests/fixtures/matrix/*.gguf (gitignored). Generation is fully
deterministic: fixed little-endian bytes, no randomness, no timestamps,
sorted iteration order. Re-running overwrites the directory contents.

Run:  python tests/differential_matrix.py
The generated entries are wired into tests/differential.py EXPECTED_MATRIX via
generated_expected_entries(); keys carry the "matrix/" prefix and rationales
are prefixed "[GENERATED]" to mark them as generated entries.
"""

import os
import struct

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MATRIX_DIR = os.path.join(SCRIPT_DIR, "fixtures", "matrix")
MATRIX_PREFIX = "matrix/"  # EXPECTED_MATRIX key prefix marking generated entries

PADDING_BYTE = 0xAA  # deterministic payload fill
DEFAULT_ALIGNMENT = 32

# Pinned active GGML type table: (type_id, name, block_size, type_size).
# Mirror of src/gguf/types.zig getTypeTraits (35 active slots); kept in sync
# with the pinned upstream oracle by tests/test_oracle_types.py.
ACTIVE_TYPES = [
    (0, "F32", 1, 4),
    (1, "F16", 1, 2),
    (2, "Q4_0", 32, 18),
    (3, "Q4_1", 32, 20),
    (6, "Q5_0", 32, 22),
    (7, "Q5_1", 32, 24),
    (8, "Q8_0", 32, 34),
    (9, "Q8_1", 32, 36),
    (10, "Q2_K", 256, 84),
    (11, "Q3_K", 256, 110),
    (12, "Q4_K", 256, 144),
    (13, "Q5_K", 256, 176),
    (14, "Q6_K", 256, 210),
    (15, "Q8_K", 256, 292),
    (16, "IQ2_XXS", 256, 66),
    (17, "IQ2_XS", 256, 74),
    (18, "IQ3_XXS", 256, 98),
    (19, "IQ1_S", 256, 50),
    (20, "IQ4_NL", 32, 18),
    (21, "IQ3_S", 256, 110),
    (22, "IQ2_S", 256, 82),
    (23, "IQ4_XS", 256, 136),
    (24, "I8", 1, 1),
    (25, "I16", 1, 2),
    (26, "I32", 1, 4),
    (27, "I64", 1, 8),
    (28, "F64", 1, 8),
    (29, "IQ1_M", 256, 56),
    (30, "BF16", 1, 2),
    (34, "TQ1_0", 256, 54),
    (35, "TQ2_0", 256, 66),
    (39, "MXFP4", 32, 17),
    (40, "NVFP4", 64, 36),
    (41, "Q1_0", 128, 18),
    (42, "Q2_0", 64, 18),
]

assert len(ACTIVE_TYPES) == 35, "expected the 35 active pinned GGML types"

# Guard: truncated-exact fixtures cut at data_base + nbytes; this is a true
# truncation (missing padding) only while no type_size is a multiple of the
# 32-byte default alignment. If a future pinned-table update violates this,
# the generator must re-derive the trunc_exact expectations.
for _t in ACTIVE_TYPES:
    assert _t[3] % DEFAULT_ALIGNMENT != 0, (
        f"type {_t[1]} type_size {_t[3]} is a multiple of {DEFAULT_ALIGNMENT}; "
        "trunc_exact would equal the full padded file"
    )

INT64_MAX = (1 << 63) - 1
UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
MAX_ARRAY_ELEMENTS = 10_000_000  # SafeGGUF limits.max_array_elements boundary
OVERSIZE_STRING = 70_000  # > SafeGGUF max_string_bytes (65536), < upstream 1 GiB cap


def align_up(val, align):
    rem = val % align
    return val if rem == 0 else val + (align - rem)


def type_bytes(n_elements, type_id):
    """Byte length of a tensor with n_elements elements of the given type."""
    for tid, _, block_size, type_size in ACTIVE_TYPES:
        if tid == type_id:
            assert n_elements % block_size == 0
            return n_elements // block_size * type_size
    raise AssertionError(f"unknown type id {type_id}")


def build_gguf(tensor_name, dims, type_id, alignment=DEFAULT_ALIGNMENT, kvs=(), payload_len=None,
               n_dims_override=None):
    """Serialize a deterministic little-endian GGUF v3 file.

    Exactly one tensor (named ``tensor_name``) unless ``tensor_name is None``
    (zero-tensor file). ``kvs`` is a list of (key, metadata_type, raw_value)
    already encoded by the kv helpers below. ``payload_len`` bytes of fill are
    appended after the aligned data base, then padded up to the aligned end.
    ``n_dims_override`` writes a raw n_dims field value without materializing
    the dimensions (for oversized n_dims fields that both binaries reject
    before reading any dim values). Returns (file_bytes, data_base).
    """
    b = bytearray()
    b += b"GGUF"
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", 1 if tensor_name is not None else 0)
    b += struct.pack("<Q", len(kvs))
    for key, mtype, raw in kvs:
        kb = key.encode("utf-8")
        b += struct.pack("<Q", len(kb))
        b += kb
        b += struct.pack("<I", mtype)
        b += raw

    if tensor_name is not None:
        tb = tensor_name.encode("utf-8")
        b += struct.pack("<Q", len(tb))
        b += tb
        b += struct.pack("<I", n_dims_override if n_dims_override is not None else len(dims))
        for d in dims:
            b += struct.pack("<Q", d)
        b += struct.pack("<I", type_id)
        b += struct.pack("<Q", 0)  # single tensor at offset 0

    # alignment=0 is serialized with align-1 semantics: both binaries reject the
    # zero alignment during kv parsing, before any data placement matters.
    data_base = align_up(len(b), alignment if alignment else 1)
    b += b"\x00" * (data_base - len(b))
    if payload_len:
        b += bytes([PADDING_BYTE]) * payload_len
        b += b"\x00" * (align_up(payload_len, alignment if alignment else 1) - payload_len)
    return bytes(b), data_base


def kv_uint32(key, value):
    return (key, 4, struct.pack("<I", value))


def kv_string(key, value):
    vb = value.encode("utf-8")
    return (key, 8, struct.pack("<Q", len(vb)) + vb)


# ---------------------------------------------------------------------------
# Case families. Each returns a list of (fixture_name, file_bytes, expected)
# where expected = (safe_llama_cpp, upstream_load, upstream_noload, rationale).
# Verdicts P=PASS / R=REJECT below.
# ---------------------------------------------------------------------------

TYPE_VARIANTS = ("min_row", "multi_block", "block_minus_1", "block_plus_1", "trunc_exact", "trunc_padded")


def type_cases():
    cases = []
    for tid, name, block, tsize in ACTIVE_TYPES:
        for variant in TYPE_VARIANTS:
            cases.append(type_case(tid, name, block, tsize, variant))
    return cases


def type_case(tid, tname, block, tsize, variant):
    safe = load = noload = "PASS"
    if variant == "min_row":
        n = block
        data, _ = build_gguf("w", [n], tid, payload_len=tsize)
        rationale = (
            f"[GENERATED] {tname} minimum valid row (ne[0]={block} == block_size {block}, "
            f"{tsize} bytes): SafeGGUF llama-cpp and upstream agree in all three modes."
        )
    elif variant == "multi_block":
        n = 2 * block
        data, _ = build_gguf("w", [n], tid, payload_len=2 * tsize)
        rationale = (
            f"[GENERATED] {tname} multi-block row (ne[0]={2 * block}, {2 * tsize} bytes): "
            "SafeGGUF llama-cpp and upstream agree in all three modes."
        )
    elif variant == "block_minus_1":
        n = block - 1
        if block == 1:
            # n == 0: zero-element tensor.
            data, _ = build_gguf("w", [0], tid, payload_len=0)
            safe, load, noload = "REJECT", "PASS", "PASS"
            rationale = (
                f"[GENERATED] {tname} ne[0]=0 (block_size 1): SafeGGUF rejects explicit "
                "zero-element dimensions (E_ZeroDimensionNotAllowed); upstream models a "
                "zero-element tensor as zero bytes (nbytes=0) and accepts (documented divergence)."
            )
        else:
            data, _ = build_gguf("w", [n], tid, payload_len=0)
            safe = load = noload = "REJECT"
            rationale = (
                f"[GENERATED] {tname} ne[0]={n} not a multiple of block_size {block}: "
                "descriptor-phase check rejects in both binaries and both modes "
                "(E_BlockDivisibilityViolation vs upstream 'not a multiple of block size')."
            )
    elif variant == "block_plus_1":
        n = block + 1
        if block == 1:
            data, _ = build_gguf("w", [n], tid, payload_len=type_bytes(n, tid))
            rationale = (
                f"[GENERATED] {tname} ne[0]={n} with block_size 1: valid row above the "
                "block boundary for both binaries in all three modes."
            )
        else:
            data, _ = build_gguf("w", [n], tid, payload_len=0)
            safe = load = noload = "REJECT"
            rationale = (
                f"[GENERATED] {tname} ne[0]={n} not a multiple of block_size {block}: "
                "descriptor-phase check rejects in both binaries and both modes "
                "(E_BlockDivisibilityViolation vs upstream 'not a multiple of block size')."
            )
    elif variant == "trunc_exact":
        n = block
        full, data_base = build_gguf("w", [n], tid, payload_len=tsize)
        data = full[: data_base + tsize]
        safe, load, noload = "REJECT", "REJECT", "PASS"
        rationale = (
            f"[GENERATED] {tname} min row truncated at the unpadded end ({tsize} bytes, "
            "missing only alignment padding): SafeGGUF requires the aligned contiguous "
            "end (E_TensorOutOfBounds); upstream load-data reads the full padded blob and "
            "fails; no-load never reads the blob (HIGH-01 pattern)."
        )
    elif variant == "trunc_padded":
        n = block
        full, data_base = build_gguf("w", [n], tid, payload_len=tsize)
        padded_end = data_base + align_up(tsize, DEFAULT_ALIGNMENT)
        data = full[: padded_end - 1]
        safe, load, noload = "REJECT", "REJECT", "PASS"
        rationale = (
            f"[GENERATED] {tname} min row truncated one byte before the required padded "
            "end: same rejection pattern as trunc_exact (SafeGGUF E_TensorOutOfBounds, "
            "upstream load short read, no-load does not read the blob)."
        )
    else:
        raise AssertionError(variant)

    return (f"type_{tname.lower()}_{variant}.gguf", data, (safe, load, noload, rationale))


def ndims_cases():
    """n_dims 0..5 + UINT32_MAX with an F32 tensor (ne = [8]*n_dims)."""
    cases = []
    for n_dims in (0, 1, 2, 3, 4, 5, UINT32_MAX):
        name = f"ndims_{n_dims}.gguf" if n_dims <= 5 else "ndims_u32max.gguf"
        if n_dims <= 5:
            dims = [8] * n_dims
            payload = type_bytes(8 ** n_dims, 0) if n_dims else 4
            data, _ = build_gguf("w", dims, 0, payload_len=payload)
        else:
            # n_dims=UINT32_MAX field with no dim values following: both
            # binaries reject the oversized count before reading dims.
            data, _ = build_gguf("w", [], 0, n_dims_override=UINT32_MAX, payload_len=0)
        if n_dims <= 4:
            expected = ("PASS", "PASS", "PASS",
                        "[GENERATED] n_dims=%d is within GGML_MAX_DIMS=4 for both binaries; "
                        "canonical F32 tensor passes all three modes." % n_dims)
        else:
            expected = ("REJECT", "REJECT", "REJECT",
                        "[GENERATED] n_dims=%s > GGML_MAX_DIMS=4: descriptor-phase check "
                        "rejects in both binaries and both modes (E_InvalidDimensionCount)."
                        % ("UINT32_MAX" if n_dims == UINT32_MAX else n_dims))
        cases.append((name, data, expected))
    return cases


def dim_value_cases():
    """Single-dim F32 dimension-value boundaries (n_dims=1)."""
    values = [
        ("dim_1", 1,
         ("PASS", "PASS", "PASS",
          "[GENERATED] ne[0]=1 F32: minimal non-zero dimension passes all three modes.")),
        ("dim_max_minus_1", INT64_MAX - 1,
         ("REJECT", "REJECT", "REJECT",
          "[GENERATED] ne[0]=INT64_MAX-1 F32: element count passes the representable guard "
          "but the byte size (x4) overflows in both binaries (E_ArithmeticOverflow vs "
          "upstream 'size in bytes > SIZE_MAX'); descriptor-phase, both modes.")),
        ("dim_int64_max", INT64_MAX,
         ("REJECT", "REJECT", "REJECT",
          "[GENERATED] ne[0]=INT64_MAX F32: upstream rejects elements >= INT64_MAX; "
          "SafeGGUF overflows the byte-size computation (E_ArithmeticOverflow). Both modes.")),
        ("dim_max_plus_1", INT64_MAX + 1,
         ("REJECT", "REJECT", "REJECT",
          "[GENERATED] ne[0]=INT64_MAX+1: read as a negative int64 upstream and rejected "
          "(E_CompatibilityViolation in SafeGGUF). Both modes.")),
        ("dim_uint64_max", UINT64_MAX,
         ("REJECT", "REJECT", "REJECT",
          "[GENERATED] ne[0]=UINT64_MAX: read as -1 upstream and rejected "
          "(E_CompatibilityViolation in SafeGGUF). Both modes.")),
    ]
    cases = []
    for name, value, expected in values:
        representable = value <= 4096  # only materialize payloads for tiny tensors
        data, _ = build_gguf("w", [value], 0, payload_len=type_bytes(value, 0) if representable else 0)
        cases.append((name + ".gguf", data, expected))
    return cases


def alignment_cases():
    """general.alignment boundaries with an F32 tensor (ne=8, 32 bytes)."""
    cases = []
    for value in (0, 1, 7, 8, 16, 24, 32, 40, 64):
        name = f"align_{value}.gguf"
        data, _ = build_gguf("w", [8], 0, alignment=value, kvs=[kv_uint32("general.alignment", value)],
                             payload_len=32)
        if value in (8, 16, 32, 64):
            expected = ("PASS", "PASS", "PASS",
                        f"[GENERATED] alignment={value} is a valid power-of-two multiple of 8 "
                        "for both binaries in all three modes.")
        elif value in (7, 24, 40):
            expected = ("REJECT", "REJECT", "REJECT",
                        f"[GENERATED] alignment={value} is not a power of two: upstream "
                        "rejects (mode-independent) and SafeGGUF llama-cpp requires a "
                        "power-of-two multiple of 8 (E_InvalidAlignment/E_CompatibilityViolation).")
        elif value == 1:
            expected = ("REJECT", "PASS", "PASS",
                        "[GENERATED] alignment=1 is a power of two, so upstream accepts it, "
                        "but it is not a multiple of 8: SafeGGUF rejects (E_InvalidAlignment) "
                        "(documented divergence; the GGUF spec floor is 8).")
        else:  # value == 0
            expected = ("REJECT", "REJECT", "REJECT",
                        "[GENERATED] alignment=0: SafeGGUF rejects (E_InvalidAlignment) and "
                        "upstream requires a non-zero power of two. Both modes.")
        cases.append((name, data, expected))

    # Maximum representable power-of-two u32 alignment with zero tensors
    # (a tensor at 2^31 alignment would require a 2 GiB file).
    data, _ = build_gguf(None, [], 0, kvs=[kv_uint32("general.alignment", 1 << 31)])
    cases.append(("align_pow2_max_u32.gguf", data, ("PASS", "PASS", "PASS",
                  "[GENERATED] alignment=2^31 (max power-of-two u32) with zero tensors: "
                  "alignment accepted by both binaries; zero-tensor file has no data "
                  "section in all three modes.")))

    # general.alignment declared with the wrong metadata type.
    data, _ = build_gguf(None, [], 0, kvs=[("general.alignment", 5, struct.pack("<i", 32))])
    cases.append(("align_wrong_type.gguf", data, ("REJECT", "REJECT", "REJECT",
                  "[GENERATED] general.alignment declared as int32 instead of uint32: "
                  "SafeGGUF (E_InvalidAlignment) and upstream both reject (mode-independent).")))
    return cases


def metadata_cases():
    cases = []

    # Complete, valid metadata variants around a canonical F32 tensor.
    data, _ = build_gguf("w", [8], 0, kvs=[kv_uint32("test.u32_val", 7)], payload_len=32)
    cases.append(("meta_scalar_u32.gguf", data, ("PASS", "PASS", "PASS",
                  "[GENERATED] single uint32 metadata entry: canonical scalar kv passes "
                  "all three modes.")))

    data, _ = build_gguf("w", [8], 0, kvs=[kv_string("test.empty_string", "")], payload_len=32)
    cases.append(("meta_empty_string_value.gguf", data, ("PASS", "PASS", "PASS",
                  "[GENERATED] zero-length string value: accepted by both binaries "
                  "(key grammar is unaffected) in all three modes.")))

    data, _ = build_gguf(
        "w", [8], 0,
        kvs=[("test.int32_arr", 9, struct.pack("<I", 5) + struct.pack("<Q", 1) + struct.pack("<i", 42))],
        payload_len=32,
    )
    cases.append(("meta_1elem_array.gguf", data, ("PASS", "PASS", "PASS",
                  "[GENERATED] 1-element int32 array metadata: accepted by both binaries "
                  "in all three modes.")))

    # Metadata edge cases that reject before any tensor parsing; the files end
    # after the kv header (tensor_count=0) since the value can never be read.

    # Empty key.
    data, _ = build_gguf(None, [], 0, kvs=[("", 4, struct.pack("<I", 7))])
    cases.append(("meta_empty_key.gguf", data, ("REJECT", "REJECT", "REJECT",
                  "[GENERATED] zero-length metadata key: SafeGGUF rejects "
                  "(E_InvalidStringLength) and upstream rejects empty keys (mode-independent).")))

    # Array count at the SafeGGUF max_array_elements boundary (10M int32 = 40 MiB
    # declared but absent -> EOF failure in both binaries).
    data, _ = build_gguf(None, [], 0,
                         kvs=[("test.big_arr", 9, struct.pack("<I", 5) + struct.pack("<Q", MAX_ARRAY_ELEMENTS))])
    cases.append(("meta_huge_count.gguf", data, ("REJECT", "REJECT", "REJECT",
                  "[GENERATED] array count=10M (SafeGGUF max_array_elements) with no array "
                  "body: SafeGGUF fails EOF (E_UnexpectedEof); upstream requires 40 MiB of "
                  "remaining file for the array (mode-independent).")))

    # Key length above the SafeGGUF 64 KiB string cap but far below the
    # upstream 1 GiB GGUF_MAX_STRING_LENGTH cap -> documented divergence.
    key = "a" * OVERSIZE_STRING
    data, _ = build_gguf(None, [], 0, kvs=[kv_uint32(key, 7)])
    cases.append(("meta_oversize_key.gguf", data, ("REJECT", "PASS", "PASS",
                  "[GENERATED] 70000-byte lower_snake_case key: upstream caps strings at "
                  "1 GiB and accepts; SafeGGUF caps keys/strings at 65536 bytes "
                  "(E_ResourceLimitExceeded) (documented divergence).")))

    # String value declaring more bytes than the file holds.
    data, _ = build_gguf(None, [], 0, kvs=[("test.str_val", 8, struct.pack("<Q", 100) + b"0123456789")])
    cases.append(("meta_truncated_value.gguf", data, ("REJECT", "REJECT", "REJECT",
                  "[GENERATED] string value declaring 100 bytes but the file ends: "
                  "SafeGGUF (E_UnexpectedEof) and upstream both reject (mode-independent).")))

    # Metadata type enum out of range (13 and UINT32_MAX).
    for raw, name in ((13, "meta_bad_enum.gguf"), (UINT32_MAX, "meta_bad_enum_u32max.gguf")):
        data, _ = build_gguf(None, [], 0, kvs=[("test.bad_type", raw, b"")])
        cases.append((name, data, ("REJECT", "REJECT", "REJECT",
                      "[GENERATED] metadata type raw=%s is outside the 13-value enum: "
                      "SafeGGUF (E_InvalidMetadataType) and upstream both reject "
                      "(mode-independent)." % ("UINT32_MAX" if raw == UINT32_MAX else raw))))

    # Nested arrays (array element type = array).
    nested = struct.pack("<I", 9) + struct.pack("<Q", 1) + struct.pack("<I", 5) + struct.pack("<Q", 1) + struct.pack("<i", 42)
    data, _ = build_gguf(None, [], 0, kvs=[("test.nested_arr", 9, nested)])
    cases.append(("meta_nested.gguf", data, ("REJECT", "REJECT", "REJECT",
                  "[GENERATED] array-of-arrays metadata: SafeGGUF llama-cpp rejects "
                  "(E_NestedArrayNotSupported) and upstream treats an ARRAY element type "
                  "as invalid (mode-independent).")))
    return cases


def matrix_cases():
    """Deterministic, name-sorted list of (name, bytes, expected) matrix cases."""
    cases = type_cases() + ndims_cases() + dim_value_cases() + alignment_cases() + metadata_cases()
    return sorted(cases, key=lambda c: c[0])


def generated_expected_entries():
    """EXPECTED_MATRIX fragment for the generated matrix, keyed "matrix/<name>"."""
    return {
        MATRIX_PREFIX + name: expected
        for name, _data, expected in matrix_cases()
    }


def write_all():
    if not os.path.isdir(MATRIX_DIR):
        os.makedirs(MATRIX_DIR)
    # Regenerate from scratch so the directory exactly matches the current spec.
    for stale in sorted(os.listdir(MATRIX_DIR)):
        if stale.endswith(".gguf"):
            os.remove(os.path.join(MATRIX_DIR, stale))

    cases = matrix_cases()
    for name, data, _expected in cases:
        with open(os.path.join(MATRIX_DIR, name), "wb") as f:
            f.write(data)

    families = {
        "type": sum(1 for n, _, _ in cases if n.startswith("type_")),
        "ndims": sum(1 for n, _, _ in cases if n.startswith("ndims_")),
        "dim": sum(1 for n, _, _ in cases if n.startswith("dim_")),
        "align": sum(1 for n, _, _ in cases if n.startswith("align_")),
        "meta": sum(1 for n, _, _ in cases if n.startswith("meta_")),
    }
    types_covered = set()
    for n, _, _ in cases:
        if n.startswith("type_"):
            for variant in TYPE_VARIANTS:
                suffix = f"_{variant}.gguf"
                if n.endswith(suffix):
                    types_covered.add(n[len("type_"):-len(suffix)])
                    break
            else:
                raise AssertionError(f"unparseable type fixture name: {n}")
    assert len(types_covered) == 35, f"type coverage broken: {len(types_covered)}"
    print(f"Generated {len(cases)} deterministic matrix fixtures in {MATRIX_DIR}")
    print(f"  families: {families}; active types covered: {len(types_covered)}/35")


if __name__ == "__main__":
    write_all()
