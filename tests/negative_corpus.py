"""
Negative CVE/upstream regression corpus (roadmap issue #9).

Turns PoC-inspired malformed GGUF inputs (parse / int-overflow / dims /
types / alloc / metadata bug classes) into regression fixtures and asserts
that SafeGGUF rejects every one of them (exit 2) with the expected error
code.

Naming convention
-----------------
  cve-YYYY-NNNN[-slug].gguf     Advisory-sourced case (CVE id); the optional
                                slug disambiguates multiple mechanisms from
                                one advisory.
  upstream-issue-NNNN[-slug].gguf  Upstream tracker case; NNNN is the upstream
                                issue/PR number. IDs 0001-0009 are reserved
                                placeholders for bug-class exemplars that do
                                not yet have a specific tracker link; when a
                                concrete PoC is triaged, rename the fixture to
                                the real issue number and update `source` and
                                `affected_commit` in CASES below.

Per-case comment convention (the CASES registry is the committed record;
tests/fixtures/negative/manifest.json is the regenerated snapshot):

  source            Where the case comes from (advisory or tracker reference
                    plus a one-line description of the bug family).
  affected_commit   Upstream commit/version range known to be affected, plus
                    the pinned ggml 0.23.0 commit (e91ded11...) used by this
                    repo as the upstream behavior reference.
  expected_behavior What SafeGGUF must do: exit 2 (REJECT) and the expected
                    error_code surfaced on stderr / JSON.

Fixtures are PoC-inspired class exemplars: the byte layout exercises the same
unchecked-count / unchecked-length family as the advisory, it is not a byte
copy of the original PoC.

Generation is fully deterministic: fixed little-endian bytes, no randomness,
no timestamps, sorted manifest keys. Re-running overwrites the fixture
directory contents (stale *.gguf files not in CASES are pruned).

Run:  python tests/negative_corpus.py            # generate + verify
      python tests/negative_corpus.py --generate-only
      python tests/negative_corpus.py --verify-only
Verification needs the ReleaseSafe binary at zig-out/bin/safegguf
(zig build -Doptimize=ReleaseSafe). Exit 0 = all cases generated and all
rejections hold; exit 1 = generation or verification failed.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SAFEGGUF_BIN = os.path.join(REPO_ROOT, "zig-out", "bin", "safegguf")
NEGATIVE_DIR = os.path.join(SCRIPT_DIR, "fixtures", "negative")

BUG_CLASSES = ("parse", "int-overflow", "dims", "types", "alloc", "metadata")

UPSTREAM_REF = "pinned ggml 0.23.0 e91ded11bdcd78c42f9c8d3978ff6686eb4c1226"


def align_up(val, align):
    rem = val % align
    return val if rem == 0 else val + (align - rem)


def _header(tensor_count, kv_count):
    b = bytearray(b"GGUF")
    b += struct.pack("<I", 3)
    b += struct.pack("<Q", tensor_count)
    b += struct.pack("<Q", kv_count)
    return b


def _kv_string(key, val):
    b = bytearray()
    b += struct.pack("<Q", len(key))
    b += key
    b += struct.pack("<I", 8)  # GGUF_METADATA_VALUE_TYPE_STRING
    b += struct.pack("<Q", len(val))
    b += val
    return b


def _tensor_desc(name, n_dims, dims, tensor_type, offset):
    b = bytearray()
    b += struct.pack("<Q", len(name))
    b += name
    b += struct.pack("<I", n_dims)
    for d in dims:
        b += struct.pack("<Q", d)
    b += struct.pack("<I", tensor_type)
    b += struct.pack("<Q", offset)
    return b


def build_parse_string_past_eof():
    # Metadata string value declares 60000 bytes (under the 65536 string cap
    # so the limit check does not fire first) while only 8 bytes remain in
    # the file: the read would extend past EOF.
    b = _header(0, 1)
    b += struct.pack("<Q", len(b"general.name"))
    b += b"general.name"
    b += struct.pack("<I", 8)  # STRING
    b += struct.pack("<Q", 60000)  # declared length >> remaining bytes
    b += b"\x00" * 8
    return b


def build_parse_truncated_tensor_descriptor():
    # Header declares 2 tensors; only the first descriptor is present and the
    # second one is cut off right after its name.
    b = _header(2, 0)
    b += _tensor_desc(b"t0", 1, [8], 0, 0)
    b += struct.pack("<Q", 2)  # name_len of t1, then EOF mid-descriptor
    b += b"t1"
    return b


def build_int_overflow_dims_product():
    # dims [2^63, 2]: each dim fits u64 but the element-count product wraps
    # u64 exactly (2^64).
    return _header(1, 0) + _tensor_desc(b"ovf_dims", 2, [0x8000000000000000, 2], 0, 0)


def build_int_overflow_nbytes():
    # dims [2^62, 1]: the element count fits u64, but nbytes = 2^62 x 4
    # (F32) wraps u64 exactly.
    return _header(1, 0) + _tensor_desc(b"ovf_bytes", 2, [0x4000000000000000, 1], 0, 0)


def build_dims_ndims_5():
    # n_dims = 5 exceeds the GGUF v3 maximum of 4.
    return _header(1, 0) + _tensor_desc(b"five_dims", 5, [1, 1, 1, 1, 1], 0, 0)


def build_dims_uint32_max():
    # n_dims = UINT32_MAX: dim-count field abuse; the dims array would claim
    # 4 GiB of u64 dimension values from a ~30-byte file.
    return _header(1, 0) + _tensor_desc(b"max_dims", 0xFFFFFFFF, [], 0, 0)


def build_types_invalid_tensor_type_43():
    # Tensor type 43 is the first id beyond the pinned 43-slot GGML table
    # (e91ded11); ids >= 43 must be rejected, never coerced to a layout.
    return _header(1, 0) + _tensor_desc(b"type43", 1, [8], 43, 0)


def build_types_metadata_value_type_99():
    # Metadata value type 99 exceeds the valid GGUF metadata type range
    # (0..12): type-confusion class.
    b = _header(0, 1)
    b += struct.pack("<Q", len(b"general.bad_type"))
    b += b"general.bad_type"
    b += struct.pack("<I", 99)  # invalid value type
    b += b"\x00" * 8
    return b


def build_alloc_kv_count_dos():
    # n_kv = UINT64_MAX: declared count implies ~1.8e19 KV entries (min 13
    # bytes each) from a 24-byte file; must hit the entry-count limit before
    # any allocation is attempted.
    return _header(0, 0xFFFFFFFFFFFFFFFF)


def build_alloc_key_string_len_dos():
    # Key length 0xFFFFFFFF (4 GiB) from a 32-byte file; must hit the 65536
    # string cap before allocation.
    b = _header(0, 1)
    b += struct.pack("<Q", 0xFFFFFFFF)
    b += b"K" * 16
    return b


def build_metadata_invalid_utf8_value():
    # String value 0xFF 0xFE 0xFD 0xFA is not valid UTF-8; strings are
    # attacker-controlled scan targets, not opaque bytes.
    return _header(0, 1) + _kv_string(b"general.name", b"\xff\xfe\xfd\xfa")


def build_metadata_array_count_dos():
    # Fixed-size I32 array declaring 10,000,001 elements (one over the 10M
    # array cap) from a ~40-byte file.
    b = _header(0, 1)
    b += struct.pack("<Q", len(b"general.arr"))
    b += b"general.arr"
    b += struct.pack("<I", 9)  # ARRAY
    b += struct.pack("<I", 4)  # element type INT32
    b += struct.pack("<Q", 10_000_001)
    b += b"\x00" * 8
    return b


CASES = [
    {
        "name": "cve-2024-25664-parse-metadata-string-past-eof.gguf",
        "bug_class": "parse",
        "build": build_parse_string_past_eof,
        "source": (
            "CVE-2024-25664 (ggml-org/llama.cpp, 2024-02 GHSA advisory batch): "
            "heap overflow in GGUF metadata KV parsing. PoC-inspired class "
            "exemplar: metadata string whose declared length extends past EOF."
        ),
        "affected_commit": (
            "llama.cpp prior to the 2024-02-15 advisory patch release "
            "(b2490-era); behavior reference for this repo: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_UnexpectedEof): declared "
            "string length extends past end of file; fail closed instead of "
            "reading out of bounds."
        ),
        "expected_error_code": "E_UnexpectedEof",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0001-parse-truncated-tensor-descriptor.gguf",
        "bug_class": "parse",
        "build": build_parse_truncated_tensor_descriptor,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0001, no specific "
            "tracker link yet): parser trusts the declared tensor count and "
            "reads a descriptor table that is truncated mid-entry."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_UnexpectedEof): tensor "
            "descriptor table extends past end of file."
        ),
        "expected_error_code": "E_UnexpectedEof",
        "cli_args": [],
    },
    {
        "name": "cve-2024-25665-int-overflow-dims-product.gguf",
        "bug_class": "int-overflow",
        "build": build_int_overflow_dims_product,
        "source": (
            "CVE-2024-25665 (ggml-org/llama.cpp, 2024-02 GHSA advisory batch): "
            "attacker-controlled count x size integer overflow. PoC-inspired "
            "class exemplar in the tensor path: dims [2^63, 2] wrap u64."
        ),
        "affected_commit": (
            "llama.cpp prior to the 2024-02-15 advisory patch release "
            "(b2490-era); behavior reference for this repo: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ArithmeticOverflow): "
            "element-count product 2^64 overflows u64 under checked arithmetic."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "cli_args": [],
    },
    {
        "name": "cve-2024-25665-int-overflow-nbytes.gguf",
        "bug_class": "int-overflow",
        "build": build_int_overflow_nbytes,
        "source": (
            "CVE-2024-25665 (ggml-org/llama.cpp, 2024-02 GHSA advisory batch): "
            "attacker-controlled count x size integer overflow. PoC-inspired "
            "class exemplar: elements fit u64 (2^62) but nbytes = 2^62 x 4 "
            "wraps u64."
        ),
        "affected_commit": (
            "llama.cpp prior to the 2024-02-15 advisory patch release "
            "(b2490-era); behavior reference for this repo: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ArithmeticOverflow): "
            "byte-size computation overflows u64 under checked arithmetic."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0002-dims-ndims-5.gguf",
        "bug_class": "dims",
        "build": build_dims_ndims_5,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0002, no specific "
            "tracker link yet): dimension-count field above the GGUF v3 "
            "maximum of 4."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidDimensionCount): "
            "n_dims 5 > 4."
        ),
        "expected_error_code": "E_InvalidDimensionCount",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0003-dims-uint32-max.gguf",
        "bug_class": "dims",
        "build": build_dims_uint32_max,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0003, no specific "
            "tracker link yet): dim-count field set to UINT32_MAX, claiming a "
            "4 GiB dimension array from a ~30-byte file."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidDimensionCount): "
            "n_dims 0xFFFFFFFF > 4."
        ),
        "expected_error_code": "E_InvalidDimensionCount",
        "cli_args": [],
    },
    {
        "name": "cve-2024-25668-types-invalid-tensor-type-43.gguf",
        "bug_class": "types",
        "build": build_types_invalid_tensor_type_43,
        "source": (
            "CVE-2024-25668 (ggml-org/llama.cpp, 2024-02 GHSA advisory batch): "
            "integer overflow in GGUF type handling. PoC-inspired class "
            "exemplar: tensor type id 43, beyond the pinned 43-slot GGML "
            "table, must never be coerced to a layout."
        ),
        "affected_commit": (
            "llama.cpp prior to the 2024-02-15 advisory patch release "
            "(b2490-era); behavior reference for this repo: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidTensorType): "
            "tensor type ids >= 43 are rejected."
        ),
        "expected_error_code": "E_InvalidTensorType",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0004-types-metadata-value-type-99.gguf",
        "bug_class": "types",
        "build": build_types_metadata_value_type_99,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0004, no specific "
            "tracker link yet): metadata value type id outside the valid "
            "GGUF range (0..12), type-confusion class."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidMetadataType): "
            "value type 99 > 12."
        ),
        "expected_error_code": "E_InvalidMetadataType",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0005-alloc-kv-count-dos.gguf",
        "bug_class": "alloc",
        "build": build_alloc_kv_count_dos,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0005, no specific "
            "tracker link yet): allocation-DoS class - header declares "
            "UINT64_MAX metadata entries; parsers that allocate per declared "
            "count before validating exhaust memory."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ResourceLimitExceeded): "
            "n_kv exceeds the 1,000,000-entry limit before any allocation."
        ),
        "expected_error_code": "E_ResourceLimitExceeded",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0006-alloc-key-string-len-dos.gguf",
        "bug_class": "alloc",
        "build": build_alloc_key_string_len_dos,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0006, no specific "
            "tracker link yet): allocation-DoS class - key length 0xFFFFFFFF "
            "(4 GiB) declared from a 32-byte file."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ResourceLimitExceeded): "
            "key length exceeds the 65536-byte string cap."
        ),
        "expected_error_code": "E_ResourceLimitExceeded",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0007-metadata-invalid-utf8-value.gguf",
        "bug_class": "metadata",
        "build": build_metadata_invalid_utf8_value,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0007, no specific "
            "tracker link yet): metadata class - string value 0xFF 0xFE 0xFD "
            "0xFA is not valid UTF-8."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidUtf8): string "
            "values must be valid UTF-8."
        ),
        "expected_error_code": "E_InvalidUtf8",
        "cli_args": [],
    },
    {
        "name": "upstream-issue-0008-metadata-array-count-dos.gguf",
        "bug_class": "metadata",
        "build": build_metadata_array_count_dos,
        "source": (
            "Bug-class exemplar (placeholder upstream-issue-0008, no specific "
            "tracker link yet): metadata class - fixed-size I32 array "
            "declares 10,000,001 elements, one over the 10M array cap."
        ),
        "affected_commit": (
            "n/a - class exemplar; behavior reference: " + UPSTREAM_REF
        ),
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ResourceLimitExceeded): "
            "array element count exceeds the 10,000,000 limit."
        ),
        "expected_error_code": "E_ResourceLimitExceeded",
        "cli_args": [],
    },
]


def generate():
    """Deterministically write all fixtures and the manifest; prune stale files."""
    os.makedirs(NEGATIVE_DIR, exist_ok=True)

    manifest_cases = []
    for case in CASES:
        payload = case["build"]()
        path = os.path.join(NEGATIVE_DIR, case["name"])
        with open(path, "wb") as f:
            f.write(payload)
        manifest_cases.append(
            {
                "file": case["name"],
                "bug_class": case["bug_class"],
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "source": case["source"],
                "affected_commit": case["affected_commit"],
                "expected_behavior": case["expected_behavior"],
                "expected_error_code": case["expected_error_code"],
                "cli_args": ["inspect", case["name"]] + case["cli_args"],
            }
        )

    # Prune stale *.gguf files that are no longer part of CASES so the
    # directory always matches the manifest.
    keep = {case["name"] for case in CASES}
    for entry in sorted(os.listdir(NEGATIVE_DIR)):
        if entry.endswith(".gguf") and entry not in keep:
            os.remove(os.path.join(NEGATIVE_DIR, entry))

    manifest = {
        "description": (
            "Negative CVE/upstream regression corpus (roadmap issue #9); "
            "regenerated by tests/negative_corpus.py - do not hand-edit."
        ),
        "naming_convention": (
            "cve-YYYY-NNNN[-slug].gguf for advisory-sourced cases; "
            "upstream-issue-NNNN[-slug].gguf for tracker cases; ids "
            "0001-0009 are reserved class-exemplar placeholders pending a "
            "specific upstream reference."
        ),
        "cases": manifest_cases,
    }
    manifest_path = os.path.join(NEGATIVE_DIR, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    return manifest_path


def run_cli(*args):
    cmd = [SAFEGGUF_BIN] + list(args)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    return proc.returncode, proc.stdout, proc.stderr


def verify():
    """Assert every corpus fixture is rejected with exit 2 and the expected error_code."""
    failures = []
    for case in CASES:
        path = os.path.join(NEGATIVE_DIR, case["name"])
        if not os.path.exists(path):
            failures.append(f"{case['name']}: fixture missing (run generation first)")
            continue
        args = ["inspect", path] + case["cli_args"]
        try:
            rc, stdout, stderr = run_cli(*args)
        except subprocess.TimeoutExpired:
            failures.append(f"{case['name']}: CLI timed out")
            continue
        if rc != 2:
            failures.append(
                f"{case['name']}: expected exit 2 (REJECT), got {rc}\n"
                f"  stdout: {stdout.strip()}\n  stderr: {stderr.strip()}"
            )
            continue
        if case["expected_error_code"] not in stderr:
            failures.append(
                f"{case['name']}: expected error_code {case['expected_error_code']} "
                f"in stderr, got: {stderr.strip()}"
            )
            continue
        print(f"  REJECT ok [{case['bug_class']}] {case['name']} -> {case['expected_error_code']}")
    return failures


def main():
    parser = argparse.ArgumentParser(description="Negative CVE/upstream regression corpus (issue #9)")
    parser.add_argument("--generate-only", action="store_true", help="generate fixtures + manifest, skip verification")
    parser.add_argument("--verify-only", action="store_true", help="verify existing fixtures without regenerating")
    args = parser.parse_args()

    if not args.verify_only:
        manifest_path = generate()
        print(f"Generated {len(CASES)} negative fixtures + manifest at {manifest_path}")

    if args.generate_only:
        return 0

    if not os.path.exists(SAFEGGUF_BIN):
        print(f"Error: binary {SAFEGGUF_BIN} does not exist. Run: zig build -Doptimize=ReleaseSafe")
        return 1

    print(f"Verifying {len(CASES)} negative fixtures against {SAFEGGUF_BIN} (expect exit 2 / REJECT)...")
    failures = verify()
    if failures:
        print(f"\nFAILED: {len(failures)} of {len(CASES)} cases:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    classes_covered = sorted({case["bug_class"] for case in CASES})
    missing_classes = [c for c in BUG_CLASSES if c not in classes_covered]
    if missing_classes:
        print(f"\nFAILED: bug classes without a sample: {missing_classes}", file=sys.stderr)
        return 1

    print(f"\nAll {len(CASES)} negative cases rejected (exit 2); bug classes covered: {classes_covered}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
