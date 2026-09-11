"""
Negative corpus: synthetic bug-class exemplars + advisory placeholder registry
(roadmap issue #9; provenance split per deep-review F-02).

Two provenance categories - never mix them:

1. Synthetic bug-class exemplars (generated + verified fixtures)
   Name:  synthetic-<bug-class>-<slug>.gguf
   Hand-built malformed inputs that exercise a specific bug class (parse /
   int-overflow / dims / types / alloc / metadata). They are NOT
   reproductions of any specific CVE/advisory and must not carry an advisory
   identity; `source` states the mechanism only.

2. True advisory regressions (placeholders until triaged)
   Name:  cve-YYYY-NNNN[-slug].gguf  (reserved)
   A fixture may use a cve-* name only once it has a verifiable primary
   source: `source_url` plus affected/patched version-or-commit recorded in
   the CASES entry. Until then the advisory lives in ADVISORY_PLACEHOLDERS as
   a manifest-only entry (fixture: null, provenance fields TRIAGE-PENDING) and
   is neither generated nor verified. Never invent tracker URLs or commit
   SHAs; promote a placeholder to a real cve-* fixture only after triage.

Per-case comment convention (the CASES registry is the committed record;
tests/fixtures/negative/manifest.json is the regenerated snapshot):

  fixture_type       synthetic-class-exemplar | advisory-regression.
  source             Mechanism description for synthetic cases; primary
                     advisory reference for triaged advisory cases.
  source_url         Verifiable primary source URL; None for synthetic cases
                     (no advisory exists), TRIAGE-PENDING for placeholders.
  affected_commit    Upstream version/commit range known to be affected, or
                     None/TRIAGE-PENDING when no advisory provenance exists.
  patched_commit     Upstream version/commit containing the fix, or
                     None/TRIAGE-PENDING when no advisory provenance exists.
  expected_behavior  What SafeGGUF must do: exit 2 (REJECT) and the expected
                     error_code surfaced on stderr / JSON.

All cases and fixtures are behavior-referenced against the pinned upstream in
UPSTREAM_REF (ggml 0.23.0 e91ded11...) and the manifest records that pin
top-level as `upstream_behavior_reference`.

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


def build_int_overflow_flagship_nbytes():
    # Flagship checked byte-size overflow shape (mechanism-level exemplar for
    # the CVE-2026-33298 advisory placeholder; not an advisory reproduction):
    # F32 [1024, 1024, 2^42 + 1, 1]. The element product 2^62 + 2^20 fits u64,
    # but the byte multiplication (x4 = 2^64 + 2^22) wraps u64. Kept as a
    # synthetic-* exemplar until the placeholder's provenance is triaged.
    return _header(1, 0) + _tensor_desc(
        b"ovf_flagship", 4, [1024, 1024, 0x400000000001, 1], 0, 0
    )


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
        "name": "synthetic-parse-metadata-string-past-eof.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "parse",
        "build": build_parse_string_past_eof,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): metadata "
            "string value declares 60000 bytes while only 8 bytes remain in "
            "the file; exercises the string-length / EOF-boundary class."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_UnexpectedEof): declared "
            "string length extends past end of file; fail closed instead of "
            "reading out of bounds."
        ),
        "expected_error_code": "E_UnexpectedEof",
        "cli_args": [],
    },
    {
        "name": "synthetic-parse-truncated-tensor-descriptor.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "parse",
        "build": build_parse_truncated_tensor_descriptor,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): parser "
            "trusts the declared tensor count and reads a descriptor table "
            "that is truncated mid-entry."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_UnexpectedEof): tensor "
            "descriptor table extends past end of file."
        ),
        "expected_error_code": "E_UnexpectedEof",
        "cli_args": [],
    },
    {
        "name": "synthetic-int-overflow-dims-product.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "int-overflow",
        "build": build_int_overflow_dims_product,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): "
            "element-count product overflow in the tensor path; dims "
            "[2^63, 2] wrap u64."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ArithmeticOverflow): "
            "element-count product 2^64 overflows u64 under checked arithmetic."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "cli_args": [],
    },
    {
        "name": "synthetic-int-overflow-nbytes.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "int-overflow",
        "build": build_int_overflow_nbytes,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): "
            "byte-size multiplication overflow; elements fit u64 (2^62) but "
            "nbytes = 2^62 x 4 wraps u64."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ArithmeticOverflow): "
            "byte-size computation overflows u64 under checked arithmetic."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "cli_args": [],
    },
    {
        "name": "synthetic-int-overflow-flagship-nbytes.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "int-overflow",
        "build": build_int_overflow_flagship_nbytes,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): flagship "
            "checked byte-size overflow shape - F32 [1024, 1024, 2^42 + 1, 1]; "
            "the element product 2^62 + 2^20 fits u64, but nbytes x 4 wraps "
            "u64 (2^64 + 2^22)."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ArithmeticOverflow): "
            "checked byte-size computation overflows u64 before allocation."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "cli_args": [],
    },
    {
        "name": "synthetic-dims-ndims-5.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "dims",
        "build": build_dims_ndims_5,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): "
            "dimension-count field above the GGUF v3 maximum of 4."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidDimensionCount): "
            "n_dims 5 > 4."
        ),
        "expected_error_code": "E_InvalidDimensionCount",
        "cli_args": [],
    },
    {
        "name": "synthetic-dims-uint32-max.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "dims",
        "build": build_dims_uint32_max,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): "
            "dim-count field set to UINT32_MAX, claiming a 4 GiB dimension "
            "array from a ~30-byte file."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidDimensionCount): "
            "n_dims 0xFFFFFFFF > 4."
        ),
        "expected_error_code": "E_InvalidDimensionCount",
        "cli_args": [],
    },
    {
        "name": "synthetic-types-invalid-tensor-type-43.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "types",
        "build": build_types_invalid_tensor_type_43,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): tensor "
            "type id 43, beyond the pinned 43-slot GGML table, must never be "
            "coerced to a layout."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidTensorType): "
            "tensor type ids >= 43 are rejected."
        ),
        "expected_error_code": "E_InvalidTensorType",
        "cli_args": [],
    },
    {
        "name": "synthetic-types-metadata-value-type-99.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "types",
        "build": build_types_metadata_value_type_99,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): "
            "metadata value type id outside the valid GGUF range (0..12), "
            "type-confusion class."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidMetadataType): "
            "value type 99 > 12."
        ),
        "expected_error_code": "E_InvalidMetadataType",
        "cli_args": [],
    },
    {
        "name": "synthetic-alloc-kv-count-dos.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "alloc",
        "build": build_alloc_kv_count_dos,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): "
            "allocation-DoS class - header declares UINT64_MAX metadata "
            "entries; parsers that allocate per declared count before "
            "validating exhaust memory."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ResourceLimitExceeded): "
            "n_kv exceeds the 1,000,000-entry limit before any allocation."
        ),
        "expected_error_code": "E_ResourceLimitExceeded",
        "cli_args": [],
    },
    {
        "name": "synthetic-alloc-key-string-len-dos.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "alloc",
        "build": build_alloc_key_string_len_dos,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): "
            "allocation-DoS class - key length 0xFFFFFFFF (4 GiB) declared "
            "from a 32-byte file."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ResourceLimitExceeded): "
            "key length exceeds the 65536-byte string cap."
        ),
        "expected_error_code": "E_ResourceLimitExceeded",
        "cli_args": [],
    },
    {
        "name": "synthetic-metadata-invalid-utf8-value.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "metadata",
        "build": build_metadata_invalid_utf8_value,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): metadata "
            "class - string value 0xFF 0xFE 0xFD 0xFA is not valid UTF-8."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_InvalidUtf8): string "
            "values must be valid UTF-8."
        ),
        "expected_error_code": "E_InvalidUtf8",
        "cli_args": [],
    },
    {
        "name": "synthetic-metadata-array-count-dos.gguf",
        "fixture_type": "synthetic-class-exemplar",
        "bug_class": "metadata",
        "build": build_metadata_array_count_dos,
        "source": (
            "Synthetic bug-class exemplar (no advisory provenance): metadata "
            "class - fixed-size I32 array declares 10,000,001 elements, one "
            "over the 10M array cap."
        ),
        "source_url": None,
        "affected_commit": None,
        "patched_commit": None,
        "expected_behavior": (
            "SafeGGUF rejects (exit 2, error_code E_ResourceLimitExceeded): "
            "array element count exceeds the 10,000,000 limit."
        ),
        "expected_error_code": "E_ResourceLimitExceeded",
        "cli_args": [],
    },
]

# Advisory placeholders: manifest-only entries for CVEs whose primary-source
# provenance has not been triaged yet. Each entry carries a mechanism and the
# expected SafeGGUF protection path, but no fixture file and no verified
# assertion; all provenance fields stay "TRIAGE-PENDING" (never invent tracker
# URLs, advisory links or commit SHAs). Promote an entry into CASES - and only
# then generate a cve-<id>-<mechanism>.gguf fixture - once source_url and the
# affected/patched references are recorded from a verifiable primary source.
ADVISORY_PLACEHOLDERS = [
    {
        "id": "CVE-2025-53630",
        "fixture_type": "advisory-regression",
        "triage_status": "TRIAGE-PENDING",
        "fixture": None,
        "source_url": "TRIAGE-PENDING",
        "source_title": "TRIAGE-PENDING",
        "affected_commit": "TRIAGE-PENDING",
        "patched_commit": "TRIAGE-PENDING",
        "sha256": None,
        "mechanism": (
            "Cumulative tensor data size overflow in GGUF parsing: tensor "
            "byte sizes accumulate past u64 before the data region is "
            "admitted."
        ),
        "expected_protection": (
            "compute tensor bytes -> checkedAlignUp -> checked cumulative "
            "offset/size -> REJECT on overflow (E_ArithmeticOverflow)."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "promotion_note": (
            "Promote to a cve-2025-53630-<mechanism>.gguf fixture only after "
            "triaging source_url and affected/patched references from a "
            "verifiable primary source; then move the entry into CASES."
        ),
    },
    {
        "id": "CVE-2026-27940",
        "fixture_type": "advisory-regression",
        "triage_status": "TRIAGE-PENDING",
        "fixture": None,
        "source_url": "TRIAGE-PENDING",
        "source_title": "TRIAGE-PENDING",
        "affected_commit": "TRIAGE-PENDING",
        "patched_commit": "TRIAGE-PENDING",
        "sha256": None,
        "mechanism": (
            "Bypass of the CVE-2025-53630 fix via final context memory size "
            "arithmetic; SafeGGUF does not allocate the same downstream ggml "
            "context, so no byte-for-byte reproduction exists."
        ),
        "expected_protection": (
            "Admission rejects impossible cumulative tensor sizing before any "
            "allocation; the regression must state the equivalent admission "
            "property it proves."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "promotion_note": (
            "Promote to a cve-2026-27940-<mechanism>.gguf fixture only after "
            "triaging source_url and affected/patched references from a "
            "verifiable primary source; then move the entry into CASES."
        ),
    },
    {
        "id": "CVE-2026-33298",
        "fixture_type": "advisory-regression",
        "triage_status": "TRIAGE-PENDING",
        "fixture": None,
        "source_url": "TRIAGE-PENDING",
        "source_title": "TRIAGE-PENDING",
        "affected_commit": "TRIAGE-PENDING",
        "patched_commit": "TRIAGE-PENDING",
        "sha256": None,
        "flagship": True,
        "mechanism": (
            "ggml_nbytes() dimension/stride arithmetic overflow drastically "
            "underestimates tensor bytes; advisory example tensor is F32 "
            "with shape [1024, 1024, 2^42 + 1, 1]."
        ),
        "expected_protection": (
            "Checked element-count / block / byte-size arithmetic rejects "
            "the shape (E_ArithmeticOverflow) before allocation; flagship "
            "regression should assert this checked byte-size path."
        ),
        "expected_error_code": "E_ArithmeticOverflow",
        "promotion_note": (
            "Promote to a cve-2026-33298-<mechanism>.gguf fixture only after "
            "triaging source_url and affected/patched references from a "
            "verifiable primary source; then move the entry into CASES."
        ),
    },
]


# Fields a promoted cve-* case must populate before generation, covering the
# advisory provenance schema available today: fixture category, primary
# source_url, affected/patched references and the fixture sha256. Synthetic
# cases legitimately carry null provenance (no advisory exists) and
# ADVISORY_PLACEHOLDERS stay manifest-only with TRIAGE-PENDING fields; only
# cve-* entries in CASES are held to triaged values for every field here.
REQUIRED_CVE_FIELDS = (
    "fixture_type",
    "source_url",
    "affected_commit",
    "patched_commit",
    "sha256",
)


def _require_triaged_provenance():
    """A cve-* fixture may only exist once its advisory provenance is triaged.

    Enforces the corpus invariant mechanically: synthetic fixtures must not
    borrow an advisory identity, and a cve-* case must carry every
    REQUIRED_CVE_FIELDS entry with a triaged value (never missing, empty,
    null or TRIAGE-PENDING).
    """
    for case in CASES:
        if not case["name"].startswith("cve-"):
            continue
        missing = [
            field
            for field in REQUIRED_CVE_FIELDS
            if not case.get(field) or case.get(field) == "TRIAGE-PENDING"
        ]
        if missing:
            raise SystemExit(
                f"provenance error: {case['name']} claims a CVE identity "
                f"without triaged {', '.join(missing)}"
            )


def generate():
    """Deterministically write all fixtures and the manifest; prune stale files."""
    _require_triaged_provenance()
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
                "fixture_type": case["fixture_type"],
                "bug_class": case["bug_class"],
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "source": case["source"],
                "source_url": case["source_url"],
                "affected_commit": case["affected_commit"],
                "patched_commit": case["patched_commit"],
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
            "Negative corpus (roadmap issue #9): synthetic bug-class exemplars "
            "+ advisory regression placeholders; regenerated by "
            "tests/negative_corpus.py - do not hand-edit."
        ),
        "naming_convention": (
            "synthetic-<bug-class>-<slug>.gguf for synthetic class exemplars "
            "(no advisory identity); cve-YYYY-NNNN[-slug].gguf is reserved for "
            "triaged advisory regressions with a verifiable primary source in "
            "source_url."
        ),
        "provenance_rules": (
            "'cases' entries are generated and verified fixtures. "
            "'advisory_placeholders' are manifest-only stubs (fixture null) "
            "and must not be promoted to a cve-* fixture until source_url and "
            "affected/patched references are triaged from a verifiable primary "
            "source. null = no advisory provenance; TRIAGE-PENDING = "
            "explicitly unresolved."
        ),
        "upstream_behavior_reference": UPSTREAM_REF,
        "cases": manifest_cases,
        "advisory_placeholders": ADVISORY_PLACEHOLDERS,
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
    parser = argparse.ArgumentParser(
        description="Negative corpus: synthetic bug-class exemplars + advisory placeholders (issue #9)"
    )
    parser.add_argument("--generate-only", action="store_true", help="generate fixtures + manifest, skip verification")
    parser.add_argument("--verify-only", action="store_true", help="verify existing fixtures without regenerating")
    args = parser.parse_args()

    if not args.verify_only:
        manifest_path = generate()
        print(
            f"Generated {len(CASES)} synthetic fixtures + "
            f"{len(ADVISORY_PLACEHOLDERS)} advisory placeholders (manifest-only, "
            f"unverified) at {manifest_path}"
        )

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
    print(
        "Advisory placeholders still TRIAGE-PENDING (manifest-only, not fixtures, "
        "not verified): " + ", ".join(p["id"] for p in ADVISORY_PLACEHOLDERS)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
