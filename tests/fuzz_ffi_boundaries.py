#!/usr/bin/env python3
"""
FFI Boundary & Robustness Fuzzing Test Suite for SafeGGUF C-ABI (v1) and Python Bindings.

Fuzzes and stress-tests:
1. Entry point NULL pointer dereferences and misaligned/truncated options structs.
2. Corrupted struct_size, out-of-range profile & endian enum discriminants.
3. Random and boundary resource limits (0, 1, UINT64_MAX).
4. Arbitrary and oversized paths (NULL, empty, 64KB, binary non-UTF8, unreadable).
5. Closed, negative, and invalid raw OS file handles.
6. Diagnostic result buffer boundaries (NULL result vs non-NULL struct).
7. High-concurrency multi-threaded stress across FFI boundaries.
8. Non-regular target matrix (dir/FIFO/socket/char/block) on path and fd entries.
9. Appended v1.1 options controls: max_file_size_bytes admission boundaries and
   require_stable_file opt-in, including struct_size gating for legacy callers.
"""

import os
import sys
import ctypes
import random
import socket
import stat
import string
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "bindings" / "python"))

import safegguf
from safegguf.core import (
    _find_library,
    SafeggufOptionsV1,
    SafeggufOptionsV1Legacy,
    SafeggufResult,
    Status,
)

DLL_PATH = _find_library()
print(f"[*] Testing SafeGGUF FFI boundaries via: {DLL_PATH}")
lib = ctypes.CDLL(DLL_PATH)

# Function signatures
lib.safegguf_version.restype = ctypes.c_char_p

lib.safegguf_validate_path_v1.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(SafeggufOptionsV1),
    ctypes.POINTER(SafeggufResult),
]
lib.safegguf_validate_path_v1.restype = ctypes.c_int

lib.safegguf_validate_fd_v1.argtypes = [
    ctypes.c_ssize_t,
    ctypes.POINTER(SafeggufOptionsV1),
    ctypes.POINTER(SafeggufResult),
]
lib.safegguf_validate_fd_v1.restype = ctypes.c_int

# Legacy (pre-v1) entry points: same regular-file target policy.
lib.safegguf_validate_path.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
lib.safegguf_validate_path.restype = ctypes.c_int

lib.safegguf_validate_fd.argtypes = [ctypes.c_ssize_t, ctypes.c_int, ctypes.c_int]
lib.safegguf_validate_fd.restype = ctypes.c_int

VALID_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "valid.gguf"
CVE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"

assert VALID_FIXTURE.exists(), f"Missing {VALID_FIXTURE}"
assert CVE_FIXTURE.exists(), f"Missing {CVE_FIXTURE}"

passed_checks = 0
failed_checks = 0

def record(name: str, cond: bool, msg: str = ""):
    global passed_checks, failed_checks
    if cond:
        passed_checks += 1
    else:
        failed_checks += 1
        print(f"[FAIL] {name}: {msg}")

def fuzz_options_struct_sizes():
    print("\n--- Fuzzing 1: Invalid struct_size in safegguf_options_v1_t ---")
    correct_size = ctypes.sizeof(SafeggufOptionsV1)
    invalid_sizes = [
        0, 1, 2, 4, 8, 16,
        correct_size - 1,
        correct_size + 1,
        correct_size + 4,
        1024,
        0x7FFFFFFF,
        0xFFFFFFFF,
    ]

    for sz in invalid_sizes:
        opts = SafeggufOptionsV1()
        opts.struct_size = sz
        opts.profile = 0
        opts.endian = 0
        res = SafeggufResult()

        rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
        err_code = res.error_code.decode("utf-8", errors="replace")
        record(
            f"struct_size={sz}",
            rc == Status.USAGE_ERROR and ("E_USAGE_INVALID_OPTIONS" in err_code or "InvalidOptionSize" in err_code),
            f"expected 64 + InvalidOptionSize, got rc={rc} error={err_code}",
        )

def fuzz_options_enums():
    print("\n--- Fuzzing 2: Out-of-Range Profile & Endian Enums ---")
    correct_size = ctypes.sizeof(SafeggufOptionsV1)

    bad_profiles = [-999999, -2, -1, 2, 3, 100, 0x7FFFFFFF]
    for bp in bad_profiles:
        opts = SafeggufOptionsV1(
            struct_size=correct_size,
            profile=bp,
            endian=0,
            max_alloc_bytes=0,
            max_work_units=0,
            max_scanned_bytes=0,
            reserved=None,
        )
        res = SafeggufResult()
        rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
        err_code = res.error_code.decode("utf-8", errors="replace")
        record(
            f"profile={bp}",
            rc == Status.USAGE_ERROR and ("E_USAGE_INVALID_PROFILE" in err_code or "InvalidProfile" in err_code),
            f"expected 64 + InvalidProfile, got rc={rc} error={err_code}",
        )

    bad_endians = [-999999, -2, -1, 3, 4, 100, 0x7FFFFFFF]
    for be in bad_endians:
        opts = SafeggufOptionsV1(
            struct_size=correct_size,
            profile=0,
            endian=be,
            max_alloc_bytes=0,
            max_work_units=0,
            max_scanned_bytes=0,
            reserved=None,
        )
        res = SafeggufResult()
        rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
        err_code = res.error_code.decode("utf-8", errors="replace")
        record(
            f"endian={be}",
            rc == Status.USAGE_ERROR and ("E_USAGE_INVALID_ENDIAN" in err_code or "InvalidEndian" in err_code),
            f"expected 64 + InvalidEndian, got rc={rc} error={err_code}",
        )

    # Test non-NULL reserved pointer must fail closed with exit 64:
    dummy_ptr = ctypes.c_void_p(0xDEADBEEF)
    opts = SafeggufOptionsV1(
        struct_size=correct_size,
        profile=0,
        endian=0,
        max_alloc_bytes=0,
        max_work_units=0,
        max_scanned_bytes=0,
        reserved=dummy_ptr,
    )
    res = SafeggufResult()
    rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
    err_code = res.error_code.decode("utf-8", errors="replace")
    record(
        "reserved!=NULL",
        rc == Status.USAGE_ERROR and "E_USAGE_INVALID_OPTIONS" in err_code,
        f"expected 64 + E_USAGE_INVALID_OPTIONS, got rc={rc} error={err_code}",
    )

    # Early options validation with non-existent path must return 64, not 74:
    rc = lib.safegguf_validate_path_v1(b"C:\\__non_existent_file__.gguf", ctypes.byref(opts), ctypes.byref(res))
    err_code = res.error_code.decode("utf-8", errors="replace")
    record(
        "reserved!=NULL with non-existent file returns 64 (pre-validation)",
        rc == Status.USAGE_ERROR and "E_USAGE_INVALID_OPTIONS" in err_code,
        f"expected 64 + E_USAGE_INVALID_OPTIONS, got rc={rc} error={err_code}",
    )

def fuzz_path_boundaries():
    print("\n--- Fuzzing 3: Path Boundaries & Malformed Strings ---")
    res = SafeggufResult()

    # 1. NULL path
    rc = lib.safegguf_validate_path_v1(None, None, ctypes.byref(res))
    record("path=NULL", rc == Status.USAGE_ERROR, f"expected 64, got {rc}")

    # 2. Empty string
    rc = lib.safegguf_validate_path_v1(b"", None, ctypes.byref(res))
    record("path=empty", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    # 3. Non-existent path
    rc = lib.safegguf_validate_path_v1(b"/non_existent/model.gguf", None, ctypes.byref(res))
    record("path=non_existent", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    # 4. Long paths up to 16384 bytes
    for length in [1024, 4096, 8192, 16384]:
        long_path = b"A" * length + b".gguf"
        rc = lib.safegguf_validate_path_v1(long_path, None, ctypes.byref(res))
        record(f"path=length_{length}", rc in (Status.IO_ERROR, Status.USAGE_ERROR), f"got {rc}")

    # 5. Non-UTF8 random binary path
    for _ in range(20):
        rand_bytes = bytes(random.getrandbits(8) for _ in range(64)) + b"\x00"
        rc = lib.safegguf_validate_path_v1(rand_bytes, None, ctypes.byref(res))
        record("path=random_bytes", rc in (Status.IO_ERROR, Status.USAGE_ERROR), f"got {rc}")

def fuzz_fd_handles():
    print("\n--- Fuzzing 4: Raw File Descriptor / OS Handle Boundaries ---")
    res = SafeggufResult()

    # Handles that must fail gracefully with IO_ERROR (74)
    adversarial_handles = [
        0, -1, -2, -100, -999999, -2**31, -2**63 + 1,
        1, 2, 42, 100, 99999, 2147483647, 2**63 - 1
    ]

    # fds 0/1/2 are the process stdio descriptors: they are open by
    # definition, and their kind follows how the harness redirected stdio. A
    # regular-file redirect (e.g. `> log.txt`) makes them regular files, which
    # are legitimate non-GGUF validation targets and reject with 2 (or with 74
    # when the redirect is write-only and the read fails); non-regular kinds
    # (tty, pipe, /dev/null) and closed handles must reject with 74. Windows
    # entry points take OS handles, not C fd numbers, so raw 0/1/2 never
    # resolve there and always report 74.
    stdio_regular = set()
    if os.name != "nt":
        for h in (0, 1, 2):
            try:
                if stat.S_ISREG(os.fstat(h).st_mode):
                    stdio_regular.add(h)
            except OSError:
                pass

    for h in adversarial_handles:
        rc = lib.safegguf_validate_fd_v1(h, None, ctypes.byref(res))
        allowed = (Status.REJECT, Status.IO_ERROR) if h in stdio_regular else (Status.IO_ERROR,)
        record(
            f"fd={h}",
            rc in allowed,
            f"expected {'/'.join(str(int(code)) for code in allowed)}, got {rc}",
        )

    # A closed but in-range descriptor is the macOS abort regression: poll()
    # does not reliably report POLLNVAL for it, so it used to reach
    # std.posix.fstat's EBADF `unreachable` and abort the host process. It must
    # report IO_ERROR (74) like any other invalid handle on both fd entries.
    if os.name != "nt":
        stale_fd = os.open(str(VALID_FIXTURE), os.O_RDONLY)
        os.close(stale_fd)
        rc = lib.safegguf_validate_fd_v1(stale_fd, None, ctypes.byref(res))
        record("fd=closed_in_range", rc == Status.IO_ERROR, f"expected 74, got {rc}")
        rc = lib.safegguf_validate_fd(stale_fd, 0, 0)
        record("fd_legacy=closed_in_range", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    # Valid file descriptor seek preservation fuzzing
    with open(VALID_FIXTURE, "rb") as f:
        if sys.platform == "win32":
            import msvcrt
            raw_h = msvcrt.get_osfhandle(f.fileno())
        else:
            raw_h = f.fileno()

        for offset in [0, 1, 16, 42, 100]:
            f.seek(offset)
            rc = lib.safegguf_validate_fd_v1(raw_h, None, ctypes.byref(res))
            current = f.tell()
            record(
                f"fd_seek_preserve_offset_{offset}",
                rc == Status.PASS and current == offset,
                f"rc={rc}, tell={current} (expected {offset})"
            )

def fuzz_null_and_buffer_diagnostics():
    print("\n--- Fuzzing 5: NULL Pointer Tolerances & Result Buffer Safety ---")
    # 1. NULL options + NULL result on valid model
    rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), None, None)
    record("path_v1(valid, NULL, NULL)", rc == Status.PASS, f"got {rc}")

    # 2. NULL options + NULL result on exploit model
    rc = lib.safegguf_validate_path_v1(str(CVE_FIXTURE).encode("utf-8"), None, None)
    record("path_v1(exploit, NULL, NULL)", rc == Status.REJECT, f"got {rc}")

    # 3. NULL result with valid options on valid model
    opts = SafeggufOptionsV1(
        struct_size=ctypes.sizeof(SafeggufOptionsV1),
        profile=0,
        endian=0,
        max_alloc_bytes=0,
        max_work_units=0,
        max_scanned_bytes=0,
        reserved=None,
    )
    rc = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), ctypes.byref(opts), None)
    record("path_v1(valid, opts, NULL)", rc == Status.PASS, f"got {rc}")

    # 4. Strict string null-termination check in SafeggufResult
    res = SafeggufResult()
    rc = lib.safegguf_validate_path_v1(str(CVE_FIXTURE).encode("utf-8"), ctypes.byref(opts), ctypes.byref(res))
    err_code = res.error_code.decode("utf-8", errors="replace")
    cat = res.category.decode("utf-8", errors="replace")
    stg = res.stage.decode("utf-8", errors="replace")
    msg = res.message.decode("utf-8", errors="replace")
    record(
        "result_buffer_diagnostics_populated",
        rc == Status.REJECT and len(err_code) > 0 and len(cat) > 0 and len(msg) > 0,
        f"err={err_code}, cat={cat}, stage={stg}, msg={msg}"
    )


class SafeggufOptionsV11(ctypes.Structure):
    """Local mirror of the current C-ABI options layout (v1.0 prefix plus the
    appended v1.1 input controls). The shipped Python binding intentionally
    stays on the v1.0 layout, so the FFI boundary suite defines the extended
    layout here to exercise struct_size gating without changing binding
    behavior."""

    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("profile", ctypes.c_int32),
        ("endian", ctypes.c_int32),
        ("max_alloc_bytes", ctypes.c_uint64),
        ("max_work_units", ctypes.c_uint64),
        ("max_scanned_bytes", ctypes.c_uint64),
        ("reserved", ctypes.c_void_p),
        ("max_file_size_bytes", ctypes.c_uint64),
        ("require_stable_file", ctypes.c_uint32),
    ]


def _extended_options(**overrides) -> SafeggufOptionsV11:
    fields = dict(
        struct_size=ctypes.sizeof(SafeggufOptionsV11),
        profile=0,
        endian=0,
        max_alloc_bytes=0,
        max_work_units=0,
        max_scanned_bytes=0,
        reserved=None,
        max_file_size_bytes=0,
        require_stable_file=0,
    )
    fields.update(overrides)
    return SafeggufOptionsV11(**fields)


def _as_options_v1(opts):
    """ctype-pun a locally defined options layout to the v1 pointer type the
    library entry points declare; the memory layout is the contract, not the
    ctypes class identity."""
    return ctypes.cast(ctypes.byref(opts), ctypes.POINTER(SafeggufOptionsV1))


def _raw_fd(fileobj):
    if sys.platform == "win32":
        import msvcrt
        return msvcrt.get_osfhandle(fileobj.fileno())
    return fileobj.fileno()


def fuzz_appended_options_controls():
    print("\n--- Fuzzing 8: Appended v1.1 options controls (max_file_size_bytes / require_stable_file) ---")
    path = str(VALID_FIXTURE).encode("utf-8")
    file_size = VALID_FIXTURE.stat().st_size
    assert file_size > 1

    record(
        "extended_layout_is_64_bytes",
        ctypes.sizeof(SafeggufOptionsV11) == 64,
        f"expected 64, got {ctypes.sizeof(SafeggufOptionsV11)}",
    )

    # --- struct_size gating: a legacy v1.0 caller stays on legacy defaults ---
    # The buffer is larger than the v1.0 prefix but is filled with 0xFF past it:
    # if the library read the appended fields despite struct_size, the garbage
    # require_stable_file would be rejected as a usage error (or the garbage
    # size limit would reject the file). Correct gating must ignore them.
    legacy_buf = ctypes.create_string_buffer(ctypes.sizeof(SafeggufOptionsV11))
    ctypes.memset(legacy_buf, 0xFF, ctypes.sizeof(SafeggufOptionsV11))
    legacy_view = ctypes.cast(legacy_buf, ctypes.POINTER(SafeggufOptionsV1)).contents
    legacy_view.struct_size = ctypes.sizeof(SafeggufOptionsV1Legacy)
    legacy_view.profile = 0
    legacy_view.endian = 0
    legacy_view.max_alloc_bytes = 0
    legacy_view.max_work_units = 0
    legacy_view.max_scanned_bytes = 0
    legacy_view.reserved = None
    res = SafeggufResult()
    rc = lib.safegguf_validate_path_v1(path, ctypes.cast(legacy_buf, ctypes.POINTER(SafeggufOptionsV1)), ctypes.byref(res))
    err = res.error_code.decode("utf-8", errors="replace")
    record(
        "legacy_struct_size_ignores_appended_bytes",
        rc == Status.PASS,
        f"expected PASS (0) on legacy defaults, got rc={rc} error={err}",
    )

    # --- max_file_size_bytes admission boundaries (path entry point) ---
    # Inclusive ceiling: size == limit PASSes, size == limit + 1 rejects with
    # the documented resource code. 0 is the default (unlimited), max uint is
    # effectively unlimited too.
    boundary_cases = [
        (0, Status.PASS, None),               # 0 = default (unlimited)
        (1, Status.REJECT, "E_FileTooLarge"),
        (file_size - 1, Status.REJECT, "E_FileTooLarge"),
        (file_size, Status.PASS, None),       # inclusive: limit == size admits
        (file_size + 1, Status.PASS, None),
        (2**64 - 1, Status.PASS, None),
    ]
    for limit, expected_rc, expected_err in boundary_cases:
        opts = _extended_options(max_file_size_bytes=limit)
        res = SafeggufResult()
        rc = lib.safegguf_validate_path_v1(path, _as_options_v1(opts), ctypes.byref(res))
        err = res.error_code.decode("utf-8", errors="replace")
        cat = res.category.decode("utf-8", errors="replace")
        if expected_rc == Status.REJECT:
            record(
                f"path_v1 max_file_size_bytes={limit}",
                rc == Status.REJECT and err == expected_err and cat == "resource",
                f"expected 2 + {expected_err}/resource, got rc={rc} error={err} category={cat}",
            )
        else:
            record(
                f"path_v1 max_file_size_bytes={limit}",
                rc == expected_rc,
                f"expected {expected_rc}, got rc={rc} error={err}",
            )

    # --- the same admission ceiling is honored on the descriptor entry point ---
    with open(VALID_FIXTURE, "rb") as f:
        raw_h = _raw_fd(f)
        for limit, expected_rc, expected_err in [
            (file_size - 1, Status.REJECT, "E_FileTooLarge"),
            (file_size, Status.PASS, None),
        ]:
            opts = _extended_options(max_file_size_bytes=limit)
            res = SafeggufResult()
            rc = lib.safegguf_validate_fd_v1(raw_h, _as_options_v1(opts), ctypes.byref(res))
            err = res.error_code.decode("utf-8", errors="replace")
            if expected_rc == Status.REJECT:
                record(
                    f"fd_v1 max_file_size_bytes={limit}",
                    rc == Status.REJECT and err == expected_err,
                    f"expected 2 + {expected_err}, got rc={rc} error={err}",
                )
            else:
                record(
                    f"fd_v1 max_file_size_bytes={limit}",
                    rc == Status.PASS,
                    f"expected 0, got rc={rc} error={err}",
                )

    # --- require_stable_file: 1 = on, 0 = off, anything else fails closed ---
    # The unmodified fixture cannot fail the identity re-check, so detection of
    # an actual mutation is covered deterministically by the core tests
    # (tests/validator_test.zig: FileIdentity + mid-read mutation); the FFI
    # boundary here proves the control is plumbed and validated.
    for flag, expected_rc, expected_err in [
        (0, Status.PASS, None),
        (1, Status.PASS, None),
        (2, Status.USAGE_ERROR, "E_USAGE_INVALID_OPTIONS"),
        (0xFFFFFFFF, Status.USAGE_ERROR, "E_USAGE_INVALID_OPTIONS"),
    ]:
        opts = _extended_options(require_stable_file=flag)
        res = SafeggufResult()
        rc = lib.safegguf_validate_path_v1(path, _as_options_v1(opts), ctypes.byref(res))
        err = res.error_code.decode("utf-8", errors="replace")
        if expected_err:
            record(
                f"path_v1 require_stable_file={flag}",
                rc == Status.USAGE_ERROR and err == expected_err,
                f"expected 64 + {expected_err}, got rc={rc} error={err}",
            )
        else:
            record(
                f"path_v1 require_stable_file={flag}",
                rc == Status.PASS,
                f"expected 0, got rc={rc} error={err}",
            )

    # Descriptor entry point honors the opt-in too (and keeps its fd position).
    with open(VALID_FIXTURE, "rb") as f:
        raw_h = _raw_fd(f)
        f.seek(16)
        opts = _extended_options(require_stable_file=1)
        res = SafeggufResult()
        rc = lib.safegguf_validate_fd_v1(raw_h, _as_options_v1(opts), ctypes.byref(res))
        err = res.error_code.decode("utf-8", errors="replace")
        record(
            "fd_v1 require_stable_file=1 passes and preserves seek",
            rc == Status.PASS and f.tell() == 16,
            f"expected 0 + tell=16, got rc={rc} error={err} tell={f.tell()}",
        )

    # A rejection verdict never runs the stability re-check, so it must not
    # change the rejection code for an oversized/malformed input.
    opts = _extended_options(max_file_size_bytes=1, require_stable_file=1)
    res = SafeggufResult()
    rc = lib.safegguf_validate_path_v1(path, _as_options_v1(opts), ctypes.byref(res))
    err = res.error_code.decode("utf-8", errors="replace")
    record(
        "admission_reject_wins_over_stability_check",
        rc == Status.REJECT and err == "E_FileTooLarge",
        f"expected 2 + E_FileTooLarge, got rc={rc} error={err}",
    )


def fuzz_multithreaded_concurrency():
    print("\n--- Fuzzing 6: Multi-Threaded FFI Boundary Stress ---")
    threads = []
    thread_errors = []

    def worker(tid: int):
        try:
            for i in range(50):
                # Valid path
                res1 = SafeggufResult()
                rc1 = lib.safegguf_validate_path_v1(str(VALID_FIXTURE).encode("utf-8"), None, ctypes.byref(res1))
                if rc1 != Status.PASS:
                    thread_errors.append(f"T{tid} valid model failed: {rc1}")

                # Exploit path
                res2 = SafeggufResult()
                rc2 = lib.safegguf_validate_path_v1(str(CVE_FIXTURE).encode("utf-8"), None, ctypes.byref(res2))
                if rc2 != Status.REJECT:
                    thread_errors.append(f"T{tid} exploit model failed: {rc2}")

                # Invalid handle
                rc3 = lib.safegguf_validate_fd_v1(-1, None, None)
                if rc3 != Status.IO_ERROR:
                    thread_errors.append(f"T{tid} handle -1 failed: {rc3}")
        except Exception as e:
            thread_errors.append(f"T{tid} exception: {e}")

    for t in range(8):
        th = threading.Thread(target=worker, args=(t,))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    record(
        "multithreaded_stress_zero_errors",
        len(thread_errors) == 0,
        f"Encountered {len(thread_errors)} concurrency errors: {thread_errors[:3]}"
    )

def fuzz_non_regular_targets():
    print("\n--- Fuzzing 7: Non-Regular Target Matrix (dir / FIFO / socket / char / block) ---")
    if os.name == "nt":
        print("[skip] POSIX target kinds (FIFO/socket/char/block devices) are not exercised on Windows")
        return

    def deadline_call(fn, timeout=5.0):
        """Run fn() on a daemon thread; returns (finished, rc). A blocking open
        (policy regression) surfaces as finished=None instead of hanging."""
        box = {}

        def target():
            try:
                box["rc"] = fn()
            except BaseException as exc:  # pragma: no cover - defensive
                box["exc"] = exc

        th = threading.Thread(target=target, daemon=True)
        th.start()
        th.join(timeout)
        if th.is_alive():
            return None, None
        if "exc" in box:
            raise box["exc"]
        return True, box["rc"]

    def check_path(name, target, expect_pass=False):
        # v1 entry point must reject the non-regular target immediately with the
        # CLI's stat-failure mapping: 74 + E_FILE_STAT_FAILED + "Not a regular
        # file" when the open succeeded, or E_FILE_OPEN_FAILED when the OS
        # refuses the open (e.g. socket nodes). MUST NOT block on open.
        res = SafeggufResult()
        finished, rc = deadline_call(
            lambda: lib.safegguf_validate_path_v1(os.fsencode(target), None, ctypes.byref(res))
        )
        if finished is None:
            record(f"path_v1({name})_immediate", False, "blocked longer than the deadline (no immediate error)")
        elif expect_pass:
            record(f"path_v1({name})", rc == Status.PASS, f"expected PASS (0), got {rc}")
        else:
            err = res.error_code.decode("utf-8", errors="replace")
            msg = res.message.decode("utf-8", errors="replace")
            if err == "E_FILE_STAT_FAILED":
                ok = rc == Status.IO_ERROR and msg == "Not a regular file"
            else:
                ok = rc == Status.IO_ERROR and err == "E_FILE_OPEN_FAILED"
            record(f"path_v1({name})", ok, f"rc={rc} error={err} msg={msg}")

        finished, rc = deadline_call(lambda: lib.safegguf_validate_path(os.fsencode(target), 0, 0))
        if finished is None:
            record(f"path_legacy({name})_immediate", False, "blocked longer than the deadline (no immediate error)")
        elif expect_pass:
            record(f"path_legacy({name})", rc == Status.PASS, f"expected PASS (0), got {rc}")
        else:
            record(f"path_legacy({name})", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    def check_fd(name, fd):
        # fd entry points must fstat and require the S_ISREG equivalent.
        res = SafeggufResult()
        rc = lib.safegguf_validate_fd_v1(fd, None, ctypes.byref(res))
        err = res.error_code.decode("utf-8", errors="replace")
        msg = res.message.decode("utf-8", errors="replace")
        record(
            f"fd_v1({name})",
            rc == Status.IO_ERROR and err == "E_FD_STAT_FAILED" and msg == "Not a regular file",
            f"rc={rc} error={err} msg={msg}",
        )
        rc = lib.safegguf_validate_fd(fd, 0, 0)
        record(f"fd_legacy({name})", rc == Status.IO_ERROR, f"expected 74, got {rc}")

    with tempfile.TemporaryDirectory(prefix="safegguf-kinds-") as td:
        fifo_path = os.path.join(td, "target.fifo")
        os.mkfifo(fifo_path)

        # Symlink policy: symlinks are followed; the resolved target's kind
        # decides. A symlink to a regular model stays valid, a symlink to a
        # FIFO is rejected without blocking.
        symlink_regular = os.path.join(td, "symlink-regular.gguf")
        os.symlink(VALID_FIXTURE, symlink_regular)
        symlink_fifo = os.path.join(td, "symlink-fifo.gguf")
        os.symlink(fifo_path, symlink_fifo)

        socket_obj = None
        sock_path = os.path.join(td, "target.sock")
        try:
            socket_obj = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            socket_obj.bind(sock_path)
        except OSError:
            socket_obj = None

        open_fds = []
        socket_fd = None
        try:
            # --- path entry points: immediate error, no blocking open ---
            check_path("dir", td)
            check_path("fifo", fifo_path)
            if socket_obj is not None:
                check_path("socket", sock_path)
            check_path("char_device", "/dev/null")
            for block_candidate in ("/dev/loop0", "/dev/sda", "/dev/vda", "/dev/nvme0n1"):
                try:
                    probe_fd = os.open(block_candidate, os.O_RDONLY | os.O_NONBLOCK)
                except OSError:
                    continue
                os.close(probe_fd)
                check_path("block_device", block_candidate)
                break
            check_path("symlink_to_regular", symlink_regular, expect_pass=True)
            check_path("symlink_to_fifo", symlink_fifo)

            # --- descriptor entry points: fstat kind must be regular ---
            open_fds.append(("dir", os.open(td, os.O_RDONLY)))
            open_fds.append(("fifo", os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)))
            if socket_obj is not None:
                socket_fd = socket_obj.fileno()
                open_fds.append(("socket", socket_fd))
            open_fds.append(("char_device", os.open("/dev/null", os.O_RDONLY)))
            for block_candidate in ("/dev/loop0", "/dev/sda", "/dev/vda", "/dev/nvme0n1"):
                try:
                    probe_fd = os.open(block_candidate, os.O_RDONLY | os.O_NONBLOCK)
                except OSError:
                    continue
                open_fds.append(("block_device", probe_fd))
                break

            for name, fd in open_fds:
                check_fd(name, fd)

            # Regular files must stay unaffected on both entries.
            res = SafeggufResult()
            with open(VALID_FIXTURE, "rb") as f:
                raw_h = f.fileno()
                rc_v1 = lib.safegguf_validate_fd_v1(raw_h, None, ctypes.byref(res))
                rc_legacy = lib.safegguf_validate_fd(raw_h, 0, 0)
            record("fd_v1(regular_valid)", rc_v1 == Status.PASS, f"expected 0, got {rc_v1}")
            record("fd_legacy(regular_valid)", rc_legacy == Status.PASS, f"expected 0, got {rc_legacy}")

            with open(CVE_FIXTURE, "rb") as f:
                rc_v1 = lib.safegguf_validate_fd_v1(f.fileno(), None, ctypes.byref(res))
            record("fd_v1(regular_reject)", rc_v1 == Status.REJECT, f"expected 2, got {rc_v1}")
        finally:
            for _, fd in open_fds:
                # The socket fd is owned by socket_obj; closing it here would
                # make the object's own close() fail on an already-closed fd.
                if fd == socket_fd:
                    continue
                try:
                    os.close(fd)
                except OSError:
                    pass
            if socket_obj is not None:
                socket_obj.close()

def main():
    print("======================================================================")
    print("       SAFEGGUF ENTERPRISE FFI BOUNDARIES & ROBUSTNESS FUZZER         ")
    print("======================================================================")

    fuzz_options_struct_sizes()
    fuzz_options_enums()
    fuzz_path_boundaries()
    fuzz_fd_handles()
    fuzz_null_and_buffer_diagnostics()
    fuzz_multithreaded_concurrency()
    fuzz_non_regular_targets()
    fuzz_appended_options_controls()

    print("\n" + "=" * 70)
    print(f"Total FFI Checks : {passed_checks + failed_checks}")
    print(f"Passed           : {passed_checks}")
    print(f"Failed           : {failed_checks}")
    print("=" * 70)

    if failed_checks == 0:
        print("\n>>> OVERALL VERDICT: ALL FFI BOUNDARY FUZZING TESTS PASSED <<<")
        sys.exit(0)
    else:
        print(f"\n>>> OVERALL VERDICT: {failed_checks} FFI FUZZ CHECKS FAILED <<<")
        sys.exit(1)

if __name__ == "__main__":
    main()
