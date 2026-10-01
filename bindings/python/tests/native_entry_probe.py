#!/usr/bin/env python3
"""Fork-isolated C-ABI entry-point probe for the Python binding.

The macOS ``test_binding.py`` CI step aborts with a bare Zig
``panic: reached unreachable code`` and no stack trace (Zig's stack-dump
handler is itself lost when the library is loaded through ``ctypes``), so the
failing native call cannot be identified from the log: Python block-buffers
stdout to a pipe and the buffer is discarded on ``abort()``.

This probe attributes a native abort to the exact exported entry point without
waiting for a second run: every entry point the binding suite exercises is
called once in a forked child. A child that hits a Zig ``unreachable``/assert
dies with SIGABRT (exit 134 at the shell level); the parent records the signal
and keeps going, so the *first* aborting entry point is named in the output.

The probe is diagnostic only: it never fails the suite, it only reports.
It is a no-op on platforms without ``os.fork`` (Windows).

Usage (standalone, from the repository root, with a built library):

    python bindings/python/tests/native_entry_probe.py

Or import and call ``run_native_entry_probe(valid_file, cve_file)``.
"""

import ctypes
import os
import sys
from pathlib import Path

# Repo layout: <root>/bindings/python/tests/native_entry_probe.py
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT / "bindings" / "python") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "bindings" / "python"))

import safegguf.core as core  # noqa: E402


def _v1_options(struct_size, **kwargs):
    return core.SafeggufOptionsV1(
        struct_size=struct_size,
        profile=kwargs.get("profile", 0),
        endian=kwargs.get("endian", 2),
        max_alloc_bytes=kwargs.get("max_alloc_bytes", 0),
        max_work_units=kwargs.get("max_work_units", 0),
        max_scanned_bytes=kwargs.get("max_scanned_bytes", 0),
        reserved=None,
        max_file_size_bytes=kwargs.get("max_file_size_bytes", 0),
        require_stable_file=kwargs.get("require_stable_file", 0),
    )


def _native_entries(valid_file, cve_file):
    """Every native call the binding suite makes, in suite order.

    Returns a list of ``(name, callable, expected_rc)``; ``expected_rc`` is
    informational (None = platform-dependent, any rc is reported as-is).
    """
    lib = core._get_lib()
    legacy = core._LEGACY_OPTIONS_SIZE
    extended = ctypes.sizeof(core.SafeggufOptionsV1)
    valid_bytes = os.fsencode(str(valid_file))
    cve_bytes = os.fsencode(str(cve_file))
    valid_size = os.path.getsize(valid_file)

    def with_fd(path, fn):
        fd = os.open(str(path), os.O_RDONLY)
        try:
            return fn(fd)
        finally:
            os.close(fd)

    def path_v1(path_bytes, opts):
        res = core.SafeggufResult()
        return lib.safegguf_validate_path_v1(path_bytes, opts, ctypes.byref(res))

    def fd_v1(fd, opts):
        res = core.SafeggufResult()
        return lib.safegguf_validate_fd_v1(fd, opts, ctypes.byref(res))

    entries = []

    def add(name, fn, expect):
        entries.append((name, fn, expect))

    # --- test 1 / 13 (known-good on macOS via the wheel PROBE; control) -----
    add("path-v1-legacy-valid", lambda: path_v1(valid_bytes, _v1_options(legacy)), 0)
    add("path-v1-legacy-missing", lambda: path_v1(b"non_existent_file.gguf", _v1_options(legacy)), 74)

    # --- test 2 / 6: llama-cpp REJECT through the dylib ---------------------
    add("path-v1-legacy-cve-llama", lambda: path_v1(cve_bytes, _v1_options(legacy, profile=1)), 2)
    add("path-v1-extended-cve-llama", lambda: path_v1(cve_bytes, _v1_options(extended, profile=1, endian=2)), 2)

    # --- test 5: legacy enum guards ----------------------------------------
    add("path-legacy-enum-guard", lambda: lib.safegguf_validate_path(b"x", 99, 0), 64)
    add("path-legacy-valid", lambda: lib.safegguf_validate_path(valid_bytes, 0, 2), 0)

    # --- tests 7/8: fd entry points on valid + rejecting files --------------
    add("fd-v1-valid", lambda: with_fd(valid_file, lambda fd: fd_v1(fd, _v1_options(legacy))), 0)
    add("fd-v1-cve-llama", lambda: with_fd(cve_file, lambda fd: fd_v1(fd, _v1_options(extended, profile=1))), 2)
    add("fd-legacy-valid", lambda: with_fd(valid_file, lambda fd: lib.safegguf_validate_fd(fd, 0, 2)), 0)

    # --- tests 9/10: invalid descriptors must stay error paths --------------
    def closed_fd_call():
        fd = os.open(str(valid_file), os.O_RDONLY)
        os.close(fd)
        return fd_v1(fd, _v1_options(legacy))

    add("fd-v1-closed", closed_fd_call, 74)
    add("fd-v1-minus-one", lambda: lib.safegguf_validate_fd_v1(-1, None, None), 74)
    add("fd-legacy-minus-one", lambda: lib.safegguf_validate_fd(-1, 0, 0), 74)
    add("fd-legacy-stdin", lambda: lib.safegguf_validate_fd(0, 0, 0), None)

    # --- test 11 / 14: quota rejection --------------------------------------
    add("path-v1-quota-128", lambda: path_v1(valid_bytes, _v1_options(legacy, max_alloc_bytes=128)), 2)

    # --- test 12: TOCTOU offset preservation --------------------------------
    def toctou():
        def call(fd):
            os.lseek(fd, 12, os.SEEK_SET)
            rc = fd_v1(fd, _v1_options(legacy))
            after = os.lseek(fd, 0, os.SEEK_CUR)
            if after != 12:
                raise AssertionError(f"offset moved to {after}")
            return rc

        return with_fd(valid_file, call)

    add("fd-v1-toctou-offset", toctou, 0)

    # --- tests 16/17: appended controls (extended struct_size) --------------
    add("path-v1-admission-exact", lambda: path_v1(valid_bytes, _v1_options(extended, max_file_size_bytes=valid_size)), 0)
    add("path-v1-admission-under", lambda: path_v1(valid_bytes, _v1_options(extended, max_file_size_bytes=valid_size - 1)), 2)
    add("fd-v1-admission-exact", lambda: with_fd(valid_file, lambda fd: fd_v1(fd, _v1_options(extended, max_file_size_bytes=valid_size))), 0)
    add("path-v1-stable", lambda: path_v1(valid_bytes, _v1_options(extended, require_stable_file=1)), 0)
    add("fd-v1-stable", lambda: with_fd(valid_file, lambda fd: fd_v1(fd, _v1_options(extended, require_stable_file=1))), 0)

    # --- test 18: extended-layout detection probe ---------------------------
    add(
        "extended-detection-probe",
        lambda: lib.safegguf_validate_path_v1(None, _v1_options(extended), ctypes.byref(core.SafeggufResult())),
        64,
    )

    # --- repeated fd validation: state/leak/allocator stress ----------------
    def repeat_fd_valid():
        rc = 0
        for _ in range(25):
            rc = with_fd(valid_file, lambda fd: fd_v1(fd, _v1_options(legacy)))
        return rc

    add("fd-v1-repeat-25x", repeat_fd_valid, 0)

    return entries


def _run_in_child(fn):
    """Run ``fn`` in a forked child. Returns (status, payload).

    payload is the returned rc as text, or "EXC:<name>" when the child raised.
    """
    read_fd, write_fd = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:  # child
        os.close(read_fd)
        try:
            rc = int(fn())
            os.write(write_fd, str(rc).encode("ascii", "replace"))
        except BaseException as exc:  # noqa: BLE001 - diagnostic payload
            os.write(write_fd, f"EXC:{type(exc).__name__}".encode("ascii", "replace"))
        finally:
            os._exit(0)
    os.close(write_fd)
    chunks = []
    while True:
        block = os.read(read_fd, 64)
        if not block:
            break
        chunks.append(block)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    return status, b"".join(chunks).decode("ascii", "replace")


def run_native_entry_probe(valid_file, cve_file, stream=None):
    """Probe every native entry point in a forked child; report aborts.

    Returns the list of results: ``(name, outcome, payload, expected)`` with
    outcome one of ``ok`` / ``CRASH`` / ``EXIT``. Never raises on a child
    abort and never fails the suite; on platforms without ``os.fork`` it
    returns an empty list.
    """
    stream = stream if stream is not None else sys.stdout
    if not hasattr(os, "fork") or not hasattr(os, "waitpid"):
        print(
            "  [native-probe] skipped: os.fork is unavailable on this platform",
            file=stream,
            flush=True,
        )
        return []

    entries = _native_entries(valid_file, cve_file)
    width = max(len(name) for name, _, _ in entries)
    results = []
    crashed = []

    for name, fn, expected in entries:
        status, payload = _run_in_child(fn)
        if os.WIFSIGNALED(status):
            outcome = "CRASH"
            detail = f"signal {os.WTERMSIG(status)}"
            crashed.append((name, detail))
        elif os.WEXITSTATUS(status) != 0:
            outcome = "EXIT"
            detail = f"exit {os.WEXITSTATUS(status)}"
            crashed.append((name, detail))
        else:
            outcome = "ok"
            detail = f"rc={payload}"
            if expected is not None and payload != str(expected):
                detail += f" (expected {expected})"
        results.append((name, outcome, payload, expected))
        print(f"  [native-probe] {name.ljust(width)}  {outcome:<5} {detail}", file=stream, flush=True)

    if crashed:
        first_name, first_detail = crashed[0]
        print(
            f"  [native-probe] NATIVE ABORT DETECTED: {first_name} died with {first_detail} "
            f"({len(crashed)} of {len(entries)} entries aborted) - see the panic line above",
            file=stream,
            flush=True,
        )
    else:
        print(
            f"  [native-probe] all {len(entries)} native entry points returned without aborting",
            file=stream,
            flush=True,
        )
    return results


def _main():
    valid = _REPO_ROOT / "tests" / "fixtures" / "valid.gguf"
    cve = _REPO_ROOT / "tests" / "fixtures" / "negative" / "cve-2025-53630-cumulative-overflow.gguf"
    if not valid.is_file():
        raise SystemExit(f"missing fixture: {valid} (run: python tests/generate_fixtures.py)")
    if not cve.is_file():
        raise SystemExit(f"missing fixture: {cve} (run: python tests/generate_fixtures.py)")
    print("Fork-isolated native entry-point probe (diagnostic; never fails the suite)")
    run_native_entry_probe(valid, cve)


if __name__ == "__main__":
    _main()
