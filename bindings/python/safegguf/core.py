import os
import sys
import ctypes
import ctypes.util
import threading
from enum import IntEnum
from typing import Union, Optional
from pathlib import Path

class Profile(IntEnum):
    GGUF_SPEC = 0
    LLAMA_CPP = 1

class Endian(IntEnum):
    LITTLE = 0
    BIG = 1
    AUTO = 2

class Status(IntEnum):
    PASS = 0
    REJECT = 2
    USAGE_ERROR = 64
    SOFTWARE_ERROR = 70
    IO_ERROR = 74

class ValidationResult:
    def __init__(
        self,
        exit_code: Union[int, Status] = Status.PASS,
        error_code: str = "",
        category: str = "",
        stage: str = "",
        message: str = "",
        *args,
        **kwargs
    ):
        if isinstance(exit_code, (int, Status)):
            code = int(exit_code)
        else:
            code = int(args[0]) if args else 0
        if args and isinstance(args[0], int) and not isinstance(exit_code, (int, Status)):
            code = args[0]
        self.exit_code = code
        self.is_valid = (code == 0)
        self.error_code = error_code or kwargs.get("error_code", "")
        self.category = category or kwargs.get("category", "")
        self.stage = stage or kwargs.get("stage", "")
        self.message = message or kwargs.get("message", "")
        self.error_message = self.message

        if code == 0:
            self.status = "PASS"
        elif code == 2:
            self.status = "REJECT"
        elif code == 74:
            self.status = "IO_ERROR"
        elif code == 70:
            self.status = "SOFTWARE_ERROR"
        elif code == 64:
            self.status = "USAGE_ERROR"
        else:
            self.status = f"UNKNOWN_{code}"

    def __bool__(self) -> bool:
        return self.is_valid

    def __repr__(self) -> str:
        if self.is_valid:
            return f"<ValidationResult status=PASS exit_code=0>"
        return (
            f"<ValidationResult status={self.status} exit_code={self.exit_code} "
            f"error_code='{self.error_code}' category='{self.category}'>"
        )

class SafeggufOptionsV1(ctypes.Structure):
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

class SafeggufOptionsV1Legacy(ctypes.Structure):
    """v1.0 options prefix, before the appended v1.1 controls.

    Only its ``sizeof`` is used: calls that set neither appended control send
    this legacy ``struct_size`` value so native libraries built before v1.1
    keep validating with their old defaults.
    """
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("profile", ctypes.c_int32),
        ("endian", ctypes.c_int32),
        ("max_alloc_bytes", ctypes.c_uint64),
        ("max_work_units", ctypes.c_uint64),
        ("max_scanned_bytes", ctypes.c_uint64),
        ("reserved", ctypes.c_void_p),
    ]

_LEGACY_OPTIONS_SIZE = ctypes.sizeof(SafeggufOptionsV1Legacy)

class SafeggufResult(ctypes.Structure):
    _fields_ = [
        ("exit_code", ctypes.c_int32),
        ("error_code", ctypes.c_char * 64),
        ("category", ctypes.c_char * 32),
        ("stage", ctypes.c_char * 32),
        ("message", ctypes.c_char * 256),
    ]

def _find_library() -> str:
    # 1. Explicit trusted path: must be absolute and point at a regular file.
    #    Fail closed so a misconfigured override never silently falls through
    #    to a less trusted candidate.
    env_lib = os.environ.get("SAFEGGUF_LIB_PATH")
    if env_lib:
        if not os.path.isabs(env_lib) or not os.path.isfile(env_lib):
            raise FileNotFoundError(
                "SAFEGGUF_LIB_PATH must be an absolute path to a regular file "
                f"(got: {env_lib!r})"
            )
        return env_lib

    # 2. Candidate names based on platform
    if sys.platform == "win32":
        lib_names = ["safegguf.dll", "libsafegguf.dll"]
    elif sys.platform == "darwin":
        lib_names = ["libsafegguf.dylib", "safegguf.dylib"]
    else:
        lib_names = ["libsafegguf.so", "safegguf.so"]

    # 3. Packaged / source-tree locations, anchored to this file: wheel layout
    #    first, then a source checkout's zig-out. Never os.getcwd(): an
    #    attacker-controlled working directory must not be able to inject a
    #    shared library.
    curr = Path(__file__).resolve().parent
    repo_root = curr.parents[2] # bindings/python/safegguf -> repo root

    search_dirs = [
        curr,
        repo_root / "zig-out" / "bin",
        repo_root / "zig-out" / "lib",
    ]

    for d in search_dirs:
        for name in lib_names:
            candidate = d / name
            if candidate.is_file():
                return str(candidate)

    # 4. Admin-managed system install path, resolved through the platform
    #    library search (ldconfig/dyld/PATH). A bare-name dlopen is
    #    deliberately not used here because the loader may consult the process
    #    CWD for leaf names on Windows/macOS.
    system_names = ["safegguf.dll", "libsafegguf.dll"] if sys.platform == "win32" else ["safegguf"]
    for name in system_names:
        resolved = ctypes.util.find_library(name)
        if resolved:
            try:
                ctypes.CDLL(resolved)
                return resolved
            except OSError:
                pass

    # Linux leaf-name resolution goes through ld.so (system directories and
    # LD_LIBRARY_PATH as configured by the administrator), never the CWD.
    if sys.platform.startswith("linux"):
        for name in lib_names:
            try:
                ctypes.CDLL(name)
                return name
            except OSError:
                pass

    raise FileNotFoundError(
        "Could not find safegguf dynamic library. Ensure 'zig build' has run or set SAFEGGUF_LIB_PATH."
    )

_lib_handle: Optional[ctypes.CDLL] = None

def _get_lib() -> ctypes.CDLL:
    global _lib_handle
    if _lib_handle is None:
        lib_path = _find_library()
        _lib_handle = ctypes.CDLL(lib_path)

        _lib_handle.safegguf_version.restype = ctypes.c_char_p
        _lib_handle.safegguf_validate_path.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        _lib_handle.safegguf_validate_path.restype = ctypes.c_int
        _lib_handle.safegguf_validate_fd.argtypes = [ctypes.c_ssize_t, ctypes.c_int, ctypes.c_int]
        _lib_handle.safegguf_validate_fd.restype = ctypes.c_int

        if hasattr(_lib_handle, "safegguf_validate_path_v1"):
            _lib_handle.safegguf_validate_path_v1.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(SafeggufOptionsV1),
                ctypes.POINTER(SafeggufResult),
            ]
            _lib_handle.safegguf_validate_path_v1.restype = ctypes.c_int

        if hasattr(_lib_handle, "safegguf_validate_fd_v1"):
            _lib_handle.safegguf_validate_fd_v1.argtypes = [
                ctypes.c_ssize_t,
                ctypes.POINTER(SafeggufOptionsV1),
                ctypes.POINTER(SafeggufResult),
            ]
            _lib_handle.safegguf_validate_fd_v1.restype = ctypes.c_int

    return _lib_handle

def version() -> str:
    """Return SafeGGUF engine version."""
    lib = _get_lib()
    return lib.safegguf_version().decode("utf-8")

def _parse_profile(profile: Union[str, Profile, int]) -> int:
    if isinstance(profile, Profile):
        return int(profile)
    if isinstance(profile, int):
        if profile in (0, 1):
            return profile
        raise ValueError(f"Invalid profile integer: {profile} (must be 0 or 1)")
    p_lower = str(profile).lower().replace("-", "_")
    if p_lower in ("llama_cpp", "llama-cpp", "llamacpp", "1"):
        return int(Profile.LLAMA_CPP)
    elif p_lower in ("gguf_spec", "gguf-spec", "ggufspec", "0"):
        return int(Profile.GGUF_SPEC)
    raise ValueError(f"Invalid profile: '{profile}' (choose 'llama-cpp' or 'gguf-spec')")

def _parse_endian(endian: Union[str, Endian, int]) -> int:
    if isinstance(endian, Endian):
        return int(endian)
    if isinstance(endian, int):
        if endian in (0, 1, 2):
            return endian
        raise ValueError(f"Invalid endian integer: {endian} (must be 0, 1, or 2)")
    e_lower = str(endian).lower()
    if e_lower in ("big", "1"):
        return int(Endian.BIG)
    elif e_lower in ("auto", "2"):
        return int(Endian.AUTO)
    elif e_lower in ("little", "0"):
        return int(Endian.LITTLE)
    raise ValueError(f"Invalid endian: '{endian}' (choose 'little', 'big', or 'auto')")

_UINT64_MAX = (1 << 64) - 1

def _parse_u64_limit(name: str, value: int) -> int:
    """Validate a resource limit destined for a ``c_uint64`` option field.

    ``0`` keeps the engine-configured default. Any other value must be a
    non-bool integer in ``[1, UINT64_MAX]``. Booleans, non-integers, negative
    values, and values above ``UINT64_MAX`` are rejected instead of being
    silently wrapped by ``ctypes`` (e.g. ``-1`` -> ``UINT64_MAX``,
    ``2**64`` -> ``0``), which would weaken the configured quota.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{name} must be an integer (0 = use engine default), "
            f"got {type(value).__name__}: {value!r}"
        )
    if value < 0:
        raise ValueError(
            f"{name} must be non-negative (0 = use engine default), got {value}"
        )
    if value > _UINT64_MAX:
        raise ValueError(
            f"{name} must be <= UINT64_MAX ({_UINT64_MAX}), got {value}"
        )
    return value

def _parse_flag(name: str, value: Union[bool, int]) -> int:
    """Validate a 0/1 option flag destined for a ``uint32`` option field.

    Accepts ``bool`` and the integers ``0`` / ``1``; any other value is
    rejected before the native call so a typo cannot silently enable or
    disable a security control.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and value in (0, 1):
        return value
    raise ValueError(
        f"{name} must be a bool or the integer 0/1, got {type(value).__name__}: {value!r}"
    )

def _parse_limits(
    max_alloc_bytes: int,
    max_work_units: int,
    max_scanned_bytes: int,
    max_file_size_bytes: int,
    require_stable_file: Union[bool, int],
):
    """Validate all per-call resource limits and controls before any native call."""
    return (
        _parse_u64_limit("max_alloc_bytes", max_alloc_bytes),
        _parse_u64_limit("max_work_units", max_work_units),
        _parse_u64_limit("max_scanned_bytes", max_scanned_bytes),
        _parse_u64_limit("max_file_size_bytes", max_file_size_bytes),
        _parse_flag("require_stable_file", require_stable_file),
    )

_extended_options_supported: Optional[bool] = None

def _native_supports_extended_options(lib: ctypes.CDLL) -> bool:
    """Detect whether the loaded native library understands the v1.1 options.

    The appended controls are gated natively on ``struct_size``: a legacy
    library rejects the extended size with ``E_USAGE_INVALID_OPTIONS``, while
    the current library accepts it and fails the NULL-path probe with
    ``E_USAGE_NULL_PATH`` instead. The probe touches no filesystem state and
    the answer is cached for the process; any other outcome is treated as
    unsupported so set controls fail closed rather than being dropped.
    """
    global _extended_options_supported
    if _extended_options_supported is None:
        probe_opts = SafeggufOptionsV1(
            struct_size=ctypes.sizeof(SafeggufOptionsV1),
            profile=int(Profile.GGUF_SPEC),
            endian=int(Endian.AUTO),
            max_alloc_bytes=0,
            max_work_units=0,
            max_scanned_bytes=0,
            reserved=None,
            max_file_size_bytes=0,
            require_stable_file=0,
        )
        probe_result = SafeggufResult()
        lib.safegguf_validate_path_v1(None, ctypes.byref(probe_opts), ctypes.byref(probe_result))
        _extended_options_supported = (
            probe_result.error_code.decode("utf-8", errors="replace") == "E_USAGE_NULL_PATH"
        )
    return _extended_options_supported

def _options_struct_size(
    lib: ctypes.CDLL, max_file_size_bytes: int, require_stable_file: int
) -> Optional[int]:
    """Pick the native options ``struct_size`` for this call.

    Calls without appended controls send the v1.0 size so legacy libraries
    stay fully usable. Calls that set a control send the current size only
    when the native library supports the extended layout; ``None`` means the
    request cannot be enforced and the caller must fail closed.
    """
    if max_file_size_bytes == 0 and require_stable_file == 0:
        return _LEGACY_OPTIONS_SIZE
    if not _native_supports_extended_options(lib):
        return None
    return ctypes.sizeof(SafeggufOptionsV1)

def _unsupported_extended_options() -> ValidationResult:
    """Fail-closed result for appended controls a legacy native library cannot enforce."""
    return ValidationResult(
        exit_code=Status.USAGE_ERROR,
        error_code="E_USAGE_UNSUPPORTED_OPTIONS",
        category="usage",
        stage="options",
        message=(
            "Loaded native library does not support max_file_size_bytes / "
            "require_stable_file (legacy safegguf_options_v1 layout); refusing "
            "to run with the requested controls silently dropped"
        ),
    )

def validate_path(
    path: Optional[Union[str, bytes, os.PathLike]],
    profile: Union[str, Profile, int] = Profile.LLAMA_CPP,
    endian: Union[str, Endian, int] = Endian.AUTO,
    max_alloc_bytes: int = 0,
    max_work_units: int = 0,
    max_scanned_bytes: int = 0,
    max_file_size_bytes: int = 0,
    require_stable_file: Union[bool, int] = False,
) -> ValidationResult:
    """
    Validate a GGUF model file on disk by path with structured diagnostics.

    Resource limits accept 0 (= engine default) or an integer in
    [1, UINT64_MAX]; anything else returns USAGE_ERROR (64).

    ``max_file_size_bytes`` is an inclusive input admission ceiling
    (0 = unlimited engine default): larger files are rejected with
    E_FileTooLarge (2, resource). ``require_stable_file`` accepts a bool or
    0/1 and, when enabled, rejects with E_FileChangedDuringValidation (2) if
    the file's identity changes while it is being validated. Both controls
    require a native library with the extended v1 options layout; on a legacy
    library they fail closed with E_USAGE_UNSUPPORTED_OPTIONS (64) instead of
    being silently ignored.
    """
    if path is None or not isinstance(path, (str, bytes, os.PathLike)):
        return ValidationResult(
            exit_code=Status.USAGE_ERROR,
            error_code="E_USAGE_NULL_PATH",
            category="usage",
            stage="input",
            message="Path is None or not a valid path-like object",
        )

    try:
        prof_id = _parse_profile(profile)
        end_id = _parse_endian(endian)
    except ValueError as exc:
        return ValidationResult(
            exit_code=Status.USAGE_ERROR,
            error_code="E_USAGE_INVALID_PROFILE",
            category="usage",
            stage="options",
            message=str(exc),
        )

    try:
        (
            max_alloc_bytes,
            max_work_units,
            max_scanned_bytes,
            max_file_size_bytes,
            require_stable_file,
        ) = _parse_limits(
            max_alloc_bytes,
            max_work_units,
            max_scanned_bytes,
            max_file_size_bytes,
            require_stable_file,
        )
    except ValueError as exc:
        return ValidationResult(
            exit_code=Status.USAGE_ERROR,
            error_code="E_USAGE_INVALID_LIMIT",
            category="usage",
            stage="options",
            message=str(exc),
        )

    try:
        if isinstance(path, bytes):
            path_bytes = path
        else:
            path_bytes = os.fsencode(path)
    except (UnicodeEncodeError, UnicodeError):
        return ValidationResult(
            exit_code=Status.IO_ERROR,
            error_code="E_IO_ENCODING_ERROR",
            category="io",
            stage="input",
            message="Failed to encode path string to filesystem bytes",
        )

    if b"\x00" in path_bytes or len(path_bytes) == 0 or len(path_bytes) > 4096:
        return ValidationResult(
            exit_code=Status.IO_ERROR,
            error_code="E_IO_INVALID_PATH",
            category="io",
            stage="input",
            message="Path length is empty, exceeds 4096 bytes, or contains null bytes",
        )

    lib = _get_lib()
    if hasattr(lib, "safegguf_validate_path_v1"):
        struct_size = _options_struct_size(lib, max_file_size_bytes, require_stable_file)
        if struct_size is None:
            return _unsupported_extended_options()
        opts = SafeggufOptionsV1(
            struct_size=struct_size,
            profile=prof_id,
            endian=end_id,
            max_alloc_bytes=max_alloc_bytes,
            max_work_units=max_work_units,
            max_scanned_bytes=max_scanned_bytes,
            reserved=None,
            max_file_size_bytes=max_file_size_bytes,
            require_stable_file=require_stable_file,
        )
        res = SafeggufResult()
        rc = lib.safegguf_validate_path_v1(path_bytes, ctypes.byref(opts), ctypes.byref(res))
        return ValidationResult(
            exit_code=rc,
            error_code=res.error_code.decode("utf-8", errors="replace"),
            category=res.category.decode("utf-8", errors="replace"),
            stage=res.stage.decode("utf-8", errors="replace"),
            message=res.message.decode("utf-8", errors="replace"),
        )
    else:
        if max_file_size_bytes != 0 or require_stable_file != 0:
            return _unsupported_extended_options()
        rc = lib.safegguf_validate_path(path_bytes, prof_id, end_id)
        return ValidationResult(rc)

_fd_lock = threading.Lock()

def validate_fd(
    fd: int,
    profile: Union[str, Profile, int] = Profile.LLAMA_CPP,
    endian: Union[str, Endian, int] = Endian.AUTO,
    max_alloc_bytes: int = 0,
    max_work_units: int = 0,
    max_scanned_bytes: int = 0,
    max_file_size_bytes: int = 0,
    require_stable_file: Union[bool, int] = False,
) -> ValidationResult:
    """
    Validate an open GGUF file descriptor directly with structured diagnostics.
    Immune to Time-Of-Check to Time-Of-Use (TOCTOU) file race conditions.

    Resource limits accept 0 (= engine default) or an integer in
    [1, UINT64_MAX]; anything else returns USAGE_ERROR (64).

    ``max_file_size_bytes`` is an inclusive input admission ceiling
    (0 = unlimited engine default): larger inputs are rejected with
    E_FileTooLarge (2, resource). ``require_stable_file`` accepts a bool or
    0/1 and, when enabled, rejects with E_FileChangedDuringValidation (2) if
    the open file's identity changes while it is being validated. Both
    controls require a native library with the extended v1 options layout; on
    a legacy library they fail closed with E_USAGE_UNSUPPORTED_OPTIONS (64)
    instead of being silently ignored.
    """
    if not isinstance(fd, int) or isinstance(fd, bool):
        return ValidationResult(
            exit_code=Status.USAGE_ERROR,
            error_code="E_USAGE_INVALID_FD",
            category="usage",
            stage="input",
            message="File descriptor must be an integer",
        )

    try:
        prof_id = _parse_profile(profile)
        end_id = _parse_endian(endian)
    except ValueError as exc:
        return ValidationResult(
            exit_code=Status.USAGE_ERROR,
            error_code="E_USAGE_INVALID_PROFILE",
            category="usage",
            stage="options",
            message=str(exc),
        )

    try:
        (
            max_alloc_bytes,
            max_work_units,
            max_scanned_bytes,
            max_file_size_bytes,
            require_stable_file,
        ) = _parse_limits(
            max_alloc_bytes,
            max_work_units,
            max_scanned_bytes,
            max_file_size_bytes,
            require_stable_file,
        )
    except ValueError as exc:
        return ValidationResult(
            exit_code=Status.USAGE_ERROR,
            error_code="E_USAGE_INVALID_LIMIT",
            category="usage",
            stage="options",
            message=str(exc),
        )

    lib = _get_lib()
    if sys.platform == "win32":
        import msvcrt
        try:
            raw_handle = msvcrt.get_osfhandle(fd)
        except (OSError, ValueError, TypeError, OverflowError):
            return ValidationResult(
                exit_code=Status.IO_ERROR,
                error_code="E_IO_INVALID_HANDLE",
                category="io",
                stage="descriptor",
                message="Failed to retrieve Windows OS handle for descriptor",
            )
    else:
        if fd < 0:
            return ValidationResult(
                exit_code=Status.IO_ERROR,
                error_code="E_IO_INVALID_FD",
                category="io",
                stage="descriptor",
                message="POSIX file descriptor is negative",
            )
        raw_handle = fd

    with _fd_lock:
        orig_offset = None
        try:
            orig_offset = os.lseek(fd, 0, os.SEEK_CUR)
        except OSError:
            pass

        try:
            if hasattr(lib, "safegguf_validate_fd_v1"):
                struct_size = _options_struct_size(lib, max_file_size_bytes, require_stable_file)
                if struct_size is None:
                    return _unsupported_extended_options()
                opts = SafeggufOptionsV1(
                    struct_size=struct_size,
                    profile=prof_id,
                    endian=end_id,
                    max_alloc_bytes=max_alloc_bytes,
                    max_work_units=max_work_units,
                    max_scanned_bytes=max_scanned_bytes,
                    reserved=None,
                    max_file_size_bytes=max_file_size_bytes,
                    require_stable_file=require_stable_file,
                )
                res = SafeggufResult()
                rc = lib.safegguf_validate_fd_v1(raw_handle, ctypes.byref(opts), ctypes.byref(res))
                return ValidationResult(
                    exit_code=rc,
                    error_code=res.error_code.decode("utf-8", errors="replace"),
                    category=res.category.decode("utf-8", errors="replace"),
                    stage=res.stage.decode("utf-8", errors="replace"),
                    message=res.message.decode("utf-8", errors="replace"),
                )
            else:
                if max_file_size_bytes != 0 or require_stable_file != 0:
                    return _unsupported_extended_options()
                rc = lib.safegguf_validate_fd(raw_handle, prof_id, end_id)
                return ValidationResult(rc)
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            return ValidationResult(
                exit_code=Status.IO_ERROR,
                error_code="E_IO_EXCEPTION",
                category="io",
                stage="descriptor",
                message=str(exc),
            )
        finally:
            if orig_offset is not None:
                try:
                    os.lseek(fd, orig_offset, os.SEEK_SET)
                except OSError:
                    pass
