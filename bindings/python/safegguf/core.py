import os
import sys
import ctypes
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
    def __init__(self, exit_code: Union[int, Status] = Status.PASS, *args, **kwargs):
        if isinstance(exit_code, (int, Status)):
            code = int(exit_code)
        else:
            code = int(args[0]) if args else 0
        if args and isinstance(args[0], int) and not isinstance(exit_code, (int, Status)):
            code = args[0]
        self.exit_code = code
        self.is_valid = (code == 0)
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
        return f"<ValidationResult status={self.status} exit_code={self.exit_code}>"

def _find_library() -> str:
    # 1. Environment variable override
    env_lib = os.environ.get("SAFEGGUF_LIB_PATH")
    if env_lib and os.path.exists(env_lib):
        return env_lib

    # 2. Candidate names based on platform
    if sys.platform == "win32":
        lib_names = ["safegguf.dll", "libsafegguf.dll"]
    elif sys.platform == "darwin":
        lib_names = ["libsafegguf.dylib", "safegguf.dylib"]
    else:
        lib_names = ["libsafegguf.so", "safegguf.so"]

    # 3. Search directories relative to this file and workspace
    curr = Path(__file__).resolve().parent
    repo_root = curr.parents[2] # bindings/python/safegguf -> repo root

    search_dirs = [
        curr,
        repo_root / "zig-out" / "bin",
        repo_root / "zig-out" / "lib",
        Path.cwd() / "zig-out" / "bin",
        Path.cwd() / "zig-out" / "lib",
    ]

    for d in search_dirs:
        for name in lib_names:
            candidate = d / name
            if candidate.exists():
                return str(candidate)

    # 4. Fallback to system search
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

    return _lib_handle

def version() -> str:
    """Return SafeGGUF engine version."""
    lib = _get_lib()
    return lib.safegguf_version().decode("utf-8")

def _parse_profile(profile: Union[str, Profile, int]) -> int:
    if isinstance(profile, Profile):
        return int(profile)
    if isinstance(profile, int):
        return profile
    p_lower = str(profile).lower().replace("-", "_")
    if "llama" in p_lower:
        return int(Profile.LLAMA_CPP)
    return int(Profile.GGUF_SPEC)

def _parse_endian(endian: Union[str, Endian, int]) -> int:
    if isinstance(endian, Endian):
        return int(endian)
    if isinstance(endian, int):
        return endian
    e_lower = str(endian).lower()
    if e_lower == "big":
        return int(Endian.BIG)
    elif e_lower == "auto":
        return int(Endian.AUTO)
    return int(Endian.LITTLE)

def validate_path(
    path: Optional[Union[str, bytes, os.PathLike]],
    profile: Union[str, Profile] = Profile.LLAMA_CPP,
    endian: Union[str, Endian] = Endian.AUTO,
) -> ValidationResult:
    """
    Validate a GGUF model file on disk by path.
    """
    if path is None or not isinstance(path, (str, bytes, os.PathLike)):
        return ValidationResult(Status.USAGE_ERROR, 64)

    try:
        if isinstance(path, bytes):
            path_bytes = path
        else:
            path_bytes = os.fsencode(path)
    except (UnicodeEncodeError, UnicodeError):
        return ValidationResult(Status.IO_ERROR, 74)

    if b"\x00" in path_bytes or len(path_bytes) == 0 or len(path_bytes) > 4096:
        return ValidationResult(Status.IO_ERROR, 74)

    lib = _get_lib()
    prof_id = _parse_profile(profile)
    end_id = _parse_endian(endian)
    rc = lib.safegguf_validate_path(path_bytes, prof_id, end_id)
    return ValidationResult(rc)

_fd_lock = threading.Lock()

def validate_fd(
    fd: int,
    profile: Union[str, Profile] = Profile.LLAMA_CPP,
    endian: Union[str, Endian] = Endian.AUTO,
) -> ValidationResult:
    """
    Validate an open GGUF file descriptor directly.
    Immune to Time-Of-Check to Time-Of-Use (TOCTOU) file race conditions.
    """
    if not isinstance(fd, int) or isinstance(fd, bool):
        return ValidationResult(Status.USAGE_ERROR, 64)

    lib = _get_lib()
    prof_id = _parse_profile(profile)
    end_id = _parse_endian(endian)
    if sys.platform == "win32":
        import msvcrt
        try:
            raw_handle = msvcrt.get_osfhandle(fd)
        except (OSError, ValueError, TypeError, OverflowError):
            return ValidationResult(Status.IO_ERROR, 74)
    else:
        if fd < 0:
            return ValidationResult(Status.IO_ERROR, 74)
        raw_handle = fd

    with _fd_lock:
        orig_offset = None
        try:
            orig_offset = os.lseek(fd, 0, os.SEEK_CUR)
        except OSError:
            pass

        try:
            rc = lib.safegguf_validate_fd(raw_handle, prof_id, end_id)
            return ValidationResult(rc)
        except (OSError, ValueError, TypeError, OverflowError):
            return ValidationResult(Status.IO_ERROR, 74)
        finally:
            if orig_offset is not None:
                try:
                    os.lseek(fd, orig_offset, os.SEEK_SET)
                except OSError:
                    pass
