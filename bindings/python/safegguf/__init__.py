"""
SafeGGUF: Memory-Safe GGUF v3 Structural & Arithmetic Validator Python Bindings.
"""

from .core import (
    validate_path,
    validate_fd,
    version,
    ValidationResult,
    Profile,
    Endian,
    Status,
)

try:
    # Generated when the package is built into a wheel; the version is read
    # from the native library the wheel bundles, never hardcoded here.
    from ._version import __version__
except ImportError:
    # Source checkout or editable install: report what the native library on
    # this machine says, or "unknown" when none is available.
    try:
        __version__ = version()
    except (OSError, AttributeError):
        __version__ = "unknown"

__all__ = [
    "validate_path",
    "validate_fd",
    "version",
    "ValidationResult",
    "Profile",
    "Endian",
    "Status",
]
