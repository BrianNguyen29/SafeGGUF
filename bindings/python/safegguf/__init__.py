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

__version__ = "0.3.7.dev0"
__all__ = [
    "validate_path",
    "validate_fd",
    "version",
    "ValidationResult",
    "Profile",
    "Endian",
    "Status",
]
