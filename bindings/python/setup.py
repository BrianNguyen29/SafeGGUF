"""Build configuration for the self-contained ``safegguf`` Python wheel.

The wheel bundles the native ``libsafegguf`` shared library and derives its
version from that exact library (``safegguf_version()``), so Python never
hardcodes a second version string. Wheels are therefore platform-specific and
must be built from a checkout whose native artifacts come from the same
commit.

Prerequisites:

* ``zig build -Doptimize=ReleaseSafe`` in the repository root (or
  ``SAFEGGUF_LIB_PATH`` set to an absolute, trusted library), and
* a native CLI built from the same commit: the build compares its
  ``source_commit`` against ``git rev-parse HEAD`` and refuses to package
  stale native artifacts.
"""

import ctypes
import hashlib
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from packaging.version import InvalidVersion, Version
from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
from setuptools.command.build_py import build_py as _build_py

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]


class NativeArtifactsError(RuntimeError):
    """The native library required by the wheel is missing, stale, or unusable."""


def platform_library_names():
    if sys.platform == "win32":
        return ("safegguf.dll", "libsafegguf.dll")
    if sys.platform == "darwin":
        return ("libsafegguf.dylib", "safegguf.dylib")
    return ("libsafegguf.so", "safegguf.so")


def git_head():
    try:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    commit = proc.stdout.strip()
    return commit if proc.returncode == 0 and commit else None


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def native_cli_path():
    names = ("safegguf.exe",) if sys.platform == "win32" else ("safegguf",)
    for name in names:
        candidate = REPO_ROOT / "zig-out" / "bin" / name
        if candidate.is_file():
            return candidate
    return None


def cli_source_commit(cli_path):
    try:
        proc = subprocess.run(
            [str(cli_path), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        if line.startswith("source_commit:"):
            return line.split(":", 1)[1].strip()
    return None


def assert_fresh_native_artifacts(lib_path, head, cli_path, cli_commit):
    """Fail closed when the native artifacts do not belong to the checkout."""
    if head is None:
        return  # Exported source tree: there is no commit to compare against.
    if cli_path is None:
        raise NativeArtifactsError(
            f"cannot verify that {lib_path.name} was built from commit {head}: "
            "no native CLI found under zig-out/bin. Run "
            "`zig build -Doptimize=ReleaseSafe` and rebuild the wheel."
        )
    if cli_commit != head:
        raise NativeArtifactsError(
            f"stale native artifacts: {cli_path} reports source_commit "
            f"{cli_commit or 'unknown'} but HEAD is {head}. Run "
            "`zig build -Doptimize=ReleaseSafe` and rebuild the wheel."
        )


def find_native_library():
    """Return ``(path, explicit)`` for the library to bundle.

    ``explicit`` is true when ``SAFEGGUF_LIB_PATH`` supplied the library; an
    explicitly trusted override skips the staleness gate below.
    """
    override = os.environ.get("SAFEGGUF_LIB_PATH")
    if override:
        path = Path(override)
        if not path.is_absolute() or not path.is_file():
            raise NativeArtifactsError(
                "SAFEGGUF_LIB_PATH must be an absolute path to a regular file "
                f"(got: {override!r})"
            )
        return path.resolve(), True

    looked = []
    for name in platform_library_names():
        for sub in ("lib", "bin"):
            candidate = REPO_ROOT / "zig-out" / sub / name
            looked.append(candidate)
            if candidate.is_file():
                return candidate.resolve(), False
    raise NativeArtifactsError(
        "native safegguf library not found; run `zig build -Doptimize=ReleaseSafe` "
        "or set SAFEGGUF_LIB_PATH. Looked in: " + ", ".join(str(p) for p in looked)
    )


def resolve_native_library():
    lib_path, explicit = find_native_library()
    if not explicit:
        cli_path = native_cli_path()
        assert_fresh_native_artifacts(
            lib_path,
            git_head(),
            cli_path,
            cli_source_commit(cli_path) if cli_path else None,
        )
    return lib_path


def read_native_version(lib_path):
    try:
        lib = ctypes.CDLL(str(lib_path))
    except OSError as exc:
        raise NativeArtifactsError(
            f"cannot load {lib_path} to read its version: {exc}"
        ) from exc
    try:
        version_fn = lib.safegguf_version
    except AttributeError as exc:
        raise NativeArtifactsError(
            f"{lib_path} does not export safegguf_version()"
        ) from exc
    version_fn.restype = ctypes.c_char_p
    raw = version_fn()
    if not raw:
        raise NativeArtifactsError(f"{lib_path} returned an empty version string")
    return raw.decode("utf-8")


def pep440_version(version):
    """Normalize the native version string for distribution metadata.

    Stable versions such as ``0.1.0`` are unchanged. Development suffixes are
    normalized for packaging; ``__version__`` keeps the exact native string.
    """
    try:
        return str(Version(version))
    except InvalidVersion as exc:
        raise NativeArtifactsError(
            f"native version {version!r} is not a valid PEP 440 version: {exc}"
        ) from exc


# Resolution happens once per build process: a missing or stale native library
# fails the build instead of producing a wheel that cannot validate anything.
NATIVE_LIBRARY = resolve_native_library()
NATIVE_VERSION = read_native_version(NATIVE_LIBRARY)
PACKAGE_VERSION = pep440_version(NATIVE_VERSION)
SOURCE_COMMIT = git_head()


class build_py(_build_py):
    """Ship the native library and a generated version module in the wheel."""

    def run(self):
        super().run()
        self._bundle_native_library()

    def _bundle_native_library(self):
        package_dir = Path(self.build_lib) / "safegguf"
        package_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(NATIVE_LIBRARY, package_dir / NATIVE_LIBRARY.name)
        (package_dir / "_version.py").write_text(
            '"""Generated by setup.py - do not edit.\n'
            "\n"
            "Derived at wheel build time from the native library bundled in this\n"
            'wheel and the checkout it was built from.\n'
            '"""\n'
            "\n"
            f'__version__ = "{NATIVE_VERSION}"\n'
            f'__lib_name__ = "{NATIVE_LIBRARY.name}"\n'
            f'__lib_sha256__ = "{sha256(NATIVE_LIBRARY)}"\n'
            f'__source_commit__ = "{SOURCE_COMMIT or "unknown"}"\n',
            encoding="utf-8",
        )


class bdist_wheel(_bdist_wheel):
    """Tag the wheel with the build platform (it bundles a native library).

    The package itself is pure Python -- ``ctypes`` loads the bundled library
    at runtime -- so the wheel keeps the ``py3-none-<platform>`` tag and root
    layout, while still being rejected on other platforms.
    """

    def get_tag(self):
        python_tag, _, _ = super().get_tag()
        if self.plat_name_supplied and self.plat_name:
            platform_tag = self.plat_name
        else:
            platform_tag = sysconfig.get_platform()
        platform_tag = (
            platform_tag.lower().replace("-", "_").replace(".", "_").replace(" ", "_")
        )
        return (python_tag, "none", platform_tag)


def main():
    setup(
        version=PACKAGE_VERSION,
        cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel},
    )


if __name__ == "__main__":
    main()
