#!/usr/bin/env python3
"""End-to-end packaging test for the self-contained ``safegguf`` wheel.

Builds the wheel from ``bindings/python``, installs it into a clean virtual
environment, and imports it from a neutral directory outside the repository:

* the wheel bundles, byte-for-byte, the native library the build resolved;
* the wheel's ``__version__`` equals the version the bundled library reports;
* the installed package and library resolve inside the venv, proving there is
  no repository/CWD dependency at import time;
* the generated version module records the commit the wheel was built from.

Usage: python bindings/python/tests/test_wheel_packaging.py
Requires a native library/CLI built from the current commit
(``zig build -Doptimize=ReleaseSafe``) or ``SAFEGGUF_LIB_PATH``, plus pip,
setuptools, packaging, and the venv module.
"""

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from packaging.version import Version

HERE = Path(__file__).resolve().parent
PACKAGE_ROOT = HERE.parent
REPO_ROOT = PACKAGE_ROOT.parents[1]
PYTHON = sys.executable
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "valid.gguf"

PROBE = r'''
import json
import sys
from pathlib import Path

import safegguf

missing = Path.cwd() / "definitely-missing.gguf"
io_result = safegguf.validate_path(str(missing))

info = {
    "package_file": safegguf.__file__,
    "lib_path": safegguf.core._find_library(),
    "native_version": safegguf.version(),
    "dunder_version": safegguf.__version__,
    "io_exit_code": io_result.exit_code,
    "sys_path": list(sys.path),
}
if len(sys.argv) > 1:
    fixture_result = safegguf.validate_path(sys.argv[1], profile="gguf-spec")
    info["fixture_exit_code"] = fixture_result.exit_code
    info["fixture_status"] = fixture_result.status
print(json.dumps(info))
'''


def platform_library_names():
    if sys.platform == "win32":
        return ("safegguf.dll", "libsafegguf.dll")
    if sys.platform == "darwin":
        return ("libsafegguf.dylib", "safegguf.dylib")
    return ("libsafegguf.so", "safegguf.so")


def reference_library():
    override = os.environ.get("SAFEGGUF_LIB_PATH")
    if override:
        path = Path(override)
        assert path.is_file(), f"SAFEGGUF_LIB_PATH is not a regular file: {override}"
        return path.resolve()
    for name in platform_library_names():
        for sub in ("lib", "bin"):
            candidate = REPO_ROOT / "zig-out" / sub / name
            if candidate.is_file():
                return candidate.resolve()
    raise AssertionError(
        "native safegguf library not found; run `zig build -Doptimize=ReleaseSafe` "
        "or set SAFEGGUF_LIB_PATH"
    )


def load_setup_module():
    spec = importlib.util.spec_from_file_location(
        "safegguf_setup_under_test", PACKAGE_ROOT / "setup.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(command, cwd):
    proc = subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f"command failed ({proc.returncode}): {' '.join(map(str, command))}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    return proc


def create_venv(venv, cwd):
    """Create a virtual environment, tolerating system Pythons without ensurepip."""
    proc = subprocess.run(
        [PYTHON, "-m", "venv", str(venv)], cwd=str(cwd), capture_output=True, text=True
    )
    if proc.returncode == 0:
        return
    shutil.rmtree(venv, ignore_errors=True)
    run([PYTHON, "-m", "venv", "--without-pip", str(venv)], cwd=cwd)


def install_wheel(venv_python, wheel, cwd):
    install_args = [
        "install", "--no-index", "--no-deps", "--disable-pip-version-check", str(wheel)
    ]
    probe = subprocess.run(
        [str(venv_python), "-m", "pip", "--version"], capture_output=True, text=True
    )
    if probe.returncode == 0:
        run([str(venv_python), "-m", "pip", *install_args], cwd=cwd)
    else:
        # Debian/Ubuntu system interpreters may lack ensurepip; let the host
        # pip install into the venv interpreter it is pointed at.
        run([PYTHON, "-m", "pip", "--python", str(venv_python), *install_args], cwd=cwd)


def check_provenance_gate(setup_module, lib_path):
    head = setup_module.git_head()
    if head is None:
        print("  (skipped provenance-gate negatives: not a git checkout)")
        return
    for cli_path, cli_commit, label in (
        (Path("zig-out/bin/safegguf"), "0" * 40, "a CLI from another commit"),
        (None, None, "a missing CLI"),
    ):
        try:
            setup_module.assert_fresh_native_artifacts(lib_path, head, cli_path, cli_commit)
        except setup_module.NativeArtifactsError:
            pass
        else:
            raise AssertionError(f"provenance gate accepted {label}")
    setup_module.assert_fresh_native_artifacts(
        lib_path, head, Path("zig-out/bin/safegguf"), head
    )
    print("  Provenance gate refuses foreign/missing CLI commits and accepts the matching one.")


def main():
    lib_path = reference_library()
    setup_module = load_setup_module()
    ref_version = setup_module.read_native_version(lib_path)
    print(f"Reference native library: {lib_path}")
    print(f"Reference native version: {ref_version}")

    check_provenance_gate(setup_module, lib_path)

    with tempfile.TemporaryDirectory(prefix="safegguf-wheel-") as tmp_name:
        tmp = Path(tmp_name)
        wheel_dir = tmp / "dist"
        wheel_dir.mkdir()

        # Build with the host interpreter and no build isolation so the test
        # stays offline; the declared build requirements must already be
        # importable (setuptools, packaging).
        run(
            [
                PYTHON, "-m", "pip", "wheel",
                "--no-deps", "--no-build-isolation",
                "--wheel-dir", str(wheel_dir),
                str(PACKAGE_ROOT),
            ],
            cwd=tmp,
        )
        wheels = sorted(wheel_dir.glob("safegguf-*.whl"))
        assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
        wheel = wheels[0]
        print(f"Built wheel: {wheel.name}")

        dist_version = wheel.name.split("-")[1]
        assert dist_version == str(Version(ref_version)), (
            f"wheel version {dist_version!r} does not normalize to the native "
            f"version {ref_version!r}"
        )
        assert not wheel.name.endswith("-any.whl"), (
            "wheel bundles a native library and must be platform-specific"
        )

        with zipfile.ZipFile(wheel) as archive:
            lib_entries = [
                name
                for name in archive.namelist()
                if Path(name).name in platform_library_names()
            ]
            assert len(lib_entries) == 1, (
                f"wheel must contain exactly one native library, got {lib_entries}"
            )
            bundled_lib = archive.read(lib_entries[0])

            metadata_name = next(
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            )
            metadata = archive.read(metadata_name).decode("utf-8")
            metadata_version = next(
                line.split(":", 1)[1].strip()
                for line in metadata.splitlines()
                if line.startswith("Version:")
            )
            assert metadata_version == str(Version(ref_version)), (
                f"METADATA version {metadata_version!r} != {str(Version(ref_version))!r}"
            )

            version_module = archive.read("safegguf/_version.py").decode("utf-8")

        bundled_sha256 = hashlib.sha256(bundled_lib).hexdigest()
        reference_sha256 = setup_module.sha256(lib_path)
        assert bundled_sha256 == reference_sha256, (
            "wheel does not bundle the native library it was built from: "
            f"{bundled_sha256} != {reference_sha256}"
        )
        assert f'__version__ = "{ref_version}"' in version_module
        assert f'__lib_sha256__ = "{bundled_sha256}"' in version_module
        head = setup_module.git_head()
        if head is not None:
            assert f'__source_commit__ = "{head}"' in version_module, (
                "wheel build did not record the checked-out commit"
            )
        print("  Wheel bundles the reference library; metadata and version module match.")

        venv = tmp / "venv"
        create_venv(venv, tmp)
        if sys.platform == "win32":
            venv_python = venv / "Scripts" / "python.exe"
        else:
            venv_python = venv / "bin" / "python"
        install_wheel(venv_python, wheel, tmp)

        probe = tmp / "probe.py"
        probe.write_text(PROBE, encoding="utf-8")
        command = [str(venv_python), str(probe)]
        fixture_copy = None
        if FIXTURE.is_file():
            fixture_copy = tmp / "valid.gguf"
            shutil.copy2(FIXTURE, fixture_copy)
            command.append(str(fixture_copy))
        proc = run(command, cwd=tmp)
        info = json.loads(proc.stdout.strip().splitlines()[-1])

        assert info["native_version"] == ref_version
        assert info["dunder_version"] == ref_version, (
            f"__version__ {info['dunder_version']!r} != bundled native version "
            f"{ref_version!r}"
        )
        venv_root = venv.resolve()
        assert Path(info["package_file"]).resolve().is_relative_to(venv_root), (
            f"imported package lives outside the venv: {info['package_file']}"
        )
        assert Path(info["lib_path"]).resolve().is_relative_to(venv_root), (
            f"native library resolved outside the venv: {info['lib_path']}"
        )
        assert all(str(REPO_ROOT) not in entry for entry in info["sys_path"]), (
            f"venv import still reflects the repository on sys.path: {info['sys_path']}"
        )
        assert info["io_exit_code"] == 74, (
            f"native validation call failed unexpectedly: exit {info['io_exit_code']}"
        )
        if fixture_copy is not None:
            assert info["fixture_exit_code"] == 0, (
                f"valid fixture rejected by the bundled library: {info}"
            )
            assert info["fixture_status"] == "PASS"
        else:
            print("  (skipped fixture validation: tests/fixtures/valid.gguf not generated)")
        print("  Clean-venv install imports and validates with no repository on sys.path.")

    print("\nAll Python wheel packaging tests passed.")


if __name__ == "__main__":
    main()
