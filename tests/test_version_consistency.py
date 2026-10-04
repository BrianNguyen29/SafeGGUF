#!/usr/bin/env python3
"""Release metadata and tag mismatch regression checks."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "version_consistency", Path(__file__).resolve().parents[1] / "scripts/version_consistency.py"
)
VERSIONS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERSIONS)


class VersionConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="safegguf-release-version-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        (self.root / "docs").mkdir()
        self.write("VERSION", "0.1.0\n")
        self.write("build.zig", 'build_options.addOption([]const u8, "version", @embedFile("VERSION"));')
        self.write("Dockerfile", "ARG SAFEGGUF_VERSION=0.1.0\n")
        self.write("README.md", "Source version: **0.1.0**\n")
        self.write("docs/release-notes-0.1.0.md", "# SafeGGUF 0.1.0\n")

    def write(self, name, text):
        (self.root / name).write_text(text, encoding="utf-8")

    def test_source_and_matching_release_tag_pass(self):
        for ref in ("", "refs/heads/main", "refs/pull/1/merge", "refs/tags/v0.1.0"):
            with self.subTest(ref=ref):
                self.assertEqual(VERSIONS.check(self.root, ref), [])

    def test_mismatched_tags_fail(self):
        for ref in ("refs/tags/v0.3.6", "refs/tags/v0.1.1", "refs/tags/0.1.0", "refs/tags/v0.1.0-rc.1"):
            with self.subTest(ref=ref):
                self.assertTrue(VERSIONS.check(self.root, ref))

    def test_metadata_drift_fails(self):
        for name, value in (
            ("Dockerfile", "ARG SAFEGGUF_VERSION=0.1.1\n"),
            ("README.md", "Source version: **0.1.1**\n"),
            ("build.zig", 'build_options.addOption([]const u8, "version", "0.1.0");'),
        ):
            with self.subTest(name=name):
                original = (self.root / name).read_text()
                self.write(name, value)
                self.assertTrue(VERSIONS.check(self.root))
                self.write(name, original)

    def test_missing_release_notes_fail(self):
        (self.root / "docs/release-notes-0.1.0.md").unlink()
        self.assertTrue(VERSIONS.check(self.root))

    def test_noncanonical_version_fails(self):
        for value in ("01.1.0", "v0.1.0", "0.1.0-dev", "0.1", ""):
            with self.subTest(value=value):
                self.write("VERSION", value)
                self.assertTrue(VERSIONS.check(self.root))


if __name__ == "__main__":
    unittest.main()
