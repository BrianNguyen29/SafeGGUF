#!/usr/bin/env python3
"""Exercise publication boundaries against real disposable Git indexes."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "public_tree", Path(__file__).resolve().parents[1] / "scripts/check_public_tree.py"
)
PUBLIC_TREE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLIC_TREE)


class PublicTreeTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="safegguf-public-tree-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.git("init", "--quiet")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], stderr=subprocess.PIPE
        )

    def write(self, path, content, stage=True):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        if stage:
            self.git("add", "--", path)

    def test_untracked_local_records_do_not_block_public_tree(self):
        self.write("README.md", "[API](docs/api.md)\n")
        self.write("docs/api.md", "# Public API\n")
        self.write("docs/runbooks/local.md", "local record", stage=False)
        self.assertEqual(PUBLIC_TREE.check(self.root), [])

    def test_staged_local_records_are_rejected(self):
        paths = (
            "docs/archive/report.md", "docs/runbooks/incident.md", "docs/private/review.md",
            "docs/internal/record.md", "SESSION.md", "docs/release-validation-2030-01-01.md",
            "docs/release-readiness.md", "SafeGGUF_Production_Readiness_Plan.md",
            "download.md:Zone.Identifier", ".env.production",
        )
        for path in paths:
            if ":" in path and os.name == "nt":
                # Windows cannot create this WSL-style filename as a normal file.
                self.assertTrue(PUBLIC_TREE.local_record(path))
                continue
            self.write(path, "local record")
        findings = PUBLIC_TREE.check(self.root)
        for path in paths:
            if ":" not in path or os.name != "nt":
                self.assertTrue(any(path in finding for finding in findings), path)

    def test_relative_encoded_and_reference_links_are_rejected(self):
        self.write("docs/api.md", (
            "[local](../docs/runbooks/incident.md)\n"
            "[encoded](%72unbooks/incident.md)\n"
            "[record]: <release-readiness.md>\n"
            "[missing](absent.md)\n"
        ))
        findings = PUBLIC_TREE.check(self.root)
        self.assertEqual(len(findings), 4)
        self.assertTrue(any("absent.md" in finding for finding in findings))

    def test_working_tree_edits_cannot_hide_a_staged_private_link(self):
        self.write("README.md", "[private](docs/runbooks/incident.md)\n")
        self.write("README.md", "# Clean working tree\n", stage=False)
        self.assertTrue(PUBLIC_TREE.check(self.root))

    def test_unstaged_private_link_is_not_in_public_index(self):
        self.write("README.md", "# Public README\n")
        self.write("README.md", "[private](docs/runbooks/incident.md)\n", stage=False)
        self.assertEqual(PUBLIC_TREE.check(self.root), [])


if __name__ == "__main__":
    unittest.main()
