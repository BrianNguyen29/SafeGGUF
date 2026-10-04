#!/usr/bin/env python3
"""Check source metadata and require release tags to match VERSION.

VERSION declares the intended source release, independently of historical tag
numbers. Tagged publication must use that exact version. Source checks do not
claim that the release has already been published.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")


def check(root: Path, release_ref: str = "") -> list[str]:
    findings = []
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        return ["VERSION must contain a stable semantic version such as 0.1.0"]
    build = (root / "build.zig").read_text(encoding="utf-8")
    if not re.search(r'addOption\(\[\]const u8, "version"[^;]*@embedFile\("VERSION"\)', build):
        findings.append("build.zig must derive the default version from VERSION")
    docker = (root / "Dockerfile").read_text(encoding="utf-8")
    default = re.search(r"^ARG SAFEGGUF_VERSION=(\S+)$", docker, re.MULTILINE)
    if default is None or default.group(1) != version:
        findings.append("Dockerfile SAFEGGUF_VERSION must match VERSION")
    readme = (root / "README.md").read_text(encoding="utf-8")
    if f"Source version: **{version}**" not in readme:
        findings.append("README source version must match VERSION")
    if not (root / "docs" / f"release-notes-{version}.md").is_file():
        findings.append("Release notes for VERSION are missing")
    if release_ref.startswith("refs/tags/") and release_ref != f"refs/tags/v{version}":
        findings.append(f"Release tag must be refs/tags/v{version}; received {release_ref}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    args = parser.parse_args()
    try:
        findings = check(args.root, args.ref)
    except (OSError, UnicodeError) as exc:
        print(f"FAIL: release metadata could not be read ({type(exc).__name__})", file=sys.stderr)
        return 1
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}", file=sys.stderr)
        return 1
    version = (args.root / "VERSION").read_text(encoding="utf-8").strip()
    print(f"PASS: source metadata agrees on {version}; release tag matches when provided.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
