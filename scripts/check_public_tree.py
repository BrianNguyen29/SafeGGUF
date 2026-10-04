#!/usr/bin/env python3
"""Reject local maintainer records in the Git index and public Markdown links.

This is a publication-boundary check, not a general-purpose secret scanner or
Git history scrubber. CI checks the committed tree; locally it checks exactly
what is staged, even when working-tree files differ.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


LOCAL_DIRECTORIES = ("docs/archive/", "docs/runbooks/", "docs/private/", "docs/internal/")
LOCAL_NAMES = (
    "session.md",
    "safegguf_*_plan.md",
    "release-readiness.md",
    "release-validation-*.md",
    "production_audit_report.md",
    "test_report.md",
    "security-review-package.md",
    "deep-review-fix-plan.md",
    "assurance-roadmap-issues.md",
    "remediation-*-exec-plan.md",
    "*:zone.identifier",
    ".env",
    ".env.*",
)
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(\s*(<[^>]*>|[^\s)]+)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(<[^>]*>|\S+)", re.MULTILINE)


def local_record(path: str) -> bool:
    normalized = path.replace("\\", "/").lower().lstrip("/")
    name = PurePosixPath(normalized).name
    return normalized.startswith(LOCAL_DIRECTORIES) or any(
        fnmatch.fnmatchcase(name, pattern) for pattern in LOCAL_NAMES
    )


def linked_path(document: str, target: str) -> str | None:
    parsed = urlsplit(unquote(target.strip("<>")))
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    base = [] if parsed.path.startswith("/") else list(PurePosixPath(document).parent.parts)
    for part in parsed.path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if base:
                base.pop()
        else:
            base.append(part)
    return "/".join(base)


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def check(root: Path) -> list[str]:
    paths = [p.decode("utf-8", "surrogateescape") for p in git(root, "ls-files", "-z").split(b"\0") if p]
    findings = []
    tracked = set(paths)
    for path in paths:
        if local_record(path):
            findings.append(f"local-only file is staged: {path}")
            continue
        if not path.lower().endswith(".md"):
            continue
        content = git(root, "show", f":{path}").decode("utf-8", "replace")
        for pattern in (MARKDOWN_LINK, REFERENCE_LINK):
            for match in pattern.finditer(content):
                destination = linked_path(path, match.group(1))
                if destination is None:
                    continue
                line = content.count("\n", 0, match.start()) + 1
                if local_record(destination):
                    findings.append(f"{path}:{line}: link to local-only record: {destination}")
                elif destination not in tracked and not any(p.startswith(destination.rstrip("/") + "/") for p in paths):
                    findings.append(f"{path}:{line}: link target absent from public tree: {destination}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        findings = check(args.root)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"Public tree check could not complete: {type(exc).__name__}", file=sys.stderr)
        return 2
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}", file=sys.stderr)
        return 1
    print("PASS: Git index contains no prohibited local records or broken Markdown links.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
