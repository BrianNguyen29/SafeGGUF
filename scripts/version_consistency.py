#!/usr/bin/env python3
"""Fail when the embedded build default drifts from the latest release tag.

`build.zig` embeds the default version reported by source builds; the release
workflow overrides it per tag with `-Dversion=<value>`. If the embedded default
does not match the newest `v*` tag, a plain `zig build` from `main` reports a
different release than the one published -- the drift this check catches.

Usage: python3 scripts/version_consistency.py
Exit:  0 when the embedded default matches the latest tag, 1 on drift, an
       unparseable build.zig, or a shallow checkout that hides the tags.
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_ZIG = REPO_ROOT / "build.zig"
VERSION_FALLBACK_RE = re.compile(
    r'addOption\(\[\]const u8, "version"[^;]*?orelse\s+"([^"]+)"'
)


def git(*args):
    """Run git in the repository root; return stdout, or None on any failure."""
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def embedded_default_version():
    match = VERSION_FALLBACK_RE.search(BUILD_ZIG.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def latest_release_tag():
    output = git("tag", "--list", "v*", "--sort=-v:refname")
    if output is None:
        return None
    tags = [line.strip() for line in output.splitlines() if line.strip()]
    return tags[0] if tags else None


def is_shallow_checkout():
    output = git("rev-parse", "--is-shallow-repository")
    return output is not None and output.strip() == "true"


def main():
    if not BUILD_ZIG.is_file():
        print(f"FAIL: build.zig not found at {BUILD_ZIG}", file=sys.stderr)
        return 1

    embedded = embedded_default_version()
    if embedded is None:
        print(
            'FAIL: could not find the embedded version fallback in build.zig '
            '(expected `addOption([]const u8, "version", ... orelse "<version>")`)',
            file=sys.stderr,
        )
        return 1
    print(f"embedded default version (build.zig): {embedded}")

    tag = latest_release_tag()
    if tag is None:
        if is_shallow_checkout():
            print(
                "FAIL: shallow checkout hides the release tags; fetch them first "
                "(`git fetch --tags`, or use actions/checkout with fetch-depth: 0)",
                file=sys.stderr,
            )
            return 1
        print("SKIP: no git repository or no v* tags to compare against")
        return 0

    expected = tag[1:] if tag.startswith("v") else tag
    if embedded == expected or (embedded.endswith("-dev")):
        print(f"OK: embedded version '{embedded}' is valid (tracks latest release tag {tag})")
        return 0

    print(
        f"FAIL: embedded default version '{embedded}' != latest release tag '{tag}'",
        file=sys.stderr,
    )
    print(
        "  A source build would report a version that does not match the latest "
        "release. Update the `orelse` fallback in build.zig (release artifacts "
        "are overridden per tag with -Dversion), or cut the tag that matches "
        "the embedded default.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
