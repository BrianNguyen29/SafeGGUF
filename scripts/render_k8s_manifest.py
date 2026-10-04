#!/usr/bin/env python3
"""Render the integration template from an explicitly supplied release digest.

This performs no network calls and never applies the manifest. The release
workflow supplies its just-built, signed image; operators must verify signatures
before supplying an image manually. A syntactically valid digest is not proof
that an image exists or is trusted.
"""
import argparse
import re
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "deploy/k8s/safegguf-initcontainer.yaml"
IMAGE_PATTERN = re.compile(
    r"ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*:"
    r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?)@sha256:[0-9a-f]{64}"
)


def render(image: str, version: str) -> str:
    match = IMAGE_PATTERN.fullmatch(image)
    if match is None or match.group("version") != version:
        raise ValueError("use a lowercase ghcr.io owner/image:VERSION@sha256:DIGEST matching --version")
    source = TEMPLATE.read_text(encoding="utf-8")
    for marker in ("SAFEGGUF_RELEASE_IMAGE", "SAFEGGUF_RELEASE_VERSION"):
        if source.count(marker) != 1:
            raise ValueError(f"template must contain exactly one {marker}")
    return source.replace("SAFEGGUF_RELEASE_IMAGE", image).replace("SAFEGGUF_RELEASE_VERSION", version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validator-image", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        content = render(args.validator_image, args.version)
        # Preserve an existing deliverable; select a new output filename.
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Rendered {args.output}; verify target namespace/PVC and image signatures before deployment.")


if __name__ == "__main__":
    main()
