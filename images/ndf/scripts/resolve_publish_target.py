#!/usr/bin/env python3
"""Resolve the GHCR repository and immutable source tag for an NDF image."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


class PublishTargetError(Exception):
    """Raised when an image cannot be resolved to a safe publishing target."""


def resolve_publish_target(
    ndf_dir: Path,
    image_id: str,
    source_sha: str,
) -> dict[str, str]:
    """Resolve an image definition to its repository and framework-qualified SHA tag."""
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_sha):
        raise PublishTargetError("Source commit must be a full 40-character Git SHA.")

    definitions_path = ndf_dir / "image-definitions" / "images-v1.json"
    manifests_dir = ndf_dir / "manifests"

    try:
        definitions: dict[str, Any] = json.loads(
            definitions_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise PublishTargetError(
            f"Unable to read image definitions {definitions_path}: {exc}"
        ) from exc

    matches = [
        item for item in definitions.get("images", []) if item.get("id") == image_id
    ]
    if len(matches) != 1:
        raise PublishTargetError(
            f"Expected exactly one image definition for '{image_id}'."
        )

    image = matches[0]
    manifest_relative_path = Path(image["manifest"])
    if manifest_relative_path.is_absolute() or ".." in manifest_relative_path.parts:
        raise PublishTargetError(
            f"Unsafe manifest path in image definition: {image['manifest']!r}"
        )

    manifest_path = manifests_dir / manifest_relative_path
    try:
        manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublishTargetError(
            f"Unable to read product manifest {manifest_path}: {exc}"
        ) from exc

    framework_version = str(manifest.get("framework", {}).get("version", ""))
    framework_match = re.match(r"^(\d+)(?:\.|$)", framework_version)
    if not framework_match:
        raise PublishTargetError(
            f"Invalid framework version in manifest: {framework_version!r}"
        )

    repository = image.get("repository")
    if not isinstance(repository, str) or not repository.startswith(
        "ghcr.io/ndftechlabs/"
    ):
        raise PublishTargetError(
            f"Image '{image_id}' does not target an approved NDF GHCR repository."
        )

    framework_major = framework_match.group(1)
    tag = f"v{framework_major}-{source_sha.lower()}"
    return {
        "image_id": image_id,
        "repository": repository,
        "framework_major": framework_major,
        "tag": tag,
        "image_ref": f"{repository}:{tag}",
        "source_sha": source_sha.lower(),
    }


def main() -> int:
    repository_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(
        description="Resolve an NDF product image to its GHCR publishing target."
    )
    parser.add_argument("--image", required=True, help="NDF image definition ID.")
    parser.add_argument(
        "--sha",
        required=True,
        help="Full 40-character source Git SHA.",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        help="Optional GitHub Actions output file to append resolved values to.",
    )
    args = parser.parse_args()

    try:
        target = resolve_publish_target(
            repository_root / "images" / "ndf",
            args.image,
            args.sha,
        )
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as output:
                for key, value in target.items():
                    output.write(f"{key}={value}\n")
        else:
            print(json.dumps(target, indent=2, sort_keys=True))
    except (OSError, PublishTargetError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
