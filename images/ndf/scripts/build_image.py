#!/usr/bin/env python3
"""Build an NDF product image locally or publish it with Docker Buildx.

Local loading is the safe default. Registry publishing requires the explicit
--push flag and supports multiple tags and target platforms.
"""

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from .prepare_build import BuildPreparationError, prepare_build
except ImportError:
    from prepare_build import BuildPreparationError, prepare_build


class BuildExecutionError(Exception):
    """Raised when a product image build cannot be completed."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildExecutionError(
            f"Unable to read build metadata {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise BuildExecutionError(f"Expected a JSON object in {path}")
    return data


def get_manifest_checksum(lock_data: dict[str, Any], manifest_path: str) -> str:
    """Return the source manifest checksum recorded in the validated lock."""
    matches = [
        item
        for item in lock_data.get("manifests", [])
        if item.get("path") == manifest_path
    ]
    if len(matches) != 1:
        raise BuildExecutionError(
            f"Expected exactly one lock checksum for manifest '{manifest_path}'."
        )
    return matches[0]["sha256"]


def build_labels(
    metadata: dict[str, Any],
    lock_data: dict[str, Any],
) -> dict[str, str]:
    """Create OCI and NDF labels for build traceability."""
    image = metadata["image"]
    framework = metadata["framework"]
    applications = [
        {
            "name": app["name"],
            "target_ref": app["target_ref"],
            "resolved_sha": app["resolved_sha"],
        }
        for app in metadata["applications"]
    ]

    return {
        "org.opencontainers.image.title": image["product"],
        "org.opencontainers.image.source": "https://github.com/NdfTechLabs/frappe_docker",
        "org.opencontainers.image.url": "https://github.com/NdfTechLabs/frappe_docker",
        "com.ndf.image.id": image["id"],
        "com.ndf.product": image["product"],
        "com.ndf.manifest.path": image["manifest"],
        "com.ndf.manifest.sha256": get_manifest_checksum(
            lock_data,
            image["manifest"],
        ),
        "com.ndf.framework.name": framework["name"],
        "com.ndf.framework.version": framework["version"],
        "com.ndf.framework.target-ref": framework["target_ref"],
        "com.ndf.lock.sha256": metadata["lock"]["sha256"],
        "com.ndf.applications": json.dumps(
            applications,
            separators=(",", ":"),
            sort_keys=True,
        ),
    }


def normalize_platforms(platform: str | None) -> list[str]:
    """Parse and validate a comma-separated Buildx platform list."""
    if not platform:
        return []

    platforms = [value.strip() for value in platform.split(",") if value.strip()]
    if not platforms:
        raise BuildExecutionError("At least one valid platform must be supplied.")

    if len(platforms) != len(set(platforms)):
        raise BuildExecutionError("Duplicate target platforms are not allowed.")

    for value in platforms:
        if "/" not in value:
            raise BuildExecutionError(
                f"Invalid platform '{value}'. Expected values such as linux/amd64."
            )

    return platforms


def build_command(
    *,
    repository_root: Path,
    dockerfile: Path,
    apps_json: Path,
    image_repository: str,
    image_tag: str | None,
    frappe_branch: str,
    labels: dict[str, str],
    platform: str | None = None,
    no_cache: bool = False,
    builder: str | None = None,
    progress: str = "plain",
    cache_from: list[str] | None = None,
    cache_to: list[str] | None = None,
    push: bool = False,
    image_tags: list[str] | None = None,
    metadata_file: Path | None = None,
) -> list[str]:
    """Construct a deterministic local-load or registry-push Buildx command."""
    tags = image_tags or ([image_tag] if image_tag else [])
    if not tags:
        raise BuildExecutionError("At least one image tag must be supplied.")

    command = ["docker", "buildx", "build", "--push" if push else "--load"]
    command.extend(
        [
            "--pull",
            "--file",
            str(dockerfile.relative_to(repository_root)),
        ]
    )

    for tag in tags:
        command.extend(["--tag", f"{image_repository}:{tag}"])

    command.extend(
        [
            "--build-arg",
            f"FRAPPE_BRANCH={frappe_branch}",
            "--build-arg",
            "FRAPPE_PATH=https://github.com/frappe/frappe",
            "--secret",
            f"id=apps_json,src={apps_json}",
            "--progress",
            progress,
        ]
    )

    if metadata_file:
        command.extend(["--metadata-file", str(metadata_file)])

    if platform:
        command.extend(["--platform", platform])

    if no_cache:
        command.append("--no-cache")

    if builder:
        command.extend(["--builder", builder])

    for cache_ref in cache_from or []:
        command.extend(["--cache-from", cache_ref])

    for cache_ref in cache_to or []:
        command.extend(["--cache-to", cache_ref])

    for name, value in sorted(labels.items()):
        command.extend(["--label", f"{name}={value}"])

    command.append(str(repository_root))
    return command


def execute_build(
    command: list[str],
    *,
    dry_run: bool = False,
    metadata_file: Path | None = None,
) -> dict[str, Any] | None:
    """Check Buildx, execute the build and return Buildx metadata when present."""
    print(shlex.join(command))

    if dry_run:
        print("Dry run: Docker build was not executed.")
        return None

    try:
        version = subprocess.run(
            ["docker", "buildx", "version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise BuildExecutionError(f"Unable to execute Docker: {exc}") from exc

    if version.returncode != 0:
        detail = (version.stderr or version.stdout).strip()
        raise BuildExecutionError(
            "Docker Buildx is unavailable or not working"
            + (f": {detail}" if detail else ".")
        )

    try:
        result = subprocess.run(command, check=False)
    except OSError as exc:
        raise BuildExecutionError(f"Unable to start Docker Buildx: {exc}") from exc

    if result.returncode != 0:
        raise BuildExecutionError(
            f"Docker Buildx failed with exit code {result.returncode}."
        )

    if metadata_file is None or not metadata_file.is_file():
        return None

    try:
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildExecutionError(
            f"Unable to read Buildx metadata file {metadata_file}: {exc}"
        ) from exc

    if not isinstance(metadata, dict):
        raise BuildExecutionError("Buildx metadata must be a JSON object.")

    return metadata


def build_image(
    *,
    repository_root: Path,
    image_id: str,
    image_tag: str | None = None,
    image_tags: list[str] | None = None,
    push: bool = False,
    definitions_relative_path: str = "image-definitions/images-v1.json",
    output_dir: Path | None = None,
    platform: str | None = None,
    no_cache: bool = False,
    builder: str | None = None,
    progress: str = "plain",
    cache_from: list[str] | None = None,
    cache_to: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Prepare and build one NDF product image locally or to a registry."""
    repository_root = repository_root.resolve()
    ndf_dir = repository_root / "images" / "ndf"
    dockerfile = repository_root / "images" / "layered" / "Containerfile"

    if not dockerfile.is_file():
        raise BuildExecutionError(f"Layered Containerfile not found: {dockerfile}")

    platforms = normalize_platforms(platform)
    if not push and len(platforms) > 1:
        raise BuildExecutionError(
            "Local --load supports one platform. Use --push for multi-platform builds."
        )

    prepared = prepare_build(
        ndf_dir=ndf_dir,
        image_id=image_id,
        definitions_relative_path=definitions_relative_path,
        output_dir=output_dir,
    )

    metadata = load_json(prepared["metadata_path"])
    lock_data = load_json(prepared["lock_path"])
    labels = build_labels(metadata, lock_data)

    image = prepared["image"]
    framework = prepared["framework"]
    tags = image_tags or ([image_tag] if image_tag else ["local"])
    if any(not tag or any(char.isspace() for char in tag) for tag in tags):
        raise BuildExecutionError(
            "Image tags must be non-empty and contain no whitespace."
        )

    build_output_dir = Path(prepared["metadata_path"]).parent
    build_output_dir.mkdir(parents=True, exist_ok=True)
    buildx_metadata_path = build_output_dir / "buildx-metadata.json"
    build_result_path = build_output_dir / "build-result.json"
    buildx_metadata_path.unlink(missing_ok=True)
    build_result_path.unlink(missing_ok=True)

    command = build_command(
        repository_root=repository_root,
        dockerfile=dockerfile,
        apps_json=prepared["apps_json_path"],
        image_repository=image["repository"],
        image_tag=None,
        image_tags=tags,
        frappe_branch=framework["target_ref"],
        labels=labels,
        platform=platform,
        no_cache=no_cache,
        builder=builder,
        progress=progress,
        cache_from=cache_from,
        cache_to=cache_to,
        push=push,
        metadata_file=buildx_metadata_path,
    )

    buildx_metadata = execute_build(
        command,
        dry_run=dry_run,
        metadata_file=buildx_metadata_path,
    )
    digest = (
        buildx_metadata.get("containerimage.digest")
        if buildx_metadata
        else None
    )

    result = {
        "schema_version": "1.0",
        "image_id": image["id"],
        "repository": image["repository"],
        "tags": tags,
        "image_refs": [f"{image['repository']}:{tag}" for tag in tags],
        "output": "registry" if push else "local",
        "pushed": push and not dry_run,
        "platforms": platforms,
        "digest": digest,
        "buildx_metadata_file": str(buildx_metadata_path),
        "dry_run": dry_run,
    }

    if not dry_run:
        build_result_path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return {
        "image": image,
        "tags": tags,
        "command": command,
        "metadata_path": prepared["metadata_path"],
        "apps_json_path": prepared["apps_json_path"],
        "buildx_metadata_path": buildx_metadata_path,
        "build_result_path": build_result_path,
        "digest": digest,
        "push": push,
        "dry_run": dry_run,
    }


def main() -> int:
    repository_root = Path(__file__).resolve().parents[3]

    parser = argparse.ArgumentParser(
        description="Prepare and build an NDF product image with Docker Buildx."
    )
    parser.add_argument(
        "--image",
        required=True,
        help="Image ID from images/ndf/image-definitions/images-v1.json.",
    )
    parser.add_argument(
        "--tag",
        action="append",
        dest="image_tags",
        help="Image tag (repeat to apply multiple tags). Defaults to 'local'.",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help=(
            "Push the image to its configured registry. Without this flag, --load is used."
        ),
    )
    parser.add_argument(
        "--definitions",
        default="image-definitions/images-v1.json",
        help="Image definitions path relative to images/ndf.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Build-input output directory (defaults to images/ndf/.build/<image-id>).",
    )
    parser.add_argument(
        "--platform",
        help=(
            "Target platform or comma-separated platforms, e.g. linux/amd64,linux/arm64."
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Build without using the Docker layer cache.",
    )
    parser.add_argument("--builder", help="Optional Docker Buildx builder instance.")
    parser.add_argument(
        "--progress",
        choices=("auto", "plain", "tty", "quiet"),
        default="plain",
        help="Docker Buildx progress output mode.",
    )
    parser.add_argument(
        "--cache-from",
        action="append",
        default=[],
        metavar="BACKEND",
        help="Buildx cache source (repeatable), e.g. type=gha,scope=ndf-dalali-v16.",
    )
    parser.add_argument(
        "--cache-to",
        action="append",
        default=[],
        metavar="BACKEND",
        help=(
            "Buildx cache destination (repeatable), e.g. "
            "type=gha,mode=max,scope=ndf-dalali-v16."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Prepare inputs and print the command without running Docker.",
    )

    args = parser.parse_args()

    try:
        result = build_image(
            repository_root=repository_root,
            image_id=args.image,
            image_tags=args.image_tags,
            push=args.push,
            definitions_relative_path=args.definitions,
            output_dir=args.output_dir,
            platform=args.platform,
            no_cache=args.no_cache,
            builder=args.builder,
            progress=args.progress,
            cache_from=args.cache_from,
            cache_to=args.cache_to,
            dry_run=args.dry_run,
        )
    except (BuildPreparationError, BuildExecutionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    image_refs = [
        f"{result['image']['repository']}:{tag}" for tag in result["tags"]
    ]
    print(f"Image: {', '.join(image_refs)}")
    print(f"Build metadata: {result['metadata_path']}")
    if result["digest"]:
        print(f"Image digest: {result['digest']}")
    if result["dry_run"]:
        print("Build command validated; no image was created or pushed.")
    elif result["push"]:
        print("Registry image build and push completed.")
    else:
        print("Local image build completed. No registry push was performed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
