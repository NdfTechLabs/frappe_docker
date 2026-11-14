#!/usr/bin/env python3
"""Validate NDF image composition and bind post-Bench inventory to its image digest."""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, ValidationError


class ImageValidationError(Exception):
    """Raised when a built image does not match its expected composition or evidence."""


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "build-inventory-v1.schema.json"
DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ImageValidationError(f"Unable to read JSON file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ImageValidationError(f"Expected a JSON object in {path}")
    return data


def run_docker(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise ImageValidationError(f"Unable to execute Docker: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ImageValidationError(
            f"Docker command failed with exit code {result.returncode}: {detail}"
        )
    return result.stdout.strip()


def inspect_image_labels(image_ref: str) -> dict[str, str]:
    output = run_docker([
        "docker", "image", "inspect", image_ref, "--format", "{{json .Config.Labels}}"
    ])
    try:
        labels = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ImageValidationError(f"Docker returned invalid image-label JSON: {exc}") from exc
    if not isinstance(labels, dict):
        raise ImageValidationError("Image has no valid OCI/NDF label object.")
    return labels


def inspect_image_contents(image_ref: str) -> dict[str, Any]:
    """Read app composition and the exact inventory bytes from the runtime image."""
    inspection_code = (
        "import base64,json,pathlib;"
        "root=pathlib.Path('/home/frappe/frappe-bench/apps');"
        "apps_file=pathlib.Path('/home/frappe/frappe-bench/sites/apps.txt');"
        "inventory=pathlib.Path('/home/frappe/frappe-bench/build-evidence/build-inventory.json');"
        "raw=inventory.read_bytes();"
        "print(json.dumps({"
        "'directories':sorted(p.name for p in root.iterdir() if p.is_dir()),"
        "'apps_txt':[line.strip() for line in apps_file.read_text().splitlines() if line.strip()],"
        "'build_inventory_base64':base64.b64encode(raw).decode('ascii')"
        "}))"
    )
    output = run_docker([
        "docker", "run", "--rm", "--entrypoint", "bash", image_ref,
        "-lc", f"python -c {json.dumps(inspection_code)}"
    ])
    try:
        contents = json.loads(output)
        raw_inventory = base64.b64decode(contents.pop("build_inventory_base64"), validate=True)
        inventory = json.loads(raw_inventory)
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
        raise ImageValidationError(
            f"Container returned missing or invalid build inventory evidence: {exc}"
        ) from exc
    if not isinstance(contents, dict) or not isinstance(inventory, dict):
        raise ImageValidationError("Container returned an invalid image content/evidence report.")
    contents["build_inventory"] = inventory
    contents["build_inventory_bytes"] = raw_inventory
    return contents


def canonical_repository(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        host, path = parsed.hostname, parsed.path.strip("/").removesuffix(".git").lower()
    elif re.fullmatch(r"[^/@:]+/.+", raw):
        host, path = raw.split("/", 1)
        path = path.removesuffix(".git").lower()
    else:
        raise ImageValidationError("Unsupported repository URL or identity in lock/build evidence.")
    if not host or not path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ImageValidationError("Invalid repository URL or identity in lock/build evidence.")
    return f"{host.lower()}/{path}"


def validate_inventory(
    inventory: dict[str, Any],
    inventory_bytes: bytes,
    metadata: dict[str, Any],
    lock_data: dict[str, Any],
    lock_sha256: str,
    image_digest: str,
) -> dict[str, Any]:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(inventory)
    except (OSError, json.JSONDecodeError) as exc:
        raise ImageValidationError(f"Unable to load build-inventory schema: {exc}") from exc
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ImageValidationError(
            f"Build inventory schema validation failed at {location}: {exc.message}"
        ) from exc

    if inventory["lock"]["version"] != 2 or inventory["lock"]["sha256"] != lock_sha256:
        raise ImageValidationError("Build inventory lock identity does not match generated lock-v2.")
    if metadata.get("lock", {}).get("sha256") != lock_sha256:
        raise ImageValidationError("Build metadata lock SHA-256 does not match the generated lock-v2.")
    if lock_data.get("lock_version") != 2:
        raise ImageValidationError("Image validation requires generated lock-v2 data.")
    if not DIGEST_PATTERN.fullmatch(image_digest):
        raise ImageValidationError("Buildx metadata does not contain a valid image digest.")

    locked_apps = lock_data.get("applications")
    metadata_apps = metadata.get("applications")
    captured_apps = inventory["applications"]
    if not isinstance(locked_apps, list) or not isinstance(metadata_apps, list):
        raise ImageValidationError("Lock-v2 and build metadata must contain application lists.")

    def by_name(items: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
        names = [item.get("name") for item in items]
        if any(not isinstance(name, str) or not name for name in names):
            raise ImageValidationError(f"{label} contains an invalid application name.")
        if len(names) != len(set(names)):
            raise ImageValidationError(f"{label} contains duplicate application names.")
        return {item["name"]: item for item in items}

    locked = by_name(locked_apps, "Lock-v2")
    built = by_name(metadata_apps, "Build metadata")
    captured = by_name(captured_apps, "Build inventory")
    if set(locked) != set(built) or set(locked) != set(captured):
        raise ImageValidationError(
            "Application composition differs between lock-v2, build metadata and runtime inventory."
        )

    for name, locked_app in locked.items():
        metadata_app, captured_app = built[name], captured[name]
        expected_repo = canonical_repository(locked_app["repository"])
        if canonical_repository(metadata_app["repository"]) != expected_repo:
            raise ImageValidationError(f"Build metadata repository mismatch for {name}.")
        if canonical_repository(captured_app["repository"]) != expected_repo:
            raise ImageValidationError(f"Captured repository identity mismatch for {name}.")
        if metadata_app["target_ref"] != locked_app["target_ref"]:
            raise ImageValidationError(f"Build metadata requested ref mismatch for {name}.")
        if metadata_app["resolved_sha"] != locked_app.get("ref"):
            raise ImageValidationError(f"Build metadata resolver commit mismatch for {name}.")
        if captured_app["requested_ref"] != locked_app["target_ref"]:
            raise ImageValidationError(f"Captured requested ref mismatch for {name}.")
        if captured_app["resolver_commit"] != locked_app.get("ref", ""):
            raise ImageValidationError(f"Captured resolver commit mismatch for {name}.")

    framework = captured.get("frappe")
    if framework is None or inventory.get("framework") != framework:
        raise ImageValidationError("Captured framework record does not match the application inventory.")
    if inventory["runtime"]["platform"]["oci"] != metadata.get("base_images", {}).get("platform"):
        raise ImageValidationError("Captured builder platform does not match the selected base-image platform.")

    inventory_sha256 = hashlib.sha256(inventory_bytes).hexdigest()
    return {
        "schema_version": "1.0",
        "image_digest": image_digest,
        "image_ref": metadata["image"]["repository"],
        "image_id": metadata["image"]["id"],
        "lock_sha256": lock_sha256,
        "inventory_sha256": inventory_sha256,
        "application_count": len(captured),
        "inventory_stage": inventory["stage"],
        "status": "bound",
    }


def validate_image(
    image_ref: str,
    metadata: dict[str, Any],
    lock_data: dict[str, Any],
    labels: dict[str, str],
    contents: dict[str, Any],
    lock_sha256: str,
    image_digest: str,
) -> dict[str, Any]:
    """Compare image labels/composition and bind its exact inventory bytes to the digest."""
    expected_apps = [app["name"] for app in metadata["applications"]]
    expected_app_set = set(expected_apps)
    if len(expected_apps) != len(expected_app_set):
        raise ImageValidationError("Build metadata contains duplicate application names.")

    actual_dirs, actual_apps_txt = contents.get("directories"), contents.get("apps_txt")
    if not isinstance(actual_dirs, list) or not isinstance(actual_apps_txt, list):
        raise ImageValidationError("Image inspection did not return application lists.")
    problems = []
    if expected_app_set != set(actual_dirs):
        problems.append(
            f"Application directory mismatch: missing={sorted(expected_app_set-set(actual_dirs))}, "
            f"unexpected={sorted(set(actual_dirs)-expected_app_set)}"
        )
    if expected_app_set != set(actual_apps_txt):
        problems.append(
            f"sites/apps.txt mismatch: missing={sorted(expected_app_set-set(actual_apps_txt))}, "
            f"unexpected={sorted(set(actual_apps_txt)-expected_app_set)}"
        )

    image, framework = metadata["image"], metadata["framework"]
    manifest_entries = [
        item for item in lock_data.get("manifests", [])
        if item.get("path") == image["manifest"]
    ]
    if len(manifest_entries) != 1:
        raise ImageValidationError(f"Expected exactly one lock checksum for '{image['manifest']}'.")
    expected_label_values = {
        "org.opencontainers.image.title": image["product"],
        "org.opencontainers.image.source": "https://github.com/NdfTechLabs/frappe_docker",
        "org.opencontainers.image.url": "https://github.com/NdfTechLabs/frappe_docker",
        "com.ndf.image.id": image["id"],
        "com.ndf.product": image["product"],
        "com.ndf.manifest.path": image["manifest"],
        "com.ndf.manifest.sha256": manifest_entries[0]["sha256"],
        "com.ndf.framework.name": framework["name"],
        "com.ndf.framework.version": framework["version"],
        "com.ndf.framework.target-ref": framework["target_ref"],
        "com.ndf.lock.sha256": lock_sha256,
    }
    for name, expected in expected_label_values.items():
        if labels.get(name) != expected:
            problems.append(
                f"Image label '{name}' mismatch: expected {expected!r}, got {labels.get(name)!r}"
            )

    expected_label_apps = [
        {"name": app["name"], "target_ref": app["target_ref"], "resolved_sha": app["resolved_sha"]}
        for app in metadata["applications"]
    ]
    try:
        actual_label_apps = json.loads(labels.get("com.ndf.applications", ""))
    except json.JSONDecodeError:
        actual_label_apps = None
    if actual_label_apps != expected_label_apps:
        problems.append("Image label 'com.ndf.applications' does not match build metadata.")
    if problems:
        raise ImageValidationError("\n".join(problems))

    inventory_bytes = contents.get("build_inventory_bytes")
    inventory = contents.get("build_inventory")
    if not isinstance(inventory_bytes, bytes) or not isinstance(inventory, dict):
        raise ImageValidationError("Runtime image does not contain build-inventory.json.")
    binding = validate_inventory(
        inventory, inventory_bytes, metadata, lock_data, lock_sha256, image_digest
    )
    return {
        "image": image_ref,
        "image_digest": image_digest,
        "product": image["product"],
        "image_id": image["id"],
        "framework": framework,
        "application_count": len(expected_apps),
        "applications": expected_apps,
        "directories_verified": True,
        "apps_txt_verified": True,
        "labels_verified": True,
        "inventory_verified": True,
        "evidence_binding": binding,
        "status": "passed",
    }


def validate_from_files(
    image_ref: str,
    metadata_path: Path,
    lock_path: Path,
    buildx_metadata_path: Path,
    inventory_output_path: Path,
    evidence_output_path: Path,
) -> dict[str, Any]:
    metadata, lock_data = load_json(metadata_path), load_json(lock_path)
    buildx_metadata = load_json(buildx_metadata_path)
    image_digest = buildx_metadata.get("containerimage.digest")
    if not isinstance(image_digest, str) or not DIGEST_PATTERN.fullmatch(image_digest):
        raise ImageValidationError("Buildx metadata is missing a valid containerimage.digest.")
    lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    labels = inspect_image_labels(image_ref)
    contents = inspect_image_contents(image_ref)
    report = validate_image(
        image_ref, metadata, lock_data, labels, contents, lock_sha256, image_digest
    )
    inventory_bytes = contents["build_inventory_bytes"]
    inventory_output_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_output_path.write_bytes(inventory_bytes)
    evidence_output_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_output_path.write_text(
        json.dumps(report["evidence_binding"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate an NDF product image and bind captured inventory to its digest."
    )
    parser.add_argument("--image", required=True, help="Local Docker image reference.")
    parser.add_argument("--metadata", required=True, type=Path, help="Build metadata JSON.")
    parser.add_argument("--lock", required=True, type=Path, help="Generated lock-v2 JSON.")
    parser.add_argument("--buildx-metadata", required=True, type=Path, help="Buildx metadata JSON.")
    parser.add_argument("--inventory-output", required=True, type=Path, help="Extracted inventory artifact path.")
    parser.add_argument("--evidence-output", required=True, type=Path, help="Digest-binding evidence output path.")
    parser.add_argument("--report", type=Path, help="Optional JSON validation report path.")
    args = parser.parse_args()
    try:
        report = validate_from_files(
            args.image, args.metadata, args.lock, args.buildx_metadata,
            args.inventory_output, args.evidence_output,
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (ImageValidationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"Validated {report['application_count']} applications, runtime inventory and "
        f"OCI/NDF labels for {report['image']}."
    )
    print(f"Image digest: {report['image_digest']}")
    print(f"Inventory SHA-256: {report['evidence_binding']['inventory_sha256']}")
    print("Image validation and evidence binding passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
