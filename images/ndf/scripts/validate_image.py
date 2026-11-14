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

try:
    from .verify_image_composition import (
        CompositionVerificationError,
        verify_composition,
    )
except ImportError:
    from verify_image_composition import CompositionVerificationError, verify_composition


class ImageValidationError(Exception):
    """Raised when a built image does not match its expected composition or evidence."""


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "build-inventory-v1.schema.json"
)
SOURCE_PROVENANCE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "source-provenance-v1.schema.json"
)
SOURCE_PROVENANCE_VERIFICATION_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "source-provenance-verification-v1.schema.json"
)
SOURCE_TREE_VERIFICATION_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "source-tree-verification-v1.schema.json"
)
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
    output = run_docker(
        ["docker", "image", "inspect", image_ref, "--format", "{{json .Config.Labels}}"]
    )
    try:
        labels = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ImageValidationError(
            f"Docker returned invalid image-label JSON: {exc}"
        ) from exc
    if not isinstance(labels, dict):
        raise ImageValidationError("Image has no valid OCI/NDF label object.")
    return labels


def inspect_image_contents(image_ref: str) -> dict[str, Any]:
    """Read composition and verify source fingerprints inside the final runtime image."""
    inspection_code = (
        "import base64,json,pathlib,subprocess;"
        "bench=pathlib.Path('/home/frappe/frappe-bench');"
        "evidence=bench/'build-evidence';"
        "provenance=evidence/'source-provenance.json';"
        "post=evidence/'source-tree-verification-post-cleanup.json';"
        "independent=evidence/'source-provenance-verification.json';"
        "runtime=pathlib.Path('/tmp/source-tree-verification-runtime.json');"
        "subprocess.run(['python','/opt/ndf/verify_source_tree.py','--bench',str(bench),"
        "'--provenance',str(provenance),'--stage','runtime_image','--output',str(runtime)],"
        "check=True,capture_output=True,text=True);"
        "inventory=(evidence/'build-inventory.json').read_bytes();independent_raw=independent.read_bytes();"
        "provenance_raw=provenance.read_bytes();post_raw=post.read_bytes();runtime_raw=runtime.read_bytes();"
        "apps=bench/'apps';apps_file=bench/'sites/apps.txt';"
        "print(json.dumps({"
        "'directories':sorted(p.name for p in apps.iterdir() if p.is_dir() and not p.name.startswith('.')),"
        "'apps_txt':[line.strip() for line in apps_file.read_text().splitlines() if line.strip()],"
        "'build_inventory_base64':base64.b64encode(inventory).decode('ascii'),"
        "'source_provenance_base64':base64.b64encode(provenance_raw).decode('ascii'),"
        "'source_provenance_verification_base64':base64.b64encode(independent_raw).decode('ascii'),"
        "'post_cleanup_verification_base64':base64.b64encode(post_raw).decode('ascii'),"
        "'runtime_verification_base64':base64.b64encode(runtime_raw).decode('ascii')"
        "}))"
    )
    output = run_docker(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "bash",
            image_ref,
            "-lc",
            f"python -c {json.dumps(inspection_code)}",
        ]
    )
    try:
        contents = json.loads(output)
        encoded = {
            key: base64.b64decode(contents.pop(key), validate=True)
            for key in (
                "build_inventory_base64",
                "source_provenance_base64",
                "source_provenance_verification_base64",
                "post_cleanup_verification_base64",
                "runtime_verification_base64",
            )
        }
        decoded = {key: json.loads(value) for key, value in encoded.items()}
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
        raise ImageValidationError(
            f"Container returned missing or invalid source/build evidence: {exc}"
        ) from exc
    if not isinstance(contents, dict) or not all(
        isinstance(item, dict) for item in decoded.values()
    ):
        raise ImageValidationError(
            "Container returned invalid image content/evidence objects."
        )
    contents.update(
        {
            "build_inventory": decoded["build_inventory_base64"],
            "build_inventory_bytes": encoded["build_inventory_base64"],
            "source_provenance": decoded["source_provenance_base64"],
            "source_provenance_bytes": encoded["source_provenance_base64"],
            "source_provenance_verification": decoded["source_provenance_verification_base64"],
            "source_provenance_verification_bytes": encoded["source_provenance_verification_base64"],
            "post_cleanup_verification": decoded["post_cleanup_verification_base64"],
            "post_cleanup_verification_bytes": encoded[
                "post_cleanup_verification_base64"
            ],
            "runtime_verification": decoded["runtime_verification_base64"],
            "runtime_verification_bytes": encoded["runtime_verification_base64"],
        }
    )
    return contents


def canonical_repository(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        host, path = (
            parsed.hostname,
            parsed.path.strip("/").removesuffix(".git").lower(),
        )
    elif re.fullmatch(r"[^/@:]+/.+", raw):
        host, path = raw.split("/", 1)
        path = path.removesuffix(".git").lower()
    else:
        raise ImageValidationError(
            "Unsupported repository URL or identity in lock/build evidence."
        )
    if not host or not path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ImageValidationError(
            "Invalid repository URL or identity in lock/build evidence."
        )
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
        raise ImageValidationError(
            f"Unable to load build-inventory schema: {exc}"
        ) from exc
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ImageValidationError(
            f"Build inventory schema validation failed at {location}: {exc.message}"
        ) from exc

    if inventory["lock"]["version"] != 2 or inventory["lock"]["sha256"] != lock_sha256:
        raise ImageValidationError(
            "Build inventory lock identity does not match generated lock-v2."
        )
    if metadata.get("lock", {}).get("sha256") != lock_sha256:
        raise ImageValidationError(
            "Build metadata lock SHA-256 does not match the generated lock-v2."
        )
    if lock_data.get("lock_version") != 2:
        raise ImageValidationError("Image validation requires generated lock-v2 data.")
    if not DIGEST_PATTERN.fullmatch(image_digest):
        raise ImageValidationError(
            "Buildx metadata does not contain a valid image digest."
        )

    locked_apps = lock_data.get("applications")
    metadata_apps = metadata.get("applications")
    captured_apps = inventory["applications"]
    if not isinstance(locked_apps, list) or not isinstance(metadata_apps, list):
        raise ImageValidationError(
            "Lock-v2 and build metadata must contain application lists."
        )

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
            raise ImageValidationError(
                f"Build metadata repository mismatch for {name}."
            )
        if canonical_repository(captured_app["repository"]) != expected_repo:
            raise ImageValidationError(
                f"Captured repository identity mismatch for {name}."
            )
        if metadata_app["target_ref"] != locked_app["target_ref"]:
            raise ImageValidationError(
                f"Build metadata requested ref mismatch for {name}."
            )
        if metadata_app["resolved_sha"] != locked_app.get("ref"):
            raise ImageValidationError(
                f"Build metadata resolver commit mismatch for {name}."
            )
        if captured_app["requested_ref"] != locked_app["target_ref"]:
            raise ImageValidationError(f"Captured requested ref mismatch for {name}.")
        if captured_app["resolver_commit"] != locked_app.get("ref", ""):
            raise ImageValidationError(f"Captured resolver commit mismatch for {name}.")

    framework = captured.get("frappe")
    if framework is None or inventory.get("framework") != framework:
        raise ImageValidationError(
            "Captured framework record does not match the application inventory."
        )
    if inventory["runtime"]["platform"]["oci"] != metadata.get("base_images", {}).get(
        "platform"
    ):
        raise ImageValidationError(
            "Captured builder platform does not match the selected base-image platform."
        )

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


def check_independent_submodules(
    observed: list[dict[str, Any]],
    expected_items: list[dict[str, Any]],
    label: str,
) -> None:
    by_path = {item["path"]: item for item in observed}
    expected_by_path = {item["path"]: item for item in expected_items}
    if len(by_path) != len(observed) or len(expected_by_path) != len(expected_items):
        raise ImageValidationError(
            f"Independent submodule verification contains duplicate paths for {label}."
        )
    if set(by_path) != set(expected_by_path):
        raise ImageValidationError(
            f"Independent submodule verification composition mismatch for {label}."
        )
    for path, expected_item in expected_by_path.items():
        result = by_path[path]
        materialized = expected_item["materialized"]
        if (
            result["materialized"] is not materialized
            or result["expected_commit"] != expected_item["expected_commit"]
        ):
            raise ImageValidationError(
                f"Independent submodule identity mismatch for {label}:{path}."
            )
        if not materialized:
            if result["status"] != "metadata_only":
                raise ImageValidationError(
                    f"Independent uninitialized submodule status mismatch for {label}:{path}."
                )
            continue
        if (
            result["status"] != "verified"
            or result["actual_commit"] != expected_item["actual_commit"]
            or result["head_tree"] != expected_item["head_tree"]
            or result["tracked_content"] != expected_item["tracked_content"]
            or result["generated_content"] != expected_item["generated_content"]
            or result["source_tree"] != expected_item["source_tree"]
        ):
            raise ImageValidationError(
                f"Independent submodule evidence mismatch for {label}:{path}."
            )
        check_independent_submodules(
            result["submodules"], expected_item["submodules"], f"{label}:{path}"
        )

def validate_source_tree_evidence(
    contents: dict[str, Any], lock_sha256: str, lock_data: dict[str, Any]
) -> dict[str, Any]:
    """Validate post-cleanup and final-runtime comparisons against pre-cleanup provenance."""
    specifications = (
        ("source_provenance", "source_provenance_bytes", SOURCE_PROVENANCE_SCHEMA_PATH),
        (
            "source_provenance_verification",
            "source_provenance_verification_bytes",
            SOURCE_PROVENANCE_VERIFICATION_SCHEMA_PATH,
        ),
        (
            "post_cleanup_verification",
            "post_cleanup_verification_bytes",
            SOURCE_TREE_VERIFICATION_SCHEMA_PATH,
        ),
        (
            "runtime_verification",
            "runtime_verification_bytes",
            SOURCE_TREE_VERIFICATION_SCHEMA_PATH,
        ),
    )
    decoded: dict[str, dict[str, Any]] = {}
    raw_values: dict[str, bytes] = {}
    for key, raw_key, schema_path in specifications:
        value, raw = contents.get(key), contents.get(raw_key)
        if not isinstance(value, dict) or not isinstance(raw, bytes):
            raise ImageValidationError(
                f"Runtime image does not contain {key} evidence."
            )
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(value)
        except (OSError, json.JSONDecodeError) as exc:
            raise ImageValidationError(f"Unable to load {key} schema: {exc}") from exc
        except ValidationError as exc:
            location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
            raise ImageValidationError(
                f"{key} schema validation failed at {location}: {exc.message}"
            ) from exc
        decoded[key], raw_values[key] = value, raw

    provenance = decoded["source_provenance"]
    if (
        provenance["lock"]["version"] != 2
        or provenance["lock"]["sha256"] != lock_sha256
    ):
        raise ImageValidationError(
            "Source provenance lock identity does not match generated lock-v2."
        )
    provenance_sha = hashlib.sha256(raw_values["source_provenance"]).hexdigest()
    expected = {item["name"]: item for item in provenance["repositories"]}
    if len(expected) != len(provenance["repositories"]):
        raise ImageValidationError("Source provenance contains duplicate repositories.")
    locked_names = {
        item.get("name")
        for item in lock_data.get("applications", [])
        if isinstance(item, dict)
    }
    if set(expected) != locked_names:
        raise ImageValidationError(
            "Source provenance repository composition does not match lock-v2."
        )

    def check_submodules(
        observed: list[dict[str, Any]], expected_items: list[dict[str, Any]], label: str
    ) -> None:
        by_path = {item["path"]: item for item in observed}
        if len(by_path) != len(observed) or set(by_path) != {
            item["path"] for item in expected_items
        }:
            raise ImageValidationError(
                f"Submodule verification composition mismatch for {label}."
            )
        for item in expected_items:
            actual = by_path[item["path"]]
            if (
                actual["materialized"] != item["materialized"]
                or actual["expected_commit"] != item["expected_commit"]
                or actual["matches"] is not True
            ):
                raise ImageValidationError(
                    f"Submodule verification failed for {label}:{item['path']}."
                )
            if actual["expected_source_tree"] != item["source_tree"]:
                raise ImageValidationError(
                    f"Submodule expected fingerprint mismatch for {label}:{item['path']}."
                )
            if item["materialized"]:
                if actual["observed_source_tree"] != item["source_tree"]:
                    raise ImageValidationError(
                        f"Submodule observed fingerprint mismatch for {label}:{item['path']}."
                    )
                check_submodules(
                    actual["submodules"], item["submodules"], f"{label}:{item['path']}"
                )

    independent = decoded["source_provenance_verification"]
    if (
        independent["status"] != "passed"
        or independent["algorithm"] != "ndf-source-provenance-verification-v1"
        or independent["lock"] != provenance["lock"]
        or independent["source_provenance_sha256"] != provenance_sha
    ):
        raise ImageValidationError(
            "Independent source provenance verification is not bound to source provenance."
        )
    independent_records = {item["name"]: item for item in independent["repositories"]}
    if len(independent_records) != len(independent["repositories"]) or set(independent_records) != set(expected):
        raise ImageValidationError(
            "Independent source provenance verification repository composition mismatch."
        )
    for name, record in expected.items():
        result = independent_records[name]
        if any((
            result["status"] != "verified",
            result["repository"] != record["repository"],
            result["requested_ref"] != record["requested_ref"],
            result["resolver_commit"] != record["resolver_commit"],
            result["actual_commit"] != record["actual_commit"],
            result["head_tree"] != record["head_tree"],
            result["tracked_content"] != record["tracked_content"],
            result["generated_content"] != record["generated_content"],
            result["source_tree"] != record["source_tree"],
        )):
            raise ImageValidationError(
                f"Independent source provenance verification mismatch for {name}."
            )
        check_independent_submodules(
            result["submodules"], record["submodules"], name
        )

    for key, stage in (
        ("post_cleanup_verification", "post_cleanup"),
        ("runtime_verification", "runtime_image"),
    ):
        report = decoded[key]
        if (
            report["stage"] != stage
            or report["source_provenance_sha256"] != provenance_sha
            or report["lock"] != provenance["lock"]
        ):
            raise ImageValidationError(
                f"{stage} source verification is not bound to source provenance."
            )
        actual = {item["name"]: item for item in report["repositories"]}
        if set(actual) != set(expected):
            raise ImageValidationError(
                f"{stage} source verification repository composition mismatch."
            )
        for name, record in expected.items():
            result = actual[name]
            if (
                result["matches"] is not True
                or result["expected_source_tree"] != record["source_tree"]
                or result["observed_source_tree"] != record["source_tree"]
            ):
                raise ImageValidationError(
                    f"{stage} source-tree fingerprint mismatch for {name}."
                )
            check_submodules(result["submodules"], record["submodules"], name)

    return {
        "source_provenance_sha256": provenance_sha,
        "repository_count": len(expected),
        "post_cleanup_verified": True,
        "runtime_image_verified": True,
        "status": "passed",
    }


def validate_image(
    image_ref: str,
    metadata: dict[str, Any],
    lock_data: dict[str, Any],
    labels: dict[str, str],
    contents: dict[str, Any],
    lock_sha256: str,
    image_digest: str,
    repository_root: Path | None = None,
    lock_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Compare image labels/composition and bind its exact inventory bytes to the digest."""
    expected_apps = [app["name"] for app in metadata["applications"]]
    expected_app_set = set(expected_apps)
    if len(expected_apps) != len(expected_app_set):
        raise ImageValidationError(
            "Build metadata contains duplicate application names."
        )

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
        item
        for item in lock_data.get("manifests", [])
        if item.get("path") == image["manifest"]
    ]
    if len(manifest_entries) != 1:
        raise ImageValidationError(
            f"Expected exactly one lock checksum for '{image['manifest']}'."
        )
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
        {
            "name": app["name"],
            "target_ref": app["target_ref"],
            "resolved_sha": app["resolved_sha"],
        }
        for app in metadata["applications"]
    ]
    try:
        actual_label_apps = json.loads(labels.get("com.ndf.applications", ""))
    except json.JSONDecodeError:
        actual_label_apps = None
    if actual_label_apps != expected_label_apps:
        problems.append(
            "Image label 'com.ndf.applications' does not match build metadata."
        )
    if problems:
        raise ImageValidationError("\n".join(problems))

    inventory_bytes = contents.get("build_inventory_bytes")
    inventory = contents.get("build_inventory")
    if not isinstance(inventory_bytes, bytes) or not isinstance(inventory, dict):
        raise ImageValidationError(
            "Runtime image does not contain build-inventory.json."
        )
    binding = validate_inventory(
        inventory, inventory_bytes, metadata, lock_data, lock_sha256, image_digest
    )
    source_tree_verification = validate_source_tree_evidence(
        contents, lock_sha256, lock_data
    )
    composition_verification = None
    if repository_root is not None:
        try:
            composition_verification = verify_composition(
                repository_root=repository_root,
                manifest_path=image["manifest"],
                lock_data=lock_data,
                lock_bytes=lock_bytes if lock_bytes is not None else json.dumps(lock_data, sort_keys=True).encode(),
                metadata_applications=metadata["applications"],
                inventory_applications=inventory["applications"],
                runtime_directories=actual_dirs,
                runtime_apps_txt=actual_apps_txt,
            )
        except CompositionVerificationError as exc:
            raise ImageValidationError(f"Independent composition verification failed: {exc}") from exc
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
        "source_tree_verified": True,
        "source_tree_verification": source_tree_verification,
        **({"composition_verification": composition_verification} if composition_verification is not None else {}),
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
    source_provenance_output_path: Path | None = None,
    post_cleanup_verification_output_path: Path | None = None,
    runtime_verification_output_path: Path | None = None,
    source_provenance_verification_output_path: Path | None = None,
    composition_output_path: Path | None = None,
) -> dict[str, Any]:
    metadata, lock_data = load_json(metadata_path), load_json(lock_path)
    buildx_metadata = load_json(buildx_metadata_path)
    image_digest = buildx_metadata.get("containerimage.digest")
    if not isinstance(image_digest, str) or not DIGEST_PATTERN.fullmatch(image_digest):
        raise ImageValidationError(
            "Buildx metadata is missing a valid containerimage.digest."
        )
    lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    labels = inspect_image_labels(image_ref)
    contents = inspect_image_contents(image_ref)
    repository_root = Path(__file__).resolve().parents[3]
    report = validate_image(
        image_ref, metadata, lock_data, labels, contents, lock_sha256, image_digest,
        repository_root=repository_root,
        lock_bytes=lock_path.read_bytes(),
    )
    inventory_bytes = contents["build_inventory_bytes"]
    inventory_output_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_output_path.write_bytes(inventory_bytes)
    evidence_output_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_output_path.write_text(
        json.dumps(report["evidence_binding"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if composition_output_path is not None:
        composition_report = report.get("composition_verification")
        if not isinstance(composition_report, dict):
            raise ImageValidationError("Independent composition verification did not produce a report.")
        composition_output_path.parent.mkdir(parents=True, exist_ok=True)
        composition_output_path.write_text(
            json.dumps(composition_report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    for path, key in (
        (source_provenance_output_path, "source_provenance"),
        (source_provenance_verification_output_path, "source_provenance_verification"),
        (post_cleanup_verification_output_path, "post_cleanup_verification"),
        (runtime_verification_output_path, "runtime_verification"),
    ):
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents[key + "_bytes"])
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate an NDF product image and bind captured inventory to its digest."
    )
    parser.add_argument("--image", required=True, help="Local Docker image reference.")
    parser.add_argument(
        "--metadata", required=True, type=Path, help="Build metadata JSON."
    )
    parser.add_argument(
        "--lock", required=True, type=Path, help="Generated lock-v2 JSON."
    )
    parser.add_argument(
        "--buildx-metadata", required=True, type=Path, help="Buildx metadata JSON."
    )
    parser.add_argument(
        "--inventory-output",
        required=True,
        type=Path,
        help="Extracted inventory artifact path.",
    )
    parser.add_argument(
        "--evidence-output",
        required=True,
        type=Path,
        help="Digest-binding evidence output path.",
    )
    parser.add_argument(
        "--report", type=Path, help="Optional JSON validation report path."
    )
    parser.add_argument("--source-provenance-output", type=Path)
    parser.add_argument("--post-cleanup-verification-output", type=Path)
    parser.add_argument("--runtime-verification-output", type=Path)
    parser.add_argument("--source-provenance-verification-output", type=Path)
    parser.add_argument("--composition-output", type=Path)
    args = parser.parse_args()
    try:
        report = validate_from_files(
            args.image,
            args.metadata,
            args.lock,
            args.buildx_metadata,
            args.inventory_output,
            args.evidence_output,
            args.source_provenance_output,
            args.post_cleanup_verification_output,
            args.runtime_verification_output,
            args.source_provenance_verification_output,
            args.composition_output,
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    except (ImageValidationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"Validated {report['application_count']} applications, runtime inventory and "
        f"OCI/NDF labels for {report['image']}."
    )
    print(f"Image digest: {report['image_digest']}")
    print(f"Inventory SHA-256: {report['evidence_binding']['inventory_sha256']}")
    print("Image validation, source-tree verification, independent composition verification and evidence binding passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
