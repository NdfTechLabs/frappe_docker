"""Independently bind a PDD to exact evidence bytes and an OCI registry manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

try:
    from .validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )
except ImportError:
    from validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )

NDF_DIR = Path(__file__).resolve().parents[1]
EVIDENCE_SCHEMA_PATH = (
    NDF_DIR / "schemas" / "image-verification-evidence-v1.schema.json"
)
SIDECAR_FILES = {
    "build_result": "build-result.json",
    "build_metadata": "build-metadata.json",
    "buildx_metadata": "buildx-metadata.json",
    "image_validation": "image-validation.json",
    "image_verification_evidence": "image-verification-evidence.json",
}
PASSED_REPORTS = (
    "source_provenance_verification",
    "source_tree_post_cleanup",
    "source_tree_runtime",
    "image_composition_verification",
)


class ProductDeploymentBindingError(Exception):
    """Raised when a PDD cannot be bound to its evidence and OCI image."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProductDeploymentBindingError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProductDeploymentBindingError(
                    f"Non-finite JSON constant in {label}: {value}"
                )
            ),
        )
    except ProductDeploymentBindingError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductDeploymentBindingError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProductDeploymentBindingError(f"{label} must be a JSON object.")
    return value


def _resolve_evidence_file(root: Path, relative_path: str) -> Path:
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\\" in relative_path
        or ":" in relative_path
        or any(ord(character) < 32 for character in relative_path)
        or any(part in ("", ".", "..") for part in relative_path.split("/"))
    ):
        raise ProductDeploymentBindingError(f"Unsafe evidence path: {relative_path!r}.")
    candidate = root
    for part in relative_path.split("/"):
        candidate = candidate / part
        if candidate.is_symlink():
            raise ProductDeploymentBindingError(
                f"Evidence path must not traverse a symlink: {relative_path}."
            )
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ProductDeploymentBindingError(
            f"Evidence file is missing or inaccessible: {relative_path}: {exc}"
        ) from exc
    if not resolved.is_relative_to(resolved_root):
        raise ProductDeploymentBindingError(
            f"Evidence path escapes the evidence directory: {relative_path}."
        )
    if not resolved.is_file():
        raise ProductDeploymentBindingError(
            f"Evidence path is not a regular file: {relative_path}."
        )
    return resolved


def _load_and_hash_evidence(
    descriptor: dict[str, Any], evidence_dir: Path, image_id: str
) -> tuple[dict[str, tuple[str, bytes]], dict[str, dict[str, Any]]]:
    if evidence_dir.is_symlink():
        raise ProductDeploymentBindingError("Evidence directory must not be a symlink.")
    root = evidence_dir.resolve(strict=True)
    if not root.is_dir():
        raise ProductDeploymentBindingError("Evidence directory must be a directory.")
    artifacts: dict[str, tuple[str, bytes]] = {}
    records: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    for record in descriptor["evidence"]:
        name, relative_path = record["name"], record["path"]
        if name in records:
            raise ProductDeploymentBindingError(f"Duplicate PDD evidence name: {name}.")
        if relative_path in seen_paths:
            raise ProductDeploymentBindingError(
                f"Duplicate PDD evidence path: {relative_path}."
            )
        seen_paths.add(relative_path)
        actual_path = f"{image_id}.lock-v2.json" if name == "lock_v2" else relative_path
        path = _resolve_evidence_file(root, actual_path)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ProductDeploymentBindingError(
                f"Unable to read evidence file {relative_path}: {exc}"
            ) from exc
        if not raw:
            raise ProductDeploymentBindingError(
                f"Evidence file is empty: {relative_path}."
            )
        actual_sha, actual_size = _sha256(raw), len(raw)
        if record["sha256"] != actual_sha:
            raise ProductDeploymentBindingError(
                f"Evidence SHA-256 mismatch for {name}: expected "
                f"{record['sha256']}, calculated {actual_sha}."
            )
        if record["size_bytes"] != actual_size:
            raise ProductDeploymentBindingError(
                f"Evidence byte-size mismatch for {name}: expected "
                f"{record['size_bytes']}, calculated {actual_size}."
            )
        artifacts[name] = (relative_path, raw)
        records[name] = record
    return artifacts, records


def _validate_evidence_manifest(
    report: dict[str, Any],
    *,
    descriptor: dict[str, Any],
    records: dict[str, dict[str, Any]],
) -> None:
    try:
        schema = json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(report)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductDeploymentBindingError(
            f"Unable to load M4.2.5 evidence schema: {exc}"
        ) from exc
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ProductDeploymentBindingError(
            f"M4.2.5 evidence manifest schema failed at {location}: {exc.message}"
        ) from exc

    artifact = descriptor["artifact"]
    image = report["image"]
    if (
        image["digest"] != artifact["digest"]
        or image["repository"] != artifact["repository"]
    ):
        raise ProductDeploymentBindingError(
            "M4.2.5 evidence manifest identifies a different image."
        )
    observed = {item["name"]: item for item in report["evidence"]}
    if len(observed) != len(report["evidence"]) or set(observed) != set(records):
        raise ProductDeploymentBindingError(
            "M4.2.5 evidence manifest has missing, duplicate or unexpected records."
        )
    for name, record in records.items():
        manifest_record = observed[name]
        if any(
            manifest_record[field] != record[field]
            for field in ("path", "sha256", "size_bytes")
        ):
            raise ProductDeploymentBindingError(
                f"PDD and M4.2.5 evidence manifest disagree for {name}."
            )
    lock = descriptor["composition"]["lock"]
    if (
        report["lock"]["version"] != lock["version"]
        or report["lock"]["sha256"] != lock["sha256"]
    ):
        raise ProductDeploymentBindingError(
            "M4.2.5 evidence manifest is bound to a different lock-v2."
        )


def _cross_check_sidecars(
    descriptor: dict[str, Any],
    artifacts: dict[str, tuple[str, bytes]],
    sidecars: dict[str, dict[str, Any]],
) -> None:
    artifact = descriptor["artifact"]
    digest = artifact["digest"]
    repository = artifact["repository"]
    lock_sha = _sha256(artifacts["lock_v2"][1])
    inventory_sha = _sha256(artifacts["build_inventory"][1])
    image_id = sidecars["build_result"].get("image_id")

    if descriptor["composition"]["lock"]["sha256"] != lock_sha:
        raise ProductDeploymentBindingError("PDD composition lock hash mismatch.")
    if descriptor["build"].get("build_metadata_sha256") != _sha256(
        artifacts["build_metadata"][1]
    ):
        raise ProductDeploymentBindingError("PDD build metadata hash mismatch.")

    result = sidecars["build_result"]
    metadata = sidecars["build_metadata"]
    buildx = sidecars["buildx_metadata"]
    validation = sidecars["image_validation"]
    evidence = sidecars["image_verification_evidence"]

    if (
        result.get("digest") != digest
        or result.get("repository") != repository
        or not image_id
    ):
        raise ProductDeploymentBindingError(
            "Build result image identity or digest differs from the PDD."
        )
    if (
        metadata.get("image", {}).get("id") != image_id
        or metadata.get("image", {}).get("repository") != repository
    ):
        raise ProductDeploymentBindingError(
            "Build metadata image identity differs from build result/PDD."
        )
    if metadata.get("lock", {}).get("sha256") != lock_sha:
        raise ProductDeploymentBindingError(
            "Build metadata is not bound to the exact lock-v2 bytes."
        )
    if buildx.get("containerimage.digest") != digest:
        raise ProductDeploymentBindingError(
            "Buildx metadata digest differs from the PDD image digest."
        )
    if result.get("platforms") != [artifact["platform"]]:
        raise ProductDeploymentBindingError(
            "Build result platform does not match the PDD artifact platform."
        )
    if (
        validation.get("status") != "passed"
        or validation.get("image_digest") != digest
        or validation.get("image_id") != image_id
    ):
        raise ProductDeploymentBindingError(
            "Image-validation report is not passed for the exact PDD image."
        )
    if validation.get("verification_evidence") != evidence:
        raise ProductDeploymentBindingError(
            "Image-validation report does not contain the supplied evidence manifest."
        )
    if (
        evidence.get("image", {}).get("digest") != digest
        or evidence.get("image", {}).get("repository") != repository
        or evidence.get("image", {}).get("id") != image_id
        or evidence.get("lock", {}).get("sha256") != lock_sha
        or evidence.get("status") != "bound"
    ):
        raise ProductDeploymentBindingError(
            "M4.2.5 evidence manifest is not bound to the exact image and lock."
        )

    build_inventory = _read_json_from_bytes(
        artifacts["build_inventory"][1], "build inventory"
    )
    build_evidence = _read_json_from_bytes(
        artifacts["build_evidence"][1], "build evidence"
    )
    if build_inventory.get("lock") != {"version": 2, "sha256": lock_sha}:
        raise ProductDeploymentBindingError(
            "Build inventory lock identity does not match the exact lock-v2."
        )
    if (
        build_evidence.get("status") != "bound"
        or build_evidence.get("image_digest") != digest
        or build_evidence.get("lock_sha256") != lock_sha
        or build_evidence.get("inventory_sha256") != inventory_sha
    ):
        raise ProductDeploymentBindingError(
            "Build evidence does not bind the exact image, lock and inventory bytes."
        )
    composition = _read_json_from_bytes(
        artifacts["image_composition_verification"][1],
        "image composition verification",
    )
    if (
        composition.get("status") != "passed"
        or composition.get("lock", {}).get("sha256") != lock_sha
    ):
        raise ProductDeploymentBindingError(
            "Composition verification does not pass for the exact lock-v2."
        )
    for name in PASSED_REPORTS:
        report = _read_json_from_bytes(artifacts[name][1], name)
        if report.get("status") != "passed":
            raise ProductDeploymentBindingError(
                f"Required verification report did not pass: {name}."
            )


def _read_json_from_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ProductDeploymentBindingError(
                    f"Non-finite JSON constant in {label}: {value}"
                )
            ),
        )
    except ProductDeploymentBindingError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductDeploymentBindingError(
            f"Invalid UTF-8 JSON in {label}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ProductDeploymentBindingError(f"{label} must be a JSON object.")
    return value


def _verify_registry_manifest(
    immutable_reference: str, expected_digest: str, *, docker_bin: str = "docker"
) -> str:
    if not immutable_reference.endswith("@" + expected_digest):
        raise ProductDeploymentBindingError(
            "OCI reference is not pinned to the descriptor image digest."
        )
    try:
        result = subprocess.run(
            [
                docker_bin,
                "buildx",
                "imagetools",
                "inspect",
                "--raw",
                immutable_reference,
            ],
            check=False,
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProductDeploymentBindingError(
            "Registry manifest inspection timed out."
        ) from exc
    except OSError as exc:
        raise ProductDeploymentBindingError(
            f"Unable to execute registry manifest inspection: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ProductDeploymentBindingError(
            f"Registry manifest inspection failed: {detail or result.returncode}."
        )
    raw = result.stdout
    if not raw:
        raise ProductDeploymentBindingError("Registry returned an empty OCI manifest.")
    actual_digest = "sha256:" + _sha256(raw)
    if actual_digest != expected_digest:
        raise ProductDeploymentBindingError(
            f"Registry OCI manifest digest mismatch: expected {expected_digest}, "
            f"calculated {actual_digest}."
        )
    return actual_digest


def verify_product_deployment_binding(
    descriptor_path: Path,
    evidence_dir: Path,
    *,
    docker_bin: str = "docker",
) -> dict[str, Any]:
    try:
        validated = validate_descriptor(descriptor_path)
    except DescriptorValidationError as exc:
        raise ProductDeploymentBindingError(
            f"Independent PDD validation failed: {exc}"
        ) from exc
    descriptor = _read_json(descriptor_path, "PDD descriptor")
    if evidence_dir.is_symlink():
        raise ProductDeploymentBindingError("Evidence directory must not be a symlink.")
    try:
        evidence_root = evidence_dir.resolve(strict=True)
    except OSError as exc:
        raise ProductDeploymentBindingError(
            f"Evidence directory is missing or inaccessible: {exc}"
        ) from exc
    sidecars = {
        name: _read_json(_resolve_evidence_file(evidence_root, filename), filename)
        for name, filename in SIDECAR_FILES.items()
    }
    image_id = sidecars["build_result"].get("image_id")
    if not isinstance(image_id, str) or not image_id:
        raise ProductDeploymentBindingError(
            "Build result must provide the product image ID."
        )
    artifacts, records = _load_and_hash_evidence(descriptor, evidence_dir, image_id)
    _validate_evidence_manifest(
        sidecars["image_verification_evidence"],
        descriptor=descriptor,
        records=records,
    )
    _cross_check_sidecars(descriptor, artifacts, sidecars)

    immutable_reference = descriptor["artifact"].get("immutable_reference")
    if not immutable_reference:
        raise ProductDeploymentBindingError(
            "PDD must provide an immutable repository@digest reference."
        )
    registry_digest = _verify_registry_manifest(
        immutable_reference,
        descriptor["artifact"]["digest"],
        docker_bin=docker_bin,
    )
    return {
        "status": "passed",
        "descriptor_id": validated["descriptor_id"],
        "image_digest": validated["image_digest"],
        "content_sha256": validated["content_sha256"],
        "evidence_count": len(records),
        "registry_manifest_digest": registry_digest,
        "checks": [
            "independent_descriptor_validation",
            "exact_evidence_file_hashes_and_sizes",
            "evidence_manifest_inventory_binding",
            "build_and_lock_identity",
            "verification_report_status",
            "registry_oci_manifest_digest",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--docker-bin", default="docker")
    args = parser.parse_args()
    try:
        report = verify_product_deployment_binding(
            args.descriptor,
            args.evidence_dir,
            docker_bin=args.docker_bin,
        )
    except ProductDeploymentBindingError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
