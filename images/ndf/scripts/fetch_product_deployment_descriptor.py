#!/usr/bin/env python3
"""Fetch and verify a digest-pinned PDD OCI artifact for a deployment consumer."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

try:
    from .publish_product_deployment_descriptor import ARTIFACT_TYPE, PDD_MEDIA_TYPE, SIDECARS
    from .validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )
    from .verify_product_deployment_binding import (
        ProductDeploymentBindingError,
        verify_product_deployment_binding,
    )
except ImportError:
    from publish_product_deployment_descriptor import ARTIFACT_TYPE, PDD_MEDIA_TYPE, SIDECARS
    from validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )
    from verify_product_deployment_binding import (
        ProductDeploymentBindingError,
        verify_product_deployment_binding,
    )

NDF_DIR = Path(__file__).resolve().parents[1]
PUBLICATION_SCHEMA = NDF_DIR / "schemas" / "pdd-publication-record-v1.schema.json"
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class PDDRetrievalError(Exception):
    """Raised when a published PDD cannot be safely retrieved or verified."""


def _run(command: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command, check=False, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise PDDRetrievalError(f"Command timed out: {command[0]}") from exc
    except OSError as exc:
        raise PDDRetrievalError(f"Unable to execute {command[0]}: {exc}") from exc


def _json_output(result: subprocess.CompletedProcess[bytes], label: str) -> dict[str, Any]:
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PDDRetrievalError(f"{label} failed: {detail or result.returncode}")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PDDRetrievalError(f"{label} returned invalid JSON.") from exc
    if not isinstance(value, dict):
        raise PDDRetrievalError(f"{label} must return a JSON object.")
    return value


def _load_receipt(path: Path) -> dict[str, Any]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        schema = json.loads(PUBLICATION_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise PDDRetrievalError(f"Invalid publication receipt: {exc}") from exc
    if not isinstance(receipt, dict):
        raise PDDRetrievalError("Publication receipt must be a JSON object.")
    return receipt


def fetch_product_deployment_descriptor(
    publication_record: Path,
    output_dir: Path,
    *,
    oras_bin: str = "oras",
    docker_bin: str = "docker",
    verify_image_binding: bool = True,
) -> dict[str, Any]:
    receipt = _load_receipt(publication_record)
    artifact = receipt["artifact"]
    reference = artifact["immutable_reference"]
    repository = artifact["repository"]
    digest = artifact["digest"]
    subject = receipt["subject_image"]
    expected_locator = (
        f"pdd-v1-{subject['platform'].replace('/', '-')}-"
        f"{subject['digest'].removeprefix('sha256:')}"
    )
    if (
        not SHA256_RE.fullmatch(digest)
        or reference != f"{repository}@{digest}"
        or repository != subject["repository"]
        or artifact["locator_tag"] != expected_locator
    ):
        raise PDDRetrievalError("Publication receipt does not contain a consistent digest-pinned artifact reference and locator.")

    manifest = _json_output(
        _run([oras_bin, "manifest", "fetch", "--format", "json", reference], timeout=120),
        "ORAS manifest fetch",
    )
    if manifest.get("digest") != digest:
        raise PDDRetrievalError("Registry manifest digest differs from the publication receipt.")
    manifest_content = manifest.get("content", {})
    if manifest_content.get("artifactType") != ARTIFACT_TYPE:
        raise PDDRetrievalError("Registry artifact type is not the NDF PDD contract.")
    layers = manifest_content.get("layers", [])
    if not any(
        isinstance(layer, dict) and layer.get("mediaType") == PDD_MEDIA_TYPE
        for layer in layers
    ):
        raise PDDRetrievalError("Registry artifact does not contain the required PDD media type layer.")
    annotations = manifest_content.get("annotations", {})
    descriptor_record = receipt["descriptor"]
    expected_annotations = {
        "io.ndf.pdd.descriptor-id": descriptor_record["id"],
        "io.ndf.pdd.content-sha256": descriptor_record["content_sha256"],
        "io.ndf.pdd.subject-image-digest": receipt["subject_image"]["digest"],
        "io.ndf.pdd.schema-version": descriptor_record["schema_version"],
    }
    if any(annotations.get(key) != value for key, value in expected_annotations.items()):
        raise PDDRetrievalError("Registry artifact annotations disagree with the publication receipt.")

    if output_dir.is_symlink():
        raise PDDRetrievalError("Output directory must not be a symlink.")
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise PDDRetrievalError("Output directory must be empty to prevent mixing artifact contents.")
    with tempfile.TemporaryDirectory(prefix="ndf-pdd-fetch-") as temp:
        pulled_dir = Path(temp)
        pull_result = _json_output(
            _run(
                [oras_bin, "pull", "--format", "json", "--output", str(pulled_dir), reference],
                timeout=300,
            ),
            "ORAS artifact pull",
        )
        if pull_result.get("reference") != reference:
            raise PDDRetrievalError("ORAS pull returned a different artifact reference.")

        pdd_path = pulled_dir / "product-deployment.json"
        binding_path = pulled_dir / "binding-verification.json"
        if not pdd_path.is_file() or pdd_path.is_symlink():
            raise PDDRetrievalError("Published artifact is missing product-deployment.json.")
        if not binding_path.is_file() or binding_path.is_symlink():
            raise PDDRetrievalError("Published artifact is missing binding-verification.json.")
        pulled_files = []
        for path in pulled_dir.rglob("*"):
            if path.is_symlink():
                raise PDDRetrievalError("Published artifact contains a symlink.")
            if path.is_file():
                pulled_files.append(path)
        if len(pulled_files) != receipt["evidence"]["published_file_count"]:
            raise PDDRetrievalError("Published artifact file count differs from the publication receipt.")
        binding_sha = hashlib.sha256(binding_path.read_bytes()).hexdigest()
        if binding_sha != receipt["evidence"]["binding_report_sha256"]:
            raise PDDRetrievalError("Binding report bytes differ from the publication receipt.")

        try:
            validated = validate_descriptor(pdd_path)
        except DescriptorValidationError as exc:
            raise PDDRetrievalError(f"Independent PDD validation failed: {exc}") from exc
        if validated["descriptor_id"] != descriptor_record["id"]:
            raise PDDRetrievalError("Retrieved PDD descriptor identity differs from the publication receipt.")
        if validated["content_sha256"] != descriptor_record["content_sha256"]:
            raise PDDRetrievalError("Retrieved PDD content hash differs from the publication receipt.")
        if validated["image_digest"] != receipt["subject_image"]["digest"]:
            raise PDDRetrievalError("Retrieved PDD image digest differs from the publication receipt.")
        try:
            descriptor = json.loads(pdd_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PDDRetrievalError(f"Unable to read retrieved PDD: {exc}") from exc
        subject = receipt["subject_image"]
        if (
            descriptor.get("artifact", {}).get("repository") != subject["repository"]
            or descriptor.get("artifact", {}).get("digest") != subject["digest"]
            or descriptor.get("artifact", {}).get("platform") != subject["platform"]
        ):
            raise PDDRetrievalError("Retrieved PDD image repository/digest/platform differs from the publication receipt.")
        if validated["schema_version"] != descriptor_record["schema_version"]:
            raise PDDRetrievalError("Retrieved PDD schema version differs from the publication receipt.")
        try:
            build_result = json.loads(
                (pulled_dir / "build-result.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PDDRetrievalError(f"Unable to read published build result: {exc}") from exc
        image_id = build_result.get("image_id")
        if not isinstance(image_id, str) or not image_id:
            raise PDDRetrievalError("Published build result has no valid image_id.")
        expected_files = {"product-deployment.json", "binding-verification.json", *SIDECARS}
        for evidence in descriptor["evidence"]:
            expected_files.add(
                f"{image_id}.lock-v2.json"
                if evidence["name"] == "lock_v2"
                else evidence["path"]
            )
        observed_files = {path.relative_to(pulled_dir).as_posix() for path in pulled_files}
        if observed_files != expected_files:
            raise PDDRetrievalError("Published artifact file inventory does not match the PDD evidence and sidecar contract.")

        if verify_image_binding:
            try:
                binding = verify_product_deployment_binding(
                    pdd_path, pulled_dir, docker_bin=docker_bin
                )
            except ProductDeploymentBindingError as exc:
                raise PDDRetrievalError(f"Retrieved PDD evidence binding failed: {exc}") from exc
            recorded = json.loads(binding_path.read_text(encoding="utf-8"))
            for key in ("status", "descriptor_id", "image_digest", "content_sha256", "evidence_count"):
                if recorded.get(key) != binding.get(key):
                    raise PDDRetrievalError(f"Retrieved binding report disagrees on {key}.")
            if binding.get("status") != "passed":
                raise PDDRetrievalError("Retrieved evidence bundle did not pass binding verification.")

        for item in pulled_dir.iterdir():
            target = output_dir / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            elif item.is_file() and not item.is_symlink():
                shutil.copy2(item, target)

    return {
        "status": "verified" if verify_image_binding else "descriptor_verified",
        "artifact_reference": reference,
        "artifact_digest": digest,
        "descriptor_id": validated["descriptor_id"],
        "content_sha256": validated["content_sha256"],
        "image_digest": validated["image_digest"],
        "evidence_binding_verified": verify_image_binding,
        "output_directory": str(output_dir.resolve()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication-record", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--oras-bin", default="oras")
    parser.add_argument("--docker-bin", default="docker")
    parser.add_argument(
        "--skip-image-binding",
        action="store_true",
        help="Validate artifact and PDD only; do not re-run M4.2.6.5 against the image registry.",
    )
    args = parser.parse_args()
    try:
        report = fetch_product_deployment_descriptor(
            args.publication_record,
            args.output_dir,
            oras_bin=args.oras_bin,
            docker_bin=args.docker_bin,
            verify_image_binding=not args.skip_image_binding,
        )
    except PDDRetrievalError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
