#!/usr/bin/env python3
"""Publish a verified PDD and its complete evidence bundle as a GHCR OCI artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

try:
    from .validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )
    from .verify_product_deployment_binding import (
        ProductDeploymentBindingError,
        verify_product_deployment_binding,
    )
except ImportError:
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
ARTIFACT_TYPE = "application/vnd.ndf.product-deployment-descriptor.v1"
PDD_MEDIA_TYPE = "application/vnd.ndf.product-deployment-descriptor.v1+json"
JSON_MEDIA_TYPE = "application/vnd.ndf.pdd.evidence.v1+json"
SIDECARS = (
    "build-result.json",
    "build-metadata.json",
    "buildx-metadata.json",
    "image-validation.json",
    "image-verification-evidence.json",
)
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class PDDPublicationError(Exception):
    """Raised when a verified PDD cannot be safely published."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _run(
    command: list[str], *, timeout: int = 300, cwd: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command, check=False, capture_output=True, timeout=timeout, cwd=cwd
        )
    except subprocess.TimeoutExpired as exc:
        raise PDDPublicationError(f"Command timed out: {command[0]}") from exc
    except OSError as exc:
        raise PDDPublicationError(f"Unable to execute {command[0]}: {exc}") from exc


def _json_output(
    result: subprocess.CompletedProcess[bytes], label: str
) -> dict[str, Any]:
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PDDPublicationError(f"{label} failed: {detail or result.returncode}")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PDDPublicationError(f"{label} returned invalid JSON.") from exc
    if not isinstance(value, dict):
        raise PDDPublicationError(f"{label} must return a JSON object.")
    return value


def _safe_file(root: Path, relative: str) -> Path:
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or ":" in relative
        or any(ord(char) < 32 for char in relative)
        or any(part in ("", ".", "..") for part in relative.split("/"))
    ):
        raise PDDPublicationError(f"Unsafe publication file path: {relative!r}")
    candidate = root
    for part in relative.split("/"):
        candidate = candidate / part
        if candidate.is_symlink():
            raise PDDPublicationError(
                f"Publication input traverses symlink: {relative}"
            )
    try:
        resolved = candidate.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise PDDPublicationError(
            f"Missing publication input {relative}: {exc}"
        ) from exc
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise PDDPublicationError(
            f"Publication input is not a regular in-root file: {relative}"
        )
    if resolved.stat().st_size == 0:
        raise PDDPublicationError(f"Publication input is empty: {relative}")
    return resolved


def _publication_files(
    descriptor: dict[str, Any], evidence_dir: Path, image_id: str
) -> dict[str, Path]:
    files: dict[str, Path] = {
        "product-deployment.json": _safe_file(evidence_dir, "product-deployment.json"),
        "binding-verification.json": _safe_file(
            evidence_dir, "binding-verification.json"
        ),
    }
    for record in descriptor["evidence"]:
        name = record["name"]
        path = f"{image_id}.lock-v2.json" if name == "lock_v2" else record["path"]
        if path in files:
            raise PDDPublicationError(f"Duplicate publication file path: {path}")
        files[path] = _safe_file(evidence_dir, path)
    for sidecar in SIDECARS:
        sidecar_path = _safe_file(evidence_dir, sidecar)
        if sidecar in files:
            if files[sidecar] != sidecar_path:
                raise PDDPublicationError(
                    f"Conflicting publication sidecar path: {sidecar}"
                )
            continue
        files[sidecar] = sidecar_path
    return dict(sorted(files.items()))


def _tag_for(descriptor: dict[str, Any]) -> str:
    platform = descriptor["artifact"]["platform"].replace("/", "-")
    digest = descriptor["artifact"]["digest"].removeprefix("sha256:")
    return f"pdd-v1-{platform}-{digest}"


def _manifest(oras_bin: str, reference: str) -> dict[str, Any] | None:
    result = _run(
        [oras_bin, "manifest", "fetch", "--format", "json", reference],
        timeout=120,
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").lower()
        if any(
            token in error
            for token in ("manifest_unknown", "manifest unknown", "not found", "404")
        ):
            return None
        raise PDDPublicationError(
            f"Unable to inspect existing publication reference: {error.strip()}"
        )
    return _json_output(result, "ORAS manifest fetch")


def _pull_and_compare(oras_bin: str, reference: str, expected: dict[str, Path]) -> None:
    with tempfile.TemporaryDirectory(prefix="ndf-pdd-publication-check-") as temp:
        output = Path(temp)
        result = _run(
            [oras_bin, "pull", "--format", "json", "--output", str(output), reference],
            timeout=300,
        )
        _json_output(result, "ORAS publication pull")
        observed: set[str] = set()
        for path in output.rglob("*"):
            if path.is_symlink():
                raise PDDPublicationError("Pulled publication contains a symlink.")
            if path.is_file():
                observed.add(path.relative_to(output).as_posix())
        if observed != set(expected):
            raise PDDPublicationError(
                "Published artifact file inventory differs from the verified input bundle."
            )
        for relative, source in expected.items():
            pulled = output / relative
            if pulled.is_symlink() or not pulled.is_file():
                raise PDDPublicationError(f"Published artifact is missing {relative}.")
            if pulled.read_bytes() != source.read_bytes():
                raise PDDPublicationError(
                    f"Published artifact bytes differ for {relative}."
                )


def publish_product_deployment_descriptor(
    descriptor_path: Path,
    evidence_dir: Path,
    publication_record_path: Path,
    *,
    oras_bin: str = "oras",
    docker_bin: str = "docker",
) -> dict[str, Any]:
    try:
        validated = validate_descriptor(descriptor_path)
    except DescriptorValidationError as exc:
        raise PDDPublicationError(f"Independent PDD validation failed: {exc}") from exc

    try:
        binding = verify_product_deployment_binding(
            descriptor_path, evidence_dir, docker_bin=docker_bin
        )
    except ProductDeploymentBindingError as exc:
        raise PDDPublicationError(
            f"M4.2.6.5 binding verification failed: {exc}"
        ) from exc

    if evidence_dir.is_symlink() or descriptor_path.is_symlink():
        raise PDDPublicationError(
            "Evidence directory and descriptor must not be symlinks."
        )
    evidence_root = evidence_dir.resolve(strict=True)
    if descriptor_path.resolve(strict=True).parent != evidence_root:
        raise PDDPublicationError(
            "Descriptor must be product-deployment.json inside evidence-dir."
        )
    if descriptor_path.name != "product-deployment.json":
        raise PDDPublicationError(
            "Descriptor filename must be product-deployment.json."
        )

    try:
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        recorded_binding = json.loads(
            _safe_file(evidence_root, "binding-verification.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PDDPublicationError(
            f"Unable to load descriptor or binding report: {exc}"
        ) from exc

    for key in (
        "status",
        "descriptor_id",
        "image_digest",
        "content_sha256",
        "evidence_count",
    ):
        if recorded_binding.get(key) != binding.get(key):
            raise PDDPublicationError(f"Recorded binding report disagrees on {key}.")
    if binding.get("status") != "passed":
        raise PDDPublicationError(
            "Only a passed image/evidence binding can be published."
        )

    build_result = json.loads(
        _safe_file(evidence_root, "build-result.json").read_text(encoding="utf-8")
    )
    image_id = build_result.get("image_id")
    if not isinstance(image_id, str) or not image_id:
        raise PDDPublicationError("Build result has no valid image_id.")

    files = _publication_files(descriptor, evidence_root, image_id)
    repository = descriptor["artifact"]["repository"]
    image_digest = descriptor["artifact"]["digest"]
    tag = _tag_for(descriptor)
    locator = f"{repository}:{tag}"
    annotations = {
        "io.ndf.pdd.descriptor-id": validated["descriptor_id"],
        "io.ndf.pdd.content-sha256": validated["content_sha256"],
        "io.ndf.pdd.subject-image-digest": image_digest,
        "io.ndf.pdd.schema-version": descriptor["schema_version"],
        "org.opencontainers.image.title": "NDF Product Deployment Descriptor",
    }

    existing = _manifest(oras_bin, locator)
    if existing is not None:
        content = existing.get("content", {})
        if content.get("artifactType") != ARTIFACT_TYPE:
            raise PDDPublicationError(
                "Deterministic PDD locator is occupied by another artifact type."
            )
        existing_annotations = content.get("annotations", {})
        if any(
            existing_annotations.get(key) != value for key, value in annotations.items()
        ):
            raise PDDPublicationError(
                "Existing publication annotations disagree with the descriptor."
            )
        if not any(
            isinstance(layer, dict) and layer.get("mediaType") == PDD_MEDIA_TYPE
            for layer in content.get("layers", [])
        ):
            raise PDDPublicationError(
                "Existing publication has no PDD descriptor media-type layer."
            )
        digest = existing.get("digest")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise PDDPublicationError(
                "Existing publication has no valid manifest digest."
            )
        immutable_reference = f"{repository}@{digest}"
        _pull_and_compare(oras_bin, immutable_reference, files)
    else:
        command = [
            oras_bin,
            "push",
            "--no-tty",
            "--artifact-type",
            ARTIFACT_TYPE,
        ]
        for key, value in annotations.items():
            command.extend(["--annotation", f"{key}={value}"])
        command.append(locator)
        for relative in files:
            media_type = (
                PDD_MEDIA_TYPE
                if relative == "product-deployment.json"
                else JSON_MEDIA_TYPE
            )
            command.append(f"{relative}:{media_type}")
        command.extend(["--format", "json"])
        result = _run(command, timeout=600, cwd=evidence_root)
        pushed = _json_output(result, "ORAS artifact push")
        digest = pushed.get("digest")
        reference = pushed.get("reference")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise PDDPublicationError(
                "ORAS push did not return a valid artifact digest."
            )
        immutable_reference = f"{repository}@{digest}"
        if reference and reference != immutable_reference:
            raise PDDPublicationError(
                "ORAS returned an unexpected immutable artifact reference."
            )
        manifest = _manifest(oras_bin, immutable_reference)
        if manifest is None or manifest.get("digest") != digest:
            raise PDDPublicationError(
                "Published artifact cannot be retrieved by its exact digest."
            )
        locator_manifest = _manifest(oras_bin, locator)
        if locator_manifest is None or locator_manifest.get("digest") != digest:
            raise PDDPublicationError(
                "Deterministic publication locator does not resolve to the pushed digest."
            )
        content = manifest.get("content", {})
        if content.get("artifactType") != ARTIFACT_TYPE:
            raise PDDPublicationError(
                "Published artifact has an unexpected artifact type."
            )
        observed_annotations = content.get("annotations", {})
        if any(
            observed_annotations.get(key) != value for key, value in annotations.items()
        ):
            raise PDDPublicationError(
                "Published artifact annotations do not match the descriptor."
            )
        if not any(
            isinstance(layer, dict) and layer.get("mediaType") == PDD_MEDIA_TYPE
            for layer in content.get("layers", [])
        ):
            raise PDDPublicationError(
                "Published artifact has no PDD descriptor media-type layer."
            )
        _pull_and_compare(oras_bin, immutable_reference, files)

    receipt = {
        "schema_version": "1.0.0",
        "publication_type": "ndf.product-deployment.publication",
        "descriptor": {
            "id": validated["descriptor_id"],
            "schema_version": descriptor["schema_version"],
            "content_sha256": validated["content_sha256"],
        },
        "subject_image": {
            "repository": repository,
            "digest": image_digest,
            "platform": descriptor["artifact"]["platform"],
        },
        "artifact": {
            "type": ARTIFACT_TYPE,
            "repository": repository,
            "locator_tag": tag,
            "digest": digest,
            "immutable_reference": immutable_reference,
        },
        "evidence": {
            "count": binding["evidence_count"],
            "binding_report_sha256": _sha256(
                (evidence_root / "binding-verification.json").read_bytes()
            ),
            "published_file_count": len(files),
        },
        "published_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    try:
        schema = json.loads(PUBLICATION_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise PDDPublicationError(
            f"Publication receipt failed schema validation: {exc}"
        ) from exc

    publication_record_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = publication_record_path.with_name(publication_record_path.name + ".tmp")
    temp_path.write_text(
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temp_path, publication_record_path)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--publication-record", required=True, type=Path)
    parser.add_argument("--oras-bin", default="oras")
    parser.add_argument("--docker-bin", default="docker")
    args = parser.parse_args()
    try:
        receipt = publish_product_deployment_descriptor(
            args.descriptor,
            args.evidence_dir,
            args.publication_record,
            oras_bin=args.oras_bin,
            docker_bin=args.docker_bin,
        )
    except PDDPublicationError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(
        json.dumps(
            {"status": "published", **receipt}, ensure_ascii=False, sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
