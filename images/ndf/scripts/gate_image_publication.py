#!/usr/bin/env python3
"""Fail-closed gate for promoting a verified NDF image to its official source tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

try:
    from .bind_verification_evidence import (
        VerificationEvidenceError,
        verify_verification_evidence,
    )
except ImportError:
    from bind_verification_evidence import (
        VerificationEvidenceError,
        verify_verification_evidence,
    )

EVIDENCE_FILES = {
    "lock_v2": None,
    "apps_json": "apps.json",
    "build_metadata": "build-metadata.json",
    "buildx_metadata": "buildx-metadata.json",
    "build_inventory": "build-inventory.json",
    "build_evidence": "build-evidence.json",
    "source_provenance": "source-provenance.json",
    "source_provenance_verification": "source-provenance-verification.json",
    "source_tree_post_cleanup": "source-tree-verification-post-cleanup.json",
    "source_tree_runtime": "source-tree-verification-runtime.json",
    "image_composition_verification": "image-composition-verification.json",
}
PASSED_REPORTS = (
    "source-provenance-verification.json",
    "source-tree-verification-post-cleanup.json",
    "source-tree-verification-runtime.json",
    "image-composition-verification.json",
)
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
STAGING_TAG = re.compile(r"^candidate-[0-9]+-[0-9]+$")


class PublicationGateError(Exception):
    """Raised when a candidate is not eligible for official publication."""


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicationGateError(f"Unable to read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise PublicationGateError(f"{path.name} must contain a JSON object.")
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _schema() -> dict[str, Any]:
    path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "publication-gate-v1.schema.json"
    )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicationGateError(
            f"Unable to load publication-gate schema: {exc}"
        ) from exc


def verify_publication_candidate(
    *,
    build_output_dir: Path,
    image_id: str,
    source_sha: str,
    framework_major: str,
    candidate_image_ref: str,
    publication_image_ref: str,
) -> dict[str, Any]:
    """Validate staging identity, all evidence bytes and image/lock digest binding."""
    if not SOURCE_SHA.fullmatch(source_sha):
        raise PublicationGateError(
            "Source commit must be a lowercase 40-character SHA."
        )
    if not re.fullmatch(r"[1-9][0-9]*", framework_major):
        raise PublicationGateError(
            "Framework major version must be a positive integer."
        )
    metadata = _json(build_output_dir / "build-metadata.json")
    buildx = _json(build_output_dir / "buildx-metadata.json")
    result = _json(build_output_dir / "build-result.json")
    validation = _json(build_output_dir / "image-validation.json")
    evidence = _json(build_output_dir / "image-verification-evidence.json")
    image = metadata.get("image")
    if not isinstance(image, dict):
        raise PublicationGateError("Build metadata has no image identity.")
    repository = image.get("repository")
    if image.get("id") != image_id or not isinstance(repository, str):
        raise PublicationGateError(
            "Build metadata image identity does not match the requested product."
        )
    framework = metadata.get("framework")
    version = framework.get("version") if isinstance(framework, dict) else None
    if not isinstance(version, str) or version.split(".", 1)[0] != framework_major:
        raise PublicationGateError(
            "Build metadata framework major does not match the publication target."
        )
    if not candidate_image_ref.startswith(
        repository + ":"
    ) or not publication_image_ref.startswith(repository + ":"):
        raise PublicationGateError(
            "Candidate and publication references must use the configured image repository."
        )
    candidate_tag = candidate_image_ref.rsplit(":", 1)[-1]
    if not STAGING_TAG.fullmatch(candidate_tag):
        raise PublicationGateError(
            "Candidate reference must use a unique candidate-<run>-<attempt> staging tag."
        )
    expected_tag = f"v{framework_major}-{source_sha}"
    if publication_image_ref != f"{repository}:{expected_tag}":
        raise PublicationGateError(
            "Publication reference does not match the framework-qualified source SHA tag."
        )
    if candidate_image_ref == publication_image_ref:
        raise PublicationGateError(
            "Staging and official publication references must be different."
        )
    digest = result.get("digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise PublicationGateError(
            "Build result does not contain a valid OCI image digest."
        )
    if result.get("pushed") is not True or result.get("output") != "registry":
        raise PublicationGateError(
            "The candidate must be pushed to the staging registry before validation."
        )
    if result.get("image_id") != image_id or result.get("repository") != repository:
        raise PublicationGateError(
            "Build result image identity does not match build metadata."
        )
    if candidate_tag not in result.get(
        "tags", []
    ) or candidate_image_ref not in result.get("image_refs", []):
        raise PublicationGateError(
            "Build result does not identify the requested staging reference."
        )
    if buildx.get("containerimage.digest") != digest:
        raise PublicationGateError(
            "Buildx metadata and build-result image digests differ."
        )
    if validation.get("status") != "passed":
        raise PublicationGateError("Image validation report is not passed.")
    if (
        validation.get("image") != candidate_image_ref
        or validation.get("image_id") != image_id
    ):
        raise PublicationGateError(
            "Image validation report identifies a different candidate."
        )
    if validation.get("image_digest") != digest:
        raise PublicationGateError(
            "Image validation digest differs from the staged image digest."
        )
    lock_path = build_output_dir / f"{image_id}.lock-v2.json"
    try:
        lock_bytes = lock_path.read_bytes()
    except OSError as exc:
        raise PublicationGateError(
            f"Required generated lock-v2 is missing: {lock_path.name}"
        ) from exc
    lock_sha = _sha(lock_bytes)
    if metadata.get("lock", {}).get("sha256") != lock_sha:
        raise PublicationGateError(
            "Generated lock-v2 bytes do not match build metadata."
        )
    ei = evidence.get("image", {})
    if (
        ei.get("reference") != candidate_image_ref
        or ei.get("repository") != repository
        or ei.get("id") != image_id
    ):
        raise PublicationGateError(
            "Verification evidence identifies a different candidate image."
        )
    if ei.get("digest") != digest:
        raise PublicationGateError(
            "Verification evidence is bound to a different image digest."
        )
    if evidence.get("lock", {}).get("sha256") != lock_sha:
        raise PublicationGateError(
            "Verification evidence is bound to a different lock-v2."
        )
    artifacts = {}
    for name, filename in EVIDENCE_FILES.items():
        filename = f"{image_id}.lock-v2.json" if name == "lock_v2" else filename
        try:
            raw = (build_output_dir / filename).read_bytes()
        except OSError as exc:
            raise PublicationGateError(
                f"Required evidence file is missing: {filename}"
            ) from exc
        artifacts[name] = ("lock-v2.json" if name == "lock_v2" else filename, raw)
    for filename in PASSED_REPORTS:
        if _json(build_output_dir / filename).get("status") != "passed":
            raise PublicationGateError(
                f"Required verification report did not pass: {filename}"
            )
    build_evidence = _json(build_output_dir / "build-evidence.json")
    inventory_sha = _sha(artifacts["build_inventory"][1])
    if (
        build_evidence.get("status") != "bound"
        or build_evidence.get("image_digest") != digest
        or build_evidence.get("lock_sha256") != lock_sha
        or build_evidence.get("inventory_sha256") != inventory_sha
    ):
        raise PublicationGateError(
            "Existing build-evidence record is not bound to this image, lock and inventory."
        )
    try:
        verify_verification_evidence(
            evidence,
            expected_image_digest=digest,
            expected_lock_sha256=lock_sha,
            artifacts=artifacts,
        )
    except VerificationEvidenceError as exc:
        raise PublicationGateError(
            f"Digest-bound verification evidence failed: {exc}"
        ) from exc
    if validation.get("verification_evidence") != evidence:
        raise PublicationGateError(
            "Image-validation report does not contain the exported evidence manifest."
        )
    report = {
        "schema_version": "1.0",
        "algorithm": "ndf-publication-gate-v1",
        "status": "ready",
        "image": {
            "id": image_id,
            "repository": repository,
            "candidate_reference": candidate_image_ref,
            "publication_reference": publication_image_ref,
            "digest": digest,
        },
        "source": {"sha": source_sha, "framework_major": framework_major},
        "lock": {"version": 2, "sha256": lock_sha},
        "verification_evidence_sha256": _sha(
            (build_output_dir / "image-verification-evidence.json").read_bytes()
        ),
    }
    try:
        Draft202012Validator(_schema()).validate(report)
    except ValidationError as exc:
        raise PublicationGateError(
            f"Publication gate report schema failed: {exc.message}"
        ) from exc
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify NDF candidate evidence before official product-tag promotion."
    )
    parser.add_argument("--build-output-dir", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--framework-major", required=True)
    parser.add_argument("--candidate-image-ref", required=True)
    parser.add_argument("--publication-image-ref", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = verify_publication_candidate(
            build_output_dir=args.build_output_dir,
            image_id=args.image_id,
            source_sha=args.source_sha,
            framework_major=args.framework_major,
            candidate_image_ref=args.candidate_image_ref,
            publication_image_ref=args.publication_image_ref,
        )
        raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_bytes(raw)
    except (PublicationGateError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Publication gate ready: {report['image']['publication_reference']}")
    print(f"Validated image digest: {report['image']['digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
