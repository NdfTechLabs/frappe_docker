#!/usr/bin/env python3
"""Generate a deterministic Product Deployment Descriptor from verified build evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
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


NDF_DIR = Path(__file__).resolve().parents[1]
SCHEMA_PATH = NDF_DIR / "schemas" / "product-deployment-descriptor-v1.schema.json"
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
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GIT_SHA = re.compile(r"^[a-f0-9]{40,64}$")
OCI_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class DescriptorGenerationError(Exception):
    """Raised when verified inputs cannot produce a truthful PDD."""


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise DescriptorGenerationError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise DescriptorGenerationError(f"{label} must be a JSON object.")
    return value, raw


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    """NDF canonical JSON v1: UTF-8, sorted keys, compact separators, no floats."""
    def check(item: Any) -> None:
        if isinstance(item, float):
            raise DescriptorGenerationError(
                "PDD canonicalization does not permit floating-point values."
            )
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise DescriptorGenerationError("JSON object keys must be strings.")
            for child in item.values():
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
    check(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DescriptorGenerationError(f"{label} must be a non-empty string.")
    return value


def _load_inputs(output_dir: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    metadata, metadata_raw = _read_json(output_dir / "build-metadata.json", "build-metadata.json")
    image_id = _require_string(metadata.get("image", {}).get("id"), "Build metadata image ID")
    filenames = {
        name: (f"{image_id}.lock-v2.json" if name == "lock_v2" else filename)
        for name, filename in EVIDENCE_FILES.items()
    }
    files: dict[str, bytes] = {}
    values: dict[str, dict[str, Any]] = {"build_metadata": metadata}
    files["build_metadata"] = metadata_raw
    for name, filename in filenames.items():
        if name == "build_metadata":
            continue
        path = output_dir / filename
        value, raw = _read_json(path, filename)
        values[name] = value
        files[name] = raw
    return values, files


def _verify_inputs(values: dict[str, dict[str, Any]], files: dict[str, bytes]) -> None:
    lock_sha = _sha(files["lock_v2"])
    lock = values["lock_v2"]
    metadata = values["build_metadata"]
    buildx = values["buildx_metadata"]
    result, validation, evidence = (
        values.get("build_result", {}),
        values.get("image_validation", {}),
        values.get("image_verification_evidence", {}),
    )
    if lock.get("lock_version") != 2:
        raise DescriptorGenerationError("PDD generation requires lock-v2.")
    if metadata.get("lock", {}).get("sha256") != lock_sha:
        raise DescriptorGenerationError("Build metadata does not bind the exact lock-v2 bytes.")
    if values["build_inventory"].get("lock") != {"version": 2, "sha256": lock_sha}:
        raise DescriptorGenerationError("Build inventory lock identity mismatch.")
    digest = result.get("digest")
    if not isinstance(digest, str) or not OCI_DIGEST.fullmatch(digest):
        raise DescriptorGenerationError("Build result has no valid immutable image digest.")
    if buildx.get("containerimage.digest") != digest:
        raise DescriptorGenerationError("Buildx metadata and build-result digests differ.")
    image = metadata.get("image", {})
    if result.get("image_id") != image.get("id") or result.get("repository") != image.get("repository"):
        raise DescriptorGenerationError("Build result and build metadata image identities differ.")
    if validation.get("status") != "passed" or validation.get("image_digest") != digest:
        raise DescriptorGenerationError("Image validation is not passed for this exact image digest.")
    if validation.get("image_id") != image.get("id"):
        raise DescriptorGenerationError("Image validation identifies a different product image.")
    if evidence.get("image", {}).get("digest") != digest:
        raise DescriptorGenerationError("Verification evidence is not bound to the image digest.")
    if evidence.get("lock", {}).get("sha256") != lock_sha:
        raise DescriptorGenerationError("Verification evidence is not bound to the exact lock-v2.")
    if values["build_evidence"].get("status") != "bound":
        raise DescriptorGenerationError("Build inventory evidence is not bound.")
    build_evidence = values["build_evidence"]
    if (
        build_evidence.get("image_digest") != digest
        or build_evidence.get("lock_sha256") != lock_sha
        or build_evidence.get("inventory_sha256") != _sha(files["build_inventory"])
    ):
        raise DescriptorGenerationError("Build evidence image/lock/inventory binding mismatch.")
    for name in (
        "source_provenance_verification",
        "source_tree_post_cleanup",
        "source_tree_runtime",
        "image_composition_verification",
    ):
        if values[name].get("status") != "passed":
            raise DescriptorGenerationError(f"Required verification report did not pass: {name}.")
    composition = values["image_composition_verification"]
    if composition.get("lock", {}).get("sha256") != lock_sha:
        raise DescriptorGenerationError("Composition verification is bound to a different lock.")
    if validation.get("verification_evidence") != evidence:
        raise DescriptorGenerationError("Image validation report does not contain the bound evidence manifest.")
    artifacts = {
        name: (
            "lock-v2.json" if name == "lock_v2" else EVIDENCE_FILES[name],
            files[name],
        )
        for name in EVIDENCE_FILES
    }
    try:
        verify_verification_evidence(
            evidence,
            expected_image_digest=digest,
            expected_lock_sha256=lock_sha,
            artifacts=artifacts,
        )
    except VerificationEvidenceError as exc:
        raise DescriptorGenerationError(f"Digest-bound evidence verification failed: {exc}") from exc


def _build_descriptor(
    values: dict[str, dict[str, Any]],
    files: dict[str, bytes],
    *,
    source_commit: str,
    workflow_run_id: str,
    built_at: str,
    workflow_run_url: str | None,
) -> dict[str, Any]:
    metadata = values["build_metadata"]
    lock = values["lock_v2"]
    inventory = values["build_inventory"]
    provenance = values["source_provenance"]
    composition_report = values["image_composition_verification"]
    evidence_report = values["image_verification_evidence"]
    result = values["build_result"]
    image_meta = metadata.get("image", {})
    product = lock.get("product", {})
    digest = result["digest"]
    platform = result.get("platforms")
    if not isinstance(platform, list) or len(platform) != 1:
        raise DescriptorGenerationError("PDD v1 requires exactly one measured target platform.")
    platform_name = _require_string(platform[0], "Build target platform")
    if inventory.get("stage") != "builder":
        raise DescriptorGenerationError("Current build inventory must identify its actual builder stage.")
    if inventory.get("lock", {}).get("sha256") != _sha(files["lock_v2"]):
        raise DescriptorGenerationError("Builder inventory lock SHA does not match lock-v2.")

    provenance_by_name = {item["name"]: item for item in provenance.get("repositories", [])}
    applications = []
    for app in inventory.get("applications", []):
        name = _require_string(app.get("name"), "Application name")
        source = provenance_by_name.get(name)
        if not source or source.get("actual_commit") != app.get("actual_commit"):
            raise DescriptorGenerationError(f"Source provenance does not confirm actual commit for {name}.")
        source_tree = source.get("source_tree", {})
        applications.append({
            "app_name": name,
            "repository": app["repository"],
            "requested_ref": app["requested_ref"],
            "actual_commit": app["actual_commit"],
            "source_tree_sha256": source_tree.get("sha256"),
            **({"descriptor_path": next(
                (item.get("descriptor") for item in lock.get("applications", []) if item.get("name") == name and item.get("descriptor")),
                None,
            )} if any(item.get("descriptor") for item in lock.get("applications", []) if item.get("name") == name) else {}),
            **({"descriptor_sha256": next(
                (item.get("descriptor_sha256") for item in lock.get("applications", []) if item.get("name") == name and item.get("descriptor_sha256")),
                None,
            )} if any(item.get("descriptor_sha256") for item in lock.get("applications", []) if item.get("name") == name) else {}),
        })
    applications.sort(key=lambda item: item["app_name"])

    verified_services = {item["service_id"]: item for item in composition_report.get("services", [])}
    verified_external = {item["service_id"]: item for item in composition_report.get("external_requirements", [])}
    services = []
    for item in lock.get("services", []):
        record = verified_services.get(item.get("service_id"))
        if not record or record.get("descriptor_sha256") != item.get("descriptor_sha256"):
            raise DescriptorGenerationError("Lock service inventory does not match verified composition.")
        artifact = item.get("artifact", {})
        service = {
            "service_id": item["service_id"],
            "service_kind": "container",
            "descriptor_path": item["descriptor"],
            "descriptor_sha256": item["descriptor_sha256"],
            "depends_on": item.get("depends_on", []),
        }
        if isinstance(artifact, dict) and artifact.get("image"):
            service["image"] = artifact["image"]
        services.append(service)
    external = []
    for item in lock.get("external_requirements", []):
        record = verified_external.get(item.get("service_id"))
        if not record or record.get("descriptor_sha256") != item.get("descriptor_sha256"):
            raise DescriptorGenerationError("Lock external-requirement inventory does not match verified composition.")
        provider = item.get("provider", {})
        external.append({
            "requirement_id": item["service_id"],
            "provider": provider["name"],
            "requirement": provider["requirement"],
            "descriptor_path": item["descriptor"],
            "descriptor_sha256": item["descriptor_sha256"],
            "depends_on": item.get("depends_on", []),
            **({"documentation": provider["documentation"]} if provider.get("documentation") else {}),
        })

    def domain(state: str = "not_declared", declarations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {"state": state, "declarations": declarations or [], "verification": []}

    service_declarations = []
    for item in composition_report.get("services", []) + composition_report.get("external_requirements", []):
        service_declarations.append({
            "authority": "service_descriptor",
            "reference": item["descriptor"],
            "sha256": item["descriptor_sha256"],
            "claims": [{"service_id": item["service_id"], "service_kind": item["service_kind"]}],
        })
    requirements = {
        "services": domain("declared", service_declarations) if service_declarations else domain(),
        "storage": domain(),
        "networking": domain(),
        "configuration": domain(),
        "health_readiness": domain(),
        "operations": domain(),
        "infrastructure": domain(),
    }

    evidence_records = []
    bound = {item["name"]: item for item in evidence_report.get("evidence", [])}
    for name in sorted(EVIDENCE_FILES):
        record = bound.get(name)
        if not record or record.get("sha256") != _sha(files[name]) or record.get("size_bytes") != len(files[name]):
            raise DescriptorGenerationError(f"Evidence binding record mismatch for {name}.")
        evidence_records.append({
            "name": name,
            "path": record["path"],
            "sha256": record["sha256"],
            "size_bytes": record["size_bytes"],
        })

    runtime = inventory["runtime"]
    framework = inventory["framework"]
    pdd = {
        "schema_version": "1.0.0",
        "descriptor_type": "ndf.product-deployment",
        "descriptor_id": f"pdd:{product['id']}:{platform_name.replace('/', '-')}:sha256:{digest.removeprefix('sha256:')}",
        "product": {"id": product["id"], "name": product["name"]},
        "artifact": {
            "repository": image_meta["repository"],
            "digest": digest,
            "platform": platform_name,
            "immutable_reference": f"{image_meta['repository']}@{digest}",
            "informational_tags": result.get("tags", []),
        },
        "build": {
            "source_repository": "https://github.com/NdfTechLabs/frappe_docker",
            "source_commit": source_commit,
            "workflow_run_id": workflow_run_id,
            "built_at": built_at,
            **({"workflow_run_url": workflow_run_url} if workflow_run_url else {}),
            "build_metadata_sha256": _sha(files["build_metadata"]),
        },
        "composition": {
            "lock": {"version": 2, "sha256": _sha(files["lock_v2"])},
            "applications": applications,
            "services": services,
            "external_requirements": external,
            "verification": {
                "status": "passed",
                "evidence_name": "image_composition_verification",
                "evidence_sha256": _sha(files["image_composition_verification"]),
            },
        },
        "runtime_inventory": {
            "scope": "builder_stage",
            "source_evidence": "build_inventory",
            "framework": framework,
            "python": runtime["python"],
            "node": runtime["node"],
            "yarn": runtime["yarn"],
            "bench": runtime["bench"],
            "platform": runtime["platform"],
            "installed_packages": inventory["installed_packages"],
        },
        "requirements": requirements,
        "evidence": evidence_records,
        "integrity": {
            "algorithm": "sha256",
            "content_sha256": "0" * 64,
            "canonicalization": "NDF-JSON-CANONICAL-V1",
            "excluded_fields": ["integrity.content_sha256"],
        },
    }
    pdd["integrity"]["content_sha256"] = _sha(_canonical_json({
        **pdd,
        "integrity": {key: value for key, value in pdd["integrity"].items() if key != "content_sha256"},
    }))
    return pdd


def generate_descriptor(
    build_output_dir: Path,
    *,
    source_commit: str,
    workflow_run_id: str,
    built_at: str,
    workflow_run_url: str | None = None,
) -> dict[str, Any]:
    if not GIT_SHA.fullmatch(source_commit):
        raise DescriptorGenerationError("Source commit must be a full lowercase Git SHA.")
    _require_string(workflow_run_id, "Workflow run ID")
    try:
        parsed = datetime.fromisoformat(built_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DescriptorGenerationError("Build timestamp must be an ISO-8601 date-time.") from exc
    if parsed.tzinfo is None:
        raise DescriptorGenerationError("Build timestamp must include a timezone.")
    values, files = _load_inputs(build_output_dir)
    # The publication workflow outputs these two reports in addition to the
    # eleven-file verification bundle. They are required as gate assertions,
    # but are not added to the fixed M4.2.5 evidence inventory.
    for key, filename in (
        ("build_result", "build-result.json"),
        ("image_validation", "image-validation.json"),
        ("image_verification_evidence", "image-verification-evidence.json"),
    ):
        values[key], _ = _read_json(build_output_dir / filename, filename)
    gate, _ = _read_json(build_output_dir / "publication-gate.json", "publication-gate.json")
    if gate.get("status") != "ready":
        raise DescriptorGenerationError("Publication gate must be ready before PDD generation.")
    gate_image = gate.get("image", {})
    if (
        gate_image.get("digest") != values["build_result"].get("digest")
        or gate_image.get("id") != values["build_metadata"].get("image", {}).get("id")
        or gate_image.get("repository") != values["build_metadata"].get("image", {}).get("repository")
    ):
        raise DescriptorGenerationError("Publication gate identifies a different image artifact.")
    _verify_inputs(values, files)
    descriptor = _build_descriptor(
        values, files, source_commit=source_commit, workflow_run_id=workflow_run_id,
        built_at=built_at, workflow_run_url=workflow_run_url,
    )
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(descriptor)
    except (OSError, json.JSONDecodeError) as exc:
        raise DescriptorGenerationError(f"Unable to load PDD schema: {exc}") from exc
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise DescriptorGenerationError(f"PDD schema validation failed at {location}: {exc.message}") from exc
    return descriptor


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-output-dir", required=True, type=Path)
    parser.add_argument("--source-commit", default=None)
    parser.add_argument("--workflow-run-id", default=None)
    parser.add_argument("--built-at", required=True, help="ISO-8601 build completion timestamp with timezone.")
    parser.add_argument("--workflow-run-url")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        descriptor = generate_descriptor(
            args.build_output_dir,
            source_commit=args.source_commit or __import__("os").environ.get("GITHUB_SHA", ""),
            workflow_run_id=args.workflow_run_id or __import__("os").environ.get("GITHUB_RUN_ID", ""),
            built_at=args.built_at,
            workflow_run_url=args.workflow_run_url,
        )
        raw = (json.dumps(descriptor, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        try:
            temporary.write_bytes(raw)
            temporary.replace(args.output)
        finally:
            # A failed write/replace must not leave a stale temporary artifact.
            temporary.unlink(missing_ok=True)
    except (DescriptorGenerationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Generated PDD: {args.output}")
    print(f"Descriptor ID: {descriptor['descriptor_id']}")
    print(f"Image digest: {descriptor['artifact']['digest']}")
    print(f"Content SHA-256: {descriptor['integrity']['content_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
