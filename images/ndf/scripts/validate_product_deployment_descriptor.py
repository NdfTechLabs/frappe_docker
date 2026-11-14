"""Independently validate an NDF Product Deployment Descriptor."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

NDF_DIR = Path(__file__).resolve().parents[1]
SCHEMA_PATH = NDF_DIR / "schemas" / "product-deployment-descriptor-v1.schema.json"
EXPECTED_EVIDENCE = {
    "lock_v2",
    "apps_json",
    "build_metadata",
    "buildx_metadata",
    "build_inventory",
    "build_evidence",
    "source_provenance",
    "source_provenance_verification",
    "source_tree_post_cleanup",
    "source_tree_runtime",
    "image_composition_verification",
}
class DescriptorValidationError(Exception):
    """Raised when a PDD fails independent validation."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DescriptorValidationError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise DescriptorValidationError(f"Non-finite JSON number is prohibited: {value}")


def _read_descriptor(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DescriptorValidationError(f"Unable to read descriptor as UTF-8: {exc}") from exc
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DescriptorValidationError(f"Descriptor is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise DescriptorValidationError("Descriptor root must be a JSON object.")
    return value


def _canonical_json(value: Any) -> bytes:
    """Independent implementation of NDF-JSON-CANONICAL-V1."""

    def check(item: Any) -> None:
        if isinstance(item, float):
            raise DescriptorValidationError(
                "NDF-JSON-CANONICAL-V1 prohibits floating-point values."
            )
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise DescriptorValidationError("JSON object keys must be strings.")
            for child in item.values():
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)

    check(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DescriptorValidationError(f"Unable to canonicalize descriptor: {exc}") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _schema_validate(descriptor: dict[str, Any], schema_path: Path) -> None:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(
            schema, format_checker=Draft202012Validator.FORMAT_CHECKER
        )
        errors = sorted(
            validator.iter_errors(descriptor),
            key=lambda error: (list(map(str, error.absolute_path)), error.message),
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise DescriptorValidationError(f"Unable to load authoritative PDD schema: {exc}") from exc
    except ValidationError as exc:
        raise DescriptorValidationError(f"Authoritative PDD schema is invalid: {exc.message}") from exc

    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise DescriptorValidationError(
            f"Schema validation failed at {location}: {error.message}"
        )


def _validate_integrity(descriptor: dict[str, Any]) -> None:
    integrity = descriptor["integrity"]
    expected = integrity["content_sha256"]
    payload = {
        **descriptor,
        "integrity": {
            key: value for key, value in integrity.items() if key != "content_sha256"
        },
    }
    actual = _sha256(_canonical_json(payload))
    if actual != expected:
        raise DescriptorValidationError(
            f"Descriptor content SHA-256 mismatch: expected {expected}, calculated {actual}."
        )


def _validate_identity(descriptor: dict[str, Any]) -> None:
    product = descriptor["product"]
    artifact = descriptor["artifact"]
    digest = artifact["digest"]
    platform = artifact["platform"].replace("/", "-")
    expected_id = (
        f"pdd:{product['id']}:{platform}:sha256:{digest.removeprefix('sha256:')}"
    )
    if descriptor["descriptor_id"] != expected_id:
        raise DescriptorValidationError(
            f"Descriptor ID does not match product/platform/image identity; expected {expected_id}."
        )

    immutable_reference = artifact.get("immutable_reference")
    expected_reference = f"{artifact['repository']}@{digest}"
    if immutable_reference is not None and immutable_reference != expected_reference:
        raise DescriptorValidationError(
            "Artifact immutable_reference does not match repository and digest."
        )


def _safe_evidence_path(value: str) -> bool:
    if not value or "\\" in value:
        return False
    if value.startswith("/") or any(ord(character) < 32 for character in value):
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def _validate_evidence_references(descriptor: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = descriptor["evidence"]
    by_name: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for record in records:
        name = record["name"]
        path = record["path"]
        if name in by_name:
            raise DescriptorValidationError(f"Duplicate evidence name: {name}.")
        if not _safe_evidence_path(path):
            raise DescriptorValidationError(f"Unsafe evidence path for {name}: {path}.")
        if path in paths:
            raise DescriptorValidationError(f"Duplicate evidence path: {path}.")
        by_name[name] = record
        paths.add(path)

    missing = EXPECTED_EVIDENCE - by_name.keys()
    extra = by_name.keys() - EXPECTED_EVIDENCE
    if missing or extra:
        raise DescriptorValidationError(
            f"Evidence inventory mismatch; missing={sorted(missing)}, extra={sorted(extra)}."
        )

    build_metadata = by_name["build_metadata"]["sha256"]
    if descriptor["build"].get("build_metadata_sha256") != build_metadata:
        raise DescriptorValidationError(
            "Build metadata SHA-256 does not match its evidence record."
        )
    composition_evidence = by_name["image_composition_verification"]["sha256"]
    if descriptor["composition"]["verification"]["evidence_sha256"] != composition_evidence:
        raise DescriptorValidationError(
            "Composition verification SHA-256 does not match its evidence record."
        )
    if descriptor["composition"]["lock"]["sha256"] != by_name["lock_v2"]["sha256"]:
        raise DescriptorValidationError(
            "Composition lock SHA-256 does not match the lock-v2 evidence record."
        )
    if descriptor["runtime_inventory"]["source_evidence"] != "build_inventory":
        raise DescriptorValidationError(
            "Runtime inventory source must identify the build_inventory evidence."
        )
    for domain in descriptor["requirements"].values():
        for verification in domain["verification"]:
            reference = verification["evidence_reference"]
            match = next(
                (item for item in records if item["path"] == reference),
                None,
            )
            if match is not None and verification["evidence_sha256"] != match["sha256"]:
                raise DescriptorValidationError(
                    f"Requirement verification SHA-256 does not match evidence record: {reference}."
                )
    return by_name


def _validate_composition(descriptor: dict[str, Any]) -> None:
    composition = descriptor["composition"]
    applications = composition["applications"]
    app_by_name: dict[str, dict[str, Any]] = {}
    for app in applications:
        name = app["app_name"]
        if name in app_by_name:
            raise DescriptorValidationError(f"Duplicate Bench application identity: {name}.")
        app_by_name[name] = app
        if ("descriptor_path" in app) != ("descriptor_sha256" in app):
            raise DescriptorValidationError(
                f"Application {name} must provide descriptor_path and descriptor_sha256 together."
            )

    artifact_platform = descriptor["artifact"]["platform"]
    runtime_platform = descriptor["runtime_inventory"]["platform"]["oci"]
    if artifact_platform != runtime_platform:
        raise DescriptorValidationError(
            "Artifact platform does not match the measured runtime inventory platform."
        )

    framework = descriptor["runtime_inventory"]["framework"]
    framework_app = app_by_name.get(framework["name"])
    if framework_app is None:
        raise DescriptorValidationError(
            f"Runtime framework {framework['name']} is absent from the Bench application inventory."
        )
    for field in ("repository", "requested_ref", "actual_commit"):
        if framework_app[field] != framework[field]:
            raise DescriptorValidationError(
                f"Runtime framework {field} does not match the corresponding Bench application."
            )

    service_ids: set[str] = set()
    graph: dict[str, list[str]] = {}
    expected_service_declarations: set[tuple[str, str, str, str]] = set()

    for service in composition["services"]:
        service_id = service["service_id"]
        if service_id in app_by_name:
            raise DescriptorValidationError(
                f"Service identity {service_id} collides with a Bench application identity."
            )
        if service_id in service_ids:
            raise DescriptorValidationError(f"Duplicate service identity: {service_id}.")
        service_ids.add(service_id)
        graph[service_id] = service["depends_on"]
        expected_service_declarations.add(
            (
                service["descriptor_path"],
                service["descriptor_sha256"],
                service_id,
                "container",
            )
        )

    for requirement in composition["external_requirements"]:
        requirement_id = requirement["requirement_id"]
        if requirement_id in app_by_name:
            raise DescriptorValidationError(
                f"External requirement identity {requirement_id} collides with a Bench application identity."
            )
        if requirement_id in service_ids:
            raise DescriptorValidationError(
                f"Service/external requirement identity collision: {requirement_id}."
            )
        service_ids.add(requirement_id)
        graph[requirement_id] = requirement["depends_on"]
        expected_service_declarations.add(
            (
                requirement["descriptor_path"],
                requirement["descriptor_sha256"],
                requirement_id,
                "external",
            )
        )

    for owner, dependencies in graph.items():
        for dependency in dependencies:
            if dependency not in service_ids:
                raise DescriptorValidationError(
                    f"Composition dependency {dependency} referenced by {owner} is not declared."
                )
            if dependency == owner:
                raise DescriptorValidationError(
                    f"Composition item {owner} cannot depend on itself."
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise DescriptorValidationError(
                f"Composition service dependency cycle includes {node}."
            )
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)

    declarations = descriptor["requirements"]["services"]["declarations"]
    actual_service_declarations: set[tuple[str, str, str, str]] = set()
    for declaration in declarations:
        if declaration["authority"] != "service_descriptor":
            continue
        for claim in declaration["claims"]:
            actual_service_declarations.add(
                (
                    declaration["reference"],
                    declaration["sha256"],
                    claim.get("service_id", ""),
                    claim.get("service_kind", ""),
                )
            )
    if actual_service_declarations != expected_service_declarations:
        raise DescriptorValidationError(
            "Services requirement declarations do not match composition service and external requirement identities."
        )

    services_state = descriptor["requirements"]["services"]["state"]
    expected_state = "declared" if expected_service_declarations else "not_declared"
    if services_state != expected_state:
        raise DescriptorValidationError(
            f"Services requirement state must be {expected_state} for the declared composition."
        )


def validate_descriptor(
    descriptor_path: Path, *, schema_path: Path = SCHEMA_PATH
) -> dict[str, Any]:
    descriptor = _read_descriptor(descriptor_path)
    _schema_validate(descriptor, schema_path)
    _validate_integrity(descriptor)
    _validate_identity(descriptor)
    evidence = _validate_evidence_references(descriptor)
    _validate_composition(descriptor)
    return {
        "status": "passed",
        "schema_version": descriptor["schema_version"],
        "descriptor_id": descriptor["descriptor_id"],
        "image_digest": descriptor["artifact"]["digest"],
        "content_sha256": descriptor["integrity"]["content_sha256"],
        "evidence_count": len(evidence),
        "checks": [
            "json_and_schema",
            "canonical_content_integrity",
            "descriptor_identity",
            "evidence_reference_inventory",
            "cross_field_consistency",
            "composition_dependency_graph",
            "requirement_state_semantics",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    args = parser.parse_args()
    try:
        report = validate_descriptor(args.descriptor, schema_path=args.schema)
    except DescriptorValidationError as exc:
        print(
            json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False),
            file=sys.stdout,
        )
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
