#!/usr/bin/env python3
"""Validate Marketplace App Descriptors and descriptor-based compositions.

This module is deliberately separate from resolve_manifest.py. It establishes
schema, metadata and composition-reference validation before resolver integration.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from referencing import Registry, Resource
from semantic_version import NpmSpec


class DescriptorValidationError(ValueError):
    """Raised when a descriptor or descriptor-based composition is invalid."""


OS_PACKAGE_MANAGERS = {
    "debian": {"apt", "dpkg"},
    "rpm": {"dnf", "yum", "rpm"},
    "alpine": {"apk"},
}
POLICY_CATALOGUE_NAME = "build-install-policies-v1.json"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DescriptorValidationError(
            f"Unable to load JSON file {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise DescriptorValidationError(f"Expected a JSON object in {path}")
    return value


def _schema_errors(
    instance: dict[str, Any], schema_path: Path, dependency_schema_path: Path
) -> list[str]:
    schema = _load_json(schema_path)
    dependency_schema = _load_json(dependency_schema_path)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(dependency_schema)
    registry = Registry().with_resource(
        dependency_schema["$id"], Resource.from_contents(dependency_schema)
    )
    validator = Draft202012Validator(
        schema,
        registry=registry,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    return [
        f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in errors
    ]


def _validate_semver(value: str, location: str) -> None:
    try:
        NpmSpec(value)
    except (TypeError, ValueError) as exc:
        raise DescriptorValidationError(
            f"Invalid SemVer range at {location}: {value!r}"
        ) from exc


def _validate_pep440(value: str, location: str) -> None:
    try:
        SpecifierSet(value)
    except (TypeError, InvalidSpecifier) as exc:
        raise DescriptorValidationError(
            f"Invalid PEP 440 specifier at {location}: {value!r}"
        ) from exc


def _validate_version_syntax(descriptor: dict[str, Any]) -> None:
    compatibility = descriptor.get("compatibility", {})
    for field in ("frappe", "erpnext", "node"):
        value = compatibility.get(field)
        if value is not None:
            _validate_semver(value, f"compatibility.{field}")
    python_runtime = compatibility.get("python")
    if python_runtime is not None:
        _validate_pep440(python_runtime, "compatibility.python")

    dependencies = descriptor.get("dependencies", {})
    for index, dependency in enumerate(dependencies.get("bench_apps", [])):
        value = dependency.get("version")
        if value is not None:
            _validate_semver(value, f"dependencies.bench_apps[{index}].version")
    for index, dependency in enumerate(dependencies.get("python", [])):
        value = dependency.get("version")
        if value is not None:
            _validate_pep440(value, f"dependencies.python[{index}].version")
    for index, dependency in enumerate(dependencies.get("node", [])):
        value = dependency.get("version")
        if value is not None:
            _validate_semver(value, f"dependencies.node[{index}].version")
    # OS version strings are intentionally not parsed here. Their semantics
    # belong to the declared target package manager and its native solver.


def _load_policy_catalogue(schema_dir: Path) -> dict[str, set[str]]:
    path = schema_dir.parent / "policies" / POLICY_CATALOGUE_NAME
    catalogue = _load_json(path)
    if catalogue.get("catalogue_version") != "1.0.0":
        raise DescriptorValidationError(
            f"Unsupported NDF policy catalogue version in {path}"
        )
    result: dict[str, set[str]] = {}
    for field in ("build_policies", "installation_policies"):
        values = catalogue.get(field)
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value.strip() for value in values
        ):
            raise DescriptorValidationError(
                f"{field} must be an array of non-empty policy identifiers in {path}"
            )
        if len(values) != len(set(values)):
            raise DescriptorValidationError(
                f"{field} contains duplicate identifiers in {path}"
            )
        result[field] = set(values)
    return result


def _validate_policy_references(
    descriptor: dict[str, Any], schema_dir: Path
) -> None:
    catalogue = _load_policy_catalogue(schema_dir)
    build = descriptor.get("build", {})
    if build.get("policy_id") and build["policy_id"] not in catalogue["build_policies"]:
        raise DescriptorValidationError(
            f"Unapproved NDF build policy: {build['policy_id']}"
        )
    installation = descriptor.get("installation", {})
    if installation.get("policy_id") and installation["policy_id"] not in catalogue[
        "installation_policies"
    ]:
        raise DescriptorValidationError(
            f"Unapproved NDF installation policy: {installation['policy_id']}"
        )


def _validate_os_package_manager(descriptor: dict[str, Any]) -> None:
    for index, dependency in enumerate(descriptor.get("dependencies", {}).get("os", [])):
        family = dependency["distribution_family"]
        manager = dependency["package_manager"]
        if manager not in OS_PACKAGE_MANAGERS[family]:
            raise DescriptorValidationError(
                "Unsupported OS package-manager combination at "
                f"dependencies.os[{index}]: {family}/{manager}"
            )


def validate_descriptor(
    descriptor: dict[str, Any],
    schema_dir: Path,
) -> None:
    """Validate authoring structure and every supplied ecosystem constraint.

    Missing metadata is allowed here; use collect_production_eligibility_issues
    to determine whether the descriptor is complete enough for production.
    """
    errors = _schema_errors(
        descriptor,
        schema_dir / "marketplace-app-descriptor-v1.schema.json",
        schema_dir / "dependency-v1.schema.json",
    )
    if errors:
        raise DescriptorValidationError(
            "Descriptor schema validation failed:\\n" + "\\n".join(errors)
        )
    _validate_version_syntax(descriptor)
    _validate_policy_references(descriptor, schema_dir)
    _validate_os_package_manager(descriptor)


def collect_production_eligibility_issues(
    descriptor: dict[str, Any],
) -> list[str]:
    """Return missing/ambiguous metadata that blocks production eligibility.

    This is a metadata completeness gate, not a dependency resolver. It does
    not calculate transitive closure or test satisfiability against an image.
    """
    issues: list[str] = []
    app_id = descriptor.get("app_id", "<unknown>")
    compatibility = descriptor.get("compatibility", {})

    if compatibility.get("status") != "verified":
        issues.append(f"{app_id}: compatibility status is not verified")

    required_compatibility = ["frappe", "python"]
    bench_dependencies = descriptor.get("dependencies", {}).get("bench_apps", [])
    if any(item.get("app_id") == "erpnext" and item.get("required") for item in bench_dependencies):
        required_compatibility.append("erpnext")
    dependencies = descriptor.get("dependencies", {})
    if any(
        item.get("required", True) for item in dependencies.get("node", [])
    ) or descriptor.get("build", {}).get("requires_assets_build"):
        required_compatibility.append("node")

    for field in required_compatibility:
        if not compatibility.get(field):
            issues.append(f"{app_id}: missing compatibility constraint for {field}")

    evidence = compatibility.get("evidence", [])
    required_evidence_versions = set(required_compatibility)
    qualifying_evidence = [
        item
        for item in evidence
        if item.get("authority") == "ndf"
        and item.get("result") == "passed"
        and required_evidence_versions.issubset(
            {
                key
                for key, value in item.get("tested_versions", {}).items()
                if value
            }
        )
    ]
    if not qualifying_evidence:
        matrix = ", ".join(sorted(required_evidence_versions))
        issues.append(
            f"{app_id}: missing passed NDF evidence covering tested versions: {matrix}"
        )

    for ecosystem in ("bench_apps", "python", "node", "os"):
        for index, dependency in enumerate(dependencies.get(ecosystem, [])):
            if dependency.get("required", True) is False:
                # Selection of optional dependencies is decided by composition.
                continue
            label = f"{app_id}: dependencies.{ecosystem}[{index}]"
            policy = dependency.get("version_policy")
            version = dependency.get("version")
            if policy == "constraint" and not version:
                issues.append(f"{label}: constraint policy requires a version")
            elif policy == "latest_compatible" and version:
                issues.append(
                    f"{label}: latest_compatible policy cannot also declare a version"
                )
            elif policy not in {"constraint", "latest_compatible"}:
                issues.append(f"{label}: missing explicit version_policy")
            elif policy == "latest_compatible" and not version:
                # Explicit policy is complete metadata; M4.2.3 must still
                # resolve and lock the exact selected version.
                continue

    return issues


def validate_production_eligibility(descriptor: dict[str, Any]) -> None:
    """Raise when descriptor metadata is not production-eligible."""
    issues = collect_production_eligibility_issues(descriptor)
    if issues:
        raise DescriptorValidationError(
            "Descriptor is not production-eligible:\\n" + "\\n".join(issues)
        )


def validate_composition_descriptors(
    composition: dict[str, Any],
    repository_root: Path,
    schema_dir: Path,
) -> list[dict[str, Any]]:
    """Validate v2 composition and resolve each referenced descriptor safely.

    Descriptor references are canonical repository-root-relative POSIX paths.
    Returned descriptors preserve composition order. No Git/network resolution
    or dependency graph resolution occurs.
    """
    composition_schema = schema_dir / "application-manifest-v2.schema.json"
    dependency_schema = schema_dir / "dependency-v1.schema.json"
    errors = _schema_errors(composition, composition_schema, dependency_schema)
    if errors:
        raise DescriptorValidationError(
            "Composition schema validation failed:\\n" + "\\n".join(errors)
        )

    root = repository_root.resolve()
    seen_ids: dict[str, str] = {}
    seen_bench_names: dict[str, str] = {}
    resolved: list[dict[str, Any]] = []

    for index, entry in enumerate(composition.get("applications", [])):
        if "descriptor" not in entry:
            # Legacy entries are schema-valid in v2 during the transition.
            continue
        relative = entry["descriptor"]
        pure_path = PurePosixPath(relative) if isinstance(relative, str) else None
        if (
            pure_path is None
            or not relative
            or relative.strip() != relative
            or "\\" in relative
            or pure_path.is_absolute()
            or ".." in pure_path.parts
            or "." in pure_path.parts
            or pure_path.as_posix() != relative
            or len(pure_path.parts) != 5
            or pure_path.parts[:4] != ("images", "ndf", "descriptors", "apps")
            or pure_path.suffix != ".json"
        ):
            raise DescriptorValidationError(
                f"applications[{index}].descriptor must be a normalized catalogue-relative POSIX path"
            )
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root):
            raise DescriptorValidationError(
                f"Descriptor path escapes repository root: {relative}"
            )
        if not candidate.is_file():
            raise DescriptorValidationError(f"Descriptor file not found: {relative}")

        descriptor = _load_json(candidate)
        validate_descriptor(descriptor, schema_dir)
        app_id = descriptor["app_id"]
        expected_relative = f"images/ndf/descriptors/apps/{app_id}.json"
        if relative != expected_relative:
            raise DescriptorValidationError(
                f"Descriptor filename/path identity mismatch: {relative} "
                f"must be {expected_relative}"
            )
        if app_id in seen_ids:
            raise DescriptorValidationError(
                f"Duplicate descriptor app_id '{app_id}' in composition: "
                f"{seen_ids[app_id]} and {relative}"
            )
        seen_ids[app_id] = relative

        bench_name = descriptor["app_module"]["bench_app_name"]
        if bench_name in seen_bench_names:
            raise DescriptorValidationError(
                f"Duplicate Bench app name '{bench_name}' in composition: "
                f"{seen_bench_names[bench_name]} and {relative}"
            )
        seen_bench_names[bench_name] = relative

        selected_ref = entry.get("target_ref") or descriptor.get("source", {}).get(
            "default_ref"
        )
        if not isinstance(selected_ref, str) or not selected_ref.strip():
            raise DescriptorValidationError(
                f"Missing source reference for application '{app_id}': "
                "set composition target_ref or descriptor source.default_ref"
            )
        resolved.append(descriptor)

    return resolved
