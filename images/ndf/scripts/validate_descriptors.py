#!/usr/bin/env python3
"""Validate Marketplace App Descriptors and descriptor-based compositions.

This module is deliberately separate from resolve_manifest.py. It establishes
schema and composition-reference validation before resolver integration.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


class DescriptorValidationError(ValueError):
    """Raised when a descriptor or descriptor-based composition is invalid."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DescriptorValidationError(f"Unable to load JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DescriptorValidationError(f"Expected a JSON object in {path}")
    return value


def _schema_errors(instance: dict[str, Any], schema_path: Path,
                   dependency_schema_path: Path) -> list[str]:
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


def validate_descriptor(descriptor: dict[str, Any], schema_dir: Path) -> None:
    errors = _schema_errors(
        descriptor,
        schema_dir / "marketplace-app-descriptor-v1.schema.json",
        schema_dir / "dependency-v1.schema.json",
    )
    if errors:
        raise DescriptorValidationError("Descriptor schema validation failed:\n" + "\n".join(errors))


def validate_composition_descriptors(
    composition: dict[str, Any],
    repository_root: Path,
    schema_dir: Path,
) -> list[dict[str, Any]]:
    """Validate v2 composition and resolve each referenced descriptor safely.

    Descriptor references are repository-root-relative POSIX paths. Returned
    descriptors preserve composition order. No Git/network resolution occurs.
    """
    composition_schema = schema_dir / "application-manifest-v2.schema.json"
    dependency_schema = schema_dir / "dependency-v1.schema.json"
    errors = _schema_errors(composition, composition_schema, dependency_schema)
    if errors:
        raise DescriptorValidationError(
            "Composition schema validation failed:\n" + "\n".join(errors)
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
        if (
            not isinstance(relative, str)
            or not relative.strip()
            or "\\" in relative
            or PurePosixPath(relative).is_absolute()
            or ".." in PurePosixPath(relative).parts
        ):
            raise DescriptorValidationError(
                f"applications[{index}].descriptor must be a normalized repository-relative POSIX path"
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

        selected_ref = entry.get("target_ref") or descriptor.get("source", {}).get("default_ref")
        if not isinstance(selected_ref, str) or not selected_ref.strip():
            raise DescriptorValidationError(
                f"Missing source reference for application '{app_id}': "
                "set composition target_ref or descriptor source.default_ref"
            )
        resolved.append(descriptor)

    return resolved
