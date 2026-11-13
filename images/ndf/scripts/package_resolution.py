#!/usr/bin/env python3
"""Offline validation for the normalized M4.2.3 package-resolution lock section."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import Version as PythonVersion
from semantic_version import NpmSpec, Version as SemVerVersion

try:
    from .validate_base_inventory import (
        InventoryError,
        find_base_package,
        validate_inventory_directory,
    )
except ImportError:
    from validate_base_inventory import (
        InventoryError,
        find_base_package,
        validate_inventory_directory,
    )


class PackageResolutionError(ValueError):
    """Raised when a package-resolution result is incomplete or inconsistent."""


def normalize_package_name(ecosystem: str, name: str) -> str:
    if not isinstance(name, str) or not name or name.strip() != name:
        raise PackageResolutionError("Package name must be a non-empty canonical string.")
    if ecosystem == "python":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "node":
        if name.startswith("@"):
            parts = name.split("/")
            if len(parts) != 2 or not all(parts) or parts[0] != parts[0].lower() or parts[1] != parts[1].lower():
                raise PackageResolutionError(f"Invalid or non-canonical npm package name: {name}")
            return name
        if name != name.lower() or "/" in name:
            raise PackageResolutionError(f"Invalid or non-canonical npm package name: {name}")
        return name
    if ecosystem == "os":
        if any(char in name for char in "|\t\r\n"):
            raise PackageResolutionError("OS package name contains an identity delimiter.")
        return name
    raise PackageResolutionError(f"Unsupported package ecosystem: {ecosystem}")


def package_identity(ecosystem: str, name: str, version: str, architecture: str = "") -> str:
    normalized = normalize_package_name(ecosystem, name)
    if not isinstance(version, str) or not version or "|" in version:
        raise PackageResolutionError("Package version must be a non-empty exact version.")
    if ecosystem == "os" and not architecture:
        raise PackageResolutionError("OS package identity requires architecture.")
    if ecosystem != "os" and architecture:
        raise PackageResolutionError(f"{ecosystem} package identity must not include architecture.")
    if "|" in normalized or "|" in architecture:
        raise PackageResolutionError("Package identity components cannot contain '|'.")
    if ecosystem == "python":
        try:
            PythonVersion(version)
        except ValueError as exc:
            raise PackageResolutionError(f"Invalid PEP 440 version: {version}") from exc
    elif ecosystem == "node":
        try:
            SemVerVersion(version)
        except ValueError as exc:
            raise PackageResolutionError(f"Invalid npm SemVer version: {version}") from exc
    return f"{ecosystem}|{normalized}|{version}|{architecture}"


def _constraint_satisfied(ecosystem: str, version: str, constraint: str) -> bool:
    try:
        if ecosystem == "python":
            return PythonVersion(version) in SpecifierSet(constraint)
        if ecosystem == "node":
            return SemVerVersion(version) in NpmSpec(constraint)
        return version == constraint
    except (TypeError, ValueError) as exc:
        raise PackageResolutionError(
            f"Invalid {ecosystem} dependency constraint {constraint!r}: {exc}"
        ) from exc


def _load_catalogue(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackageResolutionError(f"Unable to load package source catalogue: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("source_profiles"), dict):
        raise PackageResolutionError("Package source catalogue is malformed.")
    return value


def validate_package_resolution(
    section: dict[str, Any],
    *,
    target_runtime: dict[str, Any] | None,
    applications: list[dict[str, Any]],
    repository_root: Path,
    catalogue_path: Path | None = None,
) -> bool:
    """Validate package-resolution records offline; never contacts registries."""
    if not isinstance(section, dict):
        raise PackageResolutionError("package_resolution must be an object.")
    required = {
        "schema_version",
        "source_policy_catalogue_version",
        "source_profiles",
        "base_inventory",
        "packages",
        "dependency_edges",
    }
    if set(section) != required or section.get("schema_version") != 1:
        raise PackageResolutionError("package_resolution has an unsupported or incomplete schema.")
    profiles = section["source_profiles"]
    packages = section["packages"]
    edges = section["dependency_edges"]
    if not isinstance(profiles, list) or any(not isinstance(x, str) or not x for x in profiles):
        raise PackageResolutionError("source_profiles must be an array of profile identifiers.")
    if profiles != sorted(set(profiles)):
        raise PackageResolutionError("source_profiles must be sorted and unique.")
    if not isinstance(packages, list) or not isinstance(edges, list):
        raise PackageResolutionError("packages and dependency_edges must be arrays.")
    if packages != sorted(packages, key=lambda item: item.get("id", "") if isinstance(item, dict) else ""):
        raise PackageResolutionError("packages must be sorted by id.")
    if edges != sorted(edges, key=lambda item: (item.get("from", ""), item.get("to", ""), item.get("constraint", "")) if isinstance(item, dict) else ("", "", "")):
        raise PackageResolutionError("dependency_edges must be canonically sorted.")

    app_ids = {
        item.get("app_id")
        for item in applications
        if isinstance(item, dict) and isinstance(item.get("app_id"), str)
    }
    if packages:
        if not isinstance(target_runtime, dict):
            raise PackageResolutionError("Package graph requires an exact target_runtime.")
        if catalogue_path is None:
            catalogue_path = Path(__file__).resolve().parents[1] / "policies" / "package-source-profiles-v1.json"
        catalogue = _load_catalogue(catalogue_path)
        if section["source_policy_catalogue_version"] != catalogue.get("catalogue_version"):
            raise PackageResolutionError("Package source catalogue version does not match the lock.")
    else:
        if edges or profiles or section["base_inventory"] is not None:
            raise PackageResolutionError("Empty package graph must not carry edges, profiles or base inventory.")
        return True

    catalogue_profiles = catalogue["source_profiles"]
    if profiles != sorted(set(profiles)):
        raise PackageResolutionError("source_profiles must be sorted and unique.")

    target_platform = target_runtime.get("platform", {})
    images = target_runtime.get("images", {})
    os_target = target_runtime.get("os", {})
    if target_platform != {"os": "linux", "architecture": "amd64"}:
        raise PackageResolutionError("Package graph target is outside the accepted A.1 linux/amd64 matrix.")
    if os_target.get("distribution_family") != "debian" or os_target.get("codename") != "trixie" or os_target.get("package_database") != "dpkg":
        raise PackageResolutionError("Package graph target OS is outside the accepted Debian Trixie/dpkg matrix.")
    for stage in ("builder", "runtime"):
        image = images.get(stage, {})
        if image.get("platform") != "linux/amd64" or not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("manifest_digest", "")):
            raise PackageResolutionError(f"target_runtime.images.{stage} is incomplete or unsupported.")

    by_id: dict[str, dict] = {}
    seen_singletons: set[tuple[str, str, str]] = set()
    used_profiles = set()
    for package in packages:
        if not isinstance(package, dict):
            raise PackageResolutionError("Package records must be objects.")
        fields = {
            "id", "ecosystem", "name", "version", "architecture", "source_profile",
            "source", "resolver", "resolver_version", "direct", "requested_by",
            "disposition", "install", "scope", "integrity", "repository_metadata",
        }
        if set(package) != fields:
            raise PackageResolutionError("Package record has missing or unknown fields.")
        ecosystem = package["ecosystem"]
        architecture = package["architecture"]
        expected_id = package_identity(ecosystem, package["name"], package["version"], architecture)
        if package["id"] != expected_id:
            raise PackageResolutionError(f"Non-canonical package identity: {package.get('id')}")
        if expected_id in by_id:
            raise PackageResolutionError(f"Duplicate package identity: {expected_id}")
        if ecosystem in {"python", "node"} and expected_id in seen_singletons:
            raise PackageResolutionError(f"Duplicate installed {ecosystem} package: {expected_id}")
        by_id[expected_id] = package
        profile_id = package["source_profile"]
        profile = catalogue_profiles.get(profile_id)
        if profile_id not in profiles or not isinstance(profile, dict) or not profile.get("enabled"):
            raise PackageResolutionError(f"Package uses an unapproved source profile: {profile_id}")
        if profile.get("ecosystem") != ecosystem:
            raise PackageResolutionError(f"Source profile {profile_id} does not support {ecosystem}.")
        resolver = package["resolver"]
        allowed = {
            "python": {"uv"},
            "node": {"npm"},
            "os": {"apt"},
        }[ecosystem]
        if resolver not in allowed or not isinstance(package["resolver_version"], str) or not package["resolver_version"]:
            raise PackageResolutionError(f"Unsupported or unpinned resolver for {ecosystem}.")
        if not isinstance(package["source"], str) or not package["source"] or "@" in package["source"] or "://" not in package["source"]:
            raise PackageResolutionError("Package source must be a credential-free absolute source URI.")
        if ecosystem == "python" and package["source"] != profile.get("registry"):
            raise PackageResolutionError("Python package source does not match its approved profile.")
        if ecosystem == "node" and package["source"] != profile.get("registry"):
            raise PackageResolutionError("Node package source does not match its approved profile.")
        if ecosystem == "os":
            if architecture not in {"amd64", "all"}:
                raise PackageResolutionError("OS package architecture is outside the accepted target.")
            if architecture not in {"amd64", "all"}:
                raise PackageResolutionError("Unsupported Debian package architecture.")
        if not isinstance(package["direct"], bool) or not isinstance(package["install"], bool):
            raise PackageResolutionError("Package direct/install fields must be booleans.")
        if package["disposition"] not in {"base", "runtime_compatible", "environment_level"}:
            raise PackageResolutionError("Unsupported package disposition.")
        if package["disposition"] == "environment_level":
            raise PackageResolutionError("Environment-level package makes this target ineligible.")
        if package["install"] != (package["disposition"] != "base"):
            raise PackageResolutionError("Package install flag conflicts with its disposition.")
        if package["scope"] not in {"build", "runtime"}:
            raise PackageResolutionError("Package scope must be build or runtime.")
        requested_by = package["requested_by"]
        if not isinstance(requested_by, list) or requested_by != sorted(set(requested_by)) or any(app_id not in app_ids for app_id in requested_by):
            raise PackageResolutionError("requested_by must contain sorted, unique locked app_id values.")
        if package["direct"] != bool(requested_by):
            raise PackageResolutionError("Direct package status must agree with requested_by.")
        if not isinstance(package["integrity"], list) or not isinstance(package["repository_metadata"], dict):
            raise PackageResolutionError("Package integrity/repository_metadata provenance is malformed.")
        used_profiles.add(profile_id)

    if sorted(used_profiles) != profiles:
        raise PackageResolutionError("source_profiles must exactly match profiles used by package records.")

    edge_keys = set()
    adjacency = {package_id: [] for package_id in by_id}
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {"from", "to", "constraint"}:
            raise PackageResolutionError("Dependency edge must contain from, to and constraint only.")
        source_id, target_id, constraint = edge["from"], edge["to"], edge["constraint"]
        if source_id not in by_id or target_id not in by_id or not isinstance(constraint, str) or not constraint:
            raise PackageResolutionError("Dependency edge has a missing endpoint or constraint.")
        key = (source_id, target_id, constraint)
        if key in edge_keys:
            raise PackageResolutionError("Duplicate dependency edge.")
        edge_keys.add(key)
        target = by_id[target_id]
        if not _constraint_satisfied(target["ecosystem"], target["version"], constraint):
            raise PackageResolutionError(f"Resolved dependency {target_id} does not satisfy {constraint}.")
        adjacency[source_id].append(target_id)

    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(node: str) -> None:
        if node in visiting:
            raise PackageResolutionError("Package dependency cycle detected.")
        if node in visited:
            return
        visiting.add(node)
        for child in adjacency[node]:
            visit(child)
        visiting.remove(node)
        visited.add(node)
    for package_id in sorted(adjacency):
        visit(package_id)

    base_packages = [item for item in packages if item["ecosystem"] == "os" and item["disposition"] == "base"]
    inventory_ref = section["base_inventory"]
    if not base_packages:
        if inventory_ref is not None:
            raise PackageResolutionError("base_inventory must be null when no OS base package is selected.")
        return True
    if not isinstance(inventory_ref, dict):
        raise PackageResolutionError("OS base packages require a verified base_inventory reference.")
    evidence_ref = inventory_ref.get("evidence_reference")
    expected_prefix = "images/ndf/inventories/debian-trixie-amd64/"
    if not isinstance(evidence_ref, str) or not evidence_ref.startswith(expected_prefix) or ".." in Path(evidence_ref).parts:
        raise PackageResolutionError("Invalid repository base inventory evidence reference.")
    evidence_dir = (repository_root / evidence_ref).resolve()
    if not evidence_dir.is_relative_to(repository_root.resolve()):
        raise PackageResolutionError("Base inventory evidence path escapes repository root.")
    manifest_path = evidence_dir / "inventory-manifest.json"
    try:
        manifest_sha = __import__("hashlib").sha256(manifest_path.read_bytes()).hexdigest()
        if manifest_sha != inventory_ref.get("manifest_sha256"):
            raise PackageResolutionError("Base inventory manifest checksum mismatch.")
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "base-inventory-manifest-v1.schema.json"
        evidence, parsed = validate_inventory_directory(evidence_dir, schema_path)
    except (OSError, InventoryError) as exc:
        raise PackageResolutionError(f"Base inventory evidence validation failed: {exc}") from exc
    for stage in ("builder", "runtime"):
        inventory = inventory_ref.get("inventories", {}).get(stage, {})
        evidence_stage = evidence["inventories"][stage]
        image = images[stage]
        if inventory.get("image_manifest_digest") != image.get("manifest_digest") or evidence_stage["image"]["manifest_digest"] != image.get("manifest_digest"):
            raise PackageResolutionError(f"Base inventory {stage} digest does not match target_runtime.")
        if inventory.get("platform") != image.get("platform") or inventory.get("package_database") != "dpkg" or inventory.get("package_database_version") != evidence_stage.get("package_database_version"):
            raise PackageResolutionError(f"Base inventory {stage} metadata does not match evidence.")
        if inventory.get("inventory_file") != evidence_stage.get("file") or inventory.get("inventory_sha256") != evidence_stage.get("sha256") or inventory.get("package_count") != evidence_stage.get("package_count"):
            raise PackageResolutionError(f"Base inventory {stage} inventory identity does not match evidence.")
    for package in base_packages:
        try:
            present = find_base_package(
                parsed,
                scope=package["scope"],
                name=package["name"],
                version=package["version"],
                architecture=package["architecture"],
            )
        except InventoryError as exc:
            raise PackageResolutionError(str(exc)) from exc
        if not present:
            raise PackageResolutionError(f"Base package is missing or mismatched in its {package['scope']} inventory: {package['name']}")
    return True
