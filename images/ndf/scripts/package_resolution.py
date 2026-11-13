#!/usr/bin/env python3
"""Offline validation for the normalized M4.2.3 package-resolution lock section."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
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
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
            raise PackageResolutionError(f"Invalid Python distribution name: {name}")
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "node":
        if name.startswith("@"):
            parts = name.split("/")
            valid_scoped = (
                len(parts) == 2
                and re.fullmatch(r"@[a-z0-9][a-z0-9._~-]*", parts[0]) is not None
                and re.fullmatch(r"[a-z0-9][a-z0-9._~-]*", parts[1]) is not None
            )
            if not valid_scoped:
                raise PackageResolutionError(f"Invalid or non-canonical npm package name: {name}")
            return name
        if re.fullmatch(r"[a-z0-9][a-z0-9._~-]*", name) is None:
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
    if not isinstance(architecture, str):
        raise PackageResolutionError("Package architecture must be a string.")
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


def _contains_secret_or_credential(value: Any) -> bool:
    forbidden_keys = {
        "password", "passwd", "token", "secret", "credential",
        "authorization", "private_key", "access_key",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            if any(marker in str(key).lower() for marker in forbidden_keys):
                return True
            if _contains_secret_or_credential(item):
                return True
    elif isinstance(value, list):
        return any(_contains_secret_or_credential(item) for item in value)
    elif isinstance(value, str) and "://" in value:
        try:
            parsed = urlsplit(value)
        except ValueError:
            return True
        if parsed.username or parsed.password or parsed.query:
            return True
    return False


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
    if (
        set(section) != required
        or section.get("schema_version") != 1
        or isinstance(section.get("schema_version"), bool)
        or not isinstance(section.get("source_policy_catalogue_version"), str)
    ):
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
    if any(not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in packages):
        raise PackageResolutionError("Every package record must be an object with a string id.")
    if any(
        not isinstance(item, dict)
        or not all(isinstance(item.get(key), str) for key in ("from", "to", "constraint"))
        for item in edges
    ):
        raise PackageResolutionError("Every dependency edge must contain string from/to/constraint fields.")
    if packages != sorted(packages, key=lambda item: item["id"]):
        raise PackageResolutionError("packages must be sorted by id.")
    if edges != sorted(edges, key=lambda item: (item["from"], item["to"], item["constraint"])):
        raise PackageResolutionError("dependency_edges must be canonically sorted.")

    app_ids = {
        item.get("app_id")
        for item in applications
        if isinstance(item, dict) and isinstance(item.get("app_id"), str)
    }
    if catalogue_path is None:
        catalogue_path = Path(__file__).resolve().parents[1] / "policies" / "package-source-profiles-v1.json"
    catalogue = _load_catalogue(catalogue_path)
    if section["source_policy_catalogue_version"] != catalogue.get("catalogue_version"):
        raise PackageResolutionError("Package source catalogue version does not match the lock.")
    if not packages:
        if edges or profiles or section["base_inventory"] is not None:
            raise PackageResolutionError("Empty package graph must not carry edges, profiles or base inventory.")
        if any(
            app.get("package_dependencies")
            for app in applications
            if isinstance(app, dict)
        ):
            raise PackageResolutionError(
                "Direct package selections are not represented by a normalized package graph."
            )
        return True
    if not isinstance(target_runtime, dict):
        raise PackageResolutionError("Package graph requires an exact target_runtime.")

    catalogue_profiles = catalogue["source_profiles"]
    if profiles != sorted(set(profiles)):
        raise PackageResolutionError("source_profiles must be sorted and unique.")

    target_platform = target_runtime.get("platform", {})
    images = target_runtime.get("images", {})
    os_target = target_runtime.get("os", {})
    if not all(isinstance(item, dict) for item in (target_platform, images, os_target)):
        raise PackageResolutionError("Target runtime platform, images and OS metadata must be objects.")
    if not isinstance(os_target.get("libc"), dict):
        raise PackageResolutionError("Target runtime libc identity is incomplete.")
    if target_platform != {"os": "linux", "architecture": "amd64"}:
        raise PackageResolutionError("Package graph target is outside the accepted A.1 linux/amd64 matrix.")
    if (
        os_target.get("distribution_family") != "debian"
        or os_target.get("id") != "debian"
        or os_target.get("version_id") != "13"
        or os_target.get("codename") != "trixie"
        or os_target.get("architecture") != "amd64"
        or os_target.get("package_manager") != "apt"
        or os_target.get("package_manager_version") != "3.0.4"
        or os_target.get("package_database") != "dpkg"
        or os_target.get("package_database_version") != "1.22.22"
        or os_target.get("libc", {}).get("implementation") != "glibc"
        or os_target.get("libc", {}).get("version") != "2.41"
    ):
        raise PackageResolutionError("Package graph target OS is outside the accepted Debian 13/Trixie, apt/dpkg, glibc 2.41 matrix.")
    if (
        target_runtime.get("python") != "3.14.10"
        or target_runtime.get("python_implementation") != "CPython"
        or target_runtime.get("python_cache_tag") != "cpython-314"
        or target_runtime.get("python_soabi") != "cpython-314-x86_64-linux-gnu"
        or target_runtime.get("python_platform") != "linux-x86_64"
        or target_runtime.get("python_executable") != "/usr/local/bin/python3"
        or not isinstance(target_runtime.get("python_build"), str)
        or "GCC 14.2.0" not in target_runtime["python_build"]
        or target_runtime.get("node") != "24.22.2"
        or target_runtime.get("npm") != "11.19.1"
        or target_runtime.get("node_platform") != "linux"
        or target_runtime.get("node_architecture") != "x64"
        or target_runtime.get("node_abi") != "137"
        or target_runtime.get("node_api") != "10"
        or target_runtime.get("node_executable") != "/home/frappe/.nvm/current/bin/node"
    ):
        raise PackageResolutionError("Package graph target Python/Node identity is incomplete or outside accepted RT-01.")
    accepted_digests = {
        "builder": "sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b",
        "runtime": "sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c",
    }
    accepted_index_digests = {
        "builder": "sha256:d97ec9f1f4c7330ac419658716244f725b3d03396ca4420ce697181dd6d31cbe",
        "runtime": "sha256:7409981f6238662325583025a8dc23364b348a806146080879f1ef48372a6bc0",
    }
    for stage in ("builder", "runtime"):
        image = images.get(stage, {})
        if (
            not isinstance(image, dict)
            or image.get("platform") != "linux/amd64"
            or image.get("manifest_digest") != accepted_digests[stage]
            or image.get("index_digest") != accepted_index_digests[stage]
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("manifest_digest", ""))
            or not isinstance(image.get("reference"), str)
            or image["reference"].rsplit("@", 1)[-1] != image.get("manifest_digest")
        ):
            raise PackageResolutionError(f"target_runtime.images.{stage} is not one of the accepted A.1 RT-01 digests.")

    by_id: dict[str, dict] = {}
    seen_singletons: set[tuple[str, str, str]] = set()
    used_profiles = set()
    source_by_package: dict[tuple[str, str], tuple[str, str]] = {}
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
        normalized_name = normalize_package_name(ecosystem, package["name"])
        if package["name"] != normalized_name or package["id"] != expected_id:
            raise PackageResolutionError(f"Non-canonical package identity: {package.get('id')}")
        if expected_id in by_id:
            raise PackageResolutionError(f"Duplicate package identity: {expected_id}")
        singleton_key = (ecosystem, normalized_name, architecture if ecosystem == "os" else "")
        if ecosystem in {"python", "os"} and singleton_key in seen_singletons:
            raise PackageResolutionError(f"Conflicting installed {ecosystem} package instance: {normalized_name}")
        seen_singletons.add(singleton_key)
        by_id[expected_id] = package
        profile_id = package["source_profile"]
        if not isinstance(profile_id, str):
            raise PackageResolutionError("Package source_profile must be a string.")
        profile = catalogue_profiles.get(profile_id)
        if profile_id not in profiles or not isinstance(profile, dict) or not profile.get("enabled"):
            raise PackageResolutionError(f"Package uses an unapproved source profile: {profile_id}")
        if profile.get("ecosystem") != ecosystem:
            raise PackageResolutionError(f"Source profile {profile_id} does not support {ecosystem}.")
        resolver = package["resolver"]
        if not isinstance(resolver, str):
            raise PackageResolutionError("Package resolver must be a string.")
        allowed = {
            "python": {"uv"},
            "node": {"npm"},
            "os": {"apt"},
        }[ecosystem]
        if resolver not in allowed or not isinstance(package["resolver_version"], str) or not package["resolver_version"]:
            raise PackageResolutionError(f"Unsupported or unpinned resolver for {ecosystem}.")
        if ecosystem == "node" and package["resolver_version"] != target_runtime.get("npm"):
            raise PackageResolutionError("npm resolver version does not match the accepted target runtime.")
        if not isinstance(package["source"], str) or not package["source"]:
            raise PackageResolutionError("Package source must be a credential-free absolute source URI.")
        try:
            parsed_source = urlsplit(package["source"])
        except ValueError as exc:
            raise PackageResolutionError("Package source URI is malformed.") from exc
        if parsed_source.scheme != "https" and ecosystem != "os":
            raise PackageResolutionError("Python and Node package sources must use HTTPS.")
        if not parsed_source.netloc or parsed_source.username or parsed_source.password or parsed_source.query or parsed_source.fragment:
            raise PackageResolutionError("Package source URI is invalid or contains credentials/query data.")
        if ecosystem == "python" and package["source"] != profile.get("registry"):
            raise PackageResolutionError("Python package source does not match its approved profile.")
        if ecosystem == "node" and package["source"] != profile.get("registry"):
            raise PackageResolutionError("Node package source does not match its approved profile.")
        if ecosystem == "os":
            if package["resolver_version"] != os_target.get("package_manager_version"):
                raise PackageResolutionError("APT resolver version does not match the accepted target runtime.")
            if architecture not in {"amd64", "all"}:
                raise PackageResolutionError("OS package architecture is outside the accepted target.")
            if package["source"] not in {
                repository["uri"]
                for repository in profile.get("repositories", [])
                if isinstance(repository, dict)
            }:
                raise PackageResolutionError("OS package source is not an approved Debian repository.")
            if profile.get("architecture") != "amd64":
                raise PackageResolutionError("OS source profile is not approved for amd64.")
        if not isinstance(package["direct"], bool) or not isinstance(package["install"], bool):
            raise PackageResolutionError("Package direct/install fields must be booleans.")
        if not isinstance(package["disposition"], str) or package["disposition"] not in {"base", "runtime_compatible", "environment_level"}:
            raise PackageResolutionError("Unsupported package disposition.")
        if package["disposition"] == "environment_level":
            raise PackageResolutionError("Environment-level package makes this target ineligible.")
        if ecosystem != "os" and package["disposition"] == "base":
            raise PackageResolutionError("A.4 dpkg evidence cannot establish Python or Node base-package presence.")
        if package["install"] != (package["disposition"] != "base"):
            raise PackageResolutionError("Package install flag conflicts with its disposition.")
        if not isinstance(package["scope"], str) or package["scope"] not in {"build", "runtime"}:
            raise PackageResolutionError("Package scope must be build or runtime.")
        requested_by = package["requested_by"]
        if (
            not isinstance(requested_by, list)
            or any(not isinstance(app_id, str) for app_id in requested_by)
            or requested_by != sorted(set(requested_by))
            or any(app_id not in app_ids for app_id in requested_by)
        ):
            raise PackageResolutionError("requested_by must contain sorted, unique locked app_id values.")
        if package["direct"] != bool(requested_by):
            raise PackageResolutionError("Direct package status must agree with requested_by.")
        if (
            not isinstance(package["integrity"], list)
            or not isinstance(package["repository_metadata"], dict)
        ):
            raise PackageResolutionError("Package integrity/repository_metadata provenance is incomplete.")
        # An empty integrity list is an explicit statement that the approved
        # source did not publish an artifact hash; never invent one.
        for integrity in package["integrity"]:
            if not isinstance(integrity, dict):
                raise PackageResolutionError("Package integrity record is malformed.")
            algorithm = integrity.get("algorithm")
            digest = integrity.get("digest")
            expected_length = {"sha256": 64, "sha512": 128}.get(algorithm)
            if (
                expected_length is None
                or not isinstance(digest, str)
                or not re.fullmatch(r"[a-fA-F0-9]+", digest)
                or len(digest) != expected_length
            ):
                raise PackageResolutionError("Package integrity record must contain a supported verified digest.")
            artifact = integrity.get("artifact")
            if not isinstance(artifact, str) or not artifact:
                raise PackageResolutionError("Package integrity record must identify its artifact.")
            if ecosystem in {"python", "node"}:
                try:
                    parsed_artifact = urlsplit(artifact)
                except ValueError as exc:
                    raise PackageResolutionError("Package artifact URI is malformed.") from exc
                if (
                    parsed_artifact.scheme != "https"
                    or not parsed_artifact.netloc
                    or parsed_artifact.username
                    or parsed_artifact.password
                    or parsed_artifact.query
                    or parsed_artifact.fragment
                ):
                    raise PackageResolutionError(
                        "Package artifact URI must be credential-free HTTPS without query or fragment data."
                    )
                allowed_hosts = (
                    profile.get("artifact_hosts", [])
                    if ecosystem == "python"
                    else ["registry.npmjs.org"]
                )
                if parsed_artifact.hostname not in allowed_hosts:
                    raise PackageResolutionError("Package artifact host is not approved by its source profile.")
            elif artifact.startswith("/") or ".." in Path(artifact).parts:
                raise PackageResolutionError("Debian package artifact path is invalid.")
        if _contains_secret_or_credential(package["repository_metadata"]):
            raise PackageResolutionError("Repository metadata contains credentials or secret-bearing values.")
        if ecosystem in {"python", "node"}:
            if package["repository_metadata"].get("source_identity") != profile.get("source_identity"):
                raise PackageResolutionError("Package repository metadata source identity does not match its approved profile.")
        if ecosystem == "os":
            metadata = package["repository_metadata"]
            approved_suites = {
                suite
                for repository in profile.get("repositories", [])
                if isinstance(repository, dict)
                for suite in repository.get("suites", [])
            }
            if (
                not isinstance(metadata.get("release_identity"), str)
                or not metadata["release_identity"]
                or not isinstance(metadata.get("release_sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", metadata["release_sha256"])
                or metadata.get("signature_verified") is not True
                or metadata.get("repository_uri") != package["source"]
                or metadata.get("suite") not in approved_suites
            ):
                raise PackageResolutionError("Debian package requires authenticated Release metadata identity/hash and verified repository signature.")
        source_key = (ecosystem, normalized_name)
        source_identity = (profile_id, package["source"])
        previous_source = source_by_package.setdefault(source_key, source_identity)
        if previous_source != source_identity:
            raise PackageResolutionError(f"Conflicting package sources selected for {ecosystem}:{normalized_name}.")
        used_profiles.add(profile_id)

    if sorted(used_profiles) != profiles:
        raise PackageResolutionError("source_profiles must exactly match profiles used by package records.")

    expected_requesters: dict[str, set[str]] = {}
    for app in applications:
        if not isinstance(app, dict):
            continue
        app_id = app.get("app_id")
        direct_dependencies = app.get("package_dependencies", [])
        if not isinstance(direct_dependencies, list):
            raise PackageResolutionError("Application package_dependencies must be an array.")
        for direct in direct_dependencies:
            if not isinstance(direct, dict):
                raise PackageResolutionError("Direct package dependency record is malformed.")
            ecosystem = direct.get("ecosystem")
            name = direct.get("name")
            version = direct.get("version")
            if not isinstance(ecosystem, str) or ecosystem not in {"python", "node", "os"} or not isinstance(name, str) or not isinstance(version, str):
                raise PackageResolutionError("Direct package dependency identity is incomplete.")
            normalized = normalize_package_name(ecosystem, name)
            candidates = [
                item for item in packages
                if item["ecosystem"] == ecosystem
                and item["name"] == normalized
                and item["version"] == version
                and item["direct"] is True
            ]
            if len(candidates) != 1:
                raise PackageResolutionError(
                    f"Direct package dependency {ecosystem}:{name}={version} "
                    "does not map to exactly one normalized package instance."
                )
            package = candidates[0]
            if not isinstance(app_id, str) or app_id not in package["requested_by"]:
                raise PackageResolutionError("Direct package requester is missing from requested_by.")
            if (
                direct.get("source") != package["source"]
                or direct.get("resolver") != package["resolver"]
                or direct.get("disposition") != package["disposition"]
                or direct.get("install") != package["install"]
                or direct.get("source_profile") != package["source_profile"]
                or direct.get("scope") != package["scope"]
            ):
                raise PackageResolutionError("Direct package provenance/disposition differs from normalized package record.")
            policy = direct.get("version_policy")
            constraint = direct.get("requested_constraint")
            if policy == "constraint":
                if not isinstance(constraint, str) or not _constraint_satisfied(ecosystem, version, constraint):
                    raise PackageResolutionError("Selected package does not satisfy a direct incoming constraint.")
            elif policy == "latest_compatible":
                if constraint is not None:
                    raise PackageResolutionError("latest_compatible direct selection must not carry a requested constraint.")
            else:
                raise PackageResolutionError("Direct package selection has an unsupported version policy.")
            expected_requesters.setdefault(package["id"], set()).add(app_id)

    for package in packages:
        expected = sorted(expected_requesters.get(package["id"], set()))
        if package["requested_by"] != expected or package["direct"] != bool(expected):
            raise PackageResolutionError("Package direct/requested_by provenance does not match application declarations.")

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

    reachable: set[str] = set()
    def mark_reachable(node: str) -> None:
        if node in reachable:
            return
        reachable.add(node)
        for child in adjacency[node]:
            mark_reachable(child)
    for package in packages:
        if package["direct"]:
            mark_reachable(package["id"])
    if reachable != set(by_id):
        missing = sorted(set(by_id) - reachable)
        raise PackageResolutionError(
            "Package graph contains orphaned or unreachable package records: "
            + ", ".join(missing)
        )

    base_packages = [item for item in packages if item["ecosystem"] == "os" and item["disposition"] == "base"]
    inventory_ref = section["base_inventory"]
    if not base_packages:
        if inventory_ref is not None:
            raise PackageResolutionError("base_inventory must be null when no OS base package is selected.")
        return True
    if not isinstance(inventory_ref, dict):
        raise PackageResolutionError("OS base packages require a verified base_inventory reference.")
    if (
        set(inventory_ref) != {"schema_version", "evidence_reference", "manifest_file", "manifest_sha256", "inventories"}
        or inventory_ref.get("schema_version") != 1
        or isinstance(inventory_ref.get("schema_version"), bool)
    ):
        raise PackageResolutionError("base_inventory reference has an unsupported or incomplete schema.")
    evidence_ref = inventory_ref.get("evidence_reference")
    expected_prefix = "images/ndf/inventories/debian-trixie-amd64/"
    expected_reference = expected_prefix + images["runtime"]["manifest_digest"].removeprefix("sha256:")
    if evidence_ref != expected_reference or ".." in Path(str(evidence_ref)).parts:
        raise PackageResolutionError("Base inventory evidence reference is not keyed by the target runtime digest.")
    if not isinstance(inventory_ref.get("inventories"), dict) or set(inventory_ref["inventories"]) != {"builder", "runtime"}:
        raise PackageResolutionError("base_inventory must contain exactly builder and runtime evidence.")
    evidence_dir = (repository_root / evidence_ref).resolve()
    if not evidence_dir.is_relative_to(repository_root.resolve()):
        raise PackageResolutionError("Base inventory evidence path escapes repository root.")
    manifest_path = evidence_dir / "inventory-manifest.json"
    if inventory_ref.get("manifest_file") != "inventory-manifest.json":
        raise PackageResolutionError("Base inventory manifest_file must be inventory-manifest.json.")
    try:
        manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if manifest_sha != inventory_ref.get("manifest_sha256"):
            raise PackageResolutionError("Base inventory manifest checksum mismatch.")
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "base-inventory-manifest-v1.schema.json"
        evidence, parsed = validate_inventory_directory(evidence_dir, schema_path)
    except (OSError, InventoryError) as exc:
        raise PackageResolutionError(f"Base inventory evidence validation failed: {exc}") from exc
    for stage in ("builder", "runtime"):
        inventory = inventory_ref["inventories"][stage]
        required_inventory_fields = {
            "image_manifest_digest", "platform", "package_database",
            "package_database_version", "inventory_file", "inventory_sha256",
            "package_count",
        }
        if not isinstance(inventory, dict) or set(inventory) != required_inventory_fields:
            raise PackageResolutionError(f"Base inventory {stage} reference is incomplete.")
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
