#!/usr/bin/env python3
import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

try:
    from .validate_descriptors import (
        DescriptorValidationError,
        collect_production_metadata_issues,
        validate_descriptor,
    )
except ImportError:
    from validate_descriptors import (
        DescriptorValidationError,
        collect_production_metadata_issues,
        validate_descriptor,
    )
from packaging.specifiers import SpecifierSet
from packaging.version import Version as PythonVersion
from semantic_version import NpmSpec
from semantic_version import Version as SemVerVersion

try:
    from .package_resolution import (
        PackageResolutionError,
        validate_package_resolution,
    )
except ImportError:
    from package_resolution import (
        PackageResolutionError,
        validate_package_resolution,
    )



class ManifestError(Exception):
    """Raised when manifest loading or resolution fails."""


class DuplicateManifestIDError(ManifestError):
    """Raised when different manifest files declare the same ID."""


class ManifestLoader:
    def __init__(self, manifests_dir: Path):
        self.manifests_dir = manifests_dir.resolve()
        self.loaded = {}
        self.loading_stack = []
        self.manifest_ids = {}
        self.repository_root = self.manifests_dir.parents[2]
        self.schema_dir = self.manifests_dir.parent / "schemas"
        self._descriptor_cache = {}

    def resolve_path(self, manifest_path: str) -> Path:
        """Resolve a manifest path relative to the manifests root."""

        path = (self.manifests_dir / manifest_path).resolve()

        if not path.is_relative_to(self.manifests_dir):
            raise ManifestError(
                f"Manifest path escapes the manifests directory: {manifest_path}"
            )

        if not path.is_file():
            raise ManifestError(f"Manifest not found: {manifest_path}")

        return path

    def load_json(self, path: Path) -> dict:
        """Load and parse a JSON manifest."""

        try:
            with path.open("r", encoding="utf-8") as file:
                manifest = json.load(file)

        except json.JSONDecodeError as exc:
            raise ManifestError(f"Invalid JSON in {path.name}: {exc}") from exc

        except OSError as exc:
            raise ManifestError(f"Unable to read {path}: {exc}") from exc

        if not isinstance(manifest, dict):
            raise ManifestError(f"Manifest must contain a JSON object: {path.name}")

        return manifest

    def load(self, manifest_path: str) -> dict:
        """Load a manifest and recursively load its includes."""

        path = self.resolve_path(manifest_path)

        if path in self.loading_stack:
            cycle = self.loading_stack + [path]
            chain = " -> ".join(p.name for p in cycle)

            raise ManifestError(f"Circular manifest inclusion detected: {chain}")

        if path in self.loaded:
            return self.loaded[path]

        manifest = self.load_json(path)
        self.validate(manifest, path)

        if "id" not in manifest:
            raise ManifestError(f"Manifest is missing its ID: {path.name}")

        self.loading_stack.append(path)

        try:
            includes = manifest.get("includes", [])

            if not isinstance(includes, list):
                raise ManifestError(f"'includes' must be an array in {path.name}")

            loaded_includes = []
            loaded_include_paths = set()

            for include in includes:

                if not isinstance(include, dict):
                    raise ManifestError(f"Invalid include entry in {path.name}")

                include_path = include.get("manifest")

                if not isinstance(include_path, str) or not include_path:
                    raise ManifestError(
                        f"Include entry has no valid manifest path in {path.name}"
                    )

                required = include.get("required", True)

                if not isinstance(required, bool):
                    raise ManifestError(
                        f"Include 'required' must be boolean in {path.name}"
                    )

                try:
                    resolved_include_path = self.resolve_path(include_path)
                    child = self.load(include_path)

                except ManifestError as exc:
                    if required or isinstance(exc, DuplicateManifestIDError):
                        raise

                    print(
                        f"WARNING: Optional manifest unavailable: {include_path}",
                        file=sys.stderr,
                    )
                    continue

                # Prevent the same manifest from appearing more than once
                # in this parent's loaded includes.
                if resolved_include_path not in loaded_include_paths:
                    loaded_includes.append(child)
                    loaded_include_paths.add(resolved_include_path)

            loaded_capabilities = []
            capability_selections = []
            capabilities = manifest.get("capabilities", [])
            if not isinstance(capabilities, list):
                raise ManifestError(f"'capabilities' must be an array in {path.name}")

            if manifest.get("manifest_version") == "2.0.0":
                seen_capability_paths = set()
                for capability in capabilities:
                    if not isinstance(capability, dict):
                        raise ManifestError(f"Invalid capability entry in {path.name}")
                    capability_path = capability.get("manifest")
                    if not isinstance(capability_path, str) or not capability_path:
                        raise ManifestError(
                            f"Capability entry has no valid manifest path in {path.name}"
                        )
                    normalized_capability_path = (
                        self.manifests_dir / capability_path
                    ).resolve()
                    if not normalized_capability_path.is_relative_to(
                        self.manifests_dir
                    ):
                        raise ManifestError(
                            f"Capability path escapes the manifests directory: {capability_path}"
                        )
                    if normalized_capability_path in seen_capability_paths:
                        raise ManifestError(
                            f"Duplicate capability reference in {path.name}: {capability_path}"
                        )
                    seen_capability_paths.add(normalized_capability_path)
                    if normalized_capability_path in loaded_include_paths:
                        raise ManifestError(
                            f"Manifest cannot be declared as both include and capability: "
                            f"{capability_path}"
                        )
                    required = capability.get("required", False)
                    selected = capability.get("selected")
                    if not isinstance(required, bool):
                        raise ManifestError(
                            f"Capability 'required' must be boolean in {path.name}"
                        )
                    if not required and not isinstance(selected, bool):
                        raise ManifestError(
                            f"Optional capability '{capability_path}' must have an explicit "
                            "'selected' boolean."
                        )
                    include_capability = required or selected is True
                    capability_selections.append(
                        {
                            "manifest": capability_path,
                            "required": required,
                            "selected": include_capability,
                        }
                    )
                    if not include_capability:
                        continue
                    try:
                        resolved_capability_path = self.resolve_path(capability_path)
                        child = self.load(capability_path)
                    except ManifestError as exc:
                        if (
                            required
                            or selected is True
                            or isinstance(exc, DuplicateManifestIDError)
                        ):
                            raise
                        raise ManifestError(
                            f"Selected optional capability is unavailable: "
                            f"{capability_path}: {exc}"
                        ) from exc
                    if resolved_capability_path not in loaded_include_paths:
                        loaded_capabilities.append(child)
                        loaded_include_paths.add(resolved_capability_path)

            manifest_id = manifest["id"]
            existing_path = self.manifest_ids.get(manifest_id)

            if existing_path is not None and existing_path != path:
                raise DuplicateManifestIDError(
                    f"Duplicate manifest ID '{manifest_id}' detected.\n"
                    f"First defined in: {existing_path}\n"
                    f"Conflicting definition in: {path}"
                )

            manifest["_source_path"] = str(path)
            manifest["_loaded_includes"] = loaded_includes
            manifest["_loaded_capabilities"] = loaded_capabilities
            manifest["_capability_selections"] = capability_selections

            self.manifest_ids[manifest_id] = path
            self.loaded[path] = manifest

            return manifest

        finally:
            self.loading_stack.pop()

    def validate(self, manifest: dict, path: Path):
        """Validate a manifest against the NDF manifest schema."""

        manifest_version = manifest.get("manifest_version")
        schema_name = (
            "application-manifest-v2.schema.json"
            if manifest_version == "2.0.0"
            else "application-manifest-v1.schema.json"
        )
        schema_path = self.schema_dir / schema_name

        try:
            with schema_path.open("r", encoding="utf-8") as file:
                schema = json.load(file)

        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(f"Unable to load manifest schema: {exc}") from exc

        validator = Draft202012Validator(schema)

        errors = sorted(
            validator.iter_errors(manifest),
            key=lambda error: list(error.absolute_path),
        )

        if errors:
            details = []

            for error in errors:
                location = ".".join(str(part) for part in error.absolute_path)
                location = location or "<root>"

                details.append(f"  - {location}: {error.message}")

            raise ManifestError(
                f"Schema validation failed for {path.name}:\n" + "\n".join(details)
            )

    def resolve_policy(self, manifest: dict) -> dict[str, bool]:
        """Compute restrictive policy across the complete loaded manifest graph."""
        policies = []

        def collect(current: dict):
            policies.append(current.get("resolution", {}))
            for child in current.get("_loaded_includes", []):
                collect(child)
            for child in current.get("_loaded_capabilities", []):
                collect(child)

        collect(manifest)
        values = {
            "require_immutable_commit": False,
            "fail_on_unverified_compatibility": False,
        }

        for policy in policies:
            if not isinstance(policy, dict):
                raise ManifestError("Manifest resolution policy must be an object.")
            for key in values:
                if key in policy and not isinstance(policy[key], bool):
                    raise ManifestError(f"Resolution policy '{key}' must be a boolean.")
            values["require_immutable_commit"] = values[
                "require_immutable_commit"
            ] or policy.get("require_immutable_commit", True)
            values["fail_on_unverified_compatibility"] = values[
                "fail_on_unverified_compatibility"
            ] or policy.get("fail_on_unverified_compatibility", True)

        return values

    def _load_app_descriptor(self, relative_path: str) -> tuple[dict, str, str]:
        """Load one canonical Marketplace App Descriptor and its checksum."""
        from pathlib import PurePosixPath

        pure = PurePosixPath(relative_path)
        if (
            not relative_path
            or relative_path.strip() != relative_path
            or "\\" in relative_path
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != relative_path
            or pure.parts[:4] != ("images", "ndf", "descriptors", "apps")
            or len(pure.parts) != 5
            or pure.suffix != ".json"
        ):
            raise ManifestError(
                f"Invalid canonical app descriptor path: {relative_path}"
            )

        path = (self.repository_root / relative_path).resolve()
        descriptor_root = (
            self.repository_root / "images" / "ndf" / "descriptors" / "apps"
        ).resolve()
        if not path.is_relative_to(descriptor_root) or not path.is_file():
            raise ManifestError(
                f"Marketplace App Descriptor not found or unsafe: {relative_path}"
            )

        raw = path.read_bytes()
        checksum = hashlib.sha256(raw).hexdigest()
        cache_key = (relative_path, checksum)
        if cache_key in self._descriptor_cache:
            return self._descriptor_cache[cache_key], relative_path, checksum
        try:
            descriptor = json.loads(raw.decode("utf-8"))
            validate_descriptor(descriptor, self.schema_dir)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            DescriptorValidationError,
        ) as exc:
            raise ManifestError(
                f"Invalid Marketplace App Descriptor {relative_path}: {exc}"
            ) from exc

        if path.stem != descriptor.get("app_id"):
            raise ManifestError(
                f"Descriptor filename does not match app_id in {relative_path}"
            )
        self._descriptor_cache[cache_key] = descriptor
        return descriptor, relative_path, checksum

    def _collect_descriptor_package_requirements(
        self, descriptor: dict, target_runtime: dict, selected_optional: set[str]
    ) -> list[dict]:
        """Collect declared package constraints without selecting or resolving versions."""
        os_target = target_runtime.get("os", {})
        catalogue_path = (
            self.repository_root / "images" / "ndf" / "policies"
            / "package-source-profiles-v1.json"
        )
        try:
            catalogue = json.loads(catalogue_path.read_text(encoding="utf-8"))
            profiles = catalogue["source_profiles"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ManifestError(f"Unable to load approved package source profiles: {exc}") from exc

        profile_ids = {
            "python": "python-pypi-public-v1",
            "node": "node-npm-public-v1",
            "os": "os-debian-trixie-public-amd64-v1",
        }
        requirements = []
        for ecosystem in ("python", "node", "os"):
            for dependency in descriptor.get("dependencies", {}).get(ecosystem, []):
                name = dependency.get("name", "")
                if (
                    not dependency.get("required", True)
                    and f"{ecosystem}:{name}" not in selected_optional
                ):
                    continue

                policy = dependency.get("version_policy")
                constraint = dependency.get("version")
                if policy == "constraint":
                    if not isinstance(constraint, str) or not constraint:
                        raise ManifestError(
                            f"{descriptor['app_id']}: {ecosystem}:{name} constraint policy requires a version."
                        )
                    try:
                        if ecosystem == "python":
                            SpecifierSet(constraint)
                        elif ecosystem == "node":
                            NpmSpec(constraint)
                    except (TypeError, ValueError) as exc:
                        raise ManifestError(
                            f"{descriptor['app_id']}: invalid {ecosystem} constraint for {name}."
                        ) from exc
                elif policy == "latest_compatible":
                    if constraint is not None:
                        raise ManifestError(
                            f"{descriptor['app_id']}: latest_compatible {ecosystem}:{name} "
                            "must not include a version."
                        )
                else:
                    raise ManifestError(
                        f"{descriptor['app_id']}: unsupported version policy for {ecosystem}:{name}."
                    )

                profile_id = profile_ids[ecosystem]
                profile = profiles.get(profile_id)
                if (
                    not isinstance(profile, dict)
                    or not profile.get("enabled")
                    or profile.get("ecosystem") != ecosystem
                ):
                    raise ManifestError(
                        f"{descriptor['app_id']}: approved source profile is unavailable: {profile_id}."
                    )

                source_hint = dependency.get("source")
                if ecosystem == "python" and source_hint is not None:
                    if source_hint != profile.get("registry"):
                        raise ManifestError(
                            f"{descriptor['app_id']}: Python dependency {name} source hint "
                            "does not match the approved public PyPI profile."
                        )
                if ecosystem == "os":
                    if (
                        os_target.get("distribution_family") != profile.get("distribution")
                        or os_target.get("version_id") != profile.get("release")
                        or os_target.get("codename") != profile.get("codename")
                        or os_target.get("architecture") != profile.get("architecture")
                        or os_target.get("package_manager") != profile.get("package_manager")
                        or os_target.get("package_database") != profile.get("package_database")
                        or dependency.get("distribution_family") != profile.get("distribution")
                        or dependency.get("package_manager") != profile.get("package_manager")
                    ):
                        raise ManifestError(
                            f"{descriptor['app_id']}: OS package requirement {name} "
                            "does not match the approved target/source profile."
                        )

                scope = dependency.get("scope")
                if ecosystem == "python":
                    scope = "build" if dependency.get("build_required", False) else "runtime"

                requirement = {
                    "ecosystem": ecosystem,
                    "name": name,
                    "version_policy": policy,
                    "requested_constraint": constraint if policy == "constraint" else None,
                    "source_profile": profile_id,
                    "disposition": dependency.get("disposition"),
                    "install": dependency.get("disposition") != "base",
                    "scope": scope,
                }
                if ecosystem == "node":
                    requirement["package_manager"] = dependency.get("package_manager")
                elif ecosystem == "os":
                    requirement["package_manager"] = dependency.get("package_manager")
                    requirement["distribution_family"] = dependency.get("distribution_family")
                requirements.append(requirement)

        return sorted(
            requirements,
            key=lambda item: (item["ecosystem"], item["name"]),
        )

    def _validate_descriptor_target(
        self, descriptor: dict, target_runtime: dict, selected_optional: set[str]
    ) -> None:
        """Check declared compatibility against the exact selected runtime matrix."""
        app_id = descriptor["app_id"]
        compatibility = descriptor.get("compatibility", {})
        required_fields = ["frappe", "python"]
        bench_deps = descriptor.get("dependencies", {}).get("bench_apps", [])
        if any(
            item.get("app_id") == "erpnext"
            and (
                item.get("required", True)
                or f"bench_apps:{item.get('app_id')}" in selected_optional
            )
            for item in bench_deps
        ):
            required_fields.append("erpnext")
        if descriptor.get("build", {}).get("requires_assets_build") or any(
            item.get("required", True)
            or f"node:{item.get('name')}" in selected_optional
            for item in descriptor.get("dependencies", {}).get("node", [])
        ):
            required_fields.append("node")

        for field in required_fields:
            target = target_runtime.get(field)
            constraint = compatibility.get(field)
            if not isinstance(target, str) or not target:
                raise ManifestError(
                    f"{app_id}: target_runtime.{field} must be an exact version."
                )
            if not isinstance(constraint, str) or not constraint:
                raise ManifestError(
                    f"{app_id}: compatibility.{field} is required for selected target."
                )
            try:
                if field == "python":
                    accepted = PythonVersion(target) in SpecifierSet(constraint)
                else:
                    accepted = SemVerVersion(target) in NpmSpec(constraint)
            except (TypeError, ValueError) as exc:
                raise ManifestError(
                    f"{app_id}: invalid target or compatibility constraint for {field}: {exc}"
                ) from exc
            if not accepted:
                raise ManifestError(
                    f"{app_id}: target {field} {target} does not satisfy {constraint}."
                )

    def _compose_v2_applications(self, manifest: dict) -> list:
        """Compose v2 descriptor-backed apps and their required dependency closure."""
        target_runtime = manifest.get("target_runtime")
        if not isinstance(target_runtime, dict):
            raise ManifestError(
                "v2 composition requires an explicit target_runtime matrix."
            )
        raw_selected_optional = manifest.get("selected_optional_dependencies", [])
        if (
            not isinstance(raw_selected_optional, list)
            or any(
                not isinstance(item, str) or not item for item in raw_selected_optional
            )
            or len(raw_selected_optional) != len(set(raw_selected_optional))
        ):
            raise ManifestError(
                "selected_optional_dependencies must be a unique array of non-empty strings."
            )
        selected_optional = set(raw_selected_optional)
        try:
            selected_frappe = SemVerVersion(target_runtime["frappe"])
            framework_major = int(
                str(manifest["framework"]["version"]).split(".", 1)[0]
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError(
                "v2 target_runtime.frappe and framework.version must identify a valid Frappe major."
            ) from exc
        if selected_frappe.major != framework_major:
            raise ManifestError(
                "target_runtime.frappe does not match the product framework major."
            )
        if any(not isinstance(item, str) or not item for item in selected_optional):
            raise ManifestError(
                "selected_optional_dependencies must contain non-empty strings."
            )

        applications: dict[str, dict] = {}
        app_ids: dict[str, str] = {}
        source_owners: dict[str, str] = {}
        pending_descriptors: list[tuple[dict, str, str, dict]] = []
        known_optional: set[str] = set()

        def add_legacy(current: dict) -> None:
            for app in current.get("applications", []):
                if "descriptor" in app or not app.get("required", False):
                    continue
                name = app["name"]
                if name in applications:
                    if applications[name] != app:
                        raise ManifestError(
                            f"Conflicting application definition: {name}\n"
                            f"First defined in: {source_owners[name]}\n"
                            f"Conflicting definition in: {current['id']}"
                        )
                    continue
                normalized = dict(app)
                normalized.setdefault("dependencies", [])
                applications[name] = normalized
                source_owners[name] = current["id"]

        def collect_legacy(current: dict) -> None:
            for child in current.get("_loaded_includes", []):
                collect_legacy(child)
            for child in current.get("_loaded_capabilities", []):
                collect_legacy(child)
            add_legacy(current)

        collect_legacy(manifest)

        def add_descriptor(relative_path: str, entry: dict, owner: str) -> None:
            descriptor, descriptor_path, checksum = self._load_app_descriptor(
                relative_path
            )
            app_id = descriptor["app_id"]
            bench_name = descriptor["app_module"]["bench_app_name"]
            existing = applications.get(bench_name)
            if existing:
                if existing.get("_app_id") != app_id:
                    raise ManifestError(
                        f"Bench app name '{bench_name}' maps to conflicting descriptor identities."
                    )
                requested_ref = entry.get("target_ref") or descriptor.get(
                    "source", {}
                ).get("default_ref")
                if existing.get("target_ref") != requested_ref:
                    raise ManifestError(
                        f"Conflicting source-ref selections for Marketplace app '{app_id}'."
                    )
                if existing.get("_descriptor_sha256") != checksum:
                    raise ManifestError(
                        f"Conflicting descriptor content for Marketplace app '{app_id}'."
                    )
                return
            if app_id in app_ids and app_ids[app_id] != bench_name:
                raise ManifestError(f"Duplicate Marketplace app_id: {app_id}")
            self._validate_descriptor_target(
                descriptor, target_runtime, selected_optional
            )
            issues = collect_production_metadata_issues(descriptor, selected_optional)
            if issues:
                raise ManifestError(
                    "Descriptor metadata is not production-ready:\n"
                    + "\n".join(f"  - {issue}" for issue in issues)
                )
            target_ref = entry.get("target_ref") or descriptor.get("source", {}).get(
                "default_ref"
            )
            if not isinstance(target_ref, str) or not target_ref:
                raise ManifestError(
                    f"{app_id}: no target_ref or descriptor default_ref."
                )
            dependencies = []
            for ecosystem in ("bench_apps", "python", "node", "os"):
                for dependency in descriptor.get("dependencies", {}).get(ecosystem, []):
                    if not dependency.get("required", True):
                        identity = dependency.get("app_id", dependency.get("name", ""))
                        known_optional.add(f"{ecosystem}:{identity}")
            for dependency in descriptor.get("dependencies", {}).get("bench_apps", []):
                dep_id = dependency["app_id"]
                selected = dependency.get("required", True) or (
                    f"bench_apps:{dep_id}" in selected_optional
                )
                if not selected:
                    continue
            package_dependencies = self._collect_descriptor_package_requirements(
                descriptor, target_runtime, selected_optional
            )
            normalized = {
                "name": bench_name,
                "repository": descriptor["source"]["repository"],
                "target_ref": target_ref,
                "required": True,
                "dependencies": dependencies,
                "compatibility_status": descriptor["compatibility"]["status"],
                "_app_id": app_id,
                "_release_version": descriptor.get("release", {}).get("version"),
                "_descriptor_path": descriptor_path,
                "_descriptor_sha256": checksum,
                "_descriptor": descriptor,
                "_package_dependencies": package_dependencies,
                "package_dependencies": package_dependencies,
                "_source_manifest": owner,
                "app_id": app_id,
                "release_version": descriptor.get("release", {}).get("version"),
                "descriptor": descriptor_path,
                "descriptor_sha256": checksum,
            }
            applications[bench_name] = normalized
            app_ids[app_id] = bench_name
            source_owners[bench_name] = owner
            pending_descriptors.append((descriptor, descriptor_path, checksum, entry))

        def collect_descriptors(current: dict) -> None:
            for child in current.get("_loaded_includes", []):
                collect_descriptors(child)
            for child in current.get("_loaded_capabilities", []):
                collect_descriptors(child)
            for entry in current.get("applications", []):
                if "descriptor" not in entry:
                    continue
                required = entry.get("required", False)
                selected = entry.get("selected")
                if not required and selected is not True:
                    continue
                add_descriptor(entry["descriptor"], entry, current["id"])

        collect_descriptors(manifest)

        # Close required descriptor dependencies using the canonical app_id filename.
        index = 0
        while index < len(pending_descriptors):
            descriptor, _, _, _ = pending_descriptors[index]
            parent_name = descriptor["app_module"]["bench_app_name"]
            parent = applications[parent_name]
            for dependency in descriptor.get("dependencies", {}).get("bench_apps", []):
                dep_id = dependency["app_id"]
                selected = dependency.get("required", True) or (
                    f"bench_apps:{dep_id}" in selected_optional
                )
                if not selected:
                    continue
                existing = applications.get(dep_id)
                if existing is None:
                    existing = next(
                        (
                            item
                            for item in applications.values()
                            if item.get("_app_id") == dep_id
                        ),
                        None,
                    )
                if existing is None:
                    canonical_path = f"images/ndf/descriptors/apps/{dep_id}.json"
                    dep_descriptor, dep_path, dep_checksum = self._load_app_descriptor(
                        canonical_path
                    )
                    add_descriptor(canonical_path, {}, f"descriptor:{parent_name}")
                    existing = applications.get(
                        dep_descriptor["app_module"]["bench_app_name"]
                    )
                if existing is None:
                    raise ManifestError(
                        f"{parent_name} requires unresolved Bench app dependency '{dep_id}'."
                    )
                dep_name = existing["name"]
                dep_release = existing.get("_release_version")
                constraint = dependency.get("version")
                if constraint:
                    if not dep_release:
                        raise ManifestError(
                            f"{parent_name} requires {dep_id} {constraint}, but the "
                            "dependency descriptor has no declared release.version."
                        )
                    try:
                        accepted = SemVerVersion(dep_release) in NpmSpec(constraint)
                    except (TypeError, ValueError) as exc:
                        raise ManifestError(
                            f"Invalid Bench app dependency constraint {constraint!r}: {exc}"
                        ) from exc
                    if not accepted:
                        raise ManifestError(
                            f"{parent_name} requires {dep_id} {constraint}, "
                            f"but descriptor declares {dep_release}."
                        )
                if dep_name not in parent["dependencies"]:
                    parent["dependencies"].append(dep_name)
            index += 1

        unknown_optional = selected_optional - known_optional
        if unknown_optional:
            raise ManifestError(
                "Unknown optional dependency selections: "
                + ", ".join(sorted(unknown_optional))
            )
        return list(applications.values())

    def compose_applications(self, manifest: dict) -> list:
        """Collect the required applications from the loaded manifest hierarchy."""
        if manifest.get("manifest_version") == "2.0.0":
            return self._compose_v2_applications(manifest)

        applications = {}
        sources = {}

        def collect(current: dict):
            for child in current.get("_loaded_includes", []):
                collect(child)
            for app in current.get("applications", []):
                if not app.get("required", False):
                    continue
                name = app["name"]
                if name in applications:
                    existing = applications[name]
                    if existing != app:
                        raise ManifestError(
                            f"Conflicting application definition: {name}\n"
                            f"First defined in: {sources[name]}\n"
                            f"Conflicting definition in: {current['id']}"
                        )
                    continue
                applications[name] = app
                sources[name] = current["id"]

        collect(manifest)
        return list(applications.values())

    def validate_dependencies(self, applications: list):
        """Ensure all application dependencies exist in the composition."""

        available_apps = {app["name"]: app for app in applications}

        errors = []

        for app in applications:
            app_name = app["name"]

            for dependency in app.get("dependencies", []):
                if dependency not in available_apps:
                    errors.append(
                        f"{app_name} requires '{dependency}', "
                        "but it is not included in the composition."
                    )

        if errors:
            raise ManifestError(
                "Application dependency validation failed:\n"
                + "\n".join(f"  - {error}" for error in errors)
            )

        return True

    def resolve_install_order(self, applications: list) -> list:
        """Calculate application installation order using dependencies."""

        available_apps = {app["name"]: app for app in applications}

        visited = set()
        visiting = []
        ordered = []

        def visit(app_name: str):
            if app_name in visiting:
                cycle_start = visiting.index(app_name)
                cycle = visiting[cycle_start:] + [app_name]

                raise ManifestError(
                    "Circular application dependency detected:\n" + " -> ".join(cycle)
                )

            if app_name in visited:
                return

            visiting.append(app_name)

            app = available_apps[app_name]

            for dependency in sorted(app.get("dependencies", [])):
                if dependency not in available_apps:
                    raise ManifestError(
                        f"Missing dependency '{dependency}' "
                        f"required by '{app_name}'"
                    )

                visit(dependency)

            visiting.pop()
            visited.add(app_name)
            ordered.append(app)

        for app_name in sorted(available_apps):
            visit(app_name)

        return ordered

    def resolve_git_ref(self, repository: str, target_ref: str) -> dict[str, str]:
        """Resolve a Git commit, tag or branch and retain selected ref provenance."""
        if re.fullmatch(r"[a-fA-F0-9]{40}", target_ref):
            try:
                with tempfile.TemporaryDirectory(prefix="ndf-git-ref-") as temp_dir:
                    subprocess.run(
                        ["git", "init", temp_dir],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=30,
                    )
                    subprocess.run(
                        [
                            "git",
                            "-C",
                            temp_dir,
                            "fetch",
                            "--depth=1",
                            repository,
                            target_ref,
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=60,
                    )
                    result = subprocess.run(
                        ["git", "-C", temp_dir, "rev-parse", "FETCH_HEAD"],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=30,
                    )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                detail = getattr(exc, "stderr", "") or str(exc)
                raise ManifestError(
                    f"Unable to verify commit '{target_ref}' from "
                    f"{repository}: {detail}"
                ) from exc

            commit = result.stdout.strip()
            if (
                not re.fullmatch(r"[a-fA-F0-9]{40}", commit)
                or commit.lower() != target_ref.lower()
            ):
                raise ManifestError(
                    f"Git did not resolve '{target_ref}' to the requested commit SHA."
                )
            return {"sha": commit, "kind": "commit", "name": commit}

        refs = [
            f"refs/tags/{target_ref}",
            f"refs/tags/{target_ref}^{{}}",
            f"refs/heads/{target_ref}",
        ]
        try:
            result = subprocess.run(
                ["git", "ls-remote", repository, *refs],
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            raise ManifestError(
                f"Git reference resolution timed out: {repository}"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise ManifestError(
                f"Unable to resolve Git reference '{target_ref}' "
                f"from {repository}: {exc.stderr.strip()}"
            ) from exc

        resolved = {}
        for line in result.stdout.splitlines():
            sha, ref = line.split("\t", 1)
            resolved[ref] = sha

        tag_ref = f"refs/tags/{target_ref}"
        peeled_tag_ref = f"refs/tags/{target_ref}^{{}}"
        branch_ref = f"refs/heads/{target_ref}"

        if peeled_tag_ref in resolved:
            return {"sha": resolved[peeled_tag_ref], "kind": "tag", "name": tag_ref}
        if tag_ref in resolved:
            return {"sha": resolved[tag_ref], "kind": "tag", "name": tag_ref}
        if branch_ref in resolved:
            return {"sha": resolved[branch_ref], "kind": "branch", "name": branch_ref}
        raise ManifestError(f"Git reference '{target_ref}' not found in {repository}")

    def resolve_application_refs(
        self,
        applications: list,
        policy: dict[str, bool],
    ) -> list:
        """Resolve required application refs and enforce effective policy."""
        errors = []
        for app in applications:
            repository = app.get("repository")
            target_ref = app.get("target_ref")
            if not repository or not target_ref:
                raise ManifestError(
                    f"Application '{app['name']}' is missing repository or target_ref."
                )

            status = str(app.get("compatibility_status", "")).strip().lower()
            if policy["fail_on_unverified_compatibility"] and status != "verified":
                errors.append(
                    f"{app['name']}: compatibility_status=" f"{status or '<missing>'}"
                )

            resolved = self.resolve_git_ref(repository, target_ref)
            commit = resolved["sha"]
            if policy["require_immutable_commit"] and not re.fullmatch(
                r"[a-fA-F0-9]{40}", commit
            ):
                errors.append(
                    f"{app['name']}: resolved source is not a full "
                    "immutable commit SHA"
                )

            app["ref"] = commit
            app["_reference_kind"] = resolved["kind"]
            app["_resolved_ref"] = resolved["name"]
            print(
                f"Resolved {app['name']}: {target_ref} -> {commit} "
                f"({resolved['kind']}: {resolved['name']})"
            )

        if errors:
            raise ManifestError(
                "Manifest resolution policy validation failed:\n"
                + "\n".join(f"  - {error}" for error in errors)
            )
        return applications

    def _load_service_descriptor(self, relative_path: str) -> tuple[dict, str]:
        """Load a canonical independent-service descriptor and checksum."""
        from pathlib import PurePosixPath

        pure = PurePosixPath(relative_path)
        if (
            not relative_path
            or relative_path.strip() != relative_path
            or "\\" in relative_path
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != relative_path
            or pure.parts[:4] != ("images", "ndf", "descriptors", "services")
            or len(pure.parts) != 5
            or pure.suffix != ".json"
        ):
            raise ManifestError(
                f"Invalid canonical service descriptor path: {relative_path}"
            )
        root = (
            self.repository_root / "images" / "ndf" / "descriptors" / "services"
        ).resolve()
        path = (self.repository_root / relative_path).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ManifestError(
                f"Service descriptor not found or unsafe: {relative_path}"
            )
        raw = path.read_bytes()
        checksum = hashlib.sha256(raw).hexdigest()
        try:
            descriptor = json.loads(raw.decode("utf-8"))
            schema_path = self.schema_dir / "service-descriptor-v1.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            errors = sorted(
                Draft202012Validator(
                    schema,
                    format_checker=Draft202012Validator.FORMAT_CHECKER,
                ).iter_errors(descriptor),
                key=lambda error: (list(error.absolute_path), error.message),
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestError(
                f"Unable to validate service descriptor {relative_path}: {exc}"
            ) from exc
        if errors:
            detail = "; ".join(error.message for error in errors)
            raise ManifestError(f"Invalid service descriptor {relative_path}: {detail}")
        if path.stem != descriptor.get("service_id"):
            raise ManifestError(
                f"Service descriptor filename does not match service_id: {relative_path}"
            )
        return descriptor, checksum

    def compose_services(self, manifest: dict) -> tuple[list[dict], list[dict]]:
        """Resolve transitive independent service and external requirement composition."""
        services: dict[str, dict] = {}
        external: dict[str, dict] = {}

        def add_descriptor(
            descriptor_path: str, expected_kind: str | None = None
        ) -> dict:
            descriptor, checksum = self._load_service_descriptor(descriptor_path)
            service_id = descriptor["service_id"]
            actual_kind = descriptor["service_kind"]
            if expected_kind and actual_kind != expected_kind:
                raise ManifestError(
                    f"{descriptor_path} has service_kind={actual_kind}; "
                    f"composition requires {expected_kind}."
                )
            inventory = services if actual_kind == "container" else external
            other_inventory = external if actual_kind == "container" else services
            if service_id in other_inventory:
                raise ManifestError(
                    f"Service identity '{service_id}' is declared as both container and external."
                )
            if service_id in inventory:
                previous = inventory[service_id]
                if previous["descriptor_sha256"] != checksum:
                    raise ManifestError(
                        f"Conflicting service descriptor identity: {service_id}"
                    )
                return previous
            item = {
                "service_id": service_id,
                "name": descriptor["name"],
                "service_kind": actual_kind,
                "artifact": descriptor.get("artifact"),
                "provider": descriptor.get("provider"),
                "depends_on": descriptor.get("depends_on", []),
                "descriptor": descriptor_path,
                "descriptor_sha256": checksum,
            }
            inventory[service_id] = item
            return item

        for current in self._walk_manifest_graph(manifest):
            for field, expected_kind in (
                ("services", "container"),
                ("external_requirements", "external"),
            ):
                for entry in current.get(field, []):
                    required = entry.get("required", False)
                    selected = entry.get("selected")
                    if not required and selected is not True:
                        continue
                    add_descriptor(entry["descriptor"], expected_kind)

        # Close service dependencies from the canonical independent-service catalogue.
        pending = list(services.values()) + list(external.values())
        index = 0
        while index < len(pending):
            item = pending[index]
            for dependency_id in sorted(item["depends_on"]):
                if dependency_id in services or dependency_id in external:
                    continue
                dependency_path = (
                    f"images/ndf/descriptors/services/{dependency_id}.json"
                )
                dependency_descriptor = add_descriptor(dependency_path)
                pending.append(dependency_descriptor)
            index += 1

        combined = {**services, **external}
        if len(combined) != len(services) + len(external):
            raise ManifestError("Service and external requirement identities overlap.")

        ordered: list[dict] = []
        visiting: list[str] = []
        visited: set[str] = set()

        def visit(service_id: str) -> None:
            if service_id in visiting:
                cycle = visiting[visiting.index(service_id) :] + [service_id]
                raise ManifestError(
                    "Circular independent-service dependency detected: "
                    + " -> ".join(cycle)
                )
            if service_id in visited:
                return
            visiting.append(service_id)
            item = combined[service_id]
            for dependency_id in sorted(item["depends_on"]):
                if dependency_id not in combined:
                    raise ManifestError(
                        f"Independent artifact '{service_id}' requires missing "
                        f"dependency '{dependency_id}'."
                    )
                visit(dependency_id)
            visiting.pop()
            visited.add(service_id)
            ordered.append(item)

        for service_id in sorted(combined):
            visit(service_id)

        for order, item in enumerate(ordered, start=1):
            item["resolution_order"] = order

        return (
            [item for item in ordered if item["service_kind"] == "container"],
            [item for item in ordered if item["service_kind"] == "external"],
        )

    def _walk_manifest_graph(self, manifest: dict) -> list[dict]:
        """Return each loaded manifest once in deterministic graph traversal order."""
        result = []
        seen = set()

        def visit(current: dict) -> None:
            path = str(Path(current["_source_path"]).resolve())
            if path in seen:
                return
            seen.add(path)
            result.append(current)
            for child in current.get("_loaded_includes", []):
                visit(child)
            for child in current.get("_loaded_capabilities", []):
                visit(child)

        visit(manifest)
        return result

    def build_lock_data(
        self,
        manifest: dict,
        applications: list,
        package_resolution: dict | None = None,
    ) -> dict[str, Any]:
        """Build deterministic application lock data in memory."""

        loaded_manifests = []
        collected_manifest_paths = set()

        def collect_manifests(current: dict):
            source_path = Path(current["_source_path"]).resolve()

            # Prevent shared manifests from appearing multiple times
            # when reached through different branches.
            if source_path in collected_manifest_paths:
                return

            collected_manifest_paths.add(source_path)

            relative_path = source_path.relative_to(self.manifests_dir)

            checksum = hashlib.sha256(source_path.read_bytes()).hexdigest()

            loaded_manifests.append(
                {
                    "id": current["id"],
                    "path": relative_path.as_posix(),
                    "sha256": checksum,
                }
            )

            for child in current.get("_loaded_includes", []):
                collect_manifests(child)
            for child in current.get("_loaded_capabilities", []):
                collect_manifests(child)

        collect_manifests(manifest)

        policy = self.resolve_policy(manifest)
        resolved_services, resolved_external = self.compose_services(manifest)
        framework_application = next(
            (app for app in applications if app["name"] == "frappe"),
            None,
        )
        if framework_application is None:
            raise ManifestError(
                "Resolved application composition does not contain Frappe."
            )

        catalogue_path = (
            self.repository_root / "images" / "ndf" / "policies"
            / "package-source-profiles-v1.json"
        )
        try:
            source_catalogue = json.loads(catalogue_path.read_text(encoding="utf-8"))
            catalogue_version = source_catalogue["catalogue_version"]
            if not isinstance(catalogue_version, str) or not catalogue_version:
                raise ValueError("catalogue_version must be a non-empty string")
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ManifestError(f"Unable to load package source catalogue version: {exc}") from exc

        if package_resolution is None:
            package_resolution_data = {
                "schema_version": 1,
                "source_policy_catalogue_version": catalogue_version,
                "source_profiles": [],
                "base_inventory": None,
                "packages": [],
                "dependency_edges": [],
            }
        else:
            package_resolution_data = copy.deepcopy(package_resolution)

        framework = dict(manifest["framework"])
        framework.update(
            {
                "target_ref": framework_application["target_ref"],
                "ref": framework_application["ref"],
                "reference_kind": framework_application.get("_reference_kind"),
                "resolved_ref": framework_application.get("_resolved_ref"),
            }
        )

        lock_data = {
            "lock_version": 2,
            "resolution_policy": policy,
            "resolver": {
                "name": "ndf-manifest-resolver",
                "version": "1.1.0",
            },
            "product": {
                "id": manifest["id"],
                "name": manifest["name"],
                "manifest_version": manifest["manifest_version"],
                "profile": manifest["profile"],
            },
            "framework": framework,
            "target_runtime": manifest.get("target_runtime"),
            "package_resolution": package_resolution_data,
            "manifests": loaded_manifests,
            "capabilities": sorted(
                [
                    {
                        "manifest": item["manifest"],
                        "required": item["required"],
                        "selected": item["selected"],
                    }
                    for current in self._walk_manifest_graph(manifest)
                    for item in current.get("_capability_selections", [])
                ],
                key=lambda item: item["manifest"],
            ),
            "services": resolved_services,
            "external_requirements": resolved_external,
            "applications": [
                {
                    "name": app["name"],
                    "repository": app["repository"],
                    "target_ref": app["target_ref"],
                    "ref": app["ref"],
                    "reference_kind": app.get("_reference_kind"),
                    "resolved_ref": app.get("_resolved_ref"),
                    "compatibility_status": app.get("compatibility_status"),
                    "dependencies": app.get("dependencies", []),
                    "installation_order": index,
                    **(
                        {
                            "app_id": app["_app_id"],
                            "release_version": app.get("_release_version"),
                            "descriptor": app["_descriptor_path"],
                            "descriptor_sha256": app["_descriptor_sha256"],
                            "package_dependencies": app.get("package_dependencies", []),
                        }
                        if app.get("_app_id")
                        else {}
                    ),
                }
                for index, app in enumerate(applications, start=1)
            ],
        }

        try:
            validate_package_resolution(
                lock_data["package_resolution"],
                target_runtime=lock_data.get("target_runtime"),
                applications=lock_data["applications"],
                repository_root=self.repository_root,
                catalogue_path=catalogue_path,
            )
        except PackageResolutionError as exc:
            raise ManifestError(f"Invalid package_resolution result: {exc}") from exc

        return lock_data

    def write_lock_file(
        self,
        lock_data: dict,
        output_path: Path,
    ) -> Path:
        """Write lock data atomically to disk."""

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")

        try:
            temporary_path.write_text(
                json.dumps(
                    lock_data,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            temporary_path.replace(output_path)

        except OSError as exc:
            raise ManifestError(
                f"Unable to write lock file {output_path}: {exc}"
            ) from exc

        return output_path

    def validate_lock_file(
        self,
        lock_path: Path,
        expected_manifest: dict,
        verify_manifest_checksums: bool = True,
        allow_package_resolution_migration: bool = False,
    ):
        """Validate a lock file and optionally verify source manifest checksums."""

        try:
            with lock_path.open("r", encoding="utf-8") as file:
                lock = json.load(file)

        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(f"Unable to read lock file {lock_path}: {exc}") from exc

        if not isinstance(lock, dict):
            raise ManifestError("Lock file must contain a JSON object.")

        # 1. Lock format version
        if lock.get("lock_version") != 2:
            raise ManifestError(f"Unsupported lock version: {lock.get('lock_version')}")

        policy = lock.get("resolution_policy")
        policy_keys = {
            "require_immutable_commit",
            "fail_on_unverified_compatibility",
        }
        if (
            not isinstance(policy, dict)
            or set(policy) != policy_keys
            or any(not isinstance(policy[key], bool) for key in policy_keys)
        ):
            raise ManifestError("Lock file has an invalid effective resolution policy.")
        if policy != self.resolve_policy(expected_manifest):
            raise ManifestError(
                "Lock file effective resolution policy does not match "
                "the source manifests."
            )

        if verify_manifest_checksums and lock.get(
            "target_runtime"
        ) != expected_manifest.get("target_runtime"):
            raise ManifestError(
                "Lock file target runtime matrix does not match the source manifest."
            )

        # 2. Product identity
        product = lock.get("product")

        if not isinstance(product, dict):
            raise ManifestError("Lock file has an invalid product section.")

        if product.get("id") != expected_manifest["id"]:
            raise ManifestError(
                "Lock file product ID does not match the requested manifest."
            )

        if product.get("manifest_version") != expected_manifest["manifest_version"]:
            raise ManifestError(
                "Lock file manifest version does not match the source manifest."
            )

        # 3. Source manifest checksums
        manifests = lock.get("manifests")

        if not isinstance(manifests, list) or not manifests:
            raise ManifestError("Lock file has no source manifests.")

        seen_paths = set()
        seen_ids = set()

        for entry in manifests:
            if not isinstance(entry, dict):
                raise ManifestError("Invalid source manifest entry in lock file.")

            manifest_id = entry.get("id")
            relative_path = entry.get("path")
            expected_sha256 = entry.get("sha256")

            if not all(
                isinstance(value, str) and value
                for value in (
                    manifest_id,
                    relative_path,
                    expected_sha256,
                )
            ):
                raise ManifestError("Incomplete source manifest entry in lock file.")

            if manifest_id in seen_ids:
                raise ManifestError(
                    f"Duplicate manifest ID in lock file: {manifest_id}"
                )

            if relative_path in seen_paths:
                raise ManifestError(
                    f"Duplicate manifest path in lock file: {relative_path}"
                )

            seen_ids.add(manifest_id)
            seen_paths.add(relative_path)

            if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
                raise ManifestError(
                    f"Invalid SHA-256 checksum for manifest: {relative_path}"
                )

            source_path = self.resolve_path(relative_path)

            if not source_path.is_file():
                raise ManifestError(f"Source manifest does not exist: {relative_path}")

            if verify_manifest_checksums:
                actual_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()

                if actual_sha256 != expected_sha256:
                    raise ManifestError(
                        f"Source manifest has changed since lock generation: "
                        f"{relative_path}"
                    )

        if expected_manifest["id"] not in seen_ids:
            raise ManifestError(
                "Requested product manifest is missing from the lock file."
            )

        # 4. Application entries and immutable Git references
        applications = lock.get("applications")

        if not isinstance(applications, list) or not applications:
            raise ManifestError("Lock file contains no applications.")

        available_apps = {}
        previous_order = 0

        for app in applications:
            if not isinstance(app, dict):
                raise ManifestError("Invalid application entry in lock file.")

            name = app.get("name")
            repository = app.get("repository")
            target_ref = app.get("target_ref")
            commit = app.get("ref")
            reference_kind = app.get("reference_kind")
            resolved_ref = app.get("resolved_ref")
            compatibility_status = app.get("compatibility_status")
            order = app.get("installation_order")
            dependencies = app.get("dependencies")

            if not isinstance(name, str) or not name:
                raise ManifestError("Application has an invalid name.")

            if name in available_apps:
                raise ManifestError(f"Duplicate application in lock file: {name}")

            if not isinstance(repository, str) or not repository:
                raise ManifestError(f"Application '{name}' has no repository.")

            if not isinstance(target_ref, str) or not target_ref:
                raise ManifestError(f"Application '{name}' has no target_ref.")

            if not isinstance(commit, str) or not re.fullmatch(
                r"[a-fA-F0-9]{40}", commit
            ):
                raise ManifestError(
                    f"Application '{name}' has an invalid Git commit SHA."
                )

            if reference_kind not in {"branch", "tag", "commit"}:
                raise ManifestError(
                    f"Application '{name}' has invalid reference provenance."
                )
            expected_ref_name = (
                target_ref
                if reference_kind == "commit"
                else (
                    f"refs/heads/{target_ref}"
                    if reference_kind == "branch"
                    else f"refs/tags/{target_ref}"
                )
            )
            if resolved_ref != expected_ref_name:
                raise ManifestError(
                    f"Application '{name}' has inconsistent resolved ref provenance."
                )
            if not isinstance(resolved_ref, str) or not resolved_ref:
                raise ManifestError(
                    f"Application '{name}' has no resolved Git reference name."
                )
            if policy["require_immutable_commit"] and not re.fullmatch(
                r"[a-fA-F0-9]{40}", commit
            ):
                raise ManifestError(
                    f"Application '{name}' is not locked to an immutable commit SHA."
                )
            if (
                policy["fail_on_unverified_compatibility"]
                and str(compatibility_status or "").strip().lower() != "verified"
            ):
                raise ManifestError(
                    f"Application '{name}' has unverified compatibility status."
                )

            if (
                not isinstance(order, int)
                or isinstance(order, bool)
                or order != previous_order + 1
            ):
                raise ManifestError(
                    f"Invalid installation order for application '{name}'."
                )

            if (
                not isinstance(dependencies, list)
                or any(not isinstance(dep, str) or not dep for dep in dependencies)
                or len(dependencies) != len(set(dependencies))
            ):
                raise ManifestError(f"Invalid dependencies for application '{name}'.")

            if "descriptor" in app:
                if (
                    not isinstance(app.get("app_id"), str)
                    or not app["app_id"]
                    or not isinstance(app.get("descriptor"), str)
                    or not isinstance(app.get("descriptor_sha256"), str)
                    or not re.fullmatch(r"[a-fA-F0-9]{64}", app["descriptor_sha256"])
                ):
                    raise ManifestError(
                        f"Application '{name}' has incomplete Marketplace descriptor identity."
                    )
                release_version = app.get("release_version")
                if release_version is not None:
                    try:
                        SemVerVersion(release_version)
                    except (TypeError, ValueError) as exc:
                        raise ManifestError(
                            f"Application '{name}' has an invalid declared release version."
                        ) from exc
                package_dependencies = app.get("package_dependencies", [])
                if not isinstance(package_dependencies, list):
                    raise ManifestError(
                        f"Application '{name}' has invalid package dependency selections."
                    )
                for requirement in package_dependencies:
                    if (
                        not isinstance(requirement, dict)
                        or not all(
                            isinstance(requirement.get(field), str) and requirement[field]
                            for field in (
                                "ecosystem",
                                "name",
                                "version_policy",
                                "source_profile",
                                "disposition",
                                "scope",
                            )
                        )
                        or requirement.get("ecosystem") not in {"python", "node", "os"}
                        or requirement.get("version_policy") not in {"constraint", "latest_compatible"}
                        or requirement.get("disposition")
                        not in {"base", "runtime_compatible", "environment_level"}
                        or requirement.get("scope") not in {"build", "runtime"}
                        or not isinstance(requirement.get("install"), bool)
                        or (
                            requirement.get("requested_constraint") is not None
                            and not isinstance(requirement.get("requested_constraint"), str)
                        )
                    ):
                        raise ManifestError(
                            f"Application '{name}' has an invalid native package requirement."
                        )
                    if requirement.get("version_policy") == "constraint" and not requirement.get(
                        "requested_constraint"
                    ):
                        raise ManifestError(
                            f"Application '{name}' has a constrained package requirement without a constraint."
                        )
                    if requirement.get("version_policy") == "latest_compatible" and requirement.get(
                        "requested_constraint"
                    ) is not None:
                        raise ManifestError(
                            f"Application '{name}' has a latest_compatible package requirement with a constraint."
                        )
                    if requirement.get("ecosystem") == "os" and not all(
                        isinstance(requirement.get(field), str) and requirement[field]
                        for field in ("package_manager", "distribution_family")
                    ):
                        raise ManifestError(
                            f"Application '{name}' has an OS package requirement without target manager metadata."
                        )
            available_apps[name] = app
            previous_order = order

        # 5. Dependency existence and installation order
        installed_apps = set()

        for app in applications:
            name = app["name"]

            for dependency in app["dependencies"]:
                if dependency not in available_apps:
                    raise ManifestError(
                        f"Application '{name}' requires missing dependency "
                        f"'{dependency}'."
                    )

                if dependency not in installed_apps:
                    raise ManifestError(
                        f"Application '{name}' appears before its dependency "
                        f"'{dependency}' in the lock file."
                    )

            installed_apps.add(name)

        capability_entries = lock.get("capabilities", [])
        if not isinstance(capability_entries, list):
            raise ManifestError("Lock file capability selections must be an array.")
        seen_capability_paths = set()
        for selection in capability_entries:
            if not isinstance(selection, dict):
                raise ManifestError("Invalid capability selection in lock file.")
            capability_path = selection.get("manifest")
            required = selection.get("required")
            selected = selection.get("selected")
            if (
                not isinstance(capability_path, str)
                or not capability_path
                or not isinstance(required, bool)
                or not isinstance(selected, bool)
                or (required and not selected)
                or capability_path in seen_capability_paths
            ):
                raise ManifestError(
                    "Invalid or duplicate capability selection in lock file."
                )
            seen_capability_paths.add(capability_path)

        target_runtime = lock.get("target_runtime")
        if target_runtime is not None and not isinstance(target_runtime, dict):
            raise ManifestError("Lock file has an invalid target runtime matrix.")

        locked_independent_artifacts = {}
        for section in ("services", "external_requirements"):
            entries = lock.get(section, [])
            if not isinstance(entries, list):
                raise ManifestError(f"Lock file {section} inventory must be an array.")
            seen_service_ids = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ManifestError(f"Invalid {section} entry in lock file.")
                service_id = entry.get("service_id")
                checksum = entry.get("descriptor_sha256")
                if (
                    not isinstance(service_id, str)
                    or not service_id
                    or service_id in seen_service_ids
                ):
                    raise ManifestError(
                        f"Invalid or duplicate identity in {section} lock inventory."
                    )
                if not isinstance(checksum, str) or not re.fullmatch(
                    r"[a-fA-F0-9]{64}", checksum
                ):
                    raise ManifestError(
                        f"Invalid descriptor checksum for {service_id}."
                    )
                if not isinstance(entry.get("descriptor"), str):
                    raise ManifestError(f"Missing descriptor path for {service_id}.")
                expected_kind = "container" if section == "services" else "external"
                if entry.get("service_kind") != expected_kind:
                    raise ManifestError(
                        f"{section} entry '{service_id}' has an invalid service kind."
                    )
                if expected_kind == "container":
                    artifact = entry.get("artifact")
                    image = (
                        artifact.get("image") if isinstance(artifact, dict) else None
                    )
                    if not isinstance(image, str) or not re.fullmatch(
                        r"[^@\s]+@sha256:[a-fA-F0-9]{64}", image
                    ):
                        raise ManifestError(
                            f"Container service '{service_id}' is not pinned to an OCI digest."
                        )
                    if entry.get("provider") is not None:
                        raise ManifestError(
                            f"Container service '{service_id}' contains external provider data."
                        )
                else:
                    provider = entry.get("provider")
                    if (
                        not isinstance(provider, dict)
                        or not isinstance(provider.get("name"), str)
                        or not provider["name"]
                        or not isinstance(provider.get("requirement"), str)
                        or not provider["requirement"]
                    ):
                        raise ManifestError(
                            f"External requirement '{service_id}' has invalid provider metadata."
                        )
                    if entry.get("artifact") is not None:
                        raise ManifestError(
                            f"External requirement '{service_id}' contains container artifact data."
                        )
                if not isinstance(entry.get("depends_on", []), list) or any(
                    not isinstance(item, str) or not item
                    for item in entry.get("depends_on", [])
                ):
                    raise ManifestError(f"Invalid dependency list for {service_id}.")
                order = entry.get("resolution_order")
                if not isinstance(order, int) or isinstance(order, bool) or order < 1:
                    raise ManifestError(
                        f"Invalid resolution order for independent artifact '{service_id}'."
                    )
                if order in locked_independent_artifacts:
                    raise ManifestError(
                        "Duplicate resolution order in independent artifact lock inventory."
                    )
                locked_independent_artifacts[order] = entry
                seen_service_ids.add(service_id)

        all_independent = {
            entry["service_id"]: entry
            for section in ("services", "external_requirements")
            for entry in lock.get(section, [])
        }
        independent_count = sum(
            len(lock.get(section, []))
            for section in ("services", "external_requirements")
        )
        if len(all_independent) != independent_count:
            raise ManifestError(
                "Duplicate independent artifact identity across service inventories."
            )
        if sorted(locked_independent_artifacts) != list(
            range(1, len(locked_independent_artifacts) + 1)
        ):
            raise ManifestError(
                "Independent artifact resolution order must be contiguous and start at one."
            )
        for entry in all_independent.values():
            for dependency_id in entry.get("depends_on", []):
                dependency = all_independent.get(dependency_id)
                if dependency is None:
                    raise ManifestError(
                        f"Independent artifact '{entry['service_id']}' has missing "
                        f"dependency '{dependency_id}' in lock file."
                    )
                if dependency["resolution_order"] >= entry["resolution_order"]:
                    raise ManifestError(
                        f"Independent artifact '{entry['service_id']}' appears before "
                        f"dependency '{dependency_id}' in lock file."
                    )

        # When validating a build lock against unchanged source manifests,
        # prove that the lock inventories the complete loaded manifest graph
        # and the exact required application composition. Structural checks
        # alone would allow a valid-looking lock to omit or substitute apps.
        # Lock comparison disables this check while comparing an older lock
        # against a changed manifest; it still performs structural validation.
        if verify_manifest_checksums:
            expected_manifest_entries = {}

            def collect_expected_manifests(current: dict):
                source_path = Path(current["_source_path"]).resolve()
                relative_path = source_path.relative_to(self.manifests_dir).as_posix()
                expected_manifest_entries[relative_path] = current["id"]
                for child in current.get("_loaded_includes", []):
                    collect_expected_manifests(child)
                for child in current.get("_loaded_capabilities", []):
                    collect_expected_manifests(child)

            collect_expected_manifests(expected_manifest)
            actual_manifest_entries = {
                entry["path"]: entry["id"] for entry in manifests
            }
            if actual_manifest_entries != expected_manifest_entries:
                raise ManifestError(
                    "Lock file manifest inventory does not match the "
                    "loaded source manifest graph."
                )

            expected_capabilities = sorted(
                [
                    {
                        "manifest": item["manifest"],
                        "required": item["required"],
                        "selected": item["selected"],
                    }
                    for current in self._walk_manifest_graph(expected_manifest)
                    for item in current.get("_capability_selections", [])
                ],
                key=lambda item: item["manifest"],
            )
            if lock.get("capabilities", []) != expected_capabilities:
                raise ManifestError(
                    "Lock file capability selections do not match source manifests."
                )

            expected_services, expected_external = self.compose_services(
                expected_manifest
            )
            if lock.get("services", []) != expected_services:
                raise ManifestError(
                    "Lock file service inventory does not match selected source composition."
                )
            if lock.get("external_requirements", []) != expected_external:
                raise ManifestError(
                    "Lock file external-requirement inventory does not match selected source composition."
                )

            expected_applications = self.compose_applications(expected_manifest)
            if expected_applications:
                self.validate_dependencies(expected_applications)
                expected_order = self.resolve_install_order(expected_applications)
                if len(expected_order) != len(applications):
                    raise ManifestError(
                        "Lock file application inventory does not match "
                        "the required source manifest composition."
                    )

                composition_fields = (
                    "name",
                    "repository",
                    "target_ref",
                    "dependencies",
                    "compatibility_status",
                    "app_id",
                    "release_version",
                    "descriptor",
                    "descriptor_sha256",
                    "package_dependencies",
                )
                for index, (expected_app, locked_app) in enumerate(
                    zip(expected_order, applications, strict=True),
                    start=1,
                ):
                    mismatches = [
                        field
                        for field in composition_fields
                        if locked_app.get(field) != expected_app.get(field)
                    ]
                    if mismatches or locked_app.get("installation_order") != index:
                        raise ManifestError(
                            "Lock file application composition does not match "
                            f"the source manifests at position {index}: "
                            f"{locked_app.get('name')} "
                            f"(mismatched fields: {mismatches or ['installation_order']})."
                        )

        package_resolution = lock.get("package_resolution")
        if package_resolution is None:
            has_direct_package_selections = any(
                app.get("package_dependencies")
                for app in applications
                if isinstance(app, dict)
            )
            if has_direct_package_selections and not allow_package_resolution_migration:
                raise ManifestError(
                    "Package-resolution migration required: lock v2 contains direct "
                    "package selections but no normalized package_resolution graph."
                )
        else:
            try:
                validate_package_resolution(
                    package_resolution,
                    target_runtime=lock.get("target_runtime"),
                    applications=applications,
                    repository_root=self.repository_root,
                )
            except PackageResolutionError as exc:
                raise ManifestError(f"Invalid package_resolution: {exc}") from exc

        frappe_app = available_apps.get("frappe")
        framework = lock.get("framework")
        if not isinstance(framework, dict) or frappe_app is None:
            raise ManifestError("Lock file has no valid locked Frappe framework entry.")
        if (
            framework.get("target_ref") != frappe_app.get("target_ref")
            or framework.get("ref") != frappe_app.get("ref")
            or framework.get("reference_kind") != frappe_app.get("reference_kind")
            or framework.get("resolved_ref") != frappe_app.get("resolved_ref")
        ):
            raise ManifestError(
                "Framework source identity does not match the locked "
                "Frappe application."
            )

        return True

    def compare_lock_files(
        self,
        previous_lock_path: Path,
        new_lock_data: dict,
        manifest: dict,
    ) -> list:
        """Compare an existing lock file with newly resolved lock data."""

        if not previous_lock_path.exists():
            return ["No previous lock file found. A new lock will be created."]

        try:
            previous_lock = json.loads(previous_lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(
                f"Unable to read previous lock file " f"{previous_lock_path}: {exc}"
            ) from exc

        # Lock v2 is the only supported format. Legacy v1 locks must be
        # removed and regenerated from the current source manifests; they are
        # not migration inputs.
        previous_version = previous_lock.get("lock_version")
        if previous_version != 2:
            raise ManifestError(f"Unsupported lock version: {previous_version}")

        # Validate structure, but allow source checksum changes.
        self.validate_lock_file(
            previous_lock_path,
            manifest,
            verify_manifest_checksums=False,
            allow_package_resolution_migration=True,
        )

        changes = []

        # A pre-extension v2 lock is a migration input, not equivalent to
        # a newly generated package-resolution-complete lock.
        previous_package_resolution = previous_lock.get("package_resolution")
        new_package_resolution = new_lock_data.get("package_resolution")
        if previous_package_resolution is None and new_package_resolution is not None:
            changes = ["Package-resolution migration required: pre-extension lock v2"]
        elif previous_package_resolution != new_package_resolution:
            changes = ["Changed package_resolution"]

        # Compare top-level metadata.
        for section in (
            "product",
            "framework",
            "target_runtime",
            "lock_version",
            "resolver",
        ):
            old_value = previous_lock.get(section)
            new_value = new_lock_data.get(section)

            if old_value != new_value:
                changes.append(f"Changed {section}: {old_value} -> {new_value}")

        # Compare manifests by manifest ID.
        old_manifests = {
            item["id"]: item for item in previous_lock.get("manifests", [])
        }

        new_manifests = {
            item["id"]: item for item in new_lock_data.get("manifests", [])
        }

        for manifest_id in sorted(new_manifests.keys() - old_manifests.keys()):
            changes.append(f"Added manifest: {manifest_id}")

        for manifest_id in sorted(old_manifests.keys() - new_manifests.keys()):
            changes.append(f"Removed manifest: {manifest_id}")

        for manifest_id in sorted(old_manifests.keys() & new_manifests.keys()):
            old_item = old_manifests[manifest_id]
            new_item = new_manifests[manifest_id]

            if old_item.get("path") != new_item.get("path"):
                changes.append(f"Changed manifest path: {manifest_id}")

            if old_item.get("sha256") != new_item.get("sha256"):
                changes.append(f"Changed manifest content: {manifest_id}")

        # Compare independently resolved service inventories.
        for section in ("services", "external_requirements", "capabilities"):
            old_items = previous_lock.get(section, [])
            new_items = new_lock_data.get(section, [])
            if old_items != new_items:
                changes.append(f"Changed {section} composition")

        # Compare applications by application name.
        old_apps = {
            item["name"]: item for item in previous_lock.get("applications", [])
        }

        new_apps = {
            item["name"]: item for item in new_lock_data.get("applications", [])
        }

        for app_name in sorted(new_apps.keys() - old_apps.keys()):
            changes.append(f"Added application: {app_name}")

        for app_name in sorted(old_apps.keys() - new_apps.keys()):
            changes.append(f"Removed application: {app_name}")

        compared_fields = (
            "repository",
            "target_ref",
            "ref",
            "dependencies",
            "installation_order",
            "reference_kind",
            "resolved_ref",
            "compatibility_status",
            "app_id",
            "release_version",
            "descriptor",
            "descriptor_sha256",
            "package_dependencies",
        )

        for app_name in sorted(old_apps.keys() & new_apps.keys()):
            old_app = old_apps[app_name]
            new_app = new_apps[app_name]

            for field in compared_fields:
                if old_app.get(field) != new_app.get(field):
                    changes.append(
                        f"Changed {app_name}.{field}: "
                        f"{old_app.get(field)} -> {new_app.get(field)}"
                    )

        return changes


def print_manifest_tree(manifest: dict, level: int = 0):
    """Display the loaded manifest hierarchy."""

    indent = "  " * level

    print(f"{indent}- {manifest['id']} " f"({Path(manifest['_source_path']).name})")

    for child in manifest.get("_loaded_includes", []):
        print_manifest_tree(child, level + 1)
    for child in manifest.get("_loaded_capabilities", []):
        print_manifest_tree(child, level + 1)


def main():
    parser = argparse.ArgumentParser(description="NDF Frappe Manifest Resolver")

    parser.add_argument(
        "manifest",
        help="Product manifest path relative to images/ndf/manifests",
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Check whether the existing lock file is up to date without modifying it.",
    )

    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    ndf_dir = script_dir.parent
    manifests_dir = ndf_dir / "manifests"

    loader = ManifestLoader(manifests_dir)

    # 1. Load manifest tree
    try:
        manifest = loader.load(args.manifest)

    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\nManifest loading successful.\n")
    print_manifest_tree(manifest)

    print(f"\nTotal unique manifests loaded: {len(loader.loaded)}")

    # 2. Compute effective policy and compose applications
    try:
        effective_policy = loader.resolve_policy(manifest)
        print(
            "\nEffective resolution policy: "
            f"{json.dumps(effective_policy, sort_keys=True)}"
        )
        applications = loader.compose_applications(manifest)

        loader.validate_dependencies(applications)

    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\nTotal unique applications composed: {len(applications)}")
    print("\nApplication dependency validation successful.")

    # 3. Resolve installation order
    try:
        ordered_applications = loader.resolve_install_order(applications)

    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\nApplication installation order:")

    for index, app in enumerate(ordered_applications, start=1):
        print(f"  {index:02d}. {app['name']}")

    # 4. Resolve immutable Git references
    try:
        ordered_applications = loader.resolve_application_refs(
            ordered_applications,
            effective_policy,
        )

    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\nApplication Git references resolved.")

    # 4a. Native package resolution/installation is owned by upstream Bench.
    # NDF writes the accepted empty graph here and verifies installed state downstream.
    package_resolution = None

    # 5. Determine lock file location
    lock_filename = f"{Path(args.manifest).stem}.lock.json"

    lock_path = ndf_dir / "locks" / lock_filename

    # 6. Build new lock data in memory
    try:
        lock_data = loader.build_lock_data(
            manifest,
            ordered_applications,
            package_resolution=package_resolution,
        )

        # 7. Check whether a previous lock exists
        if args.check and not lock_path.exists():
            print(
                f"\nERROR: Lock file does not exist: {lock_path}",
                file=sys.stderr,
            )
            sys.exit(1)

        # 8. Compare against the previous lock
        changes = loader.compare_lock_files(
            lock_path,
            lock_data,
            manifest,
        )

        print("\nLock file comparison:")

        if changes:
            for change in changes:
                print(f"  - {change}")
        else:
            print("  No changes detected.")

        # 9. Handle check-only mode
        if args.check:
            if changes:
                print("\nERROR: Lock file is outdated.")
                sys.exit(1)

            print("\nLock file is up to date.")
            return

        # 10. Write the new lock file
        loader.write_lock_file(
            lock_data,
            lock_path,
        )

        # 11. Validate the newly written lock
        loader.validate_lock_file(
            lock_path,
            manifest,
        )

    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"\nLock file generated and validated: {lock_path}")


if __name__ == "__main__":
    main()
