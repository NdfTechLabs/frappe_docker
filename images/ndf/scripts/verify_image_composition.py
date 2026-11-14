"""Independent verification of lock-v2 application and service composition.

This module deliberately does not import the manifest resolver. It verifies the
source bytes named by lock-v2 and compares that independent inventory with the
build metadata and final runtime Bench application set.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, ValidationError


class CompositionVerificationError(Exception):
    """Raised when source or runtime composition is incomplete or inconsistent."""


REPORT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "image-composition-verification-v1.schema.json"
)
SERVICE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "service-descriptor-v1.schema.json"
)
SHA256 = re.compile(r"^[a-f0-9]{64}$")
OCI_DIGEST = re.compile(r"^[^@\\s]+@sha256:[a-fA-F0-9]{64}$")


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompositionVerificationError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CompositionVerificationError(f"{label} must be a JSON object.")
    return value, raw


def _safe_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or "\\" in value:
        raise CompositionVerificationError(f"{label} is not a canonical relative path.")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise CompositionVerificationError(f"{label} is not a canonical relative path.")
    return value


def _unique_records(items: Any, key: str, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        raise CompositionVerificationError(f"{label} must be an array.")
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise CompositionVerificationError(f"{label} contains a non-object record.")
        identity = item.get(key)
        if not isinstance(identity, str) or not identity:
            raise CompositionVerificationError(f"{label} contains an invalid {key}.")
        if identity in result:
            raise CompositionVerificationError(f"{label} contains duplicate {key}: {identity}.")
        result[identity] = item
    return result


def _load_manifest_inventory(
    repository_root: Path, manifest_path: str, lock: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    entries = lock.get("manifests")
    if not isinstance(entries, list) or not entries:
        raise CompositionVerificationError("Lock-v2 must contain a non-empty manifest inventory.")
    manifest_root = (repository_root / "images" / "ndf" / "manifests").resolve()
    by_path: dict[str, dict[str, Any]] = {}
    by_id: dict[str, str] = {}
    evidence = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise CompositionVerificationError("Lock manifest inventory contains an invalid record.")
        relative = _safe_relative_path(entry.get("path"), "Lock manifest path")
        manifest_id = entry.get("id")
        expected = entry.get("sha256")
        if not isinstance(manifest_id, str) or not manifest_id or not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise CompositionVerificationError(f"Invalid lock manifest identity/checksum: {relative}.")
        if relative in by_path or manifest_id in by_id:
            raise CompositionVerificationError("Lock manifest inventory contains duplicate paths or IDs.")
        source = (manifest_root / relative).resolve()
        if not source.is_relative_to(manifest_root) or not source.is_file():
            raise CompositionVerificationError(f"Locked source manifest is missing or unsafe: {relative}.")
        manifest, raw = _read_json(source, f"source manifest {relative}")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise CompositionVerificationError(f"Source manifest checksum mismatch: {relative}.")
        if manifest.get("id") != manifest_id:
            raise CompositionVerificationError(f"Source manifest ID mismatch: {relative}.")
        by_path[relative] = manifest
        by_id[manifest_id] = relative
        evidence.append({"path": relative, "sha256": actual})
    if manifest_path not in by_path:
        raise CompositionVerificationError("Product manifest is absent from the lock manifest inventory.")
    return by_path, sorted(evidence, key=lambda item: item["path"])


def _verify_capabilities(manifests: dict[str, dict[str, Any]], lock: dict[str, Any]) -> list[dict[str, Any]]:
    version_two = any(item.get("manifest_version") == "2.0.0" for item in manifests.values())
    locked = lock.get("capabilities", [])
    if not isinstance(locked, list):
        raise CompositionVerificationError("Lock-v2 capabilities must be an array.")
    if not version_two:
        # Legacy v1 capabilities are not selections. A non-empty lock inventory
        # would therefore claim semantics the source format never defined.
        if locked:
            raise CompositionVerificationError(
                "Legacy v1 manifests cannot authoritatively define capability selections."
            )
        return []
    expected: dict[str, dict[str, Any]] = {}
    for source_path, manifest in manifests.items():
        if manifest.get("manifest_version") != "2.0.0":
            continue
        declarations = manifest.get("capabilities", [])
        if not isinstance(declarations, list):
            raise CompositionVerificationError(f"Capabilities must be an array in {source_path}.")
        for item in declarations:
            if not isinstance(item, dict):
                raise CompositionVerificationError(f"Invalid capability declaration in {source_path}.")
            path = _safe_relative_path(item.get("manifest"), "Capability manifest path")
            required, selected = item.get("required"), item.get("selected")
            if not isinstance(required, bool) or not isinstance(selected, bool):
                raise CompositionVerificationError(f"Capability selection must use boolean required/selected values: {path}.")
            if required and not selected:
                raise CompositionVerificationError(f"Required capability is unselected: {path}.")
            if path in expected:
                raise CompositionVerificationError(f"Duplicate capability selection: {path}.")
            expected[path] = {"manifest": path, "required": required, "selected": selected}
            if selected and path not in manifests:
                raise CompositionVerificationError(f"Selected capability is absent from locked manifests: {path}.")
            if not selected and path in manifests:
                raise CompositionVerificationError(f"Unselected capability appears in locked manifests: {path}.")
    actual = {}
    for item in locked:
        if not isinstance(item, dict):
            raise CompositionVerificationError("Lock capability inventory contains an invalid record.")
        path = _safe_relative_path(item.get("manifest"), "Lock capability path")
        if path in actual:
            raise CompositionVerificationError(f"Duplicate lock capability selection: {path}.")
        if not isinstance(item.get("required"), bool) or not isinstance(item.get("selected"), bool):
            raise CompositionVerificationError(f"Invalid lock capability booleans: {path}.")
        actual[path] = {key: item.get(key) for key in ("manifest", "required", "selected")}
    if actual != expected:
        raise CompositionVerificationError("Lock capability selections do not match source manifest declarations.")
    return [expected[path] for path in sorted(expected)]




def _verify_manifest_graph(
    root_path: str, manifests: dict[str, dict[str, Any]]
) -> None:
    """Require the lock manifest inventory to be the complete reachable source graph."""
    reachable: set[str] = set()
    pending = [root_path]
    while pending:
        current_path = pending.pop()
        if current_path in reachable:
            continue
        manifest = manifests.get(current_path)
        if manifest is None:
            raise CompositionVerificationError(f"Manifest graph references an unlocked source manifest: {current_path}.")
        reachable.add(current_path)
        includes = manifest.get("includes", [])
        if not isinstance(includes, list):
            raise CompositionVerificationError(f"Manifest includes must be an array: {current_path}.")
        for include in includes:
            if not isinstance(include, dict):
                raise CompositionVerificationError(f"Invalid include declaration: {current_path}.")
            child = _safe_relative_path(include.get("manifest"), "Included manifest path")
            pending.append(child)
        if manifest.get("manifest_version") == "2.0.0":
            capabilities = manifest.get("capabilities", [])
            if not isinstance(capabilities, list):
                raise CompositionVerificationError(f"Manifest capabilities must be an array: {current_path}.")
            for capability in capabilities:
                if not isinstance(capability, dict):
                    raise CompositionVerificationError(f"Invalid capability declaration: {current_path}.")
                if capability.get("required") is True or capability.get("selected") is True:
                    pending.append(_safe_relative_path(capability.get("manifest"), "Selected capability path"))
    if reachable != set(manifests):
        extra = sorted(set(manifests) - reachable)
        missing = sorted(reachable - set(manifests))
        raise CompositionVerificationError(f"Lock manifest inventory is not the exact source graph: extra={extra}, missing={missing}.")


def _verify_service_source_declarations(
    manifests: dict[str, dict[str, Any]],
    containers: list[dict[str, Any]],
    external: list[dict[str, Any]],
) -> None:
    expected = {"container": set(), "external": set()}
    for source_path, manifest in manifests.items():
        if manifest.get("manifest_version") != "2.0.0":
            continue
        for field, kind in (("services", "container"), ("external_requirements", "external")):
            declarations = manifest.get(field, [])
            if not isinstance(declarations, list):
                raise CompositionVerificationError(f"{field} must be an array in {source_path}.")
            for declaration in declarations:
                if not isinstance(declaration, dict):
                    raise CompositionVerificationError(f"Invalid {field} declaration in {source_path}.")
                required = declaration.get("required", False)
                selected = declaration.get("selected", False)
                if not isinstance(required, bool) or not isinstance(selected, bool):
                    raise CompositionVerificationError(f"Invalid {field} selection flags in {source_path}.")
                if required or selected:
                    expected[kind].add(_safe_relative_path(declaration.get("descriptor"), f"{field} descriptor path"))
    actual = {
        "container": {item["descriptor"] for item in containers},
        "external": {item["descriptor"] for item in external},
    }
    if actual != expected:
        raise CompositionVerificationError("Lock service inventories do not match selected service descriptor declarations.")


def _verify_application_declarations(
    repository_root: Path,
    manifests: dict[str, dict[str, Any]],
    lock_apps: dict[str, dict[str, Any]],
) -> None:
    """Check manifest declarations and any locked Marketplace App Descriptors."""
    declared: set[str] = set()
    for source_path, manifest in manifests.items():
        entries = manifest.get("applications", [])
        if not isinstance(entries, list):
            raise CompositionVerificationError(f"Applications must be an array in {source_path}.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise CompositionVerificationError(f"Invalid application declaration in {source_path}.")
            required = entry.get("required", False)
            selected = entry.get("selected", False)
            if not isinstance(required, bool) or not isinstance(selected, bool):
                raise CompositionVerificationError(f"Invalid application selection flags in {source_path}.")
            if not (required or selected):
                continue
            descriptor_path = entry.get("descriptor")
            if descriptor_path:
                relative = _safe_relative_path(descriptor_path, "Application descriptor path")
                prefix = "images/ndf/descriptors/apps/"
                if not relative.startswith(prefix) or len(PurePosixPath(relative).parts) != 5 or not relative.endswith(".json"):
                    raise CompositionVerificationError(f"Non-canonical application descriptor path: {relative}.")
                source = (repository_root / relative).resolve()
                descriptor_root = (repository_root / prefix).resolve()
                if not source.is_relative_to(descriptor_root) or not source.is_file():
                    raise CompositionVerificationError(f"Application descriptor is missing or unsafe: {relative}.")
                descriptor, _ = _read_json(source, f"application descriptor {relative}")
                bench_name = descriptor.get("app_module", {}).get("bench_app_name")
                if not isinstance(bench_name, str) or not bench_name:
                    raise CompositionVerificationError(f"Application descriptor lacks Bench app identity: {relative}.")
                declared.add(bench_name)
            else:
                name = entry.get("name")
                if not isinstance(name, str) or not name:
                    raise CompositionVerificationError(f"Invalid legacy application name in {source_path}.")
                declared.add(name)

    # Every legacy lock application must have a source-manifest declaration.
    # Descriptor-backed transitive dependencies may be introduced by another
    # selected descriptor, so validate their canonical descriptor identity too.
    for name, locked in lock_apps.items():
        descriptor_path = locked.get("descriptor")
        if not descriptor_path:
            if name not in declared:
                raise CompositionVerificationError(f"Locked Bench application has no source-manifest declaration: {name}.")
            continue
        relative = _safe_relative_path(descriptor_path, "Locked application descriptor path")
        prefix = "images/ndf/descriptors/apps/"
        if not relative.startswith(prefix) or len(PurePosixPath(relative).parts) != 5 or not relative.endswith(".json"):
            raise CompositionVerificationError(f"Non-canonical locked application descriptor path: {relative}.")
        source = (repository_root / relative).resolve()
        descriptor_root = (repository_root / prefix).resolve()
        if not source.is_relative_to(descriptor_root) or not source.is_file():
            raise CompositionVerificationError(f"Locked application descriptor is missing or unsafe: {relative}.")
        descriptor, raw = _read_json(source, f"locked application descriptor {relative}")
        if hashlib.sha256(raw).hexdigest() != locked.get("descriptor_sha256"):
            raise CompositionVerificationError(f"Locked application descriptor checksum mismatch: {relative}.")
        if descriptor.get("app_module", {}).get("bench_app_name") != name:
            raise CompositionVerificationError(f"Locked application descriptor Bench identity mismatch: {name}.")
    unexpected = declared - set(lock_apps)
    if unexpected:
        raise CompositionVerificationError("Source manifests declare applications absent from lock-v2: " + ", ".join(sorted(unexpected)))


def _verify_services(repository_root: Path, lock: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    try:
        schema = json.loads(SERVICE_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CompositionVerificationError(f"Unable to load service descriptor schema: {exc}") from exc
    inventories: dict[str, dict[str, dict[str, Any]]] = {"container": {}, "external": {}}
    descriptor_evidence = []
    combined: dict[str, dict[str, Any]] = {}
    for section, expected_kind in (("services", "container"), ("external_requirements", "external")):
        items = lock.get(section, [])
        if not isinstance(items, list):
            raise CompositionVerificationError(f"Lock {section} must be an array.")
        for item in items:
            if not isinstance(item, dict):
                raise CompositionVerificationError(f"Lock {section} contains an invalid record.")
            service_id = item.get("service_id")
            if not isinstance(service_id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]*", service_id):
                raise CompositionVerificationError(f"Invalid independent artifact identity in {section}.")
            if service_id in combined:
                raise CompositionVerificationError(f"Duplicate/cross-category independent artifact identity: {service_id}.")
            relative = _safe_relative_path(item.get("descriptor"), "Service descriptor path")
            prefix = "images/ndf/descriptors/services/"
            if not relative.startswith(prefix) or len(PurePosixPath(relative).parts) != 5 or not relative.endswith(".json"):
                raise CompositionVerificationError(f"Non-canonical service descriptor path: {relative}.")
            if PurePosixPath(relative).stem != service_id:
                raise CompositionVerificationError(f"Service descriptor filename does not match identity: {service_id}.")
            source = (repository_root / relative).resolve()
            descriptor_root = (repository_root / prefix).resolve()
            if not source.is_relative_to(descriptor_root) or not source.is_file():
                raise CompositionVerificationError(f"Service descriptor is missing or unsafe: {relative}.")
            descriptor, raw = _read_json(source, f"service descriptor {relative}")
            try:
                Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(descriptor)
            except ValidationError as exc:
                raise CompositionVerificationError(f"Service descriptor schema failure at {relative}: {exc.message}") from exc
            checksum = hashlib.sha256(raw).hexdigest()
            if item.get("descriptor_sha256") != checksum:
                raise CompositionVerificationError(f"Service descriptor checksum mismatch: {relative}.")
            if descriptor.get("service_id") != service_id or descriptor.get("service_kind") != expected_kind:
                raise CompositionVerificationError(f"Service descriptor identity/category mismatch: {service_id}.")
            for field in ("name", "service_kind", "artifact", "provider", "depends_on"):
                expected_value = descriptor.get(field, [] if field == "depends_on" else None)
                if item.get(field) != expected_value:
                    raise CompositionVerificationError(f"Lock {section} descriptor field mismatch for {service_id}: {field}.")
            if expected_kind == "container":
                image = descriptor.get("artifact", {}).get("image", "")
                if not isinstance(image, str) or not OCI_DIGEST.fullmatch(image):
                    raise CompositionVerificationError(f"Container service {service_id} must use an immutable digest-pinned image.")
            else:
                provider = descriptor.get("provider")
                if not isinstance(provider, dict) or not provider.get("name") or not provider.get("requirement"):
                    raise CompositionVerificationError(f"External requirement {service_id} lacks provider/requirement.")
            combined[service_id] = item
            inventories[expected_kind][service_id] = item
            descriptor_evidence.append({"service_id": service_id, "path": relative, "sha256": checksum, "service_kind": expected_kind})

    # Independently validate dependency closure, acyclicity, and the resolver's
    # declared topological order without importing its graph implementation.
    state: dict[str, int] = {}
    order: list[str] = []
    def visit(identity: str, chain: list[str]) -> None:
        mark = state.get(identity, 0)
        if mark == 1:
            raise CompositionVerificationError("Circular independent-service dependency: " + " -> ".join(chain + [identity]))
        if mark == 2:
            return
        state[identity] = 1
        item = combined[identity]
        dependencies = item.get("depends_on", [])
        if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
            raise CompositionVerificationError(f"Invalid/duplicate dependencies for {identity}.")
        for dependency in sorted(dependencies):
            if dependency not in combined:
                raise CompositionVerificationError(f"Independent artifact {identity} has missing dependency {dependency}.")
            visit(dependency, chain + [identity])
        state[identity] = 2
        order.append(identity)
    for identity in sorted(combined):
        visit(identity, [])
    declared = sorted(combined.values(), key=lambda item: item.get("resolution_order", 0))
    if [item.get("service_id") for item in declared] != order:
        raise CompositionVerificationError("Independent artifact resolution order is not the verified topological order.")
    if [item.get("resolution_order") for item in declared] != list(range(1, len(declared) + 1)):
        raise CompositionVerificationError("Independent artifact resolution order must be contiguous and start at one.")
    return (
        sorted(inventories["container"].values(), key=lambda item: item["resolution_order"]),
        sorted(inventories["external"].values(), key=lambda item: item["resolution_order"]),
        {"descriptor_count": len(descriptor_evidence), "descriptors": sorted(descriptor_evidence, key=lambda item: item["service_id"]), "dependency_order": order, "dependency_closure_verified": True},
    )


def verify_composition(
    *,
    repository_root: Path,
    manifest_path: str,
    lock_data: dict[str, Any],
    lock_bytes: bytes,
    metadata_applications: list[dict[str, Any]],
    inventory_applications: list[dict[str, Any]],
    runtime_directories: list[str],
    runtime_apps_txt: list[str],
) -> dict[str, Any]:
    """Verify source composition and actual runtime Bench application membership."""
    if lock_data.get("lock_version") != 2:
        raise CompositionVerificationError("Independent composition verification requires lock-v2.")
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    manifests, manifest_evidence = _load_manifest_inventory(repository_root, manifest_path, lock_data)
    _verify_manifest_graph(manifest_path, manifests)
    capabilities = _verify_capabilities(manifests, lock_data)
    containers, external, service_evidence = _verify_services(repository_root, lock_data)
    _verify_service_source_declarations(manifests, containers, external)
    apps = _unique_records(lock_data.get("applications"), "name", "Lock applications")
    _verify_application_declarations(repository_root, manifests, apps)
    metadata = _unique_records(metadata_applications, "name", "Build metadata applications")
    inventory = _unique_records(inventory_applications, "name", "Build inventory applications")
    if set(apps) != set(metadata) or set(apps) != set(inventory):
        raise CompositionVerificationError("Bench application composition differs across lock, build metadata and inventory.")
    expected_names = set(apps)
    for label, observed in (("runtime app directories", runtime_directories), ("runtime sites/apps.txt", runtime_apps_txt)):
        if not isinstance(observed, list) or any(not isinstance(name, str) or not name for name in observed):
            raise CompositionVerificationError(f"{label} is not a valid application-name list.")
        if len(observed) != len(set(observed)):
            raise CompositionVerificationError(f"{label} contains duplicate application names.")
        if set(observed) != expected_names:
            raise CompositionVerificationError(f"{label} differs from lock-v2 Bench applications.")
    independent_ids = {item["service_id"] for item in containers + external}
    collision = expected_names & independent_ids
    if collision:
        raise CompositionVerificationError("Bench application identity collides with independent artifact: " + ", ".join(sorted(collision)))
    report = {
        "schema_version": "1.0",
        "algorithm": "ndf-image-composition-verification-v1",
        "verifier": {"name": "verify_image_composition.py", "version": "1.0.0"},
        "lock": {"version": 2, "sha256": lock_sha},
        "manifests": manifest_evidence,
        "applications": {"expected": sorted(expected_names), "metadata": sorted(metadata), "inventory": sorted(inventory), "runtime_directories": sorted(runtime_directories), "runtime_apps_txt": sorted(runtime_apps_txt), "count": len(expected_names)},
        "capabilities": capabilities,
        "services": containers,
        "external_requirements": external,
        "service_verification": service_evidence,
        "category_separation": {"bench_service_identity_disjoint": True, "runtime_contains_only_bench_apps": True},
        "status": "passed",
    }
    try:
        schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(report)
    except (OSError, json.JSONDecodeError) as exc:
        raise CompositionVerificationError(f"Unable to load composition report schema: {exc}") from exc
    except ValidationError as exc:
        raise CompositionVerificationError(f"Composition report schema validation failed: {exc.message}") from exc
    return report
