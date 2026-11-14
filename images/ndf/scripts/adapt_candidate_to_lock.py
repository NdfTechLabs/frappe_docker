#!/usr/bin/env python3
"""Translate an intake-validated DT Master candidate into NDF lock-v2 inputs.

The product manifest remains authoritative for application membership,
repository identity, dependency topology and compatibility policy. Candidate
records supply immutable source commits and the requested ref assertions.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

try:
    from .validate_image_definitions import (
        ImageDefinitionError,
        load_json,
        validate_definitions,
        validate_schema,
    )
    from .prepare_build import (
        BuildPreparationError,
        build_apps_json,
        build_metadata,
        load_image_definition,
        write_json,
    )
    from .resolve_manifest import ManifestError, ManifestLoader
except ImportError:
    from validate_image_definitions import (
        ImageDefinitionError,
        load_json,
        validate_definitions,
        validate_schema,
    )
    from prepare_build import (
        BuildPreparationError,
        build_apps_json,
        build_metadata,
        load_image_definition,
        write_json,
    )
    from resolve_manifest import ManifestError, ManifestLoader


class CandidateCompositionError(Exception):
    """Raised when a candidate cannot be mapped to an NDF composition."""


class CandidateManifestLoader(ManifestLoader):
    """Load the normal manifest graph with candidate-selected capabilities."""

    def __init__(self, manifests_dir: Path, selected_capabilities: set[str]):
        super().__init__(manifests_dir)
        self.selected_capabilities = selected_capabilities
        self.seen_optional_capabilities: set[str] = set()

    def load_json(self, path: Path) -> dict:
        manifest = super().load_json(path)
        relative_path = path.resolve().relative_to(self.manifests_dir).as_posix()

        for capability in manifest.get("capabilities", []):
            if not isinstance(capability, dict):
                continue
            capability_path = capability.get("manifest")
            if not isinstance(capability_path, str):
                continue
            if capability.get("required", False):
                continue

            normalized = PurePosixPath(capability_path)
            if (
                normalized.is_absolute()
                or ".." in normalized.parts
                or normalized.as_posix() != capability_path
            ):
                raise CandidateCompositionError(
                    f"Unsafe optional capability path in {relative_path}: "
                    f"{capability_path}"
                )

            self.seen_optional_capabilities.add(capability_path)
            capability["selected"] = capability_path in self.selected_capabilities

        return manifest


def _strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CandidateCompositionError(
                    f"Candidate JSON contains duplicate key: {key}"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda item: (_ for _ in ()).throw(
                CandidateCompositionError(
                    f"Candidate JSON contains invalid numeric constant: {item}"
                )
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateCompositionError(f"Unable to read candidate JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise CandidateCompositionError("Candidate payload must be a JSON object.")
    return value


def _validate_candidate(candidate: dict, ndf_dir: Path) -> None:
    schema_path = ndf_dir / "schemas" / "deployment-candidate-v1.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateCompositionError(
            f"Unable to load candidate schema: {exc}"
        ) from exc

    errors = sorted(
        Draft202012Validator(schema).iter_errors(candidate),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        details = "; ".join(
            f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: "
            f"{error.message}"
            for error in errors
        )
        raise CandidateCompositionError(f"Candidate schema validation failed: {details}")


def _validate_optional_capabilities(candidate: dict) -> set[str]:
    selected = candidate.get("optional_capabilities", [])
    if not isinstance(selected, list) or any(
        not isinstance(item, str) or not item for item in selected
    ):
        raise CandidateCompositionError(
            "optional_capabilities must be an array of manifest-relative paths."
        )
    if len(selected) != len(set(selected)):
        raise CandidateCompositionError("Duplicate optional capability selection.")

    for item in selected:
        path = PurePosixPath(item)
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != item
            or not item.endswith(".json")
        ):
            raise CandidateCompositionError(
                f"Invalid optional capability path: {item}"
            )
    return set(selected)


def _select_image(
    ndf_dir: Path, definitions_relative_path: str, candidate: dict
) -> tuple[dict, dict]:
    product_id = candidate["product"]["id"]
    definitions_path = (ndf_dir / definitions_relative_path).resolve()
    if not definitions_path.is_relative_to(ndf_dir.resolve()) or not definitions_path.is_file():
        raise CandidateCompositionError("Image definitions path is invalid.")

    try:
        definitions = load_json(definitions_path)
        schema_path = ndf_dir / "schemas" / "image-definitions-v1.schema.json"
        validate_schema(definitions, schema_path)
        validate_definitions(definitions, ndf_dir / "manifests")
    except (OSError, json.JSONDecodeError, ImageDefinitionError) as exc:
        raise CandidateCompositionError(f"Invalid NDF image definitions: {exc}") from exc

    matches = [item for item in definitions["images"] if item["product"] == product_id]
    if len(matches) != 1:
        raise CandidateCompositionError(
            f"Candidate product '{product_id}' must map to exactly one NDF image; "
            f"found {len(matches)}."
        )
    image = matches[0]
    manifest_path = (ndf_dir / "manifests" / image["manifest"]).resolve()
    if not manifest_path.is_relative_to((ndf_dir / "manifests").resolve()):
        raise CandidateCompositionError("Product manifest path escapes manifests directory.")
    try:
        product_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateCompositionError(f"Unable to read product manifest: {exc}") from exc

    if candidate["framework_version"] != product_manifest["framework"]["version"]:
        raise CandidateCompositionError(
            "Candidate framework_version does not match the selected product manifest."
        )
    return image, product_manifest


def _map_candidate_applications(
    candidate: dict, applications: list[dict], loader: ManifestLoader
) -> list[dict]:
    expected_by_id = {}
    for app in applications:
        app_id = app.get("_app_id") or app.get("name")
        if not isinstance(app_id, str) or not app_id:
            raise CandidateCompositionError(
                "NDF composition contains an application without a stable identity."
            )
        if app_id in expected_by_id:
            raise CandidateCompositionError(
                f"NDF composition contains duplicate application identity: {app_id}"
            )
        expected_by_id[app_id] = app

    supplied = {}
    for app in candidate["applications"]:
        app_id = app["app_id"]
        if app_id in supplied:
            raise CandidateCompositionError(
                f"Candidate contains duplicate application identity: {app_id}"
            )
        supplied[app_id] = app

    missing = sorted(set(expected_by_id) - set(supplied))
    unexpected = sorted(set(supplied) - set(expected_by_id))
    if missing or unexpected:
        raise CandidateCompositionError(
            "Candidate application set does not equal the authoritative NDF "
            f"composition (missing={missing}, unexpected={unexpected})."
        )

    mapped = []
    for expected in applications:
        app_id = expected.get("_app_id") or expected["name"]
        requested = supplied[app_id]

        if requested["app_source"] != expected.get("repository"):
            raise CandidateCompositionError(
                f"{app_id}: candidate source repository differs from the NDF manifest."
            )
        commit = requested["immutable_commit"]
        if not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise CandidateCompositionError(
                f"{app_id}: lock-v2 requires a full 40-character Git commit SHA."
            )

        descriptor = expected.get("_descriptor") or {}
        expected_app_name = descriptor.get("name", expected["name"])
        if requested["app_name"] != expected_app_name:
            raise CandidateCompositionError(
                f"{app_id}: candidate app_name differs from the registered NDF application identity."
            )

        descriptor_release = expected.get("_release_version")
        if descriptor_release and requested["release_version"] != descriptor_release:
            raise CandidateCompositionError(
                f"{app_id}: candidate release_version differs from the registered "
                "NDF Marketplace App Descriptor."
            )

        try:
            resolved_commit = loader.resolve_git_ref(expected["repository"], commit)
        except ManifestError as exc:
            raise CandidateCompositionError(
                f"{app_id}: immutable commit cannot be verified in its declared repository: {exc}"
            ) from exc
        if (
            resolved_commit.get("kind") != "commit"
            or resolved_commit.get("sha", "").lower() != commit
            or resolved_commit.get("name", "").lower() != commit
        ):
            raise CandidateCompositionError(
                f"{app_id}: repository did not confirm the exact candidate commit."
            )

        expected = dict(expected)
        expected["target_ref"] = commit
        expected["ref"] = commit
        expected["_reference_kind"] = "commit"
        expected["_resolved_ref"] = commit
        expected["_candidate_app_id"] = app_id
        expected["_candidate_requested_version"] = requested["requested_version"]
        expected["_candidate_release_version"] = requested["release_version"]
        expected["_candidate_descriptor_ref"] = requested["descriptor_ref"]
        expected["_candidate_descriptor_digest"] = requested["descriptor_digest"]
        mapped.append(expected)

    # Preserve the existing resolver's deterministic dependency order.
    return mapped


def adapt_candidate_to_lock(
    ndf_dir: Path,
    candidate_path: Path,
    output_dir: Path,
    candidate_artifact_ref: str,
    payload_sha256: str,
    definitions_relative_path: str = "image-definitions/images-v1.json",
) -> dict[str, Any]:
    ndf_dir = ndf_dir.resolve()
    candidate_path = candidate_path.resolve()
    candidate = _strict_json(candidate_path)
    _validate_candidate(candidate, ndf_dir)

    if not re.fullmatch(r"ghcr\.io/ndftechlabs/dt-master-deployment-candidates@sha256:[a-f0-9]{64}", candidate_artifact_ref):
        raise CandidateCompositionError("Candidate artifact reference is not allowlisted and digest-pinned.")
    artifact_digest = candidate_artifact_ref.rsplit("@", 1)[1]
    if not re.fullmatch(r"[a-f0-9]{64}", payload_sha256):
        raise CandidateCompositionError("Candidate payload SHA-256 is invalid.")

    actual_payload_sha256 = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    if actual_payload_sha256 != payload_sha256:
        raise CandidateCompositionError(
            "Candidate file bytes do not match the dispatch payload SHA-256."
        )

    image, product_manifest = _select_image(
        ndf_dir, definitions_relative_path, candidate
    )
    selected_capabilities = _validate_optional_capabilities(candidate)

    manifests_dir = ndf_dir / "manifests"
    manifest_relative_path = image["manifest"]
    loader = CandidateManifestLoader(manifests_dir, selected_capabilities)
    manifest = loader.load(manifest_relative_path)

    unknown_capabilities = selected_capabilities - loader.seen_optional_capabilities
    if unknown_capabilities:
        raise CandidateCompositionError(
            "Candidate selects unknown optional capabilities: "
            + ", ".join(sorted(unknown_capabilities))
        )

    if manifest["framework"]["version"] != candidate["framework_version"]:
        raise CandidateCompositionError(
            "Loaded product manifest framework version changed during resolution."
        )

    if candidate.get("target_platforms") != ["linux/amd64"]:
        raise CandidateCompositionError(
            "Candidate target platform is not in the currently verified NDF runtime matrix."
        )

    runtime = candidate.get("runtime_profile", {})
    if not isinstance(runtime.get("python"), str) or not re.fullmatch(
        r"3\.14(?:\.\d+)?", runtime["python"]
    ) or not isinstance(runtime.get("node"), str) or not re.fullmatch(
        r"24(?:\.\d+){0,2}", runtime["node"]
    ):
        raise CandidateCompositionError(
            "Candidate runtime_profile must select the verified Python 3.14 and Node 24 families."
        )

    build_parameters = candidate.get("approved_build_parameters", {})
    if build_parameters.get("build_profile", "production") != "production":
        raise CandidateCompositionError("Only the production build profile is supported.")
    build_options = build_parameters.get("build_options", {})
    if any(key != "assets" or value is not True for key, value in build_options.items()):
        raise CandidateCompositionError(
            "Candidate contains build options not implemented by the NDF build pipeline."
        )

    policy = loader.resolve_policy(manifest)
    applications = loader.compose_applications(manifest)
    loader.validate_dependencies(applications)
    ordered = loader.resolve_install_order(applications)
    pinned = _map_candidate_applications(candidate, ordered, loader)

    lock_data = loader.build_lock_data(manifest, pinned, package_resolution=None)
    frappe = next(app for app in lock_data["applications"] if app["name"] == "frappe")
    lock_data["framework"].update(
        {
            "target_ref": frappe["target_ref"],
            "ref": frappe["ref"],
            "reference_kind": frappe["reference_kind"],
            "resolved_ref": frappe["resolved_ref"],
        }
    )

    for locked_app, mapped_app in zip(
        lock_data["applications"], pinned, strict=True
    ):
        locked_app.update(
            {
                "app_id": mapped_app["_candidate_app_id"],
                "requested_version": mapped_app["_candidate_requested_version"],
                "candidate_release_version": mapped_app["_candidate_release_version"],
                "candidate_descriptor_ref": mapped_app["_candidate_descriptor_ref"],
                "candidate_descriptor_digest": mapped_app[
                    "_candidate_descriptor_digest"
                ],
            }
        )

    lock_data["candidate"] = {
        "schema_version": candidate["schema_version"],
        "candidate_id": candidate["candidate_id"],
        "candidate_code": candidate["candidate_code"],
        "artifact_reference": candidate_artifact_ref,
        "artifact_digest": artifact_digest,
        "payload_sha256": payload_sha256,
        "composition_hash": candidate["composition_hash"],
        "optional_capabilities": sorted(selected_capabilities),
        "target_platforms": candidate["target_platforms"],
    }

    output_dir = output_dir.resolve()
    if output_dir.is_relative_to((ndf_dir / "locks").resolve()):
        raise CandidateCompositionError(
            "Candidate build output must not be written to the obsolete checked-in locks directory."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_name = f"candidate-{hashlib.sha256(candidate['candidate_id'].encode()).hexdigest()[:16]}.lock-v2.json"
    lock_path = output_dir / lock_name

    try:
        loader.write_lock_file(lock_data, lock_path)
        # The adapter has already checked the complete candidate-to-manifest
        # mapping. Skip source-composition equality because candidate pins
        # replace manifest refs with immutable commit refs; retain all
        # structural lock, dependency, policy and manifest inventory checks.
        loader.validate_lock_file(
            lock_path, manifest, verify_manifest_checksums=False
        )
        lock_bytes = lock_path.read_bytes()
        apps_json = build_apps_json(lock_data)
        apps_path = write_json(output_dir / "apps.json", apps_json)
        metadata = build_metadata(image, lock_data, lock_path, manifest_relative_path)
        metadata["candidate"] = lock_data["candidate"]
        metadata_path = write_json(output_dir / "build-metadata.json", metadata)
        mapping_path = write_json(
            output_dir / "candidate-composition.json",
            {
                "candidate_id": candidate["candidate_id"],
                "candidate_artifact_ref": candidate_artifact_ref,
                "candidate_payload_sha256": payload_sha256,
                "composition_hash": candidate["composition_hash"],
                "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
                "applications": [
                    {
                        "app_id": item["app_id"],
                        "repository": item["repository"],
                        "requested_version": item["requested_version"],
                        "immutable_commit": item["immutable_commit"],
                    }
                    for item in candidate["applications"]
                ],
            },
        )
    except (ManifestError, BuildPreparationError, OSError) as exc:
        lock_path.unlink(missing_ok=True)
        raise CandidateCompositionError(str(exc)) from exc

    return {
        "image": image,
        "lock_path": lock_path,
        "apps_json_path": apps_path,
        "metadata_path": metadata_path,
        "mapping_path": mapping_path,
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "applications_count": len(lock_data["applications"]),
        "bench_apps_count": len(apps_json),
    }


def main() -> int:
    ndf_dir = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Translate a validated deployment candidate into NDF lock-v2 build inputs."
    )
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-artifact-ref", required=True)
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--definitions",
        default="image-definitions/images-v1.json",
        help="Image definitions path relative to images/ndf.",
    )
    args = parser.parse_args()

    try:
        result = adapt_candidate_to_lock(
            ndf_dir=ndf_dir,
            candidate_path=args.candidate,
            output_dir=args.output_dir,
            candidate_artifact_ref=args.candidate_artifact_ref,
            payload_sha256=args.payload_sha256,
            definitions_relative_path=args.definitions,
        )
    except (CandidateCompositionError, ManifestError, BuildPreparationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Candidate: {args.candidate}")
    print(f"Image: {result['image']['id']}")
    print(f"Lock-v2: {result['lock_path']}")
    print(f"Lock SHA-256: {result['lock_sha256']}")
    print(f"Applications: {result['applications_count']}")
    print(f"Bench apps: {result['bench_apps_count']}")
    print(f"Build metadata: {result['metadata_path']}")
    print(f"Candidate composition: {result['mapping_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
