#!/usr/bin/env python3
"""Generate deterministic SLSA Provenance v1 for a validated NDF image build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from jsonschema import Draft202012Validator, ValidationError

try:
    from .gate_image_publication import (
        PublicationGateError,
        verify_publication_candidate,
    )
except ImportError:
    from gate_image_publication import (
        PublicationGateError,
        verify_publication_candidate,
    )


NDF_DIR = Path(__file__).resolve().parents[1]
PROVENANCE_SCHEMA = NDF_DIR / "schemas" / "ndf-image-provenance-v1.schema.json"
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40,64}$")
PRODUCT_IMAGE_WORKFLOW_PATH = ".github/workflows/ndf-publish-product.yml"
WORKFLOW_REF_RE = re.compile(
    r"^(?P<repository>NdfTechLabs/frappe_docker)/"
    + re.escape(PRODUCT_IMAGE_WORKFLOW_PATH)
    + r"@(?P<ref>refs/heads/main)$"
)


class ImageProvenanceError(Exception):
    """Raised when build evidence cannot support a trustworthy provenance claim."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_constant(value: str) -> None:
    raise ImageProvenanceError(f"Non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ImageProvenanceError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ImageProvenanceError(f"Required evidence is missing or unsafe: {path.name}")
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImageProvenanceError(f"Unable to read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ImageProvenanceError(f"{path.name} must contain a JSON object.")
    return value, raw


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ImageProvenanceError(message)


def _workflow_context(env: dict[str, str]) -> dict[str, Any]:
    required = (
        "GITHUB_REPOSITORY",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_REF",
        "GITHUB_EVENT_NAME",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
    )
    missing = [name for name in required if not env.get(name)]
    _require(not missing, f"GitHub Actions context is incomplete: {', '.join(missing)}")
    _require(
        env["GITHUB_REPOSITORY"] == "NdfTechLabs/frappe_docker",
        "Workflow repository is not the approved NDF repository.",
    )
    _require(env["GITHUB_REF"] == "refs/heads/main", "Only refs/heads/main is accepted.")
    _require(
        env["GITHUB_EVENT_NAME"] == "workflow_dispatch",
        "Only workflow_dispatch provenance is accepted by this publication contract.",
    )
    match = WORKFLOW_REF_RE.fullmatch(env["GITHUB_WORKFLOW_REF"])
    _require(match is not None, "GITHUB_WORKFLOW_REF is not an approved main-branch workflow ref.")
    _require(
        re.fullmatch(r"[0-9]+", env["GITHUB_RUN_ID"]) is not None,
        "GITHUB_RUN_ID must contain decimal digits only.",
    )
    _require(
        re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_ATTEMPT"]) is not None,
        "GITHUB_RUN_ATTEMPT must be a positive integer.",
    )
    source_commit = env["GITHUB_SHA"].lower()
    _require(COMMIT_RE.fullmatch(source_commit) is not None, "GITHUB_SHA is not a valid commit SHA.")
    return {
        "repository": env["GITHUB_REPOSITORY"],
        "path": PRODUCT_IMAGE_WORKFLOW_PATH,
        "ref": env["GITHUB_REF"],
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "source_commit": source_commit,
    }


def _source_revisions(
    inventory: dict[str, Any], provenance: dict[str, Any], verification: dict[str, Any]
) -> list[dict[str, str]]:
    inventory_apps = inventory.get("applications")
    framework = inventory.get("framework")
    _require(isinstance(inventory_apps, list) and all(isinstance(item, dict) for item in inventory_apps), "Build inventory has malformed application records.")
    _require(isinstance(framework, dict), "Build inventory framework record is missing.")
    inventory_by_name: dict[str, dict[str, Any]] = {}
    for item in inventory_apps:
        name = item.get("name")
        _require(isinstance(name, str) and name not in inventory_by_name, "Build inventory has missing or duplicate repository names.")
        inventory_by_name[name] = item
    _require(inventory_by_name.get("frappe") == framework, "Build inventory framework record differs from the Frappe application record.")

    provenance_records = provenance.get("repositories")
    verification_records = verification.get("repositories")
    _require(isinstance(provenance_records, list) and isinstance(verification_records, list), "Source provenance repository records are malformed.")
    provenance_by_name = {item.get("name"): item for item in provenance_records if isinstance(item, dict)}
    verification_by_name = {item.get("name"): item for item in verification_records if isinstance(item, dict)}
    _require(
        len(provenance_by_name) == len(provenance_records)
        and len(verification_by_name) == len(verification_records),
        "Source provenance contains malformed or duplicate repository records.",
    )
    _require(
        set(inventory_by_name) == set(provenance_by_name) == set(verification_by_name),
        "Build inventory, source provenance and independent verification repository sets differ.",
    )

    revisions = []
    for name in sorted(inventory_by_name):
        inv = inventory_by_name[name]
        src = provenance_by_name[name]
        verified = verification_by_name[name]
        repository = inv.get("repository")
        commit = inv.get("actual_commit")
        _require(isinstance(repository, str) and repository, f"Missing repository identity for {name}.")
        _require(isinstance(commit, str) and COMMIT_RE.fullmatch(commit), f"Invalid acquired commit for {name}.")
        _require(
            src.get("repository") == repository
            and src.get("actual_commit") == commit,
            f"Source provenance identity/commit mismatch for {name}.",
        )
        _require(
            verified.get("repository") == repository
            and verified.get("actual_commit") == commit
            and verified.get("status") == "verified",
            f"Independent source verification mismatch for {name}.",
        )
        revisions.append({"repository": repository, "commit": commit})
    return revisions


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ImageProvenanceError(f"Refusing to replace symlink output: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise ImageProvenanceError(f"Unable to write provenance output {path}: {exc}") from exc


def generate_image_provenance(
    *,
    build_output_dir: Path,
    image_id: str,
    candidate_image_ref: str,
    publication_image_ref: str,
    framework_major: str,
    predicate_output: Path,
    statement_output: Path,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate existing publication evidence and create predicate + Statement."""
    build_output_dir = build_output_dir.resolve()
    runtime_env = dict(os.environ if env is None else env)
    workflow = _workflow_context(runtime_env)

    metadata, _ = load_json(build_output_dir / "build-metadata.json")
    buildx, _ = load_json(build_output_dir / "buildx-metadata.json")
    result, _ = load_json(build_output_dir / "build-result.json")
    inventory, _ = load_json(build_output_dir / "build-inventory.json")
    provenance, provenance_raw = load_json(build_output_dir / "source-provenance.json")
    source_verification, _ = load_json(
        build_output_dir / "source-provenance-verification.json"
    )
    composition, composition_raw = load_json(
        build_output_dir / "image-composition-verification.json"
    )
    image_validation, image_validation_raw = load_json(
        build_output_dir / "image-validation.json"
    )
    evidence, evidence_raw = load_json(build_output_dir / "image-verification-evidence.json")
    gate_report, _ = load_json(build_output_dir / "publication-gate.json")

    _require(gate_report.get("status") == "ready", "Publication gate report is not ready.")
    _require(composition.get("status") == "passed", "Image composition verification did not pass.")
    _require(source_verification.get("status") == "passed", "Independent source provenance verification did not pass.")
    _require(image_validation.get("status") == "passed", "Image validation did not pass.")
    _require(inventory.get("stage") == "builder", "Build inventory is not from the builder stage.")
    _require(inventory.get("schema_version") == "1.0", "Unsupported build inventory schema version.")
    _require(provenance.get("algorithm") == "ndf-source-provenance-v1", "Unsupported source provenance algorithm.")
    _require(source_verification.get("source_provenance_sha256") == sha256(provenance_raw), "Independent verification does not bind the exact source provenance bytes.")

    image = metadata.get("image")
    framework = metadata.get("framework")
    lock = metadata.get("lock")
    _require(isinstance(image, dict) and image.get("id") == image_id, "Build metadata product identity mismatch.")
    _require(isinstance(framework, dict) and isinstance(lock, dict), "Build metadata framework/lock fields are missing.")
    _require(str(framework.get("version", "")).split(".", 1)[0] == framework_major, "Framework major version mismatch.")
    repository = image.get("repository")
    digest = result.get("digest")
    _require(isinstance(repository, str) and repository, "Build metadata image repository is missing.")
    _require(isinstance(digest, str) and DIGEST_RE.fullmatch(digest), "Build result has no valid immutable image digest.")
    _require(buildx.get("containerimage.digest") == digest, "Buildx and registry build-result digests differ.")
    _require(gate_report.get("image", {}).get("digest") == digest, "Publication gate report identifies a different image digest.")
    _require(gate_report.get("image", {}).get("id") == image_id, "Publication gate report identifies a different image.")
    _require(gate_report.get("image", {}).get("repository") == repository, "Publication gate report identifies a different repository.")
    _require(gate_report.get("source", {}).get("sha") == workflow["source_commit"], "Publication gate source SHA differs from GitHub Actions GITHUB_SHA.")
    _require(gate_report.get("image", {}).get("candidate_reference") == candidate_image_ref, "Publication gate candidate reference mismatch.")
    _require(gate_report.get("image", {}).get("publication_reference") == publication_image_ref, "Publication gate publication reference mismatch.")
    _require(inventory.get("lock", {}).get("sha256") == lock.get("sha256"), "Build inventory lock hash differs from build metadata.")
    _require(provenance.get("lock", {}).get("sha256") == lock.get("sha256"), "Source provenance lock hash differs from build metadata.")
    _require(source_verification.get("lock", {}).get("sha256") == lock.get("sha256"), "Independent source verification lock hash differs from build metadata.")
    _require(composition.get("lock", {}).get("sha256") == lock.get("sha256"), "Composition verification lock hash differs from build metadata.")

    lock_path = build_output_dir / f"{image_id}.lock-v2.json"
    _, lock_raw = load_json(lock_path)
    lock_sha = sha256(lock_raw)
    _require(lock_sha == lock.get("sha256"), "Exact lock-v2 bytes differ from build metadata.")
    _require(lock_sha == gate_report.get("lock", {}).get("sha256"), "Exact lock-v2 bytes differ from publication gate.")
    _require(evidence.get("status") == "bound", "Image verification evidence is not bound.")
    _require(evidence.get("image", {}).get("digest") == digest, "Image verification evidence is bound to another digest.")
    _require(evidence.get("lock", {}).get("sha256") == lock_sha, "Image verification evidence is bound to another lock.")

    # Re-run the existing publication gate against exact evidence bytes; compare its result.
    try:
        independently_gated = verify_publication_candidate(
            build_output_dir=build_output_dir,
            image_id=image_id,
            source_sha=workflow["source_commit"],
            framework_major=framework_major,
            candidate_image_ref=candidate_image_ref,
            publication_image_ref=publication_image_ref,
        )
    except PublicationGateError as exc:
        raise ImageProvenanceError(f"Existing publication evidence gate failed: {exc}") from exc
    _require(independently_gated == gate_report, "Stored publication gate report differs from independently recomputed result.")

    platform = inventory.get("runtime", {}).get("platform", {}).get("oci")
    _require(platform in ("linux/amd64", "linux/arm64"), "Build inventory contains an unsupported OCI platform.")
    revisions = _source_revisions(inventory, provenance, source_verification)

    # composition_sha256 is defined as the hash of the exact passed report bytes.
    composition_sha = sha256(composition_raw)
    evidence_checks = {
        "image_validation": {"status": "passed", "report_sha256": sha256(image_validation_raw)},
        "source_provenance": {"status": "passed", "report_sha256": sha256(provenance_raw)},
        "composition_verification": {"status": "passed", "report_sha256": composition_sha},
        "evidence_binding": {"status": "passed", "report_sha256": sha256(evidence_raw)},
    }
    predicate = {
        "buildDefinition": {
            "buildType": "https://ndftechlabs.com/buildtypes/frappe-docker-image/v1",
            "externalParameters": {
                "product_id": image_id,
                "image_repository": repository,
                "platform": platform,
                "framework_version": framework["version"],
                "lock_sha256": lock_sha,
                "composition_sha256": composition_sha,
            },
            "resolvedDependencies": [
                {
                    "uri": f"https://github.com/{quote(item['repository'], safe='/')}",
                    "digest": {"gitCommit": item["commit"]},
                    "name": item["repository"],
                }
                for item in revisions
            ],
        },
        "runDetails": {
            "builder": {"id": "https://github.com/NdfTechLabs/frappe_docker/actions"},
        },
        "ndf_build": {
            "schema_version": "1.0.0",
            "product_id": image_id,
            "platform": platform,
            "workflow": workflow,
            "lock_sha256": lock_sha,
            "composition_sha256": composition_sha,
            "source_revisions": revisions,
            "validation": evidence_checks,
        },
    }
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": repository, "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }
    schema, _ = load_json(PROVENANCE_SCHEMA)
    try:
        Draft202012Validator(schema).validate(statement)
    except ValidationError as exc:
        location = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ImageProvenanceError(f"NDF image provenance schema failed at {location}: {exc.message}") from exc

    predicate_raw = (json.dumps(predicate, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    statement_raw = (json.dumps(statement, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(predicate_output, predicate_raw)
    try:
        _atomic_write(statement_output, statement_raw)
    except ImageProvenanceError:
        predicate_output.unlink(missing_ok=True)
        raise
    return {
        "status": "passed",
        "image_digest": digest,
        "product_id": image_id,
        "platform": platform,
        "lock_sha256": lock_sha,
        "composition_sha256": composition_sha,
        "source_revision_count": len(revisions),
        "predicate_sha256": sha256(predicate_raw),
        "statement_sha256": sha256(statement_raw),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-output-dir", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--framework-major", required=True)
    parser.add_argument("--candidate-image-ref", required=True)
    parser.add_argument("--publication-image-ref", required=True)
    parser.add_argument("--predicate-output", type=Path, required=True)
    parser.add_argument("--statement-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = generate_image_provenance(
            build_output_dir=args.build_output_dir,
            image_id=args.image_id,
            framework_major=args.framework_major,
            candidate_image_ref=args.candidate_image_ref,
            publication_image_ref=args.publication_image_ref,
            predicate_output=args.predicate_output,
            statement_output=args.statement_output,
        )
    except (ImageProvenanceError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
