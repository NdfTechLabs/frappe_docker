#!/usr/bin/env python3
"""Generate deterministic in-toto Statement v1 binding a PDD to its source image."""

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

from jsonschema import Draft202012Validator, ValidationError

try:
    from .artifact_trust import (
        ArtifactTrustError,
        validate_trust_verification_result,
    )
    from .validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )
except ImportError:
    from artifact_trust import ArtifactTrustError, validate_trust_verification_result
    from validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )

NDF_DIR = Path(__file__).resolve().parents[1]
PUBLICATION_SCHEMA = NDF_DIR / "schemas" / "pdd-publication-record-v1.schema.json"
BINDING_SCHEMA = NDF_DIR / "schemas" / "pdd-image-binding-v1.schema.json"
PDD_WORKFLOW_PATH = ".github/workflows/ndf-publish-product-deployment-descriptor.yml"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
PROVISIONAL_REASON = "IDENTITY_POLICY_PROVISIONAL"
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40,64}$")


class PDDBindingGenerationError(Exception):
    """Raised when inputs cannot support a trustworthy PDD binding statement."""


def _reject_constant(value: str) -> None:
    raise PDDBindingGenerationError(f"Non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PDDBindingGenerationError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PDDBindingGenerationError(f"{label} is missing or unsafe.")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except PDDBindingGenerationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PDDBindingGenerationError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise PDDBindingGenerationError(f"{label} must be a JSON object.")
    return value


def _canonical_json(value: Any) -> bytes:
    """NDF-JSON-CANONICAL-V1: sorted compact UTF-8 JSON plus one LF."""
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PDDBindingGenerationError(f"Unable to canonicalize JSON: {exc}") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_schema(value: dict[str, Any], path: Path, label: str) -> None:
    try:
        schema = _read_json(path, f"{label} schema")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema, format_checker=Draft202012Validator.FORMAT_CHECKER
        ).validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
        raise PDDBindingGenerationError(f"{label} schema validation failed: {exc}") from exc


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
    if missing:
        raise PDDBindingGenerationError(
            f"GitHub Actions context is incomplete: {', '.join(missing)}"
        )
    expected_ref = (
        f"NdfTechLabs/frappe_docker/{PDD_WORKFLOW_PATH}@refs/heads/main"
    )
    if (
        env["GITHUB_REPOSITORY"] != "NdfTechLabs/frappe_docker"
        or env["GITHUB_WORKFLOW_REF"] != expected_ref
        or env["GITHUB_REF"] != "refs/heads/main"
        or env["GITHUB_EVENT_NAME"] != "workflow_dispatch"
    ):
        raise PDDBindingGenerationError(
            "Workflow context is not the approved PDD publication workflow on main."
        )
    if not re.fullmatch(r"[0-9]+", env["GITHUB_RUN_ID"]):
        raise PDDBindingGenerationError("GITHUB_RUN_ID must contain decimal digits only.")
    if not re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_ATTEMPT"]):
        raise PDDBindingGenerationError("GITHUB_RUN_ATTEMPT must be a positive integer.")
    source_commit = env["GITHUB_SHA"].lower()
    if not COMMIT_RE.fullmatch(source_commit):
        raise PDDBindingGenerationError("GITHUB_SHA is not a valid commit SHA.")
    return {
        "repository": env["GITHUB_REPOSITORY"],
        "path": PDD_WORKFLOW_PATH,
        "ref": env["GITHUB_REF"],
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "source_commit": source_commit,
    }


def _validate_publication_receipt(
    receipt: dict[str, Any], descriptor: dict[str, Any]
) -> None:
    _validate_schema(receipt, PUBLICATION_SCHEMA, "PDD publication receipt")
    artifact = receipt["artifact"]
    pdd_artifact = descriptor["artifact"]
    expected_reference = f"{artifact['repository']}@{artifact['digest']}"
    if artifact["immutable_reference"] != expected_reference:
        raise PDDBindingGenerationError(
            "Publication receipt immutable reference does not match its repository/digest."
        )
    if (
        receipt["descriptor"]["id"] != descriptor["descriptor_id"]
        or receipt["descriptor"]["schema_version"] != descriptor["schema_version"]
        or receipt["descriptor"]["content_sha256"]
        != descriptor["integrity"]["content_sha256"]
    ):
        raise PDDBindingGenerationError(
            "Publication receipt descriptor identity/content does not match the PDD."
        )
    subject = receipt["subject_image"]
    if any(
        subject[field] != pdd_artifact[field]
        for field in ("repository", "digest", "platform")
    ):
        raise PDDBindingGenerationError(
            "Publication receipt subject image does not match the PDD artifact."
        )
    if (
        artifact["repository"] != pdd_artifact["repository"]
        or artifact["digest"] == pdd_artifact["digest"]
    ):
        # PDD and image may share a registry repository only in unusual setups,
        # but their artifact digests must never be conflated.
        if artifact["digest"] == pdd_artifact["digest"]:
            raise PDDBindingGenerationError(
                "PDD OCI artifact digest must differ from the subject image digest."
            )


def _validate_source_image_trust(
    trust_result: dict[str, Any],
    predicate: dict[str, Any],
    descriptor: dict[str, Any],
) -> str:
    try:
        validate_trust_verification_result(trust_result)
    except ArtifactTrustError as exc:
        raise PDDBindingGenerationError(
            f"Source image trust result is invalid: {exc}"
        ) from exc

    artifact = trust_result["artifact"]
    image = descriptor["artifact"]
    expected_reference = f"{image['repository']}@{image['digest']}"
    if (
        artifact["kind"] != "product_image"
        or artifact["repository"] != image["repository"]
        or artifact["digest"] != image["digest"]
        or artifact["immutable_reference"] != expected_reference
    ):
        raise PDDBindingGenerationError(
            "Source image trust result is not bound to the exact PDD image."
        )
    if (
        trust_result["signature"]["verified"] is not True
        or trust_result["signer"]["verified"] is not True
        or trust_result["transparency"]["verified"] is not True
        or trust_result["transparency"]["log_entry_verified"] is not True
    ):
        raise PDDBindingGenerationError(
            "Source image signature, signer or Rekor verification did not pass."
        )
    matching = [
        item
        for item in trust_result["attestations"]
        if item["predicate_type"] == PREDICATE_TYPE
    ]
    if len(matching) != 1:
        raise PDDBindingGenerationError(
            "Source image trust result must contain exactly one SLSA Provenance v1 attestation."
        )
    attestation = matching[0]
    if attestation["verified"] is not True or attestation["subject_digest"] != image["digest"]:
        raise PDDBindingGenerationError(
            "Source image SLSA attestation is not verified for the exact image digest."
        )
    actual_hash = _sha256(_canonical_json(predicate))
    if attestation.get("predicate_sha256") != actual_hash:
        raise PDDBindingGenerationError(
            "Verified source provenance predicate hash does not match the supplied predicate."
        )
    if (
        predicate.get("ndf_build", {}).get("product_id") != descriptor["product"]["id"]
        or predicate.get("ndf_build", {}).get("platform") != image["platform"]
    ):
        raise PDDBindingGenerationError(
            "Source provenance product/platform claims do not match the PDD."
        )
    workflow = predicate.get("ndf_build", {}).get("workflow", {})
    if (
        workflow.get("repository") != "NdfTechLabs/frappe_docker"
        or workflow.get("source_commit") != descriptor["build"]["source_commit"]
        or workflow.get("run_id") != descriptor["build"]["workflow_run_id"]
    ):
        raise PDDBindingGenerationError(
            "Source provenance workflow claims do not match the PDD build identity."
        )

    decision = trust_result["decision"]
    if decision["status"] == "trusted":
        if decision["reason_codes"]:
            raise PDDBindingGenerationError(
                "Trusted source image result must not contain rejection reason codes."
            )
    elif decision["reason_codes"] != [PROVISIONAL_REASON]:
        raise PDDBindingGenerationError(
            "Rejected source image trust is accepted only for provisional identity policy."
        )
    return actual_hash


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise PDDBindingGenerationError(f"Refusing to replace symlink output: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp",
            delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise PDDBindingGenerationError(f"Unable to write output {path}: {exc}") from exc


def generate_pdd_image_binding(
    *,
    descriptor_path: Path,
    publication_record_path: Path,
    source_trust_result_path: Path,
    source_predicate_path: Path,
    statement_output: Path,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate all inputs and emit a deterministic PDD-to-image Statement v1."""
    try:
        validate_descriptor(descriptor_path)
    except DescriptorValidationError as exc:
        raise PDDBindingGenerationError(f"PDD validation failed: {exc}") from exc
    descriptor = _read_json(descriptor_path, "PDD")
    receipt = _read_json(publication_record_path, "PDD publication receipt")
    trust_result = _read_json(source_trust_result_path, "source image trust result")
    predicate = _read_json(source_predicate_path, "verified source image predicate")
    _validate_publication_receipt(receipt, descriptor)
    predicate_hash = _validate_source_image_trust(trust_result, predicate, descriptor)
    workflow = _workflow_context(dict(os.environ if env is None else env))

    artifact = descriptor["artifact"]
    lock_sha = descriptor["composition"]["lock"]["sha256"]
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": receipt["artifact"]["repository"],
                "digest": {
                    "sha256": receipt["artifact"]["digest"].removeprefix("sha256:")
                },
            }
        ],
        "predicateType": "https://ndftechlabs.com/attestations/pdd-image-binding/v1",
        "predicate": {
            "schema_version": "1.0.0",
            "descriptor": {
                "id": descriptor["descriptor_id"],
                "content_sha256": descriptor["integrity"]["content_sha256"],
            },
            "subject_image": {
                "repository": artifact["repository"],
                "digest": artifact["digest"],
                "platform": artifact["platform"],
            },
            "lock_sha256": lock_sha,
            "source_provenance": {
                "predicate_type": PREDICATE_TYPE,
                "predicate_sha256": predicate_hash,
            },
            "workflow": workflow,
        },
    }
    _validate_schema(statement, BINDING_SCHEMA, "PDD image binding statement")
    raw = (
        json.dumps(statement, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    _atomic_write(statement_output, raw)
    return {
        "status": "passed",
        "descriptor_id": descriptor["descriptor_id"],
        "pdd_artifact_digest": receipt["artifact"]["digest"],
        "image_digest": artifact["digest"],
        "source_predicate_sha256": predicate_hash,
        "statement_sha256": _sha256(raw),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--publication-record", required=True, type=Path)
    parser.add_argument("--source-trust-result", required=True, type=Path)
    parser.add_argument("--source-predicate", required=True, type=Path)
    parser.add_argument("--statement-output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = generate_pdd_image_binding(
            descriptor_path=args.descriptor,
            publication_record_path=args.publication_record,
            source_trust_result_path=args.source_trust_result,
            source_predicate_path=args.source_predicate,
            statement_output=args.statement_output,
        )
    except (PDDBindingGenerationError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
