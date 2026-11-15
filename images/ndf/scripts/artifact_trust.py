"""Validate NDF artifact-trust policy, signer claims and attestation statements.

This module validates trust metadata and in-toto statement structure. It does not
perform Cosign cryptographic verification or establish Rekor inclusion; callers
must perform those checks independently before issuing a trusted result.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, SchemaError, ValidationError

NDF_DIR = Path(__file__).resolve().parents[1]
POLICY_PATH = NDF_DIR / "policies" / "artifact-trust-identity-policy-v1.json"
POLICY_SCHEMA_PATH = (
    NDF_DIR / "schemas" / "artifact-trust-identity-policy-v1.schema.json"
)
IMAGE_PROVENANCE_SCHEMA_PATH = (
    NDF_DIR / "schemas" / "ndf-image-provenance-v1.schema.json"
)
PDD_BINDING_SCHEMA_PATH = (
    NDF_DIR / "schemas" / "pdd-image-binding-v1.schema.json"
)
TRUST_RESULT_SCHEMA_PATH = (
    NDF_DIR / "schemas" / "artifact-trust-verification-result-v1.schema.json"
)
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


class ArtifactTrustError(Exception):
    """Raised when artifact trust metadata fails deterministic validation."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactTrustError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ArtifactTrustError(
                    f"Non-finite JSON constant in {label}: {token}"
                )
            ),
        )
    except ArtifactTrustError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactTrustError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactTrustError(f"{label} root must be a JSON object.")
    return value


def _validate_schema(
    value: dict[str, Any], schema_path: Path, label: str
) -> None:
    try:
        schema = _read_json(schema_path, f"{label} schema")
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(
            schema, format_checker=Draft202012Validator.FORMAT_CHECKER
        )
        errors = sorted(
            validator.iter_errors(value),
            key=lambda error: (
                list(map(str, error.absolute_path)),
                error.message,
            ),
        )
    except SchemaError as exc:
        raise ArtifactTrustError(
            f"{label} schema is invalid: {exc.message}"
        ) from exc
    except ValidationError as exc:
        raise ArtifactTrustError(
            f"{label} schema validation failed: {exc.message}"
        ) from exc

    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ArtifactTrustError(
            f"{label} schema validation failed at {location}: {error.message}"
        )


def load_identity_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    """Load and schema-validate the machine-readable identity policy."""
    policy = _read_json(path, "artifact trust identity policy")
    _validate_schema(policy, POLICY_SCHEMA_PATH, "Artifact trust identity policy")

    identities = policy["identities"]
    ids = [entry["id"] for entry in identities]
    if len(ids) != len(set(ids)):
        raise ArtifactTrustError("Identity policy contains duplicate identity IDs.")

    # Multiple purposes may intentionally share a caller identity (candidate
    # image/PDD), but an exact identity cannot be reused for the same artifact
    # kind because that would make policy selection ambiguous.
    seen: set[tuple[str, str]] = set()
    for entry in identities:
        for kind in entry["artifact_kinds"]:
            key = (entry["certificate_identity"], kind)
            if key in seen:
                raise ArtifactTrustError(
                    "Identity policy has an ambiguous duplicate certificate "
                    f"identity for artifact kind {kind}: {entry['certificate_identity']}"
                )
            seen.add(key)

    if policy["issuer"] != GITHUB_OIDC_ISSUER:
        raise ArtifactTrustError("Identity policy OIDC issuer is not the approved GitHub issuer.")
    if policy["status"] not in (
        "provisional_until_live_certificate_observation",
        "confirmed",
    ):
        raise ArtifactTrustError("Identity policy status is not recognized.")
    return policy


def _identity_entry(
    policy: dict[str, Any], identity_id: str
) -> dict[str, Any]:
    matches = [item for item in policy["identities"] if item["id"] == identity_id]
    if len(matches) != 1:
        raise ArtifactTrustError(f"Unknown or ambiguous signer identity purpose: {identity_id}")
    return matches[0]


def validate_signer_claims(
    claims: dict[str, Any],
    *,
    identity_id: str,
    policy: dict[str, Any] | None = None,
    expected_reusable_workflow_sha: str | None = None,
) -> dict[str, Any]:
    """Require exact issuer, caller identity and reusable workflow claims.

    This validates claims supplied by a trusted Cosign/certificate inspection
    step. It does not authenticate those claims itself.
    """
    selected_policy = policy if policy is not None else load_identity_policy()
    _validate_schema(
        selected_policy, POLICY_SCHEMA_PATH, "Artifact trust identity policy"
    )
    entry = _identity_entry(selected_policy, identity_id)

    required = set(selected_policy["required_claims"])
    missing = sorted(name for name in required if claims.get(name) in (None, ""))
    if missing:
        raise ArtifactTrustError(
            f"Signer identity claims are missing required values: {', '.join(missing)}"
        )

    expected = {
        "iss": selected_policy["issuer"],
        "repository": selected_policy["verification"]["required_repository"],
        "ref": selected_policy["verification"]["required_ref"],
        "event_name": selected_policy["verification"]["required_event_name"],
        "workflow_ref": entry["workflow_ref"],
    }
    for claim, expected_value in expected.items():
        if claims.get(claim) != expected_value:
            raise ArtifactTrustError(
                f"Signer claim {claim} mismatch: expected {expected_value!r}, "
                f"got {claims.get(claim)!r}."
            )

    if claims.get("certificate_identity") != entry["certificate_identity"]:
        raise ArtifactTrustError("Fulcio certificate identity does not match the exact allowlist entry.")

    if not re.fullmatch(r"[0-9]+", str(claims["run_id"])):
        raise ArtifactTrustError("Signer run_id must contain decimal digits only.")
    if (
        isinstance(claims["run_attempt"], bool)
        or not isinstance(claims["run_attempt"], int)
        or claims["run_attempt"] < 1
    ):
        raise ArtifactTrustError("Signer run_attempt must be a positive integer.")

    expected_reusable_ref = entry["reusable_workflow_ref"]
    if expected_reusable_ref is not None:
        actual_ref = claims.get("job_workflow_ref")
        actual_sha = claims.get("job_workflow_sha")
        if actual_ref != expected_reusable_ref:
            raise ArtifactTrustError(
                "Reusable workflow identity mismatch: expected "
                f"{expected_reusable_ref!r}, got {actual_ref!r}."
            )
        if not isinstance(actual_sha, str) or not re.fullmatch(
            r"[a-f0-9]{40,64}", actual_sha
        ):
            raise ArtifactTrustError(
                "Reusable workflow job_workflow_sha is missing or invalid."
            )
        if (
            expected_reusable_workflow_sha is not None
            and actual_sha != expected_reusable_workflow_sha
        ):
            raise ArtifactTrustError("Reusable workflow commit SHA mismatch.")
    elif claims.get("job_workflow_ref") not in (None, ""):
        raise ArtifactTrustError(
            "A direct workflow identity must not be verified as a reusable workflow."
        )

    return {
        "identity_id": entry["id"],
        "artifact_kinds": list(entry["artifact_kinds"]),
        "certificate_identity": entry["certificate_identity"],
        "issuer": selected_policy["issuer"],
        "workflow_ref": entry["workflow_ref"],
        "reusable_workflow_ref": expected_reusable_ref,
        "reusable_workflow_sha": claims.get("job_workflow_sha"),
        "run_id": str(claims["run_id"]),
        "run_attempt": claims["run_attempt"],
        "policy_status": selected_policy["status"],
        "identity_claims_validated": True,
        "cryptographic_signature_verified": False,
        "transparency_log_verified": False,
    }


def validate_image_provenance_statement(
    statement: dict[str, Any], image_digest: str
) -> dict[str, Any]:
    """Validate the NDF SLSA provenance profile and exact image subject digest."""
    _validate_schema(
        statement, IMAGE_PROVENANCE_SCHEMA_PATH, "NDF image provenance statement"
    )
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest):
        raise ArtifactTrustError("Requested image digest must be a valid sha256 digest.")
    subjects = statement["subject"]
    if len(subjects) != 1:
        raise ArtifactTrustError("Image provenance must contain exactly one subject.")
    actual = "sha256:" + subjects[0]["digest"]["sha256"]
    if actual != image_digest:
        raise ArtifactTrustError(
            f"Image provenance subject digest mismatch: expected {image_digest}, got {actual}."
        )
    return {
        "predicate_type": statement["predicateType"],
        "subject_name": subjects[0]["name"],
        "subject_digest": actual,
        "product_id": statement["predicate"]["ndf_build"]["product_id"],
        "platform": statement["predicate"]["ndf_build"]["platform"],
        "candidate": "candidate" in statement["predicate"]["ndf_build"],
        "statement_schema_validated": True,
    }


def validate_pdd_binding_statement(
    statement: dict[str, Any],
    *,
    pdd_digest: str,
    image_digest: str,
    descriptor_content_sha256: str,
) -> dict[str, Any]:
    """Validate PDD binding statement subject and its image/content claims."""
    _validate_schema(
        statement, PDD_BINDING_SCHEMA_PATH, "PDD-image binding statement"
    )
    for label, digest in (("PDD", pdd_digest), ("image", image_digest)):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ArtifactTrustError(f"Requested {label} digest is not a valid sha256 digest.")
    if not re.fullmatch(r"[a-f0-9]{64}", descriptor_content_sha256):
        raise ArtifactTrustError("Descriptor content SHA-256 is invalid.")

    subject_digest = "sha256:" + statement["subject"][0]["digest"]["sha256"]
    if subject_digest != pdd_digest:
        raise ArtifactTrustError(
            f"PDD statement subject mismatch: expected {pdd_digest}, got {subject_digest}."
        )
    predicate = statement["predicate"]
    if predicate["subject_image"]["digest"] != image_digest:
        raise ArtifactTrustError("PDD binding predicate identifies a different image digest.")
    if predicate["descriptor"]["content_sha256"] != descriptor_content_sha256:
        raise ArtifactTrustError("PDD binding descriptor content hash mismatch.")

    return {
        "predicate_type": statement["predicateType"],
        "pdd_subject_digest": subject_digest,
        "image_digest": image_digest,
        "descriptor_content_sha256": descriptor_content_sha256,
        "statement_schema_validated": True,
    }


def validate_trust_verification_result(result: dict[str, Any]) -> None:
    """Validate the normalized verification-result document."""
    _validate_schema(
        result, TRUST_RESULT_SCHEMA_PATH, "Artifact trust verification result"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate NDF artifact trust identity policy."
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=POLICY_PATH,
        help="Path to the signer identity policy JSON.",
    )
    args = parser.parse_args(argv)
    try:
        policy = load_identity_policy(args.policy)
    except ArtifactTrustError as exc:
        print(f"Artifact trust policy validation failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "passed",
                "policy_id": policy["policy_id"],
                "policy_status": policy["status"],
                "identity_count": len(policy["identities"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
