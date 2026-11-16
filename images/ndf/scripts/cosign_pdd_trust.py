#!/usr/bin/env python3
"""Sign and independently verify NDF PDD OCI artifacts with Cosign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from . import artifact_trust
    from . import cosign_image_trust as image_trust
except ImportError:
    import artifact_trust
    import cosign_image_trust as image_trust

NDF_DIR = Path(__file__).resolve().parents[1]
POLICY_PATH = NDF_DIR / "policies" / "artifact-trust-identity-policy-v1.json"
COSIGN_STATEMENT_SCHEMA = (
    NDF_DIR / "schemas" / "cosign-pdd-binding-statement-v0.1.schema.json"
)
COSIGN_VERSION = "v3.1.4"
IDENTITY_ID = "product-pdd-publication"
PREDICATE_TYPE = "https://ndftechlabs.com/attestations/pdd-image-binding/v1"
WORKFLOW_PATH = ".github/workflows/ndf-publish-product-deployment-descriptor.yml"
WORKFLOW_REF = (
    "NdfTechLabs/frappe_docker/"
    ".github/workflows/ndf-publish-product-deployment-descriptor.yml@refs/heads/main"
)
PROVISIONAL_REASON = "IDENTITY_POLICY_PROVISIONAL"
PDD_REF_RE = re.compile(
    r"^(?P<repository>[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+)"
    r"@(?P<digest>sha256:[a-f0-9]{64})$"
)


class PDDCosignTrustError(Exception):
    """Raised when PDD signing or verification cannot establish the trust contract."""


def parse_pdd_reference(reference: str) -> tuple[str, str]:
    match = PDD_REF_RE.fullmatch(reference)
    if match is None:
        raise PDDCosignTrustError(
            "PDD reference must be a fully qualified repository@sha256 digest; tags are forbidden."
        )
    return match.group("repository"), match.group("digest")


def _load_identity(
    policy_path: Path = POLICY_PATH,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        policy = artifact_trust.load_identity_policy(policy_path)
    except Exception as exc:
        raise PDDCosignTrustError(
            f"Unable to load signer identity policy: {exc}"
        ) from exc
    matches = [
        entry
        for entry in policy["identities"]
        if entry["id"] == IDENTITY_ID and "pdd" in entry["artifact_kinds"]
    ]
    if len(matches) != 1:
        raise PDDCosignTrustError("PDD signer identity is missing or ambiguous.")
    identity = matches[0]
    if identity["reusable_workflow_ref"] is not None:
        raise PDDCosignTrustError("PDD signer must be a direct workflow identity.")
    if identity["workflow_ref"] != WORKFLOW_REF:
        raise PDDCosignTrustError("PDD signer workflow reference changed unexpectedly.")
    if identity["certificate_identity"] != (
        "https://github.com/NdfTechLabs/frappe_docker/"
        ".github/workflows/ndf-publish-product-deployment-descriptor.yml@refs/heads/main"
    ):
        raise PDDCosignTrustError("PDD certificate identity changed unexpectedly.")
    if policy["issuer"] != "https://token.actions.githubusercontent.com":
        raise PDDCosignTrustError("PDD signer policy uses an unapproved OIDC issuer.")
    return policy, identity


def _runtime_workflow(env: dict[str, str]) -> dict[str, Any]:
    if env.get("GITHUB_ACTIONS", "").lower() != "true":
        raise PDDCosignTrustError(
            "Keyless PDD signing is permitted only inside GitHub Actions."
        )
    required = (
        "GITHUB_REPOSITORY",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_REF",
        "GITHUB_EVENT_NAME",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
    )
    missing = [key for key in required if not env.get(key)]
    if missing:
        raise PDDCosignTrustError(
            f"GitHub Actions context is incomplete: {', '.join(missing)}"
        )
    if (
        env["GITHUB_REPOSITORY"] != "NdfTechLabs/frappe_docker"
        or env["GITHUB_WORKFLOW_REF"] != WORKFLOW_REF
        or env["GITHUB_REF"] != "refs/heads/main"
        or env["GITHUB_EVENT_NAME"] != "workflow_dispatch"
    ):
        raise PDDCosignTrustError(
            "Runtime is not the approved PDD publication workflow on main."
        )
    if not re.fullmatch(r"[0-9]+", env["GITHUB_RUN_ID"]):
        raise PDDCosignTrustError("GITHUB_RUN_ID must contain decimal digits only.")
    if not re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_ATTEMPT"]):
        raise PDDCosignTrustError("GITHUB_RUN_ATTEMPT must be a positive integer.")
    source_commit = env["GITHUB_SHA"].lower()
    if not re.fullmatch(r"[a-f0-9]{40,64}", source_commit):
        raise PDDCosignTrustError("GITHUB_SHA is not a valid commit SHA.")
    return {
        "repository": env["GITHUB_REPOSITORY"],
        "path": WORKFLOW_PATH,
        "ref": env["GITHUB_REF"],
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "source_commit": source_commit,
    }


def _validate_statement_v1(
    statement: dict[str, Any], *, repository: str, digest: str
) -> dict[str, Any]:
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise PDDCosignTrustError("Original NDF PDD binding must use Statement v1.")
    try:
        predicate = statement["predicate"]
        report = artifact_trust.validate_pdd_binding_statement(
            statement,
            pdd_digest=digest,
            image_digest=predicate["subject_image"]["digest"],
            descriptor_content_sha256=predicate["descriptor"]["content_sha256"],
        )
    except Exception as exc:
        raise PDDCosignTrustError(f"PDD binding statement is invalid: {exc}") from exc
    subject = statement["subject"]
    if len(subject) != 1 or subject[0]["name"] != repository:
        raise PDDCosignTrustError(
            "PDD binding subject repository does not match the immutable reference."
        )
    if statement["predicateType"] != PREDICATE_TYPE:
        raise PDDCosignTrustError("PDD binding predicate type is not approved.")
    workflow = predicate["workflow"]
    if (
        workflow["repository"] != "NdfTechLabs/frappe_docker"
        or workflow["path"] != WORKFLOW_PATH
        or workflow["ref"] != "refs/heads/main"
    ):
        raise PDDCosignTrustError(
            "PDD binding workflow claims are outside the exact signer policy."
        )
    return report


def sign_pdd(
    *,
    pdd_ref: str,
    statement_path: Path,
    predicate_path: Path,
    env: dict[str, str] | None = None,
    policy_path: Path = POLICY_PATH,
    cosign_binary: str = "cosign",
    runner: Any = None,
) -> dict[str, Any]:
    """Sign an immutable PDD OCI artifact and attach its validated binding predicate."""
    runtime_env = dict(os.environ if env is None else env)
    workflow = _runtime_workflow(runtime_env)
    repository, digest = parse_pdd_reference(pdd_ref)
    policy, identity = _load_identity(policy_path)
    statement = image_trust._strict_json(statement_path, "PDD binding Statement")
    predicate = image_trust._strict_json(predicate_path, "PDD binding predicate")
    _validate_statement_v1(statement, repository=repository, digest=digest)
    if predicate != statement["predicate"]:
        raise PDDCosignTrustError(
            "Predicate file does not exactly match the Statement predicate."
        )
    if predicate["workflow"] != workflow:
        raise PDDCosignTrustError(
            "PDD binding workflow claims differ from the actual runtime context."
        )

    command_runner = runner or image_trust.subprocess.run
    image_trust._require_cosign_version(
        runner=command_runner, cosign_binary=cosign_binary
    )
    image_trust._run(
        [cosign_binary, "sign", "--yes", pdd_ref],
        runner=command_runner,
        env=runtime_env,
    )
    image_trust._run(
        [
            cosign_binary,
            "attest",
            "--yes",
            "--type",
            PREDICATE_TYPE,
            "--predicate",
            str(predicate_path),
            pdd_ref,
        ],
        runner=command_runner,
        env=runtime_env,
    )
    return {
        "status": "signed",
        "pdd_repository": repository,
        "pdd_digest": digest,
        "predicate_type": PREDICATE_TYPE,
        "predicate_sha256": hashlib.sha256(
            image_trust._canonical_json(predicate)
        ).hexdigest(),
        "identity_id": identity["id"],
        "policy_status": policy["status"],
    }


def _validate_cosign_statement(
    statement: dict[str, Any], *, repository: str, digest: str
) -> dict[str, Any]:
    if statement.get("_type") != "https://in-toto.io/Statement/v0.1":
        raise PDDCosignTrustError(
            "Cosign PDD interoperability statement must use Statement v0.1."
        )
    try:
        image_trust.artifact_trust._validate_schema(
            statement, COSIGN_STATEMENT_SCHEMA, "Cosign PDD Statement v0.1 profile"
        )
        canonical_statement = dict(statement)
        canonical_statement["_type"] = "https://in-toto.io/Statement/v1"
        report = _validate_statement_v1(
            canonical_statement, repository=repository, digest=digest
        )
    except Exception as exc:
        raise PDDCosignTrustError(
            f"Verified PDD binding statement is invalid: {exc}"
        ) from exc
    return report


def verify_pdd(
    *,
    pdd_ref: str,
    result_output: Path,
    expected_predicate_path: Path,
    attestation_output: Path | None = None,
    policy_path: Path = POLICY_PATH,
    cosign_binary: str = "cosign",
    runner: Any = None,
    verified_at: datetime | None = None,
) -> dict[str, Any]:
    """Verify PDD signature, Rekor-backed binding attestation and exact predicate."""
    repository, digest = parse_pdd_reference(pdd_ref)
    policy, identity = _load_identity(policy_path)
    command_runner = runner or image_trust.subprocess.run
    image_trust._require_cosign_version(
        runner=command_runner, cosign_binary=cosign_binary
    )
    initial_args = image_trust._workflow_identity_args(policy, identity, "0" * 40)[:-2]
    signature_result = image_trust._run(
        [
            cosign_binary,
            "verify",
            "--output",
            "json",
            *initial_args,
            pdd_ref,
        ],
        runner=command_runner,
    )
    image_trust._parse_signature_output(signature_result.stdout)
    attestation_args = image_trust._workflow_identity_args(policy, identity, "0" * 40)[
        :-2
    ]
    attestation_result = image_trust._run(
        [
            cosign_binary,
            "verify-attestation",
            "--type",
            PREDICATE_TYPE,
            *attestation_args,
            pdd_ref,
        ],
        runner=command_runner,
    )
    statement = image_trust.extract_verified_statement(attestation_result.stdout)
    _validate_cosign_statement(statement, repository=repository, digest=digest)
    expected_predicate = image_trust._strict_json(
        expected_predicate_path, "expected PDD binding predicate"
    )
    if statement["predicate"] != expected_predicate:
        raise PDDCosignTrustError(
            "Verified PDD binding predicate differs from the locally generated predicate."
        )

    source_commit = statement["predicate"]["workflow"]["source_commit"]
    if not re.fullmatch(r"[a-f0-9]{40,64}", source_commit):
        raise PDDCosignTrustError("Verified PDD binding source commit is invalid.")
    exact_args = image_trust._workflow_identity_args(policy, identity, source_commit)
    exact_signature = image_trust._run(
        [
            cosign_binary,
            "verify",
            "--output",
            "json",
            *exact_args,
            pdd_ref,
        ],
        runner=command_runner,
    )
    image_trust._parse_signature_output(exact_signature.stdout)
    exact_attestation = image_trust._run(
        [
            cosign_binary,
            "verify-attestation",
            "--type",
            PREDICATE_TYPE,
            *exact_args,
            pdd_ref,
        ],
        runner=command_runner,
    )
    verified_statement = image_trust.extract_verified_statement(
        exact_attestation.stdout
    )
    if verified_statement != statement:
        raise PDDCosignTrustError(
            "PDD binding attestation changed between verification passes."
        )
    _validate_cosign_statement(verified_statement, repository=repository, digest=digest)
    if attestation_output is not None:
        # Preserve the second verification pass, which includes the exact source-SHA
        # certificate constraint, rather than the preliminary identity-only pass.
        image_trust._atomic_write(
            attestation_output, exact_attestation.stdout.encode("utf-8")
        )

    now = verified_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise PDDCosignTrustError("Verification timestamp must be timezone-aware.")
    predicate_hash = hashlib.sha256(
        image_trust._canonical_json(verified_statement["predicate"])
    ).hexdigest()
    trusted = policy["status"] == "confirmed"
    result = {
        "schema_version": "1.0.0",
        "verification_id": str(uuid.uuid4()),
        "artifact": {
            "kind": "pdd",
            "repository": repository,
            "digest": digest,
            "immutable_reference": pdd_ref,
        },
        "signature": {
            "verified": True,
            "verification_method": "cosign-keyless",
            "signature_reference": pdd_ref,
        },
        "signer": {
            "verified": True,
            "oidc_issuer": policy["issuer"],
            "certificate_identity": identity["certificate_identity"],
            "workflow_ref": identity["workflow_ref"],
        },
        "transparency": {
            "verified": True,
            "log_entry_verified": True,
        },
        "attestations": [
            {
                "predicate_type": PREDICATE_TYPE,
                "verified": True,
                "subject_digest": digest,
                "predicate_sha256": predicate_hash,
            }
        ],
        "decision": {
            "status": "trusted" if trusted else "rejected",
            "reason_codes": [] if trusted else [PROVISIONAL_REASON],
        },
        "verified_at": now.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    try:
        artifact_trust.validate_trust_verification_result(result)
    except Exception as exc:
        raise PDDCosignTrustError(
            f"Normalized PDD trust result is invalid: {exc}"
        ) from exc
    image_trust._atomic_write(result_output, image_trust._canonical_json(result))
    if not trusted:
        raise PDDCosignTrustError(
            "PDD cryptographic verification passed, but signer identity policy is provisional; result is rejected."
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("--pdd-ref", required=True)
    sign_parser.add_argument("--statement", required=True, type=Path)
    sign_parser.add_argument("--predicate", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--pdd-ref", required=True)
    verify_parser.add_argument("--expected-predicate", required=True, type=Path)
    verify_parser.add_argument("--result-output", required=True, type=Path)
    verify_parser.add_argument("--attestation-output", type=Path)
    parser.add_argument("--cosign-bin", default="cosign")
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            result = sign_pdd(
                pdd_ref=args.pdd_ref,
                statement_path=args.statement,
                predicate_path=args.predicate,
                cosign_binary=args.cosign_bin,
            )
        else:
            result = verify_pdd(
                pdd_ref=args.pdd_ref,
                expected_predicate_path=args.expected_predicate,
                result_output=args.result_output,
                attestation_output=args.attestation_output,
                cosign_binary=args.cosign_bin,
            )
    except (PDDCosignTrustError, image_trust.CosignTrustError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
