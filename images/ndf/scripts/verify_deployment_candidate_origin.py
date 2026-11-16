#!/usr/bin/env python3
"""Independently verify DT Master's signed deployment-candidate OCI artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker

try:
    from . import artifact_trust
    from . import cosign_image_trust as cosign
    from . import intake_deployment_candidate as intake
except ImportError:
    import artifact_trust
    import cosign_image_trust as cosign
    import intake_deployment_candidate as intake

NDF_DIR = Path(__file__).resolve().parents[1]
POLICY_PATH = NDF_DIR / "policies" / "dt-master-candidate-origin-identity-policy-v1.json"
POLICY_SCHEMA_PATH = NDF_DIR / "schemas" / "dt-master-candidate-origin-identity-policy-v1.schema.json"
PREDICATE_SCHEMA_PATH = NDF_DIR / "schemas" / "deployment-candidate-origin-predicate-v1.schema.json"
STATEMENT_SCHEMA_PATH = NDF_DIR / "schemas" / "cosign-deployment-candidate-origin-statement-v0.1.schema.json"
RESULT_SCHEMA_PATH = NDF_DIR / "schemas" / "candidate-origin-verification-result-v1.schema.json"
COSIGN_VERSION = "v3.1.4"
PREDICATE_TYPE = "https://ndftechlabs.com/attestations/deployment-candidate/v1"
CANDIDATE_REPOSITORY = "ghcr.io/ndftechlabs/dt-master-deployment-candidates"
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
CANDIDATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,139}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")


class CandidateOriginTrustError(Exception):
    """Raised when candidate origin cannot be independently established."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _strict_json(raw: bytes, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise CandidateOriginTrustError(
                    "PREDICATE_INVALID", f"{label} contains duplicate JSON key {key!r}."
                )
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                CandidateOriginTrustError(
                    "PREDICATE_INVALID", f"{label} contains invalid constant {token}."
                )
            ),
        )
    except CandidateOriginTrustError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID", f"{label} is not valid UTF-8 JSON."
        ) from exc


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _atomic_write(path: Path, raw: bytes) -> None:
    cosign._atomic_write(path, raw)


def _load_policy(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED", f"Unable to read candidate-origin policy: {exc}"
        ) from exc
    policy = _strict_json(raw, "candidate-origin identity policy")
    if not isinstance(policy, dict):
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED", "Candidate-origin policy root must be an object."
        )
    try:
        artifact_trust._validate_schema(
            policy, POLICY_SCHEMA_PATH, "DT Master candidate-origin identity policy"
        )
    except Exception as exc:
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED", f"Candidate-origin identity policy is invalid: {exc}"
        ) from exc
    if policy.get("issuer") != GITHUB_OIDC_ISSUER:
        raise CandidateOriginTrustError(
            "OIDC_ISSUER_REJECTED", "Candidate-origin policy has an unapproved OIDC issuer."
        )
    return policy


def _identity(policy: dict[str, Any]) -> dict[str, Any]:
    if policy["status"] != "confirmed":
        raise CandidateOriginTrustError(
            "IDENTITY_POLICY_PROVISIONAL",
            "DT Master candidate signer identity remains provisional pending live M4.4 certificate observation.",
        )
    identity = policy["identity"]
    required = ("certificate_identity", "workflow_path", "workflow_ref")
    if any(not identity.get(name) for name in required):
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED",
            "Confirmed candidate-origin policy is missing exact workflow identity values.",
        )
    expected_workflow_ref = (
        f"{policy['verification']['required_repository']}/"
        f"{identity['workflow_path']}@{policy['verification']['required_ref']}"
    )
    if identity["workflow_ref"] != expected_workflow_ref:
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED",
            "Configured candidate producer workflow ref does not match its repository, path and approved ref.",
        )
    expected_certificate_identity = (
        f"https://github.com/{policy['verification']['required_repository']}/"
        f"{identity['workflow_path']}@{policy['verification']['required_ref']}"
    )
    if identity["certificate_identity"] != expected_certificate_identity:
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED",
            "Configured Fulcio certificate identity does not match the exact producer workflow identity.",
        )
    if not policy["verification"].get("required_event_name"):
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED",
            "Confirmed candidate-origin policy must pin the observed GitHub Actions event.",
        )
    return identity


def _cosign_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {"issuer": policy["issuer"], "verification": policy["verification"]}


def _validate_statement(
    statement: dict[str, Any],
    *,
    candidate_id: str,
    artifact_reference: str,
    payload_sha256: str,
    correlation_id: str,
    policy: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    try:
        artifact_trust._validate_schema(
            statement, STATEMENT_SCHEMA_PATH, "Cosign candidate-origin Statement v0.1"
        )
        predicate = statement["predicate"]
        artifact_trust._validate_schema(
            predicate, PREDICATE_SCHEMA_PATH, "DT Master candidate-origin predicate"
        )
    except Exception as exc:
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID", f"Candidate-origin Statement or predicate is invalid: {exc}"
        ) from exc

    digest = intake.parse_candidate_reference(artifact_reference)
    subject = statement["subject"][0]
    if subject["name"] != CANDIDATE_REPOSITORY or (
        "sha256:" + subject["digest"]["sha256"]
    ) != digest:
        raise CandidateOriginTrustError(
            "SUBJECT_DIGEST_MISMATCH",
            "Verified attestation subject does not match the exact candidate OCI repository and digest.",
        )

    artifact = predicate["candidate_artifact"]
    if (
        predicate["candidate_id"] != candidate_id
        or artifact["repository"] != CANDIDATE_REPOSITORY
        or artifact["digest"] != digest
        or predicate["candidate_payload_sha256"] != payload_sha256
        or predicate["correlation_id"] != correlation_id
    ):
        raise CandidateOriginTrustError(
            "PAYLOAD_DIGEST_MISMATCH",
            "Signed candidate ID, artifact digest, payload hash or correlation ID differs from dispatch.",
        )

    producer = predicate["producer"]
    if (
        producer["repository"] != policy["verification"]["required_repository"]
        or producer["workflow_path"] != identity["workflow_path"]
        or producer["workflow_ref"] != identity["workflow_ref"]
        or not COMMIT_RE.fullmatch(producer["source_commit"])
    ):
        raise CandidateOriginTrustError(
            "SIGNER_IDENTITY_REJECTED",
            "Signed producer repository, workflow path/ref or source commit differs from the exact identity policy.",
        )
    return predicate


def verify_candidate_origin(
    *,
    candidate_id: str,
    artifact_reference: str,
    payload_sha256: str,
    correlation_id: str,
    policy_path: Path = POLICY_PATH,
    signature_output: Path | None = None,
    attestation_output: Path | None = None,
    cosign_binary: str = "cosign",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Verify the candidate signature and origin attestation for an exact dispatch.

    A provisional identity policy is an explicit rejection. No wildcard identity
    verification is attempted and no candidate payload is parsed in that state.
    """
    if not CANDIDATE_ID_RE.fullmatch(candidate_id or ""):
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID", "Candidate ID violates the shared 140-character contract."
        )
    if not SHA256_RE.fullmatch(payload_sha256 or ""):
        raise CandidateOriginTrustError(
            "PAYLOAD_DIGEST_MISMATCH", "Dispatch payload SHA-256 is invalid."
        )
    try:
        canonical_uuid = str(uuid.UUID(correlation_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID", "Correlation ID must be a canonical lowercase UUID."
        ) from exc
    if canonical_uuid != correlation_id:
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID", "Correlation ID must be a canonical lowercase UUID."
        )

    try:
        digest = intake.parse_candidate_reference(artifact_reference)
    except Exception as exc:
        raise CandidateOriginTrustError(
            "SUBJECT_DIGEST_MISMATCH", f"Candidate artifact reference is invalid: {exc}"
        ) from exc
    policy = _load_policy(policy_path)
    identity = _identity(policy)
    if signature_output is None or attestation_output is None:
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID",
            "Signature-verification and attestation evidence output paths are both required.",
        )
    for output_path in (signature_output, attestation_output):
        if output_path.exists() or output_path.is_symlink():
            raise CandidateOriginTrustError(
                "PREDICATE_INVALID",
                f"Refusing to overwrite existing candidate-origin evidence: {output_path.name}",
            )

    try:
        cosign._require_cosign_version(runner=runner, cosign_binary=cosign_binary)
        cosign_policy = _cosign_policy(policy)
        identity_entry = {
            "certificate_identity": identity["certificate_identity"],
            "workflow_ref": identity["workflow_ref"],
        }
        initial_args = cosign._workflow_identity_args(
            cosign_policy, identity_entry, "0" * 40
        )[:-2]

        signature_first = cosign._run(
            [cosign_binary, "verify", "--output", "json", *initial_args, artifact_reference],
            runner=runner,
        )
        cosign._parse_signature_output(signature_first.stdout)

        attestation_first = cosign._run(
            [
                cosign_binary,
                "verify-attestation",
                "--type",
                PREDICATE_TYPE,
                *initial_args,
                artifact_reference,
            ],
            runner=runner,
        )
        statement = cosign.extract_verified_statement(attestation_first.stdout)
        predicate = _validate_statement(
            statement,
            candidate_id=candidate_id,
            artifact_reference=artifact_reference,
            payload_sha256=payload_sha256,
            correlation_id=correlation_id,
            policy=policy,
            identity=identity,
        )

        exact_args = cosign._workflow_identity_args(
            cosign_policy, identity_entry, predicate["producer"]["source_commit"]
        )
        signature_exact = cosign._run(
            [cosign_binary, "verify", "--output", "json", *exact_args, artifact_reference],
            runner=runner,
        )
        cosign._parse_signature_output(signature_exact.stdout)
        attestation_exact = cosign._run(
            [
                cosign_binary,
                "verify-attestation",
                "--type",
                PREDICATE_TYPE,
                *exact_args,
                artifact_reference,
            ],
            runner=runner,
        )
        verified_statement = cosign.extract_verified_statement(attestation_exact.stdout)
        if verified_statement != statement:
            raise CandidateOriginTrustError(
                "PREDICATE_INVALID",
                "Candidate-origin Statement changed between identity and source-SHA verification passes.",
            )
        _validate_statement(
            verified_statement,
            candidate_id=candidate_id,
            artifact_reference=artifact_reference,
            payload_sha256=payload_sha256,
            correlation_id=correlation_id,
            policy=policy,
            identity=identity,
        )

        signature_bytes = signature_exact.stdout.encode("utf-8")
        attestation_bytes = attestation_exact.stdout.encode("utf-8")
        if signature_output is not None:
            _atomic_write(signature_output, signature_bytes)
        if attestation_output is not None:
            _atomic_write(attestation_output, attestation_bytes)

        evidence = []
        if signature_output is not None:
            evidence.append(
                {
                    "kind": "cosign_signature",
                    "reference": signature_output.name,
                    "sha256": hashlib.sha256(signature_bytes).hexdigest(),
                }
            )
        if attestation_output is not None:
            evidence.append(
                {
                    "kind": "candidate_origin_attestation",
                    "reference": attestation_output.name,
                    "sha256": hashlib.sha256(attestation_bytes).hexdigest(),
                }
            )
        return {
            "schema_version": "1.0.0",
            "decision": "verified",
            "reason_code": "CANDIDATE_ORIGIN_VERIFIED",
            "candidate_id": candidate_id,
            "correlation_id": correlation_id,
            "subject": {"repository": CANDIDATE_REPOSITORY, "digest": digest},
            "payload_sha256": payload_sha256,
            "producer": {
                "repository": predicate["producer"]["repository"],
                "workflow_path": predicate["producer"]["workflow_path"],
                "workflow_ref": predicate["producer"]["workflow_ref"],
                "source_commit": predicate["producer"]["source_commit"],
                "run_id": predicate["workflow_run"]["run_id"],
                "run_attempt": predicate["workflow_run"]["run_attempt"],
            },
            "evidence_references": evidence,
        }
    except CandidateOriginTrustError:
        raise
    except cosign.CosignTrustError as exc:
        message = str(exc)
        lowered = message.lower()
        if any(token in lowered for token in ("rekor", "transparency", "tlog")):
            reason = "REKOR_EVIDENCE_INVALID"
        elif "issuer" in lowered or "oidc" in lowered:
            reason = "OIDC_ISSUER_REJECTED"
        elif any(token in lowered for token in ("identity", "certificate", "workflow")):
            reason = "SIGNER_IDENTITY_REJECTED"
        else:
            reason = "SIGNATURE_INVALID"
        raise CandidateOriginTrustError(reason, message) from exc


def validate_result(result: dict[str, Any]) -> None:
    schema = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(result),
        key=lambda error: (list(map(str, error.absolute_path)), error.message),
    )
    if errors:
        first = errors[0]
        location = ".".join(map(str, first.absolute_path)) or "<root>"
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID",
            f"Candidate-origin verification result violates schema at {location}: {first.message}",
        )


def _write_result(path: Path, result: dict[str, Any]) -> None:
    validate_result(result)
    if path.exists() or path.is_symlink():
        raise CandidateOriginTrustError(
            "PREDICATE_INVALID", "Refusing to overwrite an existing candidate-origin result."
        )
    _atomic_write(path, _canonical_json(result))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--artifact-reference", required=True)
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("--signature-output", type=Path, required=True)
    parser.add_argument("--attestation-output", type=Path, required=True)
    parser.add_argument("--result-output", type=Path, required=True)
    parser.add_argument("--cosign-bin", default="cosign")
    args = parser.parse_args(argv)

    try:
        result = verify_candidate_origin(
            candidate_id=args.candidate_id,
            artifact_reference=args.artifact_reference,
            payload_sha256=args.payload_sha256,
            correlation_id=args.correlation_id,
            policy_path=args.policy,
            signature_output=args.signature_output,
            attestation_output=args.attestation_output,
            cosign_binary=args.cosign_bin,
        )
    except CandidateOriginTrustError as exc:
        digest = ""
        try:
            digest = intake.parse_candidate_reference(args.artifact_reference)
        except Exception:
            digest = None
        result = {
            "schema_version": "1.0.0",
            "decision": "rejected",
            "reason_code": exc.reason_code,
            "candidate_id": args.candidate_id,
            "correlation_id": args.correlation_id,
            "subject": {"repository": CANDIDATE_REPOSITORY, "digest": digest},
            "payload_sha256": args.payload_sha256 if SHA256_RE.fullmatch(args.payload_sha256 or "") else None,
            "producer": None,
            "evidence_references": [],
            "error": str(exc),
        }
        try:
            _write_result(args.result_output, result)
        except Exception as write_error:
            print(json.dumps({"status": "failed", "error": str(write_error)}), file=sys.stderr)
            return 2
        print(json.dumps(result, sort_keys=True))
        return 1

    try:
        _write_result(args.result_output, result)
    except CandidateOriginTrustError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
