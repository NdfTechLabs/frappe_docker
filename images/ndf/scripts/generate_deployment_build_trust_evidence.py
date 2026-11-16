#!/usr/bin/env python3
"""Generate the NDF-owned companion trust-evidence report for one build attempt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

NDF_REPOSITORY = "NdfTechLabs/frappe_docker"
CANDIDATE_REPOSITORY = "ghcr.io/ndftechlabs/dt-master-deployment-candidates"
RESULT_FILENAME = "deployment-build-result.json"
NOT_EVALUATED_REASON = "NOT_EVALUATED"
REASON_CODES = {
    "CANDIDATE_ORIGIN_VERIFIED",
    "IDENTITY_POLICY_PROVISIONAL",
    "SIGNATURE_INVALID",
    "SIGNER_IDENTITY_REJECTED",
    "OIDC_ISSUER_REJECTED",
    "REKOR_EVIDENCE_INVALID",
    "SUBJECT_DIGEST_MISMATCH",
    "PREDICATE_INVALID",
    "PAYLOAD_DIGEST_MISMATCH",
}
CANDIDATE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,139}$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


class TrustEvidenceError(Exception):
    """Raised when report inputs or their integrity bindings are invalid."""


def _strict_json(raw: bytes, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise TrustEvidenceError(
                    f"{label} contains duplicate JSON key {key!r}."
                )
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                TrustEvidenceError(f"{label} contains invalid constant {token}.")
            ),
        )
    except TrustEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustEvidenceError(f"{label} is not valid UTF-8 JSON.") from exc


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TrustEvidenceError(f"Unable to read {label}: {exc}") from exc
    value = _strict_json(raw, label)
    if not isinstance(value, dict):
        raise TrustEvidenceError(f"{label} root must be a JSON object.")
    return value, raw


def _validate_schema(value: dict[str, Any], path: Path, label: str) -> None:
    try:
        schema = _strict_json(path.read_bytes(), f"{label} schema")
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
                value
            ),
            key=lambda error: (
                tuple(map(str, error.absolute_path)),
                error.message,
            ),
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustEvidenceError(f"Unable to load {label} schema: {exc}") from exc
    if errors:
        first = errors[0]
        location = ".".join(map(str, first.absolute_path)) or "<root>"
        raise TrustEvidenceError(
            f"{label} violates schema at {location}: {first.message}"
        )


def _safe_evidence_file(root: Path, reference: str) -> Path:
    relative = Path(reference)
    if (
        not reference
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise TrustEvidenceError(
            f"Evidence reference is not a safe relative path: {reference!r}."
        )
    if root.is_symlink():
        raise TrustEvidenceError(
            "Candidate-origin evidence directory must not be a symlink."
        )
    root_resolved = root.resolve(strict=True)
    candidate = root / relative
    if candidate.is_symlink():
        raise TrustEvidenceError(f"Evidence file is a symlink: {reference}.")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise TrustEvidenceError(
            f"Evidence file is missing or escapes its evidence directory: {reference}."
        ) from exc
    if not resolved.is_file():
        raise TrustEvidenceError(
            f"Evidence reference is not a regular file: {reference}."
        )
    return resolved


def _verified_origin_evidence(
    origin: dict[str, Any], evidence_root: Path
) -> list[dict[str, str]]:
    references = origin.get("evidence_references")
    if not isinstance(references, list):
        raise TrustEvidenceError(
            "Candidate-origin evidence_references must be an array."
        )
    validated: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in references:
        if not isinstance(item, dict):
            raise TrustEvidenceError(
                "Candidate-origin evidence reference must be an object."
            )
        reference = item.get("reference")
        expected_hash = item.get("sha256")
        kind = item.get("kind")
        if not isinstance(reference, str) or not isinstance(expected_hash, str):
            raise TrustEvidenceError(
                "Candidate-origin evidence reference is incomplete."
            )
        if kind not in {"cosign_signature", "candidate_origin_attestation"}:
            raise TrustEvidenceError(
                f"Unsupported candidate-origin evidence kind: {kind!r}."
            )
        if reference in seen:
            raise TrustEvidenceError(
                f"Duplicate candidate-origin evidence reference: {reference}."
            )
        seen.add(reference)
        if not HASH_PATTERN.fullmatch(expected_hash):
            raise TrustEvidenceError(f"Invalid evidence SHA-256 for {reference}.")
        evidence_path = _safe_evidence_file(evidence_root, reference)
        actual_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise TrustEvidenceError(f"Evidence SHA-256 mismatch for {reference}.")
        validated.append({"kind": kind, "reference": reference, "sha256": actual_hash})
    return validated


def generate_report(
    *,
    result_path: Path,
    origin_result_path: Path | None,
    origin_evidence_dir: Path,
    schema_path: Path,
) -> dict[str, Any]:
    if result_path.name != RESULT_FILENAME:
        raise TrustEvidenceError(
            f"Terminal result filename must be exactly {RESULT_FILENAME}."
        )
    if result_path.is_symlink():
        raise TrustEvidenceError("Terminal result must not be a symlink.")
    result, result_bytes = _read_json(result_path, "deployment build result")
    _validate_schema(
        result,
        schema_path.with_name("deployment-build-result-v1.schema.json"),
        "deployment build result",
    )

    candidate_id = result.get("candidate_id")
    correlation_id = result.get("correlation_id")
    candidate_digest = result.get("candidate_artifact_digest")
    payload_sha256 = result.get("candidate_payload_sha256")
    workflow = result.get("workflow")
    if not isinstance(candidate_id, str) or not CANDIDATE_ID_PATTERN.fullmatch(
        candidate_id
    ):
        raise TrustEvidenceError("Terminal result has an invalid candidate ID.")
    if not isinstance(correlation_id, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        correlation_id,
    ):
        raise TrustEvidenceError(
            "Terminal result has a missing or noncanonical correlation UUID."
        )
    if not isinstance(candidate_digest, str) or not DIGEST_PATTERN.fullmatch(
        candidate_digest
    ):
        raise TrustEvidenceError(
            "Terminal result has an invalid candidate artifact digest."
        )
    expected_candidate_ref = f"{CANDIDATE_REPOSITORY}@{candidate_digest}"
    if result.get("candidate_artifact_ref") != expected_candidate_ref:
        raise TrustEvidenceError(
            "Terminal result candidate artifact reference and digest do not agree."
        )
    if not isinstance(payload_sha256, str) or not HASH_PATTERN.fullmatch(
        payload_sha256
    ):
        raise TrustEvidenceError(
            "Terminal result has an invalid candidate payload SHA-256."
        )
    if not isinstance(workflow, dict):
        raise TrustEvidenceError("Terminal result workflow metadata is missing.")
    run_id = workflow.get("run_id")
    attempt = workflow.get("run_attempt")
    source_commit = workflow.get("source_commit")
    if (
        not isinstance(run_id, str)
        or not run_id.isdigit()
        or not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
        or not isinstance(source_commit, str)
        or not re.fullmatch(r"[a-f0-9]{40,64}", source_commit)
    ):
        raise TrustEvidenceError("Terminal result workflow identity is invalid.")
    if result.get("result_id") != f"ndf-{run_id}-{attempt}":
        raise TrustEvidenceError(
            "Terminal result ID does not match its run ID and attempt."
        )

    if origin_result_path is None or not origin_result_path.exists():
        origin = None
    else:
        if origin_result_path.is_symlink():
            raise TrustEvidenceError("Candidate-origin result must not be a symlink.")
        origin, _ = _read_json(
            origin_result_path, "candidate-origin verification result"
        )
        origin_schema = schema_path.with_name(
            "candidate-origin-verification-result-v1.schema.json"
        )
        _validate_schema(origin, origin_schema, "candidate-origin verification result")

    if origin is None:
        decision = "not_evaluated"
        reason_code = NOT_EVALUATED_REASON
        evidence_references: list[dict[str, str]] = []
        subject_digest = candidate_digest
        origin_payload_hash = payload_sha256
    else:
        if origin.get("candidate_id") != candidate_id:
            raise TrustEvidenceError(
                "Candidate-origin result candidate ID differs from terminal result."
            )
        if origin.get("correlation_id") != correlation_id:
            raise TrustEvidenceError(
                "Candidate-origin result correlation ID differs from terminal result."
            )
        subject = origin.get("subject")
        if (
            not isinstance(subject, dict)
            or subject.get("repository") != CANDIDATE_REPOSITORY
        ):
            raise TrustEvidenceError(
                "Candidate-origin result subject repository is invalid."
            )
        subject_digest = subject.get("digest") or candidate_digest
        origin_payload_hash = origin.get("payload_sha256") or payload_sha256
        if subject_digest != candidate_digest:
            raise TrustEvidenceError(
                "Candidate-origin subject digest differs from terminal result."
            )
        if origin_payload_hash != payload_sha256:
            raise TrustEvidenceError(
                "Candidate-origin payload SHA-256 differs from terminal result."
            )
        decision = origin.get("decision")
        reason_code = origin.get("reason_code")
        if decision not in {"verified", "rejected"}:
            raise TrustEvidenceError("Candidate-origin decision is not supported.")
        if reason_code not in REASON_CODES:
            raise TrustEvidenceError("Candidate-origin reason code is not supported.")
        if decision == "verified" and reason_code != "CANDIDATE_ORIGIN_VERIFIED":
            raise TrustEvidenceError(
                "Verified candidate origin must use CANDIDATE_ORIGIN_VERIFIED."
            )
        if decision == "rejected" and reason_code == "CANDIDATE_ORIGIN_VERIFIED":
            raise TrustEvidenceError(
                "Rejected candidate origin cannot use the verified reason code."
            )
        evidence_references = _verified_origin_evidence(origin, origin_evidence_dir)
        if decision == "verified":
            kinds = {item["kind"] for item in evidence_references}
            if kinds != {"cosign_signature", "candidate_origin_attestation"}:
                raise TrustEvidenceError(
                    "Verified candidate origin requires signature and attestation evidence."
                )
        elif evidence_references:
            raise TrustEvidenceError(
                "Rejected candidate origin must not be represented with successful verification evidence."
            )

    report = {
        "schema_version": "1.0.0",
        "report_id": f"ndf-{run_id}-{attempt}-trust",
        "candidate_id": candidate_id,
        "correlation_id": correlation_id,
        "result_binding": {
            "result_id": result.get("result_id"),
            "result_file": RESULT_FILENAME,
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        },
        "workflow": {
            "repository": NDF_REPOSITORY,
            "run_id": run_id,
            "run_attempt": attempt,
            "source_commit": source_commit,
        },
        "candidate_origin": {
            "verifier": "NDF",
            "decision": decision,
            "reason_code": reason_code,
            "subject": {
                "repository": CANDIDATE_REPOSITORY,
                "digest": subject_digest,
            },
            "payload_sha256": origin_payload_hash,
            "evidence_references": evidence_references,
        },
    }
    _validate_schema(report, schema_path, "deployment build trust-evidence report")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--origin-result", type=Path)
    parser.add_argument("--origin-evidence-dir", type=Path, required=True)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        report = generate_report(
            result_path=args.result,
            origin_result_path=args.origin_result,
            origin_evidence_dir=args.origin_evidence_dir,
            schema_path=args.schema,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists() or args.output.is_symlink():
            raise TrustEvidenceError(
                "Refusing to overwrite an existing trust-evidence report."
            )
        temporary = args.output.with_name(args.output.name + ".tmp")
        if temporary.exists() or temporary.is_symlink():
            raise TrustEvidenceError(
                "Refusing to overwrite an existing temporary report."
            )
        encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        temporary.write_bytes(encoded)
        os.replace(temporary, args.output)
        print(
            json.dumps(
                {
                    "report_id": report["report_id"],
                    "decision": report["candidate_origin"]["decision"],
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, TrustEvidenceError, json.JSONDecodeError) as exc:
        print(f"Trust-evidence report generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
