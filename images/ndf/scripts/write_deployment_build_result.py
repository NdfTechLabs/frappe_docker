#!/usr/bin/env python3
"""Build one immutable, schema-validated terminal result for a candidate run attempt."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


CANDIDATE_REF = re.compile(
    r"^ghcr\\.io/ndftechlabs/dt-master-deployment-candidates@sha256:([a-f0-9]{64})$"
)
HASH = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
SAFE_FAILURES = {
    "dispatch-gate": ("DISPATCH_NOT_AUTHORIZED", "Candidate dispatch authorization failed."),
    "prepare-candidate": ("CANDIDATE_INTAKE_FAILED", "Candidate intake or preparation failed."),
    "build-candidate": ("IMAGE_BUILD_OR_VERIFICATION_FAILED", "Candidate image build or verification failed."),
    "publish-candidate-pdd": ("PDD_PUBLICATION_FAILED", "Candidate descriptor verification or publication failed."),
}


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"Required workflow metadata is missing: {name}")
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    run_id = required_env("GITHUB_RUN_ID")
    run_attempt = int(required_env("GITHUB_RUN_ATTEMPT"))
    candidate_ref = required_env("CANDIDATE_ARTIFACT_REF")
    match = CANDIDATE_REF.fullmatch(candidate_ref)
    if not match:
        raise ValueError("Candidate artifact reference is not the accepted immutable GHCR reference.")
    candidate_digest = f"sha256:{match.group(1)}"
    payload_hash = required_env("CANDIDATE_PAYLOAD_SHA256")
    if not HASH.fullmatch(payload_hash):
        raise ValueError("Candidate payload SHA-256 is invalid.")

    outcomes = {
        "dispatch-gate": required_env("DISPATCH_GATE_RESULT"),
        "prepare-candidate": required_env("PREPARE_RESULT"),
        "build-candidate": required_env("BUILD_RESULT"),
        "publish-candidate-pdd": required_env("PDD_RESULT"),
    }
    all_succeeded = all(value == "success" for value in outcomes.values())
    cancelled = not any(value == "failure" for value in outcomes.values()) and any(
        value == "cancelled" for value in outcomes.values()
    )
    if all_succeeded:
        status = "succeeded"
        failure = None
    elif cancelled:
        status = "cancelled"
        failure = {
            "code": "WORKFLOW_CANCELLED",
            "summary": "Candidate workflow execution was cancelled before completion.",
        }
    else:
        status = "failed"
        failed_stage = next(
            (stage for stage in SAFE_FAILURES if outcomes[stage] == "failure"),
            None,
        )
        code, summary = SAFE_FAILURES.get(
            failed_stage,
            ("RESULT_EVIDENCE_INVALID", "Required candidate result evidence is missing or invalid."),
        )
        failure = {"code": code, "summary": summary}

    source_commit = required_env("GITHUB_SHA")
    run_url = required_env("WORKFLOW_RUN_URL")
    started_at = required_env("WORKFLOW_STARTED_AT")
    result: dict[str, Any] = {
        "schema_version": "1.0.0",
        "result_id": f"ndf-{run_id}-{run_attempt}",
        "candidate_id": required_env("CANDIDATE_ID"),
        "candidate_artifact_ref": candidate_ref,
        "candidate_artifact_digest": candidate_digest,
        "candidate_payload_sha256": payload_hash,
        "workflow": {
            "repository": required_env("GITHUB_REPOSITORY"),
            "workflow_name": required_env("GITHUB_WORKFLOW"),
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_url": run_url,
            "source_commit": source_commit,
        },
        "status": status,
        "started_at": started_at,
        "completed_at": utc_now(),
    }
    correlation_id = os.environ.get("CORRELATION_ID", "")
    if correlation_id:
        result["correlation_id"] = correlation_id

    composition_hash = os.environ.get("COMPOSITION_HASH", "")
    lock_hash = os.environ.get("LOCK_SHA256", "")
    image_digest = os.environ.get("IMAGE_DIGEST", "")
    image_id = os.environ.get("IMAGE_ID", "")
    pdd_ref = os.environ.get("PDD_REFERENCE", "")
    pdd_digest = os.environ.get("PDD_DIGEST", "")
    pdd_content_hash = os.environ.get("PDD_CONTENT_SHA256", "")

    if composition_hash and HASH.fullmatch(composition_hash):
        result["composition_hash"] = composition_hash
    if lock_hash and HASH.fullmatch(lock_hash):
        result["resolved_lock_hash"] = lock_hash
    if image_digest and DIGEST.fullmatch(image_digest) and image_id:
        image_repository = f"ghcr.io/ndftechlabs/{image_id}"
        result["image"] = {
            "repository": image_repository,
            "digest": image_digest,
            "immutable_reference": f"{image_repository}@{image_digest}",
        }
    if pdd_ref and pdd_digest and DIGEST.fullmatch(pdd_digest) and pdd_content_hash and HASH.fullmatch(pdd_content_hash):
        if not pdd_ref.endswith("@" + pdd_digest):
            raise ValueError("PDD reference and digest outputs do not agree.")
        result["descriptor"] = {
            "reference": pdd_ref,
            "digest": pdd_digest,
            "content_hash": pdd_content_hash,
        }

    if status == "succeeded":
        required_success_fields = (
            result.get("composition_hash"),
            result.get("resolved_lock_hash"),
            result.get("image"),
            result.get("descriptor"),
        )
        if not all(required_success_fields):
            result["status"] = "failed"
            result["failure"] = {
                "code": "RESULT_EVIDENCE_INVALID",
                "summary": "Required successful image or descriptor evidence is missing or inconsistent.",
            }
        else:
            result["provenance_ref"] = run_url
    if result["status"] in {"failed", "cancelled"}:
        result["failure"] = failure or {
            "code": "RESULT_EVIDENCE_INVALID",
            "summary": "Required candidate result evidence is missing or invalid.",
        }

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(result),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        details = "; ".join(
            f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"Generated deployment build result violates schema: {details}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError("Refusing to overwrite an existing attempt result.")
    temporary = args.output.with_name(args.output.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError("Refusing to overwrite an existing temporary result.")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
    temporary.replace(args.output)
    print(json.dumps({"result_id": result["result_id"], "status": result["status"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Candidate result generation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
