#!/usr/bin/env python3
"""Correlate and seal the evidence produced by an NDF PDD publication run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    from . import artifact_trust, cosign_image_trust, cosign_pdd_trust
except ImportError:
    import artifact_trust
    import cosign_image_trust
    import cosign_pdd_trust

NDF_DIR = Path(__file__).resolve().parents[1]
RECEIPT_SCHEMA = NDF_DIR / "schemas" / "pdd-publication-record-v1.schema.json"
BINDING_SCHEMA = NDF_DIR / "schemas" / "pdd-image-binding-v1.schema.json"
TRUST_RESULT_SCHEMA = (
    NDF_DIR / "schemas" / "artifact-trust-verification-result-v1.schema.json"
)
MANIFEST_SCHEMA = NDF_DIR / "schemas" / "pdd-trust-evidence-manifest-v1.schema.json"
MANIFEST_NAME = "pdd-trust-evidence-manifest.json"
COSIGN_VERSION = "v3.1.4"
EXPECTED_PROVISIONAL_MESSAGE = (
    "PDD cryptographic verification passed, but signer identity policy is provisional; "
    "result is rejected."
)
REQUIRED_FILES = (
    "pdd-publication-record.json",
    "pdd-image-binding-statement.json",
    "pdd-image-binding-predicate.json",
    "pdd-trust-verification-result.json",
    "pdd-verified-attestation.json",
    "pdd-verify.log",
)
SIGNING_INPUT_RE = re.compile(
    r"^ndf-pdd-signing-input-(?P<build_run>[0-9]+)-(?P<publication_attempt>[1-9][0-9]*)$"
)


class PDDTrustEvidenceError(Exception):
    """Raised when PDD publication trust evidence is incomplete or inconsistent."""


def _strict_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PDDTrustEvidenceError(f"{label} is missing or unsafe: {path}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PDDTrustEvidenceError(
                    f"{label} contains duplicate JSON key: {key}"
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise PDDTrustEvidenceError(f"{label} contains non-finite JSON value: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PDDTrustEvidenceError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise PDDTrustEvidenceError(f"{label} must be a JSON object.")
    return value


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    try:
        from jsonschema import Draft202012Validator

        schema = _strict_json(schema_path, f"{label} schema")
        Draft202012Validator(
            schema, format_checker=Draft202012Validator.FORMAT_CHECKER
        ).validate(value)
    except Exception as exc:
        raise PDDTrustEvidenceError(f"{label} schema validation failed: {exc}") from exc


def _read_nonempty(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PDDTrustEvidenceError(f"{label} is missing or unsafe: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PDDTrustEvidenceError(f"Unable to read {label}: {exc}") from exc
    if not raw:
        raise PDDTrustEvidenceError(f"{label} must not be empty.")
    return raw


def _verify_attestation(raw: bytes, statement_v1: dict[str, Any]) -> None:
    try:
        verified = cosign_image_trust.extract_verified_statement(raw.decode("utf-8"))
    except Exception as exc:
        raise PDDTrustEvidenceError(
            f"Raw verified Cosign attestation output is invalid: {exc}"
        ) from exc
    if verified.get("_type") != "https://in-toto.io/Statement/v0.1":
        raise PDDTrustEvidenceError("Verified Cosign envelope is not Statement v0.1.")
    normalized = dict(verified)
    normalized["_type"] = "https://in-toto.io/Statement/v1"
    if normalized != statement_v1:
        raise PDDTrustEvidenceError(
            "Raw verified Cosign attestation does not match the published Statement."
        )


def _runtime_context(env: dict[str, str]) -> dict[str, Any]:
    required = (
        "GITHUB_ACTIONS",
        "GITHUB_REPOSITORY",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_REF",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
    )
    missing = [name for name in required if not env.get(name)]
    if missing or env.get("GITHUB_ACTIONS", "").lower() != "true":
        raise PDDTrustEvidenceError(
            f"GitHub Actions runtime context is missing or invalid: {', '.join(missing)}"
        )
    if (
        env["GITHUB_REPOSITORY"] != "NdfTechLabs/frappe_docker"
        or env["GITHUB_WORKFLOW_REF"] != cosign_pdd_trust.WORKFLOW_REF
        or env["GITHUB_REF"] != "refs/heads/main"
    ):
        raise PDDTrustEvidenceError("Evidence is outside the approved PDD workflow.")
    if not re.fullmatch(r"[0-9]+", env["GITHUB_RUN_ID"]):
        raise PDDTrustEvidenceError("Publication run ID is invalid.")
    if not re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_ATTEMPT"]):
        raise PDDTrustEvidenceError("Publication run attempt is invalid.")
    source_commit = env["GITHUB_SHA"].lower()
    if not re.fullmatch(r"[a-f0-9]{40,64}", source_commit):
        raise PDDTrustEvidenceError("Publication source commit is invalid.")
    return {
        "repository": env["GITHUB_REPOSITORY"],
        "path": cosign_pdd_trust.WORKFLOW_PATH,
        "ref": env["GITHUB_REF"],
        "source_commit": source_commit,
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]),
    }


def correlate_evidence(
    *,
    evidence_dir: Path,
    source_build_run_id: str,
    source_build_attempt: int,
    signing_input_artifact: str,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate all evidence relationships and atomically write the manifest."""
    root = evidence_dir.resolve(strict=True)
    if evidence_dir.is_symlink() or not root.is_dir():
        raise PDDTrustEvidenceError("Evidence directory must be a real directory.")
    manifest_output = root / MANIFEST_NAME
    if manifest_output.is_symlink():
        raise PDDTrustEvidenceError(
            "Unable to atomically write the PDD evidence manifest: output is a symlink."
        )
    if not re.fullmatch(r"[0-9]+", source_build_run_id):
        raise PDDTrustEvidenceError("Source build run ID is invalid.")
    if (
        isinstance(source_build_attempt, bool)
        or not isinstance(source_build_attempt, int)
        or source_build_attempt < 1
    ):
        raise PDDTrustEvidenceError("Source build attempt must be a positive integer.")
    artifact_match = SIGNING_INPUT_RE.fullmatch(signing_input_artifact)
    if (
        artifact_match is None
        or artifact_match.group("build_run") != source_build_run_id
    ):
        raise PDDTrustEvidenceError(
            "Signing-input artifact name does not match the source build run."
        )

    expected_entries = set(REQUIRED_FILES)
    actual_entries = {item.name for item in root.iterdir()}
    if actual_entries != expected_entries:
        missing = sorted(expected_entries - actual_entries)
        unexpected = sorted(actual_entries - expected_entries)
        raise PDDTrustEvidenceError(
            f"Evidence directory inventory mismatch; missing={missing}, unexpected={unexpected}."
        )
    for filename in REQUIRED_FILES:
        _read_nonempty(root / filename, filename)

    receipt = _strict_json(root / "pdd-publication-record.json", "PDD publication receipt")
    statement = _strict_json(
        root / "pdd-image-binding-statement.json", "PDD binding Statement"
    )
    predicate = _strict_json(
        root / "pdd-image-binding-predicate.json", "PDD binding predicate"
    )
    result = _strict_json(
        root / "pdd-trust-verification-result.json", "PDD trust verification result"
    )
    _validate(receipt, RECEIPT_SCHEMA, "PDD publication receipt")
    _validate(statement, BINDING_SCHEMA, "PDD binding Statement")
    _validate(result, TRUST_RESULT_SCHEMA, "PDD trust verification result")

    artifact = receipt["artifact"]
    immutable_reference = f"{artifact['repository']}@{artifact['digest']}"
    if artifact["immutable_reference"] != immutable_reference:
        raise PDDTrustEvidenceError("Receipt immutable reference is inconsistent.")
    if statement["subject"][0]["name"] != artifact["repository"]:
        raise PDDTrustEvidenceError("Statement subject repository differs from receipt.")
    statement_digest = "sha256:" + statement["subject"][0]["digest"]["sha256"]
    if statement_digest != artifact["digest"]:
        raise PDDTrustEvidenceError("Statement subject digest differs from receipt.")
    if statement["predicate"] != predicate:
        raise PDDTrustEvidenceError("Predicate file differs from Statement predicate.")
    if cosign_image_trust._canonical_json(statement["predicate"]) != (
        cosign_image_trust._canonical_json(predicate)
    ):
        raise PDDTrustEvidenceError("Canonical predicate bytes do not match.")
    if predicate["descriptor"]["id"] != receipt["descriptor"]["id"]:
        raise PDDTrustEvidenceError("PDD descriptor ID differs between receipt and predicate.")
    if predicate["descriptor"]["content_sha256"] != receipt["descriptor"]["content_sha256"]:
        raise PDDTrustEvidenceError("PDD content hash differs between receipt and predicate.")
    if predicate["subject_image"] != receipt["subject_image"]:
        raise PDDTrustEvidenceError("Subject image claims differ between receipt and predicate.")

    result_artifact = result["artifact"]
    if (
        result_artifact["kind"] != "pdd"
        or result_artifact["repository"] != artifact["repository"]
        or result_artifact["digest"] != artifact["digest"]
        or result_artifact["immutable_reference"] != immutable_reference
    ):
        raise PDDTrustEvidenceError("Trust result does not identify the receipt's PDD.")
    if (
        result["signature"]["verified"] is not True
        or result["signer"]["verified"] is not True
        or result["transparency"]["verified"] is not True
        or result["transparency"]["log_entry_verified"] is not True
    ):
        raise PDDTrustEvidenceError("Cryptographic signature, signer or Rekor checks failed.")
    attestations = result["attestations"]
    if len(attestations) != 1:
        raise PDDTrustEvidenceError("Exactly one verified PDD binding attestation is required.")
    attestation = attestations[0]
    predicate_hash = hashlib.sha256(
        cosign_image_trust._canonical_json(predicate)
    ).hexdigest()
    if (
        attestation["predicate_type"] != cosign_pdd_trust.PREDICATE_TYPE
        or attestation["verified"] is not True
        or attestation["subject_digest"] != artifact["digest"]
        or attestation.get("predicate_sha256") != predicate_hash
    ):
        raise PDDTrustEvidenceError("Verified attestation does not match the PDD predicate.")
    expected_decision = {
        "status": "rejected",
        "reason_codes": [cosign_pdd_trust.PROVISIONAL_REASON],
    }
    if result["decision"] != expected_decision:
        raise PDDTrustEvidenceError("Trust decision is not the exact provisional-policy rejection.")

    log_raw = (root / "pdd-verify.log").read_bytes()
    if EXPECTED_PROVISIONAL_MESSAGE.encode("utf-8") not in log_raw:
        raise PDDTrustEvidenceError("Verifier log lacks the exact provisional rejection.")
    attestation_raw = (root / "pdd-verified-attestation.json").read_bytes()
    _verify_attestation(attestation_raw, statement)

    runtime = _runtime_context(dict(os.environ if env is None else env))
    if statement["predicate"]["workflow"] != {
        "repository": runtime["repository"],
        "path": runtime["path"],
        "ref": runtime["ref"],
        "run_id": runtime["run_id"],
        "run_attempt": runtime["run_attempt"],
        "source_commit": runtime["source_commit"],
    }:
        raise PDDTrustEvidenceError(
            "Statement workflow claims do not match the publication workflow runtime."
        )
    if artifact_match.group("publication_attempt") != str(runtime["run_attempt"]):
        raise PDDTrustEvidenceError(
            "Signing-input artifact attempt does not match publication workflow attempt."
        )
    if result["verified_at"] == "":
        raise PDDTrustEvidenceError("Trust verification timestamp is empty.")

    files: dict[str, dict[str, Any]] = {}
    for filename in REQUIRED_FILES:
        raw = _read_nonempty(root / filename, filename)
        files[filename] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }

    manifest = {
        "schema_version": "1.0.0",
        "evidence_kind": "pdd-publication-trust",
        "publication_workflow": runtime,
        "source_build": {
            "run_id": source_build_run_id,
            "run_attempt": source_build_attempt,
            "signing_input_artifact": signing_input_artifact,
        },
        "artifact": {
            "descriptor_id": receipt["descriptor"]["id"],
            "repository": artifact["repository"],
            "digest": artifact["digest"],
            "immutable_reference": immutable_reference,
        },
        "verification": {
            "verification_id": result["verification_id"],
            "cosign_version": COSIGN_VERSION,
            "verified_at": result["verified_at"],
            "decision": result["decision"]["status"],
            "reason_codes": result["decision"]["reason_codes"],
        },
        "files": files,
    }
    _validate(manifest, MANIFEST_SCHEMA, "PDD trust evidence manifest")
    try:
        cosign_image_trust._atomic_write(
            root / MANIFEST_NAME, cosign_image_trust._canonical_json(manifest)
        )
    except (OSError, cosign_image_trust.CosignTrustError) as exc:
        raise PDDTrustEvidenceError(
            f"Unable to atomically write the PDD evidence manifest: {exc}"
        ) from exc
    return manifest


def verify_evidence_manifest(evidence_dir: Path) -> dict[str, Any]:
    """Recompute every evidence-file digest against the durable manifest."""
    root = evidence_dir.resolve(strict=True)
    if evidence_dir.is_symlink() or not root.is_dir():
        raise PDDTrustEvidenceError("Evidence directory must be a real directory.")
    manifest = _strict_json(root / MANIFEST_NAME, "PDD trust evidence manifest")
    _validate(manifest, MANIFEST_SCHEMA, "PDD trust evidence manifest")
    if set(manifest["files"]) != set(REQUIRED_FILES):
        raise PDDTrustEvidenceError("Evidence manifest file inventory is incomplete or unexpected.")
    expected_entries = set(REQUIRED_FILES) | {MANIFEST_NAME}
    actual_entries = {item.name for item in root.iterdir()}
    if actual_entries != expected_entries:
        raise PDDTrustEvidenceError("Evidence directory contains missing or unexpected files.")
    for filename, expected in manifest["files"].items():
        raw = _read_nonempty(root / filename, filename)
        if len(raw) != expected["size_bytes"]:
            raise PDDTrustEvidenceError(f"Evidence file size changed after manifest creation: {filename}")
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != expected["sha256"]:
            raise PDDTrustEvidenceError(f"Evidence file hash changed after manifest creation: {filename}")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--source-build-run-id")
    parser.add_argument("--source-build-attempt", type=int)
    parser.add_argument("--signing-input-artifact")
    parser.add_argument("--verify-manifest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.verify_manifest:
            manifest = verify_evidence_manifest(args.evidence_dir)
            print(json.dumps({"status": "passed", "manifest": str(args.evidence_dir / MANIFEST_NAME)}, sort_keys=True))
            return 0
        if (
            args.source_build_run_id is None
            or args.source_build_attempt is None
            or args.signing_input_artifact is None
        ):
            parser.error(
                "correlation requires --source-build-run-id, --source-build-attempt "
                "and --signing-input-artifact"
            )
        manifest = correlate_evidence(
            evidence_dir=args.evidence_dir,
            source_build_run_id=args.source_build_run_id,
            source_build_attempt=args.source_build_attempt,
            signing_input_artifact=args.signing_input_artifact,
        )
    except (PDDTrustEvidenceError, OSError, cosign_image_trust.CosignTrustError) as exc:
        print(f"PDD trust evidence correlation failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "passed",
                "immutable_reference": manifest["artifact"]["immutable_reference"],
                "decision": manifest["verification"]["decision"],
                "reason_codes": manifest["verification"]["reason_codes"],
                "manifest": str(args.evidence_dir / MANIFEST_NAME),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
