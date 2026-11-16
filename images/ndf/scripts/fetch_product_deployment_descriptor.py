#!/usr/bin/env python3
"""Fetch and verify a digest-pinned PDD OCI artifact for a deployment consumer."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

try:
    from . import artifact_trust, cosign_image_trust, cosign_pdd_trust
    from .publish_product_deployment_descriptor import (
        ARTIFACT_TYPE,
        PDD_MEDIA_TYPE,
        SIDECARS,
    )
    from .validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )
    from .verify_product_deployment_binding import (
        ProductDeploymentBindingError,
        verify_product_deployment_binding,
    )
except ImportError:
    import artifact_trust
    import cosign_image_trust
    import cosign_pdd_trust
    from publish_product_deployment_descriptor import (
        ARTIFACT_TYPE,
        PDD_MEDIA_TYPE,
        SIDECARS,
    )
    from validate_product_deployment_descriptor import (
        DescriptorValidationError,
        validate_descriptor,
    )
    from verify_product_deployment_binding import (
        ProductDeploymentBindingError,
        verify_product_deployment_binding,
    )

NDF_DIR = Path(__file__).resolve().parents[1]
PUBLICATION_SCHEMA = NDF_DIR / "schemas" / "pdd-publication-record-v1.schema.json"
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
CONSUMER_REPORT_SCHEMA = NDF_DIR / "schemas" / "pdd-consumer-verification-report-v1.schema.json"
TRUST_RESULT_SCHEMA = NDF_DIR / "schemas" / "artifact-trust-verification-result-v1.schema.json"
PROVISIONAL_POLICY_STATUS = "provisional_until_live_certificate_observation"
PROVISIONAL_REASON = "IDENTITY_POLICY_PROVISIONAL"


class PDDRetrievalError(Exception):
    """Raised when a published PDD cannot be safely retrieved or verified."""


def _run(
    command: list[str], *, timeout: int = 300
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command, check=False, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise PDDRetrievalError(f"Command timed out: {command[0]}") from exc
    except OSError as exc:
        raise PDDRetrievalError(f"Unable to execute {command[0]}: {exc}") from exc


def _json_output(
    result: subprocess.CompletedProcess[bytes], label: str
) -> dict[str, Any]:
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PDDRetrievalError(f"{label} failed: {detail or result.returncode}")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PDDRetrievalError(f"{label} returned invalid JSON.") from exc
    if not isinstance(value, dict):
        raise PDDRetrievalError(f"{label} must return a JSON object.")
    return value


def _load_receipt(path: Path) -> dict[str, Any]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        schema = json.loads(PUBLICATION_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise PDDRetrievalError(f"Invalid publication receipt: {exc}") from exc
    if not isinstance(receipt, dict):
        raise PDDRetrievalError("Publication receipt must be a JSON object.")
    return receipt


def fetch_product_deployment_descriptor(
    publication_record: Path,
    output_dir: Path,
    *,
    oras_bin: str = "oras",
    docker_bin: str = "docker",
    verify_image_binding: bool = True,
    cosign_bin: str = "cosign",
) -> dict[str, Any]:
    receipt = _load_receipt(publication_record)
    artifact = receipt["artifact"]
    reference = artifact["immutable_reference"]
    repository = artifact["repository"]
    digest = artifact["digest"]
    subject = receipt["subject_image"]
    expected_locator = (
        f"pdd-v1-{subject['platform'].replace('/', '-')}-"
        f"{subject['digest'].removeprefix('sha256:')}"
    )
    if (
        not SHA256_RE.fullmatch(digest)
        or reference != f"{repository}@{digest}"
        or repository != subject["repository"]
        or artifact["locator_tag"] != expected_locator
    ):
        raise PDDRetrievalError(
            "Publication receipt does not contain a consistent digest-pinned artifact reference and locator."
        )

    manifest = _json_output(
        _run(
            [oras_bin, "manifest", "fetch", "--format", "json", reference], timeout=120
        ),
        "ORAS manifest fetch",
    )
    if manifest.get("digest") != digest:
        raise PDDRetrievalError(
            "Registry manifest digest differs from the publication receipt."
        )
    manifest_content = manifest.get("content", {})
    if manifest_content.get("artifactType") != ARTIFACT_TYPE:
        raise PDDRetrievalError("Registry artifact type is not the NDF PDD contract.")
    layers = manifest_content.get("layers", [])
    if not any(
        isinstance(layer, dict) and layer.get("mediaType") == PDD_MEDIA_TYPE
        for layer in layers
    ):
        raise PDDRetrievalError(
            "Registry artifact does not contain the required PDD media type layer."
        )
    annotations = manifest_content.get("annotations", {})
    descriptor_record = receipt["descriptor"]
    expected_annotations = {
        "io.ndf.pdd.descriptor-id": descriptor_record["id"],
        "io.ndf.pdd.content-sha256": descriptor_record["content_sha256"],
        "io.ndf.pdd.subject-image-digest": receipt["subject_image"]["digest"],
        "io.ndf.pdd.schema-version": descriptor_record["schema_version"],
    }
    if any(
        annotations.get(key) != value for key, value in expected_annotations.items()
    ):
        raise PDDRetrievalError(
            "Registry artifact annotations disagree with the publication receipt."
        )

    if output_dir.is_symlink():
        raise PDDRetrievalError("Output directory must not be a symlink.")
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise PDDRetrievalError(
            "Output directory must be empty to prevent mixing artifact contents."
        )
    with tempfile.TemporaryDirectory(prefix="ndf-pdd-fetch-") as temp:
        pulled_dir = Path(temp)
        pull_result = _json_output(
            _run(
                [
                    oras_bin,
                    "pull",
                    "--format",
                    "json",
                    "--output",
                    str(pulled_dir),
                    reference,
                ],
                timeout=300,
            ),
            "ORAS artifact pull",
        )
        if pull_result.get("reference") != reference:
            raise PDDRetrievalError(
                "ORAS pull returned a different artifact reference."
            )

        pdd_path = pulled_dir / "product-deployment.json"
        binding_path = pulled_dir / "binding-verification.json"
        if not pdd_path.is_file() or pdd_path.is_symlink():
            raise PDDRetrievalError(
                "Published artifact is missing product-deployment.json."
            )
        if not binding_path.is_file() or binding_path.is_symlink():
            raise PDDRetrievalError(
                "Published artifact is missing binding-verification.json."
            )
        pulled_files = []
        for path in pulled_dir.rglob("*"):
            if path.is_symlink():
                raise PDDRetrievalError("Published artifact contains a symlink.")
            if path.is_file():
                pulled_files.append(path)
        if len(pulled_files) != receipt["evidence"]["published_file_count"]:
            raise PDDRetrievalError(
                "Published artifact file count differs from the publication receipt."
            )
        binding_sha = hashlib.sha256(binding_path.read_bytes()).hexdigest()
        if binding_sha != receipt["evidence"]["binding_report_sha256"]:
            raise PDDRetrievalError(
                "Binding report bytes differ from the publication receipt."
            )

        try:
            validated = validate_descriptor(pdd_path)
        except DescriptorValidationError as exc:
            raise PDDRetrievalError(
                f"Independent PDD validation failed: {exc}"
            ) from exc
        if validated["descriptor_id"] != descriptor_record["id"]:
            raise PDDRetrievalError(
                "Retrieved PDD descriptor identity differs from the publication receipt."
            )
        if validated["content_sha256"] != descriptor_record["content_sha256"]:
            raise PDDRetrievalError(
                "Retrieved PDD content hash differs from the publication receipt."
            )
        if validated["image_digest"] != receipt["subject_image"]["digest"]:
            raise PDDRetrievalError(
                "Retrieved PDD image digest differs from the publication receipt."
            )
        try:
            descriptor = json.loads(pdd_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PDDRetrievalError(f"Unable to read retrieved PDD: {exc}") from exc
        subject = receipt["subject_image"]
        if (
            descriptor.get("artifact", {}).get("repository") != subject["repository"]
            or descriptor.get("artifact", {}).get("digest") != subject["digest"]
            or descriptor.get("artifact", {}).get("platform") != subject["platform"]
        ):
            raise PDDRetrievalError(
                "Retrieved PDD image repository/digest/platform differs from the publication receipt."
            )
        if validated["schema_version"] != descriptor_record["schema_version"]:
            raise PDDRetrievalError(
                "Retrieved PDD schema version differs from the publication receipt."
            )
        try:
            build_result = json.loads(
                (pulled_dir / "build-result.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PDDRetrievalError(
                f"Unable to read published build result: {exc}"
            ) from exc
        image_id = build_result.get("image_id")
        if not isinstance(image_id, str) or not image_id:
            raise PDDRetrievalError("Published build result has no valid image_id.")
        expected_files = {
            "product-deployment.json",
            "binding-verification.json",
            *SIDECARS,
        }
        for evidence in descriptor["evidence"]:
            expected_files.add(
                f"{image_id}.lock-v2.json"
                if evidence["name"] == "lock_v2"
                else evidence["path"]
            )
        observed_files = {
            path.relative_to(pulled_dir).as_posix() for path in pulled_files
        }
        if observed_files != expected_files:
            raise PDDRetrievalError(
                "Published artifact file inventory does not match the PDD evidence and sidecar contract."
            )

        if verify_image_binding:
            try:
                binding = verify_product_deployment_binding(
                    pdd_path, pulled_dir, docker_bin=docker_bin
                )
            except ProductDeploymentBindingError as exc:
                raise PDDRetrievalError(
                    f"Retrieved PDD evidence binding failed: {exc}"
                ) from exc
            recorded = json.loads(binding_path.read_text(encoding="utf-8"))
            for key in (
                "status",
                "descriptor_id",
                "image_digest",
                "content_sha256",
                "evidence_count",
            ):
                if recorded.get(key) != binding.get(key):
                    raise PDDRetrievalError(
                        f"Retrieved binding report disagrees on {key}."
                    )
            if binding.get("status") != "passed":
                raise PDDRetrievalError(
                    "Retrieved evidence bundle did not pass binding verification."
                )
            consumer_report = _verify_independent_consumer_trust(
                receipt=receipt,
                descriptor=descriptor,
                validated=validated,
                pdd_path=pdd_path,
                pulled_dir=pulled_dir,
                output_dir=output_dir,
                cosign_bin=cosign_bin,
            )

        for item in pulled_dir.iterdir():
            target = output_dir / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            elif item.is_file() and not item.is_symlink():
                shutil.copy2(item, target)

    if verify_image_binding:
        return consumer_report
    return {
        "status": "descriptor_only_non_trust_verifying",
        "artifact_reference": reference,
        "artifact_digest": digest,
        "descriptor_id": validated["descriptor_id"],
        "content_sha256": validated["content_sha256"],
        "image_digest": validated["image_digest"],
        "evidence_binding_verified": False,
        "output_directory": str(output_dir.resolve()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication-record", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--oras-bin", default="oras")
    parser.add_argument("--docker-bin", default="docker")
    parser.add_argument("--cosign-bin", default="cosign")
    parser.add_argument(
        "--skip-image-binding",
        action="store_true",
        help="Validate artifact and PDD only; do not re-run M4.2.6.5 against the image registry.",
    )
    args = parser.parse_args()
    try:
        report = fetch_product_deployment_descriptor(
            args.publication_record,
            args.output_dir,
            oras_bin=args.oras_bin,
            docker_bin=args.docker_bin,
            cosign_bin=args.cosign_bin,
            verify_image_binding=not args.skip_image_binding,
        )
    except PDDRetrievalError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    if report.get("trust_decision", {}).get("status") == "rejected" and report.get("trust_decision", {}).get("reason_codes") == [PROVISIONAL_REASON]:
        return 2
    return 0


def _strict_json_file(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PDDRetrievalError(f"{label} is missing or unsafe: {path}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PDDRetrievalError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise PDDRetrievalError(f"{label} contains non-finite JSON value: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except PDDRetrievalError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PDDRetrievalError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise PDDRetrievalError(f"{label} must be a JSON object.")
    return value


def _load_trust_result(
    path: Path,
    *,
    kind: str,
    repository: str,
    digest: str,
    immutable_reference: str,
    predicate_type: str,
    expected_identity: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    result = _strict_json_file(path, f"{kind} trust result")
    try:
        artifact_trust.validate_trust_verification_result(result)
    except Exception as exc:
        raise PDDRetrievalError(f"{kind} trust result schema validation failed: {exc}") from exc

    artifact = result["artifact"]
    if (
        artifact["kind"] != kind
        or artifact["repository"] != repository
        or artifact["digest"] != digest
        or artifact["immutable_reference"] != immutable_reference
    ):
        raise PDDRetrievalError(f"{kind} trust result identifies a different artifact.")
    if result["signature"]["verified"] is not True:
        raise PDDRetrievalError(f"{kind} signature was not verified.")
    if (
        result["signer"]["verified"] is not True
        or result["signer"]["oidc_issuer"] != policy["issuer"]
        or result["signer"]["certificate_identity"] != expected_identity["certificate_identity"]
        or result["signer"]["workflow_ref"] != expected_identity["workflow_ref"]
    ):
        raise PDDRetrievalError(f"{kind} signer identity does not match the trust policy.")
    if (
        result["transparency"]["verified"] is not True
        or result["transparency"]["log_entry_verified"] is not True
    ):
        raise PDDRetrievalError(f"{kind} transparency-log verification is incomplete.")
    attestations = result["attestations"]
    if len(attestations) != 1:
        raise PDDRetrievalError(f"{kind} must contain exactly one verified attestation.")
    attestation = attestations[0]
    if (
        attestation["verified"] is not True
        or attestation["predicate_type"] != predicate_type
        or attestation["subject_digest"] != digest
    ):
        raise PDDRetrievalError(f"{kind} attestation result does not match its artifact.")
    if policy["status"] == PROVISIONAL_POLICY_STATUS:
        if (
            result["decision"]["status"] != "rejected"
            or result["decision"]["reason_codes"] != [PROVISIONAL_REASON]
        ):
            raise PDDRetrievalError(f"{kind} did not produce the exact provisional rejection.")
    elif policy["status"] == "confirmed":
        if (
            result["decision"]["status"] != "trusted"
            or result["decision"]["reason_codes"] != []
        ):
            raise PDDRetrievalError(f"{kind} did not produce a trusted decision under confirmed policy.")
    else:
        raise PDDRetrievalError("Artifact trust policy status is not recognized.")
    return result


def _verify_independent_consumer_trust(
    *,
    receipt: dict[str, Any],
    descriptor: dict[str, Any],
    validated: dict[str, Any],
    pdd_path: Path,
    pulled_dir: Path,
    output_dir: Path,
    cosign_bin: str,
) -> dict[str, Any]:
    """Verify PDD and source-image trust using only second-pass registry attestations."""
    pdd_ref = receipt["artifact"]["immutable_reference"]
    pdd_repository, pdd_digest = cosign_pdd_trust.parse_pdd_reference(pdd_ref)
    policy = artifact_trust.load_identity_policy()
    policy_path = artifact_trust.POLICY_PATH
    policy_file_sha256 = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    pdd_identity_matches = [
        item for item in policy["identities"]
        if item["id"] == cosign_pdd_trust.IDENTITY_ID and "pdd" in item["artifact_kinds"]
    ]
    image_identity_matches = [
        item for item in policy["identities"]
        if item["id"] == cosign_image_trust.IDENTITY_ID and "product_image" in item["artifact_kinds"]
    ]
    if len(pdd_identity_matches) != 1 or len(image_identity_matches) != 1:
        raise PDDRetrievalError("Consumer signer identities are missing or ambiguous in the shared policy.")
    pdd_identity = pdd_identity_matches[0]
    image_identity = image_identity_matches[0]
    pdd_result_path = output_dir / "pdd-trust-result.json"
    pdd_attestation_path = output_dir / "pdd-verified-attestation.json"
    image_result_path = output_dir / "image-trust-result.json"
    image_attestation_path = output_dir / "image-verified-attestation.json"
    report_path = output_dir / "pdd-consumer-verification-report.json"

    try:
        cosign_pdd_trust.verify_pdd(
            pdd_ref=pdd_ref,
            result_output=pdd_result_path,
            attestation_output=pdd_attestation_path,
            cosign_binary=cosign_bin,
            policy_path=policy_path,
            self_contained=True,
        )
    except cosign_pdd_trust.PDDCosignTrustError:
        # Only a complete, schema-valid, correlated provisional result is an
        # expected negative trust decision. Every other exception fails closed.
        if not pdd_result_path.is_file():
            raise PDDRetrievalError("PDD Cosign verification failed without a result file.")
    pdd_result = _load_trust_result(
        pdd_result_path,
        kind="pdd",
        repository=pdd_repository,
        digest=pdd_digest,
        immutable_reference=pdd_ref,
        predicate_type=cosign_pdd_trust.PREDICATE_TYPE,
        expected_identity=pdd_identity,
        policy=policy,
    )
    pdd_statement = cosign_image_trust.extract_verified_statement(
        pdd_attestation_path.read_text(encoding="utf-8")
    )
    if pdd_statement.get("_type") != "https://in-toto.io/Statement/v0.1":
        raise PDDRetrievalError("PDD attestation is not the supported Cosign Statement v0.1.")
    normalized_pdd_statement = dict(pdd_statement)
    normalized_pdd_statement["_type"] = "https://in-toto.io/Statement/v1"
    pdd_predicate = normalized_pdd_statement["predicate"]
    image_claim = pdd_predicate["subject_image"]
    image_repository = image_claim["repository"]
    image_digest = image_claim["digest"]
    image_platform = image_claim["platform"]
    image_ref = f"{image_repository}@{image_digest}"
    try:
        parsed_image_repository, parsed_image_digest = cosign_image_trust.parse_image_reference(image_ref)
    except cosign_image_trust.CosignTrustError as exc:
        raise PDDRetrievalError(f"PDD binding does not provide an immutable image reference: {exc}") from exc
    if parsed_image_repository != image_repository or parsed_image_digest != image_digest:
        raise PDDRetrievalError("Derived image reference does not match the PDD binding predicate.")

    try:
        artifact_trust.validate_pdd_binding_statement(
            normalized_pdd_statement,
            pdd_digest=pdd_digest,
            image_digest=image_digest,
            descriptor_content_sha256=validated["content_sha256"],
        )
    except Exception as exc:
        raise PDDRetrievalError(f"Verified PDD binding predicate is invalid: {exc}") from exc
    if (
        pdd_statement["subject"][0]["name"] != pdd_repository
        or pdd_predicate["descriptor"]["id"] != validated["descriptor_id"]
        or pdd_predicate["descriptor"]["content_sha256"] != validated["content_sha256"]
        or pdd_predicate["subject_image"]["repository"] != descriptor["artifact"]["repository"]
        or pdd_predicate["subject_image"]["digest"] != descriptor["artifact"]["digest"]
        or pdd_predicate["subject_image"]["platform"] != descriptor["artifact"]["platform"]
        or pdd_predicate["subject_image"]["repository"] != receipt["subject_image"]["repository"]
        or pdd_predicate["subject_image"]["digest"] != receipt["subject_image"]["digest"]
        or pdd_predicate["subject_image"]["platform"] != receipt["subject_image"]["platform"]
    ):
        raise PDDRetrievalError("PDD binding predicate disagrees with the retrieved descriptor or receipt.")
    if pdd_statement["subject"][0]["digest"]["sha256"] != pdd_digest.removeprefix("sha256:"):
        raise PDDRetrievalError("PDD binding Statement subject digest does not match the PDD artifact.")

    lock_files = [item for item in pulled_dir.rglob("*.lock-v2.json") if item.is_file() and not item.is_symlink()]
    if len(lock_files) != 1:
        raise PDDRetrievalError("Published PDD evidence must contain exactly one lock-v2 file.")
    lock_sha = hashlib.sha256(lock_files[0].read_bytes()).hexdigest()
    if pdd_predicate["lock_sha256"] != lock_sha:
        raise PDDRetrievalError("PDD binding lock hash does not match the published lock-v2 evidence.")

    try:
        cosign_image_trust.verify_image(
            image_ref=image_ref,
            result_output=image_result_path,
            attestation_output=image_attestation_path,
            cosign_binary=cosign_bin,
            policy_path=policy_path,
            self_contained=True,
        )
    except cosign_image_trust.CosignTrustError:
        if not image_result_path.is_file():
            raise PDDRetrievalError("Image Cosign verification failed without a result file.")
    image_result = _load_trust_result(
        image_result_path,
        kind="product_image",
        repository=image_repository,
        digest=image_digest,
        immutable_reference=image_ref,
        predicate_type=cosign_image_trust.PREDICATE_TYPE,
        expected_identity=image_identity,
        policy=policy,
    )
    if hashlib.sha256(policy_path.read_bytes()).hexdigest() != policy_file_sha256:
        raise PDDRetrievalError("Artifact trust identity policy changed during consumer verification.")
    if pdd_result["decision"]["status"] != image_result["decision"]["status"]:
        raise PDDRetrievalError("PDD and image trust decisions are mixed; refusing to infer a combined decision.")
    if policy["status"] == PROVISIONAL_POLICY_STATUS and (
        pdd_result["decision"]["reason_codes"] != [PROVISIONAL_REASON]
        or image_result["decision"]["reason_codes"] != [PROVISIONAL_REASON]
    ):
        raise PDDRetrievalError("Both artifacts must have the exact provisional rejection.")

    image_statement = cosign_image_trust.extract_verified_statement(
        image_attestation_path.read_text(encoding="utf-8")
    )
    if image_statement.get("_type") != "https://in-toto.io/Statement/v0.1":
        raise PDDRetrievalError("Image attestation is not the supported Cosign Statement v0.1.")
    normalized_image_statement = dict(image_statement)
    normalized_image_statement["_type"] = "https://in-toto.io/Statement/v1"
    try:
        artifact_trust.validate_image_provenance_statement(normalized_image_statement, image_digest)
    except Exception as exc:
        raise PDDRetrievalError(f"Verified source-image provenance is invalid: {exc}") from exc
    image_subject = normalized_image_statement["subject"]
    image_predicate = normalized_image_statement["predicate"]
    workflow = image_predicate["ndf_build"]["workflow"]
    image_source_commit = workflow["source_commit"]
    pdd_source_commit = pdd_predicate["workflow"]["source_commit"]
    if (
        image_subject[0]["name"] != image_repository
        or image_subject[0]["digest"]["sha256"] != image_digest.removeprefix("sha256:")
        or image_predicate["ndf_build"]["platform"] != image_platform
        or image_predicate["ndf_build"]["lock_sha256"] != pdd_predicate["lock_sha256"]
    ):
        raise PDDRetrievalError("Verified image provenance disagrees with the PDD binding predicate.")
    predicate_hash = hashlib.sha256(cosign_image_trust._canonical_json(image_predicate)).hexdigest()
    expected_predicate_hash = pdd_predicate["source_provenance"]["predicate_sha256"]
    if predicate_hash != expected_predicate_hash:
        raise PDDRetrievalError("Verified SLSA predicate hash does not match the PDD binding claim.")

    pdd_attestation_hash = hashlib.sha256(cosign_image_trust._canonical_json(pdd_predicate)).hexdigest()
    if pdd_result["attestations"][0].get("predicate_sha256") != pdd_attestation_hash:
        raise PDDRetrievalError("PDD trust result predicate hash does not match its verified attestation.")
    if image_result["attestations"][0].get("predicate_sha256") != predicate_hash:
        raise PDDRetrievalError("Image trust result predicate hash does not match its verified attestation.")
    evidence_files = []
    for item in sorted(pulled_dir.rglob("*")):
        if item.is_file() and not item.is_symlink():
            raw = item.read_bytes()
            evidence_files.append({
                "path": item.relative_to(pulled_dir).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            })
    binding_report_sha = hashlib.sha256((pulled_dir / "binding-verification.json").read_bytes()).hexdigest()
    policy_status = policy["status"]
    trust_status = pdd_result["decision"]["status"]
    reasons = [PROVISIONAL_REASON] if trust_status == "rejected" else []
    report = {
        "schema_version": "1.0.0",
        "verification_id": str(uuid.uuid4()),
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "execution": {
            "status": "completed",
            "stages": {
                "pdd_retrieval": "passed",
                "pdd_trust": "passed",
                "image_trust": "passed",
                "provenance_correlation": "passed",
                "evidence_binding": "passed",
            },
        },
        "policy": {
            "policy_id": policy["policy_id"],
            "schema_version": policy["schema_version"],
            "status": policy_status,
        },
        "pdd": {
            "kind": "pdd",
            "repository": pdd_repository,
            "digest": pdd_digest,
            "immutable_reference": pdd_ref,
            "descriptor_id": validated["descriptor_id"],
            "descriptor_content_sha256": validated["content_sha256"],
            "predicate_type": cosign_pdd_trust.PREDICATE_TYPE,
            "predicate_sha256": pdd_attestation_hash,
            "signature_verified": pdd_result["signature"]["verified"],
            "signer_verified": pdd_result["signer"]["verified"],
            "certificate_identity": pdd_result["signer"]["certificate_identity"],
            "oidc_issuer": pdd_result["signer"]["oidc_issuer"],
            "workflow_ref": pdd_result["signer"]["workflow_ref"],
            "transparency_verified": pdd_result["transparency"]["verified"],
            "trust_decision": pdd_result["decision"]["status"],
            "trust_reason_codes": pdd_result["decision"]["reason_codes"],
            "source_commit": pdd_source_commit,
            "trust_result_file": pdd_result_path.name,
            "attestation_file": pdd_attestation_path.name,
        },
        "source_image": {
            "kind": "product_image",
            "repository": image_repository,
            "digest": image_digest,
            "immutable_reference": image_ref,
            "platform": image_platform,
            "predicate_type": cosign_image_trust.PREDICATE_TYPE,
            "predicate_sha256": predicate_hash,
            "signature_verified": image_result["signature"]["verified"],
            "signer_verified": image_result["signer"]["verified"],
            "certificate_identity": image_result["signer"]["certificate_identity"],
            "oidc_issuer": image_result["signer"]["oidc_issuer"],
            "workflow_ref": image_result["signer"]["workflow_ref"],
            "transparency_verified": image_result["transparency"]["verified"],
            "trust_decision": image_result["decision"]["status"],
            "trust_reason_codes": image_result["decision"]["reason_codes"],
            "source_commit": image_source_commit,
            "trust_result_file": image_result_path.name,
            "attestation_file": image_attestation_path.name,
        },
        "correlation": {
            "pdd_subject_matches": True,
            "descriptor_matches": True,
            "image_repository_matches": True,
            "image_digest_matches": True,
            "image_platform_matches": True,
            "image_source_sha_verified": True,
            "predicate_hash_matches": True,
            "pdd_subject_digest": pdd_digest,
            "image_repository": image_repository,
            "image_digest": image_digest,
            "platform": image_platform,
            "binding_predicate_sha256": expected_predicate_hash,
            "verified_predicate_sha256": predicate_hash,
        },
        "evidence": {
            "binding_status": "passed",
            "published_file_count": len(evidence_files),
            "binding_report_sha256": binding_report_sha,
            "files": evidence_files,
        },
        "trust_decision": {"status": trust_status, "reason_codes": reasons},
        "deployment_authorization": "not_granted",
    }
    try:
        schema = json.loads(CONSUMER_REPORT_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(report)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise PDDRetrievalError(f"Consumer verification report failed schema validation: {exc}") from exc
    cosign_image_trust._atomic_write(
        report_path,
        (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    return report


if __name__ == "__main__":
    raise SystemExit(main())
