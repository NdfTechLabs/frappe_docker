import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import artifact_trust  # noqa: E402
from scripts import cosign_image_trust  # noqa: E402
from scripts import fetch_product_deployment_descriptor as consumer  # noqa: E402


@pytest.fixture
def policy():
    return artifact_trust.load_identity_policy()


def _trust_result(policy, *, kind="pdd", digest="sha256:" + "a" * 64):
    identity_id = (
        "product-pdd-publication" if kind == "pdd" else "product-image-publication"
    )
    identity = next(item for item in policy["identities"] if item["id"] == identity_id)
    repository = (
        "ghcr.io/ndftechlabs/dalali-pdd"
        if kind == "pdd"
        else "ghcr.io/ndftechlabs/dalali"
    )
    predicate_type = (
        "https://ndftechlabs.com/attestations/pdd-image-binding/v1"
        if kind == "pdd"
        else "https://slsa.dev/provenance/v1"
    )
    reference = f"{repository}@{digest}"
    return {
        "schema_version": "1.0.0",
        "verification_id": "consumer-test-verification",
        "artifact": {
            "kind": kind,
            "repository": repository,
            "digest": digest,
            "immutable_reference": reference,
        },
        "signature": {
            "verified": True,
            "verification_method": "cosign-keyless",
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
                "predicate_type": predicate_type,
                "verified": True,
                "subject_digest": digest,
                "predicate_sha256": "b" * 64,
            }
        ],
        "decision": {
            "status": "rejected",
            "reason_codes": ["IDENTITY_POLICY_PROVISIONAL"],
        },
        "verified_at": "2026-11-16T11:00:00Z",
    }


def _write_result(tmp_path, result):
    path = tmp_path / "trust-result.json"
    path.write_text(json.dumps(result), encoding="utf-8")
    return path


@pytest.mark.parametrize("kind", ["pdd", "product_image"])
def test_loads_exact_provisional_trust_result(tmp_path, policy, kind):
    result = _trust_result(policy, kind=kind)
    path = _write_result(tmp_path, result)
    identity_id = (
        "product-pdd-publication" if kind == "pdd" else "product-image-publication"
    )
    identity = next(item for item in policy["identities"] if item["id"] == identity_id)

    loaded = consumer._load_trust_result(
        path,
        kind=kind,
        repository=result["artifact"]["repository"],
        digest=result["artifact"]["digest"],
        immutable_reference=result["artifact"]["immutable_reference"],
        predicate_type=result["attestations"][0]["predicate_type"],
        expected_identity=identity,
        policy=policy,
    )

    assert loaded["decision"] == {
        "status": "rejected",
        "reason_codes": ["IDENTITY_POLICY_PROVISIONAL"],
    }


def test_rejects_trust_result_for_different_digest(tmp_path, policy):
    result = _trust_result(policy)
    path = _write_result(tmp_path, result)

    with pytest.raises(consumer.PDDRetrievalError, match="different artifact"):
        consumer._load_trust_result(
            path,
            kind="pdd",
            repository=result["artifact"]["repository"],
            digest="sha256:" + "c" * 64,
            immutable_reference=result["artifact"]["immutable_reference"],
            predicate_type=result["attestations"][0]["predicate_type"],
            expected_identity=policy["identities"][1],
            policy=policy,
        )


def test_rejects_trust_result_with_wrong_signer_identity(tmp_path, policy):
    result = _trust_result(policy)
    result["signer"]["certificate_identity"] = "https://github.com/attacker/workflow"
    path = _write_result(tmp_path, result)
    identity = next(
        item for item in policy["identities"] if item["id"] == "product-pdd-publication"
    )

    with pytest.raises(consumer.PDDRetrievalError, match="signer identity"):
        consumer._load_trust_result(
            path,
            kind="pdd",
            repository=result["artifact"]["repository"],
            digest=result["artifact"]["digest"],
            immutable_reference=result["artifact"]["immutable_reference"],
            predicate_type=result["attestations"][0]["predicate_type"],
            expected_identity=identity,
            policy=policy,
        )


def test_rejects_trust_result_without_rekor_verification(tmp_path, policy):
    result = _trust_result(policy)
    result["transparency"]["log_entry_verified"] = False
    path = _write_result(tmp_path, result)
    identity = next(
        item for item in policy["identities"] if item["id"] == "product-pdd-publication"
    )

    with pytest.raises(consumer.PDDRetrievalError, match="transparency"):
        consumer._load_trust_result(
            path,
            kind="pdd",
            repository=result["artifact"]["repository"],
            digest=result["artifact"]["digest"],
            immutable_reference=result["artifact"]["immutable_reference"],
            predicate_type=result["attestations"][0]["predicate_type"],
            expected_identity=identity,
            policy=policy,
        )


def test_rejects_non_provisional_decision_under_provisional_policy(tmp_path, policy):
    result = _trust_result(policy)
    result["decision"] = {"status": "rejected", "reason_codes": ["OTHER_REASON"]}
    path = _write_result(tmp_path, result)
    identity = next(
        item for item in policy["identities"] if item["id"] == "product-pdd-publication"
    )

    with pytest.raises(consumer.PDDRetrievalError, match="exact provisional rejection"):
        consumer._load_trust_result(
            path,
            kind="pdd",
            repository=result["artifact"]["repository"],
            digest=result["artifact"]["digest"],
            immutable_reference=result["artifact"]["immutable_reference"],
            predicate_type=result["attestations"][0]["predicate_type"],
            expected_identity=identity,
            policy=policy,
        )


def test_rejects_duplicate_keys_in_trust_result(tmp_path, policy):
    path = tmp_path / "duplicate.json"
    path.write_text('{"decision": {}, "decision": {}}', encoding="utf-8")

    with pytest.raises(consumer.PDDRetrievalError, match="duplicate JSON key"):
        consumer._strict_json_file(path, "test result")


def test_rejects_symlinked_trust_result(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "linked.json"
    link.symlink_to(target)

    with pytest.raises(consumer.PDDRetrievalError, match="missing or unsafe"):
        consumer._strict_json_file(link, "test result")


def test_rejects_mutable_image_reference():
    with pytest.raises(cosign_image_trust.CosignTrustError, match="tags are forbidden"):
        cosign_image_trust.parse_image_reference("ghcr.io/ndftechlabs/dalali:latest")


def _consumer_report_fixture():
    digest = "sha256:" + "a" * 64
    sha = "b" * 64
    artifact = {
        "kind": "pdd",
        "repository": "ghcr.io/ndftechlabs/dalali-pdd",
        "digest": digest,
        "immutable_reference": f"ghcr.io/ndftechlabs/dalali-pdd@{digest}",
        "predicate_type": "https://ndftechlabs.com/attestations/pdd-image-binding/v1",
        "predicate_sha256": sha,
        "signature_verified": True,
        "signer_verified": True,
        "certificate_identity": "https://github.com/NdfTechLabs/frappe_docker/.github/workflows/publish.yml@refs/heads/main",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "workflow_ref": "NdfTechLabs/frappe_docker/.github/workflows/publish.yml@refs/heads/main",
        "transparency_verified": True,
        "trust_decision": "rejected",
        "trust_reason_codes": ["IDENTITY_POLICY_PROVISIONAL"],
        "source_commit": "c" * 40,
        "trust_result_file": "pdd-trust-result.json",
        "attestation_file": "pdd-verified-attestation.json",
    }
    source_image = {
        **artifact,
        "kind": "product_image",
        "repository": "ghcr.io/ndftechlabs/dalali",
        "immutable_reference": f"ghcr.io/ndftechlabs/dalali@{digest}",
        "predicate_type": "https://slsa.dev/provenance/v1",
        "trust_result_file": "image-trust-result.json",
        "attestation_file": "image-verified-attestation.json",
        "platform": "linux/amd64",
    }
    return {
        "schema_version": "1.0.0",
        "verification_id": "consumer-report-test",
        "verified_at": "2026-11-16T11:00:00Z",
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
            "policy_id": "ndf-artifact-trust-identity-policy-v1",
            "schema_version": "1.0.0",
            "status": "provisional_until_live_certificate_observation",
            "policy_sha256": sha,
        },
        "pdd": artifact,
        "source_image": source_image,
        "correlation": {
            "pdd_subject_matches": True,
            "descriptor_matches": True,
            "image_repository_matches": True,
            "image_digest_matches": True,
            "image_platform_matches": True,
            "image_source_sha_verified": True,
            "predicate_hash_matches": True,
            "pdd_subject_digest": digest,
            "image_repository": "ghcr.io/ndftechlabs/dalali",
            "image_digest": digest,
            "platform": "linux/amd64",
            "binding_predicate_sha256": sha,
            "verified_predicate_sha256": sha,
        },
        "evidence": {
            "binding_status": "passed",
            "published_file_count": 1,
            "binding_report_sha256": sha,
            "files": [
                {"path": "binding-verification.json", "sha256": sha, "size_bytes": 1}
            ],
        },
        "trust_decision": {
            "status": "rejected",
            "reason_codes": ["IDENTITY_POLICY_PROVISIONAL"],
        },
        "deployment_authorization": "not_granted",
    }


def test_consumer_report_schema_accepts_generated_field_contract():
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "pdd-consumer-verification-report-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    from jsonschema import Draft202012Validator

    Draft202012Validator(schema).validate(_consumer_report_fixture())


def test_consumer_report_schema_rejects_legacy_source_workflow_field():
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "pdd-consumer-verification-report-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    from jsonschema import Draft202012Validator, ValidationError

    report = _consumer_report_fixture()
    report["correlation"]["source_workflow_sha_matches_binding"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(report)


def test_consumer_report_schema_is_valid():
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "pdd-consumer-verification-report-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    from jsonschema import Draft202012Validator

    Draft202012Validator.check_schema(schema)
