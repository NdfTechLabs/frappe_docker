import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import artifact_trust as trust  # noqa: E402
from scripts.artifact_trust import ArtifactTrustError  # noqa: E402


@pytest.fixture
def policy():
    return trust.load_identity_policy()


def _claims(entry, *, reusable=False):
    claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "repository": "NdfTechLabs/frappe_docker",
        "ref": "refs/heads/main",
        "event_name": "workflow_dispatch",
        "workflow_ref": entry["workflow_ref"],
        "run_id": "123456789",
        "run_attempt": 2,
        "certificate_identity": entry["certificate_identity"],
    }
    if reusable:
        claims["job_workflow_ref"] = entry["reusable_workflow_ref"]
        claims["job_workflow_sha"] = "a" * 40
    return claims


def _image_statement():
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "ghcr.io/ndftechlabs/dalali",
                "digest": {"sha256": "a" * 64},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://ndftechlabs.com/buildtypes/ndf-image/v1",
                "externalParameters": {"product": "dalali-v16"},
                "resolvedDependencies": [],
            },
            "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
            "ndf_build": {
                "schema_version": "1.0.0",
                "product_id": "dalali-v16",
                "platform": "linux/amd64",
                "workflow": {
                    "repository": "NdfTechLabs/frappe_docker",
                    "path": ".github/workflows/ndf-publish-product.yml",
                    "ref": "refs/heads/main",
                    "run_id": "123456789",
                    "run_attempt": 2,
                    "source_commit": "b" * 40,
                },
                "lock_sha256": "c" * 64,
                "composition_sha256": "d" * 64,
                "source_revisions": [
                    {"repository": "frappe", "commit": "e" * 40}
                ],
                "validation": {
                    "image_validation": {
                        "status": "passed",
                        "report_sha256": "1" * 64,
                    },
                    "source_provenance": {
                        "status": "passed",
                        "report_sha256": "2" * 64,
                    },
                    "composition_verification": {
                        "status": "passed",
                        "report_sha256": "3" * 64,
                    },
                    "evidence_binding": {
                        "status": "passed",
                        "report_sha256": "4" * 64,
                    },
                },
            },
        },
    }


def _pdd_statement():
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "ghcr.io/ndftechlabs/dalali-pdd",
                "digest": {"sha256": "f" * 64},
            }
        ],
        "predicateType": "https://ndftechlabs.com/attestations/pdd-image-binding/v1",
        "predicate": {
            "schema_version": "1.0.0",
            "descriptor": {"id": "pdd:dalali:linux-amd64", "content_sha256": "9" * 64},
            "subject_image": {
                "repository": "ghcr.io/ndftechlabs/dalali",
                "digest": "sha256:" + "a" * 64,
                "platform": "linux/amd64",
            },
            "lock_sha256": "c" * 64,
            "source_provenance": {
                "predicate_type": "https://slsa.dev/provenance/v1",
                "attestation_sha256": "8" * 64,
            },
            "workflow": {
                "repository": "NdfTechLabs/frappe_docker",
                "path": ".github/workflows/ndf-publish-product-deployment-descriptor.yml",
                "ref": "refs/heads/main",
                "run_id": "123456789",
                "run_attempt": 1,
                "source_commit": "b" * 40,
            },
        },
    }


def test_loads_and_validates_identity_policy(policy):
    assert policy["policy_id"] == "ndf-artifact-trust-identity-policy-v1"
    assert len(policy["identities"]) == 4


def test_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"policy_id":"one","policy_id":"two"}', encoding="utf-8")
    with pytest.raises(ArtifactTrustError, match="Duplicate JSON object key"):
        trust._read_json(path, "test policy")


def test_accepts_exact_product_image_signer_claims(policy):
    entry = next(x for x in policy["identities"] if x["id"] == "product-image-publication")
    result = trust.validate_signer_claims(
        _claims(entry), identity_id=entry["id"], policy=policy
    )
    assert result["identity_claims_validated"] is True
    assert result["cryptographic_signature_verified"] is False
    assert result["policy_status"] == "provisional_until_live_certificate_observation"


@pytest.mark.parametrize(
    ("claim", "value", "message"),
    [
        ("iss", "https://attacker.example", "claim iss mismatch"),
        ("repository", "attacker/repo", "claim repository mismatch"),
        ("ref", "refs/heads/feature", "claim ref mismatch"),
        ("event_name", "pull_request", "claim event_name mismatch"),
        ("certificate_identity", "https://github.com/attacker/workflow", "certificate identity"),
        ("workflow_ref", "attacker/repo/.github/workflows/x.yml@refs/heads/main", "claim workflow_ref mismatch"),
    ],
)
def test_rejects_mismatched_signer_claims(policy, claim, value, message):
    entry = next(x for x in policy["identities"] if x["id"] == "product-image-publication")
    claims = _claims(entry)
    claims[claim] = value
    with pytest.raises(ArtifactTrustError, match=message):
        trust.validate_signer_claims(claims, identity_id=entry["id"], policy=policy)


def test_rejects_missing_signer_claim(policy):
    entry = next(x for x in policy["identities"] if x["id"] == "product-image-publication")
    claims = _claims(entry)
    del claims["run_attempt"]
    with pytest.raises(ArtifactTrustError, match="missing required values"):
        trust.validate_signer_claims(claims, identity_id=entry["id"], policy=policy)


def test_accepts_candidate_reusable_workflow_claims(policy):
    entry = next(x for x in policy["identities"] if x["id"] == "candidate-image-build")
    result = trust.validate_signer_claims(
        _claims(entry, reusable=True),
        identity_id=entry["id"],
        policy=policy,
        expected_reusable_workflow_sha="a" * 40,
    )
    assert result["reusable_workflow_ref"] == entry["reusable_workflow_ref"]
    assert result["reusable_workflow_sha"] == "a" * 40


def test_rejects_candidate_reusable_workflow_mismatch(policy):
    entry = next(x for x in policy["identities"] if x["id"] == "candidate-image-build")
    claims = _claims(entry, reusable=True)
    claims["job_workflow_ref"] = "NdfTechLabs/frappe_docker/.github/workflows/unapproved.yml@refs/heads/main"
    with pytest.raises(ArtifactTrustError, match="Reusable workflow identity mismatch"):
        trust.validate_signer_claims(claims, identity_id=entry["id"], policy=policy)


def test_rejects_candidate_reusable_workflow_sha_mismatch(policy):
    entry = next(x for x in policy["identities"] if x["id"] == "candidate-image-build")
    with pytest.raises(ArtifactTrustError, match="commit SHA mismatch"):
        trust.validate_signer_claims(
            _claims(entry, reusable=True),
            identity_id=entry["id"],
            policy=policy,
            expected_reusable_workflow_sha="f" * 40,
        )


def test_validates_image_provenance_and_exact_subject_digest():
    report = trust.validate_image_provenance_statement(
        _image_statement(), "sha256:" + "a" * 64
    )
    assert report["predicate_type"] == "https://slsa.dev/provenance/v1"
    assert report["subject_digest"] == "sha256:" + "a" * 64
    assert report["candidate"] is False


def test_rejects_image_provenance_subject_digest_mismatch():
    with pytest.raises(ArtifactTrustError, match="subject digest mismatch"):
        trust.validate_image_provenance_statement(
            _image_statement(), "sha256:" + "f" * 64
        )


def test_validates_pdd_binding_and_exact_subjects():
    report = trust.validate_pdd_binding_statement(
        _pdd_statement(),
        pdd_digest="sha256:" + "f" * 64,
        image_digest="sha256:" + "a" * 64,
        descriptor_content_sha256="9" * 64,
    )
    assert report["pdd_subject_digest"] == "sha256:" + "f" * 64


def test_rejects_pdd_image_digest_mismatch():
    with pytest.raises(ArtifactTrustError, match="different image digest"):
        trust.validate_pdd_binding_statement(
            _pdd_statement(),
            pdd_digest="sha256:" + "f" * 64,
            image_digest="sha256:" + "b" * 64,
            descriptor_content_sha256="9" * 64,
        )


def test_rejects_pdd_descriptor_content_hash_mismatch():
    with pytest.raises(ArtifactTrustError, match="content hash mismatch"):
        trust.validate_pdd_binding_statement(
            _pdd_statement(),
            pdd_digest="sha256:" + "f" * 64,
            image_digest="sha256:" + "a" * 64,
            descriptor_content_sha256="7" * 64,
        )


def _valid_trust_result():
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": "1.0.0",
        "verification_id": "verify-123",
        "artifact": {
            "kind": "product_image",
            "repository": "ghcr.io/ndftechlabs/dalali",
            "digest": digest,
            "immutable_reference": "ghcr.io/ndftechlabs/dalali@" + digest,
        },
        "signature": {
            "verified": True,
            "verification_method": "cosign-keyless",
            "signature_reference": "ghcr.io/ndftechlabs/dalali",
        },
        "signer": {
            "verified": True,
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": "https://github.com/NdfTechLabs/frappe_docker/.github/workflows/ndf-publish-product.yml@refs/heads/main",
        },
        "transparency": {
            "verified": True,
            "log_entry_verified": True,
            "log_index": 123,
            "integrated_time": 1760000000,
            "entry_uuid": "rekor-entry-123",
        },
        "attestations": [
            {
                "predicate_type": "https://slsa.dev/provenance/v1",
                "verified": True,
                "subject_digest": digest,
                "predicate_sha256": "b" * 64,
            }
        ],
        "decision": {"status": "trusted", "reason_codes": []},
        "verified_at": "2026-11-15T16:00:00Z",
    }


def _write_policy(tmp_path, policy):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_rejects_non_finite_json_constants(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(ArtifactTrustError, match="Non-finite JSON constant"):
        trust._read_json(path, "test policy")


def test_rejects_duplicate_identity_ids_in_policy(tmp_path, policy):
    malformed = json.loads(json.dumps(policy))
    malformed["identities"].append(dict(malformed["identities"][0]))
    with pytest.raises(ArtifactTrustError, match="duplicate identity IDs"):
        trust.load_identity_policy(_write_policy(tmp_path, malformed))


def test_rejects_ambiguous_certificate_identity_for_same_artifact_kind(
    tmp_path, policy
):
    malformed = json.loads(json.dumps(policy))
    duplicate = dict(malformed["identities"][0])
    duplicate["id"] = "duplicate-product-image"
    malformed["identities"].append(duplicate)
    with pytest.raises(ArtifactTrustError, match="ambiguous duplicate certificate"):
        trust.load_identity_policy(_write_policy(tmp_path, malformed))


def test_allows_shared_candidate_caller_identity_for_distinct_artifact_kinds(
    policy,
):
    image = next(x for x in policy["identities"] if x["id"] == "candidate-image-build")
    pdd = next(x for x in policy["identities"] if x["id"] == "candidate-pdd-publication")
    assert image["certificate_identity"] == pdd["certificate_identity"]
    assert set(image["artifact_kinds"]).isdisjoint(pdd["artifact_kinds"])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("iss", "https://token.actions.githubusercontent.com", "claim iss mismatch"),
        ("run_id", "../123", "run_id must contain decimal digits"),
        ("run_attempt", True, "run_attempt must be a positive integer"),
        ("run_attempt", 0, "run_attempt must be a positive integer"),
    ],
)
def test_rejects_invalid_signer_claim_values(policy, field, value, message):
    entry = next(x for x in policy["identities"] if x["id"] == "product-image-publication")
    claims = _claims(entry)
    claims[field] = value
    if field == "iss" and value == "https://token.actions.githubusercontent.com":
        claims["iss"] = "https://attacker.example"
    with pytest.raises(ArtifactTrustError, match=message):
        trust.validate_signer_claims(claims, identity_id=entry["id"], policy=policy)


def test_rejects_malformed_reusable_workflow_sha(policy):
    entry = next(x for x in policy["identities"] if x["id"] == "candidate-image-build")
    claims = _claims(entry, reusable=True)
    claims["job_workflow_sha"] = "not-a-commit"
    with pytest.raises(ArtifactTrustError, match="job_workflow_sha is missing or invalid"):
        trust.validate_signer_claims(claims, identity_id=entry["id"], policy=policy)


def test_rejects_unexpected_reusable_workflow_claim_for_direct_workflow(policy):
    entry = next(x for x in policy["identities"] if x["id"] == "product-image-publication")
    claims = _claims(entry)
    claims["job_workflow_ref"] = "NdfTechLabs/frappe_docker/.github/workflows/other.yml@refs/heads/main"
    with pytest.raises(ArtifactTrustError, match="must not be verified as a reusable workflow"):
        trust.validate_signer_claims(claims, identity_id=entry["id"], policy=policy)


def test_rejects_wrong_image_provenance_predicate_type():
    statement = _image_statement()
    statement["predicateType"] = "https://example.com/untrusted"
    with pytest.raises(ArtifactTrustError, match="schema validation failed"):
        trust.validate_image_provenance_statement(statement, "sha256:" + "a" * 64)


def test_rejects_malformed_image_provenance_subject():
    statement = _image_statement()
    statement["subject"][0]["digest"]["sha256"] = "not-a-sha256"
    with pytest.raises(ArtifactTrustError, match="schema validation failed"):
        trust.validate_image_provenance_statement(statement, "sha256:" + "a" * 64)


def test_rejects_wrong_pdd_binding_predicate_type():
    statement = _pdd_statement()
    statement["predicateType"] = "https://slsa.dev/provenance/v1"
    with pytest.raises(ArtifactTrustError, match="schema validation failed"):
        trust.validate_pdd_binding_statement(
            statement,
            pdd_digest="sha256:" + "f" * 64,
            image_digest="sha256:" + "a" * 64,
            descriptor_content_sha256="9" * 64,
        )


def test_rejects_malformed_pdd_binding_subject():
    statement = _pdd_statement()
    statement["subject"][0]["digest"]["sha256"] = "bad"
    with pytest.raises(ArtifactTrustError, match="schema validation failed"):
        trust.validate_pdd_binding_statement(
            statement,
            pdd_digest="sha256:" + "f" * 64,
            image_digest="sha256:" + "a" * 64,
            descriptor_content_sha256="9" * 64,
        )


def test_accepts_consistent_trusted_verification_result():
    trust.validate_trust_verification_result(_valid_trust_result())


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda result: result["signature"].update(verified=False), "schema validation failed"),
        (lambda result: result["signer"].update(verified=False), "schema validation failed"),
        (lambda result: result["transparency"].update(verified=False), "schema validation failed"),
        (lambda result: result["transparency"].update(log_entry_verified=False), "schema validation failed"),
        (lambda result: result["attestations"][0].update(verified=False), "schema validation failed"),
        (lambda result: result["decision"].update(reason_codes=["SIGNATURE_INVALID"]), "schema validation failed"),
    ],
)
def test_rejects_trusted_result_with_failed_trust_component(mutate, message):
    result = _valid_trust_result()
    mutate(result)
    with pytest.raises(ArtifactTrustError, match=message):
        trust.validate_trust_verification_result(result)


def test_rejects_trusted_result_without_attestations():
    result = _valid_trust_result()
    result["attestations"] = []
    with pytest.raises(ArtifactTrustError, match="schema validation failed"):
        trust.validate_trust_verification_result(result)


def test_rejects_duplicate_trust_result_reason_codes():
    result = _valid_trust_result()
    result["decision"] = {
        "status": "rejected",
        "reason_codes": ["SIGNATURE_INVALID", "SIGNATURE_INVALID"],
    }
    with pytest.raises(ArtifactTrustError, match="schema validation failed"):
        trust.validate_trust_verification_result(result)


def test_rejects_trust_result_with_mutable_artifact_reference():
    result = _valid_trust_result()
    result["artifact"]["immutable_reference"] = "ghcr.io/ndftechlabs/dalali:latest"
    with pytest.raises(ArtifactTrustError, match="schema validation failed"):
        trust.validate_trust_verification_result(result)
