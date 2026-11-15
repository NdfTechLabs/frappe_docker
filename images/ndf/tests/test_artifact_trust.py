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
