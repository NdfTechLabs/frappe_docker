from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

NDF = Path(__file__).resolve().parents[1]
SCHEMA = NDF / "schemas" / "deployment-build-trust-evidence-v1.schema.json"
FIXTURE = (
    NDF / "fixtures" / "trust" / "valid" / "deployment-build-trust-evidence-v1.json"
)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validator():
    schema = load_json(SCHEMA)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_valid_trust_evidence_fixture_conforms_to_schema():
    report = load_json(FIXTURE)
    assert not list(validator().iter_errors(report))


def test_verified_candidate_origin_requires_signature_and_attestation_evidence():
    report = load_json(FIXTURE)
    report["candidate_origin"]["evidence_references"] = [
        evidence
        for evidence in report["candidate_origin"]["evidence_references"]
        if evidence["kind"] != "candidate_origin_attestation"
    ]
    assert list(validator().iter_errors(report))


def test_rejected_candidate_origin_cannot_claim_verified_reason():
    report = load_json(FIXTURE)
    report["candidate_origin"]["decision"] = "rejected"
    report["candidate_origin"]["reason_code"] = "CANDIDATE_ORIGIN_VERIFIED"
    assert list(validator().iter_errors(report))


def test_provisional_identity_is_a_rejection_not_a_verification():
    report = load_json(FIXTURE)
    report["candidate_origin"]["decision"] = "rejected"
    report["candidate_origin"]["reason_code"] = "IDENTITY_POLICY_PROVISIONAL"
    assert not list(validator().iter_errors(report))


def test_not_evaluated_candidate_origin_uses_fixed_reason_code():
    report = load_json(FIXTURE)
    report["candidate_origin"]["decision"] = "not_evaluated"
    report["candidate_origin"]["reason_code"] = "NOT_EVALUATED"
    report["candidate_origin"]["evidence_references"] = []
    assert not list(validator().iter_errors(report))


def test_trust_report_has_no_dt_master_verification_outcome_fields():
    report = load_json(FIXTURE)
    assert "master_image_verification" not in report
    assert "master_descriptor_verification" not in report
    assert "deployment_authorized" not in report


def test_correlation_id_requires_canonical_lowercase_uuid():
    report = load_json(FIXTURE)
    report["correlation_id"] = report["correlation_id"].upper()
    assert list(validator().iter_errors(report))
