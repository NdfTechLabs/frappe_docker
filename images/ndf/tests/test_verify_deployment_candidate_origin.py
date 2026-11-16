from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import verify_deployment_candidate_origin as verifier  # noqa: E402

REPOSITORY = "ghcr.io/ndftechlabs/dt-master-deployment-candidates"
DIGEST = "sha256:" + "a" * 64
REFERENCE = f"{REPOSITORY}@{DIGEST}"
CANDIDATE_ID = "candidate-example"
PAYLOAD_SHA256 = "b" * 64
CORRELATION_ID = "4f9b4c7e-2c10-4c9e-9e3d-8a0d5f2e7b61"
SOURCE_COMMIT = "c" * 40
WORKFLOW_PATH = ".github/workflows/publish-deployment-candidate.yml"
WORKFLOW_REF = (
    "NdfTechLabs/dt_master/"
    ".github/workflows/publish-deployment-candidate.yml@refs/heads/main"
)
CERTIFICATE_IDENTITY = (
    "https://github.com/NdfTechLabs/dt_master/"
    ".github/workflows/publish-deployment-candidate.yml@refs/heads/main"
)


def _predicate():
    return {
        "schema_version": "1.0.0",
        "candidate_id": CANDIDATE_ID,
        "candidate_artifact": {"repository": REPOSITORY, "digest": DIGEST},
        "candidate_payload_sha256": PAYLOAD_SHA256,
        "producer": {
            "repository": "NdfTechLabs/dt_master",
            "workflow_path": WORKFLOW_PATH,
            "workflow_ref": WORKFLOW_REF,
            "source_commit": SOURCE_COMMIT,
        },
        "workflow_run": {"run_id": "123456789", "run_attempt": 2},
        "correlation_id": CORRELATION_ID,
    }


def _statement():
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {"name": REPOSITORY, "digest": {"sha256": "a" * 64}}
        ],
        "predicateType": verifier.PREDICATE_TYPE,
        "predicate": _predicate(),
    }


def _policy(status="confirmed"):
    return {
        "schema_version": "1.0.0",
        "policy_id": "dt-master-candidate-origin-identity-policy-v1",
        "status": status,
        "issuer": verifier.GITHUB_OIDC_ISSUER,
        "verification": {
            "required_repository": "NdfTechLabs/dt_master",
            "required_ref": "refs/heads/main",
            "required_event_name": "workflow_dispatch" if status == "confirmed" else None,
        },
        "identity": {
            "certificate_identity": CERTIFICATE_IDENTITY if status == "confirmed" else None,
            "workflow_path": WORKFLOW_PATH if status == "confirmed" else None,
            "workflow_ref": WORKFLOW_REF if status == "confirmed" else None,
        },
        "notes": ["Test-only identity. Never use as production policy."],
    }


def _write_policy(tmp_path, status="confirmed"):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy(status)), encoding="utf-8")
    return path


class FakeCosign:
    def __init__(self, statement=None):
        self.statement = statement or _statement()
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(
                command, 0, "GitVersion: v3.1.4\n", ""
            )
        if command[1] == "verify":
            return subprocess.CompletedProcess(command, 0, '[{"critical":{}}]', "")
        if command[1] == "verify-attestation":
            return subprocess.CompletedProcess(
                command, 0, json.dumps(self.statement), ""
            )
        raise AssertionError(f"Unexpected command: {command}")


def _verify(tmp_path, runner, policy_path=None, statement=None):
    return verifier.verify_candidate_origin(
        candidate_id=CANDIDATE_ID,
        artifact_reference=REFERENCE,
        payload_sha256=PAYLOAD_SHA256,
        correlation_id=CORRELATION_ID,
        policy_path=policy_path or _write_policy(tmp_path),
        signature_output=tmp_path / "candidate-signature-verification.json",
        attestation_output=tmp_path / "candidate-origin-attestation.json",
        runner=runner,
    )


def test_provisional_policy_rejects_before_cosign_or_candidate_intake(tmp_path):
    policy = _write_policy(tmp_path, status="provisional_until_live_certificate_observation")
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        raise AssertionError("Cosign must not run under an unconfirmed producer identity.")

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        verifier.verify_candidate_origin(
            candidate_id=CANDIDATE_ID,
            artifact_reference=REFERENCE,
            payload_sha256=PAYLOAD_SHA256,
            correlation_id=CORRELATION_ID,
            policy_path=policy,
            runner=runner,
        )

    assert error.value.reason_code == "IDENTITY_POLICY_PROVISIONAL"
    assert calls == []


def test_confirmed_policy_verifies_exact_candidate_origin_and_writes_evidence(tmp_path):
    runner = FakeCosign()
    result = _verify(tmp_path, runner)

    assert result["decision"] == "verified"
    assert result["reason_code"] == "CANDIDATE_ORIGIN_VERIFIED"
    assert result["producer"]["source_commit"] == SOURCE_COMMIT
    assert len(result["evidence_references"]) == 2
    assert (tmp_path / "candidate-signature-verification.json").is_file()
    assert (tmp_path / "candidate-origin-attestation.json").is_file()

    commands = runner.calls
    assert [command[1] for command in commands] == [
        "version",
        "verify",
        "verify-attestation",
        "verify",
        "verify-attestation",
    ]
    assert all(
        "--certificate-identity" in command
        and CERTIFICATE_IDENTITY in command
        and "--certificate-oidc-issuer" in command
        and verifier.GITHUB_OIDC_ISSUER in command
        for command in commands[1:]
    )
    assert all(
        not any("insecure-ignore" in arg or "check-claims=false" in arg for arg in command)
        for command in commands
    )
    assert SOURCE_COMMIT in commands[3]
    assert SOURCE_COMMIT in commands[4]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("candidate_id", "other-candidate", "PAYLOAD_DIGEST_MISMATCH"),
        ("candidate_payload_sha256", "d" * 64, "PAYLOAD_DIGEST_MISMATCH"),
        ("correlation_id", "11111111-1111-4111-8111-111111111111", "PAYLOAD_DIGEST_MISMATCH"),
    ],
)
def test_signed_predicate_must_match_dispatch_values(tmp_path, field, value, reason):
    statement = _statement()
    statement["predicate"][field] = value
    runner = FakeCosign(statement)

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, runner)

    assert error.value.reason_code == reason


def test_statement_subject_digest_must_match_immutable_reference(tmp_path):
    statement = _statement()
    statement["subject"][0]["digest"]["sha256"] = "e" * 64

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, FakeCosign(statement))

    assert error.value.reason_code == "SUBJECT_DIGEST_MISMATCH"


def test_wrong_predicate_type_is_rejected(tmp_path):
    statement = _statement()
    statement["predicateType"] = "https://example.invalid/other"

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, FakeCosign(statement))

    assert error.value.reason_code == "PREDICATE_INVALID"


def test_wrong_producer_workflow_is_rejected(tmp_path):
    statement = _statement()
    statement["predicate"]["producer"]["workflow_path"] = (
        ".github/workflows/unapproved.yml"
    )

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, FakeCosign(statement))

    assert error.value.reason_code == "SIGNER_IDENTITY_REJECTED"


def test_attestation_must_remain_identical_after_source_sha_verification(tmp_path):
    class ChangingAttestationRunner(FakeCosign):
        def __init__(self):
            super().__init__()
            self.attestation_count = 0

        def __call__(self, command, **kwargs):
            if command[1] == "verify-attestation":
                self.attestation_count += 1
                statement = _statement()
                if self.attestation_count == 2:
                    statement["predicate"]["candidate_id"] = "changed"
                return subprocess.CompletedProcess(command, 0, json.dumps(statement), "")
            return super().__call__(command, **kwargs)

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, ChangingAttestationRunner())

    assert error.value.reason_code == "PREDICATE_INVALID"


def test_invalid_candidate_reference_is_rejected(tmp_path):
    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        verifier.verify_candidate_origin(
            candidate_id=CANDIDATE_ID,
            artifact_reference="ghcr.io/ndftechlabs/dt-master-deployment-candidates:latest",
            payload_sha256=PAYLOAD_SHA256,
            correlation_id=CORRELATION_ID,
            policy_path=_write_policy(tmp_path),
            runner=FakeCosign(),
        )

    assert error.value.reason_code == "SUBJECT_DIGEST_MISMATCH"


def test_identity_policy_rejects_noncanonical_certificate_identity(tmp_path):
    policy = _policy()
    policy["identity"]["certificate_identity"] = "https://github.com/*"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, FakeCosign(), policy_path=path)

    assert error.value.reason_code == "SIGNER_IDENTITY_REJECTED"

def test_cli_writes_attempt_scoped_rejection_for_provisional_identity(tmp_path):
    policy = _write_policy(
        tmp_path, status="provisional_until_live_certificate_observation"
    )
    result_path = tmp_path / "candidate-origin-result.json"
    exit_code = verifier.main(
        [
            "--candidate-id",
            CANDIDATE_ID,
            "--artifact-reference",
            REFERENCE,
            "--payload-sha256",
            PAYLOAD_SHA256,
            "--correlation-id",
            CORRELATION_ID,
            "--policy",
            str(policy),
            "--signature-output",
            str(tmp_path / "signature.json"),
            "--attestation-output",
            str(tmp_path / "attestation.json"),
            "--result-output",
            str(result_path),
        ]
    )

    assert exit_code == 1
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["decision"] == "rejected"
    assert result["reason_code"] == "IDENTITY_POLICY_PROVISIONAL"
    assert result["producer"] is None
    assert result["evidence_references"] == []


def test_cosign_signature_failure_is_not_treated_as_candidate_origin(tmp_path):
    class InvalidSignatureRunner(FakeCosign):
        def __call__(self, command, **kwargs):
            if command[1] == "verify":
                self.calls.append(command)
                return subprocess.CompletedProcess(
                    command, 1, "", "no matching signatures"
                )
            return super().__call__(command, **kwargs)

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, InvalidSignatureRunner())

    assert error.value.reason_code == "SIGNATURE_INVALID"


def test_missing_rekor_evidence_is_rejected(tmp_path):
    class MissingRekorRunner(FakeCosign):
        def __call__(self, command, **kwargs):
            if command[1] == "verify-attestation":
                self.calls.append(command)
                return subprocess.CompletedProcess(
                    command, 1, "", "Rekor inclusion proof not found"
                )
            return super().__call__(command, **kwargs)

    with pytest.raises(verifier.CandidateOriginTrustError) as error:
        _verify(tmp_path, MissingRekorRunner())

    assert error.value.reason_code == "REKOR_EVIDENCE_INVALID"


def test_candidate_origin_verification_result_schema_rejects_success_without_evidence():
    result = {
        "schema_version": "1.0.0",
        "decision": "verified",
        "reason_code": "CANDIDATE_ORIGIN_VERIFIED",
        "candidate_id": CANDIDATE_ID,
        "correlation_id": CORRELATION_ID,
        "subject": {"repository": REPOSITORY, "digest": DIGEST},
        "payload_sha256": PAYLOAD_SHA256,
        "producer": {
            "repository": "NdfTechLabs/dt_master",
            "workflow_path": WORKFLOW_PATH,
            "workflow_ref": WORKFLOW_REF,
            "source_commit": SOURCE_COMMIT,
            "run_id": "123456789",
            "run_attempt": 1,
        },
        "evidence_references": [],
    }

    with pytest.raises(verifier.CandidateOriginTrustError):
        verifier.validate_result(result)
