import base64
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import cosign_pdd_trust as trust


PDD_REPOSITORY = "ghcr.io/ndftechlabs/dalali"
PDD_DIGEST = "sha256:" + "b" * 64
PDD_REF = PDD_REPOSITORY + "@" + PDD_DIGEST
IMAGE_DIGEST = "sha256:" + "a" * 64
DESCRIPTOR_SHA = "c" * 64
SOURCE_COMMIT = "d" * 40


def _statement():
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": PDD_REPOSITORY,
                "digest": {"sha256": "b" * 64},
            }
        ],
        "predicateType": trust.PREDICATE_TYPE,
        "predicate": {
            "schema_version": "1.0.0",
            "descriptor": {
                "id": "pdd:dalali:linux-amd64:" + DESCRIPTOR_SHA,
                "content_sha256": DESCRIPTOR_SHA,
            },
            "subject_image": {
                "repository": PDD_REPOSITORY,
                "digest": IMAGE_DIGEST,
                "platform": "linux/amd64",
            },
            "lock_sha256": "e" * 64,
            "source_provenance": {
                "predicate_type": "https://slsa.dev/provenance/v1",
                "predicate_sha256": "f" * 64,
            },
            "workflow": {
                "repository": "NdfTechLabs/frappe_docker",
                "path": trust.WORKFLOW_PATH,
                "ref": "refs/heads/main",
                "run_id": "987654",
                "run_attempt": 1,
                "source_commit": SOURCE_COMMIT,
            },
        },
    }


def _workflow_env():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "NdfTechLabs/frappe_docker",
        "GITHUB_WORKFLOW_REF": trust.WORKFLOW_REF,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ID": "987654",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": SOURCE_COMMIT,
    }


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _policy(tmp_path, status="provisional_until_live_certificate_observation"):
    value = json.loads(trust.POLICY_PATH.read_text(encoding="utf-8"))
    value["status"] = status
    return _write(tmp_path / "policy.json", value)


class FakeRunner:
    def __init__(self, statement=None):
        self.calls = []
        self.statement = dict(statement or _statement())
        self.statement["_type"] = "https://in-toto.io/Statement/v0.1"
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(
                json.dumps(self.statement, separators=(",", ":")).encode()
            ).decode(),
            "signatures": [{"keyid": "", "sig": "c2ln"}],
        }
        self.attestation_output = (
            "Verification for PDD --\n" + json.dumps(envelope) + "\n"
        )

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[1] == "version":
            stdout = "GitVersion: v3.1.4\n"
        elif args[1] == "verify":
            stdout = '[{"critical":{"identity":{"docker-reference":"'
            stdout += PDD_REPOSITORY + '"}}}]'
        elif args[1] == "verify-attestation":
            stdout = self.attestation_output
        else:
            stdout = ""
        return subprocess.CompletedProcess(args, 0, stdout, "")


def test_parse_pdd_reference_accepts_immutable_digest():
    assert trust.parse_pdd_reference(PDD_REF) == (PDD_REPOSITORY, PDD_DIGEST)


@pytest.mark.parametrize(
    "reference",
    [
        PDD_REPOSITORY + ":latest",
        PDD_REPOSITORY,
        PDD_REPOSITORY + ":latest@" + PDD_DIGEST,
        PDD_REPOSITORY + "@sha256:" + "A" * 64,
        "not-an-oci-reference",
    ],
)
def test_parse_pdd_reference_rejects_mutable_or_malformed(reference):
    with pytest.raises(trust.PDDCosignTrustError):
        trust.parse_pdd_reference(reference)


def test_identity_selection_requires_exact_direct_pdd_workflow(tmp_path):
    policy = json.loads(trust.POLICY_PATH.read_text(encoding="utf-8"))
    pdd = next(item for item in policy["identities"] if item["id"] == trust.IDENTITY_ID)
    pdd["workflow_ref"] = "NdfTechLabs/frappe_docker/.github/workflows/other.yml@refs/heads/main"
    path = _write(tmp_path / "policy.json", policy)
    with pytest.raises(trust.PDDCosignTrustError, match="workflow reference changed"):
        trust._load_identity(path)


def test_runtime_workflow_requires_exact_context():
    assert trust._runtime_workflow(_workflow_env())["source_commit"] == SOURCE_COMMIT
    env = _workflow_env()
    env["GITHUB_EVENT_NAME"] = "push"
    with pytest.raises(trust.PDDCosignTrustError, match="approved PDD publication"):
        trust._runtime_workflow(env)


def test_sign_validates_statement_then_signs_exact_digest_and_predicate(tmp_path):
    statement = _statement()
    statement_path = _write(tmp_path / "statement.json", statement)
    predicate_path = _write(tmp_path / "predicate.json", statement["predicate"])
    runner = FakeRunner()
    result = trust.sign_pdd(
        pdd_ref=PDD_REF,
        statement_path=statement_path,
        predicate_path=predicate_path,
        env=_workflow_env(),
        policy_path=_policy(tmp_path),
        runner=runner,
    )
    assert result["status"] == "signed"
    assert result["pdd_digest"] == PDD_DIGEST
    assert [call[1] for call in runner.calls] == ["version", "sign", "attest"]
    assert runner.calls[1][-1] == PDD_REF
    attest = runner.calls[2]
    assert attest[-1] == PDD_REF
    assert attest[attest.index("--type") + 1] == trust.PREDICATE_TYPE
    assert "slsaprovenance1" not in attest


def test_sign_rejects_local_execution(tmp_path):
    statement = _statement()
    with pytest.raises(trust.PDDCosignTrustError, match="only inside GitHub Actions"):
        trust.sign_pdd(
            pdd_ref=PDD_REF,
            statement_path=_write(tmp_path / "statement.json", statement),
            predicate_path=_write(tmp_path / "predicate.json", statement["predicate"]),
            env={},
            runner=FakeRunner(),
        )


def test_sign_rejects_predicate_disagreement_before_cosign(tmp_path):
    statement = _statement()
    runner = FakeRunner()
    with pytest.raises(trust.PDDCosignTrustError, match="does not exactly match"):
        trust.sign_pdd(
            pdd_ref=PDD_REF,
            statement_path=_write(tmp_path / "statement.json", statement),
            predicate_path=_write(tmp_path / "predicate.json", {}),
            env=_workflow_env(),
            policy_path=_policy(tmp_path),
            runner=runner,
        )
    assert not any(call[1] in ("sign", "attest") for call in runner.calls)


def test_sign_rejects_wrong_statement_subject(tmp_path):
    statement = _statement()
    statement["subject"][0]["digest"]["sha256"] = "9" * 64
    runner = FakeRunner()
    with pytest.raises(trust.PDDCosignTrustError, match="subject mismatch"):
        trust.sign_pdd(
            pdd_ref=PDD_REF,
            statement_path=_write(tmp_path / "statement.json", statement),
            predicate_path=_write(tmp_path / "predicate.json", statement["predicate"]),
            env=_workflow_env(),
            policy_path=_policy(tmp_path),
            runner=runner,
        )
    assert not any(call[1] in ("sign", "attest") for call in runner.calls)


def test_sign_rejects_wrong_runtime_workflow_claims(tmp_path):
    statement = _statement()
    statement["predicate"]["workflow"]["run_id"] = "111"
    runner = FakeRunner()
    with pytest.raises(trust.PDDCosignTrustError, match="runtime context"):
        trust.sign_pdd(
            pdd_ref=PDD_REF,
            statement_path=_write(tmp_path / "statement.json", statement),
            predicate_path=_write(tmp_path / "predicate.json", statement["predicate"]),
            env=_workflow_env(),
            policy_path=_policy(tmp_path),
            runner=runner,
        )
    assert not any(call[1] in ("sign", "attest") for call in runner.calls)


def test_cosign_v01_profile_rejects_missing_or_extra_fields():
    statement = _statement()
    statement["_type"] = "https://in-toto.io/Statement/v0.1"
    del statement["predicate"]["source_provenance"]
    with pytest.raises(trust.PDDCosignTrustError, match="invalid"):
        trust._validate_cosign_statement(
            statement, repository=PDD_REPOSITORY, digest=PDD_DIGEST
        )
    statement = _statement()
    statement["_type"] = "https://in-toto.io/Statement/v0.1"
    statement["unexpected"] = True
    with pytest.raises(trust.PDDCosignTrustError, match="invalid"):
        trust._validate_cosign_statement(
            statement, repository=PDD_REPOSITORY, digest=PDD_DIGEST
        )


def test_verify_rejects_provisional_policy_and_writes_normalized_result(tmp_path):
    result_path = tmp_path / "trust-result.json"
    attestation_path = tmp_path / "verified-attestation.json"
    runner = FakeRunner()
    with pytest.raises(trust.PDDCosignTrustError, match="policy is provisional"):
        trust.verify_pdd(
            pdd_ref=PDD_REF,
            result_output=result_path,
            expected_predicate_path=_write(
                tmp_path / "expected.json", _statement()["predicate"]
            ),
            attestation_output=attestation_path,
            policy_path=_policy(tmp_path),
            runner=runner,
            verified_at=datetime(2026, 11, 16, tzinfo=timezone.utc),
        )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["artifact"]["kind"] == "pdd"
    assert result["artifact"]["immutable_reference"] == PDD_REF
    assert result["decision"] == {
        "status": "rejected",
        "reason_codes": [trust.PROVISIONAL_REASON],
    }
    assert attestation_path.is_file()
    checks = [
        call
        for call in runner.calls
        if len(call) > 1 and call[1] in ("verify", "verify-attestation")
    ]
    assert len(checks) == 4
    for command in checks:
        assert "--certificate-identity" in command
        assert "--certificate-oidc-issuer" in command
        assert "--certificate-github-workflow-trigger" in command
        assert "--certificate-github-workflow-repository" in command
        assert "--certificate-github-workflow-ref" in command
        assert "--insecure-ignore-tlog" not in command
        assert "--check-claims=false" not in command
    assert checks[-1][checks[-1].index("--certificate-github-workflow-sha") + 1] == SOURCE_COMMIT


def test_verify_accepts_confirmed_policy(tmp_path):
    result = trust.verify_pdd(
        pdd_ref=PDD_REF,
        result_output=tmp_path / "result.json",
        expected_predicate_path=_write(
            tmp_path / "expected.json", _statement()["predicate"]
        ),
        policy_path=_policy(tmp_path, status="confirmed"),
        runner=FakeRunner(),
        verified_at=datetime(2026, 11, 16, tzinfo=timezone.utc),
    )
    assert result["decision"] == {"status": "trusted", "reason_codes": []}
    assert result["attestations"][0]["subject_digest"] == PDD_DIGEST


def test_verify_rejects_changed_expected_predicate(tmp_path):
    expected = _statement()["predicate"]
    expected["lock_sha256"] = "0" * 64
    runner = FakeRunner()
    with pytest.raises(trust.PDDCosignTrustError, match="differs from"):
        trust.verify_pdd(
            pdd_ref=PDD_REF,
            result_output=tmp_path / "result.json",
            expected_predicate_path=_write(tmp_path / "expected.json", expected),
            policy_path=_policy(tmp_path, status="confirmed"),
            runner=runner,
        )


def test_verify_rejects_cosign_version_mismatch(tmp_path):
    def wrong_version(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, "GitVersion: v3.0.0", "")

    with pytest.raises(trust.image_trust.CosignTrustError, match="v3.1.4 is required"):
        trust.verify_pdd(
            pdd_ref=PDD_REF,
            result_output=tmp_path / "result.json",
            expected_predicate_path=_write(
                tmp_path / "expected.json", _statement()["predicate"]
            ),
            policy_path=_policy(tmp_path, status="confirmed"),
            runner=wrong_version,
        )


def test_verify_rejects_cosign_command_failure(tmp_path):
    def failed(args, **kwargs):
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, "GitVersion: v3.1.4", "")
        return subprocess.CompletedProcess(args, 1, "", "verification failed")

    with pytest.raises(trust.image_trust.CosignTrustError, match="verification failed"):
        trust.verify_pdd(
            pdd_ref=PDD_REF,
            result_output=tmp_path / "result.json",
            expected_predicate_path=_write(
                tmp_path / "expected.json", _statement()["predicate"]
            ),
            policy_path=_policy(tmp_path, status="confirmed"),
            runner=failed,
        )
