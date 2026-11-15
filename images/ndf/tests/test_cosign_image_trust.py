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

from scripts import cosign_image_trust as trust


def _statement():
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "ghcr.io/ndftechlabs/dalali",
                "digest": {"sha256": "a" * 64},
            }
        ],
        "predicateType": trust.PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://ndftechlabs.com/buildtypes/frappe-docker-image/v1",
                "externalParameters": {"product_id": "dalali-v16"},
                "resolvedDependencies": [
                    {
                        "uri": "https://github.com/frappe/frappe",
                        "digest": {"gitCommit": "b" * 40},
                        "name": "frappe/frappe",
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/NdfTechLabs/frappe_docker/actions"
                }
            },
            "ndf_build": {
                "schema_version": "1.0.0",
                "product_id": "dalali-v16",
                "platform": "linux/amd64",
                "workflow": {
                    "repository": "NdfTechLabs/frappe_docker",
                    "path": ".github/workflows/ndf-publish-product.yml",
                    "ref": "refs/heads/main",
                    "run_id": "123456",
                    "run_attempt": 1,
                    "source_commit": "c" * 40,
                },
                "lock_sha256": "d" * 64,
                "composition_sha256": "e" * 64,
                "source_revisions": [
                    {"repository": "frappe/frappe", "commit": "b" * 40}
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


def _workflow_env():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "NdfTechLabs/frappe_docker",
        "GITHUB_WORKFLOW_REF": (
            "NdfTechLabs/frappe_docker/"
            ".github/workflows/ndf-publish-product.yml@refs/heads/main"
        ),
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ID": "123456",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": "c" * 40,
    }


def _write_policy(tmp_path, status="provisional_until_live_certificate_observation"):
    policy = json.loads(trust.POLICY_PATH.read_text(encoding="utf-8"))
    policy["status"] = status
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def _write_expected_predicate(tmp_path, statement=None):
    value = (statement or _statement())["predicate"]
    path = tmp_path / "expected-predicate.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


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
            "Verification for ghcr.io/ndftechlabs/dalali --\n"
            + json.dumps(envelope)
            + "\n"
        )

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[1] == "version":
            stdout = "GitVersion: v3.1.4\n"
        elif args[1] == "verify":
            stdout = (
                '[{"Critical":{"Image":{"DockerManifestDigest":"sha256:'
                + "a" * 64
                + '"}}}]'
            )
        elif args[1] == "verify-attestation":
            stdout = self.attestation_output
        else:
            stdout = ""
        return subprocess.CompletedProcess(args, 0, stdout, "")


def test_parse_image_reference_requires_immutable_digest():
    assert trust.parse_image_reference(
        "ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64
    ) == ("ghcr.io/ndftechlabs/dalali", "sha256:" + "a" * 64)


@pytest.mark.parametrize(
    "value",
    [
        "ghcr.io/ndftechlabs/dalali:latest",
        "ghcr.io/ndftechlabs/dalali",
        "ghcr.io/ndftechlabs/dalali:latest@sha256:" + "a" * 64,
        "ghcr.io/ndftechlabs/dalali@sha256:" + "A" * 64,
        "not-a-reference",
    ],
)
def test_parse_image_reference_rejects_mutable_or_malformed_reference(value):
    with pytest.raises(trust.CosignTrustError):
        trust.parse_image_reference(value)


def test_cosign_version_must_match_contract():
    def wrong_version(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, "GitVersion: v3.0.0", "")

    with pytest.raises(trust.CosignTrustError, match="v3.1.4 is required"):
        trust._require_cosign_version(runner=wrong_version)


def test_sign_requires_github_actions_and_exact_provenance(tmp_path):
    statement = _statement()
    statement_path = tmp_path / "statement.json"
    predicate_path = tmp_path / "predicate.json"
    statement_path.write_text(json.dumps(statement), encoding="utf-8")
    predicate_path.write_text(json.dumps(statement["predicate"]), encoding="utf-8")
    policy_path = _write_policy(tmp_path)
    runner = FakeRunner(statement)

    result = trust.sign_image(
        image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
        predicate_path=predicate_path,
        statement_path=statement_path,
        env=_workflow_env(),
        policy_path=policy_path,
        runner=runner,
    )

    assert result["status"] == "signed"
    assert [call[1] for call in runner.calls] == ["version", "sign", "attest"]
    assert "--yes" in runner.calls[1]
    assert "--type" in runner.calls[2]
    assert runner.calls[2][runner.calls[2].index("--type") + 1] == trust.PREDICATE_TYPE
    assert "slsaprovenance1" not in runner.calls[2]


def test_sign_rejects_local_execution(tmp_path):
    statement = _statement()
    statement_path = tmp_path / "statement.json"
    predicate_path = tmp_path / "predicate.json"
    statement_path.write_text(json.dumps(statement), encoding="utf-8")
    predicate_path.write_text(json.dumps(statement["predicate"]), encoding="utf-8")

    with pytest.raises(trust.CosignTrustError, match="only inside GitHub Actions"):
        trust.sign_image(
            image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
            predicate_path=predicate_path,
            statement_path=statement_path,
            env={},
            runner=FakeRunner(statement),
        )


def test_sign_rejects_predicate_statement_disagreement(tmp_path):
    statement = _statement()
    statement_path = tmp_path / "statement.json"
    predicate_path = tmp_path / "predicate.json"
    statement_path.write_text(json.dumps(statement), encoding="utf-8")
    predicate_path.write_text("{}", encoding="utf-8")

    with pytest.raises(trust.CosignTrustError, match="does not exactly match"):
        trust.sign_image(
            image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
            predicate_path=predicate_path,
            statement_path=statement_path,
            env=_workflow_env(),
            runner=FakeRunner(statement),
        )


def test_cosign_v01_compatibility_schema_requires_complete_ndf_profile():
    statement = _statement()
    statement["_type"] = "https://in-toto.io/Statement/v0.1"
    del statement["predicate"]["ndf_build"]
    with pytest.raises(
        trust.CosignTrustError, match="Image provenance statement is invalid"
    ):
        trust._validate_cosign_statement(
            statement,
            repository="ghcr.io/ndftechlabs/dalali",
            digest="sha256:" + "a" * 64,
        )


def test_extract_verified_statement_decodes_dsse_envelope():
    statement = _statement()
    cosign_statement = dict(statement)
    cosign_statement["_type"] = "https://in-toto.io/Statement/v0.1"
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(cosign_statement).encode()).decode(),
    }
    assert (
        trust.extract_verified_statement("header\n" + json.dumps(envelope))
        == cosign_statement
    )


def test_statement_candidate_parser_accepts_only_cosign_v01():
    statement = _statement()
    with pytest.raises(trust.CosignTrustError, match="found 0"):
        trust.extract_verified_statement(json.dumps(statement))


@pytest.mark.parametrize(
    "stdout",
    ["", "not-json", '{"payloadType":"application/vnd.in-toto+json","payload":"%%%"}'],
)
def test_extract_verified_statement_rejects_empty_or_malformed_output(stdout):
    with pytest.raises(trust.CosignTrustError):
        trust.extract_verified_statement(stdout)


def test_verify_uses_exact_identity_and_rejects_provisional_policy(tmp_path):
    policy_path = _write_policy(tmp_path)
    runner = FakeRunner()
    output = tmp_path / "trust-result.json"
    attestation_output = tmp_path / "verified-attestation-output.json"

    with pytest.raises(trust.CosignTrustError, match="policy is provisional"):
        trust.verify_image(
            image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
            result_output=output,
            attestation_output=attestation_output,
            expected_predicate_path=_write_expected_predicate(tmp_path),
            policy_path=policy_path,
            runner=runner,
            verified_at=datetime(2026, 11, 15, tzinfo=timezone.utc),
        )

    assert attestation_output.read_text(encoding="utf-8") == runner.attestation_output
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["decision"] == {
        "status": "rejected",
        "reason_codes": ["IDENTITY_POLICY_PROVISIONAL"],
    }
    commands = [
        call
        for call in runner.calls
        if len(call) > 1 and call[1] in ("verify", "verify-attestation")
    ]
    assert len(commands) == 4
    for command in commands:
        if command[1] == "verify-attestation":
            assert command[command.index("--type") + 1] == trust.PREDICATE_TYPE
        assert "--certificate-identity" in command
        assert "--certificate-oidc-issuer" in command
        assert "--certificate-github-workflow-trigger" in command
        assert "--certificate-github-workflow-repository" in command
        assert "--certificate-github-workflow-ref" in command
        assert "--insecure-ignore-tlog" not in command
        assert "--check-claims=false" not in command
    assert (
        commands[-1][commands[-1].index("--certificate-github-workflow-sha") + 1]
        == "c" * 40
    )


def test_verify_trusts_only_confirmed_policy(tmp_path):
    policy_path = _write_policy(tmp_path, status="confirmed")
    output = tmp_path / "trust-result.json"
    result = trust.verify_image(
        image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
        result_output=output,
        policy_path=policy_path,
        expected_predicate_path=_write_expected_predicate(tmp_path),
        runner=FakeRunner(),
        verified_at=datetime(2026, 11, 15, tzinfo=timezone.utc),
    )
    assert result["decision"] == {"status": "trusted", "reason_codes": []}
    assert json.loads(output.read_text(encoding="utf-8")) == result


def test_verify_rejects_attestation_for_another_digest(tmp_path):
    statement = _statement()
    statement["subject"][0]["digest"]["sha256"] = "f" * 64
    output = tmp_path / "trust-result.json"
    with pytest.raises(trust.CosignTrustError, match="subject digest mismatch"):
        trust.verify_image(
            image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
            result_output=output,
            policy_path=_write_policy(tmp_path, status="confirmed"),
            expected_predicate_path=_write_expected_predicate(tmp_path),
            runner=FakeRunner(statement),
        )


def test_verify_rejects_any_change_to_original_ndf_predicate(tmp_path):
    statement = _statement()
    statement["predicate"]["ndf_build"]["composition_sha256"] = "f" * 64
    expected = _write_expected_predicate(tmp_path)
    with pytest.raises(
        trust.CosignTrustError,
        match="differs from the original NDF provenance predicate",
    ):
        trust.verify_image(
            image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
            result_output=tmp_path / "result.json",
            expected_predicate_path=expected,
            policy_path=_write_policy(tmp_path, status="confirmed"),
            runner=FakeRunner(statement),
        )


def test_verify_rejects_cosign_command_failure(tmp_path):
    def failed(args, **kwargs):
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, "GitVersion: v3.1.4", "")
        return subprocess.CompletedProcess(args, 1, "", "verification failed")

    with pytest.raises(trust.CosignTrustError, match="verification failed"):
        trust.verify_image(
            image_ref="ghcr.io/ndftechlabs/dalali@sha256:" + "a" * 64,
            result_output=tmp_path / "result.json",
            policy_path=_write_policy(tmp_path, status="confirmed"),
            expected_predicate_path=_write_expected_predicate(tmp_path),
            runner=failed,
        )
