import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "images" / "ndf" / "scripts" / "write_deployment_build_result.py"
SCHEMA = ROOT / "images" / "ndf" / "schemas" / "deployment-build-result-v1.schema.json"
CANDIDATE_DIGEST = "a" * 64
PAYLOAD_HASH = "b" * 64
LOCK_HASH = "c" * 64
COMPOSITION_HASH = "d" * 64
IMAGE_DIGEST = "sha256:" + "e" * 64
PDD_DIGEST = "sha256:" + "f" * 64


def base_env():
    return {
        **os.environ,
        "GITHUB_RUN_ID": "123456",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_REPOSITORY": "NdfTechLabs/frappe_docker",
        "GITHUB_WORKFLOW": "NDF / Build Deployment Candidate",
        "GITHUB_SHA": "1" * 40,
        "CANDIDATE_ID": "CAND-2026-00042",
        "CANDIDATE_ARTIFACT_REF": (
            "ghcr.io/ndftechlabs/dt-master-deployment-candidates@sha256:"
            + CANDIDATE_DIGEST
        ),
        "CANDIDATE_PAYLOAD_SHA256": PAYLOAD_HASH,
        "CORRELATION_ID": "4f9b4c7e-2c10-4c9e-9e3d-8a0d5f2e7b61",
        "WORKFLOW_RUN_URL": "https://github.com/NdfTechLabs/frappe_docker/actions/runs/123456",
        "WORKFLOW_STARTED_AT": "2026-11-15T10:00:00Z",
        "DISPATCH_GATE_RESULT": "success",
        "PREPARE_RESULT": "success",
        "BUILD_RESULT": "success",
        "PDD_RESULT": "success",
        "IMAGE_ID": "dalali",
        "LOCK_SHA256": LOCK_HASH,
        "COMPOSITION_HASH": COMPOSITION_HASH,
        "IMAGE_DIGEST": IMAGE_DIGEST,
        "PDD_REFERENCE": "ghcr.io/ndftechlabs/pdd/dalali@" + PDD_DIGEST,
        "PDD_DIGEST": PDD_DIGEST,
        "PDD_CONTENT_SHA256": "9" * 64,
    }


def invoke(tmp_path, env):
    output = tmp_path / "deployment-build-result.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--schema",
            str(SCHEMA),
            "--output",
            str(output),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed, output


def test_success_result_binds_candidate_attempt_image_and_pdd(tmp_path):
    completed, output = invoke(tmp_path, base_env())
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "succeeded"
    assert result["result_id"] == "ndf-123456-2"
    assert result["candidate_artifact_digest"] == "sha256:" + CANDIDATE_DIGEST
    assert result["candidate_payload_sha256"] == PAYLOAD_HASH
    assert result["correlation_id"] == "4f9b4c7e-2c10-4c9e-9e3d-8a0d5f2e7b61"
    assert result["workflow"]["run_attempt"] == 2
    assert result["image"]["digest"] == IMAGE_DIGEST
    assert result["descriptor"]["digest"] == PDD_DIGEST
    assert result["provenance_ref"] == result["workflow"]["run_url"]


def test_failed_stage_produces_sanitized_terminal_result(tmp_path):
    env = base_env()
    env["BUILD_RESULT"] = "failure"
    env["PDD_RESULT"] = "skipped"
    completed, output = invoke(tmp_path, env)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "failed"
    assert result["failure"]["code"] == "IMAGE_BUILD_OR_VERIFICATION_FAILED"
    assert "stack" not in result["failure"]["summary"].lower()


def test_cancelled_attempt_produces_cancelled_result(tmp_path):
    env = base_env()
    env["PREPARE_RESULT"] = "cancelled"
    env["BUILD_RESULT"] = "skipped"
    env["PDD_RESULT"] = "skipped"
    completed, output = invoke(tmp_path, env)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "cancelled"
    assert result["failure"]["code"] == "WORKFLOW_CANCELLED"


def test_invalid_candidate_reference_fails_closed(tmp_path):
    env = base_env()
    env["CANDIDATE_ARTIFACT_REF"] = (
        "ghcr.io/ndftechlabs/dt-master-deployment-candidates:latest"
    )
    completed, _ = invoke(tmp_path, env)
    assert completed.returncode != 0
    assert "immutable GHCR reference" in completed.stderr


def test_result_writer_refuses_to_overwrite_attempt_result(tmp_path):
    env = base_env()
    output = tmp_path / "deployment-build-result.json"
    output.write_text("existing", encoding="utf-8")
    completed, _ = invoke(tmp_path, env)
    assert completed.returncode != 0
    assert "Refusing to overwrite" in completed.stderr


@pytest.mark.parametrize(
    ("failed_stage", "expected_code"),
    [
        ("DISPATCH_GATE_RESULT", "DISPATCH_NOT_AUTHORIZED"),
        ("PREPARE_RESULT", "CANDIDATE_INTAKE_FAILED"),
        ("BUILD_RESULT", "IMAGE_BUILD_OR_VERIFICATION_FAILED"),
        ("PDD_RESULT", "PDD_PUBLICATION_FAILED"),
    ],
)
def test_each_required_stage_failure_produces_failed_result(
    tmp_path, failed_stage, expected_code
):
    env = base_env()
    env[failed_stage] = "failure"
    completed, output = invoke(tmp_path, env)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "failed"
    assert result["failure"]["code"] == expected_code
    assert "stack trace" not in result["failure"]["summary"].lower()
    assert "registry password" not in result["failure"]["summary"].lower()


def test_successful_stages_with_missing_image_evidence_fail_closed(tmp_path):
    env = base_env()
    env["IMAGE_DIGEST"] = ""
    completed, output = invoke(tmp_path, env)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "failed"
    assert result["failure"]["code"] == "RESULT_EVIDENCE_INVALID"
    assert "provenance_ref" not in result


def test_successful_stages_with_malformed_lock_hash_fail_closed(tmp_path):
    env = base_env()
    env["LOCK_SHA256"] = "not-a-sha256"
    completed, output = invoke(tmp_path, env)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "failed"
    assert result["failure"]["code"] == "RESULT_EVIDENCE_INVALID"


def test_invalid_candidate_payload_hash_fails_closed(tmp_path):
    env = base_env()
    env["CANDIDATE_PAYLOAD_SHA256"] = "not-a-sha256"
    completed, _ = invoke(tmp_path, env)
    assert completed.returncode != 0
    assert "payload SHA-256 is invalid" in completed.stderr


def test_pdd_reference_digest_mismatch_fails_closed(tmp_path):
    env = base_env()
    env["PDD_REFERENCE"] = "ghcr.io/ndftechlabs/pdd/dalali@sha256:" + "0" * 64
    completed, _ = invoke(tmp_path, env)
    assert completed.returncode != 0
    assert "PDD reference and digest outputs do not agree" in completed.stderr


def test_new_run_attempt_gets_a_distinct_result_identity(tmp_path):
    first_env = base_env()
    first, first_output = invoke(tmp_path, first_env)
    assert first.returncode == 0, first.stderr

    second_dir = tmp_path / "attempt-3"
    second_dir.mkdir()
    second_env = base_env()
    second_env["GITHUB_RUN_ATTEMPT"] = "3"
    second, second_output = invoke(second_dir, second_env)
    assert second.returncode == 0, second.stderr

    first_result = json.loads(first_output.read_text(encoding="utf-8"))
    second_result = json.loads(second_output.read_text(encoding="utf-8"))
    assert first_result["result_id"] == "ndf-123456-2"
    assert second_result["result_id"] == "ndf-123456-3"
    assert (
        first_result["workflow"]["run_attempt"]
        != second_result["workflow"]["run_attempt"]
    )


def test_missing_correlation_id_fails_closed(tmp_path):
    env = base_env()
    env.pop("CORRELATION_ID")
    completed, _ = invoke(tmp_path, env)
    assert completed.returncode != 0
    assert "CORRELATION_ID" in completed.stderr


@pytest.mark.parametrize(
    "value", ["master-request-42", "4F9B4C7E-2C10-4C9E-9E3D-8A0D5F2E7B61"]
)
def test_noncanonical_correlation_id_fails_closed(tmp_path, value):
    env = base_env()
    env["CORRELATION_ID"] = value
    completed, _ = invoke(tmp_path, env)
    assert completed.returncode != 0
    assert "canonical lowercase UUID" in completed.stderr


@pytest.mark.parametrize("candidate_id", ["bad id", "A" + "a" * 140, "-invalid"])
def test_candidate_id_must_match_shared_contract(tmp_path, candidate_id):
    env = base_env()
    env["CANDIDATE_ID"] = candidate_id
    completed, _ = invoke(tmp_path, env)
    assert completed.returncode != 0
    assert "shared 140-character contract" in completed.stderr
