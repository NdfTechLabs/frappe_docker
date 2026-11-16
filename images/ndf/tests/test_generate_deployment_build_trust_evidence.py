from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import generate_deployment_build_trust_evidence as generator  # noqa: E402

SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"
CANDIDATE_ID = "CAND-2026-00042"
CORRELATION_ID = "4f9b4c7e-2c10-4c9e-9e3d-8a0d5f2e7b61"
CANDIDATE_DIGEST = "sha256:" + "a" * 64
PAYLOAD_SHA = "b" * 64
RUN_ID = "123456"
ATTEMPT = 2
SOURCE_COMMIT = "c" * 40
CANDIDATE_REPOSITORY = generator.CANDIDATE_REPOSITORY


def _result():
    return {
        "schema_version": "1.0.0",
        "result_id": f"ndf-{RUN_ID}-{ATTEMPT}",
        "candidate_id": CANDIDATE_ID,
        "candidate_artifact_ref": f"{CANDIDATE_REPOSITORY}@{CANDIDATE_DIGEST}",
        "candidate_artifact_digest": CANDIDATE_DIGEST,
        "candidate_payload_sha256": PAYLOAD_SHA,
        "correlation_id": CORRELATION_ID,
        "workflow": {
            "repository": "NdfTechLabs/frappe_docker",
            "workflow_name": "NDF / Build Deployment Candidate",
            "run_id": RUN_ID,
            "run_attempt": ATTEMPT,
            "run_url": f"https://github.com/NdfTechLabs/frappe_docker/actions/runs/{RUN_ID}",
            "source_commit": SOURCE_COMMIT,
        },
        "status": "failed",
        "started_at": "2026-11-17T00:00:00Z",
        "completed_at": "2026-11-17T00:01:00Z",
        "failure": {
            "code": "CANDIDATE_ORIGIN_TRUST_FAILED",
            "summary": "Candidate origin verification failed.",
        },
    }


def _origin(decision="verified"):
    signature = b'{"verified":true}\n'
    attestation = b'{"statement":"verified"}\n'
    return {
        "schema_version": "1.0.0",
        "decision": decision,
        "reason_code": (
            "CANDIDATE_ORIGIN_VERIFIED"
            if decision == "verified"
            else "IDENTITY_POLICY_PROVISIONAL"
        ),
        "candidate_id": CANDIDATE_ID,
        "correlation_id": CORRELATION_ID,
        "subject": {
            "repository": CANDIDATE_REPOSITORY,
            "digest": CANDIDATE_DIGEST,
        },
        "payload_sha256": PAYLOAD_SHA,
        "producer": (
            {
                "repository": "NdfTechLabs/dt_master",
                "workflow_path": ".github/workflows/publish-deployment-candidate.yml",
                "workflow_ref": "NdfTechLabs/dt_master/.github/workflows/publish-deployment-candidate.yml@refs/heads/main",
                "source_commit": "d" * 40,
                "run_id": "987654",
                "run_attempt": 1,
            }
            if decision == "verified"
            else None
        ),
        "evidence_references": (
            [
                {
                    "kind": "cosign_signature",
                    "reference": "candidate-origin-signature-verification.json",
                    "sha256": hashlib.sha256(signature).hexdigest(),
                },
                {
                    "kind": "candidate_origin_attestation",
                    "reference": "candidate-origin-attestation.json",
                    "sha256": hashlib.sha256(attestation).hexdigest(),
                },
            ]
            if decision == "verified"
            else []
        ),
    }


def _write_inputs(tmp_path, *, decision="verified", origin=True):
    result_path = tmp_path / generator.RESULT_FILENAME
    result_path.write_text(json.dumps(_result(), sort_keys=True) + "\n", encoding="utf-8")
    evidence_dir = tmp_path / "origin-evidence"
    evidence_dir.mkdir()
    signature = b'{"verified":true}\n'
    attestation = b'{"statement":"verified"}\n'
    (evidence_dir / "candidate-origin-signature-verification.json").write_bytes(signature)
    (evidence_dir / "candidate-origin-attestation.json").write_bytes(attestation)
    origin_path = None
    if origin:
        origin_path = tmp_path / "candidate-origin-verification-result.json"
        origin_path.write_text(json.dumps(_origin(decision)), encoding="utf-8")
    return result_path, origin_path, evidence_dir


def _generate(tmp_path, *, decision="verified", origin=True):
    result_path, origin_path, evidence_dir = _write_inputs(
        tmp_path, decision=decision, origin=origin
    )
    report = generator.generate_report(
        result_path=result_path,
        origin_result_path=origin_path,
        origin_evidence_dir=evidence_dir,
        schema_path=SCHEMAS / "deployment-build-trust-evidence-v1.schema.json",
    )
    return report, result_path, origin_path, evidence_dir


def test_verified_report_binds_exact_result_and_candidate_origin_evidence(tmp_path):
    report, result_path, _, _ = _generate(tmp_path)

    assert report["report_id"] == f"ndf-{RUN_ID}-{ATTEMPT}-trust"
    assert report["candidate_id"] == CANDIDATE_ID
    assert report["correlation_id"] == CORRELATION_ID
    assert report["result_binding"]["result_id"] == f"ndf-{RUN_ID}-{ATTEMPT}"
    assert report["result_binding"]["result_file"] == generator.RESULT_FILENAME
    assert report["result_binding"]["result_sha256"] == hashlib.sha256(
        result_path.read_bytes()
    ).hexdigest()
    assert report["workflow"] == {
        "repository": "NdfTechLabs/frappe_docker",
        "run_id": RUN_ID,
        "run_attempt": ATTEMPT,
        "source_commit": SOURCE_COMMIT,
    }
    assert report["candidate_origin"]["decision"] == "verified"
    assert {item["kind"] for item in report["candidate_origin"]["evidence_references"]} == {
        "cosign_signature",
        "candidate_origin_attestation",
    }
    assert "ndf_artifacts" not in report


def test_provisional_origin_is_reported_as_rejected_not_verified(tmp_path):
    report, _, _, _ = _generate(tmp_path, decision="rejected")

    assert report["candidate_origin"]["decision"] == "rejected"
    assert report["candidate_origin"]["reason_code"] == "IDENTITY_POLICY_PROVISIONAL"
    assert report["candidate_origin"]["evidence_references"] == []


def test_missing_origin_result_is_explicitly_not_evaluated(tmp_path):
    report, _, _, _ = _generate(tmp_path, origin=False)

    assert report["candidate_origin"]["decision"] == "not_evaluated"
    assert report["candidate_origin"]["reason_code"] == "NOT_EVALUATED"
    assert report["candidate_origin"]["subject"]["digest"] == CANDIDATE_DIGEST
    assert report["candidate_origin"]["evidence_references"] == []


@pytest.mark.parametrize("field", ["candidate_id", "correlation_id", "payload_sha256"])
def test_origin_identity_must_match_terminal_result(tmp_path, field):
    _, origin_path, evidence_dir = _write_inputs(tmp_path)
    origin = _origin()
    origin[field] = "different" if field != "payload_sha256" else "e" * 64
    origin_path.write_text(json.dumps(origin), encoding="utf-8")

    with pytest.raises(generator.TrustEvidenceError):
        generator.generate_report(
            result_path=tmp_path / generator.RESULT_FILENAME,
            origin_result_path=origin_path,
            origin_evidence_dir=evidence_dir,
            schema_path=SCHEMAS / "deployment-build-trust-evidence-v1.schema.json",
        )


def test_origin_subject_digest_must_match_terminal_result(tmp_path):
    _, _, origin_path, evidence_dir = _write_inputs(tmp_path)
    origin = _origin()
    origin["subject"]["digest"] = "sha256:" + "e" * 64
    origin_path.write_text(json.dumps(origin), encoding="utf-8")

    with pytest.raises(generator.TrustEvidenceError, match="subject digest"):
        generator.generate_report(
            result_path=tmp_path / generator.RESULT_FILENAME,
            origin_result_path=origin_path,
            origin_evidence_dir=evidence_dir,
            schema_path=SCHEMAS / "deployment-build-trust-evidence-v1.schema.json",
        )


def test_evidence_hash_mismatch_is_rejected(tmp_path):
    _, _, _, evidence_dir = _write_inputs(tmp_path)
    (evidence_dir / "candidate-origin-attestation.json").write_text("tampered")

    with pytest.raises(generator.TrustEvidenceError, match="SHA-256 mismatch"):
        _generate_from_existing(tmp_path, evidence_dir)


def test_missing_evidence_file_is_rejected(tmp_path):
    _, _, _, evidence_dir = _write_inputs(tmp_path)
    (evidence_dir / "candidate-origin-attestation.json").unlink()

    with pytest.raises(generator.TrustEvidenceError, match="missing"):
        _generate_from_existing(tmp_path, evidence_dir)


def test_path_traversal_evidence_reference_is_rejected(tmp_path):
    _, _, origin_path, evidence_dir = _write_inputs(tmp_path)
    origin = _origin()
    origin["evidence_references"][0]["reference"] = "../outside.json"
    origin_path.write_text(json.dumps(origin), encoding="utf-8")

    with pytest.raises(generator.TrustEvidenceError, match="safe relative path"):
        _generate_from_existing(tmp_path, evidence_dir)


def test_symlink_evidence_file_is_rejected(tmp_path):
    _, _, origin_path, evidence_dir = _write_inputs(tmp_path)
    target = tmp_path / "outside.json"
    target.write_text("outside")
    evidence = evidence_dir / "candidate-origin-attestation.json"
    evidence.unlink()
    evidence.symlink_to(target)

    with pytest.raises(generator.TrustEvidenceError, match="symlink"):
        _generate_from_existing(tmp_path, evidence_dir)


def test_duplicate_json_keys_are_rejected(tmp_path):
    result_path = tmp_path / generator.RESULT_FILENAME
    result_path.write_text('{"candidate_id":"one","candidate_id":"two"}')
    with pytest.raises(generator.TrustEvidenceError, match="duplicate JSON key"):
        generator._read_json(result_path, "test result")


def test_result_bytes_are_hashed_without_json_reserialization(tmp_path):
    result_path, origin_path, evidence_dir = _write_inputs(tmp_path)
    raw = result_path.read_bytes()
    result_path.write_bytes(raw.replace(b'"status": "failed"', b'"status":"failed"'))

    report = generator.generate_report(
        result_path=result_path,
        origin_result_path=origin_path,
        origin_evidence_dir=evidence_dir,
        schema_path=SCHEMAS / "deployment-build-trust-evidence-v1.schema.json",
    )
    assert report["result_binding"]["result_sha256"] == hashlib.sha256(
        result_path.read_bytes()
    ).hexdigest()


def test_cli_refuses_to_overwrite_existing_report(tmp_path):
    result_path, origin_path, evidence_dir = _write_inputs(tmp_path)
    output = tmp_path / "trust-report.json"
    output.write_text("existing")
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(generator.__file__)),
            "--result",
            str(result_path),
            "--origin-result",
            str(origin_path),
            "--origin-evidence-dir",
            str(evidence_dir),
            "--schema",
            str(SCHEMAS / "deployment-build-trust-evidence-v1.schema.json"),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert "Refusing to overwrite" in completed.stderr
    assert output.read_text() == "existing"


def _generate_from_existing(tmp_path, evidence_dir):
    return generator.generate_report(
        result_path=tmp_path / generator.RESULT_FILENAME,
        origin_result_path=tmp_path / "candidate-origin-verification-result.json",
        origin_evidence_dir=evidence_dir,
        schema_path=SCHEMAS / "deployment-build-trust-evidence-v1.schema.json",
    )
