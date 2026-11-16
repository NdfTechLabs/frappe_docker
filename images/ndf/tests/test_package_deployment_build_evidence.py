from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import package_deployment_build_evidence as bundle  # noqa: E402

SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"
CORRELATION_ID = "4f9b4c7e-2c10-4c9e-9e3d-8a0d5f2e7b61"
RUN_ID = "123456"
ATTEMPT = 2
SOURCE_COMMIT = "c" * 40
CANDIDATE_ID = "CAND-2026-00042"


def _inputs(tmp_path: Path):
    result = {
        "schema_version": "1.0.0",
        "result_id": f"ndf-{RUN_ID}-{ATTEMPT}",
        "candidate_id": CANDIDATE_ID,
        "candidate_artifact_ref": "ghcr.io/ndftechlabs/dt-master-deployment-candidates@sha256:" + "a" * 64,
        "candidate_artifact_digest": "sha256:" + "a" * 64,
        "candidate_payload_sha256": "b" * 64,
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
        "failure": {"code": "CANDIDATE_ORIGIN_TRUST_FAILED", "summary": "Origin rejected."},
    }
    result_bytes = (json.dumps(result, sort_keys=True) + "\n").encode()
    evidence = b'{"verified":true}\n'
    report = {
        "schema_version": "1.0.0",
        "report_id": f"ndf-{RUN_ID}-{ATTEMPT}-trust",
        "candidate_id": CANDIDATE_ID,
        "correlation_id": CORRELATION_ID,
        "result_binding": {
            "result_id": result["result_id"],
            "result_file": bundle.RESULT_FILENAME,
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        },
        "workflow": {
            "repository": "NdfTechLabs/frappe_docker",
            "run_id": RUN_ID,
            "run_attempt": ATTEMPT,
            "source_commit": SOURCE_COMMIT,
        },
        "candidate_origin": {
            "verifier": "NDF",
            "decision": "rejected",
            "reason_code": "IDENTITY_POLICY_PROVISIONAL",
            "subject": {
                "repository": "ghcr.io/ndftechlabs/dt-master-deployment-candidates",
                "digest": "sha256:" + "a" * 64,
            },
            "payload_sha256": "b" * 64,
            "evidence_references": [],
        },
    }
    result_path = tmp_path / "input-result.json"
    report_path = tmp_path / "input-report.json"
    result_path.write_bytes(result_bytes)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    evidence_root = tmp_path / "source-evidence"
    evidence_root.mkdir()
    (evidence_root / "candidate-origin.json").write_bytes(evidence)
    return result_path, report_path, evidence_root, result, report


def _add_verified_evidence(result_path: Path, report_path: Path, evidence_root: Path):
    signature = b'{"signature":"verified"}\\n'
    attestation = b'{"attestation":"verified"}\\n'
    (evidence_root / "signature.json").write_bytes(signature)
    (evidence_root / "attestation.json").write_bytes(attestation)
    result_bytes = result_path.read_bytes()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["candidate_origin"]["decision"] = "verified"
    report["candidate_origin"]["reason_code"] = "CANDIDATE_ORIGIN_VERIFIED"
    report["candidate_origin"]["evidence_references"] = [
        {
            "kind": "cosign_signature",
            "reference": "signature.json",
            "sha256": hashlib.sha256(signature).hexdigest(),
        },
        {
            "kind": "candidate_origin_attestation",
            "reference": "attestation.json",
            "sha256": hashlib.sha256(attestation).hexdigest(),
        },
    ]
    report["result_binding"]["result_sha256"] = hashlib.sha256(result_bytes).hexdigest()
    report_path.write_text(json.dumps(report), encoding="utf-8")


def _pack(tmp_path: Path):
    result, report, evidence, _, _ = _inputs(tmp_path)
    output = tmp_path / "bundle"
    manifest = bundle.pack_bundle(
        result_path=result,
        report_path=report,
        evidence_root=evidence,
        schema_dir=SCHEMAS,
        output_dir=output,
    )
    return output, manifest


def test_pack_and_verify_attempt_scoped_bundle(tmp_path):
    output, manifest = _pack(tmp_path)

    assert manifest["bundle_id"] == f"ndf-{RUN_ID}-{ATTEMPT}-evidence"
    assert {item["role"] for item in manifest["files"]} == {"result", "trust_evidence"}
    verified = bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)
    assert verified["transport_integrity"] == "verified"
    assert verified["candidate_id"] == CANDIDATE_ID
    assert verified["workflow"]["run_attempt"] == ATTEMPT


def test_pack_includes_report_referenced_evidence(tmp_path):
    result_path, report_path, evidence_root, _, _ = _inputs(tmp_path)
    _add_verified_evidence(result_path, report_path, evidence_root)

    output = tmp_path / "bundle"
    bundle.pack_bundle(
        result_path=result_path,
        report_path=report_path,
        evidence_root=evidence_root,
        schema_dir=SCHEMAS,
        output_dir=output,
    )
    assert (output / "evidence/signature.json").is_file()
    assert (output / "evidence/attestation.json").is_file()
    assert bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)["file_count"] == 5


def test_packer_rejects_missing_referenced_evidence(tmp_path):
    result, report, evidence, _, _ = _inputs(tmp_path)
    _add_verified_evidence(result, report, evidence)
    (evidence / "attestation.json").unlink()
    with pytest.raises(bundle.EvidenceBundleError, match="missing or escapes"):
        bundle.pack_bundle(
            result_path=result,
            report_path=report,
            evidence_root=evidence,
            schema_dir=SCHEMAS,
            output_dir=tmp_path / "bundle",
        )


def test_packer_rejects_unsafe_evidence_reference(tmp_path):
    result, report_path, evidence, _, _ = _inputs(tmp_path)
    _add_verified_evidence(result, report_path, evidence)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["candidate_origin"]["evidence_references"][0]["reference"] = "../outside.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(bundle.EvidenceBundleError, match="safe relative path"):
        bundle.pack_bundle(
            result_path=result,
            report_path=report_path,
            evidence_root=evidence,
            schema_dir=SCHEMAS,
            output_dir=tmp_path / "bundle",
        )


def test_packer_rejects_evidence_hash_mismatch(tmp_path):
    result, report, evidence, _, _ = _inputs(tmp_path)
    _add_verified_evidence(result, report, evidence)
    (evidence / "attestation.json").write_text("changed")
    with pytest.raises(bundle.EvidenceBundleError, match="SHA-256 differs"):
        bundle.pack_bundle(
            result_path=result,
            report_path=report,
            evidence_root=evidence,
            schema_dir=SCHEMAS,
            output_dir=tmp_path / "bundle",
        )


def test_packer_rejects_symlinked_evidence_source(tmp_path):
    result, report, evidence, _, _ = _inputs(tmp_path)
    _add_verified_evidence(result, report, evidence)
    outside = tmp_path / "outside"
    outside.write_text("secret")
    (evidence / "signature.json").unlink()
    (evidence / "signature.json").symlink_to(outside)
    with pytest.raises(bundle.EvidenceBundleError, match="symlink"):
        bundle.pack_bundle(
            result_path=result,
            report_path=report,
            evidence_root=evidence,
            schema_dir=SCHEMAS,
            output_dir=tmp_path / "bundle",
        )


def test_verifier_rejects_tampered_result(tmp_path):
    output, _ = _pack(tmp_path)
    (output / bundle.RESULT_FILENAME).write_text("tampered")
    with pytest.raises(bundle.EvidenceBundleError, match="size mismatch|SHA-256 mismatch"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_tampered_referenced_evidence(tmp_path):
    result, report, evidence, _, _ = _inputs(tmp_path)
    _add_verified_evidence(result, report, evidence)
    output = tmp_path / "bundle"
    bundle.pack_bundle(
        result_path=result,
        report_path=report,
        evidence_root=evidence,
        schema_dir=SCHEMAS,
        output_dir=output,
    )
    (output / "evidence/attestation.json").write_text("tampered")
    with pytest.raises(bundle.EvidenceBundleError, match="size mismatch|SHA-256 mismatch"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_missing_report(tmp_path):
    output, _ = _pack(tmp_path)
    (output / bundle.REPORT_FILENAME).unlink()
    with pytest.raises(bundle.EvidenceBundleError, match="file set mismatch"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_unexpected_file(tmp_path):
    output, _ = _pack(tmp_path)
    (output / "extra.txt").write_text("unexpected")
    with pytest.raises(bundle.EvidenceBundleError, match="file set mismatch"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_unexpected_empty_directory(tmp_path):
    output, _ = _pack(tmp_path)
    (output / "unexpected").mkdir()
    with pytest.raises(bundle.EvidenceBundleError, match="unexpected_dirs"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_duplicate_manifest_paths(tmp_path):
    output, manifest = _pack(tmp_path)
    manifest["files"].append(dict(manifest["files"][0]))
    (output / bundle.MANIFEST_FILENAME).write_text(json.dumps(manifest))
    with pytest.raises(bundle.EvidenceBundleError, match="Duplicate bundle path"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_symlinked_bundle_file(tmp_path):
    output, _ = _pack(tmp_path)
    target = tmp_path / "external-result"
    target.write_bytes((output / bundle.RESULT_FILENAME).read_bytes())
    (output / bundle.RESULT_FILENAME).unlink()
    (output / bundle.RESULT_FILENAME).symlink_to(target)
    with pytest.raises(bundle.EvidenceBundleError, match="symlink"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_cross_attempt_manifest_identity(tmp_path):
    output, manifest = _pack(tmp_path)
    manifest["workflow"]["run_attempt"] = ATTEMPT + 1
    manifest["bundle_id"] = f"ndf-{RUN_ID}-{ATTEMPT + 1}-evidence"
    (output / bundle.MANIFEST_FILENAME).write_text(json.dumps(manifest))
    with pytest.raises(bundle.EvidenceBundleError, match="identity differs"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_report_result_binding_mismatch(tmp_path):
    output, manifest = _pack(tmp_path)
    report_path = output / bundle.REPORT_FILENAME
    report = json.loads(report_path.read_text())
    report["result_binding"]["result_sha256"] = "e" * 64
    report_bytes = (json.dumps(report) + "\n").encode()
    report_path.write_bytes(report_bytes)
    report_entry = next(item for item in manifest["files"] if item["role"] == "trust_evidence")
    report_entry["size"] = len(report_bytes)
    report_entry["sha256"] = hashlib.sha256(report_bytes).hexdigest()
    (output / bundle.MANIFEST_FILENAME).write_text(json.dumps(manifest))
    with pytest.raises(bundle.EvidenceBundleError, match="exact terminal result bytes"):
        bundle.verify_bundle(bundle_dir=output, schema_dir=SCHEMAS)


def test_verifier_rejects_symlink_bundle_root(tmp_path):
    output, _ = _pack(tmp_path)
    alias = tmp_path / "bundle-alias"
    alias.symlink_to(output, target_is_directory=True)
    with pytest.raises(bundle.EvidenceBundleError, match="root"):
        bundle.verify_bundle(bundle_dir=alias, schema_dir=SCHEMAS)


def test_packer_refuses_to_overwrite_existing_bundle(tmp_path):
    result, report, evidence, _, _ = _inputs(tmp_path)
    output = tmp_path / "bundle"
    output.mkdir()
    with pytest.raises(bundle.EvidenceBundleError, match="overwrite"):
        bundle.pack_bundle(
            result_path=result,
            report_path=report,
            evidence_root=evidence,
            schema_dir=SCHEMAS,
            output_dir=output,
        )
