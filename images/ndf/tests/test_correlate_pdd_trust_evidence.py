import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import correlate_pdd_trust_evidence as evidence  # noqa: E402
from scripts import cosign_image_trust  # noqa: E402

PDD_REPOSITORY = "ghcr.io/ndftechlabs/dalali-pdd"
PDD_DIGEST = "sha256:" + "b" * 64
IMAGE_REPOSITORY = "ghcr.io/ndftechlabs/dalali"
IMAGE_DIGEST = "sha256:" + "a" * 64
CONTENT_SHA = "c" * 64
SOURCE_COMMIT = "d" * 40
RUN_ID = "987654"
RUN_ATTEMPT = "2"
BUILD_RUN_ID = "123456"
BUILD_ATTEMPT = 3
SIGNING_ARTIFACT = f"ndf-pdd-signing-input-{BUILD_RUN_ID}-{RUN_ATTEMPT}"


def _predicate():
    return {
        "schema_version": "1.0.0",
        "descriptor": {
            "id": "pdd:dalali:linux-amd64:sha256:" + CONTENT_SHA,
            "content_sha256": CONTENT_SHA,
        },
        "subject_image": {
            "repository": IMAGE_REPOSITORY,
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
            "path": ".github/workflows/ndf-publish-product-deployment-descriptor.yml",
            "ref": "refs/heads/main",
            "run_id": RUN_ID,
            "run_attempt": int(RUN_ATTEMPT),
            "source_commit": SOURCE_COMMIT,
        },
    }


def _statement():
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": PDD_REPOSITORY, "digest": {"sha256": "b" * 64}}],
        "predicateType": evidence.cosign_pdd_trust.PREDICATE_TYPE,
        "predicate": _predicate(),
    }


def _receipt():
    return {
        "schema_version": "1.0.0",
        "publication_type": "ndf.product-deployment.publication",
        "descriptor": {
            "id": _predicate()["descriptor"]["id"],
            "schema_version": "1.0.0",
            "content_sha256": CONTENT_SHA,
        },
        "subject_image": _predicate()["subject_image"],
        "artifact": {
            "type": "application/vnd.ndf.product-deployment-descriptor.v1",
            "repository": PDD_REPOSITORY,
            "locator_tag": "pdd-v1-linux-amd64-" + "1" * 64,
            "digest": PDD_DIGEST,
            "immutable_reference": PDD_REPOSITORY + "@" + PDD_DIGEST,
        },
        "evidence": {
            "count": 11,
            "binding_report_sha256": "2" * 64,
            "published_file_count": 16,
        },
        "published_at": "2026-11-16T08:00:00Z",
    }


def _trust_result():
    predicate_hash = hashlib.sha256(
        cosign_image_trust._canonical_json(_predicate())
    ).hexdigest()
    return {
        "schema_version": "1.0.0",
        "verification_id": "verification-123",
        "artifact": {
            "kind": "pdd",
            "repository": PDD_REPOSITORY,
            "digest": PDD_DIGEST,
            "immutable_reference": PDD_REPOSITORY + "@" + PDD_DIGEST,
        },
        "signature": {
            "verified": True,
            "verification_method": "cosign-keyless",
            "signature_reference": PDD_REPOSITORY + "@" + PDD_DIGEST,
        },
        "signer": {
            "verified": True,
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": "https://github.com/NdfTechLabs/frappe_docker/.github/workflows/ndf-publish-product-deployment-descriptor.yml@refs/heads/main",
            "workflow_ref": "NdfTechLabs/frappe_docker/.github/workflows/ndf-publish-product-deployment-descriptor.yml@refs/heads/main",
        },
        "transparency": {"verified": True, "log_entry_verified": True},
        "attestations": [
            {
                "predicate_type": evidence.cosign_pdd_trust.PREDICATE_TYPE,
                "verified": True,
                "subject_digest": PDD_DIGEST,
                "predicate_sha256": predicate_hash,
            }
        ],
        "decision": {
            "status": "rejected",
            "reason_codes": ["IDENTITY_POLICY_PROVISIONAL"],
        },
        "verified_at": "2026-11-16T08:00:00Z",
    }


def _env():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "NdfTechLabs/frappe_docker",
        "GITHUB_WORKFLOW_REF": evidence.cosign_pdd_trust.WORKFLOW_REF,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": RUN_ID,
        "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
        "GITHUB_SHA": SOURCE_COMMIT,
    }


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path


def _bundle(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    _write_json(root / "pdd-publication-record.json", _receipt())
    statement = _statement()
    _write_json(root / "pdd-image-binding-statement.json", statement)
    _write_json(root / "pdd-image-binding-predicate.json", statement["predicate"])
    _write_json(root / "pdd-trust-verification-result.json", _trust_result())
    cosign_statement = dict(statement)
    cosign_statement["_type"] = "https://in-toto.io/Statement/v0.1"
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(
            json.dumps(cosign_statement, separators=(",", ":")).encode()
        ).decode(),
        "signatures": [{"keyid": "", "sig": "c2ln"}],
    }
    (root / "pdd-verified-attestation.json").write_text(
        "Verification for PDD --\n" + json.dumps(envelope) + "\n",
        encoding="utf-8",
    )
    (root / "pdd-verify.log").write_text(
        evidence.EXPECTED_PROVISIONAL_MESSAGE + "\n", encoding="utf-8"
    )
    return root


def _correlate(root, **kwargs):
    return evidence.correlate_evidence(
        evidence_dir=root,
        source_build_run_id=BUILD_RUN_ID,
        source_build_attempt=BUILD_ATTEMPT,
        signing_input_artifact=SIGNING_ARTIFACT,
        env=_env(),
        **kwargs,
    )


def test_correlates_valid_evidence_and_hashes_exact_files(tmp_path):
    root = _bundle(tmp_path)
    manifest = _correlate(root)
    assert manifest["artifact"]["immutable_reference"] == (
        PDD_REPOSITORY + "@" + PDD_DIGEST
    )
    assert manifest["verification"]["decision"] == "rejected"
    assert manifest["verification"]["reason_codes"] == [
        "IDENTITY_POLICY_PROVISIONAL"
    ]
    for name, record in manifest["files"].items():
        raw = (root / name).read_bytes()
        assert record["sha256"] == hashlib.sha256(raw).hexdigest()
        assert record["size_bytes"] == len(raw)
    saved = json.loads((root / evidence.MANIFEST_NAME).read_text())
    assert saved == manifest


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r, s, p, t: r["artifact"].update(digest="sha256:" + "0" * 64), "immutable reference"),
        (lambda r, s, p, t: s["subject"][0]["digest"].update(sha256="0" * 64), "subject digest"),
        (lambda r, s, p, t: p["descriptor"].update(content_sha256="0" * 64), "Predicate file differs"),
        (lambda r, s, p, t: t["artifact"].update(kind="product_image"), "Trust result"),
        (lambda r, s, p, t: t["signature"].update(verified=False), "Cryptographic signature"),
        (lambda r, s, p, t: t["signer"].update(verified=False), "Cryptographic signature"),
        (lambda r, s, p, t: t["transparency"].update(log_entry_verified=False), "Cryptographic signature"),
        (lambda r, s, p, t: t["attestations"][0].update(subject_digest="sha256:" + "0" * 64), "attestation"),
        (lambda r, s, p, t: t["attestations"][0].update(predicate_sha256="0" * 64), "attestation"),
        (lambda r, s, p, t: t.update(decision={"status":"trusted","reason_codes":[]}), "exact provisional"),
        (lambda r, s, p, t: t.update(decision={"status":"rejected","reason_codes":["IDENTITY_POLICY_PROVISIONAL","OTHER"]}), "exact provisional"),
    ],
)
def test_rejects_cross_file_mismatches(tmp_path, mutate, message):
    root = _bundle(tmp_path)
    receipt = json.loads((root / "pdd-publication-record.json").read_text())
    statement = json.loads((root / "pdd-image-binding-statement.json").read_text())
    predicate = json.loads((root / "pdd-image-binding-predicate.json").read_text())
    result = json.loads((root / "pdd-trust-verification-result.json").read_text())
    mutate(receipt, statement, predicate, result)
    _write_json(root / "pdd-publication-record.json", receipt)
    _write_json(root / "pdd-image-binding-statement.json", statement)
    _write_json(root / "pdd-image-binding-predicate.json", predicate)
    _write_json(root / "pdd-trust-verification-result.json", result)
    with pytest.raises(evidence.PDDTrustEvidenceError, match=message):
        _correlate(root)


def test_rejects_raw_attestation_that_does_not_match_statement(tmp_path):
    root = _bundle(tmp_path)
    (root / "pdd-verified-attestation.json").write_text("{}", encoding="utf-8")
    with pytest.raises(evidence.PDDTrustEvidenceError, match="Raw verified Cosign"):
        _correlate(root)


def test_rejects_missing_or_empty_evidence_file(tmp_path):
    root = _bundle(tmp_path)
    (root / "pdd-verify.log").write_text("", encoding="utf-8")
    with pytest.raises(evidence.PDDTrustEvidenceError, match="must not be empty"):
        _correlate(root)


def test_rejects_wrong_signing_artifact_source_run(tmp_path):
    root = _bundle(tmp_path)
    with pytest.raises(evidence.PDDTrustEvidenceError, match="does not match"):
        evidence.correlate_evidence(
            evidence_dir=root,
            source_build_run_id="999999",
            source_build_attempt=BUILD_ATTEMPT,
            signing_input_artifact=SIGNING_ARTIFACT,
            env=_env(),
        )


def test_rejects_statement_workflow_run_attempt_mismatch(tmp_path):
    root = _bundle(tmp_path)
    statement = json.loads((root / "pdd-image-binding-statement.json").read_text())
    statement["predicate"]["workflow"]["run_attempt"] = 1
    _write_json(root / "pdd-image-binding-statement.json", statement)
    _write_json(root / "pdd-image-binding-predicate.json", statement["predicate"])
    with pytest.raises(evidence.PDDTrustEvidenceError, match="runtime"):
        _correlate(root)


def test_rejects_duplicate_json_keys(tmp_path):
    root = _bundle(tmp_path)
    (root / "pdd-publication-record.json").write_text(
        '{"schema_version":"1.0.0","schema_version":"1.0.0"}',
        encoding="utf-8",
    )
    with pytest.raises(evidence.PDDTrustEvidenceError, match="duplicate JSON key"):
        _correlate(root)


def test_rejects_symlinked_required_file(tmp_path):
    root = _bundle(tmp_path)
    original = root / "pdd-verify.log"
    external = tmp_path / "external.log"
    external.write_bytes(original.read_bytes())
    original.unlink()
    original.symlink_to(external)
    with pytest.raises(evidence.PDDTrustEvidenceError, match="unsafe"):
        _correlate(root)


def test_rejects_symlinked_evidence_directory(tmp_path):
    root = _bundle(tmp_path)
    link = tmp_path / "linked"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(evidence.PDDTrustEvidenceError, match="real directory"):
        evidence.correlate_evidence(
            evidence_dir=link,
            source_build_run_id=BUILD_RUN_ID,
            source_build_attempt=BUILD_ATTEMPT,
            signing_input_artifact=SIGNING_ARTIFACT,
            env=_env(),
        )


def test_rejects_wrong_publication_runtime_identity(tmp_path):
    root = _bundle(tmp_path)
    env = _env()
    env["GITHUB_REF"] = "refs/heads/feature"
    with pytest.raises(evidence.PDDTrustEvidenceError, match="approved PDD workflow"):
        evidence.correlate_evidence(
            evidence_dir=root,
            source_build_run_id=BUILD_RUN_ID,
            source_build_attempt=BUILD_ATTEMPT,
            signing_input_artifact=SIGNING_ARTIFACT,
            env=env,
        )


def test_rejects_missing_expected_provisional_message(tmp_path):
    root = _bundle(tmp_path)
    (root / "pdd-verify.log").write_text("other verifier error", encoding="utf-8")
    with pytest.raises(evidence.PDDTrustEvidenceError, match="exact provisional"):
        _correlate(root)
