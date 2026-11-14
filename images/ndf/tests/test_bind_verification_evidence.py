import hashlib

import pytest

from scripts.bind_verification_evidence import (
    VerificationEvidenceError,
    create_verification_evidence,
    verify_verification_evidence,
)


@pytest.fixture
def evidence_inputs():
    names = {
        "apps_json",
        "build_metadata",
        "buildx_metadata",
        "build_inventory",
        "build_evidence",
        "source_provenance",
        "source_provenance_verification",
        "source_tree_post_cleanup",
        "source_tree_runtime",
        "image_composition_verification",
    }
    artifacts = {
        name: (f"{name}.json", (name + "-bytes").encode()) for name in names
    }
    lock = b'{"lock_version":2}'
    statuses = {
        name: "passed"
        for name in (
            "source_provenance_verification",
            "source_tree_post_cleanup",
            "source_tree_runtime",
            "image_composition_verification",
        )
    }
    return artifacts, lock, statuses


def build_evidence(artifacts, lock, statuses):
    return create_verification_evidence(
        image_reference="ghcr.io/ndf/dalali:test",
        image_repository="ghcr.io/ndf/dalali",
        image_id="dalali-v16",
        image_digest="sha256:" + "a" * 64,
        lock_bytes=lock,
        artifacts={"lock_v2": ("lock-v2.json", lock), **artifacts},
        statuses=statuses,
    )


def verify(report, artifacts, lock):
    verify_verification_evidence(
        report,
        expected_image_digest="sha256:" + "a" * 64,
        expected_lock_sha256=hashlib.sha256(lock).hexdigest(),
        artifacts={"lock_v2": ("lock-v2.json", lock), **artifacts},
    )


def test_binds_exact_bytes_to_image_and_lock(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    report = build_evidence(artifacts, lock, statuses)

    verify(report, artifacts, lock)

    assert report["status"] == "bound"
    assert len(report["evidence"]) == 11


def test_rejects_image_digest_swap(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    report = build_evidence(artifacts, lock, statuses)

    with pytest.raises(VerificationEvidenceError, match="different image digest"):
        verify_verification_evidence(
            report,
            expected_image_digest="sha256:" + "b" * 64,
            expected_lock_sha256=hashlib.sha256(lock).hexdigest(),
            artifacts={"lock_v2": ("lock-v2.json", lock), **artifacts},
        )


def test_rejects_lock_swap(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    report = build_evidence(artifacts, lock, statuses)

    with pytest.raises(VerificationEvidenceError, match="different lock-v2"):
        verify_verification_evidence(
            report,
            expected_image_digest="sha256:" + "a" * 64,
            expected_lock_sha256="b" * 64,
            artifacts={"lock_v2": ("lock-v2.json", lock), **artifacts},
        )


def test_rejects_tampered_evidence_bytes(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    report = build_evidence(artifacts, lock, statuses)
    changed = dict(artifacts)
    changed["source_provenance"] = ("source-provenance.json", b"tampered")

    with pytest.raises(VerificationEvidenceError, match="hash/identity mismatch"):
        verify(report, changed, lock)


def test_rejects_missing_evidence(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    del artifacts["image_composition_verification"]

    with pytest.raises(VerificationEvidenceError, match="inventory mismatch"):
        build_evidence(artifacts, lock, statuses)


def test_rejects_failed_verification_status(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    statuses["source_tree_runtime"] = "failed"

    with pytest.raises(VerificationEvidenceError, match="did not pass"):
        build_evidence(artifacts, lock, statuses)


def test_rejects_duplicate_evidence_records(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    report = build_evidence(artifacts, lock, statuses)
    report["evidence"].append(report["evidence"][0])

    with pytest.raises(VerificationEvidenceError, match="schema failed"):
        verify(report, artifacts, lock)


def test_rejects_malformed_digest(evidence_inputs):
    artifacts, lock, statuses = evidence_inputs
    with pytest.raises(VerificationEvidenceError, match="64 lowercase hexadecimal"):
        create_verification_evidence(
            image_reference="ghcr.io/ndf/dalali:test",
            image_repository="ghcr.io/ndf/dalali",
            image_id="dalali-v16",
            image_digest="sha256:xyz",
            lock_bytes=lock,
            artifacts={"lock_v2": ("lock-v2.json", lock), **artifacts},
            statuses=statuses,
        )
