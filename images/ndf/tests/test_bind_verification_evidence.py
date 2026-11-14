import hashlib
import pytest
from scripts.bind_verification_evidence import VerificationEvidenceError, create_verification_evidence, verify_verification_evidence

@pytest.fixture
def inputs():
    names={"apps_json","build_metadata","buildx_metadata","build_inventory","build_evidence","source_provenance","source_provenance_verification","source_tree_post_cleanup","source_tree_runtime","image_composition_verification"}
    artifacts={n:(f"{n}.json",(n+"-bytes").encode()) for n in names}
    lock=b'{"lock_version":2}'
    statuses={n:"passed" for n in ("source_provenance_verification","source_tree_post_cleanup","source_tree_runtime","image_composition_verification")}
    return artifacts,lock,statuses

def build(artifacts,lock,statuses):
    return create_verification_evidence(image_reference="ghcr.io/ndf/dalali:test",image_repository="ghcr.io/ndf/dalali",image_id="dalali-v16",image_digest="sha256:"+"a"*64,lock_bytes=lock,artifacts={"lock_v2":("lock-v2.json",lock),**artifacts},statuses=statuses)

def test_binds_exact_bytes_to_image_and_lock(inputs):
    artifacts,lock,statuses=inputs; report=build(artifacts,lock,statuses)
    verify_verification_evidence(report,expected_image_digest="sha256:"+"a"*64,expected_lock_sha256=hashlib.sha256(lock).hexdigest(),artifacts={"lock_v2":("lock-v2.json",lock),**artifacts})
    assert report["status"]=="bound" and len(report["evidence"])==11

def test_rejects_image_digest_swap(inputs):
    artifacts,lock,statuses=inputs; report=build(artifacts,lock,statuses)
    with pytest.raises(VerificationEvidenceError,match="different image digest"):
        verify_verification_evidence(report,expected_image_digest="sha256:"+"b"*64,expected_lock_sha256=hashlib.sha256(lock).hexdigest(),artifacts={"lock_v2":("lock-v2.json",lock),**artifacts})

def test_rejects_lock_swap(inputs):
    artifacts,lock,statuses=inputs; report=build(artifacts,lock,statuses)
    with pytest.raises(VerificationEvidenceError,match="different lock-v2"):
        verify_verification_evidence(report,expected_image_digest="sha256:"+"a"*64,expected_lock_sha256="b"*64,artifacts={"lock_v2":("lock-v2.json",lock),**artifacts})

def test_rejects_tampered_evidence_bytes(inputs):
    artifacts,lock,statuses=inputs; report=build(artifacts,lock,statuses); changed=dict(artifacts); changed["source_provenance"]=("source_provenance.json",b"tampered")
    with pytest.raises(VerificationEvidenceError,match="hash/identity mismatch"):
        verify_verification_evidence(report,expected_image_digest="sha256:"+"a"*64,expected_lock_sha256=hashlib.sha256(lock).hexdigest(),artifacts={"lock_v2":("lock-v2.json",lock),**changed})

def test_rejects_missing_evidence(inputs):
    artifacts,lock,statuses=inputs; del artifacts["image_composition_verification"]
    with pytest.raises(VerificationEvidenceError,match="inventory mismatch"): build(artifacts,lock,statuses)

def test_rejects_failed_verification_status(inputs):
    artifacts,lock,statuses=inputs; statuses["source_tree_runtime"]="failed"
    with pytest.raises(VerificationEvidenceError,match="did not pass"): build(artifacts,lock,statuses)

def test_rejects_duplicate_evidence_records(inputs):
    artifacts,lock,statuses=inputs; report=build(artifacts,lock,statuses); report["evidence"].append(report["evidence"][0])
    with pytest.raises(VerificationEvidenceError,match="duplicated"):
        verify_verification_evidence(report,expected_image_digest="sha256:"+"a"*64,expected_lock_sha256=hashlib.sha256(lock).hexdigest(),artifacts={"lock_v2":("lock-v2.json",lock),**artifacts})
