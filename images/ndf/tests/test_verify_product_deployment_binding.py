import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

import test_generate_product_deployment_descriptor as generator_fixtures  # noqa: E402
from scripts import verify_product_deployment_binding as binding  # noqa: E402
from scripts.verify_product_deployment_binding import (  # noqa: E402
    ProductDeploymentBindingError,
    verify_product_deployment_binding,
)
from test_generate_product_deployment_descriptor import (  # noqa: E402
    _generate,
    _refresh_evidence_bindings,
    _write_json,
    complete_build_output,
)

MANIFEST_BYTES = (
    b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",'
    b'"config":{"digest":"sha256:' + b"1" * 64 + b'"}}'
)
MANIFEST_DIGEST = "sha256:" + hashlib.sha256(MANIFEST_BYTES).hexdigest()


def _write_descriptor(output_dir, descriptor):
    path = output_dir / "product-deployment.json"
    path.write_text(
        json.dumps(descriptor, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _refresh_descriptor_integrity(descriptor):
    integrity = descriptor["integrity"]
    payload = {
        **descriptor,
        "integrity": {
            key: value for key, value in integrity.items() if key != "content_sha256"
        },
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    descriptor["integrity"]["content_sha256"] = hashlib.sha256(canonical).hexdigest()


def _prepare_binding_fixture(output_dir, monkeypatch):
    monkeypatch.setattr(generator_fixtures, "IMAGE_DIGEST", MANIFEST_DIGEST)
    result_path = output_dir / "build-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["digest"] = MANIFEST_DIGEST
    _write_json(result_path, result)

    buildx_path = output_dir / "buildx-metadata.json"
    buildx = json.loads(buildx_path.read_text(encoding="utf-8"))
    buildx["containerimage.digest"] = MANIFEST_DIGEST
    _write_json(buildx_path, buildx)

    evidence_path = output_dir / "build-evidence.json"
    build_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    build_evidence["image_digest"] = MANIFEST_DIGEST
    _write_json(evidence_path, build_evidence)

    validation_path = output_dir / "image-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["image_digest"] = MANIFEST_DIGEST
    _write_json(validation_path, validation)

    gate_path = output_dir / "publication-gate.json"
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    gate["image"]["digest"] = MANIFEST_DIGEST
    _write_json(gate_path, gate)

    _refresh_evidence_bindings(output_dir)
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["image_digest"] = MANIFEST_DIGEST
    _write_json(validation_path, validation)

    descriptor = _generate(output_dir)
    descriptor_path = _write_descriptor(output_dir, descriptor)
    return descriptor_path


@pytest.fixture
def binding_fixture(complete_build_output, monkeypatch):
    descriptor_path = _prepare_binding_fixture(complete_build_output, monkeypatch)
    return complete_build_output, descriptor_path


def _mock_registry(monkeypatch, *, stdout=MANIFEST_BYTES, returncode=0, stderr=b""):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(binding.subprocess, "run", run)
    return calls


def test_binds_all_evidence_and_exact_registry_manifest(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    calls = _mock_registry(monkeypatch)

    report = verify_product_deployment_binding(descriptor_path, output_dir)

    assert report["status"] == "passed"
    assert report["evidence_count"] == 11
    assert report["registry_manifest_digest"] == MANIFEST_DIGEST
    assert calls[0][0][-1] == (
        "ghcr.io/ndftechlabs/dalali@" + MANIFEST_DIGEST
    )


def test_rejects_tampered_evidence_bytes(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    (output_dir / "source-provenance.json").write_bytes(b'{"tampered":true}\n')
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="Evidence SHA-256 mismatch"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_missing_evidence_file(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    (output_dir / "apps.json").unlink()
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="missing or inaccessible"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_symlink_evidence_file(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    (output_dir / "source-provenance.json").unlink()
    (output_dir / "source-provenance.json").symlink_to(output_dir / "apps.json")
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="symlink"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_evidence_manifest_record_mismatch(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    path = output_dir / "image-verification-evidence.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["evidence"][0]["sha256"] = "f" * 64
    _write_json(path, report)
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="disagree"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_buildx_digest_mismatch(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    _write_json(
        output_dir / "buildx-metadata.json",
        {"containerimage.digest": "sha256:" + "f" * 64},
    )
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="Buildx metadata digest"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_build_result_platform_mismatch(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    result = json.loads((output_dir / "build-result.json").read_text())
    result["platforms"] = ["linux/arm64"]
    _write_json(output_dir / "build-result.json", result)
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="platform"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_registry_manifest_digest_mismatch(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    _mock_registry(monkeypatch, stdout=b'{"tampered":"manifest"}')

    with pytest.raises(ProductDeploymentBindingError, match="manifest digest mismatch"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_registry_command_failure(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    _mock_registry(monkeypatch, returncode=1, stderr=b"unauthorized")

    with pytest.raises(ProductDeploymentBindingError, match="inspection failed"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_empty_registry_manifest(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    _mock_registry(monkeypatch, stdout=b"")

    with pytest.raises(ProductDeploymentBindingError, match="empty OCI manifest"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_descriptor_without_immutable_reference(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    descriptor = json.loads(descriptor_path.read_text())
    descriptor["artifact"].pop("immutable_reference")
    _refresh_descriptor_integrity(descriptor)
    _write_descriptor(output_dir, descriptor)
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="immutable repository@digest"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_lock_evidence_hash_mismatch(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    lock_path = output_dir / "dalali-v16.lock-v2.json"
    lock_path.write_bytes(lock_path.read_bytes() + b" ")
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="Evidence SHA-256 mismatch"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_failed_verification_report(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    path = output_dir / "source-tree-verification-runtime.json"
    _write_json(path, {"status": "failed"})

    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    evidence_record = next(
        item
        for item in descriptor["evidence"]
        if item["name"] == "source_tree_runtime"
    )
    raw = path.read_bytes()
    evidence_record["sha256"] = hashlib.sha256(raw).hexdigest()
    evidence_record["size_bytes"] = len(raw)
    _refresh_descriptor_integrity(descriptor)
    _write_descriptor(output_dir, descriptor)

    manifest_path = output_dir / "image-verification-evidence.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_record = next(
        item
        for item in manifest["evidence"]
        if item["name"] == "source_tree_runtime"
    )
    manifest_record["sha256"] = evidence_record["sha256"]
    manifest_record["size_bytes"] = evidence_record["size_bytes"]
    _write_json(manifest_path, manifest)

    validation_path = output_dir / "image-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["verification_evidence"] = manifest
    _write_json(validation_path, validation)
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="did not pass"):
        verify_product_deployment_binding(descriptor_path, output_dir)


def test_rejects_non_digest_pinned_registry_reference(binding_fixture, monkeypatch):
    output_dir, descriptor_path = binding_fixture
    descriptor = json.loads(descriptor_path.read_text())
    descriptor["artifact"]["immutable_reference"] = (
        "ghcr.io/ndftechlabs/dalali:latest"
    )
    _refresh_descriptor_integrity(descriptor)
    _write_descriptor(output_dir, descriptor)
    _mock_registry(monkeypatch)

    with pytest.raises(ProductDeploymentBindingError, match="not pinned"):
        verify_product_deployment_binding(descriptor_path, output_dir)
