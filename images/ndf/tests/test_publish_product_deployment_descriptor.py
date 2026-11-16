import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import fetch_product_deployment_descriptor as retriever  # noqa: E402
from scripts import publish_product_deployment_descriptor as publisher  # noqa: E402
from scripts.fetch_product_deployment_descriptor import (  # noqa: E402
    PDDRetrievalError,
    fetch_product_deployment_descriptor,
)
from scripts.publish_product_deployment_descriptor import (  # noqa: E402
    ARTIFACT_TYPE,
    PDDPublicationError,
    _publication_files,
    _safe_file,
    _tag_for,
    publish_product_deployment_descriptor,
)


def _bundle(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    image_id = "dalali-v16"
    names = [
        "lock_v2",
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
    ]
    records = []
    for name in names:
        physical_names = {
            "apps_json": "apps.json",
            "build_metadata": "build-metadata.json",
            "buildx_metadata": "buildx-metadata.json",
            "build_inventory": "build-inventory.json",
            "build_evidence": "build-evidence.json",
            "source_provenance": "source-provenance.json",
            "source_provenance_verification": "source-provenance-verification.json",
            "source_tree_post_cleanup": "source-tree-post-cleanup.json",
            "source_tree_runtime": "source-tree-runtime.json",
            "image_composition_verification": "image-composition-verification.json",
        }
        physical = (
            f"{image_id}.lock-v2.json" if name == "lock_v2" else physical_names[name]
        )
        raw = f"fixture:{name}".encode()
        (evidence_dir / physical).write_bytes(raw)
        records.append(
            {
                "name": name,
                "path": "lock-v2.json" if name == "lock_v2" else physical,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
        )
    for sidecar in publisher.SIDECARS:
        (evidence_dir / sidecar).write_text("{}", encoding="utf-8")
    (evidence_dir / "build-result.json").write_text(
        json.dumps({"image_id": image_id}), encoding="utf-8"
    )
    descriptor = {
        "schema_version": "1.0.0",
        "artifact": {
            "repository": "ghcr.io/ndftechlabs/dalali",
            "digest": "sha256:" + "a" * 64,
            "platform": "linux/amd64",
        },
        "evidence": records,
    }
    descriptor_path = evidence_dir / "product-deployment.json"
    descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")
    binding = {
        "status": "passed",
        "descriptor_id": "pdd:dalali-v16:linux-amd64:sha256:" + "a" * 64,
        "image_digest": descriptor["artifact"]["digest"],
        "content_sha256": "b" * 64,
        "evidence_count": 11,
    }
    (evidence_dir / "binding-verification.json").write_text(
        json.dumps(binding), encoding="utf-8"
    )
    return evidence_dir, descriptor_path, descriptor, binding


def test_publication_tag_is_deterministic_and_digest_specific():
    descriptor = {
        "artifact": {
            "platform": "linux/amd64",
            "digest": "sha256:" + "c" * 64,
        }
    }
    assert _tag_for(descriptor) == "pdd-v1-linux-amd64-" + "c" * 64


def test_publication_bundle_contains_pdd_report_and_all_original_evidence(tmp_path):
    evidence_dir, _, descriptor, _ = _bundle(tmp_path)
    files = _publication_files(descriptor, evidence_dir, "dalali-v16")
    assert len(files) == 16
    assert "product-deployment.json" in files
    assert "binding-verification.json" in files
    assert "dalali-v16.lock-v2.json" in files
    assert "lock-v2.json" not in files


def test_safe_file_rejects_parent_traversal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(PDDPublicationError, match="Unsafe"):
        _safe_file(root, "../escape.json")


def test_safe_file_rejects_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (root / "linked.json").symlink_to(outside)
    with pytest.raises(PDDPublicationError, match="symlink"):
        _safe_file(root, "linked.json")


def test_publication_receipt_schema_requires_digest_pinned_reference():
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "pdd-publication-record-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    receipt = {
        "schema_version": "1.0.0",
        "publication_type": "ndf.product-deployment.publication",
        "descriptor": {
            "id": "pdd:dalali-v16:linux-amd64:sha256:" + "a" * 64,
            "schema_version": "1.0.0",
            "content_sha256": "b" * 64,
        },
        "subject_image": {
            "repository": "ghcr.io/ndftechlabs/dalali",
            "digest": "sha256:" + "a" * 64,
            "platform": "linux/amd64",
        },
        "artifact": {
            "type": ARTIFACT_TYPE,
            "repository": "ghcr.io/ndftechlabs/dalali",
            "locator_tag": "pdd-v1-linux-amd64-" + "a" * 64,
            "digest": "sha256:" + "c" * 64,
            "immutable_reference": "ghcr.io/ndftechlabs/dalali@sha256:" + "c" * 64,
        },
        "evidence": {
            "count": 11,
            "binding_report_sha256": "d" * 64,
            "published_file_count": 16,
        },
        "published_at": "2026-11-14T12:00:00Z",
    }
    Draft202012Validator(schema).validate(receipt)
    receipt["artifact"]["immutable_reference"] = (
        receipt["artifact"]["repository"] + ":latest"
    )
    with pytest.raises(Exception):
        Draft202012Validator(schema).validate(receipt)


def test_publisher_fails_when_binding_report_disagrees_before_registry_write(
    tmp_path, monkeypatch
):
    evidence_dir, descriptor_path, _, binding_report = _bundle(tmp_path)
    binding_report["content_sha256"] = "f" * 64
    (evidence_dir / "binding-verification.json").write_text(
        json.dumps(binding_report), encoding="utf-8"
    )
    monkeypatch.setattr(
        publisher,
        "validate_descriptor",
        lambda path: {
            "descriptor_id": binding_report["descriptor_id"],
            "content_sha256": "b" * 64,
            "image_digest": binding_report["image_digest"],
        },
    )
    monkeypatch.setattr(
        publisher,
        "verify_product_deployment_binding",
        lambda *args, **kwargs: {
            **binding_report,
            "content_sha256": "b" * 64,
        },
    )
    monkeypatch.setattr(
        publisher,
        "_run",
        lambda *args, **kwargs: pytest.fail("Registry must not be contacted"),
    )
    with pytest.raises(PDDPublicationError, match="disagrees"):
        publish_product_deployment_descriptor(
            descriptor_path,
            evidence_dir,
            tmp_path / "receipt.json",
        )


def test_publisher_pushes_and_rechecks_the_digest_pinned_artifact(
    tmp_path, monkeypatch
):
    evidence_dir, descriptor_path, descriptor, binding_report = _bundle(tmp_path)
    descriptor["schema_version"] = "1.0.0"
    descriptor["product"] = {"id": "dalali-v16", "name": "Dalali"}
    descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")
    monkeypatch.setattr(
        publisher,
        "validate_descriptor",
        lambda path: {
            "descriptor_id": binding_report["descriptor_id"],
            "content_sha256": binding_report["content_sha256"],
            "image_digest": binding_report["image_digest"],
            "schema_version": "1.0.0",
        },
    )
    monkeypatch.setattr(
        publisher,
        "verify_product_deployment_binding",
        lambda *args, **kwargs: binding_report,
    )
    annotations = {
        "io.ndf.pdd.descriptor-id": binding_report["descriptor_id"],
        "io.ndf.pdd.content-sha256": binding_report["content_sha256"],
        "io.ndf.pdd.subject-image-digest": binding_report["image_digest"],
        "io.ndf.pdd.schema-version": "1.0.0",
        "org.opencontainers.image.title": "NDF Product Deployment Descriptor",
    }
    digest = "sha256:" + "e" * 64
    manifest = {
        "digest": digest,
        "content": {
            "artifactType": ARTIFACT_TYPE,
            "annotations": annotations,
            "layers": [
                {
                    "mediaType": "application/vnd.ndf.product-deployment-descriptor.v1+json"
                }
            ],
        },
    }
    manifest_calls = iter([None, manifest, manifest])
    monkeypatch.setattr(publisher, "_manifest", lambda *args: next(manifest_calls))
    monkeypatch.setattr(publisher, "_pull_and_compare", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "digest": digest,
                    "reference": "ghcr.io/ndftechlabs/dalali@" + digest,
                }
            ).encode(),
            stderr=b"",
        ),
    )

    receipt_path = tmp_path / "publication" / "receipt.json"
    receipt = publish_product_deployment_descriptor(
        descriptor_path, evidence_dir, receipt_path
    )
    assert receipt["artifact"]["immutable_reference"].endswith(digest)
    assert receipt["evidence"]["count"] == 11
    assert receipt["evidence"]["published_file_count"] == 16
    assert json.loads(receipt_path.read_text(encoding="utf-8")) == receipt


def _valid_receipt():
    image_digest = "sha256:" + "a" * 64
    artifact_digest = "sha256:" + "c" * 64
    repository = "ghcr.io/ndftechlabs/dalali"
    return {
        "schema_version": "1.0.0",
        "publication_type": "ndf.product-deployment.publication",
        "descriptor": {
            "id": "pdd:dalali-v16:linux-amd64:" + image_digest,
            "schema_version": "1.0.0",
            "content_sha256": "b" * 64,
        },
        "subject_image": {
            "repository": repository,
            "digest": image_digest,
            "platform": "linux/amd64",
        },
        "artifact": {
            "type": ARTIFACT_TYPE,
            "repository": repository,
            "locator_tag": "pdd-v1-linux-amd64-" + "a" * 64,
            "digest": artifact_digest,
            "immutable_reference": repository + "@" + artifact_digest,
        },
        "evidence": {
            "count": 11,
            "binding_report_sha256": "d" * 64,
            "published_file_count": 16,
        },
        "published_at": "2026-11-14T12:00:00Z",
    }


def test_retriever_fetches_and_validates_digest_pinned_artifact(tmp_path, monkeypatch):
    evidence_dir, descriptor_path, descriptor, binding_report = _bundle(tmp_path)
    receipt = _valid_receipt()
    receipt["descriptor"]["id"] = binding_report["descriptor_id"]
    binding_payload = {
        "status": "passed",
        "descriptor_id": receipt["descriptor"]["id"],
        "image_digest": receipt["subject_image"]["digest"],
        "content_sha256": receipt["descriptor"]["content_sha256"],
        "evidence_count": 11,
    }
    binding_bytes = json.dumps(binding_payload).encode()
    receipt["evidence"]["binding_report_sha256"] = hashlib.sha256(
        binding_bytes
    ).hexdigest()
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    pdd_bytes = descriptor_path.read_bytes()
    (evidence_dir / "binding-verification.json").write_bytes(binding_bytes)
    annotations = {
        "io.ndf.pdd.descriptor-id": receipt["descriptor"]["id"],
        "io.ndf.pdd.content-sha256": receipt["descriptor"]["content_sha256"],
        "io.ndf.pdd.subject-image-digest": receipt["subject_image"]["digest"],
        "io.ndf.pdd.schema-version": receipt["descriptor"]["schema_version"],
    }

    def fake_run(command, **kwargs):
        if command[1:3] == ["manifest", "fetch"]:
            payload = {
                "digest": receipt["artifact"]["digest"],
                "content": {
                    "artifactType": ARTIFACT_TYPE,
                    "annotations": annotations,
                    "layers": [
                        {
                            "mediaType": "application/vnd.ndf.product-deployment-descriptor.v1+json"
                        }
                    ],
                },
            }
            return SimpleNamespace(
                returncode=0, stdout=json.dumps(payload).encode(), stderr=b""
            )
        output = Path(command[command.index("--output") + 1])
        for source in evidence_dir.iterdir():
            if source.name not in {
                "product-deployment.json",
                "binding-verification.json",
            }:
                (output / source.name).write_bytes(source.read_bytes())
        (output / "product-deployment.json").write_bytes(pdd_bytes)
        (output / "binding-verification.json").write_bytes(binding_bytes)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"reference": receipt["artifact"]["immutable_reference"]}
            ).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(retriever, "_run", fake_run)
    monkeypatch.setattr(
        retriever,
        "validate_descriptor",
        lambda path: {
            "descriptor_id": receipt["descriptor"]["id"],
            "content_sha256": receipt["descriptor"]["content_sha256"],
            "image_digest": receipt["subject_image"]["digest"],
            "schema_version": "1.0.0",
        },
    )
    monkeypatch.setattr(
        retriever,
        "verify_product_deployment_binding",
        lambda *args, **kwargs: binding_payload,
    )
    consumer_report = {
        "execution": {"status": "completed"},
        "evidence": {"binding_status": "passed"},
        "trust_decision": {
            "status": "rejected",
            "reason_codes": ["IDENTITY_POLICY_PROVISIONAL"],
        },
        "deployment_authorization": "not_granted",
    }
    trust_calls = []
    pulled_files_at_verification = []

    def fake_independent_trust_verification(**kwargs):
        pulled_dir = kwargs["pulled_dir"]
        assert pulled_dir.is_dir()
        pulled_files_at_verification.extend(
            sorted(item.relative_to(pulled_dir).as_posix() for item in pulled_dir.rglob("*"))
        )
        trust_calls.append(kwargs)
        return consumer_report

    monkeypatch.setattr(
        retriever,
        "_verify_independent_consumer_trust",
        fake_independent_trust_verification,
    )
    output_dir = tmp_path / "retrieved"
    report = fetch_product_deployment_descriptor(receipt_path, output_dir)
    assert report is consumer_report
    assert report["execution"]["status"] == "completed"
    assert report["evidence"]["binding_status"] == "passed"
    assert report["trust_decision"]["reason_codes"] == [
        "IDENTITY_POLICY_PROVISIONAL"
    ]
    assert report["deployment_authorization"] == "not_granted"
    assert len(trust_calls) == 1
    assert trust_calls[0]["receipt"] == receipt
    assert trust_calls[0]["output_dir"] == output_dir
    assert "product-deployment.json" in pulled_files_at_verification
    assert "binding-verification.json" in pulled_files_at_verification
    assert not trust_calls[0]["pulled_dir"].exists()  # TemporaryDirectory cleanup
    assert (output_dir / "product-deployment.json").read_bytes() == pdd_bytes


def test_retriever_rejects_mutable_tag_reference(tmp_path):
    receipt = _valid_receipt()
    receipt["artifact"]["immutable_reference"] = (
        receipt["artifact"]["repository"] + ":latest"
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(PDDRetrievalError, match="Invalid publication receipt"):
        fetch_product_deployment_descriptor(
            receipt_path, tmp_path / "retrieved", verify_image_binding=False
        )


def test_publisher_is_idempotent_for_an_identical_existing_artifact(
    tmp_path, monkeypatch
):
    evidence_dir, descriptor_path, descriptor, binding_report = _bundle(tmp_path)
    annotations = {
        "io.ndf.pdd.descriptor-id": binding_report["descriptor_id"],
        "io.ndf.pdd.content-sha256": binding_report["content_sha256"],
        "io.ndf.pdd.subject-image-digest": binding_report["image_digest"],
        "io.ndf.pdd.schema-version": descriptor["schema_version"],
        "org.opencontainers.image.title": "NDF Product Deployment Descriptor",
    }
    digest = "sha256:" + "e" * 64
    existing = {
        "digest": digest,
        "content": {
            "artifactType": ARTIFACT_TYPE,
            "annotations": annotations,
            "layers": [
                {
                    "mediaType": "application/vnd.ndf.product-deployment-descriptor.v1+json"
                }
            ],
        },
    }
    monkeypatch.setattr(
        publisher,
        "validate_descriptor",
        lambda path: {
            "descriptor_id": binding_report["descriptor_id"],
            "content_sha256": binding_report["content_sha256"],
            "image_digest": binding_report["image_digest"],
            "schema_version": descriptor["schema_version"],
        },
    )
    monkeypatch.setattr(
        publisher,
        "verify_product_deployment_binding",
        lambda *args, **kwargs: binding_report,
    )
    monkeypatch.setattr(publisher, "_manifest", lambda *args: existing)
    monkeypatch.setattr(
        publisher,
        "_pull_and_compare",
        lambda oras_bin, reference, files: (
            reference.endswith(digest)
            or pytest.fail("Expected digest-pinned existing reference")
        ),
    )
    monkeypatch.setattr(
        publisher,
        "_run",
        lambda *args, **kwargs: pytest.fail(
            "Identical existing artifact must not be pushed again"
        ),
    )

    receipt = publish_product_deployment_descriptor(
        descriptor_path, evidence_dir, tmp_path / "receipt.json"
    )
    assert receipt["artifact"]["digest"] == digest
