import hashlib
import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import generate_pdd_image_binding as generator  # noqa: E402


def _hash(value):
    return hashlib.sha256(generator._canonical_json(value)).hexdigest()


def _inputs():
    image_digest = "sha256:" + "a" * 64
    pdd_digest = "sha256:" + "b" * 64
    predicate = {
        "buildDefinition": {"buildType": "https://ndftechlabs.com/buildtypes/frappe-docker-image/v1"},
        "runDetails": {"builder": {"id": "https://github.com/NdfTechLabs/frappe_docker/actions"}},
        "ndf_build": {
            "product_id": "dalali",
            "platform": "linux/amd64",
            "workflow": {
                "repository": "NdfTechLabs/frappe_docker",
                "source_commit": "c" * 40,
                "run_id": "123456",
            },
        },
    }
    descriptor = {
        "schema_version": "1.0.0",
        "descriptor_id": "pdd:dalali:linux-amd64:sha256:" + "d" * 64,
        "product": {"id": "dalali"},
        "artifact": {
            "repository": "ghcr.io/ndftechlabs/dalali",
            "digest": image_digest,
            "platform": "linux/amd64",
        },
        "build": {"source_commit": "c" * 40, "workflow_run_id": "123456"},
        "composition": {"lock": {"sha256": "e" * 64}},
        "integrity": {"content_sha256": "f" * 64},
    }
    receipt = {
        "schema_version": "1.0.0",
        "publication_type": "ndf.product-deployment.publication",
        "descriptor": {
            "id": descriptor["descriptor_id"],
            "schema_version": "1.0.0",
            "content_sha256": descriptor["integrity"]["content_sha256"],
        },
        "subject_image": {
            "repository": descriptor["artifact"]["repository"],
            "digest": image_digest,
            "platform": "linux/amd64",
        },
        "artifact": {
            "type": "application/vnd.ndf.product-deployment-descriptor.v1",
            "repository": descriptor["artifact"]["repository"],
            "locator_tag": "pdd-v1-linux-amd64-" + "1" * 64,
            "digest": pdd_digest,
            "immutable_reference": descriptor["artifact"]["repository"] + "@" + pdd_digest,
        },
        "evidence": {
            "count": 11,
            "binding_report_sha256": "2" * 64,
            "published_file_count": 16,
        },
        "published_at": "2026-11-16T08:00:00Z",
    }
    trust_result = {
        "schema_version": "1.0.0",
        "verification_id": "verification-1",
        "artifact": {
            "kind": "product_image",
            "repository": descriptor["artifact"]["repository"],
            "digest": image_digest,
            "immutable_reference": descriptor["artifact"]["repository"] + "@" + image_digest,
        },
        "signature": {"verified": True, "verification_method": "cosign-keyless"},
        "signer": {
            "verified": True,
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": "https://github.com/NdfTechLabs/frappe_docker/.github/workflows/ndf-publish-product.yml@refs/heads/main",
        },
        "transparency": {"verified": True, "log_entry_verified": True},
        "attestations": [{
            "predicate_type": generator.PREDICATE_TYPE,
            "verified": True,
            "subject_digest": image_digest,
            "predicate_sha256": _hash(predicate),
        }],
        "decision": {"status": "rejected", "reason_codes": [generator.PROVISIONAL_REASON]},
        "verified_at": "2026-11-16T08:00:00Z",
    }
    env = {
        "GITHUB_REPOSITORY": "NdfTechLabs/frappe_docker",
        "GITHUB_WORKFLOW_REF": "NdfTechLabs/frappe_docker/" + generator.PDD_WORKFLOW_PATH + "@refs/heads/main",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ID": "987654",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": "9" * 40,
    }
    return descriptor, receipt, trust_result, predicate, env


def _write(path: Path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_canonical_json_uses_compact_sorted_utf8_and_trailing_lf():
    assert generator._canonical_json({"z": 1, "a": "é"}) == '{"a":"é","z":1}\n'.encode()


def test_workflow_context_requires_exact_pdd_workflow():
    _, _, _, _, env = _inputs()
    assert generator._workflow_context(env)["path"] == generator.PDD_WORKFLOW_PATH
    env["GITHUB_WORKFLOW_REF"] = "NdfTechLabs/frappe_docker/.github/workflows/other.yml@refs/heads/main"
    with pytest.raises(generator.PDDBindingGenerationError, match="approved PDD publication workflow"):
        generator._workflow_context(env)


def test_source_trust_accepts_only_provisional_policy_rejection():
    descriptor, _, trust_result, predicate, _ = _inputs()
    assert generator._validate_source_image_trust(trust_result, predicate, descriptor) == _hash(predicate)


def test_source_trust_rejects_predicate_hash_mismatch():
    descriptor, _, trust_result, predicate, _ = _inputs()
    trust_result["attestations"][0]["predicate_sha256"] = "0" * 64
    with pytest.raises(generator.PDDBindingGenerationError, match="predicate hash"):
        generator._validate_source_image_trust(trust_result, predicate, descriptor)


def test_source_trust_rejects_other_rejection_reasons():
    descriptor, _, trust_result, predicate, _ = _inputs()
    trust_result["decision"]["reason_codes"] = ["SIGNATURE_INVALID"]
    with pytest.raises(generator.PDDBindingGenerationError, match="only for provisional"):
        generator._validate_source_image_trust(trust_result, predicate, descriptor)


def test_source_trust_rejects_image_digest_mismatch():
    descriptor, _, trust_result, predicate, _ = _inputs()
    trust_result["artifact"]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(generator.PDDBindingGenerationError, match="exact PDD image"):
        generator._validate_source_image_trust(trust_result, predicate, descriptor)


def test_publication_receipt_must_match_descriptor():
    descriptor, receipt, _, _, _ = _inputs()
    receipt["descriptor"]["content_sha256"] = "0" * 64
    with pytest.raises(generator.PDDBindingGenerationError, match="does not match the PDD"):
        generator._validate_publication_receipt(receipt, descriptor)


def test_publication_receipt_must_use_distinct_pdd_digest():
    descriptor, receipt, _, _, _ = _inputs()
    receipt["artifact"]["digest"] = descriptor["artifact"]["digest"]
    receipt["artifact"]["immutable_reference"] = receipt["artifact"]["repository"] + "@" + receipt["artifact"]["digest"]
    with pytest.raises(generator.PDDBindingGenerationError, match="must differ"):
        generator._validate_publication_receipt(receipt, descriptor)


def test_generator_emits_schema_valid_deterministic_statement(tmp_path, monkeypatch):
    descriptor, receipt, trust_result, predicate, env = _inputs()
    descriptor_path = _write(tmp_path / "product-deployment.json", descriptor)
    receipt_path = _write(tmp_path / "publication.json", receipt)
    trust_path = _write(tmp_path / "trust-result.json", trust_result)
    predicate_path = _write(tmp_path / "predicate.json", predicate)
    output = tmp_path / "binding-statement.json"
    monkeypatch.setattr(generator, "validate_descriptor", lambda path: {"status": "passed"})

    result = generator.generate_pdd_image_binding(
        descriptor_path=descriptor_path,
        publication_record_path=receipt_path,
        source_trust_result_path=trust_path,
        source_predicate_path=predicate_path,
        statement_output=output,
        env=env,
    )
    statement = json.loads(output.read_text(encoding="utf-8"))
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"][0]["digest"]["sha256"] == "b" * 64
    assert statement["predicate"]["source_provenance"]["predicate_sha256"] == _hash(predicate)
    assert result["status"] == "passed"
    first_bytes = output.read_bytes()

    second = tmp_path / "binding-statement-second.json"
    generator.generate_pdd_image_binding(
        descriptor_path=descriptor_path,
        publication_record_path=receipt_path,
        source_trust_result_path=trust_path,
        source_predicate_path=predicate_path,
        statement_output=second,
        env=env,
    )
    assert second.read_bytes() == first_bytes
