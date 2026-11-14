import hashlib
import json
import sys
from pathlib import Path

import pytest
from scripts.generate_product_deployment_descriptor import _canonical_json
from scripts.validate_product_deployment_descriptor import (
    DescriptorValidationError,
    main,
    validate_descriptor,
)
from test_generate_product_deployment_descriptor import (
    _generate,
    complete_build_output,
)


def _write_descriptor(path: Path, descriptor: dict) -> None:
    path.write_text(
        json.dumps(descriptor, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _rehash(descriptor: dict) -> None:
    integrity = descriptor["integrity"]
    payload = {
        **descriptor,
        "integrity": {
            key: value for key, value in integrity.items() if key != "content_sha256"
        },
    }
    integrity["content_sha256"] = hashlib.sha256(_canonical_json(payload)).hexdigest()


@pytest.fixture
def valid_descriptor(tmp_path, complete_build_output):
    descriptor = _generate(complete_build_output)
    path = tmp_path / "product-deployment.json"
    _write_descriptor(path, descriptor)
    return path


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _mutate(path: Path, change, *, rehash: bool = True) -> None:
    descriptor = _load(path)
    change(descriptor)
    if rehash:
        _rehash(descriptor)
    _write_descriptor(path, descriptor)


def test_accepts_independently_generated_descriptor(valid_descriptor):
    report = validate_descriptor(valid_descriptor)

    assert report["status"] == "passed"
    assert report["schema_version"] == "1.0.0"
    assert report["evidence_count"] == 11
    assert "canonical_content_integrity" in report["checks"]


def test_rejects_descriptor_content_tampering(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["product"].update({"name": "Tampered"}),
        rehash=False,
    )

    with pytest.raises(DescriptorValidationError, match="content SHA-256 mismatch"):
        validate_descriptor(valid_descriptor)


def test_rejects_descriptor_identity_mismatch(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor.update({"descriptor_id": "pdd:other:linux-amd64:sha256:" + "a" * 64}),
    )

    with pytest.raises(DescriptorValidationError, match="Descriptor ID does not match"):
        validate_descriptor(valid_descriptor)


def test_rejects_immutable_reference_mismatch(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["artifact"].update(
            {"immutable_reference": "ghcr.io/example/other@sha256:" + "b" * 64}
        ),
    )

    with pytest.raises(DescriptorValidationError, match="immutable_reference"):
        validate_descriptor(valid_descriptor)


def test_rejects_duplicate_evidence_names(valid_descriptor):
    def duplicate(descriptor):
        descriptor["evidence"][-1]["name"] = descriptor["evidence"][0]["name"]

    _mutate(valid_descriptor, duplicate)
    with pytest.raises(DescriptorValidationError, match="Duplicate evidence name"):
        validate_descriptor(valid_descriptor)


@pytest.mark.parametrize("unsafe_path", ["../outside.json", "/absolute.json", "a\\\\b.json", "a/../b.json"])
def test_rejects_unsafe_evidence_paths(valid_descriptor, unsafe_path):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["evidence"][0].update({"path": unsafe_path}),
    )

    with pytest.raises(DescriptorValidationError, match="Unsafe evidence path"):
        validate_descriptor(valid_descriptor)


def test_rejects_build_metadata_hash_reference_mismatch(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["build"].update({"build_metadata_sha256": "f" * 64}),
    )

    with pytest.raises(DescriptorValidationError, match="Build metadata SHA-256"):
        validate_descriptor(valid_descriptor)


def test_rejects_framework_application_identity_mismatch(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["runtime_inventory"]["framework"].update(
            {"actual_commit": "e" * 40}
        ),
    )

    with pytest.raises(DescriptorValidationError, match="framework actual_commit"):
        validate_descriptor(valid_descriptor)


def test_rejects_service_requirement_state_without_composition_service(valid_descriptor):
    def set_inconsistent_state(descriptor):
        descriptor["requirements"]["services"]["state"] = "declared"
        descriptor["requirements"]["services"]["declarations"] = [
            {
                "authority": "service_descriptor",
                "reference": "services/redis.json",
                "sha256": "c" * 64,
                "claims": [{"service_id": "redis", "service_kind": "container"}],
            }
        ]

    _mutate(valid_descriptor, set_inconsistent_state)
    with pytest.raises(DescriptorValidationError, match="Services requirement declarations"):
        validate_descriptor(valid_descriptor)


def test_rejects_composition_dependency_cycle(valid_descriptor):
    def add_cycle(descriptor):
        descriptor["composition"]["services"] = [
            {
                "service_id": "redis",
                "service_kind": "container",
                "descriptor_path": "services/redis.json",
                "descriptor_sha256": "c" * 64,
                "depends_on": ["smtp"],
            }
        ]
        descriptor["composition"]["external_requirements"] = [
            {
                "requirement_id": "smtp",
                "provider": "Example",
                "requirement": "SMTP relay",
                "descriptor_path": "services/smtp.json",
                "descriptor_sha256": "d" * 64,
                "depends_on": ["redis"],
            }
        ]
        descriptor["requirements"]["services"] = {
            "state": "declared",
            "declarations": [
                {
                    "authority": "service_descriptor",
                    "reference": "services/redis.json",
                    "sha256": "c" * 64,
                    "claims": [{"service_id": "redis", "service_kind": "container"}],
                },
                {
                    "authority": "service_descriptor",
                    "reference": "services/smtp.json",
                    "sha256": "d" * 64,
                    "claims": [{"service_id": "smtp", "service_kind": "external"}],
                },
            ],
            "verification": [],
        }

    _mutate(valid_descriptor, add_cycle)
    with pytest.raises(DescriptorValidationError, match="dependency cycle"):
        validate_descriptor(valid_descriptor)


def test_rejects_unresolved_composition_dependency(valid_descriptor):
    def add_unresolved_dependency(descriptor):
        descriptor["composition"]["services"] = [
            {
                "service_id": "redis",
                "service_kind": "container",
                "descriptor_path": "services/redis.json",
                "descriptor_sha256": "c" * 64,
                "depends_on": ["missing"],
            }
        ]
        descriptor["requirements"]["services"] = {
            "state": "declared",
            "declarations": [
                {
                    "authority": "service_descriptor",
                    "reference": "services/redis.json",
                    "sha256": "c" * 64,
                    "claims": [{"service_id": "redis", "service_kind": "container"}],
                }
            ],
            "verification": [],
        }

    _mutate(valid_descriptor, add_unresolved_dependency)
    with pytest.raises(DescriptorValidationError, match="is not declared"):
        validate_descriptor(valid_descriptor)


def test_rejects_schema_invalid_descriptor(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor.update({"unrecognized": True}),
    )

    with pytest.raises(DescriptorValidationError, match="Schema validation failed"):
        validate_descriptor(valid_descriptor)


def test_rejects_floating_point_values_under_canonicalization_profile(valid_descriptor):
    def add_float(descriptor):
        descriptor["runtime_inventory"]["installed_packages"]["python"] = [
            {"name": "example", "version": "1.0", "unapproved_metric": 1.5}
        ]

    descriptor = _load(valid_descriptor)
    add_float(descriptor)
    # A descriptor containing a float cannot be re-hashed under the contract profile.
    valid_descriptor.write_text(
        json.dumps(descriptor, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(DescriptorValidationError, match="prohibits floating-point"):
        validate_descriptor(valid_descriptor)


def test_rejects_duplicate_json_object_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"1.0.0","schema_version":"1.0.0"}', encoding="utf-8")

    with pytest.raises(DescriptorValidationError, match="Duplicate JSON object key"):
        validate_descriptor(path)


def test_rejects_composition_lock_hash_reference_mismatch(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["composition"]["lock"].update({"sha256": "f" * 64}),
    )

    with pytest.raises(DescriptorValidationError, match="Composition lock SHA-256"):
        validate_descriptor(valid_descriptor)


def test_rejects_artifact_runtime_platform_mismatch(valid_descriptor):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["runtime_inventory"]["platform"].update(
            {"oci": "linux/arm64"}
        ),
    )

    with pytest.raises(DescriptorValidationError, match="Artifact platform"):
        validate_descriptor(valid_descriptor)


def test_rejects_requirement_verification_hash_reference_mismatch(valid_descriptor):
    def add_invalid_verification(descriptor):
        descriptor["requirements"]["storage"] = {
            "state": "verified",
            "declarations": [
                {
                    "authority": "product_manifest",
                    "reference": "images/ndf/manifests/products/tenant/dalali-v16.json",
                    "sha256": "a" * 64,
                    "claims": [{"storage": "persistent"}],
                }
            ],
            "verification": [
                {
                    "method": "fixture-check",
                    "result": "passed",
                    "evidence_reference": "build-inventory.json",
                    "evidence_sha256": "f" * 64,
                }
            ],
        }

    _mutate(valid_descriptor, add_invalid_verification)
    with pytest.raises(DescriptorValidationError, match="verification SHA-256"):
        validate_descriptor(valid_descriptor)


def test_validator_has_no_generator_or_evidence_binder_dependency():
    source = Path(validate_descriptor.__code__.co_filename).read_text(encoding="utf-8")

    assert "generate_product_deployment_descriptor" not in source
    assert "bind_verification_evidence" not in source


def test_allows_requirement_evidence_references_outside_fixed_m425_bundle(valid_descriptor):
    def add_external_evidence_reference(descriptor):
        descriptor["requirements"]["storage"] = {
            "state": "verified",
            "declarations": [
                {
                    "authority": "product_manifest",
                    "reference": "images/ndf/manifests/products/tenant/dalali-v16.json",
                    "sha256": "a" * 64,
                    "claims": [{"storage": "persistent"}],
                }
            ],
            "verification": [
                {
                    "method": "storage-contract-review",
                    "result": "passed",
                    "evidence_reference": "evidence/storage-verification.json",
                    "evidence_sha256": "b" * 64,
                }
            ],
        }

    _mutate(valid_descriptor, add_external_evidence_reference)
    report = validate_descriptor(valid_descriptor)

    assert report["status"] == "passed"


def test_rejects_service_identity_collision_with_bench_application(valid_descriptor):
    def add_collision(descriptor):
        descriptor["composition"]["services"] = [
            {
                "service_id": "frappe",
                "service_kind": "container",
                "descriptor_path": "services/frappe.json",
                "descriptor_sha256": "c" * 64,
                "depends_on": [],
            }
        ]
        descriptor["requirements"]["services"] = {
            "state": "declared",
            "declarations": [
                {
                    "authority": "service_descriptor",
                    "reference": "services/frappe.json",
                    "sha256": "c" * 64,
                    "claims": [{"service_id": "frappe", "service_kind": "container"}],
                }
            ],
            "verification": [],
        }

    _mutate(valid_descriptor, add_collision)
    with pytest.raises(DescriptorValidationError, match="collides with a Bench application"):
        validate_descriptor(valid_descriptor)


def test_cli_emits_machine_readable_success_report(valid_descriptor, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["validate_product_deployment_descriptor.py", "--descriptor", str(valid_descriptor)],
    )

    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "passed"
    assert report["evidence_count"] == 11


def test_cli_emits_machine_readable_failure_and_nonzero_status(
    valid_descriptor, monkeypatch, capsys
):
    _mutate(
        valid_descriptor,
        lambda descriptor: descriptor["product"].update({"name": "Tampered"}),
        rehash=False,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["validate_product_deployment_descriptor.py", "--descriptor", str(valid_descriptor)],
    )

    assert main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "failed"
    assert "content SHA-256 mismatch" in report["error"]


def test_accepts_verified_service_requirement_state_when_evidence_is_present(
    valid_descriptor,
):
    def add_verified_service(descriptor):
        service_path = "services/redis.json"
        service_sha = "c" * 64
        descriptor["composition"]["services"] = [
            {
                "service_id": "redis",
                "service_kind": "container",
                "descriptor_path": service_path,
                "descriptor_sha256": service_sha,
                "depends_on": [],
            }
        ]
        inventory_evidence = next(
            item for item in descriptor["evidence"] if item["name"] == "build_inventory"
        )
        descriptor["requirements"]["services"] = {
            "state": "verified",
            "declarations": [
                {
                    "authority": "service_descriptor",
                    "reference": service_path,
                    "sha256": service_sha,
                    "claims": [{"service_id": "redis", "service_kind": "container"}],
                }
            ],
            "verification": [
                {
                    "method": "independent-service-check",
                    "result": "passed",
                    "evidence_reference": inventory_evidence["path"],
                    "evidence_sha256": inventory_evidence["sha256"],
                }
            ],
        }

    _mutate(valid_descriptor, add_verified_service)
    report = validate_descriptor(valid_descriptor)

    assert report["status"] == "passed"
