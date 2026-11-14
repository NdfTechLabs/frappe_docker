import hashlib
import json

import pytest
from scripts.bind_verification_evidence import create_verification_evidence
from scripts.generate_product_deployment_descriptor import (
    DescriptorGenerationError,
    _canonical_json,
    _load_inputs,
    generate_descriptor,
    main,
)


def test_canonical_json_is_stable_and_compact():
    left = {"z": 1, "a": {"y": True, "x": "value"}}
    right = {"a": {"x": "value", "y": True}, "z": 1}

    assert _canonical_json(left) == _canonical_json(right)
    assert _canonical_json(left) == b'{"a":{"x":"value","y":true},"z":1}'


def test_canonical_json_rejects_floats():
    with pytest.raises(DescriptorGenerationError, match="floating-point"):
        _canonical_json({"unsafe": 1.25})


def test_generator_requires_complete_verified_evidence(tmp_path):
    with pytest.raises(DescriptorGenerationError, match="Unable to read"):
        generate_descriptor(
            tmp_path,
            source_commit="a" * 40,
            workflow_run_id="123456",
            built_at="2026-11-14T12:00:00Z",
        )


@pytest.mark.parametrize(
    "timestamp",
    ["not-a-date", "2026-11-14T12:00:00"],
)
def test_generator_rejects_invalid_or_timezone_free_timestamp(tmp_path, timestamp):
    with pytest.raises(DescriptorGenerationError, match="timestamp"):
        generate_descriptor(
            tmp_path,
            source_commit="a" * 40,
            workflow_run_id="123456",
            built_at=timestamp,
        )


def test_generator_rejects_non_full_source_commit(tmp_path):
    with pytest.raises(DescriptorGenerationError, match="full lowercase Git SHA"):
        generate_descriptor(
            tmp_path,
            source_commit="abc123",
            workflow_run_id="123456",
            built_at="2026-11-14T12:00:00Z",
        )


def test_load_inputs_uses_product_specific_lock_filename(tmp_path):
    (tmp_path / "build-metadata.json").write_text(
        json.dumps({"image": {"id": "dalali-v16"}}), encoding="utf-8"
    )
    expected = {
        "dalali-v16.lock-v2.json": {"lock_version": 2},
        "apps.json": {},
        "buildx-metadata.json": {},
        "build-inventory.json": {},
        "build-evidence.json": {},
        "source-provenance.json": {},
        "source-provenance-verification.json": {},
        "source-tree-verification-post-cleanup.json": {},
        "source-tree-verification-runtime.json": {},
        "image-composition-verification.json": {},
    }
    for filename, value in expected.items():
        (tmp_path / filename).write_text(json.dumps(value), encoding="utf-8")

    values, files = _load_inputs(tmp_path)

    assert values["lock_v2"]["lock_version"] == 2
    assert "lock_v2" in files
    assert "build_metadata" in values


# End-to-end generator fixtures use synthetic, internally consistent evidence.
# They exercise the real file-loading, digest-binding, gate and schema paths
# without requiring a registry image or trusting a mutable image tag.

IMAGE_ID = "dalali-v16"
IMAGE_REPOSITORY = "ghcr.io/ndftechlabs/dalali"
IMAGE_DIGEST = "sha256:" + "a" * 64
APP_COMMIT = "b" * 40
LOCK_FILENAME = f"{IMAGE_ID}.lock-v2.json"


def _write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_evidence_bindings(output_dir):
    """Rebind synthetic evidence after a deliberate fixture mutation."""
    lock_bytes = (output_dir / LOCK_FILENAME).read_bytes()
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    inventory_path = output_dir / "build-inventory.json"
    build_evidence_path = output_dir / "build-evidence.json"
    build_evidence = json.loads(build_evidence_path.read_text(encoding="utf-8"))
    build_evidence["inventory_sha256"] = hashlib.sha256(
        inventory_path.read_bytes()
    ).hexdigest()
    build_evidence["lock_sha256"] = lock_sha
    _write_json(build_evidence_path, build_evidence)

    logical_files = {
        "lock_v2": ("lock-v2.json", LOCK_FILENAME),
        "apps_json": ("apps.json", "apps.json"),
        "build_metadata": ("build-metadata.json", "build-metadata.json"),
        "buildx_metadata": ("buildx-metadata.json", "buildx-metadata.json"),
        "build_inventory": ("build-inventory.json", "build-inventory.json"),
        "build_evidence": ("build-evidence.json", "build-evidence.json"),
        "source_provenance": ("source-provenance.json", "source-provenance.json"),
        "source_provenance_verification": (
            "source-provenance-verification.json",
            "source-provenance-verification.json",
        ),
        "source_tree_post_cleanup": (
            "source-tree-verification-post-cleanup.json",
            "source-tree-verification-post-cleanup.json",
        ),
        "source_tree_runtime": (
            "source-tree-verification-runtime.json",
            "source-tree-verification-runtime.json",
        ),
        "image_composition_verification": (
            "image-composition-verification.json",
            "image-composition-verification.json",
        ),
    }
    artifacts = {
        name: (logical_path, (output_dir / filename).read_bytes())
        for name, (logical_path, filename) in logical_files.items()
    }
    statuses = {
        name: "passed"
        for name in (
            "source_provenance_verification",
            "source_tree_post_cleanup",
            "source_tree_runtime",
            "image_composition_verification",
        )
    }
    evidence = create_verification_evidence(
        image_reference=f"{IMAGE_REPOSITORY}:candidate-test",
        image_repository=IMAGE_REPOSITORY,
        image_id=IMAGE_ID,
        image_digest=IMAGE_DIGEST,
        lock_bytes=lock_bytes,
        artifacts=artifacts,
        statuses=statuses,
    )
    _write_json(output_dir / "image-verification-evidence.json", evidence)
    validation = json.loads(
        (output_dir / "image-validation.json").read_text(encoding="utf-8")
    )
    validation["verification_evidence"] = evidence
    _write_json(output_dir / "image-validation.json", validation)


@pytest.fixture
def complete_build_output(tmp_path):
    lock = {
        "lock_version": 2,
        "product": {"id": "dalali", "name": "Dalali"},
        "applications": [{"name": "frappe"}],
        "services": [],
        "external_requirements": [],
    }
    lock_bytes = (json.dumps(lock, sort_keys=True) + "\n").encode()
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    (tmp_path / LOCK_FILENAME).write_bytes(lock_bytes)

    metadata = {
        "image": {"id": IMAGE_ID, "repository": IMAGE_REPOSITORY},
        "lock": {"sha256": lock_sha},
    }
    inventory = {
        "stage": "builder",
        "lock": {"version": 2, "sha256": lock_sha},
        "applications": [
            {
                "name": "frappe",
                "repository": "frappe/frappe",
                "requested_ref": "version-16",
                "actual_commit": APP_COMMIT,
            }
        ],
        "framework": {
            "name": "frappe",
            "repository": "frappe/frappe",
            "requested_ref": "version-16",
            "resolver_commit": APP_COMMIT,
            "actual_commit": APP_COMMIT,
        },
        "runtime": {
            "python": {
                "executable": "/usr/bin/python3",
                "environment": "system",
                "version": "3.14.3",
                "implementation": "CPython",
            },
            "node": {"version": "24.21.0"},
            "yarn": {"version": "1.22.22"},
            "bench": {"version": "5.31.1"},
            "platform": {"system": "Linux", "machine": "x86_64", "oci": "linux/amd64"},
        },
        "installed_packages": {"python": [], "node": [], "debian": []},
    }
    composition = {
        "status": "passed",
        "lock": {"version": 2, "sha256": lock_sha},
        "services": [],
        "external_requirements": [],
    }
    provenance = {
        "repositories": [
            {
                "name": "frappe",
                "actual_commit": APP_COMMIT,
                "source_tree": {"sha256": "c" * 64},
            }
        ]
    }
    payloads = {
        "apps.json": {"apps": ["frappe"]},
        "build-metadata.json": metadata,
        "buildx-metadata.json": {"containerimage.digest": IMAGE_DIGEST},
        "build-inventory.json": inventory,
        "build-evidence.json": {
            "status": "bound",
            "image_digest": IMAGE_DIGEST,
            "lock_sha256": lock_sha,
            "inventory_sha256": "",
        },
        "source-provenance.json": provenance,
        "source-provenance-verification.json": {"status": "passed"},
        "source-tree-verification-post-cleanup.json": {"status": "passed"},
        "source-tree-verification-runtime.json": {"status": "passed"},
        "image-composition-verification.json": composition,
    }
    for filename, value in payloads.items():
        _write_json(tmp_path / filename, value)

    # First compute the exact inventory binding, then create the evidence manifest.
    build_evidence_path = tmp_path / "build-evidence.json"
    build_evidence = json.loads(build_evidence_path.read_text(encoding="utf-8"))
    build_evidence["inventory_sha256"] = hashlib.sha256(
        (tmp_path / "build-inventory.json").read_bytes()
    ).hexdigest()
    _write_json(build_evidence_path, build_evidence)
    _write_json(
        tmp_path / "image-validation.json",
        {
            "status": "passed",
            "image_id": IMAGE_ID,
            "image_digest": IMAGE_DIGEST,
            "verification_evidence": {},
        },
    )
    _refresh_evidence_bindings(tmp_path)

    _write_json(
        tmp_path / "build-result.json",
        {
            "digest": IMAGE_DIGEST,
            "image_id": IMAGE_ID,
            "repository": IMAGE_REPOSITORY,
            "platforms": ["linux/amd64"],
            "tags": ["candidate-test"],
        },
    )
    evidence = json.loads(
        (tmp_path / "image-verification-evidence.json").read_text(encoding="utf-8")
    )
    _write_json(
        tmp_path / "image-validation.json",
        {
            "status": "passed",
            "image_id": IMAGE_ID,
            "image_digest": IMAGE_DIGEST,
            "verification_evidence": evidence,
        },
    )
    _write_json(
        tmp_path / "publication-gate.json",
        {
            "status": "ready",
            "image": {
                "id": IMAGE_ID,
                "repository": IMAGE_REPOSITORY,
                "digest": IMAGE_DIGEST,
            },
        },
    )
    return tmp_path


def _generate(output_dir, **overrides):
    arguments = {
        "source_commit": "d" * 40,
        "workflow_run_id": "43610000000",
        "built_at": "2026-11-14T12:00:00Z",
    }
    arguments.update(overrides)
    return generate_descriptor(output_dir, **arguments)


def test_generates_complete_schema_valid_descriptor_deterministically(
    complete_build_output,
):
    first = _generate(complete_build_output)
    second = _generate(complete_build_output)

    assert first == second
    assert first["descriptor_id"] == f"pdd:dalali:linux-amd64:sha256:{'a' * 64}"
    assert (
        first["artifact"]["immutable_reference"] == f"{IMAGE_REPOSITORY}@{IMAGE_DIGEST}"
    )
    assert first["composition"]["applications"][0]["actual_commit"] == APP_COMMIT
    assert first["runtime_inventory"]["scope"] == "builder_stage"
    assert len(first["evidence"]) == 11
    assert first["integrity"]["content_sha256"] == second["integrity"]["content_sha256"]


def test_rejects_publication_gate_not_ready(complete_build_output):
    _write_json(
        complete_build_output / "publication-gate.json",
        {"status": "blocked", "image": {}},
    )
    with pytest.raises(
        DescriptorGenerationError, match="Publication gate must be ready"
    ):
        _generate(complete_build_output)


def test_rejects_publication_gate_image_digest_mismatch(complete_build_output):
    gate = json.loads((complete_build_output / "publication-gate.json").read_text())
    gate["image"]["digest"] = "sha256:" + "e" * 64
    _write_json(complete_build_output / "publication-gate.json", gate)
    with pytest.raises(DescriptorGenerationError, match="different image artifact"):
        _generate(complete_build_output)


def test_rejects_buildx_and_result_digest_mismatch(complete_build_output):
    _write_json(
        complete_build_output / "buildx-metadata.json",
        {"containerimage.digest": "sha256:" + "e" * 64},
    )
    with pytest.raises(
        DescriptorGenerationError,
        match="Buildx metadata and build-result digests differ",
    ):
        _generate(complete_build_output)


def test_rejects_lock_bytes_not_bound_by_build_metadata(complete_build_output):
    (complete_build_output / LOCK_FILENAME).write_bytes(
        b'{"lock_version":2,"tampered":true}\n'
    )
    with pytest.raises(DescriptorGenerationError, match="exact lock-v2 bytes"):
        _generate(complete_build_output)


def test_rejects_tampered_bound_evidence(complete_build_output):
    (complete_build_output / "source-provenance.json").write_text('{"tampered":true}\n')
    with pytest.raises(
        DescriptorGenerationError, match="Digest-bound evidence verification failed"
    ):
        _generate(complete_build_output)


def test_rejects_application_commit_not_confirmed_by_provenance(complete_build_output):
    inventory = json.loads((complete_build_output / "build-inventory.json").read_text())
    inventory["applications"][0]["actual_commit"] = "e" * 40
    _write_json(complete_build_output / "build-inventory.json", inventory)
    _refresh_evidence_bindings(complete_build_output)
    with pytest.raises(
        DescriptorGenerationError,
        match="Source provenance does not confirm actual commit",
    ):
        _generate(complete_build_output)


def test_rejects_lock_service_not_confirmed_by_composition(complete_build_output):
    lock_path = complete_build_output / LOCK_FILENAME
    lock = json.loads(lock_path.read_text())
    lock["services"] = [
        {
            "service_id": "redis",
            "descriptor": "services/redis.json",
            "descriptor_sha256": "f" * 64,
            "depends_on": [],
            "artifact": {"image": "redis@sha256:" + "1" * 64},
        }
    ]
    lock_bytes = (json.dumps(lock, sort_keys=True) + "\n").encode()
    lock_path.write_bytes(lock_bytes)
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    metadata = json.loads((complete_build_output / "build-metadata.json").read_text())
    metadata["lock"]["sha256"] = lock_sha
    _write_json(complete_build_output / "build-metadata.json", metadata)
    inventory = json.loads((complete_build_output / "build-inventory.json").read_text())
    inventory["lock"]["sha256"] = lock_sha
    _write_json(complete_build_output / "build-inventory.json", inventory)
    composition = json.loads(
        (complete_build_output / "image-composition-verification.json").read_text()
    )
    composition["lock"]["sha256"] = lock_sha
    _write_json(
        complete_build_output / "image-composition-verification.json", composition
    )
    build_evidence = json.loads(
        (complete_build_output / "build-evidence.json").read_text()
    )
    build_evidence["lock_sha256"] = lock_sha
    _write_json(complete_build_output / "build-evidence.json", build_evidence)
    _refresh_evidence_bindings(complete_build_output)
    with pytest.raises(
        DescriptorGenerationError,
        match="Lock service inventory does not match verified composition",
    ):
        _generate(complete_build_output)


def test_cli_writes_descriptor_atomically_and_cleans_temporary_file(
    complete_build_output, tmp_path, monkeypatch
):
    import sys

    output = tmp_path / "published" / "product-deployment.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate_product_deployment_descriptor",
            "--build-output-dir",
            str(complete_build_output),
            "--source-commit",
            "d" * 40,
            "--workflow-run-id",
            "43610000000",
            "--built-at",
            "2026-11-14T12:00:00Z",
            "--output",
            str(output),
        ],
    )

    assert main() == 0
    generated = json.loads(output.read_text(encoding="utf-8"))
    assert generated["descriptor_type"] == "ndf.product-deployment"
    assert not output.with_suffix(output.suffix + ".tmp").exists()


def test_cli_preserves_existing_output_and_cleans_temp_file_on_replace_failure(
    complete_build_output, tmp_path, monkeypatch
):
    import sys
    from pathlib import Path

    output = tmp_path / "product-deployment.json"
    output.write_text("previous-valid-output\n", encoding="utf-8")
    temporary = output.with_suffix(output.suffix + ".tmp")
    original_replace = Path.replace

    def fail_temporary_replace(self, target):
        if self == temporary:
            raise OSError("simulated atomic replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_temporary_replace)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate_product_deployment_descriptor",
            "--build-output-dir",
            str(complete_build_output),
            "--source-commit",
            "d" * 40,
            "--workflow-run-id",
            "43610000000",
            "--built-at",
            "2026-11-14T12:00:00Z",
            "--output",
            str(output),
        ],
    )

    assert main() == 1
    assert output.read_text(encoding="utf-8") == "previous-valid-output\n"
    assert not temporary.exists()
