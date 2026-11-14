import json

import pytest

from scripts.generate_product_deployment_descriptor import (
    DescriptorGenerationError,
    _canonical_json,
    _load_inputs,
    generate_descriptor,
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
