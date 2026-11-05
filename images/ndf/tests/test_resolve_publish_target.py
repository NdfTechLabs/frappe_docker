import json

import pytest

from scripts.resolve_publish_target import (
    PublishTargetError,
    resolve_publish_target,
)


def _write_publish_inputs(
    ndf_dir,
    *,
    repository="ghcr.io/ndftechlabs/dalali",
    manifest_path="products/tenant/dalali-v16.json",
    framework_version="16",
):
    definitions_dir = ndf_dir / "image-definitions"
    manifests_dir = ndf_dir / "manifests" / "products" / "tenant"
    definitions_dir.mkdir(parents=True)
    manifests_dir.mkdir(parents=True)

    definitions = {
        "schema_version": "1.0",
        "images": [
            {
                "id": "dalali-v16",
                "manifest": manifest_path,
                "repository": repository,
            }
        ],
    }
    (definitions_dir / "images-v1.json").write_text(
        json.dumps(definitions),
        encoding="utf-8",
    )

    manifest = {"framework": {"version": framework_version}}
    (manifests_dir / "dalali-v16.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )


def test_resolve_publish_target_uses_framework_major_and_full_sha(tmp_path):
    _write_publish_inputs(tmp_path)
    source_sha = "a" * 40

    result = resolve_publish_target(tmp_path, "dalali-v16", source_sha)

    assert result == {
        "image_id": "dalali-v16",
        "repository": "ghcr.io/ndftechlabs/dalali",
        "framework_major": "16",
        "tag": f"v16-{source_sha}",
        "image_ref": f"ghcr.io/ndftechlabs/dalali:v16-{source_sha}",
        "source_sha": source_sha,
    }


def test_resolve_publish_target_rejects_non_full_git_sha(tmp_path):
    _write_publish_inputs(tmp_path)

    with pytest.raises(PublishTargetError, match="full 40-character Git SHA"):
        resolve_publish_target(tmp_path, "dalali-v16", "abc123")


def test_resolve_publish_target_rejects_unknown_image(tmp_path):
    _write_publish_inputs(tmp_path)

    with pytest.raises(PublishTargetError, match="exactly one image definition"):
        resolve_publish_target(tmp_path, "missing-v16", "a" * 40)


def test_resolve_publish_target_rejects_unsafe_manifest_path(tmp_path):
    _write_publish_inputs(tmp_path, manifest_path="../outside.json")

    with pytest.raises(PublishTargetError, match="Unsafe manifest path"):
        resolve_publish_target(tmp_path, "dalali-v16", "a" * 40)


def test_resolve_publish_target_rejects_non_ndf_registry(tmp_path):
    _write_publish_inputs(tmp_path, repository="ghcr.io/other-org/dalali")

    with pytest.raises(PublishTargetError, match="approved NDF GHCR repository"):
        resolve_publish_target(tmp_path, "dalali-v16", "a" * 40)


def test_resolve_publish_target_rejects_invalid_framework_version(tmp_path):
    _write_publish_inputs(tmp_path, framework_version="stable")

    with pytest.raises(PublishTargetError, match="Invalid framework version"):
        resolve_publish_target(tmp_path, "dalali-v16", "a" * 40)
