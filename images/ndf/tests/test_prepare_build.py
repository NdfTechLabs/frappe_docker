import json
import shutil
from pathlib import Path

import pytest
from scripts.prepare_build import (
    BuildPreparationError,
    build_apps_json,
    prepare_build,
)
from scripts.resolve_manifest import ManifestLoader


@pytest.fixture
def build_project(tmp_path):
    """Create a small, isolated NDF project with a valid product lock."""
    project_root = Path(__file__).resolve().parents[1]

    ndf_dir = tmp_path / "images" / "ndf"
    manifests_dir = ndf_dir / "manifests" / "products"
    schemas_dir = ndf_dir / "schemas"
    locks_dir = ndf_dir / "locks"
    definitions_dir = ndf_dir / "image-definitions"

    for directory in (manifests_dir, schemas_dir, locks_dir, definitions_dir):
        directory.mkdir(parents=True, exist_ok=True)

    for schema_name in (
        "application-manifest-v1.schema.json",
        "image-definitions-v1.schema.json",
    ):
        shutil.copy2(
            project_root / "schemas" / schema_name,
            schemas_dir / schema_name,
        )

    applications = [
        {
            "name": "frappe",
            "repository": "https://github.com/frappe/frappe",
            "target_ref": "version-16",
            "ref": "a" * 40,
            "compatibility_status": "verified",
            "_reference_kind": "tag",
            "_resolved_ref": "refs/tags/version-16",
            "dependencies": [],
        },
        {
            "name": "erpnext",
            "repository": "https://github.com/frappe/erpnext",
            "target_ref": "version-16",
            "ref": "b" * 40,
            "compatibility_status": "verified",
            "_reference_kind": "tag",
            "_resolved_ref": "refs/tags/version-16",
            "dependencies": ["frappe"],
        },
        {
            "name": "dt_example",
            "repository": "https://github.com/NdfTechLabs/dt_example",
            "target_ref": "version-1",
            "ref": "c" * 40,
            "compatibility_status": "verified",
            "_reference_kind": "tag",
            "_resolved_ref": "refs/tags/version-1",
            "dependencies": ["frappe", "erpnext"],
        },
    ]

    manifest = {
        "manifest_version": "1.0.0",
        "id": "test-product-v16",
        "name": "Test Product",
        "framework": {
            "name": "frappe",
            "version": "16",
            "release_channel": "stable",
            "target_ref": "version-16",
        },
        "profile": {
            "type": "product",
            "required": True,
            "install_by_default": True,
        },
        "resolution": {
            "strategy": "locked",
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
            "notes": [],
        },
        "validation": {},
    }

    manifest_path = manifests_dir / "test-product-v16.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    # Generate the fixture lock through the current resolver contract.
    # This keeps the test aligned with lock v2 policy and provenance fields.
    loader = ManifestLoader(ndf_dir / "manifests")
    loaded_manifest = loader.load("products/test-product-v16.json")
    lock_data = loader.build_lock_data(loaded_manifest, applications)
    loader.write_lock_file(
        lock_data,
        locks_dir / "test-product-v16.lock.json",
    )

    definitions = {
        "$schema": "../schemas/image-definitions-v1.schema.json",
        "schema_version": "1.0",
        "registry": {
            "host": "ghcr.io",
            "namespace": "ndftechlabs",
        },
        "images": [
            {
                "id": manifest["id"],
                "product": "test-product",
                "manifest": "products/test-product-v16.json",
                "repository": "ghcr.io/ndftechlabs/test-product",
            }
        ],
    }

    (definitions_dir / "images-v1.json").write_text(
        json.dumps(definitions, indent=2),
        encoding="utf-8",
    )

    return ndf_dir


def test_build_apps_json_uses_target_refs_and_excludes_frappe():
    lock = {
        "applications": [
            {
                "name": "frappe",
                "repository": "https://github.com/frappe/frappe",
                "target_ref": "version-16",
                "installation_order": 1,
            },
            {
                "name": "erpnext",
                "repository": "https://github.com/frappe/erpnext",
                "target_ref": "version-16",
                "installation_order": 2,
            },
            {
                "name": "dt_example",
                "repository": "https://github.com/NdfTechLabs/dt_example",
                "target_ref": "version-1",
                "installation_order": 3,
            },
        ]
    }

    assert build_apps_json(lock) == [
        {
            "url": "https://github.com/frappe/erpnext",
            "branch": "version-16",
        },
        {
            "url": "https://github.com/NdfTechLabs/dt_example",
            "branch": "version-1",
        },
    ]


def test_prepare_build_generates_bench_inputs_and_metadata(
    build_project,
    tmp_path,
):
    output_dir = tmp_path / "prepared"

    result = prepare_build(
        ndf_dir=build_project,
        image_id="test-product-v16",
        output_dir=output_dir,
    )
    apps_json = json.loads(result["apps_json_path"].read_text(encoding="utf-8"))
    metadata = json.loads(result["metadata_path"].read_text(encoding="utf-8"))

    assert result["image"]["repository"] == ("ghcr.io/ndftechlabs/test-product")
    assert result["framework"]["target_ref"] == "version-16"
    assert result["applications_count"] == 3
    assert result["bench_apps_count"] == 2

    assert [app["branch"] for app in apps_json] == [
        "version-16",
        "version-1",
    ]
    assert all(app["url"].endswith(("erpnext", "dt_example")) for app in apps_json)

    assert metadata["image"]["id"] == "test-product-v16"
    assert metadata["applications"][0]["resolved_sha"] == "a" * 40
    assert metadata["applications"][2]["resolved_sha"] == "c" * 40
    assert len(metadata["lock"]["sha256"]) == 64


def test_prepare_build_rejects_unknown_image(build_project):
    with pytest.raises(BuildPreparationError, match="Unknown image ID"):
        prepare_build(
            ndf_dir=build_project,
            image_id="missing-v16",
        )


def test_prepare_build_rejects_stale_manifest_checksum(
    build_project,
):
    manifest_path = build_project / "manifests" / "products" / "test-product-v16.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["name"] = "Changed Product"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    with pytest.raises(
        BuildPreparationError,
        match="Source manifest has changed",
    ):
        prepare_build(
            ndf_dir=build_project,
            image_id="test-product-v16",
        )


def test_prepare_build_rejects_framework_ref_mismatch(build_project):
    lock_path = build_project / "locks" / "test-product-v16.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["framework"]["target_ref"] = "develop"
    lock_path.write_text(
        json.dumps(lock, indent=2),
        encoding="utf-8",
    )

    with pytest.raises(
        BuildPreparationError,
        match="Framework source identity does not match the locked Frappe application.",
    ):
        prepare_build(
            ndf_dir=build_project,
            image_id="test-product-v16",
        )
