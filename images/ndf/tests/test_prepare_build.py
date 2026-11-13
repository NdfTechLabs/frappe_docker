import hashlib
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
    """Create an isolated NDF project with a current product manifest."""
    project_root = Path(__file__).resolve().parents[1]

    ndf_dir = tmp_path / "images" / "ndf"
    manifests_dir = ndf_dir / "manifests" / "products"
    schemas_dir = ndf_dir / "schemas"
    policies_dir = ndf_dir / "policies"
    locks_dir = ndf_dir / "locks"
    definitions_dir = ndf_dir / "image-definitions"

    for directory in (
        manifests_dir,
        schemas_dir,
        policies_dir,
        locks_dir,
        definitions_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    shutil.copy2(
        project_root / "policies" / "package-source-profiles-v1.json",
        policies_dir / "package-source-profiles-v1.json",
    )

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
            "ref": None,
            "required": True,
            "install_order": 10,
            "dependencies": [],
            "compatibility_status": "verified",
        },
        {
            "name": "erpnext",
            "repository": "https://github.com/frappe/erpnext",
            "target_ref": "version-16",
            "ref": None,
            "required": True,
            "install_order": 20,
            "dependencies": ["frappe"],
            "compatibility_status": "verified",
        },
        {
            "name": "dt_example",
            "repository": "https://github.com/NdfTechLabs/dt_example",
            "target_ref": "version-1",
            "ref": None,
            "required": True,
            "install_order": 30,
            "dependencies": ["frappe", "erpnext"],
            "compatibility_status": "verified",
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
        "applications": applications,
        "validation": {},
    }

    manifest_path = manifests_dir / "test-product-v16.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
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


@pytest.fixture
def fake_git_refs(monkeypatch):
    """Replace remote Git lookup with deterministic per-repository evidence."""
    resolved = {
        "https://github.com/frappe/frappe": "a" * 40,
        "https://github.com/frappe/erpnext": "b" * 40,
        "https://github.com/NdfTechLabs/dt_example": "c" * 40,
    }
    calls = []

    def resolve_git_ref(_loader, repository, target_ref):
        calls.append((repository, target_ref))
        return {
            "sha": resolved[repository],
            "kind": "tag",
            "name": f"refs/tags/{target_ref}",
        }

    monkeypatch.setattr(ManifestLoader, "resolve_git_ref", resolve_git_ref)
    return calls


def test_build_apps_json_uses_requested_refs_and_excludes_frappe():
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


def test_prepare_build_generates_fresh_lock_and_bench_inputs(
    build_project,
    fake_git_refs,
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
    lock = json.loads(result["lock_path"].read_text(encoding="utf-8"))

    assert result["image"]["repository"] == "ghcr.io/ndftechlabs/test-product"
    assert result["framework"]["target_ref"] == "version-16"
    assert result["applications_count"] == 3
    assert result["bench_apps_count"] == 2
    assert result["lock_path"] == output_dir / "test-product-v16.lock-v2.json"
    assert lock["lock_version"] == 2

    assert [app["branch"] for app in apps_json] == ["version-16", "version-1"]
    assert all(app["url"].endswith(("erpnext", "dt_example")) for app in apps_json)

    assert metadata["image"]["id"] == "test-product-v16"
    assert metadata["lock"]["version"] == 2
    assert metadata["lock"]["generated_from_current_manifests"] is True
    assert metadata["applications"][0]["resolved_sha"] == "a" * 40
    assert metadata["applications"][2]["resolved_sha"] == "c" * 40
    assert metadata["applications"][0]["target_ref"] == "version-16"
    assert len(metadata["lock"]["sha256"]) == 64
    assert len(fake_git_refs) == 3


def test_prepare_build_ignores_obsolete_checked_in_lock_v1(
    build_project,
    fake_git_refs,
    tmp_path,
):
    obsolete_lock = build_project / "locks" / "test-product-v16.lock.json"
    obsolete_lock.write_text(
        json.dumps({"lock_version": 1, "obsolete": True}),
        encoding="utf-8",
    )
    original_bytes = obsolete_lock.read_bytes()

    result = prepare_build(
        ndf_dir=build_project,
        image_id="test-product-v16",
        output_dir=tmp_path / "fresh-build",
    )

    generated_lock = json.loads(result["lock_path"].read_text(encoding="utf-8"))
    assert generated_lock["lock_version"] == 2
    assert result["lock_path"] != obsolete_lock
    assert obsolete_lock.read_bytes() == original_bytes


def test_prepare_build_resolves_rolling_refs_for_each_build(
    build_project,
    fake_git_refs,
    tmp_path,
):
    prepare_build(
        ndf_dir=build_project,
        image_id="test-product-v16",
        output_dir=tmp_path / "build-one",
    )
    prepare_build(
        ndf_dir=build_project,
        image_id="test-product-v16",
        output_dir=tmp_path / "build-two",
    )

    assert len(fake_git_refs) == 6


def test_prepare_build_uses_current_manifest_content(
    build_project,
    fake_git_refs,
    tmp_path,
):
    manifest_path = (
        build_project / "manifests" / "products" / "test-product-v16.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["name"] = "Updated Product"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    result = prepare_build(
        ndf_dir=build_project,
        image_id="test-product-v16",
        output_dir=tmp_path / "prepared",
    )
    lock = json.loads(result["lock_path"].read_text(encoding="utf-8"))
    product_manifest = next(
        item for item in lock["manifests"] if item["id"] == "test-product-v16"
    )

    assert lock["product"]["name"] == "Updated Product"
    assert product_manifest["sha256"] == hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()


def test_prepare_build_rejects_unverified_compatibility(
    build_project,
    fake_git_refs,
    tmp_path,
):
    manifest_path = (
        build_project / "manifests" / "products" / "test-product-v16.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["applications"][2]["compatibility_status"] = "pending_validation"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    with pytest.raises(
        BuildPreparationError,
        match="dt_example: compatibility_status=pending_validation",
    ):
        prepare_build(
            ndf_dir=build_project,
            image_id="test-product-v16",
            output_dir=tmp_path / "prepared",
        )


def test_prepare_build_rejects_unknown_image(build_project):
    with pytest.raises(BuildPreparationError, match="Unknown image ID"):
        prepare_build(
            ndf_dir=build_project,
            image_id="missing-v16",
        )
