import hashlib
import json
from pathlib import Path

import pytest

from scripts.validate_base_inventory import (
    InventoryError,
    find_base_package,
    validate_inventory_directory,
)

NDF_DIR = Path(__file__).resolve().parents[1]
SCHEMA = NDF_DIR / "schemas" / "base-inventory-manifest-v1.schema.json"

BUILDER_DIGEST = "sha256:" + "1" * 64
RUNTIME_DIGEST = "sha256:" + "2" * 64
INDEX_DIGEST = "sha256:" + "3" * 64


def write_evidence(root: Path):
    records = {
        "builder": [
            "base-files\t13.8+deb13u1\tamd64",
            "dpkg\t1.22.22\tamd64",
        ],
        "runtime": [
            "base-files\t13.8+deb13u1\tamd64",
        ],
    }
    inventory_items = {}
    for stage, lines in records.items():
        stage_dir = root / stage
        stage_dir.mkdir(parents=True)
        raw = ("\n".join(lines) + "\n").encode()
        (stage_dir / "dpkg-inventory.tsv").write_bytes(raw)
        digest = BUILDER_DIGEST if stage == "builder" else RUNTIME_DIGEST
        repository = "frappe/build" if stage == "builder" else "frappe/base"
        inventory_items[stage] = {
            "image": {
                "reference": f"{repository}@{digest}",
                "index_digest": INDEX_DIGEST,
                "manifest_digest": digest,
                "platform": "linux/amd64",
            },
            "package_database_version": "1.22.22",
            "file": f"{stage}/dpkg-inventory.tsv",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "package_count": len(lines),
        }

    manifest = {
        "schema_version": "1.0.0",
        "producer": {
            "name": "images/ndf/scripts/inspect_target_runtime.sh",
            "version": "1",
        },
        "package_database": {"name": "dpkg", "format": "dpkg-query-tsv"},
        "inventories": inventory_items,
    }
    (root / "inventory-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def test_valid_manifest_and_both_stage_inventories_validate(tmp_path):
    manifest = write_evidence(tmp_path)
    validated, parsed = validate_inventory_directory(tmp_path, SCHEMA)

    assert validated == manifest
    assert len(parsed["builder"]) == 2
    assert len(parsed["runtime"]) == 1


def test_base_package_lookup_uses_the_declared_stage_scope(tmp_path):
    manifest = write_evidence(tmp_path)
    _, parsed = validate_inventory_directory(tmp_path, SCHEMA)

    assert find_base_package(
        parsed,
        scope="build",
        name="dpkg",
        version="1.22.22",
        architecture="amd64",
    )
    assert not find_base_package(
        parsed,
        scope="runtime",
        name="dpkg",
        version="1.22.22",
        architecture="amd64",
    )


def test_checksum_tampering_fails_closed(tmp_path):
    write_evidence(tmp_path)
    inventory = tmp_path / "runtime" / "dpkg-inventory.tsv"
    inventory.write_text(inventory.read_text() + "unexpected\t1\tamd64\n")

    with pytest.raises(InventoryError, match="SHA-256 mismatch"):
        validate_inventory_directory(tmp_path, SCHEMA)


def test_path_escape_fails_closed(tmp_path):
    manifest = write_evidence(tmp_path)
    manifest["inventories"]["runtime"]["file"] = "../outside.tsv"
    (tmp_path / "inventory-manifest.json").write_text(json.dumps(manifest))

    with pytest.raises(InventoryError, match="inventory path must be exactly"):
        validate_inventory_directory(tmp_path, SCHEMA)


def test_image_reference_digest_mismatch_fails_closed(tmp_path):
    manifest = write_evidence(tmp_path)
    manifest["inventories"]["runtime"]["image"]["reference"] = (
        "frappe/base@sha256:" + "4" * 64
    )
    (tmp_path / "inventory-manifest.json").write_text(json.dumps(manifest))

    with pytest.raises(InventoryError, match="reference does not match"):
        validate_inventory_directory(tmp_path, SCHEMA)


def test_package_count_mismatch_fails_closed(tmp_path):
    manifest = write_evidence(tmp_path)
    manifest["inventories"]["builder"]["package_count"] = 99
    (tmp_path / "inventory-manifest.json").write_text(json.dumps(manifest))

    with pytest.raises(InventoryError, match="Package count mismatch"):
        validate_inventory_directory(tmp_path, SCHEMA)


def test_unsorted_or_duplicate_records_fail_closed(tmp_path):
    manifest = write_evidence(tmp_path)
    inventory = tmp_path / "builder" / "dpkg-inventory.tsv"
    raw = b"dpkg\t1.22.22\tamd64\nbase-files\t13.8+deb13u1\tamd64\n"
    inventory.write_bytes(raw)
    manifest["inventories"]["builder"]["sha256"] = hashlib.sha256(raw).hexdigest()
    (tmp_path / "inventory-manifest.json").write_text(json.dumps(manifest))

    with pytest.raises(InventoryError, match="not sorted deterministically"):
        validate_inventory_directory(tmp_path, SCHEMA)
