import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.validate_descriptors import (
    DescriptorValidationError,
    validate_composition_descriptors,
    validate_descriptor,
)


NDF_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = NDF_DIR.parents[1]
SCHEMA_DIR = NDF_DIR / "schemas"
FIXTURE_DIR = NDF_DIR / "fixtures"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def copy_descriptor_tree(destination):
    source = NDF_DIR / "descriptors"
    shutil.copytree(source, destination / "images" / "ndf" / "descriptors")


class TestMarketplaceDescriptorSchemas:
    def test_representative_descriptor_fixtures_validate(self):
        for path in sorted((NDF_DIR / "descriptors" / "apps").glob("*.json")):
            validate_descriptor(read_json(path), SCHEMA_DIR)

    def test_v2_composition_fixture_resolves_descriptors(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        descriptors = validate_composition_descriptors(
            composition, REPOSITORY_ROOT, SCHEMA_DIR
        )
        assert [item["app_id"] for item in descriptors] == [
            "dt_ecommerce",
            "dt_recomendations",
        ]

    def test_invalid_dependency_disposition_is_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"]["python"] = [{
            "name": "example-package",
            "disposition": "install_anywhere",
        }]
        with pytest.raises(DescriptorValidationError, match="Descriptor schema validation failed"):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_unknown_dependency_properties_are_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"]["node"] = [{
            "name": "example-package",
            "package_manager": "npm",
            "scope": "build",
            "disposition": "runtime_compatible",
            "run": "arbitrary command",
        }]
        with pytest.raises(DescriptorValidationError, match="Descriptor schema validation failed"):
            validate_descriptor(descriptor, SCHEMA_DIR)


class TestCompositionDescriptorSemantics:
    def test_descriptor_path_traversal_is_rejected(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0]["descriptor"] = "../../../../etc/passwd"
        with pytest.raises(DescriptorValidationError, match="escapes repository root"):
            validate_composition_descriptors(composition, REPOSITORY_ROOT, SCHEMA_DIR)

    def test_missing_descriptor_file_is_rejected(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0]["descriptor"] = "images/ndf/descriptors/apps/not-found.json"
        with pytest.raises(DescriptorValidationError, match="Descriptor file not found"):
            validate_composition_descriptors(composition, REPOSITORY_ROOT, SCHEMA_DIR)

    def test_duplicate_descriptor_app_ids_are_rejected(self, tmp_path):
        copy_descriptor_tree(tmp_path)
        duplicate = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        duplicate["name"] = "Duplicate identity fixture"
        duplicate_path = (
            tmp_path / "images" / "ndf" / "descriptors" / "apps" / "duplicate.json"
        )
        duplicate_path.write_text(json.dumps(duplicate), encoding="utf-8")

        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][1]["descriptor"] = (
            "images/ndf/descriptors/apps/duplicate.json"
        )
        with pytest.raises(DescriptorValidationError, match="Duplicate descriptor app_id"):
            validate_composition_descriptors(composition, tmp_path, SCHEMA_DIR)

    def test_missing_source_reference_is_rejected(self, tmp_path):
        copy_descriptor_tree(tmp_path)
        descriptor_path = (
            tmp_path / "images" / "ndf" / "descriptors" / "apps" / "dt_ecommerce.json"
        )
        descriptor = read_json(descriptor_path)
        descriptor["source"].pop("default_ref")
        descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")

        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0].pop("target_ref", None)
        with pytest.raises(DescriptorValidationError, match="Missing source reference"):
            validate_composition_descriptors(composition, tmp_path, SCHEMA_DIR)

    def test_composition_target_ref_overrides_descriptor_default(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0]["target_ref"] = "release-override"
        descriptors = validate_composition_descriptors(
            composition, REPOSITORY_ROOT, SCHEMA_DIR
        )
        assert descriptors[0]["source"]["default_ref"] == "version-1"


class TestLegacyManifestCompatibility:
    def test_existing_v1_core_manifest_validates_against_v1_schema(self):
        schema = read_json(SCHEMA_DIR / "application-manifest-v1.schema.json")
        manifest = read_json(NDF_DIR / "manifests" / "core" / "dhana-base-v16.json")
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(manifest))
        assert errors == []

    def test_v2_schema_accepts_legacy_embedded_application_entries(self):
        schema = read_json(SCHEMA_DIR / "application-manifest-v2.schema.json")
        manifest = read_json(NDF_DIR / "manifests" / "core" / "dhana-base-v16.json")
        manifest["$schema"] = "../../schemas/application-manifest-v2.schema.json"
        manifest["manifest_version"] = "2.0.0"
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(manifest))
        assert errors == []
