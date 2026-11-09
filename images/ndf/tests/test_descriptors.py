import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from scripts.validate_descriptors import (
    DescriptorValidationError,
    collect_production_metadata_issues,
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
    target = destination / "images" / "ndf" / "descriptors"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)


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

    def test_typed_dependency_ecosystems_accept_valid_contract_records(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"].update(
            {
                "python": [
                    {
                        "name": "example-python-package",
                        "required": True,
                        "version": ">=1.0,<2.0",
                        "disposition": "runtime_compatible",
                        "build_required": True,
                    }
                ],
                "node": [
                    {
                        "name": "example-node-package",
                        "required": True,
                        "version": "^1.2.3",
                        "package_manager": "npm",
                        "scope": "build",
                        "disposition": "runtime_compatible",
                    }
                ],
                "os": [
                    {
                        "name": "example-system-library",
                        "required": True,
                        "distribution_family": "debian",
                        "package_manager": "apt",
                        "scope": "build",
                        "disposition": "environment_level",
                    }
                ],
            }
        )
        validate_descriptor(descriptor, SCHEMA_DIR)

    def test_verified_compatibility_requires_passed_evidence(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"] = {"status": "verified"}
        with pytest.raises(
            DescriptorValidationError, match="Descriptor schema validation failed"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_invalid_dependency_disposition_is_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"]["python"] = [
            {
                "name": "example-package",
                "required": True,
                "disposition": "install_anywhere",
            }
        ]
        with pytest.raises(
            DescriptorValidationError, match="Descriptor schema validation failed"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_unknown_dependency_properties_are_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"]["node"] = [
            {
                "name": "example-package",
                "required": True,
                "package_manager": "npm",
                "scope": "build",
                "disposition": "runtime_compatible",
                "run": "arbitrary command",
            }
        ]
        with pytest.raises(
            DescriptorValidationError, match="Descriptor schema validation failed"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_invalid_semver_constraint_is_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"]["frappe"] = "not-a-valid-range"
        with pytest.raises(DescriptorValidationError, match="Invalid SemVer range"):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_invalid_pep440_constraint_is_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"]["python"] = "not-a-specifier"
        with pytest.raises(DescriptorValidationError, match="Invalid PEP 440"):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_valid_ecosystem_constraints_are_accepted(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"].update(
            {
                "frappe": ">=16.0.0 <17.0.0",
                "erpnext": "^16.0.0",
                "python": ">=3.12,<3.15",
                "node": "^24.0.0",
            }
        )
        validate_descriptor(descriptor, SCHEMA_DIR)

    def test_os_package_manager_must_match_distribution_family(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"]["os"] = [
            {
                "name": "example-package",
                "required": True,
                "distribution_family": "debian",
                "package_manager": "dnf",
                "scope": "build",
                "disposition": "environment_level",
            }
        ]
        with pytest.raises(
            DescriptorValidationError, match="Unsupported OS package-manager"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_unapproved_build_policy_is_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["build"] = {
            "build_system": "custom_policy",
            "policy_id": "publisher.arbitrary-command",
        }
        with pytest.raises(DescriptorValidationError, match="Unapproved NDF build policy"):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_unapproved_installation_policy_is_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["installation"].update(
            {
                "post_install_policy": "approved_policy",
                "policy_id": "publisher.custom-hook",
            }
        )
        with pytest.raises(
            DescriptorValidationError, match="Unapproved NDF installation policy"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_publisher_evidence_cannot_establish_ndf_verified_status(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"] = {
            "status": "verified",
            "frappe": "^16.0.0",
            "python": ">=3.12,<3.15",
            "evidence": [
                {
                    "kind": "automated_test",
                    "authority": "publisher",
                    "reference": "https://example.com/publisher-ci",
                    "result": "passed",
                    "tested_versions": {
                        "frappe": "16.1.0",
                        "python": "3.14.3",
                    },
                }
            ],
        }
        with pytest.raises(
            DescriptorValidationError, match="Descriptor schema validation failed"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_verified_compatibility_requires_ndf_test_matrix(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"] = {
            "status": "verified",
            "frappe": "^16.0.0",
            "python": ">=3.12,<3.15",
            "evidence": [
                {
                    "kind": "automated_test",
                    "authority": "ndf",
                    "reference": "https://github.com/NdfTechLabs/frappe_docker/actions",
                    "result": "passed",
                    "tested_versions": {
                        "frappe": "16.1.0",
                        "python": "3.14.3",
                    },
                }
            ],
        }
        validate_descriptor(descriptor, SCHEMA_DIR)

    def test_tested_version_must_satisfy_declared_compatibility_range(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"].update(
            {
                "frappe": "^16.0.0",
                "evidence": [
                    {
                        "kind": "automated_test",
                        "authority": "publisher",
                        "reference": "https://example.com/test-report",
                        "result": "passed",
                        "tested_versions": {
                            "frappe": "17.0.0",
                            "python": "3.14.3",
                        },
                    }
                ],
            }
        )
        with pytest.raises(
            DescriptorValidationError, match="does not satisfy compatibility.frappe"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_invalid_tested_version_in_compatibility_evidence_is_rejected(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"]["evidence"] = [
            {
                "kind": "automated_test",
                "authority": "publisher",
                "reference": "https://example.com/test-report",
                "result": "passed",
                "tested_versions": {
                    "frappe": "sixteen",
                    "python": "3.14.3",
                },
            }
        ]
        with pytest.raises(
            DescriptorValidationError, match="Invalid tested SemVer version"
        ):
            validate_descriptor(descriptor, SCHEMA_DIR)

    def test_production_metadata_gate_rejects_incomplete_authoring_descriptor(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        issues = collect_production_metadata_issues(descriptor)
        assert any("compatibility status is not verified" in item for item in issues)
        assert any("missing explicit version_policy" in item for item in issues)

    def test_latest_compatible_policy_completes_dependency_metadata(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["compatibility"].update(
            {
                "status": "verified",
                "frappe": "^16.0.0",
                "erpnext": "^16.0.0",
                "python": ">=3.12,<3.15",
                "evidence": [
                    {
                        "kind": "automated_test",
                        "authority": "ndf",
                        "reference": "https://github.com/NdfTechLabs/frappe_docker/actions",
                        "result": "passed",
                        "tested_versions": {
                            "frappe": "16.1.0",
                            "erpnext": "16.1.0",
                            "python": "3.14.3",
                        },
                    }
                ],
            }
        )
        for dependency in descriptor["dependencies"]["bench_apps"]:
            dependency["version_policy"] = "latest_compatible"
        assert collect_production_metadata_issues(descriptor) == []

    def test_selected_optional_dependency_is_subject_to_metadata_gate(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        optional = descriptor["dependencies"]["bench_apps"][0]
        optional["required"] = False
        optional["version_policy"] = "constraint"
        unselected = collect_production_metadata_issues(descriptor)
        assert not any("constraint policy requires a version" in item for item in unselected)
        selected = collect_production_metadata_issues(
            descriptor, {"bench_apps:frappe"}
        )
        assert any("constraint policy requires a version" in item for item in selected)

    def test_constraint_policy_without_version_blocks_metadata_readiness(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"]["bench_apps"][0]["version_policy"] = "constraint"
        issues = collect_production_metadata_issues(descriptor)
        assert any("constraint policy requires a version" in item for item in issues)

    def test_latest_compatible_cannot_also_declare_version(self):
        descriptor = read_json(NDF_DIR / "descriptors" / "apps" / "dt_ecommerce.json")
        descriptor["dependencies"]["bench_apps"][0].update(
            {"version_policy": "latest_compatible", "version": "^16.0.0"}
        )
        issues = collect_production_metadata_issues(descriptor)
        assert any("cannot also declare a version" in item for item in issues)

    def test_descriptor_catalogue_filename_must_match_app_identity(self, tmp_path):
        copy_descriptor_tree(tmp_path)
        descriptor_path = (
            tmp_path / "images" / "ndf" / "descriptors" / "apps" / "dt_ecommerce.json"
        )
        renamed_path = descriptor_path.with_name("renamed.json")
        descriptor_path.rename(renamed_path)
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0][
            "descriptor"
        ] = "images/ndf/descriptors/apps/renamed.json"
        with pytest.raises(
            DescriptorValidationError, match="filename/path identity mismatch"
        ):
            validate_composition_descriptors(composition, tmp_path, SCHEMA_DIR)


class TestCompositionDescriptorSemantics:
    def test_descriptor_path_traversal_is_rejected(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0]["descriptor"] = "../../../../etc/passwd"
        with pytest.raises(
            DescriptorValidationError, match="normalized catalogue-relative"
        ):
            validate_composition_descriptors(composition, REPOSITORY_ROOT, SCHEMA_DIR)

    def test_windows_style_descriptor_path_is_rejected(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0]["descriptor"] = r"..\\..\\outside.json"
        with pytest.raises(
            DescriptorValidationError, match="normalized catalogue-relative"
        ):
            validate_composition_descriptors(composition, REPOSITORY_ROOT, SCHEMA_DIR)

    def test_missing_descriptor_file_is_rejected(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0][
            "descriptor"
        ] = "images/ndf/descriptors/apps/not-found.json"
        with pytest.raises(
            DescriptorValidationError, match="Descriptor file not found"
        ):
            validate_composition_descriptors(composition, REPOSITORY_ROOT, SCHEMA_DIR)

    def test_duplicate_descriptor_app_ids_are_rejected(self):
        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][1][
            "descriptor"
        ] = composition["applications"][0]["descriptor"]
        with pytest.raises(
            DescriptorValidationError, match="Duplicate descriptor app_id"
        ):
            validate_composition_descriptors(composition, REPOSITORY_ROOT, SCHEMA_DIR)

    def test_duplicate_bench_install_names_are_rejected(self, tmp_path):
        copy_descriptor_tree(tmp_path)
        duplicate = read_json(
            NDF_DIR / "descriptors" / "apps" / "dt_recomendations.json"
        )
        duplicate["app_id"] = "different_marketplace_id"
        duplicate["app_module"]["bench_app_name"] = "dt_ecommerce"
        duplicate_path = (
            tmp_path
            / "images"
            / "ndf"
            / "descriptors"
            / "apps"
            / "different_marketplace_id.json"
        )
        duplicate_path.write_text(json.dumps(duplicate), encoding="utf-8")

        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][1][
            "descriptor"
        ] = "images/ndf/descriptors/apps/different_marketplace_id.json"
        with pytest.raises(DescriptorValidationError, match="Duplicate Bench app name"):
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

    def test_composition_target_ref_satisfies_missing_descriptor_default(
        self, tmp_path
    ):
        copy_descriptor_tree(tmp_path)
        descriptor_path = (
            tmp_path / "images" / "ndf" / "descriptors" / "apps" / "dt_ecommerce.json"
        )
        descriptor = read_json(descriptor_path)
        descriptor["source"].pop("default_ref")
        descriptor_path.write_text(json.dumps(descriptor), encoding="utf-8")

        composition = read_json(FIXTURE_DIR / "compositions" / "dalali-v2.json")
        composition["applications"][0]["target_ref"] = "release-override"
        descriptors = validate_composition_descriptors(
            composition, tmp_path, SCHEMA_DIR
        )
        assert descriptors[0]["app_id"] == "dt_ecommerce"


class TestLegacyManifestCompatibility:
    def test_all_existing_v1_manifests_validate_against_v1_schema(self):
        schema = read_json(SCHEMA_DIR / "application-manifest-v1.schema.json")
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        manifests = sorted((NDF_DIR / "manifests").rglob("*.json"))
        assert manifests, "Expected existing v1 manifest fixtures"
        failures = {}
        for path in manifests:
            errors = list(validator.iter_errors(read_json(path)))
            if errors:
                failures[str(path.relative_to(NDF_DIR))] = [
                    error.message for error in errors
                ]
        assert failures == {}

    def test_v2_schema_accepts_legacy_embedded_application_entries(self):
        schema = read_json(SCHEMA_DIR / "application-manifest-v2.schema.json")
        manifest = read_json(NDF_DIR / "manifests" / "core" / "dhana-base-v16.json")
        manifest["$schema"] = "../../schemas/application-manifest-v2.schema.json"
        manifest["manifest_version"] = "2.0.0"
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(manifest))
        assert errors == []
