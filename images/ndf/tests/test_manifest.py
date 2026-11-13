import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.resolve_manifest import (
    ManifestError,
    ManifestLoader,
)


def run_resolver(environment, *arguments):
    """Execute the manifest resolver as a subprocess."""

    return subprocess.run(
        [
            sys.executable,
            str(environment["script"]),
            environment["manifest_argument"],
            *arguments,
        ],
        cwd=environment["ndf_dir"].parents[1],
        capture_output=True,
        text=True,
    )


def write_test_manifest(
    manifests_dir,
    filename,
    manifest_id,
    includes=None,
    applications=None,
):
    manifests_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "manifest_version": "1.0",
        "id": manifest_id,
        "name": manifest_id.replace("-", " ").title(),
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
        "includes": includes or [],
        "applications": (
            applications
            if applications is not None
            else [
                {
                    "name": "frappe",
                    "repository": "https://github.com/frappe/frappe",
                    "target_ref": "version-16",
                    "required": True,
                    "install_order": 0,
                    "dependencies": [],
                    "ref": None,
                    "compatibility_status": "verified",
                }
            ]
        ),
    }

    path = manifests_dir / filename
    path.write_text(json.dumps(manifest, indent=2))

    return path


def shared_test_application():
    """Return an identical application definition for manifest tests."""

    return {
        "name": "frappe",
        "repository": "https://github.com/frappe/frappe",
        "target_ref": "version-16",
        "required": True,
        "install_order": 0,
        "dependencies": [],
        "ref": "a" * 40,
        "compatibility_status": "verified",
        "_reference_kind": "tag",
        "_resolved_ref": "refs/tags/version-16",
    }


@pytest.fixture
def loader(tmp_path):
    """Create a resolver using an isolated temporary manifest directory."""

    manifests_dir = tmp_path / "manifests"
    schemas_dir = tmp_path / "schemas"

    manifests_dir.mkdir()
    schemas_dir.mkdir()

    # Copy the actual project schema into the temporary environment.
    project_ndf_dir = Path(__file__).resolve().parents[1]

    policies_dir = tmp_path / "images" / "ndf" / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        project_ndf_dir / "policies" / "package-source-profiles-v1.json",
        policies_dir / "package-source-profiles-v1.json",
    )

    for schema_name in (
        "application-manifest-v1.schema.json",
        "application-manifest-v2.schema.json",
        "marketplace-app-descriptor-v1.schema.json",
        "dependency-v1.schema.json",
        "service-descriptor-v1.schema.json",
    ):
        shutil.copy2(
            project_ndf_dir / "schemas" / schema_name,
            schemas_dir / schema_name,
        )

    instance = ManifestLoader(manifests_dir)
    instance.repository_root = tmp_path
    return instance


@pytest.fixture
def sample_manifest(loader):
    """Create a minimal source manifest for lock tests."""

    source_path = loader.manifests_dir / "test-product.json"

    source_data = {
        "manifest_version": "1.0",
        "id": "test-product",
        "name": "Test Product",
    }

    source_path.write_text(
        json.dumps(source_data, indent=2),
        encoding="utf-8",
    )

    return {
        "manifest_version": "1.0",
        "id": "test-product",
        "name": "Test Product",
        "profile": {
            "type": "product",
            "required": True,
            "install_by_default": True,
        },
        "framework": {
            "name": "frappe",
            "version": "16",
        },
        "_source_path": str(source_path),
        "_loaded_includes": [],
    }


@pytest.fixture
def sample_applications():
    """Create a minimal application list."""

    return [
        {
            "name": "frappe",
            "repository": "https://github.com/frappe/frappe",
            "target_ref": "version-16",
            "ref": "a" * 40,
            "dependencies": [],
            "compatibility_status": "verified",
            "_reference_kind": "tag",
            "_resolved_ref": "refs/tags/version-16",
        }
    ]


@pytest.fixture
def generated_lock(loader, sample_manifest, sample_applications, tmp_path):
    """Generate and persist a valid sample lock."""

    lock_data = loader.build_lock_data(
        sample_manifest,
        sample_applications,
    )

    lock_path = tmp_path / "test-product.lock.json"

    loader.write_lock_file(
        lock_data,
        lock_path,
    )

    return lock_path, lock_data


@pytest.fixture
def cli_environment(tmp_path):
    """Create an isolated environment for CLI integration tests."""

    ndf_dir = tmp_path / "images" / "ndf"
    scripts_dir = ndf_dir / "scripts"
    manifests_dir = ndf_dir / "manifests"
    schemas_dir = ndf_dir / "schemas"
    policies_dir = ndf_dir / "policies"
    locks_dir = ndf_dir / "locks"

    for directory in (
        scripts_dir,
        manifests_dir / "products",
        schemas_dir,
        policies_dir,
        locks_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    # Copy the actual resolver and schema.
    project_ndf_dir = Path(__file__).resolve().parents[1]

    shutil.copy2(
        project_ndf_dir / "scripts" / "resolve_manifest.py",
        scripts_dir / "resolve_manifest.py",
    )
    shutil.copy2(
        project_ndf_dir / "scripts" / "validate_descriptors.py",
        scripts_dir / "validate_descriptors.py",
    )
    shutil.copy2(
        project_ndf_dir / "scripts" / "package_resolution.py",
        scripts_dir / "package_resolution.py",
    )
    shutil.copy2(
        project_ndf_dir / "scripts" / "validate_base_inventory.py",
        scripts_dir / "validate_base_inventory.py",
    )
    shutil.copy2(
        project_ndf_dir / "policies" / "package-source-profiles-v1.json",
        policies_dir / "package-source-profiles-v1.json",
    )

    shutil.copy2(
        project_ndf_dir / "schemas" / "application-manifest-v1.schema.json",
        schemas_dir / "application-manifest-v1.schema.json",
    )

    # Create a local Git repository so tests don't depend on GitHub.
    repository_dir = tmp_path / "test-app-repository"
    repository_dir.mkdir()

    subprocess.run(
        ["git", "init", "-b", "main"],
        cwd=repository_dir,
        check=True,
        capture_output=True,
    )

    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repository_dir,
        check=True,
    )

    subprocess.run(
        ["git", "config", "user.name", "Manifest Test"],
        cwd=repository_dir,
        check=True,
    )

    (repository_dir / "README.md").write_text(
        "Test application",
        encoding="utf-8",
    )

    subprocess.run(
        ["git", "add", "."],
        cwd=repository_dir,
        check=True,
    )

    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repository_dir,
        check=True,
        capture_output=True,
    )

    repository_url = repository_dir.as_uri()

    manifest = {
        "manifest_version": "1.0",
        "id": "cli-test",
        "name": "CLI Test Product",
        "framework": {
            "name": "frappe",
            "version": "16",
            "release_channel": "stable",
            "target_ref": "main",
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
        "applications": [
            {
                "name": "frappe",
                "repository": repository_url,
                "target_ref": "main",
                "required": True,
                "install_order": 0,
                "dependencies": [],
                "ref": None,
                "compatibility_status": "verified",
            },
            {
                "name": "test_app",
                "repository": repository_url,
                "target_ref": "main",
                "required": True,
                "install_order": 1,
                "dependencies": ["frappe"],
                "ref": None,
                "compatibility_status": "verified",
            },
        ],
    }

    manifest_path = manifests_dir / "products" / "cli-test.json"

    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    return {
        "ndf_dir": ndf_dir,
        "script": scripts_dir / "resolve_manifest.py",
        "manifest_path": manifest_path,
        "lock_path": locks_dir / "cli-test.lock.json",
        "manifest_argument": "products/cli-test.json",
    }


# ---------------------------------------------------------
# Lock generation
# ---------------------------------------------------------


class TestResolutionPolicy:

    def test_policy_is_aggregated_restrictively_across_includes(self, loader):
        manifest = {
            "resolution": {
                "require_immutable_commit": True,
                "fail_on_unverified_compatibility": True,
            },
            "_loaded_includes": [
                {
                    "resolution": {
                        "require_immutable_commit": False,
                        "fail_on_unverified_compatibility": False,
                    },
                    "_loaded_includes": [],
                }
            ],
        }

        assert loader.resolve_policy(manifest) == {
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
        }

    def test_invalid_policy_type_is_rejected(self, loader):
        with pytest.raises(ManifestError, match="must be a boolean"):
            loader.resolve_policy(
                {
                    "resolution": {"require_immutable_commit": "true"},
                    "_loaded_includes": [],
                }
            )


class TestReferencePolicyEnforcement:

    @pytest.mark.parametrize("target_ref", ["main", "master", "develop", "version-16"])
    def test_branch_refs_are_accepted_when_sha_and_compatibility_are_valid(
        self, loader, monkeypatch, target_ref
    ):
        commit = "a" * 40
        monkeypatch.setattr(
            loader,
            "resolve_git_ref",
            lambda repository, ref: {
                "sha": commit,
                "kind": "branch",
                "name": f"refs/heads/{ref}",
            },
        )
        apps = [
            {
                "name": "test_app",
                "repository": "https://example.com/test.git",
                "target_ref": target_ref,
                "compatibility_status": "verified",
            }
        ]
        policy = {
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
        }

        resolved = loader.resolve_application_refs(apps, policy)

        assert resolved[0]["ref"] == commit
        assert resolved[0]["_reference_kind"] == "branch"
        assert resolved[0]["_resolved_ref"] == f"refs/heads/{target_ref}"

    def test_unverified_compatibility_is_rejected(self, loader, monkeypatch):
        monkeypatch.setattr(
            loader,
            "resolve_git_ref",
            lambda repository, target_ref: {
                "sha": "a" * 40,
                "kind": "tag",
                "name": "refs/tags/version-16",
            },
        )
        apps = [
            {
                "name": "test_app",
                "repository": "https://example.com/test.git",
                "target_ref": "version-16",
                "compatibility_status": "pending",
            }
        ]
        policy = {
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
        }

        with pytest.raises(ManifestError, match="compatibility_status=pending"):
            loader.resolve_application_refs(apps, policy)

    def test_missing_compatibility_status_is_rejected(self, loader, monkeypatch):
        monkeypatch.setattr(
            loader,
            "resolve_git_ref",
            lambda repository, target_ref: {
                "sha": "a" * 40,
                "kind": "tag",
                "name": "refs/tags/version-16",
            },
        )
        apps = [
            {
                "name": "test_app",
                "repository": "https://example.com/test.git",
                "target_ref": "version-16",
            }
        ]
        policy = {
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
        }

        with pytest.raises(ManifestError, match="<missing>"):
            loader.resolve_application_refs(apps, policy)

    def test_non_commit_resolution_is_rejected_by_immutable_policy(
        self, loader, monkeypatch
    ):
        monkeypatch.setattr(
            loader,
            "resolve_git_ref",
            lambda repository, target_ref: {
                "sha": "not-a-commit",
                "kind": "tag",
                "name": "refs/tags/version-16",
            },
        )
        apps = [
            {
                "name": "test_app",
                "repository": "https://example.com/test.git",
                "target_ref": "version-16",
                "compatibility_status": "verified",
            }
        ]
        policy = {
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
        }

        with pytest.raises(ManifestError, match="immutable commit SHA"):
            loader.resolve_application_refs(apps, policy)

    def test_verified_release_tag_is_accepted_and_provenance_is_retained(
        self, loader, monkeypatch
    ):
        commit = "a" * 40
        monkeypatch.setattr(
            loader,
            "resolve_git_ref",
            lambda repository, target_ref: {
                "sha": commit,
                "kind": "tag",
                "name": "refs/tags/version-16",
            },
        )
        apps = [
            {
                "name": "frappe",
                "repository": "https://example.com/frappe.git",
                "target_ref": "version-16",
                "compatibility_status": "verified",
            }
        ]
        policy = {
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
        }

        resolved = loader.resolve_application_refs(apps, policy)
        assert resolved[0]["ref"] == commit
        assert resolved[0]["_reference_kind"] == "tag"
        assert resolved[0]["_resolved_ref"] == "refs/tags/version-16"


class TestLockGeneration:

    def test_build_lock_data(self, loader, sample_manifest, sample_applications):
        lock_data = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        assert lock_data["lock_version"] == 2
        assert lock_data["product"]["id"] == "test-product"
        assert len(lock_data["applications"]) == 1
        assert lock_data["package_resolution"] == {
            "schema_version": 1,
            "source_policy_catalogue_version": "1.0.0",
            "source_profiles": [],
            "base_inventory": None,
            "packages": [],
            "dependency_edges": [],
        }

        # A01: the generated lock must persist the complete requested-source
        # identity, not merely prove that the resolver returned a SHA.
        frappe_lock = lock_data["applications"][0]
        assert frappe_lock["name"] == "frappe"
        assert frappe_lock["target_ref"] == "version-16"
        assert frappe_lock["ref"] == "a" * 40
        assert frappe_lock["reference_kind"] == "tag"
        assert frappe_lock["resolved_ref"] == "refs/tags/version-16"
        assert frappe_lock["compatibility_status"] == "verified"

        # The framework identity must be bound to the same Frappe source.
        assert lock_data["framework"]["target_ref"] == frappe_lock["target_ref"]
        assert lock_data["framework"]["ref"] == frappe_lock["ref"]
        assert lock_data["framework"]["reference_kind"] == frappe_lock["reference_kind"]
        assert lock_data["framework"]["resolved_ref"] == frappe_lock["resolved_ref"]

    def test_direct_only_package_selections_cannot_generate_complete_lock(
        self, loader, sample_manifest, sample_applications
    ):
        applications = [
            {
                **sample_applications[0],
                "package_dependencies": [{
                    "ecosystem": "python",
                    "name": "demo-package",
                    "version": "1.0.0",
                    "source": "https://pypi.org/simple",
                    "resolver": "uv",
                    "version_policy": "latest_compatible",
                    "requested_constraint": None,
                    "source_profile": "python-pypi-public-v1",
                    "disposition": "runtime_compatible",
                    "install": True,
                    "scope": "runtime",
                }],
            }
        ]
        with pytest.raises(ManifestError, match="complete transitive closure"):
            loader.build_lock_data(sample_manifest, applications)

    def test_lock_generation_is_deterministic(
        self,
        loader,
        sample_manifest,
        sample_applications,
    ):
        first = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        second = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        assert first == second

    def test_write_lock_file(
        self, loader, sample_manifest, sample_applications, tmp_path
    ):
        lock_data = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        lock_path = tmp_path / "test.lock.json"

        result = loader.write_lock_file(
            lock_data,
            lock_path,
        )

        assert result == lock_path
        assert lock_path.exists()

        written_data = json.loads(lock_path.read_text(encoding="utf-8"))

        assert written_data == lock_data


# ---------------------------------------------------------
# Lock validation
# ---------------------------------------------------------


class TestGitReferenceResolution:

    def test_explicit_commit_reference_is_verified(self, loader, monkeypatch):
        commit = "d" * 40

        def fake_run(args, **kwargs):
            output = commit + "\n" if args[-1] == "FETCH_HEAD" else ""
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=output,
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        resolved = loader.resolve_git_ref(
            "https://example.com/frappe.git",
            commit,
        )

        assert resolved == {
            "sha": commit,
            "kind": "commit",
            "name": commit,
        }

    def test_exact_tag_is_preferred_over_same_named_branch(self, loader, monkeypatch):
        tag_object = "b" * 40
        peeled_commit = "a" * 40
        branch_commit = "c" * 40
        output = (
            f"{tag_object}\trefs/tags/version-16\n"
            f"{peeled_commit}\trefs/tags/version-16^{{}}\n"
            f"{branch_commit}\trefs/heads/version-16\n"
        )
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args=args[0], returncode=0, stdout=output, stderr=""
            ),
        )

        resolved = loader.resolve_git_ref(
            "https://example.com/frappe.git",
            "version-16",
        )

        assert resolved == {
            "sha": peeled_commit,
            "kind": "tag",
            "name": "refs/tags/version-16",
        }


class TestLockValidation:

    def test_valid_lock_passes(self, loader, sample_manifest, generated_lock):
        lock_path, _ = generated_lock

        assert (
            loader.validate_lock_file(
                lock_path,
                sample_manifest,
            )
            is True
        )

    def test_pre_extension_v2_without_package_dependencies_remains_readable(
        self, loader, sample_manifest, generated_lock, tmp_path
    ):
        _, lock_data = generated_lock
        lock_data.pop("package_resolution")
        lock_path = tmp_path / "legacy-v2.lock.json"
        lock_path.write_text(json.dumps(lock_data), encoding="utf-8")

        assert loader.validate_lock_file(lock_path, sample_manifest) is True

    def test_pre_extension_v2_with_direct_packages_requires_migration(
        self, loader, sample_manifest, generated_lock, tmp_path
    ):
        _, lock_data = generated_lock
        lock_data.pop("package_resolution")
        lock_data["applications"][0]["package_dependencies"] = [{
            "ecosystem": "python",
            "name": "demo-package",
            "version": "1.0.0",
            "source": "https://pypi.org/simple",
            "resolver": "uv",
            "disposition": "runtime_compatible",
            "install": True,
        }]
        lock_path = tmp_path / "legacy-v2-packages.lock.json"
        lock_path.write_text(json.dumps(lock_data), encoding="utf-8")

        with pytest.raises(ManifestError, match="Package-resolution migration required"):
            loader.validate_lock_file(lock_path, sample_manifest)

    def test_empty_package_resolution_section_rejects_unexplained_profile(
        self, loader, sample_manifest, generated_lock, tmp_path
    ):
        _, lock_data = generated_lock
        lock_data["package_resolution"]["source_profiles"] = ["python-pypi-public-v1"]
        lock_path = tmp_path / "tampered-package-resolution.lock.json"
        lock_path.write_text(json.dumps(lock_data), encoding="utf-8")

        with pytest.raises(ManifestError, match="Empty package graph"):
            loader.validate_lock_file(lock_path, sample_manifest)

    def test_modified_manifest_fails_checksum_validation(
        self,
        loader,
        sample_manifest,
        generated_lock,
    ):
        lock_path, _ = generated_lock

        source_path = Path(sample_manifest["_source_path"])

        source_path.write_text(
            '{"id": "modified-product"}',
            encoding="utf-8",
        )

        with pytest.raises(
            ManifestError,
            match="Source manifest has changed",
        ):
            loader.validate_lock_file(
                lock_path,
                sample_manifest,
            )

    def test_modified_manifest_can_be_structurally_validated(
        self,
        loader,
        sample_manifest,
        generated_lock,
    ):
        lock_path, _ = generated_lock

        source_path = Path(sample_manifest["_source_path"])

        source_path.write_text(
            '{"id": "modified-product"}',
            encoding="utf-8",
        )

        assert (
            loader.validate_lock_file(
                lock_path,
                sample_manifest,
                verify_manifest_checksums=False,
            )
            is True
        )

    def test_missing_resolution_policy_is_rejected(
        self, loader, sample_manifest, generated_lock
    ):
        lock_path, lock_data = generated_lock
        lock_data.pop("resolution_policy")
        lock_path.write_text(json.dumps(lock_data), encoding="utf-8")

        with pytest.raises(ManifestError, match="effective resolution policy"):
            loader.validate_lock_file(lock_path, sample_manifest)

    def test_lock_cannot_omit_required_application_from_source_manifest(
        self, loader, tmp_path
    ):
        manifest_path = write_test_manifest(
            loader.manifests_dir,
            "product.json",
            "test-product",
            applications=[
                {
                    "name": "frappe",
                    "repository": "https://github.com/frappe/frappe",
                    "target_ref": "version-16",
                    "required": True,
                    "install_order": 0,
                    "dependencies": [],
                    "compatibility_status": "verified",
                },
                {
                    "name": "erpnext",
                    "repository": "https://github.com/frappe/erpnext",
                    "target_ref": "version-16",
                    "required": True,
                    "install_order": 1,
                    "dependencies": ["frappe"],
                    "compatibility_status": "verified",
                },
            ],
        )
        manifest = loader.load("product.json")
        resolved_apps = [
            {
                **app,
                "ref": ("a" if app["name"] == "frappe" else "b") * 40,
                "_reference_kind": "tag",
                "_resolved_ref": "refs/tags/version-16",
            }
            for app in loader.resolve_install_order(
                loader.compose_applications(manifest)
            )
        ]
        lock_data = loader.build_lock_data(manifest, resolved_apps)
        lock_path = tmp_path / "product.lock.json"
        lock_data["applications"] = [
            app for app in lock_data["applications"] if app["name"] != "erpnext"
        ]
        lock_data["applications"][0]["installation_order"] = 1
        loader.write_lock_file(lock_data, lock_path)

        with pytest.raises(
            ManifestError,
            match="application inventory does not match",
        ):
            loader.validate_lock_file(lock_path, manifest)

    def test_lock_cannot_substitute_application_repository(self, loader, tmp_path):
        write_test_manifest(
            loader.manifests_dir,
            "product.json",
            "test-product",
            applications=[
                {
                    "name": "frappe",
                    "repository": "https://github.com/frappe/frappe",
                    "target_ref": "version-16",
                    "required": True,
                    "install_order": 0,
                    "dependencies": [],
                    "compatibility_status": "verified",
                }
            ],
        )
        manifest = loader.load("product.json")
        app = {
            **loader.compose_applications(manifest)[0],
            "ref": "a" * 40,
            "_reference_kind": "tag",
            "_resolved_ref": "refs/tags/version-16",
        }
        lock_data = loader.build_lock_data(manifest, [app])
        lock_data["applications"][0][
            "repository"
        ] = "https://example.com/attacker/frappe.git"
        lock_path = tmp_path / "product.lock.json"
        loader.write_lock_file(lock_data, lock_path)

        with pytest.raises(
            ManifestError,
            match="application composition does not match",
        ):
            loader.validate_lock_file(lock_path, manifest)

    def test_framework_commit_must_match_frappe_application(
        self, loader, sample_manifest, generated_lock
    ):
        lock_path, lock_data = generated_lock
        lock_data["framework"]["ref"] = "b" * 40
        lock_path.write_text(json.dumps(lock_data), encoding="utf-8")

        with pytest.raises(ManifestError, match="Framework source identity"):
            loader.validate_lock_file(lock_path, sample_manifest)

    def test_invalid_lock_json_is_rejected(
        self,
        loader,
        sample_manifest,
        tmp_path,
    ):
        lock_path = tmp_path / "invalid.lock.json"
        lock_path.write_text("{invalid json", encoding="utf-8")

        with pytest.raises(ManifestError, match="Unable to read lock file"):
            loader.validate_lock_file(
                lock_path,
                sample_manifest,
            )


# ---------------------------------------------------------
# Lock comparison
# ---------------------------------------------------------


class TestLockComparison:

    def test_unchanged_lock_has_no_changes(
        self,
        loader,
        sample_manifest,
        generated_lock,
    ):
        lock_path, lock_data = generated_lock

        changes = loader.compare_lock_files(
            lock_path,
            lock_data,
            sample_manifest,
        )

        assert changes == []

    def test_changed_manifest_is_detected(
        self,
        loader,
        sample_manifest,
        sample_applications,
        generated_lock,
    ):
        lock_path, _ = generated_lock

        source_path = Path(sample_manifest["_source_path"])

        source_path.write_text(
            '{"id": "test-product", "modified": true}',
            encoding="utf-8",
        )

        new_lock_data = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        changes = loader.compare_lock_files(
            lock_path,
            new_lock_data,
            sample_manifest,
        )

        assert any(
            "Changed manifest content: test-product" in change for change in changes
        )

    def test_changed_application_reference_is_detected(
        self,
        loader,
        sample_manifest,
        sample_applications,
        generated_lock,
    ):
        lock_path, _ = generated_lock

        updated_applications = [
            {
                **sample_applications[0],
                "ref": "b" * 40,
            }
        ]

        new_lock_data = loader.build_lock_data(
            sample_manifest,
            updated_applications,
        )

        changes = loader.compare_lock_files(
            lock_path,
            new_lock_data,
            sample_manifest,
        )

        assert any("frappe.ref" in change for change in changes)

    def test_added_application_is_detected(
        self,
        loader,
        sample_manifest,
        sample_applications,
        generated_lock,
    ):
        lock_path, _ = generated_lock

        updated_applications = sample_applications + [
            {
                "name": "erpnext",
                "repository": "https://github.com/frappe/erpnext",
                "target_ref": "version-16",
                "ref": "b" * 40,
                "dependencies": ["frappe"],
            }
        ]

        new_lock_data = loader.build_lock_data(
            sample_manifest,
            updated_applications,
        )

        changes = loader.compare_lock_files(
            lock_path,
            new_lock_data,
            sample_manifest,
        )

        assert any("Added application: erpnext" in change for change in changes)

    def test_removed_application_is_detected(
        self,
        loader,
        sample_manifest,
        sample_applications,
        generated_lock,
    ):
        lock_path, _ = generated_lock

        # The previous composition contains Frappe and ERPNext.
        previous_applications = sample_applications + [
            {
                "name": "erpnext",
                "repository": "https://github.com/frappe/erpnext",
                "target_ref": "version-16",
                "ref": "b" * 40,
                "dependencies": ["frappe"],
                "compatibility_status": "verified",
                "_reference_kind": "tag",
                "_resolved_ref": "refs/tags/version-16",
            }
        ]
        previous_lock_data = loader.build_lock_data(
            sample_manifest,
            previous_applications,
        )
        loader.write_lock_file(previous_lock_data, lock_path)

        # Frappe remains in the valid composition; ERPNext is removed.
        new_lock_data = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        changes = loader.compare_lock_files(
            lock_path,
            new_lock_data,
            sample_manifest,
        )

        assert any("Removed application: erpnext" in change for change in changes)

    def test_missing_previous_lock_is_reported(
        self,
        loader,
        sample_manifest,
        sample_applications,
        tmp_path,
    ):
        lock_path = tmp_path / "missing.lock.json"

        lock_data = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        changes = loader.compare_lock_files(
            lock_path,
            lock_data,
            sample_manifest,
        )

        assert changes
        assert any("No previous lock file found" in change for change in changes)

    def test_version_one_lock_is_reported_for_migration(
        self,
        loader,
        sample_manifest,
        sample_applications,
        tmp_path,
    ):
        lock_path = tmp_path / "legacy.lock.json"
        lock_path.write_text(json.dumps({"lock_version": 1}), encoding="utf-8")
        new_lock_data = loader.build_lock_data(sample_manifest, sample_applications)

        changes = loader.compare_lock_files(
            lock_path,
            new_lock_data,
            sample_manifest,
        )

        assert changes == ["Lock format upgrade required: 1 -> 2"]

    def test_invalid_previous_lock_is_rejected_without_modification(
        self,
        loader,
        sample_manifest,
        sample_applications,
        tmp_path,
    ):
        lock_path = tmp_path / "invalid.lock.json"

        original_content = '{"lock_version": 999}'

        lock_path.write_text(
            original_content,
            encoding="utf-8",
        )

        new_lock_data = loader.build_lock_data(
            sample_manifest,
            sample_applications,
        )

        with pytest.raises(ManifestError):
            loader.compare_lock_files(
                lock_path,
                new_lock_data,
                sample_manifest,
            )

        assert lock_path.read_text(encoding="utf-8") == original_content


class TestCheckMode:

    def test_check_passes_when_lock_is_current(self, cli_environment):
        environment = cli_environment

        # Generate the initial lock.
        generation = run_resolver(environment)

        assert generation.returncode == 0
        assert environment["lock_path"].exists()

        # Run check mode.
        result = run_resolver(environment, "--check")

        assert result.returncode == 0
        assert "No changes detected." in result.stdout
        assert "Lock file is up to date." in result.stdout

    def test_check_fails_when_lock_is_outdated(self, cli_environment):
        environment = cli_environment

        # Generate the initial lock.
        generation = run_resolver(environment)

        assert generation.returncode == 0

        # Modify the source manifest without changing its meaning.
        with environment["manifest_path"].open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write("\n")

        result = run_resolver(environment, "--check")

        assert result.returncode == 1
        assert "Lock file is outdated." in result.stdout
        assert "Changed manifest content: cli-test" in result.stdout

    def test_check_does_not_modify_existing_lock(self, cli_environment):
        environment = cli_environment

        # Generate the initial lock.
        generation = run_resolver(environment)

        assert generation.returncode == 0

        original_lock = environment["lock_path"].read_bytes()

        # Modify the manifest.
        with environment["manifest_path"].open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write("\n")

        # Run check mode.
        result = run_resolver(environment, "--check")

        assert result.returncode == 1

        # The previous lock must remain untouched.
        current_lock = environment["lock_path"].read_bytes()

        assert current_lock == original_lock

    def test_normal_execution_updates_outdated_lock(self, cli_environment):
        environment = cli_environment

        # Generate the initial lock.
        generation = run_resolver(environment)

        assert generation.returncode == 0

        original_lock = environment["lock_path"].read_bytes()

        # Modify the manifest.
        with environment["manifest_path"].open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write("\n")

        # Normal execution should update the lock.
        result = run_resolver(environment)

        assert result.returncode == 0
        assert "Changed manifest content: cli-test" in result.stdout
        assert "Lock file generated and validated" in result.stdout

        updated_lock = environment["lock_path"].read_bytes()

        assert updated_lock != original_lock

        # The updated lock should now pass check mode.
        check = run_resolver(environment, "--check")

        assert check.returncode == 0
        assert "Lock file is up to date." in check.stdout

    def test_check_fails_when_lock_does_not_exist(self, cli_environment):
        environment = cli_environment

        result = run_resolver(environment, "--check")

        assert result.returncode == 1
        assert "Lock file does not exist" in result.stderr


class TestRecursiveManifestLoading:

    def test_recursive_manifest_loading(self, loader):
        manifests_dir = loader.manifests_dir

        write_test_manifest(
            manifests_dir,
            "base.json",
            "base",
        )

        write_test_manifest(
            manifests_dir,
            "capability.json",
            "capability",
            includes=[
                {
                    "manifest": "base.json",
                    "required": True,
                }
            ],
        )

        write_test_manifest(
            manifests_dir,
            "product.json",
            "product",
            includes=[
                {
                    "manifest": "capability.json",
                    "required": True,
                }
            ],
        )

        result = loader.load("product.json")

        capability = result["_loaded_includes"][0]
        base = capability["_loaded_includes"][0]

        assert result["id"] == "product"
        assert capability["id"] == "capability"
        assert base["id"] == "base"

    def test_circular_manifest_include_is_detected(self, loader):
        manifests_dir = loader.manifests_dir

        write_test_manifest(
            manifests_dir,
            "first.json",
            "first",
            includes=[
                {
                    "manifest": "second.json",
                    "required": True,
                }
            ],
        )

        write_test_manifest(
            manifests_dir,
            "second.json",
            "second",
            includes=[
                {
                    "manifest": "first.json",
                    "required": True,
                }
            ],
        )

        with pytest.raises(
            ManifestError,
            match="Circular manifest inclusion detected",
        ):
            loader.load("first.json")

    def test_duplicate_manifest_is_loaded_only_once(self, loader):
        manifests_dir = loader.manifests_dir

        write_test_manifest(
            manifests_dir,
            "shared.json",
            "shared",
        )

        write_test_manifest(
            manifests_dir,
            "product.json",
            "product",
            includes=[
                {
                    "manifest": "shared.json",
                    "required": True,
                },
                {
                    "manifest": "shared.json",
                    "required": True,
                },
            ],
        )

        result = loader.load("product.json")

        included_ids = [item["id"] for item in result["_loaded_includes"]]

        assert included_ids.count("shared") == 1

    def test_shared_manifest_across_branches_is_deduplicated(
        self,
        loader,
    ):
        manifests_dir = loader.manifests_dir

        application = shared_test_application()

        # Shared manifest
        write_test_manifest(
            manifests_dir,
            "shared.json",
            "shared",
            applications=[application],
        )

        # Two capabilities both include the same shared manifest
        write_test_manifest(
            manifests_dir,
            "capability-a.json",
            "capability-a",
            includes=[
                {
                    "manifest": "shared.json",
                    "required": True,
                }
            ],
            applications=[application],
        )

        write_test_manifest(
            manifests_dir,
            "capability-b.json",
            "capability-b",
            includes=[
                {
                    "manifest": "shared.json",
                    "required": True,
                }
            ],
            applications=[application],
        )

        # Product includes both capabilities
        write_test_manifest(
            manifests_dir,
            "product.json",
            "product",
            includes=[
                {
                    "manifest": "capability-a.json",
                    "required": True,
                },
                {
                    "manifest": "capability-b.json",
                    "required": True,
                },
            ],
            applications=[application],
        )

        product = loader.load("product.json")

        # 1. The shared manifest should be the same cached object
        capability_a = product["_loaded_includes"][0]
        capability_b = product["_loaded_includes"][1]

        shared_a = capability_a["_loaded_includes"][0]
        shared_b = capability_b["_loaded_includes"][0]

        assert shared_a is shared_b

        # 2. Application composition should deduplicate identical apps
        applications = loader.compose_applications(product)

        assert len(applications) == 1
        assert applications[0]["name"] == "frappe"

        # 3. Lock generation should record each manifest only once
        lock_data = loader.build_lock_data(
            product,
            applications,
        )

        manifest_paths = [entry["path"] for entry in lock_data["manifests"]]

        assert len(manifest_paths) == len(set(manifest_paths))

        assert set(manifest_paths) == {
            "product.json",
            "capability-a.json",
            "capability-b.json",
            "shared.json",
        }

    def test_duplicate_manifest_id_from_different_files_is_rejected(self, loader):
        manifests_dir = loader.manifests_dir

        write_test_manifest(
            manifests_dir,
            "first.json",
            "shared-identity",
        )

        write_test_manifest(
            manifests_dir,
            "second.json",
            "shared-identity",
        )

        write_test_manifest(
            manifests_dir,
            "product.json",
            "product",
            includes=[
                {"manifest": "first.json", "required": True},
                {"manifest": "second.json", "required": True},
            ],
        )

        with pytest.raises(
            ManifestError,
            match="Duplicate manifest ID 'shared-identity'",
        ):
            loader.load("product.json")

    def test_duplicate_manifest_id_in_optional_include_is_rejected(self, loader):
        manifests_dir = loader.manifests_dir

        write_test_manifest(
            manifests_dir,
            "first.json",
            "shared-identity",
        )

        write_test_manifest(
            manifests_dir,
            "second.json",
            "shared-identity",
        )

        write_test_manifest(
            manifests_dir,
            "product.json",
            "product",
            includes=[
                {"manifest": "first.json", "required": True},
                {"manifest": "second.json", "required": False},
            ],
        )

        with pytest.raises(
            ManifestError,
            match="Duplicate manifest ID 'shared-identity'",
        ):
            loader.load("product.json")


class TestApplicationComposition:

    def test_duplicate_application_definitions_are_deduplicated(self, loader):
        application = {
            "name": "frappe",
            "repository": "https://github.com/frappe/frappe",
            "target_ref": "version-16",
            "required": True,
            "install_order": 0,
            "dependencies": [],
        }

        manifest = {
            "id": "product",
            "applications": [application],
            "_loaded_includes": [
                {
                    "id": "base",
                    "applications": [application.copy()],
                    "_loaded_includes": [],
                }
            ],
        }

        applications = loader.compose_applications(manifest)

        names = [app["name"] for app in applications]

        assert names.count("frappe") == 1

    def test_conflicting_application_definitions_are_rejected(self, loader):
        first_definition = {
            "name": "frappe",
            "repository": "https://github.com/frappe/frappe",
            "target_ref": "version-16",
            "required": True,
            "install_order": 0,
            "dependencies": [],
        }

        conflicting_definition = {
            **first_definition,
            "target_ref": "develop",
        }

        manifest = {
            "id": "product",
            "applications": [first_definition],
            "_loaded_includes": [
                {
                    "id": "base",
                    "applications": [conflicting_definition],
                    "_loaded_includes": [],
                }
            ],
        }

        with pytest.raises(
            ManifestError,
            match="Conflicting application definition",
        ):
            loader.compose_applications(manifest)


class TestApplicationDependencies:

    def test_missing_application_dependency_is_rejected(self, loader):
        applications = [
            {
                "name": "dt_dalali_ecommerce",
                "dependencies": ["dt_ecommerce"],
            }
        ]

        with pytest.raises(
            ManifestError,
            match="Application dependency validation failed",
        ):
            loader.validate_dependencies(applications)

    def test_circular_application_dependencies_are_rejected(self, loader):
        applications = [
            {
                "name": "app_a",
                "dependencies": ["app_b"],
            },
            {
                "name": "app_b",
                "dependencies": ["app_c"],
            },
            {
                "name": "app_c",
                "dependencies": ["app_a"],
            },
        ]

        loader.validate_dependencies(applications)

        with pytest.raises(
            ManifestError,
            match="Circular application dependency",
        ):
            loader.resolve_install_order(applications)

    def test_installation_order_respects_dependencies(self, loader):
        applications = [
            {
                "name": "dt_dalali_ecommerce",
                "dependencies": [
                    "dt_ecommerce",
                    "dt_recomendations",
                ],
            },
            {
                "name": "dt_recomendations",
                "dependencies": ["dt_ecommerce"],
            },
            {
                "name": "dt_ecommerce",
                "dependencies": ["webshop"],
            },
            {
                "name": "webshop",
                "dependencies": ["erpnext"],
            },
            {
                "name": "erpnext",
                "dependencies": ["frappe"],
            },
            {
                "name": "frappe",
                "dependencies": [],
            },
        ]

        loader.validate_dependencies(applications)

        ordered = loader.resolve_install_order(applications)
        ordered_names = [app["name"] for app in ordered]

        assert ordered_names.index("frappe") < ordered_names.index("erpnext")
        assert ordered_names.index("erpnext") < ordered_names.index("webshop")
        assert ordered_names.index("webshop") < ordered_names.index("dt_ecommerce")
        assert ordered_names.index("dt_ecommerce") < ordered_names.index(
            "dt_recomendations"
        )
        assert ordered_names.index("dt_recomendations") < ordered_names.index(
            "dt_dalali_ecommerce"
        )


class TestV2CompositionAndCapabilityLoading:
    def _manifest(self, manifest_id, **overrides):
        value = {
            "manifest_version": "2.0.0",
            "id": manifest_id,
            "name": manifest_id,
            "framework": {
                "name": "frappe",
                "version": "16",
                "release_channel": "stable",
                "target_ref": "version-16",
            },
            "target_runtime": {"frappe": "16.0.0", "python": "3.14.3"},
            "profile": {
                "type": "product",
                "required": True,
                "install_by_default": True,
            },
            "resolution": {
                "strategy": "locked",
                "require_immutable_commit": True,
                "fail_on_unverified_compatibility": True,
            },
            "validation": {},
        }
        value.update(overrides)
        return value

    def test_v2_schema_is_selected_by_manifest_version(self, loader):
        manifest = self._manifest("v2-schema-test")
        loader.validate(manifest, loader.manifests_dir / "product-v2.json")

    def test_optional_capability_requires_explicit_boolean_selection(self, loader):
        path = loader.manifests_dir / "product.json"
        path.write_text(
            json.dumps(
                self._manifest(
                    "product",
                    capabilities=[{"manifest": "capability.json", "required": False}],
                )
            ),
            encoding="utf-8",
        )
        with pytest.raises(ManifestError, match="Schema validation failed"):
            loader.load("product.json")

    def test_optional_capability_is_not_loaded_when_explicitly_unselected(self, loader):
        capability = self._manifest(
            "optional-ai",
            profile={
                "type": "capability",
                "required": False,
                "install_by_default": False,
            },
        )
        (loader.manifests_dir / "optional-ai.json").write_text(
            json.dumps(capability), encoding="utf-8"
        )
        product = self._manifest(
            "product",
            capabilities=[
                {"manifest": "optional-ai.json", "required": False, "selected": False}
            ],
        )
        (loader.manifests_dir / "product.json").write_text(
            json.dumps(product), encoding="utf-8"
        )

        loaded = loader.load("product.json")

        assert loaded["_loaded_capabilities"] == []
        assert loaded["_capability_selections"] == [
            {"manifest": "optional-ai.json", "required": False, "selected": False}
        ]

    def test_selected_optional_capability_is_loaded_into_graph(self, loader):
        capability = self._manifest(
            "optional-ai",
            profile={
                "type": "capability",
                "required": False,
                "install_by_default": False,
            },
        )
        (loader.manifests_dir / "optional-ai.json").write_text(
            json.dumps(capability), encoding="utf-8"
        )
        product = self._manifest(
            "product",
            capabilities=[
                {"manifest": "optional-ai.json", "required": False, "selected": True}
            ],
        )
        (loader.manifests_dir / "product.json").write_text(
            json.dumps(product), encoding="utf-8"
        )

        loaded = loader.load("product.json")

        assert [item["id"] for item in loaded["_loaded_capabilities"]] == [
            "optional-ai"
        ]

    def test_capability_selection_is_recorded_and_lock_tampering_is_rejected(
        self, loader, tmp_path, monkeypatch
    ):
        manifest = self._manifest(
            "product",
            capabilities=[
                {
                    "manifest": "optional-ai.json",
                    "required": False,
                    "selected": False,
                }
            ],
            applications=[
                {
                    "name": "frappe",
                    "repository": "https://github.com/frappe/frappe",
                    "target_ref": "version-16",
                    "required": True,
                    "install_order": 0,
                    "dependencies": [],
                    "compatibility_status": "verified",
                }
            ],
        )
        source = loader.manifests_dir / "product.json"
        source.write_text(json.dumps(manifest), encoding="utf-8")
        loaded = loader.load("product.json")
        applications = loader.compose_applications(loaded)
        monkeypatch.setattr(
            loader,
            "resolve_git_ref",
            lambda repository, target_ref: {
                "sha": "a" * 40,
                "kind": "tag",
                "name": f"refs/tags/{target_ref}",
            },
        )
        applications = loader.resolve_application_refs(
            loader.resolve_install_order(applications),
            loader.resolve_policy(loaded),
        )
        lock = loader.build_lock_data(loaded, applications)

        assert lock["capabilities"] == [
            {
                "manifest": "optional-ai.json",
                "required": False,
                "selected": False,
            }
        ]
        lock_path = tmp_path / "capability.lock.json"
        loader.write_lock_file(lock, lock_path)
        assert loader.validate_lock_file(lock_path, loaded) is True

        tampered = json.loads(lock_path.read_text(encoding="utf-8"))
        tampered["capabilities"][0]["selected"] = True
        loader.write_lock_file(tampered, lock_path)
        with pytest.raises(ManifestError, match="capability selections"):
            loader.validate_lock_file(lock_path, loaded)

    def test_v1_capability_declarations_keep_legacy_non_loading_behaviour(self, loader):
        product_path = write_test_manifest(
            loader.manifests_dir, "product.json", "product"
        )
        product = json.loads(product_path.read_text(encoding="utf-8"))
        product["capabilities"] = [
            {
                "manifest": "legacy-capability.json",
                "required": False,
                "install_by_default": False,
            }
        ]
        product_path.write_text(json.dumps(product), encoding="utf-8")

        loaded = loader.load("product.json")

        assert loaded["_loaded_capabilities"] == []


class TestDescriptorResolutionPrimitives:
    def test_target_runtime_compatibility_uses_ecosystem_semantics(self, loader):
        descriptor = {
            "app_id": "example_app",
            "compatibility": {
                "frappe": ">=16.0.0 <17.0.0",
                "python": ">=3.12,<3.15",
                "erpnext": "^16.0.0",
            },
            "dependencies": {"bench_apps": [{"app_id": "erpnext", "required": True}]},
        }
        loader._validate_descriptor_target(
            descriptor,
            {"frappe": "16.2.0", "python": "3.14.3", "erpnext": "16.1.0"},
            set(),
        )
        with pytest.raises(ManifestError, match="does not satisfy"):
            loader._validate_descriptor_target(
                descriptor,
                {"frappe": "17.0.0", "python": "3.14.3", "erpnext": "16.1.0"},
                set(),
            )

    def test_package_constraints_resolve_to_exact_target_versions(self, loader):
        descriptor = {
            "app_id": "example_app",
            "dependencies": {
                "python": [
                    {
                        "name": "requests",
                        "required": True,
                        "version_policy": "constraint",
                        "version": ">=2.30,<3.0",
                        "disposition": "runtime_compatible",
                    }
                ],
                "node": [
                    {
                        "name": "vite",
                        "required": True,
                        "version_policy": "latest_compatible",
                        "scope": "build",
                        "disposition": "runtime_compatible",
                    }
                ],
            },
        }
        result = loader._resolve_descriptor_packages(
            descriptor,
            {
                "package_versions": {
                    "python:requests": {
                        "version": "2.32.3",
                        "source": "https://pypi.org/simple",
                        "resolver": "uv",
                    },
                    "node:vite": {
                        "version": "6.0.0",
                        "source": "https://registry.npmjs.org",
                        "resolver": "npm",
                    },
                }
            },
            set(),
        )
        assert [
            (item["ecosystem"], item["name"], item["version"]) for item in result
        ] == [
            ("node", "vite", "6.0.0"),
            ("python", "requests", "2.32.3"),
        ]

    def test_os_package_versions_require_exact_native_selection_and_matching_target(
        self, loader
    ):
        descriptor = {
            "app_id": "example_app",
            "dependencies": {
                "os": [
                    {
                        "name": "libpq-dev",
                        "required": True,
                        "version_policy": "constraint",
                        "version": "16.4-1",
                        "disposition": "environment_level",
                        "distribution_family": "debian",
                        "package_manager": "apt",
                        "scope": "build",
                    }
                ]
            },
        }
        result = loader._resolve_descriptor_packages(
            descriptor,
            {
                "os": {"distribution_family": "debian", "package_manager": "apt"},
                "package_versions": {
                    "os:libpq-dev": {
                        "version": "16.4-1",
                        "source": "http://deb.debian.org/debian",
                        "resolver": "apt",
                    }
                },
            },
            set(),
        )
        assert result[0]["install"] is True
        assert result[0]["disposition"] == "environment_level"

    def test_missing_exact_package_selection_fails_closed(self, loader):
        descriptor = {
            "app_id": "example_app",
            "dependencies": {
                "python": [
                    {
                        "name": "requests",
                        "required": True,
                        "version_policy": "latest_compatible",
                        "disposition": "runtime_compatible",
                    }
                ]
            },
        }
        with pytest.raises(ManifestError, match="must provide an exact selection"):
            loader._resolve_descriptor_packages(
                descriptor, {"package_versions": {}}, set()
            )


class TestIndependentServiceComposition:
    def _write_service(self, loader, service_id, descriptor):
        path = (
            loader.repository_root
            / "images"
            / "ndf"
            / "descriptors"
            / "services"
            / f"{service_id}.json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(descriptor), encoding="utf-8")
        return f"images/ndf/descriptors/services/{service_id}.json"

    def test_container_services_and_external_requirements_are_separate(self, loader):
        service_path = self._write_service(
            loader,
            "search",
            {
                "descriptor_version": "1.0.0",
                "service_id": "search",
                "name": "Search service",
                "service_kind": "container",
                "artifact": {"image": "ghcr.io/example/search@sha256:" + "a" * 64},
            },
        )
        external_path = self._write_service(
            loader,
            "payments_api",
            {
                "descriptor_version": "1.0.0",
                "service_id": "payments_api",
                "name": "Payments API",
                "service_kind": "external",
                "provider": {
                    "name": "Example Payments",
                    "requirement": "Merchant API v1",
                },
            },
        )
        source = loader.manifests_dir / "product.json"
        source.write_text("{}", encoding="utf-8")
        manifest = {
            "id": "product",
            "_source_path": str(source),
            "_loaded_includes": [],
            "_loaded_capabilities": [],
            "services": [{"descriptor": service_path, "required": True}],
            "external_requirements": [{"descriptor": external_path, "required": True}],
        }

        services, external = loader.compose_services(manifest)

        assert [item["service_id"] for item in services] == ["search"]
        assert [item["service_id"] for item in external] == ["payments_api"]
        assert services[0]["artifact"]["image"].endswith("a" * 64)
        assert external[0]["provider"]["requirement"] == "Merchant API v1"

    def test_service_inventory_never_enters_bench_apps_json(
        self, loader, sample_manifest, sample_applications
    ):
        service_path = self._write_service(
            loader,
            "search",
            {
                "descriptor_version": "1.0.0",
                "service_id": "search",
                "name": "Search",
                "service_kind": "container",
                "artifact": {"image": "registry.example/search@sha256:" + "5" * 64},
            },
        )
        manifest = dict(sample_manifest)
        manifest["services"] = [{"descriptor": service_path, "required": True}]
        applications = sample_applications + [
            {
                "name": "example_app",
                "repository": "https://github.com/example/example_app",
                "target_ref": "version-1",
                "ref": "b" * 40,
                "dependencies": ["frappe"],
                "compatibility_status": "verified",
                "_reference_kind": "tag",
                "_resolved_ref": "refs/tags/version-1",
            }
        ]

        lock = loader.build_lock_data(manifest, applications)
        from scripts.prepare_build import build_apps_json

        apps_json = build_apps_json(lock)

        assert [item["service_id"] for item in lock["services"]] == ["search"]
        assert [item["url"] for item in apps_json] == [
            "https://github.com/example/example_app"
        ]
        assert all(item.get("name") != "search" for item in apps_json)

    def test_lock_validation_rejects_omitted_service_inventory(
        self, loader, sample_manifest, sample_applications, tmp_path
    ):
        service_path = self._write_service(
            loader,
            "search",
            {
                "descriptor_version": "1.0.0",
                "service_id": "search",
                "name": "Search",
                "service_kind": "container",
                "artifact": {"image": "registry.example/search@sha256:" + "6" * 64},
            },
        )
        manifest = dict(sample_manifest)
        manifest["services"] = [{"descriptor": service_path, "required": True}]
        lock_data = loader.build_lock_data(manifest, sample_applications)
        lock_path = tmp_path / "service.lock.json"
        loader.write_lock_file(lock_data, lock_path)
        assert loader.validate_lock_file(lock_path, manifest) is True

        lock_data["services"] = []
        loader.write_lock_file(lock_data, lock_path)
        with pytest.raises(
            ManifestError,
            match="service inventory does not match",
        ):
            loader.validate_lock_file(lock_path, manifest)

    def test_container_service_rejects_mutable_tag(self, loader):
        service_path = self._write_service(
            loader,
            "search",
            {
                "descriptor_version": "1.0.0",
                "service_id": "search",
                "name": "Search service",
                "service_kind": "container",
                "artifact": {"image": "ghcr.io/example/search:latest"},
            },
        )
        source = loader.manifests_dir / "product.json"
        source.write_text("{}", encoding="utf-8")
        manifest = {
            "id": "product",
            "_source_path": str(source),
            "_loaded_includes": [],
            "_loaded_capabilities": [],
            "services": [{"descriptor": service_path, "required": True}],
        }
        with pytest.raises(ManifestError, match="Invalid service descriptor"):
            loader.compose_services(manifest)

    def test_service_dependencies_are_closed_from_catalogue(self, loader):
        self._write_service(
            loader,
            "cache",
            {
                "descriptor_version": "1.0.0",
                "service_id": "cache",
                "name": "Cache",
                "service_kind": "container",
                "artifact": {"image": "registry.example/cache@sha256:" + "3" * 64},
            },
        )
        root_path = self._write_service(
            loader,
            "search",
            {
                "descriptor_version": "1.0.0",
                "service_id": "search",
                "name": "Search",
                "service_kind": "container",
                "artifact": {"image": "registry.example/search@sha256:" + "4" * 64},
                "depends_on": ["cache"],
            },
        )
        source = loader.manifests_dir / "product.json"
        source.write_text("{}", encoding="utf-8")
        manifest = {
            "id": "product",
            "_source_path": str(source),
            "_loaded_includes": [],
            "_loaded_capabilities": [],
            "services": [{"descriptor": root_path, "required": True}],
        }

        services, external = loader.compose_services(manifest)

        assert [item["service_id"] for item in services] == ["cache", "search"]
        assert services[0]["resolution_order"] < services[1]["resolution_order"]
        assert external == []

    def test_service_dependency_cycles_are_rejected(self, loader):
        first = self._write_service(
            loader,
            "first",
            {
                "descriptor_version": "1.0.0",
                "service_id": "first",
                "name": "First",
                "service_kind": "container",
                "artifact": {"image": "registry.example/first@sha256:" + "1" * 64},
                "depends_on": ["second"],
            },
        )
        second = self._write_service(
            loader,
            "second",
            {
                "descriptor_version": "1.0.0",
                "service_id": "second",
                "name": "Second",
                "service_kind": "container",
                "artifact": {"image": "registry.example/second@sha256:" + "2" * 64},
                "depends_on": ["first"],
            },
        )
        source = loader.manifests_dir / "product.json"
        source.write_text("{}", encoding="utf-8")
        manifest = {
            "id": "product",
            "_source_path": str(source),
            "_loaded_includes": [],
            "_loaded_capabilities": [],
            "services": [
                {"descriptor": first, "required": True},
                {"descriptor": second, "required": True},
            ],
        }
        with pytest.raises(
            ManifestError, match="Circular independent-service dependency"
        ):
            loader.compose_services(manifest)


class TestDescriptorLockIdentity:
    def test_app_id_release_and_git_ref_provenance_remain_distinct(
        self, loader, sample_manifest
    ):
        applications = [
            {
                "name": "frappe",
                "repository": "https://github.com/frappe/frappe",
                "target_ref": "version-16",
                "ref": "a" * 40,
                "dependencies": [],
                "compatibility_status": "verified",
                "_reference_kind": "tag",
                "_resolved_ref": "refs/tags/version-16",
            },
            {
                "name": "example_app",
                "repository": "https://github.com/example/example_app",
                "target_ref": "release-4",
                "ref": "b" * 40,
                "dependencies": ["frappe"],
                "compatibility_status": "verified",
                "_reference_kind": "tag",
                "_resolved_ref": "refs/tags/release-4",
                "_app_id": "example_app",
                "_release_version": "4.2.1",
                "_descriptor_path": "images/ndf/descriptors/apps/example_app.json",
                "_descriptor_sha256": "c" * 64,
                "app_id": "example_app",
                "release_version": "4.2.1",
                "descriptor": "images/ndf/descriptors/apps/example_app.json",
                "descriptor_sha256": "c" * 64,
                "package_dependencies": [],
            },
        ]
        lock = loader.build_lock_data(sample_manifest, applications)
        locked = next(
            item for item in lock["applications"] if item["name"] == "example_app"
        )

        assert locked["app_id"] == "example_app"
        assert locked["release_version"] == "4.2.1"
        assert locked["target_ref"] == "release-4"
        assert locked["ref"] == "b" * 40
        assert locked["reference_kind"] == "tag"
        assert locked["resolved_ref"] == "refs/tags/release-4"
        assert locked["descriptor_sha256"] == "c" * 64


class TestDescriptorCompositionClosureAndLock:
    def _descriptor(self, app_id, version, dependencies=None):
        return {
            "descriptor_version": "1.0.0",
            "app_id": app_id,
            "name": app_id.replace("_", " ").title(),
            "publisher": "NDF",
            "source": {
                "repository": f"https://github.com/example/{app_id}",
                "default_ref": f"git-ref-{app_id}",
            },
            "app_module": {"bench_app_name": app_id},
            "release": {"version": version},
            "compatibility": {
                "status": "verified",
                "frappe": ">=16.0.0 <17.0.0",
                "python": ">=3.12,<3.15",
                "evidence": [
                    {
                        "kind": "automated_test",
                        "authority": "ndf",
                        "reference": "https://github.com/NdfTechLabs/frappe_docker/actions",
                        "result": "passed",
                        "tested_at": "2026-11-10T00:00:00Z",
                        "tested_versions": {
                            "frappe": "16.0.0",
                            "python": "3.14.3",
                        },
                    }
                ],
            },
            "dependencies": {"bench_apps": dependencies or []},
            "build": {},
            "installation": {
                "bench_installable": True,
                "requires_migrate": True,
                "post_install_policy": "operator_action",
            },
        }

    def test_required_descriptor_dependency_closure_and_lock_identity(
        self, loader, tmp_path, monkeypatch
    ):
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        shutil.copy2(
            Path(__file__).resolve().parents[1]
            / "policies"
            / "build-install-policies-v1.json",
            policy_dir / "build-install-policies-v1.json",
        )
        descriptor_dir = tmp_path / "images" / "ndf" / "descriptors" / "apps"
        descriptor_dir.mkdir(parents=True)

        dependency = self._descriptor("dependency_app", "2.1.0")
        root = self._descriptor(
            "root_app",
            "4.2.1",
            dependencies=[
                {
                    "app_id": "dependency_app",
                    "required": True,
                    "version_policy": "constraint",
                    "version": "^2.0.0",
                }
            ],
        )
        (descriptor_dir / "dependency_app.json").write_text(
            json.dumps(dependency), encoding="utf-8"
        )
        (descriptor_dir / "root_app.json").write_text(
            json.dumps(root), encoding="utf-8"
        )

        manifest = {
            "manifest_version": "2.0.0",
            "id": "descriptor-product",
            "name": "Descriptor Product",
            "framework": {
                "name": "frappe",
                "version": "16",
                "release_channel": "stable",
                "target_ref": "framework-ref-16",
            },
            "target_runtime": {"frappe": "16.0.0", "python": "3.14.3"},
            "profile": {
                "type": "product",
                "required": True,
                "install_by_default": True,
            },
            "resolution": {
                "strategy": "locked",
                "require_immutable_commit": True,
                "fail_on_unverified_compatibility": True,
            },
            "applications": [
                {
                    "descriptor": "images/ndf/descriptors/apps/root_app.json",
                    "required": True,
                },
                {
                    "name": "frappe",
                    "repository": "https://github.com/frappe/frappe",
                    "target_ref": "framework-ref-16",
                    "required": True,
                    "install_order": 0,
                    "dependencies": [],
                    "compatibility_status": "verified",
                },
            ],
            "validation": {},
        }
        (loader.manifests_dir / "descriptor-product.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

        loaded = loader.load("descriptor-product.json")
        applications = loader.compose_applications(loaded)
        ordered = loader.resolve_install_order(applications)
        names = [item["name"] for item in ordered]

        assert "dependency_app" in names
        assert names.index("dependency_app") < names.index("root_app")
        root_app = next(item for item in ordered if item["name"] == "root_app")
        assert root_app["app_id"] == "root_app"
        assert root_app["release_version"] == "4.2.1"
        assert root_app["target_ref"] == "git-ref-root_app"

        commits = {
            "framework-ref-16": "a" * 40,
            "git-ref-root_app": "b" * 40,
            "git-ref-dependency_app": "c" * 40,
        }
        monkeypatch.setattr(
            loader,
            "resolve_git_ref",
            lambda repository, target_ref: {
                "sha": commits[target_ref],
                "kind": "tag",
                "name": f"refs/tags/{target_ref}",
            },
        )
        resolved = loader.resolve_application_refs(
            ordered, loader.resolve_policy(loaded)
        )
        lock = loader.build_lock_data(loaded, resolved)
        locked_root = next(
            item for item in lock["applications"] if item["name"] == "root_app"
        )

        assert locked_root["app_id"] == "root_app"
        assert locked_root["release_version"] == "4.2.1"
        assert locked_root["target_ref"] == "git-ref-root_app"
        assert locked_root["ref"] == "b" * 40
        assert locked_root["reference_kind"] == "tag"
        assert locked_root["resolved_ref"] == "refs/tags/git-ref-root_app"
        assert locked_root["descriptor"] == "images/ndf/descriptors/apps/root_app.json"
        assert locked_root["descriptor_sha256"]

        lock_path = tmp_path / "descriptor-product.lock.json"
        loader.write_lock_file(lock, lock_path)
        assert loader.validate_lock_file(lock_path, loaded) is True

        tampered = json.loads(lock_path.read_text(encoding="utf-8"))
        tampered_root = next(
            item for item in tampered["applications"] if item["name"] == "root_app"
        )
        tampered_root["release_version"] = "9.9.9"
        loader.write_lock_file(tampered, lock_path)
        with pytest.raises(
            ManifestError,
            match="application composition does not match",
        ):
            loader.validate_lock_file(lock_path, loaded)
