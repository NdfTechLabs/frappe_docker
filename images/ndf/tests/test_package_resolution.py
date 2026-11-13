import hashlib
import json
from pathlib import Path

import pytest

from scripts.package_resolution import (
    PackageResolutionError,
    package_identity,
    validate_package_resolution,
)
from scripts.resolve_manifest import ManifestLoader, ManifestError

NDF_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = NDF_DIR.parents[1]
CATALOGUE = NDF_DIR / "policies" / "package-source-profiles-v1.json"
INVENTORY_ROOT = (
    "images/ndf/inventories/debian-trixie-amd64/"
    "f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c"
)
BUILDER_DIGEST = "sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b"
RUNTIME_DIGEST = "sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c"
BUILDER_INDEX_DIGEST = "sha256:d97ec9f1f4c7330ac419658716244f725b3d03396ca4420ce697181dd6d31cbe"
RUNTIME_INDEX_DIGEST = "sha256:7409981f6238662325583025a8dc23364b348a806146080879f1ef48372a6bc0"


def target_runtime():
    return {
        "frappe": "16.0.0",
        "python": "3.14.10",
        "python_implementation": "CPython",
        "python_cache_tag": "cpython-314",
        "python_soabi": "cpython-314-x86_64-linux-gnu",
        "python_platform": "linux-x86_64",
        "python_executable": "/usr/local/bin/python3",
        "python_build": "CPython 3.14.10, compiled with GCC 14.2.0",
        "node": "24.22.2",
        "npm": "11.19.1",
        "node_platform": "linux",
        "node_architecture": "x64",
        "node_abi": "137",
        "node_api": "10",
        "node_executable": "/home/frappe/.nvm/current/bin/node",
        "platform": {"os": "linux", "architecture": "amd64"},
        "images": {
            "builder": {
                "reference": f"frappe/build@{BUILDER_DIGEST}",
                "index_digest": BUILDER_INDEX_DIGEST,
                "manifest_digest": BUILDER_DIGEST,
                "platform": "linux/amd64",
            },
            "runtime": {
                "reference": f"frappe/base@{RUNTIME_DIGEST}",
                "index_digest": RUNTIME_INDEX_DIGEST,
                "manifest_digest": RUNTIME_DIGEST,
                "platform": "linux/amd64",
            },
        },
        "os": {
            "distribution_family": "debian",
            "id": "debian",
            "version_id": "13",
            "codename": "trixie",
            "architecture": "amd64",
            "package_manager": "apt",
            "package_manager_version": "3.0.4",
            "package_database": "dpkg",
            "package_database_version": "1.22.22",
            "libc": {"implementation": "glibc", "version": "2.41"},
        },
    }


def python_package(name, version, *, direct=False, requested_by=None):
    return {
        "id": package_identity("python", name, version),
        "ecosystem": "python",
        "name": name,
        "version": version,
        "architecture": "",
        "source_profile": "python-pypi-public-v1",
        "source": "https://pypi.org/simple",
        "resolver": "uv",
        "resolver_version": "0.9.5",
        "direct": direct,
        "requested_by": requested_by or [],
        "disposition": "runtime_compatible",
        "install": True,
        "scope": "runtime",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "a" * 64,
            "artifact": "https://files.pythonhosted.org/packages/demo/demo.whl",
        }],
        "repository_metadata": {"source_identity": "official-public-pypi"},
    }


def node_package(name, version, *, direct=False, requested_by=None):
    return {
        "id": package_identity("node", name, version),
        "ecosystem": "node",
        "name": name,
        "version": version,
        "architecture": "",
        "source_profile": "node-npm-public-v1",
        "source": "https://registry.npmjs.org",
        "resolver": "npm",
        "resolver_version": "11.19.1",
        "direct": direct,
        "requested_by": requested_by or [],
        "disposition": "runtime_compatible",
        "install": True,
        "scope": "build",
        "integrity": [{
            "algorithm": "sha512",
            "digest": "b" * 128,
            "artifact": "https://registry.npmjs.org/demo/-/demo-1.2.3.tgz",
        }],
        "repository_metadata": {"source_identity": "official-public-npm-registry"},
    }


def package_resolution(packages=None, edges=None):
    profiles = sorted({item["source_profile"] for item in packages or []})
    return {
        "schema_version": 1,
        "source_policy_catalogue_version": "1.0.0",
        "source_profiles": profiles,
        "base_inventory": None,
        "packages": sorted(packages or [], key=lambda item: item["id"]),
        "dependency_edges": sorted(
            edges or [],
            key=lambda item: (item["from"], item["to"], item["constraint"]),
        ),
    }


def applications():
    return [{"name": "demo_app", "app_id": "demo_app", "package_dependencies": []}]


def validate(section, *, target=None, apps=None, catalogue_path=CATALOGUE):
    if apps is None:
        direct_dependencies = []
        for package in section["packages"]:
            if not package["direct"]:
                continue
            direct_dependencies.append({
                "ecosystem": package["ecosystem"],
                "name": package["name"],
                "version": package["version"],
                "source": package["source"],
                "resolver": package["resolver"],
                "source_profile": package["source_profile"],
                "scope": package["scope"],
                "version_policy": "latest_compatible",
                "requested_constraint": None,
                "disposition": package["disposition"],
                "install": package["install"],
            })
        apps = [{
            "name": "demo_app",
            "app_id": "demo_app",
            "package_dependencies": direct_dependencies,
        }]
    return validate_package_resolution(
        section,
        target_runtime=target if target is not None else target_runtime(),
        applications=apps,
        repository_root=REPOSITORY_ROOT,
        catalogue_path=catalogue_path,
    )


def _build_package_lock(tmp_path):
    manifests_dir = tmp_path / "manifests"
    manifests_dir.mkdir()
    source_path = manifests_dir / "demo-product.json"
    source_path.write_text('{"id":"demo-product"}', encoding="utf-8")
    loader = ManifestLoader(manifests_dir)
    loader.repository_root = REPOSITORY_ROOT
    loader.schema_dir = NDF_DIR / "schemas"
    manifest = {
        "manifest_version": "1.0",
        "id": "demo-product",
        "name": "Demo Product",
        "profile": {"type": "product", "required": True, "install_by_default": True},
        "framework": {
            "name": "frappe",
            "version": "16",
            "release_channel": "stable",
            "target_ref": "version-16",
        },
        "resolution": {
            "require_immutable_commit": True,
            "fail_on_unverified_compatibility": True,
        },
        "target_runtime": target_runtime(),
        "_source_path": str(source_path),
        "_loaded_includes": [],
        "_loaded_capabilities": [],
        "_capability_selections": [],
    }
    applications_list = [
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
            "name": "demo_app",
            "repository": "https://github.com/example/demo_app",
            "target_ref": "main",
            "ref": "b" * 40,
            "dependencies": ["frappe"],
            "compatibility_status": "verified",
            "_reference_kind": "branch",
            "_resolved_ref": "refs/heads/main",
            "_app_id": "demo_app",
            "_release_version": "1.0.0",
            "_descriptor_path": "images/ndf/descriptors/apps/demo_app.json",
            "_descriptor_sha256": "c" * 64,
            "package_dependencies": [],
        },
    ]
    lock = loader.build_lock_data(manifest, applications_list)
    package = python_package(
        "requests", "2.32.3", direct=True, requested_by=["demo_app"]
    )
    direct = {
        "ecosystem": "python",
        "name": "requests",
        "version": "2.32.3",
        "source": "https://pypi.org/simple",
        "resolver": "uv",
        "source_profile": "python-pypi-public-v1",
        "scope": "runtime",
        "version_policy": "constraint",
        "requested_constraint": ">=2.30,<3.0",
        "disposition": "runtime_compatible",
        "install": True,
    }
    lock["applications"][1]["package_dependencies"] = [direct]
    lock["package_resolution"] = package_resolution([package])
    lock_path = tmp_path / "demo-product.lock.json"
    loader.write_lock_file(lock, lock_path)
    return loader, manifest, lock_path, lock


def test_manifest_loader_validates_package_resolution_offline(tmp_path):
    loader, manifest, lock_path, _ = _build_package_lock(tmp_path)

    assert loader.validate_lock_file(lock_path, manifest) is True


def test_manifest_loader_rejects_package_resolution_tampering(tmp_path):
    loader, manifest, lock_path, lock = _build_package_lock(tmp_path)
    lock["package_resolution"]["packages"][0]["resolver_version"] = ""
    loader.write_lock_file(lock, lock_path)

    with pytest.raises(ManifestError, match="unpinned resolver"):
        loader.validate_lock_file(lock_path, manifest)


def test_scoped_npm_package_uses_approved_registry_and_target_npm_version():
    package = node_package(
        "@ndf/example",
        "1.2.3",
        direct=True,
        requested_by=["demo_app"],
    )

    assert package["id"] == "node|@ndf/example|1.2.3|"
    assert validate(package_resolution([package])) is True


def test_python_package_identity_uses_pep503_normalization():
    assert package_identity("python", "Demo_Pkg.Name", "1.2.3") == (
        "python|demo-pkg-name|1.2.3|"
    )


def test_valid_direct_and_transitive_graph_passes_offline_validation():
    root = python_package("demo-root", "1.0.0", direct=True, requested_by=["demo_app"])
    dependency = python_package("demo-dependency", "2.4.0")
    section = package_resolution(
        [root, dependency],
        [{
            "from": root["id"],
            "to": dependency["id"],
            "constraint": ">=2,<3",
        }],
    )

    assert validate(section) is True


def test_package_graph_fixture_is_deterministic_for_equivalent_input_order():
    root = python_package("demo-root", "1.0.0", direct=True, requested_by=["demo_app"])
    dependency = python_package("demo-dependency", "2.4.0")
    edge = {
        "from": root["id"],
        "to": dependency["id"],
        "constraint": ">=2,<3",
    }

    first = package_resolution([root, dependency], [edge])
    second = package_resolution([dependency, root], [edge])

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_noncanonical_package_record_order_fails_closed():
    root = python_package("z-root", "1.0.0", direct=True, requested_by=["demo_app"])
    dependency = python_package("a-dependency", "2.4.0")
    section = package_resolution([root, dependency])
    section["packages"].reverse()

    with pytest.raises(PackageResolutionError, match="sorted by id"):
        validate(section)


def test_direct_request_constraint_is_preserved_and_enforced():
    package = python_package("demo-root", "1.5.0", direct=True, requested_by=["demo_app"])
    section = package_resolution([package])
    app = {
        "name": "demo_app",
        "app_id": "demo_app",
        "package_dependencies": [{
            "ecosystem": "python",
            "name": "demo-root",
            "version": "1.5.0",
            "source": "https://pypi.org/simple",
            "resolver": "uv",
            "source_profile": "python-pypi-public-v1",
            "scope": "runtime",
            "version_policy": "constraint",
            "requested_constraint": ">=1,<2",
            "disposition": "runtime_compatible",
            "install": True,
        }],
    }

    assert validate(section, apps=[app]) is True
    app["package_dependencies"][0]["requested_constraint"] = ">=2,<3"
    with pytest.raises(PackageResolutionError, match="direct incoming constraint"):
        validate(section, apps=[app])


def test_multiple_descriptor_constraints_for_one_package_are_all_enforced():
    package = python_package(
        "shared-library",
        "1.5.0",
        direct=True,
        requested_by=["app_one", "app_two"],
    )
    def app_request(app_id, constraint):
        return {
            "name": app_id,
            "app_id": app_id,
            "package_dependencies": [{
                "ecosystem": "python",
                "name": "shared-library",
                "version": "1.5.0",
                "source": "https://pypi.org/simple",
                "resolver": "uv",
                "source_profile": "python-pypi-public-v1",
                "scope": "runtime",
                "version_policy": "constraint",
                "requested_constraint": constraint,
                "disposition": "runtime_compatible",
                "install": True,
            }],
        }
    apps = [
        app_request("app_one", ">=1,<2"),
        app_request("app_two", ">=2,<3"),
    ]

    with pytest.raises(PackageResolutionError, match="direct incoming constraint"):
        validate(package_resolution([package]), apps=apps)


def test_package_source_url_must_match_approved_profile():
    package = python_package("demo-root", "1.0.0", direct=True, requested_by=["demo_app"])
    package["source"] = "https://packages.example.invalid/simple"
    section = package_resolution([package])

    with pytest.raises(PackageResolutionError, match="does not match its approved profile"):
        validate(section)


def test_package_cycle_fails_closed():
    first = python_package("first", "1.0.0", direct=True, requested_by=["demo_app"])
    second = python_package("second", "1.0.0")
    section = package_resolution(
        [first, second],
        [
            {"from": first["id"], "to": second["id"], "constraint": ">=1"},
            {"from": second["id"], "to": first["id"], "constraint": ">=1"},
        ],
    )

    with pytest.raises(PackageResolutionError, match="cycle"):
        validate(section)


def test_unreachable_transitive_package_record_fails_closed():
    root = python_package("demo-root", "1.0.0", direct=True, requested_by=["demo_app"])
    orphan = python_package("orphan", "2.0.0")
    section = package_resolution([root, orphan])

    with pytest.raises(PackageResolutionError, match="unreachable package records"):
        validate(section)


def test_missing_transitive_package_endpoint_fails_closed():
    root = python_package("demo-root", "1.0.0", direct=True, requested_by=["demo_app"])
    section = package_resolution(
        [root],
        [{
            "from": root["id"],
            "to": "python|missing-dependency|1.0.0|",
            "constraint": ">=1",
        }],
    )

    with pytest.raises(PackageResolutionError, match="missing endpoint"):
        validate(section)


def test_multiple_incoming_constraints_must_all_be_satisfied():
    first = python_package("first", "1.0.0", direct=True, requested_by=["demo_app"])
    second = python_package("second", "1.0.0", direct=True, requested_by=["demo_app"])
    shared = python_package("shared", "1.5.0")
    section = package_resolution(
        [first, second, shared],
        [
            {"from": first["id"], "to": shared["id"], "constraint": ">=1,<2"},
            {"from": second["id"], "to": shared["id"], "constraint": ">=2,<3"},
        ],
    )

    with pytest.raises(PackageResolutionError, match="does not satisfy"):
        validate(section)


def test_unapproved_or_cross_ecosystem_source_profile_fails():
    package = python_package("demo", "1.0.0", direct=True, requested_by=["demo_app"])
    package["source_profile"] = "node-npm-public-v1"
    section = package_resolution([package])

    with pytest.raises(PackageResolutionError, match="does not support"):
        validate(section)


def test_target_runtime_outside_accepted_a1_digest_fails():
    package = python_package("demo", "1.0.0", direct=True, requested_by=["demo_app"])
    target = target_runtime()
    target["images"]["runtime"]["manifest_digest"] = "sha256:" + "f" * 64

    with pytest.raises(PackageResolutionError, match="accepted A.1"):
        validate(package_resolution([package]), target=target)


def test_optional_package_omission_is_a_valid_empty_selection():
    section = package_resolution()
    assert validate(section) is True
    assert section["packages"] == []
    assert section["dependency_edges"] == []


def _repository_inventory_reference():
    evidence_dir = REPOSITORY_ROOT / INVENTORY_ROOT
    manifest_path = evidence_dir / "inventory-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result = {
        "schema_version": 1,
        "evidence_reference": INVENTORY_ROOT,
        "manifest_file": "inventory-manifest.json",
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "inventories": {},
    }
    for stage in ("builder", "runtime"):
        item = manifest["inventories"][stage]
        result["inventories"][stage] = {
            "image_manifest_digest": item["image"]["manifest_digest"],
            "platform": item["image"]["platform"],
            "package_database": "dpkg",
            "package_database_version": item["package_database_version"],
            "inventory_file": item["file"],
            "inventory_sha256": item["sha256"],
            "package_count": item["package_count"],
        }
    return result


def test_runtime_scoped_base_package_is_verified_against_committed_inventory():
    package = {
        "id": "os|dpkg|1.22.22|amd64",
        "ecosystem": "os",
        "name": "dpkg",
        "version": "1.22.22",
        "architecture": "amd64",
        "source_profile": "os-debian-trixie-public-amd64-v1",
        "source": "http://deb.debian.org/debian",
        "resolver": "apt",
        "resolver_version": "3.0.4",
        "direct": True,
        "requested_by": ["demo_app"],
        "disposition": "base",
        "install": False,
        "scope": "runtime",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "b" * 64,
            "artifact": "pool/main/d/dpkg/dpkg_1.22.22_amd64.deb",
        }],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
            "signature_verified": True,
            "repository_uri": "http://deb.debian.org/debian",
            "suite": "trixie",
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()

    assert validate(section) is True


@pytest.mark.parametrize(
    ("version", "architecture"),
    [("1.22.23", "amd64"), ("1.22.22", "all")],
)
def test_base_package_version_or_architecture_mismatch_fails(
    version, architecture
):
    package = {
        "id": package_identity("os", "dpkg", version, architecture),
        "ecosystem": "os",
        "name": "dpkg",
        "version": version,
        "architecture": architecture,
        "source_profile": "os-debian-trixie-public-amd64-v1",
        "source": "http://deb.debian.org/debian",
        "resolver": "apt",
        "resolver_version": "3.0.4",
        "direct": True,
        "requested_by": ["demo_app"],
        "disposition": "base",
        "install": False,
        "scope": "runtime",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "b" * 64,
            "artifact": "pool/main/d/dpkg/dpkg_1.22.22_amd64.deb",
        }],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
            "signature_verified": True,
            "repository_uri": "http://deb.debian.org/debian",
            "suite": "trixie",
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()

    with pytest.raises(PackageResolutionError, match="runtime inventory"):
        validate(section)


def test_base_inventory_reference_must_match_runtime_digest():
    package = {
        "id": "os|dpkg|1.22.22|amd64",
        "ecosystem": "os",
        "name": "dpkg",
        "version": "1.22.22",
        "architecture": "amd64",
        "source_profile": "os-debian-trixie-public-amd64-v1",
        "source": "http://deb.debian.org/debian",
        "resolver": "apt",
        "resolver_version": "3.0.4",
        "direct": True,
        "requested_by": ["demo_app"],
        "disposition": "base",
        "install": False,
        "scope": "runtime",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "b" * 64,
            "artifact": "pool/main/d/dpkg/dpkg_1.22.22_amd64.deb",
        }],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
            "signature_verified": True,
            "repository_uri": "http://deb.debian.org/debian",
            "suite": "trixie",
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()
    section["base_inventory"]["evidence_reference"] = (
        "images/ndf/inventories/debian-trixie-amd64/" + "0" * 64
    )

    with pytest.raises(PackageResolutionError, match="not keyed by the target runtime digest"):
        validate(section)


def test_dpkg_evidence_cannot_classify_python_package_as_base():
    package = python_package(
        "demo-root", "1.0.0", direct=True, requested_by=["demo_app"]
    )
    package["disposition"] = "base"
    package["install"] = False

    with pytest.raises(PackageResolutionError, match="cannot establish Python or Node"):
        validate(package_resolution([package]))


def test_builder_only_package_cannot_satisfy_runtime_scope():
    package = {
        "id": "os|dpkg-dev|1.22.22|all",
        "ecosystem": "os",
        "name": "dpkg-dev",
        "version": "1.22.22",
        "architecture": "all",
        "source_profile": "os-debian-trixie-public-amd64-v1",
        "source": "http://deb.debian.org/debian",
        "resolver": "apt",
        "resolver_version": "3.0.4",
        "direct": True,
        "requested_by": ["demo_app"],
        "disposition": "base",
        "install": False,
        "scope": "runtime",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "b" * 64,
            "artifact": "pool/main/d/dpkg/dpkg_1.22.22_amd64.deb",
        }],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
            "signature_verified": True,
            "repository_uri": "http://deb.debian.org/debian",
            "suite": "trixie",
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()

    with pytest.raises(PackageResolutionError, match="runtime inventory"):
        validate(section)



def test_empty_integrity_is_valid_when_source_publishes_no_artifact_hash():
    package = python_package("demo", "1.0.0", direct=True, requested_by=["demo_app"])
    package["integrity"] = []
    section = package_resolution([package])

    assert validate(section) is True


@pytest.mark.parametrize(
    "artifact",
    [
        "http://files.pythonhosted.org/packages/demo/demo.whl",
        "https://user:secret@files.pythonhosted.org/packages/demo/demo.whl",
        "https://files.pythonhosted.org/packages/demo/demo.whl?token=secret",
        "https://files.pythonhosted.org/packages/demo/demo.whl#fragment",
    ],
)
def test_package_artifact_uri_rejects_non_https_credentials_and_query_data(artifact):
    package = python_package("demo", "1.0.0", direct=True, requested_by=["demo_app"])
    package["integrity"][0]["artifact"] = artifact

    with pytest.raises(PackageResolutionError, match="artifact URI"):
        validate(package_resolution([package]))


def test_target_runtime_platform_must_match_accepted_a1_matrix():
    package = python_package("demo", "1.0.0", direct=True, requested_by=["demo_app"])
    target = target_runtime()
    target["platform"]["architecture"] = "arm64"

    with pytest.raises(PackageResolutionError, match="accepted A.1 linux/amd64"):
        validate(package_resolution([package]), target=target)


def test_same_package_name_cannot_mix_source_profiles_or_sources(tmp_path):
    package_root = python_package("demo-root", "1.0.0", direct=True, requested_by=["demo_app"])
    node_one = {
        **python_package("node-dependency", "1.0.0"),
        "id": package_identity("node", "node-dependency", "1.0.0"),
        "ecosystem": "node",
        "source_profile": "node-npm-public-v1",
        "source": "https://registry.npmjs.org",
        "resolver": "npm",
        "resolver_version": "11.19.1",
        "repository_metadata": {"source_identity": "official-public-npm-registry"},
        "integrity": [{
            "algorithm": "sha256",
            "digest": "c" * 64,
            "artifact": "https://registry.npmjs.org/node-dependency/-/node-dependency-1.0.0.tgz",
        }],
    }
    node_two = {
        **node_one,
        "id": package_identity("node", "node-dependency", "2.0.0"),
        "version": "2.0.0",
        "source_profile": "node-test-alternate-v1",
        "source": "https://registry.example.invalid",
        "repository_metadata": {"source_identity": "alternate-test-registry"},
        "integrity": [{
            "algorithm": "sha256",
            "digest": "d" * 64,
            "artifact": "https://registry.npmjs.org/node-dependency/-/node-dependency-2.0.0.tgz",
        }],
    }
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    alternate = dict(catalogue["source_profiles"]["node-npm-public-v1"])
    alternate["registry"] = "https://registry.example.invalid"
    alternate["artifact_hosts"] = ["registry.npmjs.org"]
    alternate["source_identity"] = "alternate-test-registry"
    catalogue["source_profiles"]["node-test-alternate-v1"] = alternate
    catalogue_path = tmp_path / "catalogue.json"
    catalogue_path.write_text(json.dumps(catalogue), encoding="utf-8")

    section = package_resolution(
        [package_root, node_one, node_two],
        [
            {"from": package_root["id"], "to": node_one["id"], "constraint": ">=1,<2"},
            {"from": package_root["id"], "to": node_two["id"], "constraint": ">=2,<3"},
        ],
    )
    # The graph's profile inventory is derived from package records.
    section["source_profiles"] = sorted({
        item["source_profile"] for item in section["packages"]
    })

    with pytest.raises(PackageResolutionError, match="Conflicting package sources"):
        validate(section, catalogue_path=catalogue_path)



def test_selected_optional_dependency_is_represented_as_direct_package():
    package = python_package("optional-feature", "1.2.0", direct=True, requested_by=["demo_app"])
    section = package_resolution([package])
    app = {
        "name": "demo_app",
        "app_id": "demo_app",
        "package_dependencies": [{
            "ecosystem": "python",
            "name": "optional-feature",
            "version": "1.2.0",
            "source": "https://pypi.org/simple",
            "resolver": "uv",
            "source_profile": "python-pypi-public-v1",
            "scope": "runtime",
            "version_policy": "latest_compatible",
            "requested_constraint": None,
            "disposition": "runtime_compatible",
            "install": True,
        }],
    }

    assert validate(section, apps=[app]) is True


def test_base_inventory_builder_digest_must_match_target_image():
    package = {
        "id": "os|libbrotli-dev|1.1.0-2+deb13u1|amd64",
        "ecosystem": "os",
        "name": "libbrotli-dev",
        "version": "1.1.0-2+deb13u1",
        "architecture": "amd64",
        "source_profile": "os-debian-trixie-public-amd64-v1",
        "source": "http://deb.debian.org/debian",
        "resolver": "apt",
        "resolver_version": "3.0.4",
        "direct": True,
        "requested_by": ["demo_app"],
        "disposition": "base",
        "install": False,
        "scope": "build",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "e" * 64,
            "artifact": "pool/main/b/brotli/libbrotli-dev_1.1.0-2+deb13u1_amd64.deb",
        }],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()
    section["base_inventory"]["inventories"]["builder"]["image_manifest_digest"] = (
        "sha256:" + "f" * 64
    )

    with pytest.raises(PackageResolutionError, match="builder digest does not match"):
        validate(section)


def test_base_inventory_platform_must_match_target_image():
    package = {
        "id": "os|dpkg|1.22.22|amd64",
        "ecosystem": "os",
        "name": "dpkg",
        "version": "1.22.22",
        "architecture": "amd64",
        "source_profile": "os-debian-trixie-public-amd64-v1",
        "source": "http://deb.debian.org/debian",
        "resolver": "apt",
        "resolver_version": "3.0.4",
        "direct": True,
        "requested_by": ["demo_app"],
        "disposition": "base",
        "install": False,
        "scope": "runtime",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "f" * 64,
            "artifact": "pool/main/d/dpkg/dpkg_1.22.22_amd64.deb",
        }],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()
    section["base_inventory"]["inventories"]["runtime"]["platform"] = "linux/arm64"

    with pytest.raises(PackageResolutionError, match="metadata does not match evidence"):
        validate(section)


def test_base_inventory_manifest_checksum_is_verified_offline():
    package = {
        "id": "os|dpkg|1.22.22|amd64",
        "ecosystem": "os",
        "name": "dpkg",
        "version": "1.22.22",
        "architecture": "amd64",
        "source_profile": "os-debian-trixie-public-amd64-v1",
        "source": "http://deb.debian.org/debian",
        "resolver": "apt",
        "resolver_version": "3.0.4",
        "direct": True,
        "requested_by": ["demo_app"],
        "disposition": "base",
        "install": False,
        "scope": "runtime",
        "integrity": [{
            "algorithm": "sha256",
            "digest": "a" * 64,
            "artifact": "pool/main/d/dpkg/dpkg_1.22.22_amd64.deb",
        }],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()
    section["base_inventory"]["manifest_sha256"] = "0" * 64

    with pytest.raises(PackageResolutionError, match="manifest checksum mismatch"):
        validate(section)
