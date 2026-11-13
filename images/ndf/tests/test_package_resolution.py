import hashlib
import json
from pathlib import Path

import pytest

from scripts.package_resolution import (
    PackageResolutionError,
    package_identity,
    validate_package_resolution,
)

NDF_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = NDF_DIR.parents[1]
CATALOGUE = NDF_DIR / "policies" / "package-source-profiles-v1.json"
INVENTORY_ROOT = (
    "images/ndf/inventories/debian-trixie-amd64/"
    "f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c"
)
BUILDER_DIGEST = "sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b"
RUNTIME_DIGEST = "sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c"


def target_runtime():
    return {
        "frappe": "16.0.0",
        "python": "3.14.10",
        "node": "24.22.2",
        "platform": {"os": "linux", "architecture": "amd64"},
        "images": {
            "builder": {
                "manifest_digest": BUILDER_DIGEST,
                "platform": "linux/amd64",
            },
            "runtime": {
                "manifest_digest": RUNTIME_DIGEST,
                "platform": "linux/amd64",
            },
        },
        "os": {
            "distribution_family": "debian",
            "codename": "trixie",
            "package_database": "dpkg",
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
        "integrity": [],
        "repository_metadata": {"source_identity": "official-public-pypi"},
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


def validate(section, *, target=None, apps=None):
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
        catalogue_path=CATALOGUE,
    )


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
    second = python_package("second", "1.0.0")
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
        "integrity": [],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()

    assert validate(section) is True


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
        "integrity": [],
        "repository_metadata": {
            "release_identity": "Debian Trixie InRelease fixture",
            "release_sha256": "a" * 64,
        },
    }
    section = package_resolution([package])
    section["base_inventory"] = _repository_inventory_reference()

    with pytest.raises(PackageResolutionError, match="runtime inventory"):
        validate(section)
