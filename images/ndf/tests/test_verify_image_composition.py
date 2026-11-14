import hashlib
import json
from pathlib import Path

import pytest

from scripts.verify_image_composition import (
    CompositionVerificationError,
    verify_composition,
)


@pytest.fixture
def composition_case(tmp_path):
    ndf = tmp_path / "images" / "ndf"
    manifests = ndf / "manifests" / "products"
    manifests.mkdir(parents=True)
    root_manifest = {
        "manifest_version": "1.0.0",
        "id": "sample-product",
        "applications": [
            {"name": "frappe", "required": True},
            {"name": "sample_app", "required": True},
        ],
        "includes": [],
        "capabilities": [
            {"manifest": "capabilities/legacy-optional.json", "required": False}
        ],
    }
    manifest_raw = (json.dumps(root_manifest, sort_keys=True, indent=2) + "\n").encode()
    (manifests / "sample.json").write_bytes(manifest_raw)
    lock = {
        "lock_version": 2,
        "manifests": [{
            "id": "sample-product",
            "path": "products/sample.json",
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
        }],
        "applications": [
            {"name": "frappe", "repository": "https://github.com/frappe/frappe", "target_ref": "version-16", "installation_order": 1},
            {"name": "sample_app", "repository": "https://github.com/example/sample_app", "target_ref": "version-1", "installation_order": 2},
        ],
        "capabilities": [],
        "services": [],
        "external_requirements": [],
    }
    apps = [{"name": "frappe"}, {"name": "sample_app"}]
    return {
        "root": tmp_path,
        "manifest_path": "products/sample.json",
        "lock": lock,
        "apps": apps,
        "directories": ["frappe", "sample_app"],
        "apps_txt": ["frappe", "sample_app"],
    }


def run_case(case):
    lock_bytes = (json.dumps(case["lock"], sort_keys=True, indent=2) + "\n").encode()
    return verify_composition(
        repository_root=case["root"],
        manifest_path=case["manifest_path"],
        lock_data=case["lock"],
        lock_bytes=lock_bytes,
        metadata_applications=case["apps"],
        inventory_applications=case["apps"],
        runtime_directories=case["directories"],
        runtime_apps_txt=case["apps_txt"],
        apps_json=[{"url": "https://github.com/example/sample_app", "branch": "version-1"}],
    )


def write_service(case, service_id, descriptor):
    path = case["root"] / "images" / "ndf" / "descriptors" / "services" / f"{service_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(descriptor, sort_keys=True, indent=2) + "\n").encode()
    path.write_bytes(raw)
    manifest_path = case["root"] / "images" / "ndf" / "manifests" / case["manifest_path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["manifest_version"] = "2.0.0"
    manifest["capabilities"] = []
    field = "services" if descriptor["service_kind"] == "container" else "external_requirements"
    manifest.setdefault(field, []).append({
        "descriptor": f"images/ndf/descriptors/services/{service_id}.json",
        "required": True,
        "selected": True,
    })
    manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    manifest_path.write_bytes(manifest_raw)
    for entry in case["lock"]["manifests"]:
        if entry["path"] == case["manifest_path"]:
            entry["sha256"] = hashlib.sha256(manifest_raw).hexdigest()
    return {
        "service_id": service_id,
        "name": descriptor["name"],
        "service_kind": descriptor["service_kind"],
        "artifact": descriptor.get("artifact"),
        "provider": descriptor.get("provider"),
        "depends_on": descriptor.get("depends_on", []),
        "descriptor": f"images/ndf/descriptors/services/{service_id}.json",
        "descriptor_sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_accepts_v1_manifest_without_inventing_capability_selection(composition_case):
    report = run_case(composition_case)
    assert report["status"] == "passed"
    assert report["capabilities"] == []
    assert report["lock"]["sha256"] == hashlib.sha256(
        (json.dumps(composition_case["lock"], sort_keys=True, indent=2) + "\n").encode()
    ).hexdigest()


def test_rejects_manifest_checksum_tampering(composition_case):
    path = composition_case["root"] / "images/ndf/manifests/products/sample.json"
    path.write_text(path.read_text() + " ", encoding="utf-8")
    with pytest.raises(CompositionVerificationError, match="checksum mismatch"):
        run_case(composition_case)


def test_rejects_missing_runtime_application(composition_case):
    composition_case["directories"].remove("sample_app")
    with pytest.raises(CompositionVerificationError, match="runtime app directories"):
        run_case(composition_case)


def test_rejects_duplicate_runtime_apps_txt_entry(composition_case):
    composition_case["apps_txt"].append("sample_app")
    with pytest.raises(CompositionVerificationError, match="duplicate application"):
        run_case(composition_case)


def test_rejects_build_inventory_application_drift(composition_case):
    composition_case["apps"] = [{"name": "frappe"}]
    with pytest.raises(CompositionVerificationError, match="differs across lock"):
        run_case(composition_case)


def test_rejects_legacy_capability_records(composition_case):
    composition_case["lock"]["capabilities"] = [{
        "manifest": "capabilities/legacy-optional.json",
        "required": False,
        "selected": True,
    }]
    with pytest.raises(CompositionVerificationError, match="Legacy v1"):
        run_case(composition_case)


def test_accepts_selected_v2_capability_and_rejects_unselected_manifest(tmp_path):
    ndf = tmp_path / "images/ndf/manifests"
    (ndf / "products").mkdir(parents=True)
    (ndf / "capabilities").mkdir()
    root = {"manifest_version":"2.0.0","id":"p","capabilities":[{"manifest":"capabilities/feature.json","required":False,"selected":True}],"applications":[{"name":"frappe","required":True}]}
    child = {"manifest_version":"2.0.0","id":"feature","applications":[],"capabilities":[]}
    entries = []
    for path, value in (("products/p.json",root),("capabilities/feature.json",child)):
        raw=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
        (ndf/path).write_bytes(raw)
        entries.append({"id":value["id"],"path":path,"sha256":hashlib.sha256(raw).hexdigest()})
    lock={"lock_version":2,"manifests":entries,"applications":[{"name":"frappe"}],"capabilities":[{"manifest":"capabilities/feature.json","required":False,"selected":True}],"services":[],"external_requirements":[]}
    apps=[{"name":"frappe"}]
    args=dict(repository_root=tmp_path,manifest_path="products/p.json",lock_data=lock,lock_bytes=json.dumps(lock).encode(),metadata_applications=apps,inventory_applications=apps,runtime_directories=["frappe"],runtime_apps_txt=["frappe"],apps_json=[])
    assert verify_composition(**args)["capabilities"][0]["selected"] is True
    lock["manifests"].pop()
    args["lock_data"]=lock
    with pytest.raises(CompositionVerificationError,match="absent from locked manifests"):
        verify_composition(**args)


def test_accepts_transitive_container_and_external_dependency(composition_case):
    external = {
        "descriptor_version":"1.0.0","service_id":"database","name":"Managed database",
        "service_kind":"external","provider":{"name":"Cloud DB","requirement":"PostgreSQL 16"},
        "depends_on":[],
    }
    container = {
        "descriptor_version":"1.0.0","service_id":"worker","name":"Worker",
        "service_kind":"container","artifact":{"image":"ghcr.io/example/worker@sha256:"+"a"*64},
        "depends_on":["database"],
    }
    external_record = write_service(composition_case,"database",external)
    container_record = write_service(composition_case,"worker",container)
    external_record["resolution_order"] = 1
    container_record["resolution_order"] = 2
    composition_case["lock"]["external_requirements"] = [external_record]
    composition_case["lock"]["services"] = [container_record]
    report = run_case(composition_case)
    assert report["service_verification"]["dependency_order"] == ["database","worker"]
    assert report["service_verification"]["dependency_closure_verified"] is True


def test_rejects_mutable_container_image(composition_case):
    descriptor = {
        "descriptor_version":"1.0.0","service_id":"worker","name":"Worker",
        "service_kind":"container","artifact":{"image":"ghcr.io/example/worker:latest"},
    }
    record = write_service(composition_case,"worker",descriptor)
    record["resolution_order"] = 1
    composition_case["lock"]["services"] = [record]
    with pytest.raises(CompositionVerificationError,match="schema failure|immutable digest"):
        run_case(composition_case)


def test_rejects_service_descriptor_byte_tampering(composition_case):
    descriptor = {
        "descriptor_version":"1.0.0","service_id":"worker","name":"Worker",
        "service_kind":"container","artifact":{"image":"ghcr.io/example/worker@sha256:"+"b"*64},
    }
    record = write_service(composition_case,"worker",descriptor)
    record["resolution_order"] = 1
    composition_case["lock"]["services"] = [record]
    path = composition_case["root"] / record["descriptor"]
    path.write_text(path.read_text().replace("Worker","Changed"),encoding="utf-8")
    with pytest.raises(CompositionVerificationError,match="checksum mismatch"):
        run_case(composition_case)


def test_rejects_missing_service_dependency(composition_case):
    descriptor = {
        "descriptor_version":"1.0.0","service_id":"worker","name":"Worker",
        "service_kind":"container","artifact":{"image":"ghcr.io/example/worker@sha256:"+"b"*64},
        "depends_on":["missing"],
    }
    record = write_service(composition_case,"worker",descriptor)
    record["resolution_order"] = 1
    composition_case["lock"]["services"] = [record]
    with pytest.raises(CompositionVerificationError,match="missing dependency"):
        run_case(composition_case)


def test_rejects_service_dependency_cycle(composition_case):
    first = {"descriptor_version":"1.0.0","service_id":"alpha","name":"Alpha","service_kind":"external","provider":{"name":"Provider","requirement":"Alpha"},"depends_on":["beta"]}
    second = {"descriptor_version":"1.0.0","service_id":"beta","name":"Beta","service_kind":"external","provider":{"name":"Provider","requirement":"Beta"},"depends_on":["alpha"]}
    a=write_service(composition_case,"alpha",first); b=write_service(composition_case,"beta",second)
    a["resolution_order"]=1; b["resolution_order"]=2
    composition_case["lock"]["external_requirements"]=[a,b]
    with pytest.raises(CompositionVerificationError,match="Circular"):
        run_case(composition_case)


def test_rejects_bench_service_identity_collision(composition_case):
    descriptor = {"descriptor_version":"1.0.0","service_id":"sample_app","name":"Collision","service_kind":"external","provider":{"name":"Provider","requirement":"Collision"}}
    record=write_service(composition_case,"sample_app",descriptor)
    record["resolution_order"]=1
    composition_case["lock"]["external_requirements"]=[record]
    with pytest.raises(CompositionVerificationError,match="collides"):
        run_case(composition_case)



def test_rejects_manifest_application_missing_from_lock(composition_case):
    path = composition_case["root"] / "images/ndf/manifests/products/sample.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["applications"].append({"name": "undeclared_in_lock", "required": True})
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\\n").encode()
    path.write_bytes(raw)
    composition_case["lock"]["manifests"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(CompositionVerificationError, match="absent from lock-v2"):
        run_case(composition_case)


def test_rejects_container_external_category_substitution(composition_case):
    descriptor = {
        "descriptor_version":"1.0.0","service_id":"worker","name":"Worker",
        "service_kind":"external","provider":{"name":"Provider","requirement":"Managed worker"},
    }
    record = write_service(composition_case, "worker", descriptor)
    record["resolution_order"] = 1
    composition_case["lock"]["services"] = [record]
    with pytest.raises(CompositionVerificationError, match="identity/category mismatch"):
        run_case(composition_case)


def test_rejects_duplicate_service_identity_across_categories(composition_case):
    descriptor = {
        "descriptor_version":"1.0.0","service_id":"shared","name":"Shared",
        "service_kind":"container","artifact":{"image":"ghcr.io/example/shared@sha256:"+"c"*64},
    }
    record = write_service(composition_case, "shared", descriptor)
    record["resolution_order"] = 1
    composition_case["lock"]["services"] = [record]
    composition_case["lock"]["external_requirements"] = [dict(record)]
    with pytest.raises(CompositionVerificationError, match="Duplicate/cross-category"):
        run_case(composition_case)
