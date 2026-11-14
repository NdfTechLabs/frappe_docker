import base64
import hashlib
import json
from unittest.mock import patch

import pytest
from scripts.validate_image import (
    ImageValidationError,
    inspect_image_contents,
    validate_image,
)


@pytest.fixture
def validation_inputs():
    digest = "sha256:" + "f" * 64
    lock_sha = "b" * 64
    applications = [
        {"name": "frappe", "target_ref": "version-16", "resolved_sha": "a" * 40,
         "repository": "https://github.com/frappe/frappe"},
        {"name": "erpnext", "target_ref": "version-16", "resolved_sha": "c" * 40,
         "repository": "https://github.com/frappe/erpnext"},
    ]
    metadata = {
        "image": {"id": "dalali-v16", "product": "dalali",
                  "manifest": "products/tenant/dalali-v16.json",
                  "repository": "ghcr.io/ndftechlabs/dalali"},
        "framework": {"name": "frappe", "version": "16", "target_ref": "version-16"},
        "lock": {"sha256": lock_sha},
        "base_images": {"platform": "linux/amd64"},
        "applications": applications,
    }
    lock_apps = [
        {"name": app["name"], "repository": app["repository"],
         "target_ref": app["target_ref"], "ref": app["resolved_sha"]}
        for app in applications
    ]
    lock = {
        "lock_version": 2,
        "applications": lock_apps,
        "manifests": [{"path": "products/tenant/dalali-v16.json", "sha256": "e" * 64}],
    }
    labels = {
        "org.opencontainers.image.title": "dalali",
        "org.opencontainers.image.source": "https://github.com/NdfTechLabs/frappe_docker",
        "org.opencontainers.image.url": "https://github.com/NdfTechLabs/frappe_docker",
        "com.ndf.image.id": "dalali-v16",
        "com.ndf.product": "dalali",
        "com.ndf.manifest.path": "products/tenant/dalali-v16.json",
        "com.ndf.manifest.sha256": "e" * 64,
        "com.ndf.framework.name": "frappe",
        "com.ndf.framework.version": "16",
        "com.ndf.framework.target-ref": "version-16",
        "com.ndf.lock.sha256": lock_sha,
        "com.ndf.applications": json.dumps([
            {"name": app["name"], "target_ref": app["target_ref"],
             "resolved_sha": app["resolved_sha"]} for app in applications
        ]),
    }
    captured = [
        {"name": app["name"], "repository": f"github.com/frappe/{app['name']}",
         "requested_ref": app["target_ref"], "resolver_commit": app["resolved_sha"],
         "actual_commit": "d" * 40}
        for app in applications
    ]
    inventory = {
        "schema_version": "1.0", "stage": "builder",
        "lock": {"version": 2, "sha256": lock_sha},
        "framework": captured[0], "applications": captured,
        "runtime": {
            "python": {"executable": "/bench/env/bin/python", "environment": "/bench/env",
                       "version": "3.14.10", "implementation": "CPython"},
            "node": {"version": "v24.21.0"}, "yarn": {"version": "1.22.22"},
            "bench": {"version": "5.31.1"},
            "platform": {"system": "Linux", "machine": "x86_64", "oci": "linux/amd64"},
        },
        "installed_packages": {"python": [], "node": [], "debian": []},
        "dependency_files": [],
        "installers": {"uv": {"version": "0.13.7"}, "pip": {"version": "25.0"}},
    }
    raw = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()
    contents = {
        "directories": ["frappe", "erpnext"],
        "apps_txt": ["frappe", "erpnext"],
        "build_inventory": inventory,
        "build_inventory_bytes": raw,
    }
    return metadata, lock, labels, contents, lock_sha, digest


def run_validation(inputs):
    metadata, lock, labels, contents, lock_sha, digest = inputs
    return validate_image("local/dalali:test", metadata, lock, labels, contents, lock_sha, digest)


def test_validate_image_accepts_contents_labels_and_digest_bound_inventory(validation_inputs):
    report = run_validation(validation_inputs)
    assert report["status"] == "passed"
    assert report["application_count"] == 2
    assert report["inventory_verified"] is True
    binding = report["evidence_binding"]
    assert binding["image_digest"] == validation_inputs[5]
    assert binding["inventory_sha256"] == hashlib.sha256(
        validation_inputs[3]["build_inventory_bytes"]
    ).hexdigest()
    assert binding["lock_sha256"] == validation_inputs[4]
    assert binding["status"] == "bound"


def test_validate_image_rejects_missing_application_directory(validation_inputs):
    validation_inputs[3]["directories"].remove("erpnext")
    with pytest.raises(ImageValidationError, match="Application directory mismatch"):
        run_validation(validation_inputs)


def test_validate_image_rejects_unexpected_application_in_apps_txt(validation_inputs):
    validation_inputs[3]["apps_txt"].append("unlisted_app")
    with pytest.raises(ImageValidationError, match="sites/apps.txt mismatch"):
        run_validation(validation_inputs)


def test_validate_image_rejects_mismatched_oci_label(validation_inputs):
    validation_inputs[2]["org.opencontainers.image.url"] = "https://github.com/frappe/frappe_docker"
    with pytest.raises(ImageValidationError, match="org.opencontainers.image.url"):
        run_validation(validation_inputs)


def test_validate_image_rejects_mismatched_application_label(validation_inputs):
    validation_inputs[2]["com.ndf.applications"] = "[]"
    with pytest.raises(ImageValidationError, match="com.ndf.applications"):
        run_validation(validation_inputs)


def test_validate_image_rejects_duplicate_expected_applications(validation_inputs):
    validation_inputs[0]["applications"].append(validation_inputs[0]["applications"][0])
    with pytest.raises(ImageValidationError, match="duplicate application"):
        run_validation(validation_inputs)


def test_validate_image_rejects_missing_inventory(validation_inputs):
    validation_inputs[3].pop("build_inventory_bytes")
    with pytest.raises(ImageValidationError, match="does not contain build-inventory"):
        run_validation(validation_inputs)


def test_validate_image_rejects_malformed_inventory(validation_inputs):
    validation_inputs[3]["build_inventory"]["runtime"]["platform"]["oci"] = "windows/amd64"
    with pytest.raises(ImageValidationError, match="schema validation"):
        run_validation(validation_inputs)


def test_validate_image_rejects_inventory_lock_mismatch(validation_inputs):
    validation_inputs[3]["build_inventory"]["lock"]["sha256"] = "0" * 64
    with pytest.raises(ImageValidationError, match="lock identity"):
        run_validation(validation_inputs)


def test_validate_image_rejects_repository_identity_mismatch(validation_inputs):
    validation_inputs[3]["build_inventory"]["applications"][1]["repository"] = "github.com/other/erpnext"
    with pytest.raises(ImageValidationError, match="repository identity mismatch"):
        run_validation(validation_inputs)


def test_inspect_image_contents_extracts_exact_inventory_bytes():
    raw = json.dumps({"schema_version": "1.0"}).encode()
    response = json.dumps({
        "directories": ["frappe", "erpnext"],
        "apps_txt": ["frappe", "erpnext"],
        "build_inventory_base64": base64.b64encode(raw).decode(),
    })

    class Result:
        returncode = 0
        stdout = response
        stderr = ""

    with patch("scripts.validate_image.subprocess.run", return_value=Result()) as run:
        result = inspect_image_contents("local/dalali:test")

    assert result["build_inventory"] == {"schema_version": "1.0"}
    assert result["build_inventory_bytes"] == raw
    command = run.call_args.args[0]
    assert command[:4] == ["docker", "run", "--rm", "--entrypoint"]
    assert "local/dalali:test" in command
