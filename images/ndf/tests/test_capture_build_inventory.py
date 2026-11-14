import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from scripts import capture_build_inventory as capture


def git(command, cwd):
    return subprocess.run(
        ["git", *command],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def bench_fixture(tmp_path, monkeypatch):
    bench = tmp_path / "frappe-bench"
    apps = bench / "apps"
    apps.mkdir(parents=True)
    (bench / "env").mkdir()
    monkeypatch.setattr(capture.sys, "prefix", str(bench / "env"))
    definitions = [
        ("frappe", "https://github.com/frappe/frappe.git", 1),
        ("erpnext", "https://github.com/frappe/erpnext.git", 2),
    ]
    locked = []
    for name, remote, order in definitions:
        app_path = apps / name
        app_path.mkdir()
        git(["init", "-b", "main"], app_path)
        git(["config", "user.email", "test@example.invalid"], app_path)
        git(["config", "user.name", "Inventory Test"], app_path)
        (app_path / "tracked.txt").write_text(name, encoding="utf-8")
        git(["add", "tracked.txt"], app_path)
        git(["commit", "-m", "initial"], app_path)
        git(["remote", "add", "origin", remote], app_path)
        locked.append(
            {
                "name": name,
                "repository": remote,
                "target_ref": "version-16",
                "ref": "a" * 40,
                "installation_order": order,
            }
        )

    lock_path = tmp_path / "product.lock-v2.json"
    lock_path.write_text(
        json.dumps({"lock_version": 2, "applications": locked}, indent=2) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        capture,
        "capture_runtime",
        lambda: {
            "python": {
                "executable": "/usr/bin/python3",
                "environment": str(bench / "env"),
                "version": "3.14.3",
                "implementation": "CPython",
            },
            "node": {"version": "v24.21.0"},
            "yarn": {"version": "1.22.22"},
            "bench": {"version": "5.31.1"},
            "platform": {"system": "Linux", "machine": "x86_64", "oci": "linux/amd64"},
        },
    )
    monkeypatch.setattr(
        capture,
        "capture_python_packages",
        lambda: [{"name": "example-python", "version": "1.2.3"}],
    )
    monkeypatch.setattr(
        capture,
        "capture_node_packages",
        lambda *_: [
            {
                "path": "apps/frappe/node_modules/example",
                "name": "example",
                "version": "2.0.0",
            }
        ],
    )
    monkeypatch.setattr(
        capture,
        "capture_dpkg_packages",
        lambda: [{"name": "bash", "version": "5.2", "architecture": "amd64"}],
    )
    monkeypatch.setattr(
        capture,
        "capture_installers",
        lambda: {"uv": {"version": "0.13.7"}, "pip": {"version": "25.0"}},
    )
    return bench, lock_path, apps


def test_capture_records_actual_git_heads_and_lock_refs(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    output = tmp_path / "evidence" / "build-inventory.json"

    report = capture.capture_inventory(bench, lock, output)

    assert report["schema_version"] == "1.0"
    assert report["lock"]["version"] == 2
    assert report["framework"]["name"] == "frappe"
    assert report["framework"]["requested_ref"] == "version-16"
    assert report["framework"]["actual_commit"] == git(
        ["rev-parse", "HEAD"], apps / "frappe"
    )
    assert report["applications"][1]["name"] == "erpnext"
    assert report["applications"][1]["resolver_commit"] == "a" * 40
    assert json.loads(output.read_text(encoding="utf-8")) == report

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "build-inventory-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


def test_capture_rejects_unexpected_application_directory(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    (apps / "unlocked_app").mkdir()

    with pytest.raises(
        capture.InventoryCaptureError, match="composition differs from lock-v2"
    ):
        capture.capture_inventory(bench, lock, tmp_path / "inventory.json")


def test_capture_accepts_matching_non_origin_remote(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    git(["remote", "rename", "origin", "upstream"], apps / "erpnext")

    report = capture.capture_inventory(bench, lock, tmp_path / "inventory.json")

    assert report["applications"][1]["repository"] == "github.com/frappe/erpnext"


def test_capture_rejects_repository_identity_mismatch(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    git(
        ["remote", "set-url", "origin", "https://github.com/other/erpnext.git"],
        apps / "erpnext",
    )

    with pytest.raises(
        capture.InventoryCaptureError, match="Repository identity mismatch"
    ):
        capture.capture_inventory(bench, lock, tmp_path / "inventory.json")


def test_capture_rejects_repository_without_remotes(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    git(["remote", "remove", "origin"], apps / "frappe")

    with pytest.raises(
        capture.InventoryCaptureError, match="No Git remotes are configured"
    ):
        capture.capture_inventory(bench, lock, tmp_path / "inventory.json")


def test_capture_rejects_missing_git_metadata(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    shutil.rmtree(apps / "frappe" / ".git")

    with pytest.raises(capture.InventoryCaptureError, match="Git metadata is missing"):
        capture.capture_inventory(bench, lock, tmp_path / "inventory.json")


def test_capture_rejects_invalid_lock_version(bench_fixture, tmp_path):
    bench, lock, _ = bench_fixture
    lock.write_text(
        json.dumps({"lock_version": 1, "applications": []}), encoding="utf-8"
    )

    with pytest.raises(capture.InventoryCaptureError, match="lock-v2"):
        capture.capture_inventory(bench, lock, tmp_path / "inventory.json")


def test_dependency_file_hashes_are_captured(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    requirements = apps / "frappe" / "requirements.txt"
    requirements.write_text("sample-package==1.0\n", encoding="utf-8")

    report = capture.capture_inventory(bench, lock, tmp_path / "inventory.json")
    item = next(
        row
        for row in report["dependency_files"]
        if row["path"] == "apps/frappe/requirements.txt"
    )

    assert item["sha256"] == hashlib.sha256(requirements.read_bytes()).hexdigest()


def test_capture_sanitizes_credentials_from_git_remote(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    git(
        [
            "remote",
            "set-url",
            "origin",
            "https://user:secret-token@github.com/frappe/frappe.git",
        ],
        apps / "frappe",
    )

    report = capture.capture_inventory(bench, lock, tmp_path / "inventory.json")
    repository = report["framework"]["repository"]

    assert repository == "github.com/frappe/frappe"
    assert "secret-token" not in json.dumps(report)
    assert "user@" not in json.dumps(report)


def test_capture_serialization_is_deterministic(bench_fixture, tmp_path):
    bench, lock, _ = bench_fixture
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    capture.capture_inventory(bench, lock, first)
    capture.capture_inventory(bench, lock, second)

    assert first.read_bytes() == second.read_bytes()
