import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from scripts import capture_source_provenance as provenance
from scripts.source_tree_fingerprint import fingerprint_tree


def git(command, cwd):
    return subprocess.run(
        ["git", *command],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def bench_fixture(tmp_path):
    bench = tmp_path / "frappe-bench"
    apps = bench / "apps"
    apps.mkdir(parents=True)
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
        git(["config", "user.name", "Provenance Test"], app_path)
        (app_path / "tracked.txt").write_text(name, encoding="utf-8")
        git(["add", "tracked.txt"], app_path)
        git(["commit", "-m", "initial"], app_path)
        git(["remote", "add", "upstream", remote], app_path)
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
    return bench, lock_path, apps


def test_capture_records_git_identity_and_source_fingerprints(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    output = tmp_path / "build-evidence" / "source-provenance.json"

    report = provenance.capture_source_provenance(bench, lock, output)

    assert report["schema_version"] == "1.0"
    assert report["algorithm"] == "ndf-source-provenance-v1"
    assert report["lock"]["sha256"] == hashlib.sha256(lock.read_bytes()).hexdigest()
    assert [item["name"] for item in report["repositories"]] == ["frappe", "erpnext"]

    frappe = report["repositories"][0]
    assert frappe["repository"] == "github.com/frappe/frappe"
    assert frappe["requested_ref"] == "version-16"
    assert frappe["resolver_commit"] == "a" * 40
    assert frappe["actual_commit"] == git(["rev-parse", "HEAD"], apps / "frappe")
    assert frappe["head_tree"] == git(["rev-parse", "HEAD^{tree}"], apps / "frappe")
    assert frappe["tracked_content"] == {
        "matches_head": True,
        "installation_modified_paths": [],
        "installation_diff_sha256": None,
    }
    assert frappe["generated_content"]["untracked_paths"] == []
    assert frappe["generated_content"]["ignored_paths"] == []
    assert frappe["source_tree"] == fingerprint_tree(apps / "frappe")
    assert json.loads(output.read_text(encoding="utf-8")) == report

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "source-provenance-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


def test_capture_classifies_modified_untracked_and_ignored_content(
    bench_fixture, tmp_path
):
    bench, lock, apps = bench_fixture
    frappe = apps / "frappe"
    (frappe / "tracked.txt").write_text("modified after clone", encoding="utf-8")
    (frappe / "generated-output.txt").write_text("generated", encoding="utf-8")
    (frappe / ".git" / "info" / "exclude").write_text(
        "ignored-output.cache\n", encoding="utf-8"
    )
    (frappe / "ignored-output.cache").write_text("ignored", encoding="utf-8")

    report = provenance.capture_source_provenance(
        bench, lock, tmp_path / "source-provenance.json"
    )
    record = report["repositories"][0]

    assert record["tracked_content"]["matches_head"] is False
    assert record["tracked_content"]["installation_modified_paths"] == ["tracked.txt"]
    assert len(record["tracked_content"]["installation_diff_sha256"]) == 64
    assert record["generated_content"]["untracked_paths"] == ["generated-output.txt"]
    assert record["generated_content"]["ignored_paths"] == ["ignored-output.cache"]


def test_capture_rejects_nested_git_metadata(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    nested = apps / "frappe" / "vendor" / "nested"
    (nested / ".git").mkdir(parents=True)

    with pytest.raises(
        provenance.SourceProvenanceError, match="Nested Git metadata"
    ):
        provenance.capture_source_provenance(
            bench, lock, tmp_path / "source-provenance.json"
        )


def test_capture_sanitizes_credentials_from_git_remotes(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    git(
        [
            "remote",
            "set-url",
            "upstream",
            "https://user:secret-token@github.com/frappe/frappe.git",
        ],
        apps / "frappe",
    )

    report = provenance.capture_source_provenance(
        bench, lock, tmp_path / "source-provenance.json"
    )

    serialized = json.dumps(report)
    assert report["repositories"][0]["repository"] == "github.com/frappe/frappe"
    assert "secret-token" not in serialized
    assert "user@" not in serialized


def test_capture_rejects_git_submodules(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    frappe = apps / "frappe"
    git(
        [
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{'a' * 40},vendor/child",
        ],
        frappe,
    )

    with pytest.raises(provenance.SourceProvenanceError, match="Git submodules"):
        provenance.capture_source_provenance(
            bench, lock, tmp_path / "source-provenance.json"
        )


def test_capture_rejects_unexpected_application_directory(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    (apps / "unexpected_app").mkdir()

    with pytest.raises(
        provenance.SourceProvenanceError, match="composition differs from lock-v2"
    ):
        provenance.capture_source_provenance(
            bench, lock, tmp_path / "source-provenance.json"
        )


def test_capture_rejects_missing_git_metadata(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    (apps / "frappe" / ".git").rename(apps / "frappe" / ".git.saved")

    with pytest.raises(
        provenance.SourceProvenanceError, match="Git metadata is missing"
    ):
        provenance.capture_source_provenance(
            bench, lock, tmp_path / "source-provenance.json"
        )
