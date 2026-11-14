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


def create_repository(path, filename, value):
    path.mkdir(parents=True)
    git(["init", "-b", "main"], path)
    git(["config", "user.email", "test@example.invalid"], path)
    git(["config", "user.name", "Provenance Test"], path)
    (path / filename).write_text(value, encoding="utf-8")
    git(["add", filename], path)
    git(["commit", "-m", "initial"], path)
    return path


def add_submodule(parent, source, relative_path, canonical_url):
    git(
        [
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            str(source),
            relative_path,
        ],
        parent,
    )
    config_path = parent / ".gitmodules"
    config = config_path.read_text(encoding="utf-8")
    config = config.replace(str(source), canonical_url)
    config_path.write_text(config, encoding="utf-8")
    child = parent / relative_path
    git(["remote", "set-url", "origin", canonical_url], child)
    git(["add", ".gitmodules", relative_path], parent)
    git(["commit", "-m", f"add {relative_path} submodule"], parent)
    return child, git(["rev-parse", "HEAD"], child)


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
        app_path = create_repository(apps / name, "tracked.txt", name)
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
    assert frappe["submodules"] == []
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


def test_capture_rejects_undeclared_gitlink(bench_fixture, tmp_path):
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

    with pytest.raises(provenance.SourceProvenanceError, match="gitlinks differ"):
        provenance.capture_source_provenance(
            bench, lock, tmp_path / "source-provenance.json"
        )


def test_capture_records_initialized_submodule_and_fingerprints_its_files(
    bench_fixture, tmp_path
):
    bench, lock, apps = bench_fixture
    frappe = apps / "frappe"
    source = create_repository(
        tmp_path / "frappe-ui-source", "ui-package.json", '{"name":"frappe-ui"}'
    )
    child, pinned_commit = add_submodule(
        frappe,
        source,
        "frappe-ui",
        "https://github.com/frappe/frappe-ui.git",
    )

    report = provenance.capture_source_provenance(
        bench, lock, tmp_path / "source-provenance.json"
    )
    record = report["repositories"][0]
    submodule = record["submodules"][0]

    assert submodule["path"] == "frappe-ui"
    assert submodule["repository"] == "github.com/frappe/frappe-ui"
    assert submodule["expected_commit"] == pinned_commit
    assert submodule["actual_commit"] == pinned_commit
    assert submodule["source_tree"] == fingerprint_tree(child)
    # Parent tree includes tracked.txt, .gitmodules and the submodule file.
    # The submodule contents are also fingerprinted independently above.
    assert record["source_tree"]["file_count"] == 3
    assert record["source_tree"]["directory_count"] == 1
    assert record["source_tree"] == fingerprint_tree(frappe)
    assert submodule["source_tree"]["sha256"] != record["source_tree"]["sha256"]

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "source-provenance-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)


def test_capture_recursively_verifies_nested_submodules(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    frappe = apps / "frappe"
    nested_source = create_repository(
        tmp_path / "nested-ui-source", "nested.txt", "nested source"
    )
    frappe_ui_source = create_repository(
        tmp_path / "frappe-ui-source", "ui.txt", "frappe ui source"
    )

    nested_url = "https://github.com/frappe/nested-ui.git"
    nested_path = frappe_ui_source / "nested"
    nested_path.mkdir()
    subprocess.run(
        ["git", "clone", str(nested_source), str(nested_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    git(["remote", "set-url", "origin", nested_url], nested_path)
    nested_commit = git(["rev-parse", "HEAD"], nested_path)
    (frappe_ui_source / ".gitmodules").write_text(
        '[submodule "nested"]\n' f"\tpath = nested\n\turl = {nested_url}\n",
        encoding="utf-8",
    )
    git(
        [
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{nested_commit},nested",
        ],
        frappe_ui_source,
    )
    git(["add", ".gitmodules"], frappe_ui_source)
    git(["commit", "-m", "record nested submodule"], frappe_ui_source)

    child, _ = add_submodule(
        frappe,
        frappe_ui_source,
        "frappe-ui",
        "https://github.com/frappe/frappe-ui.git",
    )
    nested_checkout = child / "nested"
    if not nested_checkout.exists():
        nested_checkout.mkdir()
    subprocess.run(
        ["git", "clone", str(nested_source), str(nested_checkout)],
        check=True,
        capture_output=True,
        text=True,
    )
    git(["remote", "set-url", "origin", nested_url], nested_checkout)

    report = provenance.capture_source_provenance(
        bench, lock, tmp_path / "source-provenance.json"
    )
    nested_record = report["repositories"][0]["submodules"][0]["submodules"][0]

    assert nested_record["path"] == "nested"
    assert nested_record["repository"] == "github.com/frappe/nested-ui"
    assert nested_record["expected_commit"] == nested_commit
    assert nested_record["actual_commit"] == nested_commit
    assert nested_record["materialized"] is True

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "source-provenance-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)


def test_capture_rejects_submodule_commit_mismatch(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    frappe = apps / "frappe"
    source = create_repository(tmp_path / "frappe-ui-source", "ui.txt", "first")
    child, pinned_commit = add_submodule(
        frappe,
        source,
        "frappe-ui",
        "https://github.com/frappe/frappe-ui.git",
    )
    (child / "ui.txt").write_text("second", encoding="utf-8")
    git(["commit", "-am", "advance submodule"], child)

    assert git(["rev-parse", "HEAD"], child) != pinned_commit
    with pytest.raises(provenance.SourceProvenanceError, match="commit mismatch"):
        provenance.capture_source_provenance(
            bench, lock, tmp_path / "source-provenance.json"
        )


def test_capture_records_uninitialized_submodule_as_gitlink_metadata(
    bench_fixture, tmp_path
):
    bench, lock, apps = bench_fixture
    frappe = apps / "frappe"
    source = create_repository(tmp_path / "frappe-ui-source", "ui.txt", "content")
    _, pinned_commit = add_submodule(
        frappe,
        source,
        "frappe-ui",
        "https://github.com/frappe/frappe-ui.git",
    )
    git(["submodule", "deinit", "-f", "--", "frappe-ui"], frappe)

    report = provenance.capture_source_provenance(
        bench, lock, tmp_path / "source-provenance.json"
    )
    submodule = report["repositories"][0]["submodules"][0]

    assert submodule == {
        "path": "frappe-ui",
        "repository": "github.com/frappe/frappe-ui",
        "expected_commit": pinned_commit,
        "materialized": False,
        "actual_commit": None,
        "head_tree": None,
        "tracked_content": None,
        "generated_content": None,
        "source_tree": None,
        "submodules": [],
    }
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "source-provenance-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)


def test_capture_rejects_uninitialized_submodule_with_unexpected_files(
    bench_fixture, tmp_path
):
    bench, lock, apps = bench_fixture
    frappe = apps / "frappe"
    source = create_repository(tmp_path / "frappe-ui-source", "ui.txt", "content")
    child, _ = add_submodule(
        frappe,
        source,
        "frappe-ui",
        "https://github.com/frappe/frappe-ui.git",
    )
    git(["submodule", "deinit", "-f", "--", "frappe-ui"], frappe)
    submodule_path = frappe / "frappe-ui"
    submodule_path.mkdir(exist_ok=True)
    (submodule_path / "unexpected.txt").write_text("untracked", encoding="utf-8")

    with pytest.raises(provenance.SourceProvenanceError, match="unexpected files"):
        provenance.capture_source_provenance(
            bench, lock, tmp_path / "source-provenance.json"
        )


def test_capture_rejects_nested_git_metadata(bench_fixture, tmp_path):
    bench, lock, apps = bench_fixture
    nested = apps / "frappe" / "vendor" / "nested"
    (nested / ".git").mkdir(parents=True)

    with pytest.raises(provenance.SourceProvenanceError, match="Nested Git metadata"):
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
