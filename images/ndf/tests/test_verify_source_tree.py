from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from scripts import verify_source_tree as verification
from scripts.source_tree_fingerprint import fingerprint_tree


def git(command: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *command], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(path: Path, name: str) -> Path:
    path.mkdir(parents=True)
    git(["init", "-b", "main"], path)
    git(["config", "user.email", "test@example.invalid"], path)
    git(["config", "user.name", "Verification Test"], path)
    (path / "source.txt").write_text(name, encoding="utf-8")
    git(["add", "source.txt"], path)
    git(["commit", "-m", "initial"], path)
    return path


@pytest.fixture
def source_fixture(tmp_path: Path):
    bench = tmp_path / "frappe-bench"
    apps = bench / "apps"
    apps.mkdir(parents=True)
    app = make_repo(apps / "frappe", "frappe")
    git(["remote", "add", "upstream", "https://github.com/frappe/frappe.git"], app)
    lock = {"version": 2, "sha256": "a" * 64}
    provenance = {
        "schema_version": "1.0",
        "algorithm": "ndf-source-provenance-v1",
        "lock": lock,
        "repositories": [
            {
                "name": "frappe",
                "source_tree": fingerprint_tree(app),
                "submodules": [],
            }
        ],
    }
    provenance_path = tmp_path / "source-provenance.json"
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    return bench, provenance_path, app, tmp_path


def test_verification_accepts_unchanged_tree_after_git_cleanup(source_fixture):
    bench, provenance_path, app, root = source_fixture
    import shutil

    shutil.rmtree(app / ".git")
    output = root / "post-cleanup.json"
    report = verification.verify_source_trees(
        bench, provenance_path, "post_cleanup", output
    )
    assert report["status"] == "passed"
    assert report["repositories"][0]["matches"] is True
    assert (
        report["repositories"][0]["observed_source_tree"]
        == report["repositories"][0]["expected_source_tree"]
    )
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_verification_rejects_changed_source_after_cleanup(source_fixture):
    bench, provenance_path, app, root = source_fixture
    (app / "source.txt").write_text("tampered", encoding="utf-8")
    with pytest.raises(
        verification.SourceTreeVerificationError, match="fingerprint mismatch"
    ):
        verification.verify_source_trees(
            bench, provenance_path, "post_cleanup", root / "failed.json"
        )


def test_verification_rejects_unexpected_application_directory(source_fixture):
    bench, provenance_path, app, root = source_fixture
    (bench / "apps" / "unexpected").mkdir()
    with pytest.raises(
        verification.SourceTreeVerificationError, match="directories differ"
    ):
        verification.verify_source_trees(
            bench, provenance_path, "runtime_image", root / "failed.json"
        )


def test_verification_rejects_unsafe_application_name(source_fixture):
    bench, provenance_path, app, root = source_fixture
    data = json.loads(provenance_path.read_text(encoding="utf-8"))
    data["repositories"][0]["name"] = "../escape"
    provenance_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(
        verification.SourceTreeVerificationError, match="Unsafe application name"
    ):
        verification.verify_source_trees(
            bench, provenance_path, "post_cleanup", root / "failed.json"
        )


def test_verification_rejects_invalid_stage(source_fixture):
    bench, provenance_path, app, root = source_fixture
    with pytest.raises(
        verification.SourceTreeVerificationError, match="Unsupported verification stage"
    ):
        verification.verify_source_trees(
            bench, provenance_path, "builder", root / "failed.json"
        )


def test_verification_schema_accepts_stage_report(source_fixture):
    bench, provenance_path, app, root = source_fixture
    report = verification.verify_source_trees(
        bench, provenance_path, "post_cleanup", root / "post-cleanup.json"
    )
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "source-tree-verification-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)
