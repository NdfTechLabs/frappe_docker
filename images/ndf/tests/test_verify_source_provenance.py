from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from scripts import capture_source_provenance as capture
from scripts import verify_source_provenance as verification


def git(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(path: Path, filename: str = "tracked.txt", content: str = "initial") -> Path:
    path.mkdir(parents=True)
    git(["init", "-b", "main"], path)
    git(["config", "user.email", "verification@example.invalid"], path)
    git(["config", "user.name", "NDF Verification Test"], path)
    (path / filename).write_text(content, encoding="utf-8")
    git(["add", filename], path)
    git(["commit", "-m", "initial"], path)
    return path


def make_fixture(tmp_path: Path):
    bench = tmp_path / "frappe-bench"
    apps = bench / "apps"
    apps.mkdir(parents=True)
    app = make_repo(apps / "frappe")
    git(["remote", "add", "origin", "https://github.com/frappe/frappe.git"], app)
    lock = {
        "lock_version": 2,
        "applications": [
            {
                "name": "frappe",
                "repository": "https://github.com/frappe/frappe.git",
                "target_ref": "version-16",
                # Resolver observation is intentionally not required to equal Bench's HEAD.
                "ref": "a" * 40,
                "installation_order": 1,
            }
        ],
    }
    lock_path = tmp_path / "build-lock-v2.json"
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    provenance_path = tmp_path / "source-provenance.json"
    capture.capture_source_provenance(bench, lock_path, provenance_path)
    return bench, lock_path, provenance_path, app


def run_verifier(bench: Path, lock: Path, provenance: Path, output: Path):
    return verification.verify_source_provenance(bench, lock, provenance, output)


def add_submodule(parent: Path, source: Path, path: str, url: str) -> tuple[Path, str]:
    subprocess.run(
        ["git", "-c", "protocol.file.allow=always", "submodule", "add", str(source), path],
        cwd=parent,
        check=True,
        capture_output=True,
        text=True,
    )
    child = parent / path
    git(["config", "user.email", "verification@example.invalid"], child)
    git(["config", "user.name", "NDF Verification Test"], child)
    git(["remote", "set-url", "origin", url], child)
    modules = parent / ".gitmodules"
    text = modules.read_text(encoding="utf-8").replace(str(source), url)
    modules.write_text(text, encoding="utf-8")
    git(["add", ".gitmodules", path], parent)
    git(["commit", "-m", "add submodule"], parent)
    return child, git(["rev-parse", "HEAD"], child)


def test_verifies_source_provenance_and_emits_schema_valid_report(tmp_path):
    bench, lock, provenance, _ = make_fixture(tmp_path)
    output = tmp_path / "build-evidence" / "source-provenance-verification.json"

    report = run_verifier(bench, lock, provenance, output)

    assert report["status"] == "passed"
    assert report["repositories"][0]["status"] == "verified"
    assert report["repositories"][0]["actual_commit"] != report["repositories"][0]["resolver_commit"]
    assert json.loads(output.read_text(encoding="utf-8")) == report
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "source-provenance-verification-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


def test_rejects_lock_digest_mismatch(tmp_path):
    bench, lock, provenance, _ = make_fixture(tmp_path)
    lock.write_text(lock.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="lock SHA-256"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unexpected"])
def test_rejects_repository_composition_mismatch(tmp_path, mutation):
    bench, lock, provenance, _ = make_fixture(tmp_path)
    data = json.loads(provenance.read_text(encoding="utf-8"))
    if mutation == "missing":
        data["repositories"] = []
    elif mutation == "duplicate":
        data["repositories"].append(dict(data["repositories"][0]))
    else:
        extra = dict(data["repositories"][0])
        extra["name"] = "extra"
        data["repositories"].append(extra)
    provenance.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="repository"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_rejects_wrong_remote_identity(tmp_path):
    bench, lock, provenance, app = make_fixture(tmp_path)
    git(["remote", "set-url", "origin", "https://github.com/other/frappe.git"], app)
    with pytest.raises(verification.SourceProvenanceVerificationError, match="identity mismatch"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_rejects_actual_head_mismatch(tmp_path):
    bench, lock, provenance, _ = make_fixture(tmp_path)
    data = json.loads(provenance.read_text(encoding="utf-8"))
    data["repositories"][0]["actual_commit"] = "b" * 40
    provenance.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="HEAD mismatch"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_rejects_head_tree_mismatch(tmp_path):
    bench, lock, provenance, _ = make_fixture(tmp_path)
    data = json.loads(provenance.read_text(encoding="utf-8"))
    data["repositories"][0]["head_tree"] = "b" * 40
    provenance.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="HEAD tree mismatch"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_recomputes_tracked_modification_paths_and_binary_diff(tmp_path):
    bench, lock, provenance, app = make_fixture(tmp_path)
    (app / "tracked.txt").write_text("changed after capture", encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="Tracked-content evidence mismatch"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_rejects_tampered_binary_diff_digest(tmp_path):
    bench, lock, provenance, _ = make_fixture(tmp_path)
    data = json.loads(provenance.read_text(encoding="utf-8"))
    tracked = data["repositories"][0]["tracked_content"]
    tracked["matches_head"] = False
    tracked["installation_modified_paths"] = ["tracked.txt"]
    tracked["installation_diff_sha256"] = hashlib.sha256(b"forged").hexdigest()
    provenance.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="Tracked-content evidence mismatch"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_recomputes_untracked_and_ignored_path_classification(tmp_path):
    bench, lock, provenance, app = make_fixture(tmp_path)
    (app / "generated.txt").write_text("generated", encoding="utf-8")
    (app / ".git" / "info" / "exclude").write_text("ignored.cache\n", encoding="utf-8")
    (app / "ignored.cache").write_text("ignored", encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="Generated/untracked/ignored"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_rejects_malformed_provenance_contract(tmp_path):
    bench, lock, provenance, _ = make_fixture(tmp_path)
    data = json.loads(provenance.read_text(encoding="utf-8"))
    data["lock"]["sha256"] = "not-a-digest"
    provenance.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="invalid lock identity"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_verifies_materialized_submodule_recursively(tmp_path):
    bench, lock, provenance, app = make_fixture(tmp_path)
    source = make_repo(tmp_path / "submodule-source", "child.txt", "child")
    child, pinned = add_submodule(
        app, source, "vendor/child", "https://github.com/frappe/child.git"
    )
    # Refresh the capture after adding the committed submodule declaration.
    capture.capture_source_provenance(bench, lock, provenance)
    report = run_verifier(bench, lock, provenance, tmp_path / "out.json")
    item = report["repositories"][0]["submodules"][0]
    assert item["path"] == "vendor/child"
    assert item["materialized"] is True
    assert item["expected_commit"] == pinned
    assert item["actual_commit"] == pinned
    assert item["status"] == "verified"


def test_verifies_uninitialized_submodule_as_metadata_only(tmp_path):
    bench, lock, provenance, app = make_fixture(tmp_path)
    source = make_repo(tmp_path / "submodule-source", "child.txt", "child")
    _, pinned = add_submodule(
        app, source, "vendor/child", "https://github.com/frappe/child.git"
    )
    subprocess.run(
        ["git", "submodule", "deinit", "-f", "--", "vendor/child"],
        cwd=app,
        check=True,
        capture_output=True,
        text=True,
    )
    capture.capture_source_provenance(bench, lock, provenance)
    report = run_verifier(bench, lock, provenance, tmp_path / "out.json")
    assert report["repositories"][0]["submodules"] == [
        {
            "path": "vendor/child",
            "materialized": False,
            "expected_commit": pinned,
            "status": "metadata_only",
        }
    ]


def test_rejects_materialized_submodule_commit_mismatch(tmp_path):
    bench, lock, provenance, app = make_fixture(tmp_path)
    source = make_repo(tmp_path / "submodule-source", "child.txt", "child")
    child, pinned = add_submodule(
        app, source, "vendor/child", "https://github.com/frappe/child.git"
    )
    capture.capture_source_provenance(bench, lock, provenance)
    (child / "child.txt").write_text("advanced", encoding="utf-8")
    git(["add", "child.txt"], child)
    git(["commit", "-m", "advance submodule"], child)
    assert git(["rev-parse", "HEAD"], child) != pinned
    with pytest.raises(verification.SourceProvenanceVerificationError, match="Submodule commit mismatch"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")


def test_rejects_uninitialized_submodule_claiming_materialized_evidence(tmp_path):
    bench, lock, provenance, app = make_fixture(tmp_path)
    source = make_repo(tmp_path / "submodule-source", "child.txt", "child")
    _, _ = add_submodule(
        app, source, "vendor/child", "https://github.com/frappe/child.git"
    )
    subprocess.run(
        ["git", "submodule", "deinit", "-f", "--", "vendor/child"],
        cwd=app,
        check=True,
        capture_output=True,
        text=True,
    )
    capture.capture_source_provenance(bench, lock, provenance)
    data = json.loads(provenance.read_text(encoding="utf-8"))
    data["repositories"][0]["submodules"][0]["materialized"] = True
    provenance.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(verification.SourceProvenanceVerificationError, match="materialization mismatch"):
        run_verifier(bench, lock, provenance, tmp_path / "out.json")
