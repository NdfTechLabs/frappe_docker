import hashlib
import json
import shutil
from pathlib import Path

import pytest
from scripts.adapt_candidate_to_lock import (
    CandidateCompositionError,
    adapt_candidate_to_lock,
)
from scripts.resolve_manifest import ManifestLoader


@pytest.fixture
def ndf_dir(tmp_path):
    source = Path(__file__).resolve().parents[1]
    target = tmp_path / "images" / "ndf"
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(
            ".build", "__pycache__", ".pytest_cache", "locks"
        ),
    )
    return target


def make_candidate(ndf_dir):
    """Build a complete candidate from the real Dalali manifest composition."""
    manifests_dir = ndf_dir / "manifests"
    loader = ManifestLoader(manifests_dir)
    manifest = loader.load("products/tenant/dalali-v16.json")
    applications = loader.resolve_install_order(loader.compose_applications(manifest))

    candidate_apps = []
    for index, app in enumerate(applications, start=1):
        app_id = app.get("_app_id") or app["name"]
        descriptor = app.get("_descriptor") or {}
        descriptor_name = descriptor.get("name", app["name"])
        candidate_apps.append(
            {
                "app_id": app_id,
                "app_name": descriptor_name,
                "release_version": app.get("_release_version") or "16.0.0",
                "descriptor_ref": (
                    "ghcr.io/ndftechlabs/marketplace-app-descriptors@sha256:"
                    + f"{index:064x}"
                ),
                "descriptor_digest": f"{index:064x}",
                "app_source_type": "git",
                "app_source": app["repository"],
                "requested_version": app["target_ref"],
                "immutable_commit": f"{index:040x}",
                "is_required": True,
                "change_action": "install",
            }
        )

    candidate = {
        "schema_version": "1.0.0",
        "candidate_id": "CAND-TEST-0001",
        "candidate_code": "dalali-v16-adapter-test",
        "candidate_type": "product",
        "product": {"id": "dalali", "release": "16.0.0"},
        "framework_version": "16",
        "base_deployment": None,
        "composition_hash": "a" * 64,
        "applications": candidate_apps,
        "optional_capabilities": [],
        "runtime_profile": {"python": "3.14.3", "node": "24.22.2"},
        "runtime_constraints": {
            "python": {"minimum_version": "3.14"},
            "node": {"minimum_version": "24"},
        },
        "target_platforms": ["linux/amd64"],
        "approved_build_parameters": {
            "build_profile": "production",
            "build_options": {"assets": True},
        },
        "provenance_refs": [],
    }
    return candidate


def write_candidate(tmp_path, candidate):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "candidate.json"
    path.write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def run_adapter(ndf_dir, tmp_path, candidate):
    candidate_path = write_candidate(tmp_path, candidate)
    payload_sha = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    return adapt_candidate_to_lock(
        ndf_dir=ndf_dir,
        candidate_path=candidate_path,
        output_dir=tmp_path / "output",
        candidate_artifact_ref=(
            "ghcr.io/ndftechlabs/dt-master-deployment-candidates@sha256:"
            + "b" * 64
        ),
        payload_sha256=payload_sha,
    )


def test_candidate_adapter_generates_deterministic_lock_v2(ndf_dir, tmp_path):
    candidate = make_candidate(ndf_dir)
    first = run_adapter(ndf_dir, tmp_path / "first", candidate)
    second = run_adapter(ndf_dir, tmp_path / "second", candidate)

    first_lock = first["lock_path"].read_bytes()
    second_lock = second["lock_path"].read_bytes()
    assert first_lock == second_lock
    assert first["lock_sha256"] == hashlib.sha256(first_lock).hexdigest()

    lock = json.loads(first_lock)
    assert lock["lock_version"] == 2
    assert lock["candidate"]["candidate_id"] == candidate["candidate_id"]
    assert lock["candidate"]["composition_hash"] == candidate["composition_hash"]
    assert all(
        item["ref"] == item["target_ref"]
        and item["reference_kind"] == "commit"
        and item["resolved_ref"] == item["target_ref"]
        for item in lock["applications"]
    )

    apps_json = json.loads(first["apps_json_path"].read_text(encoding="utf-8"))
    expected_commits = {
        item["immutable_commit"]
        for item in candidate["applications"]
        if item["app_id"] != "frappe"
    }
    assert {item["branch"] for item in apps_json} == expected_commits


def test_candidate_adapter_never_resolves_rolling_git_refs(
    ndf_dir, tmp_path, monkeypatch
):
    def verify_commit(_loader, _repository, target_ref):
        assert len(target_ref) == 40
        assert all(character in "0123456789abcdef" for character in target_ref)
        return {"sha": target_ref, "kind": "commit", "name": target_ref}

    monkeypatch.setattr(ManifestLoader, "resolve_git_ref", verify_commit)
    candidate = make_candidate(ndf_dir)
    run_adapter(ndf_dir, tmp_path, candidate)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda candidate: candidate["applications"].pop(),
            "application set does not equal",
        ),
        (
            lambda candidate: candidate["applications"].append(
                dict(candidate["applications"][0], app_id="unexpected")
            ),
            "application set does not equal",
        ),
        (
            lambda candidate: candidate["applications"][0].update(
                app_source="https://github.com/attacker/unapproved"
            ),
            "source repository differs",
        ),
        (
            lambda candidate: candidate["applications"][0].update(
                requested_version="main"
            ),
            "requested_version differs",
        ),
        (
            lambda candidate: candidate["applications"][0].update(
                immutable_commit="a" * 39
            ),
            "full 40-character Git commit",
        ),
        (
            lambda candidate: candidate.update(framework_version="17"),
            "framework_version does not match",
        ),
        (
            lambda candidate: candidate.update(target_platforms=["linux/arm64"]),
            "target platform is not",
        ),
        (
            lambda candidate: candidate.update(
                optional_capabilities=["../untrusted.json"]
            ),
            "Invalid optional capability path",
        ),
        (
            lambda candidate: candidate["approved_build_parameters"].update(
                build_options={"shell": "echo unsafe"}
            ),
            "build options not implemented",
        ),
        (
            lambda candidate: candidate["approved_build_parameters"].update(
                build_profile="debug"
            ),
            "Only the production build profile",
        ),
    ],
)
def test_candidate_adapter_rejects_unsupported_or_mismatched_composition(
    ndf_dir, tmp_path, mutate, message
):
    candidate = make_candidate(ndf_dir, None)
    mutate(candidate)
    with pytest.raises(CandidateCompositionError, match=message):
        run_adapter(ndf_dir, tmp_path, candidate)


def test_candidate_adapter_rejects_payload_hash_mismatch(ndf_dir, tmp_path):
    candidate = make_candidate(ndf_dir, None)
    candidate_path = write_candidate(tmp_path, candidate)
    with pytest.raises(
        CandidateCompositionError, match="do not match the dispatch payload"
    ):
        adapt_candidate_to_lock(
            ndf_dir=ndf_dir,
            candidate_path=candidate_path,
            output_dir=tmp_path / "output",
            candidate_artifact_ref=(
                "ghcr.io/ndftechlabs/dt-master-deployment-candidates@sha256:"
                + "b" * 64
            ),
            payload_sha256="c" * 64,
        )


def test_candidate_adapter_rejects_wrong_candidate_artifact_repository(
    ndf_dir, tmp_path
):
    candidate = make_candidate(ndf_dir, None)
    candidate_path = write_candidate(tmp_path, candidate)
    payload_sha = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    with pytest.raises(CandidateCompositionError, match="not allowlisted"):
        adapt_candidate_to_lock(
            ndf_dir=ndf_dir,
            candidate_path=candidate_path,
            output_dir=tmp_path / "output",
            candidate_artifact_ref=(
                "ghcr.io/attacker/candidates@sha256:" + "b" * 64
            ),
            payload_sha256=payload_sha,
        )
