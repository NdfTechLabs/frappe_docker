import json
from pathlib import Path
from unittest.mock import patch

import pytest
from scripts.build_image import (
    BuildExecutionError,
    resolve_base_images,
    build_command,
    build_labels,
    execute_build,
    get_manifest_checksum,
    normalize_platforms,
    validate_image_tags,
)


def test_get_manifest_checksum_returns_matching_source_revision():
    lock = {"manifests": [{"path": "products/dalali-v16.json", "sha256": "a" * 64}]}
    assert get_manifest_checksum(lock, "products/dalali-v16.json") == "a" * 64


def test_get_manifest_checksum_rejects_missing_or_duplicate_entries():
    with pytest.raises(BuildExecutionError, match="exactly one"):
        get_manifest_checksum({"manifests": []}, "products/missing.json")

    lock = {
        "manifests": [
            {"path": "products/app.json", "sha256": "a" * 64},
            {"path": "products/app.json", "sha256": "b" * 64},
        ]
    }
    with pytest.raises(BuildExecutionError, match="exactly one"):
        get_manifest_checksum(lock, "products/app.json")


def test_build_labels_include_manifest_lock_and_application_refs():
    metadata = {
        "image": {
            "id": "dalali-v16",
            "product": "dalali",
            "manifest": "products/dalali-v16.json",
        },
        "framework": {"name": "frappe", "version": "16", "target_ref": "version-16"},
        "lock": {"sha256": "b" * 64},
        "applications": [
            {"name": "erpnext", "target_ref": "version-16", "resolved_sha": "c" * 40}
        ],
    }
    lock = {"manifests": [{"path": "products/dalali-v16.json", "sha256": "a" * 64}]}

    labels = build_labels(metadata, lock)
    apps = json.loads(labels["com.ndf.applications"])

    assert labels["org.opencontainers.image.source"] == (
        "https://github.com/NdfTechLabs/frappe_docker"
    )
    assert labels["org.opencontainers.image.url"] == (
        "https://github.com/NdfTechLabs/frappe_docker"
    )
    assert labels["com.ndf.image.id"] == "dalali-v16"
    assert labels["com.ndf.manifest.sha256"] == "a" * 64
    assert labels["com.ndf.lock.sha256"] == "b" * 64
    assert labels["com.ndf.framework.target-ref"] == "version-16"
    assert apps[0]["target_ref"] == "version-16"
    assert apps[0]["resolved_sha"] == "c" * 40


def _build_command(tmp_path, **overrides):
    root = tmp_path
    dockerfile = root / "images" / "layered" / "Containerfile"
    apps_json = root / "images" / "ndf" / ".build" / "dalali" / "apps.json"
    dockerfile.parent.mkdir(parents=True, exist_ok=True)
    apps_json.parent.mkdir(parents=True, exist_ok=True)
    dockerfile.touch()
    apps_json.write_text("[]", encoding="utf-8")

    arguments = {
        "repository_root": root,
        "dockerfile": dockerfile,
        "apps_json": apps_json,
        "image_repository": "ghcr.io/ndftechlabs/dalali",
        "image_tag": "local",
        "frappe_branch": "version-16",
        "builder_image": "frappe/build@sha256:" + "1" * 64,
        "runtime_image": "frappe/base@sha256:" + "2" * 64,
        "labels": {"com.ndf.image.id": "dalali-v16"},
        "platform": "linux/amd64",
        "no_cache": False,
        "builder": None,
    }
    arguments.update(overrides)
    return build_command(**arguments)


def test_resolve_base_images_uses_the_accepted_rt01_platform_digests():
    ndf_dir = Path(__file__).resolve().parents[1]
    resolved = resolve_base_images(ndf_dir, None, ["linux/amd64"])

    assert resolved["platform"] == "linux/amd64"
    assert resolved["builder"] == (
        "frappe/build@sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b"
    )
    assert resolved["runtime"] == (
        "frappe/base@sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c"
    )
    assert resolved["inventory_manifest_sha256"]


def test_resolve_base_images_rejects_unsupported_platforms():
    ndf_dir = Path(__file__).resolve().parents[1]
    with pytest.raises(BuildExecutionError, match="only linux/amd64"):
        resolve_base_images(ndf_dir, None, ["linux/arm64"])


def test_build_command_loads_locally_and_uses_buildkit_secret(tmp_path):
    command = _build_command(
        tmp_path,
        no_cache=True,
        builder="ndf-local",
    )

    assert "--load" in command
    assert "--push" not in command
    assert "--secret" in command
    assert any(item.startswith("id=apps_json,src=") for item in command)
    assert "FRAPPE_BRANCH=version-16" in command
    assert "FRAPPE_BUILD_IMAGE=frappe/build@sha256:" + "1" * 64 in command
    assert "FRAPPE_BASE_IMAGE=frappe/base@sha256:" + "2" * 64 in command
    assert "ghcr.io/ndftechlabs/dalali:local" in command
    assert "linux/amd64" in command
    assert "--build-arg" in command
    assert "--no-cache" in command
    assert "ndf-local" in command


def test_build_command_adds_buildkit_cache_sources_and_destinations(tmp_path):
    command = _build_command(
        tmp_path,
        cache_from=["type=gha,scope=ndf-dalali-v16"],
        cache_to=["type=gha,mode=max,scope=ndf-dalali-v16"],
    )

    assert command.count("--cache-from") == 1
    assert "type=gha,scope=ndf-dalali-v16" in command
    assert command.count("--cache-to") == 1
    assert "type=gha,mode=max,scope=ndf-dalali-v16" in command


def test_build_command_supports_multiple_cache_backends(tmp_path):
    command = _build_command(
        tmp_path,
        cache_from=["type=gha,scope=product", "type=registry,ref=example/cache:latest"],
        cache_to=["type=gha,mode=max,scope=product"],
    )

    assert command.count("--cache-from") == 2
    assert command.count("--cache-to") == 1


def test_execute_build_dry_run_does_not_call_subprocess():
    with patch("scripts.build_image.subprocess.run") as run:
        execute_build(["docker", "buildx", "build", "--load", "."], dry_run=True)
    run.assert_not_called()


def test_execute_build_rejects_unavailable_buildx():
    class Result:
        returncode = 1
        stderr = "buildx not installed"
        stdout = ""

    with patch("scripts.build_image.subprocess.run", return_value=Result()):
        with pytest.raises(BuildExecutionError, match="Buildx is unavailable"):
            execute_build(["docker", "buildx", "build", "--load", "."])


def test_execute_build_reports_build_failure():
    class VersionResult:
        returncode = 0
        stderr = ""
        stdout = "github.com/docker/buildx"

    class BuildResult:
        returncode = 17

    with patch(
        "scripts.build_image.subprocess.run",
        side_effect=[VersionResult(), BuildResult()],
    ):
        with pytest.raises(BuildExecutionError, match="exit code 17"):
            execute_build(["docker", "buildx", "build", "--load", "."])


def test_build_command_pushes_to_registry_with_multiple_tags_and_platforms(tmp_path):
    command = _build_command(
        tmp_path,
        image_tag=None,
        image_tags=["v16-1.0.0", "v16-latest", "v16-0123456789abcdef"],
        push=True,
        platform="linux/amd64,linux/arm64",
        metadata_file=tmp_path / "buildx-metadata.json",
    )

    assert "--push" in command
    assert "--load" not in command
    assert command.count("--tag") == 3
    assert "ghcr.io/ndftechlabs/dalali:v16-1.0.0" in command
    assert "ghcr.io/ndftechlabs/dalali:v16-latest" in command
    assert "ghcr.io/ndftechlabs/dalali:v16-0123456789abcdef" in command
    assert "linux/amd64,linux/arm64" in command
    assert "--metadata-file" in command
    assert str(tmp_path / "buildx-metadata.json") in command


def test_build_command_requires_at_least_one_tag(tmp_path):
    with pytest.raises(BuildExecutionError, match="At least one image tag"):
        _build_command(tmp_path, image_tag=None, image_tags=[])


def test_normalize_platforms_accepts_single_and_multiple_platforms():
    assert normalize_platforms("linux/amd64") == ["linux/amd64"]
    assert normalize_platforms("linux/amd64, linux/arm64") == [
        "linux/amd64",
        "linux/arm64",
    ]


def test_normalize_platforms_rejects_invalid_and_duplicate_values():
    with pytest.raises(BuildExecutionError, match="Invalid platform"):
        normalize_platforms("amd64")
    with pytest.raises(BuildExecutionError, match="Duplicate"):
        normalize_platforms("linux/amd64,linux/amd64")


def test_execute_build_reads_buildx_metadata(tmp_path):
    metadata_file = tmp_path / "buildx-metadata.json"
    metadata_file.write_text(
        json.dumps({"containerimage.digest": "sha256:" + "a" * 64}),
        encoding="utf-8",
    )

    class VersionResult:
        returncode = 0
        stderr = ""
        stdout = "github.com/docker/buildx"

    class BuildResult:
        returncode = 0

    with patch(
        "scripts.build_image.subprocess.run",
        side_effect=[VersionResult(), BuildResult()],
    ):
        result = execute_build(
            ["docker", "buildx", "build", "--push", "."],
            metadata_file=metadata_file,
        )

    assert result["containerimage.digest"] == "sha256:" + "a" * 64


def test_validate_image_tags_accepts_valid_tags():
    assert validate_image_tags(["v16-1.2.0", "v16-latest", "v16-0123456789abcdef"]) == [
        "v16-1.2.0",
        "v16-latest",
        "v16-0123456789abcdef",
    ]


def test_validate_image_tags_rejects_invalid_and_duplicate_tags():
    with pytest.raises(BuildExecutionError, match="Invalid Docker image tag"):
        validate_image_tags(["invalid tag"])
    with pytest.raises(BuildExecutionError, match="Duplicate"):
        validate_image_tags(["v16-latest", "v16-latest"])
