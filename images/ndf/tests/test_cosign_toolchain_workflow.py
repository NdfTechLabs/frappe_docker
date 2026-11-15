from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_cosign_toolchain_smoke_workflow_is_manual_and_read_only():
    workflow = (WORKFLOWS / "ndf-cosign-toolchain-smoke.yml").read_text(
        encoding="utf-8"
    )
    assert "workflow_dispatch:" in workflow
    assert "contents: read" in workflow
    assert "packages: write" not in workflow
    assert "id-token: write" not in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow


def test_cosign_toolchain_is_pinned_to_approved_versions():
    workflow = (WORKFLOWS / "ndf-cosign-toolchain-smoke.yml").read_text(
        encoding="utf-8"
    )
    assert (
        "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6"
        in workflow
    )
    assert "cosign-release: v3.1.4" in workflow
    assert "cosign version" in workflow
    assert "v3.1.4" in workflow


def test_cosign_toolchain_smoke_checks_required_cli_options():
    workflow = (WORKFLOWS / "ndf-cosign-toolchain-smoke.yml").read_text(
        encoding="utf-8"
    )
    for option in (
        "--predicate",
        "--type",
        "--certificate-identity",
        "--certificate-oidc-issuer",
    ):
        assert option in workflow
    assert "cosign attest --help" in workflow
    assert "cosign verify --help" in workflow
    assert "cosign verify-attestation --help" in workflow
