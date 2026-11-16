import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"


def read_workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def job_block(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    assert match is not None, f"Missing workflow job: {name}"
    return match.group(1)


def test_signing_is_main_branch_only_and_follows_build_validation():
    workflow = read_workflow("ndf-publish-product.yml")
    sign = job_block(workflow, "sign-trust")
    verify = job_block(workflow, "verify-trust")

    assert "name: NDF / Publish Product Images" in workflow
    assert "workflow_dispatch:" in workflow
    assert "if: ${{ github.ref == 'refs/heads/main' }}" in sign
    assert "needs: [prepare, build-validate]" in sign
    assert "needs: [prepare, build-validate, sign-trust]" in verify


def test_only_signing_job_receives_oidc_permission():
    workflow = read_workflow("ndf-publish-product.yml")
    build = job_block(workflow, "build-validate")
    sign = job_block(workflow, "sign-trust")
    verify = job_block(workflow, "verify-trust")
    promote = job_block(workflow, "promote")

    assert "id-token: write" not in build
    assert "id-token: write" in sign
    assert "packages: write" in sign
    assert "contents: read" in sign
    assert "contents: write" not in sign
    assert "actions: write" not in sign
    assert "packages: read" in verify
    assert "id-token: write" not in verify
    assert "packages: write" in promote
    assert "id-token: write" not in promote


def test_provenance_generation_follows_publication_gate_and_is_uploaded():
    workflow = read_workflow("ndf-publish-product.yml")
    build = job_block(workflow, "build-validate")
    gate = build.index("name: Verify publication gate")
    provenance = build.index("name: Generate deterministic image provenance")
    upload = build.index("name: Upload publishing and validation artifacts")

    assert gate < provenance < upload
    assert "generate_image_provenance.py" in build
    assert "image-provenance-predicate.json" in build
    assert "image-provenance-statement.json" in build


def test_sign_and_verify_jobs_use_attempt_scoped_evidence_and_pinned_cosign():
    workflow = read_workflow("ndf-publish-product.yml")
    sign = job_block(workflow, "sign-trust")
    verify = job_block(workflow, "verify-trust")

    assert (
        "ndf-publish-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}"
        in sign
    )
    assert "cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6" in sign
    assert "cosign-release: v3.1.4" in sign
    assert "cosign_image_trust.py sign" in sign
    assert "cosign-sign-result.json" in sign
    assert "cosign_image_trust.py verify" not in sign

    assert (
        "ndf-cosign-sign-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}"
        in verify
    )
    assert "cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6" in verify
    assert "cosign-release: v3.1.4" in verify
    assert "cosign_image_trust.py verify" in verify
    assert "--self-contained" in verify
    assert "--expected-product-id" in verify
    assert "--expected-source-commit" in verify
    assert "--attestation-output" in verify


def test_independent_verification_checks_signature_identity_transparency_and_policy():
    workflow = read_workflow("ndf-publish-product.yml")
    verify = job_block(workflow, "verify-trust")

    assert "packages: read" in verify
    assert "id-token: write" not in verify
    required = (
        '("signature", "signer", "transparency")',
        '["IDENTITY_POLICY_PROVISIONAL"]',
        "PUBLISH_REQUESTED",
        "Official promotion is blocked while signer identity policy remains provisional",
    )
    for item in required:
        assert item in verify
    assert 'result.get("transparency", {}).get("log_entry_verified") is not True' in verify
    assert "attestation.get(\"verified\") is not True" in verify
    assert 'attestation.get("predicate_type") != "https://slsa.dev/provenance/v1"' in verify
    assert 'attestation.get("subject_digest") != image_ref.rsplit("@", 1)[1]' in verify
    assert "imagetools create" not in verify
    assert "imagetools create" not in verify


def test_promotion_is_separate_and_requires_trusted_independent_result():
    workflow = read_workflow("ndf-publish-product.yml")
    sign = job_block(workflow, "sign-trust")
    verify = job_block(workflow, "verify-trust")
    promote = job_block(workflow, "promote")

    assert "imagetools create" not in sign
    assert "imagetools create" not in verify
    assert "inputs.publish" in promote
    assert "needs.verify-trust.result == 'success'" in promote
    assert "decision" in promote and '"trusted"' in promote
    assert "Only an independently trusted image may be promoted." in promote
    assert "imagetools create" in promote
