from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"


def read_workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_live_signing_is_confined_to_existing_product_workflow_identity():
    workflow = read_workflow("ndf-publish-product.yml")
    assert "name: NDF / Publish Product Images" in workflow
    assert "workflow_dispatch:" in workflow
    assert "sign-trust:" in workflow
    assert (
        "if: ${{ inputs.publish == false && inputs.product != 'all' && github.ref == 'refs/heads/main' }}"
        in workflow
    )
    assert "needs: [prepare, publish]" in workflow


def test_only_dedicated_signing_job_receives_oidc_permission():
    workflow = read_workflow("ndf-publish-product.yml")
    publish_job = workflow.split("\n  publish:\n", 1)[1].split("\n  sign-trust:\n", 1)[
        0
    ]
    sign_job = workflow.split("\n  sign-trust:\n", 1)[1]
    assert "id-token: write" not in publish_job
    assert "id-token: write" in sign_job
    assert "packages: write" in sign_job
    assert "contents: read" in sign_job
    assert "contents: write" not in sign_job
    assert "actions: write" not in sign_job


def test_provenance_generation_follows_publication_gate_and_is_uploaded():
    workflow = read_workflow("ndf-publish-product.yml")
    gate = workflow.index("name: Verify publication gate")
    provenance = workflow.index("name: Generate deterministic image provenance")
    upload = workflow.index("name: Upload publishing and validation artifacts")
    assert gate < provenance < upload
    assert "generate_image_provenance.py" in workflow
    assert "image-provenance-predicate.json" in workflow
    assert "image-provenance-statement.json" in workflow


def test_live_job_uses_run_attempt_scoped_evidence_and_pinned_cosign():
    workflow = read_workflow("ndf-publish-product.yml")
    sign_job = workflow.split("\n  sign-trust:\n", 1)[1]
    assert (
        "ndf-publish-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}"
        in sign_job
    )
    assert "cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6" in sign_job
    assert "cosign-release: v3.1.4" in sign_job
    assert "cosign_image_trust.py sign" in sign_job
    assert "cosign_image_trust.py verify" in sign_job


def test_live_job_uses_digest_reference_and_expects_only_provisional_rejection():
    workflow = read_workflow("ndf-publish-product.yml")
    sign_job = workflow.split("\n  sign-trust:\n", 1)[1]
    assert 'print(f"image_ref={repository}@{digest}")' in sign_job
    assert 'result.get("decision", {}).get("status") != "rejected"' in sign_job
    assert '["IDENTITY_POLICY_PROVISIONAL"]' in sign_job
    assert "transparency" in sign_job
    assert "--insecure-ignore-tlog" not in sign_job
    assert "--check-claims=false" not in sign_job


def test_live_job_never_promotes_or_changes_the_official_product_tag():
    workflow = read_workflow("ndf-publish-product.yml")
    sign_job = workflow.split("\n  sign-trust:\n", 1)[1]
    assert "imagetools create" not in sign_job
    assert "Promote verified digest" not in sign_job
    promotion = workflow.split(
        "name: Promote verified digest to official source tag", 1
    )[1].split("      - name:", 1)[0]
    assert "if: ${{ inputs.publish }}" in promotion
