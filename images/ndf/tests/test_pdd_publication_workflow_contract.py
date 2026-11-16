from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"


def read_workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_pdd_publication_workflow_defaults_to_read_only_permissions():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    top_level = workflow.split("\njobs:\n", 1)[0]
    assert "permissions:\n  actions: read\n  contents: read" in top_level
    assert "packages: write" not in top_level
    assert "id-token: write" not in top_level


def test_pdd_publication_job_has_only_required_registry_write_permission():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    publish_job = workflow.split("\n  publish:\n", 1)[1]
    permissions = publish_job.split("\n    env:\n", 1)[0]
    assert "permissions:" in permissions
    assert "actions: read" in permissions
    assert "contents: read" in permissions
    assert "packages: write" in permissions
    assert "id-token: write" not in permissions
    assert "contents: write" not in permissions
    assert "actions: write" not in permissions


def test_source_trust_artifact_is_derived_from_exact_build_artifact_identity():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    assert 're.fullmatch(r"ndf-publish-(.+)-(\\d+)-(\\d+)", build_name)' in workflow
    assert (
        'trust_name = f"ndf-cosign-live-{image_id}-{build_id}-{build_attempt}"'
        in workflow
    )
    assert 'trust_job_name = f"Live Cosign trust check for {image_id}"' in workflow
    assert "build-jobs.json" in workflow
    assert "jobs?per_page=100" in workflow
    assert 'trust_job.get("conclusion") != "success"' in workflow
    assert 'trust_artifact.get("expired")' in workflow


def test_source_trust_artifact_must_be_present_and_match_build_predicate():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    download = workflow.split("name: Download original build evidence", 1)[1].split(
        "\n      - name:", 1
    )[0]
    assert "steps.source.outputs.source_trust_artifact_name" in download
    assert "cosign-live-verification-result.json" in download
    assert "image-provenance-predicate.json" in download
    assert (
        'cmp "$EVIDENCE_DIR/image-provenance-predicate.json" "$SOURCE_TRUST_DIR/image-provenance-predicate.json"'
        in download
    )


def test_existing_publication_receipt_artifact_contract_is_preserved():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    assert "pdd-publication-record.json" in workflow
    assert (
        "name: ndf-pdd-publication-${{ inputs.build_run_id }}-${{ github.run_attempt }}"
        in workflow
    )
    assert "path: ${{ runner.temp }}/pdd-publication-record.json" in workflow
    assert "retention-days: 90" in workflow


def test_pdd_publication_remains_manual_main_only_and_only_signer_receives_oidc():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    publish_job = workflow.split("\n  publish:\n", 1)[1].split("\n  sign-pdd:\n", 1)[0]
    sign_job = workflow.split("\n  sign-pdd:\n", 1)[1]
    assert "workflow_dispatch:" in workflow
    assert '[[ "$GITHUB_REF" == "refs/heads/main" ]]' in workflow
    assert "id-token: write" not in publish_job
    assert "id-token: write" in sign_job
    assert "--insecure-ignore-tlog" not in workflow
    assert "--check-claims=false" not in workflow


def test_binding_generation_emits_statement_and_predicate_after_publication():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    publish_job = workflow.split("\n  publish:\n", 1)[1].split("\n  sign-pdd:\n", 1)[0]
    publish_step = publish_job.index("name: Publish PDD and verified evidence bundle")
    binding_step = publish_job.index("name: Generate deterministic PDD binding statement and predicate")
    upload_step = publish_job.index("name: Upload PDD signing inputs")
    assert publish_step < binding_step < upload_step
    assert "--statement-output" in publish_job
    assert "--predicate-output" in publish_job
    assert "pdd-publication-record.json" in publish_job
    assert "pdd-image-binding-statement.json" in publish_job
    assert "pdd-image-binding-predicate.json" in publish_job
    assert "signing_input_artifact:" in publish_job


def test_signer_job_is_dependent_isolated_and_uses_immutable_receipt_digest():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    sign_job = workflow.split("\n  sign-pdd:\n", 1)[1]
    assert "needs: publish" in sign_job
    assert "id-token: write" in sign_job
    assert "packages: write" in sign_job
    assert "actions/download-artifact@v7" in sign_job
    assert "needs.publish.outputs.signing_input_artifact" in sign_job
    assert "artifact.immutable_reference" in sign_job
    assert "cosign_pdd_trust.py sign" in sign_job
    assert "cosign_pdd_trust.py verify" in sign_job
    assert "cosign-release: v3.1.4" in sign_job
    assert "6f9f17788090df1f26f669e9d70d6ae9567deba6" in sign_job
    assert "IDENTITY_POLICY_PROVISIONAL" in sign_job
    assert "pdd-publication-record-v1.schema.json" in sign_job
    assert "PDD cryptographic verification passed, but signer identity policy is provisional; result is rejected." in sign_job
    assert "pdd-trust-verification-result.json" in sign_job
    assert "pdd-verified-attestation.json" in sign_job


def test_other_product_and_consumer_trust_workflows_are_not_changed_by_pdd_scope():
    product = read_workflow("ndf-publish-product.yml")
    consumer = read_workflow("ndf-fetch-product-deployment-descriptor.yml")
    assert "sign-trust:" in product
    assert "id-token: write" in product
    assert "id-token: write" not in consumer
    assert "packages: read" in consumer
