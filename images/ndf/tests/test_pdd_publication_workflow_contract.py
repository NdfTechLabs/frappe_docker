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


def test_source_trust_artifacts_are_derived_from_exact_build_artifact_identity():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    assert 're.fullmatch(r"ndf-publish-(.+)-(\\d+)-(\\d+)", build_name)' in workflow
    assert (
        'signing_name = f"ndf-cosign-sign-{image_id}-{build_id}-{build_attempt}"'
        in workflow
    )
    assert (
        'source_verification_name = f"ndf-cosign-verify-{image_id}-{build_id}-{build_attempt}"'
        in workflow
    )
    assert 'signing_job_name = f"Sign product image {image_id}"' in workflow
    assert (
        'verification_job_name = f"Independently verify product trust for {image_id}"'
        in workflow
    )
    assert 'signing_job.get("conclusion") != "success"' in workflow
    assert 'verification_job.get("conclusion") != "success"' in workflow
    assert 'signing_artifact.get("expired")' in workflow
    assert 'verification_artifact.get("expired")' in workflow

    product = read_workflow("ndf-publish-product.yml")
    assert "name: ndf-cosign-sign-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}" in product
    assert "name: ndf-cosign-verify-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}" in product

def test_source_signing_and_verification_artifacts_match_build_predicate():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    download = workflow.split(
        "name: Download exact source build, signing and verification evidence", 1
    )[1].split("\n      - name:", 1)[0]
    assert "source_signing_artifact_name" in download
    assert "source_verification_artifact_name" in download
    assert "cosign-sign-result.json" in download
    assert "cosign-independent-verification-result.json" in download
    assert "image-provenance-predicate.json" in download
    assert 'signing.get("status") != "signed"' in download
    assert 'signing.get("image_repository") != repository' in download
    assert 'signing.get("image_digest") != digest' in download
    assert 'print(f"Verified descriptor/report: {VERIFICATION_ARTIFACT_NAME}")' in workflow
    assert (
        'cmp "$EVIDENCE_DIR/image-provenance-predicate.json" "$SOURCE_SIGNING_DIR/image-provenance-predicate.json"'
        in download
    )
    assert '--source-trust-result "$SOURCE_VERIFY_DIR/cosign-independent-verification-result.json"' in workflow
    assert '--source-predicate "$SOURCE_SIGNING_DIR/image-provenance-predicate.json"' in workflow
    assert "cosign-live-verification-result.json" not in workflow
    assert "ndf-cosign-live-" not in workflow

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
    binding_step = publish_job.index(
        "name: Generate deterministic PDD binding statement and predicate"
    )
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
    assert 'receipt["artifact"]["immutable_reference"]' in sign_job
    assert "cosign_pdd_trust.py sign" in sign_job
    assert "cosign_pdd_trust.py verify" in sign_job
    assert "cosign-release: v3.1.4" in sign_job
    assert "6f9f17788090df1f26f669e9d70d6ae9567deba6" in sign_job
    assert "IDENTITY_POLICY_PROVISIONAL" in sign_job
    assert "pdd-publication-record-v1.schema.json" in sign_job
    assert (
        "PDD cryptographic verification passed, but signer identity policy is "
        "provisional; result is rejected."
    ) in sign_job
    assert "pdd-trust-verification-result.json" in sign_job
    assert "pdd-verified-attestation.json" in sign_job


def test_other_product_and_consumer_trust_workflows_are_not_changed_by_pdd_scope():
    product = read_workflow("ndf-publish-product.yml")
    consumer = read_workflow("ndf-fetch-product-deployment-descriptor.yml")
    assert "sign-trust:" in product
    assert "id-token: write" in product
    assert "id-token: write" not in consumer
    assert "packages: read" in consumer


def test_signer_correlates_and_publishes_complete_attempt_scoped_trust_evidence():
    workflow = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    sign_job = workflow.split("\n  sign-pdd:\n", 1)[1]
    correlation = sign_job.index("name: Assemble and correlate PDD trust evidence")
    upload = sign_job.index("name: Upload correlated PDD trust evidence")
    summary = sign_job.index("name: Write PDD trust evidence summary")
    assert correlation < upload < summary
    assert "correlate_pdd_trust_evidence.py" in sign_job
    assert "--source-build-run-id" in sign_job
    assert "--source-build-attempt" in sign_job
    assert "--signing-input-artifact" in sign_job
    assert (
        "ndf-pdd-trust-evidence-${{ inputs.build_run_id }}-${{ github.run_attempt }}"
        in sign_job
    )
    assert "retention-days: 90" in sign_job
    assert (
        "pdd-trust-evidence-manifest.json"
        not in sign_job.split("name: Upload correlated PDD trust evidence", 1)[0]
        or "correlate_pdd_trust_evidence.py" in sign_job
    )
    assert "REJECTED: IDENTITY_POLICY_PROVISIONAL" in sign_job
    assert (
        "Cryptographic signature, signer, Rekor and binding-attestation checks passed"
        in sign_job
    )
    assert "BUILD_ARTIFACT_NAME: ${{ inputs.build_artifact_name }}" in sign_job
    assert 'SOURCE_BUILD_ATTEMPT="${BASH_REMATCH[3]}"' in sign_job
    assert (
        "source_build_attempt: ${{ steps.source.outputs.source_build_attempt }}"
        not in workflow
    )
    assert "id-token: write" in sign_job
    assert sign_job.count("id-token: write") == 1


def test_pdd_trust_evidence_manifest_schema_is_versioned_and_hashes_required_files():
    import json

    from jsonschema import Draft202012Validator

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "pdd-trust-evidence-manifest-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    required_files = {
        "pdd-publication-record.json",
        "pdd-image-binding-statement.json",
        "pdd-image-binding-predicate.json",
        "pdd-trust-verification-result.json",
        "pdd-verified-attestation.json",
        "pdd-verify.log",
    }
    assert set(schema["properties"]["files"]["required"]) == required_files
    assert (
        schema["properties"]["verification"]["properties"]["decision"]["const"]
        == "rejected"
    )
    assert schema["properties"]["verification"]["properties"]["reason_codes"][
        "const"
    ] == ["IDENTITY_POLICY_PROVISIONAL"]
