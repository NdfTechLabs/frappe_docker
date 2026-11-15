from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"


def read_workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_candidate_entry_is_manual_and_uses_configured_actor_gate():
    workflow = read_workflow("ndf-build-candidate.yml")
    assert "workflow_dispatch:" in workflow
    assert "refs/heads/main" in workflow
    assert "NDF_MASTER_DISPATCH_ACTOR" in workflow
    assert 'if [[ "$DISPATCH_ACTOR" != "$EXPECTED_DISPATCH_ACTOR" ]]' in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow


def test_candidate_intake_and_adapter_are_ordered_and_attempt_scoped():
    workflow = read_workflow("ndf-build-candidate.yml")
    assert "needs: dispatch-gate" in workflow
    assert "intake_deployment_candidate.py" in workflow
    assert "adapt_candidate_to_lock.py" in workflow
    assert workflow.index("intake_deployment_candidate.py") < workflow.index(
        "adapt_candidate_to_lock.py"
    )
    assert (
        "ndf-candidate-prepared-${{ github.run_id }}-${{ github.run_attempt }}"
        in workflow
    )
    assert "packages: read" in workflow


def test_candidate_handoff_uses_prepared_inputs_not_normal_preparation():
    workflow = read_workflow("ndf-build-candidate.yml")
    assert "build_image.py" not in workflow
    assert "--output-dir" in workflow  # adapter output only
    assert "prepare_build.py" not in workflow
    assert "build-metadata.json" in workflow
    assert "*.lock-v2.json" in workflow


def test_existing_manual_product_and_release_paths_remain_dispatchable():
    publish = read_workflow("ndf-publish-product.yml")
    build = read_workflow("ndf-build-product.yml")
    release = read_workflow("ndf-release-product.yml")
    assert "workflow_dispatch:" in publish
    assert "workflow_dispatch:" in build
    assert "workflow_dispatch:" in release
    assert "Build staging image (not the official product tag)" in publish


def test_pdd_source_ownership_checks_remain_intact():
    binding = read_workflow("ndf-verify-product-deployment-binding.yml")
    publication = read_workflow("ndf-publish-product-deployment-descriptor.yml")
    assert ".github/workflows/ndf-publish-product.yml" in binding
    assert "Publish {image_id}" in binding
    assert "Build staging image (not the official product tag)" in binding
    assert ".github/workflows/ndf-publish-product.yml" in publication
    assert ".github/workflows/ndf-verify-product-deployment-binding.yml" in publication


def test_candidate_build_consumes_prepared_inputs_and_never_promotes_official_tag():
    entry = read_workflow("ndf-build-candidate.yml")
    reusable = read_workflow("ndf-reusable-build-candidate.yml")
    assert "uses: ./.github/workflows/ndf-reusable-build-candidate.yml" in entry
    assert "packages: write" in entry
    assert "workflow_call:" in reusable
    assert "--prepared-inputs-dir" in reusable
    assert "prepare_build.py" not in reusable
    assert "--output-dir" not in reusable
    assert "gate_image_publication.py" in reusable
    assert "docker pull" in reusable
    assert "imagetools inspect" in reusable
    assert "Promote verified digest" not in reusable
    assert "imagetools create" not in reusable
    assert "publish: true" not in reusable


def test_candidate_build_handoff_is_attempt_bound_and_digest_verified():
    reusable = read_workflow("ndf-reusable-build-candidate.yml")
    assert "workflow_run_id" in reusable
    assert "workflow_run_attempt" in reusable
    assert "EXPECTED_LOCK_SHA256" in reusable
    assert (
        "ndf-candidate-build-${{ github.run_id }}-${{ github.run_attempt }}" in reusable
    )
    assert '"$BUILD_OUTPUT/build-result.json"' in reusable
    assert 'result.get("pushed") is not True' in reusable
    assert 'result.get("output") != "registry"' in reusable
    assert 'result.get("digest")' in reusable
    assert 'docker buildx imagetools inspect "$STAGING_REF"' in reusable
    assert 'ACTUAL_DIGEST" == "$EXPECTED_DIGEST"' in reusable
    assert "packages: write" in reusable


def test_candidate_registry_inspection_is_authenticated_and_no_official_promotion_occurs():
    reusable = read_workflow("ndf-reusable-build-candidate.yml")
    login = reusable.index("Log in to GitHub Container Registry")
    buildx = reusable.index("Set up Docker Buildx")
    inspect = reusable.index("Ensure candidate staging tag is unused")
    assert login < inspect
    assert buildx < inspect
    assert "docker buildx imagetools create" not in reusable


def test_candidate_pdd_stage_reuses_independent_pdd_and_binding_tools():
    entry = read_workflow("ndf-build-candidate.yml")
    pdd = read_workflow("ndf-reusable-pdd-candidate.yml")
    assert "uses: ./.github/workflows/ndf-reusable-pdd-candidate.yml" in entry
    assert "needs: [prepare-candidate, build-candidate]" in entry
    assert "workflow_call:" in pdd
    assert "generate_product_deployment_descriptor.py" in pdd
    assert "validate_product_deployment_descriptor.py" in pdd
    assert "verify_product_deployment_binding.py" in pdd
    assert "publish_product_deployment_descriptor.py" in pdd
    assert "candidate-composition.json" in pdd
    assert "EXPECTED_IMAGE_DIGEST" in pdd
    assert "EXPECTED_LOCK_SHA256" in pdd
    assert "EXPECTED_COMPOSITION_HASH" in pdd
    assert "packages: write" in pdd
    assert "actions: read" in pdd
    assert "imagetools create" not in pdd
    assert "Promote verified digest" not in pdd


def test_candidate_build_exports_pdd_provenance_outputs():
    build = read_workflow("ndf-reusable-build-candidate.yml")
    assert "value: ${{ jobs.build-verify.outputs.built_at }}" in build
    assert "value: ${{ jobs.build-verify.outputs.composition_hash }}" in build
    assert "built_at: ${{ steps.build.outputs.built_at }}" in build
    assert "composition_hash: ${{ steps.handoff.outputs.composition_hash }}" in build
    assert "date -u +'%Y-%m-%dT%H:%M:%SZ'" in build
