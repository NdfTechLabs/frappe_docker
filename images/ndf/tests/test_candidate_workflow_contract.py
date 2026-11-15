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
