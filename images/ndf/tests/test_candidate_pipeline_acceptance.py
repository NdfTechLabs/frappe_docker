"""Cross-stage contract checks for the candidate-driven NDF workflow."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"


def workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def section(source: str, start: str, end: str | None = None) -> str:
    body = source.split(start, 1)[1]
    return body.split(end, 1)[0] if end else body


def test_candidate_pipeline_has_a_fail_closed_stage_dependency_chain():
    entry = workflow("ndf-build-candidate.yml")

    prepare = section(entry, "  prepare-candidate:")
    assert "needs: [dispatch-gate, verify-candidate-origin]" in prepare
    assert "needs: prepare-candidate" in section(entry, "  build-candidate:")
    pdd = section(entry, "  publish-candidate-pdd:", "  publish-candidate-result:")
    assert "needs: [prepare-candidate, build-candidate]" in pdd

    result = section(entry, "  publish-candidate-result:")
    assert "if: always()" in result
    for dependency in (
        "- dispatch-gate",
        "- verify-candidate-origin",
        "- prepare-candidate",
        "- build-candidate",
        "- publish-candidate-pdd",
    ):
        assert dependency in result


def test_candidate_identity_and_prepared_lock_flow_into_the_image_build():
    entry = workflow("ndf-build-candidate.yml")
    build = workflow("ndf-reusable-build-candidate.yml")

    assert "CANDIDATE_ID: ${{ inputs.candidate_id }}" in entry
    assert "CANDIDATE_ARTIFACT_REF: ${{ inputs.candidate_artifact_ref }}" in entry
    assert "CANDIDATE_PAYLOAD_SHA256: ${{ inputs.candidate_payload_sha256 }}" in entry
    assert "candidate_artifact_ref: ${{ inputs.candidate_artifact_ref }}" in entry
    assert "candidate_payload_sha256: ${{ inputs.candidate_payload_sha256 }}" in entry

    assert "actions/download-artifact@v7" in build
    assert "name: ${{ inputs.prepared_artifact_name }}" in build
    assert "EXPECTED_LOCK_SHA256: ${{ inputs.lock_sha256 }}" in build
    assert "--prepared-inputs-dir" in build
    assert "prepare_build.py" not in build
    assert "--output-dir" not in build


def test_image_build_outputs_are_bound_to_the_pdd_stage():
    entry = workflow("ndf-build-candidate.yml")
    build = workflow("ndf-reusable-build-candidate.yml")
    pdd = workflow("ndf-reusable-pdd-candidate.yml")

    assert "value: ${{ jobs.build-verify.outputs.image_digest }}" in build
    assert "value: ${{ jobs.build-verify.outputs.composition_hash }}" in build
    assert "image_digest: ${{ needs.build-candidate.outputs.image_digest }}" in entry
    assert (
        "composition_hash: ${{ needs.build-candidate.outputs.composition_hash }}"
        in entry
    )
    assert "EXPECTED_IMAGE_DIGEST: ${{ inputs.image_digest }}" in pdd
    assert "EXPECTED_LOCK_SHA256: ${{ inputs.lock_sha256 }}" in pdd
    assert "EXPECTED_COMPOSITION_HASH: ${{ inputs.composition_hash }}" in pdd

    for required_tool in (
        "generate_product_deployment_descriptor.py",
        "validate_product_deployment_descriptor.py",
        "verify_product_deployment_binding.py",
        "publish_product_deployment_descriptor.py",
    ):
        assert required_tool in pdd


def test_pdd_outputs_are_bound_to_the_same_attempt_result():
    entry = workflow("ndf-build-candidate.yml")
    result = section(entry, "  publish-candidate-result:")

    for binding in (
        "IMAGE_DIGEST: ${{ needs.build-candidate.outputs.image_digest }}",
        "COMPOSITION_HASH: ${{ needs.build-candidate.outputs.composition_hash }}",
        "PDD_REFERENCE: ${{ needs.publish-candidate-pdd.outputs.pdd_artifact_reference }}",
        "PDD_DIGEST: ${{ needs.publish-candidate-pdd.outputs.pdd_artifact_digest }}",
        "PDD_CONTENT_SHA256: ${{ needs.publish-candidate-pdd.outputs.pdd_content_sha256 }}",
        "LOCK_SHA256: ${{ needs.prepare-candidate.outputs.lock_sha256 }}",
    ):
        assert binding in result

    assert "write_deployment_build_result.py" in result
    assert "deployment-build-result-v1.schema.json" in result
    assert (
        "ndf-candidate-evidence-${{ github.run_id }}-${{ github.run_attempt }}"
        in result
    )
    assert "${{ runner.temp }}/ndf-candidate-evidence-bundle/" in result
    assert "package_deployment_build_evidence.py pack" in result
    assert "package_deployment_build_evidence.py verify" in result
    assert "ndf-candidate-result-${{ github.run_id }}-${{ github.run_attempt }}" not in result


def test_candidate_jobs_keep_registry_permissions_at_the_required_boundaries():
    entry = workflow("ndf-build-candidate.yml")
    prepare = section(entry, "  prepare-candidate:", "  build-candidate:")
    build = section(entry, "  build-candidate:", "  publish-candidate-pdd:")
    pdd = section(entry, "  publish-candidate-pdd:", "  publish-candidate-result:")
    result = section(entry, "  publish-candidate-result:")

    assert "packages: read" in prepare
    assert "packages: write" not in prepare
    assert "packages: write" in build
    assert "packages: write" in pdd
    assert "packages: write" not in result
    assert "actions: read" in result
    assert "contents: read" in result


def test_candidate_pipeline_never_promotes_an_official_product_tag():
    build = workflow("ndf-reusable-build-candidate.yml")
    pdd = workflow("ndf-reusable-pdd-candidate.yml")

    assert "gate_image_publication.py" in build
    assert "docker pull" in build
    assert "imagetools create" not in build
    assert "Promote verified digest" not in build
    assert "imagetools create" not in pdd
    assert "Promote verified digest" not in pdd
