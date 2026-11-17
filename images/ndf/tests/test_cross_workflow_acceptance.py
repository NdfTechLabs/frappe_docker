from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
POLICIES = ROOT / "images" / "ndf" / "policies"


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _job(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    assert match, f"Workflow job {name!r} was not found."
    return match.group(1)


def _job_permissions(workflow: str, name: str) -> dict[str, str]:
    block = _job(workflow, name)
    match = re.search(r"(?m)^    permissions:\n((?:^      [^\n]*\n)+)", block)
    assert match, f"Job {name!r} must declare explicit permissions."
    return {
        key.strip(): value.strip()
        for key, value in (
            line.strip().split(":", 1) for line in match.group(1).splitlines()
        )
    }


def _oidc_jobs(workflow: str) -> set[str]:
    names = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", workflow)
    return {name for name in names if "id-token: write" in _job(workflow, name)}


def test_candidate_pipeline_has_a_single_ordered_trust_gate_before_intake():
    workflow = _workflow("ndf-build-candidate.yml")
    origin = _job(workflow, "verify-candidate-origin")
    prepare = _job(workflow, "prepare-candidate")
    build = _job(workflow, "build-candidate")
    pdd = _job(workflow, "publish-candidate-pdd")
    result = _job(workflow, "publish-candidate-result")

    assert "needs: dispatch-gate" in origin
    assert "verify_deployment_candidate_origin.py" in origin
    assert "needs: [dispatch-gate, verify-candidate-origin]" in prepare
    assert "intake_deployment_candidate.py" in prepare
    assert "adapt_candidate_to_lock.py" in prepare
    assert "needs: prepare-candidate" in build
    assert "needs: [prepare-candidate, build-candidate]" in pdd
    for dependency in (
        "dispatch-gate",
        "verify-candidate-origin",
        "prepare-candidate",
        "build-candidate",
        "publish-candidate-pdd",
    ):
        assert dependency in result
    assert "if: always()" in result
    assert workflow.index("verify_deployment_candidate_origin.py") < workflow.index(
        "intake_deployment_candidate.py"
    )


def test_candidate_dispatch_is_restricted_to_main_and_configured_app_actor():
    workflow = _workflow("ndf-build-candidate.yml")
    gate = _job(workflow, "dispatch-gate")
    assert "refs/heads/main" in gate
    assert "vars.NDF_MASTER_DISPATCH_ACTOR" in gate
    assert '[[ "$DISPATCH_ACTOR" != "$EXPECTED_DISPATCH_ACTOR" ]]' in gate
    assert "pull_request:" not in workflow
    assert "push:" not in workflow


def test_candidate_terminal_result_cannot_report_success_after_origin_rejection():
    writer = (
        ROOT / "images" / "ndf" / "scripts" / "write_deployment_build_result.py"
    ).read_text(encoding="utf-8")
    assert '"verify-candidate-origin"' in writer
    assert '"CANDIDATE_ORIGIN_TRUST_FAILED"' in writer
    assert (
        'all_succeeded = all(value == "success" for value in outcomes.values())'
        in writer
    )

    workflow = _workflow("ndf-build-candidate.yml")
    result = _job(workflow, "publish-candidate-result")
    assert "ORIGIN_VERIFY_RESULT: ${{ needs.verify-candidate-origin.result }}" in result
    assert "generate_deployment_build_trust_evidence.py" in result
    assert "package_deployment_build_evidence.py pack" in result
    assert "package_deployment_build_evidence.py verify" in result


def test_product_image_promotion_requires_an_independently_trusted_exact_digest():
    workflow = _workflow("ndf-publish-product.yml")
    sign = _job(workflow, "sign-trust")
    verify = _job(workflow, "verify-trust")
    promote = _job(workflow, "promote")

    assert "needs: [prepare, build-validate]" in sign
    assert "needs: [prepare, build-validate, sign-trust]" in verify
    assert "IDENTITY_POLICY_PROVISIONAL" in verify
    assert (
        "if: ${{ always() && inputs.publish && needs.build-validate.result == 'success' && needs.verify-trust.result == 'success' }}"
        in promote
    )
    assert 'trust.get("decision", {}).get("status") != "trusted"' in promote
    assert 'artifact.get("immutable_reference") != image_ref' in verify
    assert 'docker buildx imagetools create --tag "$PUBLICATION_REF"' in promote


def test_release_promotion_is_blocked_unless_source_trust_verification_succeeds():
    workflow = _workflow("ndf-release-product.yml")
    verify = _job(workflow, "verify-trust")
    release = _job(workflow, "release")
    assert "cosign_image_trust.py verify" in verify
    assert "needs: verify-trust" in release
    assert "needs.verify-trust.result == 'success'" in release
    assert "Re-resolve source tag and enforce verified digest continuity" in release
    assert "ACTUAL_DIGEST" in release
    assert "docker buildx imagetools create" in release


def test_product_image_to_pdd_boundary_uses_current_signing_and_verification_artifacts():
    product = _workflow("ndf-publish-product.yml")
    pdd = _workflow("ndf-publish-product-deployment-descriptor.yml")

    assert "name: ndf-cosign-sign-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}" in product
    assert "name: ndf-cosign-verify-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}" in product
    assert 'signing_name = f"ndf-cosign-sign-{image_id}-{build_id}-{build_attempt}"' in pdd
    assert 'verification_name = f"ndf-cosign-verify-{image_id}-{build_id}-{build_attempt}"' in pdd
    assert 'signing_job_name = f"Sign product image {image_id}"' in pdd
    assert 'verification_job_name = f"Independently verify product trust for {image_id}"' in pdd
    assert "cosign-sign-result.json" in pdd
    assert 'signing.get("image_digest") != digest' in pdd
    assert 'signing.get("image_repository") != repository' in pdd    assert "cosign-independent-verification-result.json" in pdd
    assert '--source-trust-result "$SOURCE_VERIFY_DIR/cosign-independent-verification-result.json"' in pdd
    assert '--source-predicate "$SOURCE_SIGNING_DIR/image-provenance-predicate.json"' in pdd
    assert "ndf-cosign-live-" not in pdd
    assert "cosign-live-verification-result.json" not in pdd

def test_pdd_consumer_is_read_only_and_never_grants_deployment_authorization():
    workflow = _workflow("ndf-fetch-product-deployment-descriptor.yml")
    assert (
        "permissions:\n  actions: read\n  contents: read\n  packages: read" in workflow
    )
    assert "id-token: write" not in workflow
    assert "packages: write" not in workflow
    assert 'report.get("deployment_authorization") != "not_granted"' in workflow
    assert 'decision.get("status") == "rejected"' in workflow
    assert 'expected_reason = ["IDENTITY_POLICY_PROVISIONAL"]' in workflow


def test_signing_oidc_authority_is_confined_to_dedicated_signing_jobs():
    product = _workflow("ndf-publish-product.yml")
    pdd = _workflow("ndf-publish-product-deployment-descriptor.yml")
    candidate = _workflow("ndf-build-candidate.yml")
    candidate_build = _workflow("ndf-reusable-build-candidate.yml")
    candidate_pdd = _workflow("ndf-reusable-pdd-candidate.yml")
    release = _workflow("ndf-release-product.yml")

    assert _oidc_jobs(product) == {"sign-trust"}
    assert _oidc_jobs(pdd) == {"sign-pdd"}
    assert _oidc_jobs(candidate) == set()
    assert _oidc_jobs(candidate_build) == set()
    assert _oidc_jobs(candidate_pdd) == set()
    assert _oidc_jobs(release) == set()


def test_candidate_jobs_use_least_privilege_permissions():
    workflow = _workflow("ndf-build-candidate.yml")
    assert _job_permissions(workflow, "dispatch-gate") == {"contents": "read"}
    assert _job_permissions(workflow, "verify-candidate-origin") == {
        "contents": "read",
        "packages": "read",
    }
    assert _job_permissions(workflow, "prepare-candidate") == {
        "contents": "read",
        "packages": "read",
    }
    assert _job_permissions(workflow, "build-candidate") == {
        "contents": "read",
        "packages": "write",
    }
    assert _job_permissions(workflow, "publish-candidate-pdd") == {
        "actions": "read",
        "contents": "read",
        "packages": "write",
    }
    assert _job_permissions(workflow, "publish-candidate-result") == {
        "actions": "read",
        "contents": "read",
    }


def test_product_and_release_sign_verify_promote_permissions_are_separated():
    product = _workflow("ndf-publish-product.yml")
    assert _job_permissions(product, "sign-trust") == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
    }
    assert _job_permissions(product, "verify-trust") == {
        "contents": "read",
        "packages": "read",
    }
    assert _job_permissions(product, "promote") == {
        "contents": "read",
        "packages": "write",
    }

    release = _workflow("ndf-release-product.yml")
    assert _job_permissions(release, "verify-trust") == {
        "contents": "read",
        "packages": "read",
    }
    assert _job_permissions(release, "release") == {
        "contents": "read",
        "packages": "write",
    }


def test_pdd_signing_isolated_from_publication_and_consumer_permissions():
    publication = _workflow("ndf-publish-product-deployment-descriptor.yml")
    assert _job_permissions(publication, "publish") == {
        "actions": "read",
        "contents": "read",
        "packages": "write",
    }
    assert _job_permissions(publication, "sign-pdd") == {
        "actions": "read",
        "contents": "read",
        "packages": "write",
        "id-token": "write",
    }

    consumer = _workflow("ndf-fetch-product-deployment-descriptor.yml")
    assert "id-token: write" not in consumer
    assert "packages: write" not in consumer


def test_attempt_scoped_artifacts_bind_run_and_attempt_across_candidate_stages():
    candidate = _workflow("ndf-build-candidate.yml")
    candidate_build = _workflow("ndf-reusable-build-candidate.yml")
    candidate_pdd = _workflow("ndf-reusable-pdd-candidate.yml")
    expected_names = (
        "ndf-candidate-origin-${{ github.run_id }}-${{ github.run_attempt }}",
        "ndf-candidate-prepared-${{ github.run_id }}-${{ github.run_attempt }}",
        "ndf-candidate-build-${{ github.run_id }}-${{ github.run_attempt }}",
        "ndf-candidate-pdd-${{ github.run_id }}-${{ github.run_attempt }}",
        "ndf-candidate-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
    )
    combined = candidate + candidate_build + candidate_pdd
    for name in expected_names:
        assert name in combined

    writer = (
        ROOT / "images" / "ndf" / "scripts" / "write_deployment_build_result.py"
    ).read_text(encoding="utf-8")
    assert 'f"ndf-{run_id}-{run_attempt}"' in writer


def test_product_pdd_and_release_evidence_artifacts_are_attempt_scoped():
    product = _workflow("ndf-publish-product.yml")
    pdd = _workflow("ndf-publish-product-deployment-descriptor.yml")
    consumer = _workflow("ndf-fetch-product-deployment-descriptor.yml")
    release = _workflow("ndf-release-product.yml")

    for prefix in (
        "ndf-publish-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}",
        "ndf-cosign-sign-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}",
        "ndf-cosign-verify-${{ matrix.image }}-${{ github.run_id }}-${{ github.run_attempt }}",
    ):
        assert prefix in product
    assert (
        "ndf-pdd-signing-input-${{ inputs.build_run_id }}-${{ github.run_attempt }}"
        in pdd
    )
    assert (
        "ndf-pdd-publication-${{ inputs.build_run_id }}-${{ github.run_attempt }}"
        in pdd
    )
    assert (
        "ndf-pdd-consumer-${{ inputs.publication_run_id }}-${{ github.run_attempt }}"
        in consumer
    )
    assert "ndf-release-trust-${{ github.run_id }}-${{ github.run_attempt }}" in release


def test_candidate_origin_policy_remains_provisional_and_unconfirmed():
    policy = json.loads(
        (POLICIES / "dt-master-candidate-origin-identity-policy-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert policy["status"] == "provisional_until_live_certificate_observation"
    assert policy["verification"]["required_repository"] == "NdfTechLabs/dt_master"
    assert policy["verification"]["required_ref"] == "refs/heads/main"
    assert policy["verification"]["required_event_name"] is None
    assert policy["identity"] == {
        "certificate_identity": None,
        "workflow_path": None,
        "workflow_ref": None,
    }
