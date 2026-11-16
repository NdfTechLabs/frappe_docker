from pathlib import Path
import re


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPOSITORY_ROOT / ".github" / "workflows"


def _job_block(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\\n(.*?)(?=^  [a-z][a-z0-9-]*:\\n|\\Z)",
        workflow,
    )
    assert match is not None, f"Missing workflow job: {job_name}"
    return match.group(1)


def test_product_publication_separates_build_sign_verify_and_promotion():
    workflow = (WORKFLOWS / "ndf-publish-product.yml").read_text(encoding="utf-8")
    build = _job_block(workflow, "build-validate")
    sign = _job_block(workflow, "sign-trust")
    verify = _job_block(workflow, "verify-trust")
    promote = _job_block(workflow, "promote")

    assert "imagetools create" not in build
    assert "id-token: write" in sign
    assert "imagetools create" not in sign
    assert "packages: read" in verify
    assert "id-token: write" not in verify
    assert "--self-contained" in verify
    assert "--expected-product-id" in verify
    assert "--expected-source-commit" in verify
    assert "imagetools create" not in verify
    assert "needs: [prepare, build-validate, verify-trust]" in promote
    assert "decision" in promote and '"trusted"' in promote
    assert "packages: write" in promote
    assert "id-token: write" not in promote


def test_product_promotion_is_conditioned_on_independent_trust_job():
    workflow = (WORKFLOWS / "ndf-publish-product.yml").read_text(encoding="utf-8")
    promote = _job_block(workflow, "promote")

    assert "inputs.publish" in promote
    assert "needs.verify-trust.result == 'success'" in promote


def test_release_workflow_verifies_trust_before_any_tag_promotion():
    workflow = (WORKFLOWS / "ndf-release-product.yml").read_text(encoding="utf-8")
    verify = _job_block(workflow, "verify-trust")
    release = _job_block(workflow, "release")

    assert "packages: read" in verify
    assert "packages: write" not in verify
    assert "id-token: write" not in verify
    assert "--self-contained" in verify
    assert "--expected-product-id" in verify
    assert "--expected-source-commit" in verify
    assert "imagetools create" not in verify

    assert "needs: verify-trust" in release
    assert "packages: write" in release
    assert "id-token: write" not in release
    assert "SOURCE_DIGEST" in release
    assert "Source tag changed after trust verification" in release
    assert "imagetools create" in release
