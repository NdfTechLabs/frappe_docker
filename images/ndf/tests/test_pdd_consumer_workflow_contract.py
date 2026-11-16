from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = (
    ROOT / ".github" / "workflows" / "ndf-fetch-product-deployment-descriptor.yml"
)


def read_workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_consumer_workflow_retains_read_only_permissions():
    workflow = read_workflow()
    top_level = workflow.split("\njobs:\n", 1)[0]
    assert (
        "permissions:\n  actions: read\n  contents: read\n  packages: read" in top_level
    )
    assert "id-token: write" not in workflow
    assert "packages: write" not in workflow
    assert "contents: write" not in workflow
    assert "actions: write" not in workflow


def test_consumer_invokes_full_trust_verification_with_explicit_evidence_paths():
    workflow = read_workflow()
    step = workflow.split("name: Independently verify PDD and source image trust", 1)[
        1
    ].split("\n      - name:", 1)[0]
    assert "fetch_product_deployment_descriptor.py" in step
    assert "--publication-record" in step
    assert "--output-dir" in step
    assert "--pdd-trust-result-output" in step
    assert "--pdd-attestation-output" in step
    assert "--image-trust-result-output" in step
    assert "--image-attestation-output" in step
    assert "--consumer-report-output" in step
    assert "--skip-image-binding" not in step


def test_consumer_workflow_distinguishes_exit_two_from_technical_failure():
    workflow = read_workflow()
    step = workflow.split("name: Independently verify PDD and source image trust", 1)[
        1
    ].split("\n      - name:", 1)[0]
    assert "verification_status=$?" in step
    assert '"$verification_status" -ne 0 && "$verification_status" -ne 2' in step
    assert 'exit "$verification_status"' in step
    assert "if exit_code == 0:" in step
    assert 'outcome = "trusted"' in step
    assert 'outcome = "provisional_rejected"' in step
    assert 'policy_status == "confirmed"' in step
    assert 'policy_status == "provisional_until_live_certificate_observation"' in step
    assert 'expected_reason = ["IDENTITY_POLICY_PROVISIONAL"]' in step
    assert 'report.get("deployment_authorization") != "not_granted"' in step
    assert "required_stages = (" in step
    assert '"signature_verified"' in step
    assert '"signer_verified"' in step
    assert '"transparency_verified"' in step
    assert 'report.get("pdd", {}).get("trust_reason_codes") == []' in step


def test_consumer_workflow_requires_complete_report_and_all_second_pass_outputs():
    workflow = read_workflow()
    step = workflow.split("name: Independently verify PDD and source image trust", 1)[
        1
    ].split("\n      - name:", 1)[0]
    for output in (
        "pdd-consumer-verification-report.json",
        "pdd-trust-result.json",
        "pdd-verified-attestation.json",
        "image-trust-result.json",
        "image-verified-attestation.json",
    ):
        assert output in step
    assert 'test -s "$REPORT_PATH"' in step
    assert 'test -s "$PDD_RESULT_PATH"' in step
    assert 'test -s "$PDD_ATTESTATION_PATH"' in step
    assert 'test -s "$IMAGE_RESULT_PATH"' in step
    assert 'test -s "$IMAGE_ATTESTATION_PATH"' in step


def test_consumer_artifact_upload_runs_even_after_verification_failure():
    workflow = read_workflow()
    upload = workflow.split(
        "name: Upload retrieved PDD and independent trust evidence", 1
    )[1].split("\n      - name:", 1)[0]
    assert "if: always()" in upload
    assert "${{ env.RECEIPT_DIR }}" in upload
    assert "${{ env.OUTPUT_DIR }}" in upload
    assert "${{ runner.temp }}/pdd-consumer-cli-output.json" in upload
    assert "if-no-files-found: warn" in upload
    assert "retention-days: 90" in upload


def test_consumer_summary_explicitly_labels_provisional_rejection_and_no_authorization():
    workflow = read_workflow()
    summary = workflow.split("name: Write consumer verification summary", 1)[1]
    assert "if: always()" in summary
    assert 'decision["status"] == "rejected"' in summary
    assert "REJECTED — cryptographic and evidence checks completed" in summary
    assert "This result is not trusted and does not authorize deployment." in summary
    assert (
        "Deployment authorization: **{report['deployment_authorization']}**" in summary
    )
    assert "remains not granted by this workflow" in summary


def test_consumer_workflow_requires_artifact_decisions_to_match_exit_policy():
    workflow = read_workflow()
    step = workflow.split("name: Independently verify PDD and source image trust", 1)[
        1
    ].split("\n      - name:", 1)[0]
    for contract in (
        'pdd_decision == "trusted"',
        'image_decision == "trusted"',
        'pdd_decision == "rejected"',
        'image_decision == "rejected"',
        'report.get("pdd", {}).get("trust_reason_codes") == expected_reason',
        'report.get("source_image", {}).get("trust_reason_codes") == expected_reason',
        'policy_status == "confirmed"',
        'policy_status == "provisional_until_live_certificate_observation"',
        'report.get("deployment_authorization") != "not_granted"',
    ):
        assert contract in step


def test_consumer_fetch_preserves_retrieved_bundle_before_verification():
    script = (
        ROOT / "images" / "ndf" / "scripts" / "fetch_product_deployment_descriptor.py"
    ).read_text(encoding="utf-8")
    pull = script.index('"ORAS artifact pull"')
    preserve = script.index("_preserve_pulled_bundle(pulled_dir, output_dir)")
    binding = script.index("binding = verify_product_deployment_binding(")
    trust = script.index("_verify_independent_consumer_trust(")
    assert pull < preserve < binding < trust
    assert "if item.is_symlink():" in script
    assert (
        "shutil.copytree(pulled_dir, output_dir, dirs_exist_ok=True, symlinks=False)"
        in script
    )
    assert "_validate_image_source_identity(descriptor, workflow)" in script
    assert '"image_source_sha_verified": True' in script

