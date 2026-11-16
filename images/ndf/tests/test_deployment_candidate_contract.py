from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

try:
    from scripts import intake_deployment_candidate as intake
except ImportError:
    from images.ndf.scripts import intake_deployment_candidate as intake

NDF = Path(__file__).resolve().parents[1]
SCHEMAS = NDF / "schemas"
FIXTURES = NDF / "fixtures" / "candidates"
CANDIDATE_ID = "CAND-2026-00042"
MANIFEST_DIGEST = "a" * 64
REFERENCE = f"{intake.CANDIDATE_REPOSITORY}@sha256:{MANIFEST_DIGEST}"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def payload_bytes() -> bytes:
    return (FIXTURES / "valid" / "candidate-v1.json").read_bytes()


def payload_hash(raw: bytes | None = None) -> str:
    return hashlib.sha256(raw if raw is not None else payload_bytes()).hexdigest()


def manifest_response(
    raw: bytes | None = None,
    *,
    candidate_id: str = CANDIDATE_ID,
    payload_sha: str | None = None,
) -> dict:
    data = raw if raw is not None else payload_bytes()
    return {
        "digest": f"sha256:{MANIFEST_DIGEST}",
        "content": {
            "schemaVersion": 2,
            "mediaType": intake.OCI_MANIFEST_MEDIA_TYPE,
            "artifactType": intake.ARTIFACT_TYPE,
            "config": {
                "mediaType": intake.EMPTY_CONFIG_MEDIA_TYPE,
                "digest": intake.EMPTY_CONFIG_DIGEST,
                "size": len(intake.EMPTY_CONFIG_BYTES),
            },
            "layers": [
                {
                    "mediaType": intake.CANDIDATE_MEDIA_TYPE,
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "annotations": {
                        "org.opencontainers.image.title": intake.LAYER_TITLE
                    },
                }
            ],
            "annotations": {
                intake.ANNOTATION_CANDIDATE_ID: candidate_id,
                intake.ANNOTATION_SCHEMA_VERSION: "1.0.0",
                intake.ANNOTATION_PAYLOAD_SHA256: payload_sha or payload_hash(data),
            },
        },
    }


def test_candidate_schema_and_fixture_are_valid():
    schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    Draft202012Validator.check_schema(schema)
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    assert not list(Draft202012Validator(schema).iter_errors(candidate))
    assert (
        intake.validate_candidate_payload(
            payload_bytes(),
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(),
        )
        == candidate
    )


@pytest.mark.parametrize(
    "reference",
    [
        f"{intake.CANDIDATE_REPOSITORY}:latest",
        intake.CANDIDATE_REPOSITORY,
        "https://ghcr.io/ndftechlabs/dt-master-deployment-candidates@sha256:"
        + "a" * 64,
        "ghcr.io/other/dt-master-deployment-candidates@sha256:" + "a" * 64,
        "ghcr.io/ndftechlabs/other@sha256:" + "a" * 64,
        f"{intake.CANDIDATE_REPOSITORY}@sha256:" + "A" * 64,
        f"{intake.CANDIDATE_REPOSITORY}@sha256:" + "a" * 63,
        f"{intake.CANDIDATE_REPOSITORY}@sha256:" + "a" * 64 + "?x=1",
        f"{intake.CANDIDATE_REPOSITORY}/../other@sha256:" + "a" * 64,
        f" {REFERENCE}",
    ],
)
def test_reference_parser_rejects_mutable_or_foreign_references(reference):
    with pytest.raises(intake.CandidateIntakeError):
        intake.parse_candidate_reference(reference)


def test_reference_parser_accepts_only_digest_pinned_allowlisted_reference():
    assert intake.parse_candidate_reference(REFERENCE) == "sha256:" + MANIFEST_DIGEST


def test_manifest_accepts_exact_artifact_layout():
    layer = intake.validate_manifest_response(
        manifest_response(),
        reference=REFERENCE,
        candidate_id=CANDIDATE_ID,
        payload_sha256=payload_hash(),
    )
    assert layer["mediaType"] == intake.CANDIDATE_MEDIA_TYPE


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update({"digest": "sha256:" + "b" * 64}),
        lambda m: m["content"].update(
            {"artifactType": "application/vnd.example.other"}
        ),
        lambda m: m["content"].update({"schemaVersion": 1}),
        lambda m: m["content"].update({"mediaType": "application/json"}),
        lambda m: m["content"].update(
            {
                "config": {
                    "mediaType": "application/json",
                    "digest": intake.EMPTY_CONFIG_DIGEST,
                    "size": 2,
                }
            }
        ),
        lambda m: m["content"].update({"layers": []}),
        lambda m: m["content"].update({"layers": m["content"]["layers"] * 2}),
        lambda m: m["content"]["layers"][0].update({"mediaType": "application/json"}),
        lambda m: m["content"]["layers"][0].update({"size": 0}),
        lambda m: m["content"]["layers"][0]["annotations"].update(
            {"org.opencontainers.image.title": "../candidate.json"}
        ),
        lambda m: m["content"]["annotations"].update(
            {intake.ANNOTATION_CANDIDATE_ID: "OTHER"}
        ),
        lambda m: m["content"]["annotations"].update(
            {intake.ANNOTATION_SCHEMA_VERSION: "2.0.0"}
        ),
        lambda m: m["content"]["annotations"].update(
            {intake.ANNOTATION_PAYLOAD_SHA256: "0" * 64}
        ),
    ],
)
def test_manifest_rejects_incorrect_oci_layout_and_annotations(mutate):
    manifest = manifest_response()
    mutate(manifest)
    with pytest.raises(intake.CandidateIntakeError):
        intake.validate_manifest_response(
            manifest,
            reference=REFERENCE,
            candidate_id=CANDIDATE_ID,
            payload_sha256=payload_hash(),
        )


def test_payload_rejects_dispatch_hash_mismatch():
    with pytest.raises(intake.CandidateIntakeError, match="SHA-256"):
        intake.validate_candidate_payload(
            payload_bytes(),
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256="0" * 64,
        )


def test_payload_rejects_duplicate_json_keys():
    raw = b'{"candidate_id":"first","candidate_id":"second"}'
    with pytest.raises(intake.CandidateIntakeError, match="duplicate key"):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_candidate_id_mismatch():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["candidate_id"] = "OTHER"
    raw = json.dumps(candidate).encode()
    with pytest.raises(intake.CandidateIntakeError, match="Candidate ID"):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_schema_violation_and_sensitive_extra_fields():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["database_password"] = "must-not-be-accepted"
    raw = json.dumps(candidate).encode()
    with pytest.raises(intake.CandidateIntakeError, match="schema"):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_duplicate_application_ids():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["applications"].append(dict(candidate["applications"][0]))
    raw = json.dumps(candidate).encode()
    with pytest.raises(intake.CandidateIntakeError, match="duplicate application"):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_descriptor_reference_digest_mismatch():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["applications"][0]["descriptor_ref"] += "0"
    raw = json.dumps(candidate).encode()
    with pytest.raises(intake.CandidateIntakeError, match="reference and digest"):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_mutable_application_commit():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["applications"][0]["immutable_commit"] = "version-16"
    raw = json.dumps(candidate).encode()
    with pytest.raises(
        intake.CandidateIntakeError, match="immutable_commit.*does not match"
    ):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_product_not_in_ndf_image_inventory():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["product"]["id"] = "unknown-product"
    raw = json.dumps(candidate).encode()
    with pytest.raises(
        intake.CandidateIntakeError, match="not present in the NDF image inventory"
    ):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_framework_version_outside_product_manifest():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["framework_version"] = "17"
    raw = json.dumps(candidate).encode()
    with pytest.raises(
        intake.CandidateIntakeError, match="does not match product manifest"
    ):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("python", "3.13.9", "CPython 3.14 family"),
        ("node", "22.12.0", "Node.js runtime"),
    ],
)
def test_payload_rejects_unsupported_runtime_family(field, value, message):
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["runtime_profile"][field] = value
    raw = json.dumps(candidate).encode()
    with pytest.raises(intake.CandidateIntakeError, match=message):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_payload_rejects_unverified_arm64_target():
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["target_platforms"] = ["linux/arm64"]
    raw = json.dumps(candidate).encode()
    with pytest.raises(intake.CandidateIntakeError, match="only linux/amd64"):
        intake.validate_candidate_payload(
            raw,
            expected_candidate_id=CANDIDATE_ID,
            expected_payload_sha256=payload_hash(raw),
        )


def test_result_schema_requires_image_and_descriptor_for_success():
    schema = load(SCHEMAS / "deployment-build-result-v1.schema.json")
    result = {
        "schema_version": "1.0.0",
        "result_id": "run-123",
        "candidate_id": CANDIDATE_ID,
        "candidate_artifact_ref": REFERENCE,
        "candidate_artifact_digest": "sha256:" + MANIFEST_DIGEST,
        "workflow": {
            "repository": "NdfTechLabs/frappe_docker",
            "workflow_name": "candidate",
            "run_id": "123",
            "source_commit": "c" * 40,
        },
        "status": "succeeded",
        "composition_hash": "b" * 64,
        "started_at": "2026-11-14T10:00:00Z",
    }
    assert list(Draft202012Validator(schema).iter_errors(result))


def test_intake_uses_digest_pinned_reference_and_writes_verified_payload(
    tmp_path, monkeypatch
):
    raw = payload_bytes()
    pulled_dir = None
    calls = []

    def fake_run(command, *, timeout):
        nonlocal pulled_dir
        calls.append(command)
        if command[1:4] == ["manifest", "fetch", "--format"]:
            return subprocess.CompletedProcess(
                command, 0, json.dumps(manifest_response(raw)).encode(), b""
            )
        if command[1] == "pull":
            pulled_dir = Path(command[command.index("--output") + 1])
            (pulled_dir / intake.LAYER_TITLE).write_bytes(raw)
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"reference": REFERENCE}).encode(), b""
            )
        raise AssertionError(command)

    monkeypatch.setattr(intake, "_run", fake_run)
    output = tmp_path / "candidate.json"
    report = intake.intake_candidate(
        candidate_id=CANDIDATE_ID,
        artifact_reference=REFERENCE,
        payload_sha256=payload_hash(raw),
        output_path=output,
    )
    assert report["status"] == "validated"
    assert output.read_bytes() == raw
    assert calls[0][-1] == REFERENCE
    assert calls[1][-1] == REFERENCE


def test_intake_rejects_layer_tampering_before_payload_validation(
    tmp_path, monkeypatch
):
    raw = payload_bytes()
    tampered = raw + b" "

    def fake_run(command, *, timeout):
        if command[1] == "manifest":
            return subprocess.CompletedProcess(
                command, 0, json.dumps(manifest_response(raw)).encode(), b""
            )
        if command[1] == "pull":
            pulled_dir = Path(command[command.index("--output") + 1])
            (pulled_dir / intake.LAYER_TITLE).write_bytes(tampered)
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"reference": REFERENCE}).encode(), b""
            )
        raise AssertionError(command)

    monkeypatch.setattr(intake, "_run", fake_run)
    with pytest.raises(intake.CandidateIntakeError, match="byte size"):
        intake.intake_candidate(
            candidate_id=CANDIDATE_ID,
            artifact_reference=REFERENCE,
            payload_sha256=payload_hash(raw),
            output_path=tmp_path / "candidate.json",
        )


def test_requested_version_is_optional_for_candidate_application():
    schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["applications"][0].pop("requested_version")
    errors = list(Draft202012Validator(schema).iter_errors(candidate))
    assert not errors


@pytest.mark.parametrize(
    "candidate_type",
    [
        "Initial",
        "Add App",
        "Remove App",
        "Upgrade App",
        "Runtime Upgrade",
        "Product Upgrade",
        "Configuration Change",
    ],
)
def test_candidate_type_matches_dt_master_select_values(candidate_type):
    schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["candidate_type"] = candidate_type
    assert not list(Draft202012Validator(schema).iter_errors(candidate))


def test_candidate_type_rejects_unregistered_values():
    schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["candidate_type"] = "product"
    assert list(Draft202012Validator(schema).iter_errors(candidate))


def test_candidate_identity_constraints_match_origin_predicate():
    payload_schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    predicate_schema = load(
        SCHEMAS / "deployment-candidate-origin-predicate-v1.schema.json"
    )
    payload_id = payload_schema["properties"]["candidate_id"]
    predicate_id = predicate_schema["properties"]["candidate_id"]
    assert payload_id == predicate_id
    assert payload_id["maxLength"] == 140
    assert payload_id["pattern"] == "^[A-Za-z0-9][A-Za-z0-9._:-]{0,139}$"


def test_candidate_id_accepts_maximum_length_and_rejects_overflow():
    schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["candidate_id"] = "A" + "a" * 139
    assert not list(Draft202012Validator(schema).iter_errors(candidate))
    candidate["candidate_id"] += "a"
    assert list(Draft202012Validator(schema).iter_errors(candidate))


def test_origin_predicate_requires_canonical_uuid_correlation_id():
    schema = load(
        SCHEMAS / "deployment-candidate-origin-predicate-v1.schema.json"
    )
    assert schema["properties"]["correlation_id"] == {
        "type": "string",
        "format": "uuid",
    }
    assert "correlation_id" in schema["required"]


def test_trust_evidence_report_schema_is_valid():
    schema = load(SCHEMAS / "deployment-build-trust-evidence-v1.schema.json")
    Draft202012Validator.check_schema(schema)


def test_product_release_is_required_by_dt_master_candidate_contract():
    schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["product"].pop("release")
    assert list(Draft202012Validator(schema).iter_errors(candidate))


def test_optional_master_projection_fields_use_empty_values_not_fabricated_data():
    schema = load(SCHEMAS / "deployment-candidate-v1.schema.json")
    candidate = load(FIXTURES / "valid" / "candidate-v1.json")
    candidate["optional_capabilities"] = []
    candidate["runtime_constraints"] = {}
    candidate["approved_build_parameters"] = {}
    candidate["provenance_refs"] = []
    assert not list(Draft202012Validator(schema).iter_errors(candidate))
