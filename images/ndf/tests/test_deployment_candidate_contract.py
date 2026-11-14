import json
import re
from pathlib import Path
from jsonschema import Draft202012Validator

NDF=Path(__file__).resolve().parents[1]
SCHEMAS=NDF/"schemas"
FIXTURES=NDF/"fixtures"/"candidates"
REF=re.compile(r"^ghcr\.io/ndftechlabs/dt-master-deployment-candidates@sha256:[a-f0-9]{64}$")

def load(path):
    return json.loads(path.read_text(encoding="utf-8"))

def test_valid_candidate_fixture_conforms():
    schema=load(SCHEMAS/"deployment-candidate-v1.schema.json")
    Draft202012Validator.check_schema(schema)
    assert not list(Draft202012Validator(schema).iter_errors(load(FIXTURES/"valid"/"candidate-v1.json")))

def test_candidate_rejects_unrecognized_sensitive_fields():
    schema=load(SCHEMAS/"deployment-candidate-v1.schema.json")
    candidate=load(FIXTURES/"valid"/"candidate-v1.json")
    candidate["database_password"]="forbidden"
    assert list(Draft202012Validator(schema).iter_errors(candidate))

def test_candidate_rejects_missing_descriptor_digest_and_mutable_commit():
    schema=load(SCHEMAS/"deployment-candidate-v1.schema.json")
    candidate=load(FIXTURES/"valid"/"candidate-v1.json")
    del candidate["applications"][0]["descriptor_digest"]
    assert list(Draft202012Validator(schema).iter_errors(candidate))
    candidate=load(FIXTURES/"valid"/"candidate-v1.json")
    candidate["applications"][0]["immutable_commit"]="version-16"
    assert list(Draft202012Validator(schema).iter_errors(candidate))

def test_candidate_rejects_duplicate_application_ids():
    schema=load(SCHEMAS/"deployment-candidate-v1.schema.json")
    candidate=load(FIXTURES/"valid"/"candidate-v1.json")
    candidate["applications"].append(dict(candidate["applications"][0]))
    ids=[app["app_id"] for app in candidate["applications"]]
    assert len(ids) != len(set(ids))


def test_candidate_reference_allowlist_rejects_mutable_and_foreign_references():
    refs=load(FIXTURES/"invalid-references.json")
    assert REF.fullmatch(refs["valid_reference"])
    for ref in refs["invalid_references"]:
        assert not REF.fullmatch(ref), ref

def test_result_schema_requires_image_and_descriptor_for_success():
    schema=load(SCHEMAS/"deployment-build-result-v1.schema.json")
    result={"schema_version":"1.0.0","result_id":"run-123","candidate_id":"CAND-2026-00042",
      "candidate_artifact_ref":"ghcr.io/ndftechlabs/dt-master-deployment-candidates@sha256:"+"a"*64,
      "candidate_artifact_digest":"sha256:"+"a"*64,
      "workflow":{"repository":"NdfTechLabs/frappe_docker","workflow_name":"candidate","run_id":"123","source_commit":"c"*40},
      "status":"succeeded","composition_hash":"b"*64,"started_at":"2026-11-14T10:00:00Z"}
    assert list(Draft202012Validator(schema).iter_errors(result))
