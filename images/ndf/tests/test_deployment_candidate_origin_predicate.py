import json
from pathlib import Path

import pytest

from scripts import artifact_trust


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "images"
    / "ndf"
    / "schemas"
    / "deployment-candidate-origin-predicate-v1.schema.json"
)


def _predicate():
    return {
        "schema_version": "1.0.0",
        "candidate_id": "candidate-example",
        "candidate_artifact": {
            "repository": "ghcr.io/ndftechlabs/deployment-candidates",
            "digest": "sha256:" + "a" * 64,
        },
        "candidate_payload_sha256": "b" * 64,
        "producer": {
            "repository": "NdfTechLabs/dt_master",
            "workflow_path": ".github/workflows/publish-deployment-candidate.yml",
            "workflow_ref": (
                "NdfTechLabs/dt_master/.github/workflows/"
                "publish-deployment-candidate.yml@refs/heads/main"
            ),
            "source_commit": "c" * 40,
        },
        "workflow_run": {"run_id": "123456789", "run_attempt": 1},
        "correlation_id": None,
    }


def test_candidate_origin_predicate_schema_accepts_complete_v1_claims():
    artifact_trust._validate_schema(
        _predicate(), SCHEMA_PATH, "deployment candidate origin predicate"
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("candidate_payload_sha256",), "not-a-sha256"),
        (("candidate_artifact", "digest"), "sha256:BAD"),
        (("producer", "source_commit"), "short"),
        (("workflow_run", "run_attempt"), 0),
        (("correlation_id",), 17),
    ],
)
def test_candidate_origin_predicate_schema_rejects_malformed_claims(path, value):
    predicate = _predicate()
    target = predicate
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(Exception):
        artifact_trust._validate_schema(
            predicate, SCHEMA_PATH, "deployment candidate origin predicate"
        )


def test_candidate_origin_predicate_schema_rejects_unknown_fields():
    predicate = _predicate()
    predicate["ndf_signed_by"] = "NDF"
    with pytest.raises(Exception):
        artifact_trust._validate_schema(
            predicate, SCHEMA_PATH, "deployment candidate origin predicate"
        )


def test_candidate_origin_schema_id_matches_predicate_documentation():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$id"] == (
        "https://ndftechlabs.com/schemas/"
        "deployment-candidate-origin-predicate-v1.schema.json"
    )
