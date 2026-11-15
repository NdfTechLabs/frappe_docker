import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import generate_image_provenance as provenance


def _workflow_env():
    return {
        "GITHUB_REPOSITORY": "NdfTechLabs/frappe_docker",
        "GITHUB_WORKFLOW_REF": (
            "NdfTechLabs/frappe_docker/"
            ".github/workflows/ndf-publish-product.yml@refs/heads/main"
        ),
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ID": "43740127333",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_SHA": "a" * 40,
    }


def test_workflow_context_uses_exact_github_runtime_identity():
    result = provenance._workflow_context(_workflow_env())
    assert result == {
        "repository": "NdfTechLabs/frappe_docker",
        "path": ".github/workflows/ndf-publish-product.yml",
        "ref": "refs/heads/main",
        "run_id": "43740127333",
        "run_attempt": 2,
        "source_commit": "a" * 40,
    }


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_REPOSITORY", "someone/else"),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_EVENT_NAME", "push"),
        (
            "GITHUB_WORKFLOW_REF",
            "NdfTechLabs/frappe_docker/.github/workflows/other.yml@refs/heads/main",
        ),
        ("GITHUB_RUN_ID", "run-1"),
        ("GITHUB_RUN_ATTEMPT", "0"),
        ("GITHUB_SHA", "not-a-commit"),
    ],
)
def test_workflow_context_rejects_unapproved_or_malformed_claims(key, value):
    env = _workflow_env()
    env[key] = value
    with pytest.raises(provenance.ImageProvenanceError):
        provenance._workflow_context(env)


def test_workflow_context_rejects_missing_runtime_claims():
    env = _workflow_env()
    del env["GITHUB_RUN_ID"]
    with pytest.raises(provenance.ImageProvenanceError, match="GITHUB_RUN_ID"):
        provenance._workflow_context(env)


def _source_inputs():
    inventory = {
        "framework": {
            "name": "frappe",
            "repository": "frappe/frappe",
            "actual_commit": "1" * 40,
        },
        "applications": [
            {
                "name": "frappe",
                "repository": "frappe/frappe",
                "actual_commit": "1" * 40,
            },
            {
                "name": "erpnext",
                "repository": "frappe/erpnext",
                "actual_commit": "2" * 40,
            },
        ],
    }
    provenance_report = {
        "repositories": [
            {"name": "frappe", "repository": "frappe/frappe", "actual_commit": "1" * 40},
            {"name": "erpnext", "repository": "frappe/erpnext", "actual_commit": "2" * 40},
        ]
    }
    verification = {
        "repositories": [
            {
                "name": "frappe",
                "repository": "frappe/frappe",
                "actual_commit": "1" * 40,
                "status": "verified",
            },
            {
                "name": "erpnext",
                "repository": "frappe/erpnext",
                "actual_commit": "2" * 40,
                "status": "verified",
            },
        ]
    }
    return inventory, provenance_report, verification


def test_source_revisions_are_derived_from_matching_acquired_commits():
    inventory, source, verification = _source_inputs()
    assert provenance._source_revisions(inventory, source, verification) == [
        {"repository": "frappe/erpnext", "commit": "2" * 40},
        {"repository": "frappe/frappe", "commit": "1" * 40},
    ]


def test_source_revisions_reject_inventory_and_provenance_commit_disagreement():
    inventory, source, verification = _source_inputs()
    source["repositories"][0]["actual_commit"] = "3" * 40
    with pytest.raises(provenance.ImageProvenanceError, match="mismatch"):
        provenance._source_revisions(inventory, source, verification)


def test_source_revisions_reject_unverified_repository():
    inventory, source, verification = _source_inputs()
    verification["repositories"][1]["status"] = "failed"
    with pytest.raises(provenance.ImageProvenanceError, match="Independent source verification"):
        provenance._source_revisions(inventory, source, verification)


def test_json_loader_rejects_duplicate_keys_and_non_finite_values(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"status":"passed","status":"failed"}', encoding="utf-8")
    with pytest.raises(provenance.ImageProvenanceError, match="Duplicate"):
        provenance.load_json(path)

    path.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(provenance.ImageProvenanceError, match="Non-finite"):
        provenance.load_json(path)


def test_atomic_write_creates_exact_bytes_and_refuses_symlink(tmp_path):
    output = tmp_path / "report.json"
    provenance._atomic_write(output, b'{"ok":true}\n')
    assert output.read_bytes() == b'{"ok":true}\n'

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(provenance.ImageProvenanceError, match="symlink"):
        provenance._atomic_write(link, b'{"bad":true}\n')


def test_schema_accepts_profile_statement_shape():
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "ghcr.io/ndftechlabs/dalali", "digest": {"sha256": "a" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://ndftechlabs.com/buildtypes/frappe-docker-image/v1",
                "externalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": "https://github.com/frappe/frappe",
                        "digest": {"gitCommit": "b" * 40},
                        "name": "frappe/frappe",
                    }
                ],
            },
            "runDetails": {"builder": {"id": "https://github.com/NdfTechLabs/frappe_docker/actions"}},
            "ndf_build": {
                "schema_version": "1.0.0",
                "product_id": "dalali-v16",
                "platform": "linux/amd64",
                "workflow": {
                    "repository": "NdfTechLabs/frappe_docker",
                    "path": ".github/workflows/ndf-publish-product.yml",
                    "ref": "refs/heads/main",
                    "run_id": "123",
                    "run_attempt": 1,
                    "source_commit": "c" * 40,
                },
                "lock_sha256": "d" * 64,
                "composition_sha256": "e" * 64,
                "source_revisions": [{"repository": "frappe/frappe", "commit": "b" * 40}],
                "validation": {
                    "image_validation": {"status": "passed", "report_sha256": "1" * 64},
                    "source_provenance": {"status": "passed", "report_sha256": "2" * 64},
                    "composition_verification": {"status": "passed", "report_sha256": "3" * 64},
                    "evidence_binding": {"status": "passed", "report_sha256": "4" * 64},
                },
            },
        },
    }
    schema = json.loads(provenance.PROVENANCE_SCHEMA.read_text(encoding="utf-8"))
    provenance.Draft202012Validator(schema).validate(statement)
