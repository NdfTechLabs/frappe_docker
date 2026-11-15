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
    with pytest.raises(
        provenance.ImageProvenanceError, match="Independent source verification"
    ):
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
        "subject": [
            {"name": "ghcr.io/ndftechlabs/dalali", "digest": {"sha256": "a" * 64}}
        ],
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
            "runDetails": {
                "builder": {
                    "id": "https://github.com/NdfTechLabs/frappe_docker/actions"
                }
            },
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
                "source_revisions": [
                    {"repository": "frappe/frappe", "commit": "b" * 40}
                ],
                "validation": {
                    "image_validation": {"status": "passed", "report_sha256": "1" * 64},
                    "source_provenance": {
                        "status": "passed",
                        "report_sha256": "2" * 64,
                    },
                    "composition_verification": {
                        "status": "passed",
                        "report_sha256": "3" * 64,
                    },
                    "evidence_binding": {"status": "passed", "report_sha256": "4" * 64},
                },
            },
        },
    }
    schema = json.loads(provenance.PROVENANCE_SCHEMA.read_text(encoding="utf-8"))
    provenance.Draft202012Validator(schema).validate(statement)


@pytest.fixture
def synthetic_build(tmp_path, monkeypatch):
    build = tmp_path / "build"
    build.mkdir()
    lock_bytes = b'{"lock_version":2,"product":{"id":"dalali-v16"}}\n'
    lock_sha = provenance.sha256(lock_bytes)
    digest = "sha256:" + "a" * 64
    candidate_ref = "ghcr.io/ndftechlabs/dalali:candidate-123-1"
    publication_ref = "ghcr.io/ndftechlabs/dalali:v16-" + "b" * 40

    def write(name, value):
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        (build / name).write_bytes(raw)
        return raw

    (build / "dalali-v16.lock-v2.json").write_bytes(lock_bytes)
    inventory = {
        "schema_version": "1.0",
        "stage": "builder",
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
        "runtime": {"platform": {"oci": "linux/amd64"}},
        "lock": {"sha256": lock_sha},
    }
    provenance_report = {
        "algorithm": "ndf-source-provenance-v1",
        "lock": {"sha256": lock_sha},
        "repositories": [
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
    source_verification = {
        "status": "passed",
        "source_provenance_sha256": None,
        "lock": {"sha256": lock_sha},
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
        ],
    }
    provenance_raw = write("source-provenance.json", provenance_report)
    source_verification["source_provenance_sha256"] = provenance.sha256(provenance_raw)
    write("source-provenance-verification.json", source_verification)
    write("build-inventory.json", inventory)
    composition = {
        "status": "passed",
        "lock": {"sha256": lock_sha},
        "composition": ["frappe", "erpnext"],
    }
    write("image-composition-verification.json", composition)
    write("image-validation.json", {"status": "passed", "image_digest": digest})
    evidence = {
        "status": "bound",
        "image": {"digest": digest},
        "lock": {"sha256": lock_sha},
    }
    write("image-verification-evidence.json", evidence)
    write(
        "build-metadata.json",
        {
            "image": {"id": "dalali-v16", "repository": "ghcr.io/ndftechlabs/dalali"},
            "framework": {"version": "16.35.0"},
            "lock": {"sha256": lock_sha},
        },
    )
    write("buildx-metadata.json", {"containerimage.digest": digest})
    write("build-result.json", {"digest": digest})
    gate = {
        "status": "ready",
        "image": {
            "id": "dalali-v16",
            "repository": "ghcr.io/ndftechlabs/dalali",
            "digest": digest,
            "candidate_reference": candidate_ref,
            "publication_reference": publication_ref,
        },
        "source": {"sha": "c" * 40},
        "lock": {"sha256": lock_sha},
    }
    write("publication-gate.json", gate)
    monkeypatch.setattr(
        provenance,
        "verify_publication_candidate",
        lambda **kwargs: gate,
    )
    return {
        "build": build,
        "gate": gate,
        "candidate_ref": candidate_ref,
        "publication_ref": publication_ref,
        "env": {
            **_workflow_env(),
            "GITHUB_SHA": "c" * 40,
        },
    }


def test_generate_provenance_emits_deterministic_predicate_and_statement(
    synthetic_build, tmp_path
):
    build = synthetic_build
    first_predicate = tmp_path / "first-predicate.json"
    first_statement = tmp_path / "first-statement.json"
    first = provenance.generate_image_provenance(
        build_output_dir=build["build"],
        image_id="dalali-v16",
        framework_major="16",
        candidate_image_ref=build["candidate_ref"],
        publication_image_ref=build["publication_ref"],
        predicate_output=first_predicate,
        statement_output=first_statement,
        env=build["env"],
    )

    second_predicate = tmp_path / "second-predicate.json"
    second_statement = tmp_path / "second-statement.json"
    second = provenance.generate_image_provenance(
        build_output_dir=build["build"],
        image_id="dalali-v16",
        framework_major="16",
        candidate_image_ref=build["candidate_ref"],
        publication_image_ref=build["publication_ref"],
        predicate_output=second_predicate,
        statement_output=second_statement,
        env=build["env"],
    )

    assert first_predicate.read_bytes() == second_predicate.read_bytes()
    assert first_statement.read_bytes() == second_statement.read_bytes()
    assert first["predicate_sha256"] == second["predicate_sha256"]
    assert first["statement_sha256"] == second["statement_sha256"]

    statement = json.loads(first_statement.read_text(encoding="utf-8"))
    assert statement["subject"][0]["digest"]["sha256"] == "a" * 64
    assert statement["predicate"]["ndf_build"][
        "composition_sha256"
    ] == provenance.sha256(
        (build["build"] / "image-composition-verification.json").read_bytes()
    )
    assert statement["predicate"]["ndf_build"]["source_revisions"] == [
        {"repository": "frappe/erpnext", "commit": "2" * 40},
        {"repository": "frappe/frappe", "commit": "1" * 40},
    ]


def test_generate_provenance_rejects_publication_gate_source_mismatch(
    synthetic_build, tmp_path, monkeypatch
):
    build = synthetic_build
    gate = dict(build["gate"])
    gate["source"] = {"sha": "d" * 40}
    monkeypatch.setattr(
        provenance, "verify_publication_candidate", lambda **kwargs: gate
    )
    (build["build"] / "publication-gate.json").write_text(
        json.dumps(gate), encoding="utf-8"
    )
    with pytest.raises(provenance.ImageProvenanceError, match="source SHA"):
        provenance.generate_image_provenance(
            build_output_dir=build["build"],
            image_id="dalali-v16",
            framework_major="16",
            candidate_image_ref=build["candidate_ref"],
            publication_image_ref=build["publication_ref"],
            predicate_output=tmp_path / "predicate.json",
            statement_output=tmp_path / "statement.json",
            env=build["env"],
        )
