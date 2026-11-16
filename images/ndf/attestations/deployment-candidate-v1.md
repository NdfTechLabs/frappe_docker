# DT Master Deployment Candidate Origin Attestation — v1

**Predicate type:** `https://ndftechlabs.com/attestations/deployment-candidate/v1`  
**JSON Schema:** `https://ndftechlabs.com/schemas/deployment-candidate-origin-predicate-v1.schema.json`  
**Schema source:** [`images/ndf/schemas/deployment-candidate-origin-predicate-v1.schema.json`](../schemas/deployment-candidate-origin-predicate-v1.schema.json)  
**Status:** Contract draft for cross-repository implementation; producer identity values require live observation and explicit approval.

## 1. Purpose

DT Master produces deployment-candidate OCI artifacts and submits them to NDF for validation and image construction. This predicate authenticates the origin and request identity of that candidate artifact.

It does not assert that the candidate is safe to deploy, that NDF has built an image, or that deployment is authorized.

## 2. Predicate type URI

The exact in-toto `predicateType` value is:

`https://ndftechlabs.com/attestations/deployment-candidate/v1`

The URI is a stable, versioned machine identifier and the canonical browser-facing documentation address. It is not an executable API endpoint.

The intended public routes are:

- `/attestations/deployment-candidate/v1` — this human-readable specification.
- `/schemas/deployment-candidate-origin-predicate-v1.schema.json` — the machine-readable JSON Schema.

These routes must be made available through static hosting or a public website route before external consumers are told to rely on browser resolution. A Frappe site can serve the documentation through its website routing, but the predicate type must not point to `/api/method` or `/api/resource`. The contract remains independent of the hosting implementation.

## 3. Statement subject

The in-toto Statement `subject` must identify the exact candidate OCI artifact:

- `subject[0].name`: OCI repository name.
- `subject[0].digest.sha256`: exact OCI manifest digest.

The candidate artifact reference supplied to NDF must resolve to this same repository and digest. Mutable tags are not valid trust subjects.

## 4. Predicate fields

The predicate must validate against the versioned JSON Schema and contain:

| Field | Meaning |
| --- | --- |
| `schema_version` | Exact predicate schema version, currently `1.0.0`. |
| `candidate_id` | DT Master candidate identifier. |
| `candidate_artifact.repository` | OCI repository containing the candidate. |
| `candidate_artifact.digest` | Exact OCI manifest digest; must match the Statement subject. |
| `candidate_payload_sha256` | SHA-256 of the exact candidate JSON layer bytes. |
| `producer.repository` | DT Master repository identity. |
| `producer.workflow_path` | Repository-relative path of the workflow that produced the artifact. |
| `producer.workflow_ref` | Full workflow ref, including repository and approved ref. |
| `producer.source_commit` | Full 40-character commit SHA of the producer workflow implementation. |
| `workflow_run.run_id` | GitHub Actions run ID that produced the candidate. |
| `workflow_run.run_attempt` | Run attempt that produced the candidate. |
| `correlation_id` | Cross-repository correlation ID, or explicit `null` when not supplied. |

## 5. Example predicate

Values below are illustrative placeholders and must be replaced with values derived from the actual producer run and artifact.

```json
{
  "schema_version": "1.0.0",
  "candidate_id": "candidate-example",
  "candidate_artifact": {
    "repository": "ghcr.io/ndftechlabs/deployment-candidates",
    "digest": "sha256:<64-lowercase-hex-characters>"
  },
  "candidate_payload_sha256": "<64-lowercase-hex-characters>",
  "producer": {
    "repository": "NdfTechLabs/dt_master",
    "workflow_path": ".github/workflows/<producer-workflow>.yml",
    "workflow_ref": "NdfTechLabs/dt_master/.github/workflows/<producer-workflow>.yml@refs/heads/main",
    "source_commit": "<40-lowercase-hex-characters>"
  },
  "workflow_run": {
    "run_id": "<numeric-run-id>",
    "run_attempt": 1
  },
  "correlation_id": null
}
```

## 6. Producer requirements — DT Master

Before dispatching the candidate to NDF, DT Master must:

1. Produce and publish the candidate OCI artifact.
2. Resolve the immutable OCI manifest digest.
3. Compute the SHA-256 of the exact candidate JSON layer bytes.
4. Generate the in-toto Statement with this predicate type and the claims above.
5. Sign the exact candidate OCI digest using Cosign keyless signing and DT Master's GitHub Actions OIDC identity.
6. Attach the candidate-origin attestation to that same digest.
7. Dispatch NDF with the existing candidate ID, immutable artifact reference, payload SHA-256 and correlation ID.

The signature and attestation must be produced by the same authorized DT Master producer workflow. The exact certificate identity and any reusable-workflow identity claims must be observed from a live run and approved separately; they must not be guessed from workflow YAML.

## 7. Consumer requirements — NDF

Before candidate adaptation or image building, NDF must independently:

1. Resolve the supplied immutable OCI reference and establish the exact digest.
2. Verify the Cosign signature against the Sigstore trust root.
3. Verify the exact DT Master certificate identity and GitHub Actions OIDC issuer.
4. Verify required Rekor transparency evidence.
5. Verify the candidate-origin attestation against the exact OCI digest and predicate type.
6. Validate the predicate against this schema.
7. Compare candidate ID, repository, digest, payload SHA-256 and correlation ID with the dispatch envelope.
8. Retrieve the candidate payload and recompute the SHA-256 over the exact JSON layer bytes.
9. Continue with the existing candidate schema, intake and lock-adapter validation.

Missing, malformed, mismatched, unsigned, untrusted or unverifiable evidence fails closed.

## 8. Producer/consumer ownership

- DT Master signs and attests to the candidate artifact because DT Master produced it.
- NDF verifies DT Master's evidence; it does not sign or re-attest the candidate.
- NDF signs the image and PDD artifacts it subsequently produces.
- DT Master independently verifies NDF's image and PDD trust evidence before considering those artifacts eligible for deployment.
- A successful candidate-origin verification is not deployment authorization.

## 9. Versioning

The `v1` predicate type and `1.0.0` schema are immutable contracts. A breaking change requires a new predicate type version and a new schema identifier. Consumers must reject unknown versions rather than silently interpreting them as v1.
