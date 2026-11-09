# NDF Frappe Docker

NDF Frappe Docker is the NDF product image factory and deployment-artifact producer built on the upstream Frappe Docker foundation.

It owns how Frappe product environments are composed, resolved, built, validated and published. It does not decide when or where a customer's Bench Environment is deployed; that orchestration belongs to DT Master.

## Responsibilities

- Maintain NDF product manifests and image definitions.
- Resolve application source references and application-to-application dependencies.
- Validate application and framework compatibility.
- Resolve Python, Node.js and OS-level dependencies into deterministic build inputs.
- Build and validate product and candidate images.
- Publish immutable OCI images to GHCR.
- Generate versioned deployment descriptors tied to exact image digests.
- Maintain versioned deployment/Compose contracts consumed by DT Master.
- Preserve upstream Frappe Docker build and runtime capabilities wherever practical.

## M4 — DTaaS integration

### M4.0 — Architecture and Repository Discovery

**Status: Complete (2026-11-09).**

The M4 architecture establishes the following ownership boundaries:

| Component         | Responsibility                                                                                                                                     |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| NDF Frappe Docker | Product composition, dependency resolution, image construction, validation, immutable publishing and deployment descriptors                        |
| GHCR              | Distribution of immutable images and associated artifacts                                                                                          |
| DT Master         | Infrastructure Nodes, Bench Environments, Docker/Compose orchestration, site lifecycle, deployment execution, migration, verification and rollback |
| DT Tenant         | Tenant-facing marketplace/subscription experience and authenticated requests to DT Master                                                          |

Governing principle:

**NDF knows how to construct a Frappe runtime. DT Master knows when, where and why to deploy it.**

### Agreed runtime and application model

- A Bench Environment is the runtime/deployment boundary and may use Host or Docker execution.
- A Bench Environment has one resolved Python runtime and one resolved Node.js runtime, plus the framework and other approved runtime components.
- Application compatibility declarations express supported version ranges; the resolved Bench composition records exact selected versions.
- Every application in a shared Bench composition must be compatible with the same resolved runtime and dependency environment.
- Bench-level application availability is distinct from site-level application installation.
- A new or changed Bench composition is built as a new immutable image and deployed through a replacement Bench Environment.
- A published image does not automatically update an existing deployment.

### M4.1 — Integration Contract and Architecture

**Status: Complete (2026-11-09).** The NDF artifact, composition, candidate/build, immutable image and deployment descriptor contracts were accepted in the final 13-point M4.1 architecture review and approved by the platform owner.

M4.1 defined and approved the NDF contracts consumed by DT Master.

| Workstream                    | NDF responsibility                                                                                   | Expected output                        |
| ----------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------- |
| Marketplace App Descriptor    | Define and validate app source, version, framework/runtime compatibility and dependency declarations | Versioned app descriptor schema        |
| Deployment Candidate          | Validate the requested complete Bench composition and build parameters                               | Candidate input schema                 |
| Runtime resolution            | Resolve compatible Python, Node.js, Yarn and framework versions                                      | Exact runtime selection                |
| Dependency resolution         | Resolve Python, Node.js and OS package dependencies                                                  | Deterministic dependency lock          |
| Candidate manifest generation | Convert a candidate composition into NDF build inputs                                                | Resolved manifest and lock             |
| Image build and validation    | Build and test the requested composition                                                             | Validated immutable OCI image          |
| Deployment descriptor         | Describe the image actually produced, not merely the requested manifest                              | Versioned descriptor with image digest |
| Publishing                    | Publish image and associated descriptor/artifacts                                                    | Immutable GHCR reference and digest    |

### M4.2 — Runtime Infrastructure Enhancements

**Status: Approved for implementation (2026-11-09).**

The read-only implementation readiness review found the repository and existing pipeline ready for implementation planning. The platform owner approved the M4.2 scope, nine work packages, deliverables, dependency order and 20 acceptance criteria, and explicitly authorized implementation on 9 November 2026.

The central implementation priority is to prove exactly what source revisions were acquired into each image while preserving upstream Bench acquisition. The composition lock records requested refs and resolution-time SHA evidence; the build inventory records the actual commits acquired by Bench; image verification validates that inventory; and the Product Deployment Descriptor binds the verified inventory to the published image digest. M4.2 extends the existing resolver, build and validation pipeline; it does not replace the upstream Frappe Docker foundation or create a competing image builder.

**Authoritative M4.2 records:**

- [M4.2 Implementation Plan](M4.2-IMPLEMENTATION-PLAN.md) — readiness conclusions, approved scope, work packages, deliverables, dependency order, acceptance criteria, boundaries and authorization.
- [M4.2 Implementation Tracker](M4.2-IMPLEMENTATION-TRACKER.md) — work-package status, acceptance evidence and execution log.
- [M4.2.1 Resolver Implementation](M4.2.1-RESOLVER-IMPLEMENTATION.md) — baseline findings, source-reference policy, resolution-time SHA/provenance, lock v2 contract and focused test requirements.
- [M4.2.2 Application Descriptor Contract](M4.2.2-APPLICATION-DESCRIPTOR.md) — descriptor/composition ownership, schema versioning, typed dependencies, compatibility evidence and migration boundaries.
- [M4.2.3 Composition and Service Resolution](M4.2.3-COMPOSITION-RESOLUTION.md) — resolver integration, dependency closure, explicit capability selection, independent service inventories and lock-integrity requirements.

**Current execution:** M4.2.1 — Build Foundation and Resolver Correction is Complete (2026-11-10); its user-run validation passed (47 resolver tests; 88 full NDF tests). PR #8 is merged. M4.2.2 — Application and Dependency Descriptors is Complete (2026-11-10); its user-run validation passed (37 focused descriptor tests; 125 full NDF tests), Python compilation completed without errors, and pre-commit passed after formatting corrections. PR #9 is merged. M4.2.3 — Composition and Service Resolution is In Progress (2026-11-10) on `feat/m4.2.3-composition-service-resolution`. Its initial repository audit and implementation baseline are recorded in `M4.2.3-COMPOSITION-RESOLUTION.md`; resolver implementation and tests are pending. The M4.2.2 descriptor-identity/release-identity lock regression requirement remains mandatory in M4.2.3. The resolver does not classify branch names as development-only.

Approved work packages:

1. M4.2.1 — Build Foundation and Resolver Correction.
2. M4.2.2 — Application and Dependency Descriptors.
3. M4.2.3 — Composition and Service Resolution.
4. M4.2.4 — Immutable Image Construction.
5. M4.2.5 — Image Verification.
6. M4.2.6 — Product Deployment Descriptor.
7. M4.2.7 — Candidate-Driven CI/CD.
8. M4.2.8 — Artifact Trust.
9. M4.2.9 — Integration Documentation and Testing.

Implementation is restricted to M4.2. M4.4 Product Image Deployment and M4.5 Runtime Application Management responsibilities remain with their designated DT Master/DT Tenant milestones; M4.2 defines and validates the NDF-side contracts they consume.

### Existing pipeline to extend

NDF already has product manifest/lock resolution, image preparation, image building and validation scripts, plus product build/publish/release workflows.

M4.1 accepted the direction to extend the existing pipeline for dynamic Deployment Candidate inputs rather than create a competing image builder or duplicate product workflows. Implementation is assigned to M4.2.

Current relevant components include:

- `images/ndf/scripts/resolve_manifest.py`
- `images/ndf/scripts/prepare_build.py`
- `images/ndf/scripts/build_image.py`
- `images/ndf/scripts/validate_image.py`
- `.github/workflows/ndf-build-product.yml`
- `.github/workflows/ndf-publish-product.yml`
- `.github/workflows/ndf-release-product.yml`

### Artifact principles

1. A deployment descriptor must identify the exact OCI image digest it describes.
2. The descriptor must record the resolved application inventory and runtime/dependency composition.
3. Requested refs and resolution-time SHA observations must be traceable separately from the actual post-acquisition source commit inventory and build provenance.
4. DT Master validates the descriptor and image digest before deployment.
5. GHCR distributes artifacts; DT Master records the operational deployment state.
6. NDF build credentials remain in NDF/GitHub Actions. DT Master submits authorized build requests and does not receive unrestricted publishing credentials.

### Cross-repository architecture records

- [DT Master M4 architecture](https://github.com/NdfTechLabs/dt_master/blob/develop/README.md)
- [DT Tenant M4 architecture](https://github.com/NdfTechLabs/dt_tenant/blob/develop/README.md)

## Upstream relationship

This repository is based on [upstream frappe_docker](https://github.com/frappe/frappe_docker). Upstream build/runtime improvements should be incorporated while keeping NDF-specific manifests, schemas, scripts and workflows isolated under `images/ndf/` where practical.

## M4.1 completion record

The following architecture areas were reviewed and approved as part of M4.1, which is Complete as of 2026-11-09:

- DocType ownership and relationship model across DT Master and DT Tenant.
- Versioned Marketplace App Descriptor and Deployment Candidate schemas.
- Runtime and dependency resolution rules and lock format.
- Deployment Descriptor schema and image-digest binding.
- Build request/result contract and GitHub Actions invocation/authentication.
- Host and Docker runtime adapter interfaces in DT Master.
- Replacement Bench, site migration, verification, rollback and retirement lifecycle.
- File-level repository migration matrix and implementation sequence.

M4.1 completion records architecture approval, not implementation completion. NDF pipeline implementation and validation are assigned to M4.2; subsequent deployment/runtime responsibilities remain assigned to M4.3–M4.7.
