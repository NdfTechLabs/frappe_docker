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

### M4.0 — Architecture and repository discovery

**Status: Completed (2026-11-09).**

The M4 architecture establishes the following ownership boundaries:

| Component | Responsibility |
|---|---|
| NDF Frappe Docker | Product composition, dependency resolution, image construction, validation, immutable publishing and deployment descriptors |
| GHCR | Distribution of immutable images and associated artifacts |
| DT Master | Infrastructure Nodes, Bench Environments, Docker/Compose orchestration, site lifecycle, deployment execution, migration, verification and rollback |
| DT Tenant | Tenant-facing marketplace/subscription experience and authenticated requests to DT Master |

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

### M4.1 — Integration contract and architecture

**Status: In progress.**  
**Implementation status: Not started under M4.1 approval.**

M4.1 will define the NDF contracts consumed by DT Master.

| Workstream | NDF responsibility | Expected output |
|---|---|---|
| Marketplace App Descriptor | Define and validate app source, version, framework/runtime compatibility and dependency declarations | Versioned app descriptor schema |
| Deployment Candidate | Validate the requested complete Bench composition and build parameters | Candidate input schema |
| Runtime resolution | Resolve compatible Python, Node.js, Yarn and framework versions | Exact runtime selection |
| Dependency resolution | Resolve Python, Node.js and OS package dependencies | Deterministic dependency lock |
| Candidate manifest generation | Convert a candidate composition into NDF build inputs | Resolved manifest and lock |
| Image build and validation | Build and test the requested composition | Validated immutable OCI image |
| Deployment descriptor | Describe the image actually produced, not merely the requested manifest | Versioned descriptor with image digest |
| Publishing | Publish image and associated descriptor/artifacts | Immutable GHCR reference and digest |

### Existing pipeline to extend

NDF already has product manifest/lock resolution, image preparation, image building and validation scripts, plus product build/publish/release workflows.

M4.1 should extend the existing pipeline to support dynamic Deployment Candidate inputs. It should not create a competing image builder or duplicate existing product workflows.

Current relevant components include:

- `images/ndf/scripts/resolve_manifest.py`
- `images/ndf/scripts/prepare_build.py`
- `images/ndf/scripts/build_image.py`
- `images/ndf/scripts/validate_image.py`
- `.github/workflows/ndf-build-product.yml`
- `.github/workflows/ndf-publish-product.yml`
- `.github/workflows/ndf-release-product.yml`

The current product workflows are based on predefined product definitions. Dynamic candidate composition, runtime/package dependency resolution and the complete deployment descriptor contract remain M4.1 design and subsequent implementation work.

### Artifact principles

1. A deployment descriptor must identify the exact OCI image digest it describes.
2. The descriptor must record the resolved application inventory and runtime/dependency composition.
3. Manifest, lock, source commit and build provenance must be traceable.
4. DT Master validates the descriptor and image digest before deployment.
5. GHCR distributes artifacts; DT Master records the operational deployment state.
6. NDF build credentials remain in NDF/GitHub Actions. DT Master submits authorized build requests and does not receive unrestricted publishing credentials.

### Cross-repository architecture records

- [DT Master M4 architecture](https://github.com/NdfTechLabs/dt_master/blob/develop/README.md)
- [DT Tenant M4 architecture](https://github.com/NdfTechLabs/dt_tenant/blob/develop/README.md)

## Upstream relationship

This repository is based on [upstream frappe_docker](https://github.com/frappe/frappe_docker). Upstream build/runtime improvements should be incorporated while keeping NDF-specific manifests, schemas, scripts and workflows isolated under `images/ndf/` where practical.

## M4.1 completion criteria

M4.1 is complete only when the following are reviewed and approved:

- DocType ownership and relationship model across DT Master and DT Tenant.
- Versioned Marketplace App Descriptor and Deployment Candidate schemas.
- Runtime and dependency resolution rules and lock format.
- Deployment Descriptor schema and image-digest binding.
- Build request/result contract and GitHub Actions invocation/authentication.
- Host and Docker runtime adapter interfaces in DT Master.
- Replacement Bench, site migration, verification, rollback and retirement lifecycle.
- File-level repository migration matrix and implementation sequence.

Until those contracts are approved, the M4.1 status remains **In progress** and no production integration should assume they are finalized.
