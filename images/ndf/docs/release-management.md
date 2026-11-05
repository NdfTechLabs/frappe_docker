# NDF Product Image Release Management

## Current release scope

The release workflow currently promotes **DhanaERP Master (Frappe v16)** only. Dalali and Vincowoods remain build/publish targets but are intentionally excluded from release promotion until the master deployment path is proven.

## Tag contract

For a product image, the intended references are:

- Immutable build tag: `v16-<full-git-sha>`
- Immutable semantic release tag: `v16-<major>.<minor>.<patch>`
- Mutable stable channel: `v16-latest`
- Production deployment reference: `ghcr.io/ndftechlabs/dhanaerp-master@sha256:<digest>`

The semantic release tag is never overwritten. The stable channel may move when a newer release is deliberately promoted. Every tag created by a release run must resolve to the exact digest of the already-published immutable source image.

## Release procedure

1. Publish the intended product image using **NDF / Publish Product Images** from `main`.
2. Confirm the publish workflow completed, including registry pull-back and image-content/metadata validation.
3. Copy the full source commit SHA from that successful publishing run.
4. Run **NDF / Release Product Image** from `main`.
5. Supply the semantic version (for example `1.0.0`) and the full source commit SHA.
6. Confirm the workflow verifies the source tag, refuses to overwrite an existing semantic version, promotes the exact digest, and verifies both the semantic tag and `v16-latest`.
7. Record the resulting digest in deployment configuration. Prefer digest references for production.

## Safety properties

- Release promotion does not rebuild the image.
- The source must already exist under its immutable SHA tag in GHCR.
- Releases are restricted to the default branch.
- Semantic release tags are immutable by workflow policy.
- The stable alias is intentionally mutable and is only updated by an explicit manual release run.
- Release promotion uses registry manifest operations and preserves the source image digest.
- The release workflow currently targets only `ghcr.io/ndftechlabs/dhanaerp-master`.

## Rollback

Do not rely on moving `v16-latest` backwards as the primary rollback mechanism. Update deployment configuration to the previously recorded immutable digest. A stable alias can be re-promoted through a controlled release operation if required, but deployment rollback should remain digest-based.

## Scope boundary

This process establishes image release tagging and digest promotion. It does not prove that `dt_master` installs, migrates, or operates correctly at runtime. That validation belongs to M4 integration and deployment testing.
