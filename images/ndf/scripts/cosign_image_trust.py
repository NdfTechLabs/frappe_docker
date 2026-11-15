#!/usr/bin/env python3
"""Sign and independently verify NDF product-image provenance with Cosign."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from . import artifact_trust
    from .generate_image_provenance import (
        ImageProvenanceError,
        _workflow_context,
    )
except ImportError:
    import artifact_trust
    from generate_image_provenance import ImageProvenanceError, _workflow_context


NDF_DIR = Path(__file__).resolve().parents[1]
POLICY_PATH = NDF_DIR / "policies" / "artifact-trust-identity-policy-v1.json"
COSIGN_VERSION = "v3.1.4"
IDENTITY_ID = "product-image-publication"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
PREDICATE_ALIAS = "slsaprovenance1"
IMAGE_REF_RE = re.compile(
    r"^(?P<repository>[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+)"
    r"@(?P<digest>sha256:[a-f0-9]{64})$"
)
VERSION_RE = re.compile(r"(?m)^GitVersion:\s*(v[0-9]+\.[0-9]+\.[0-9]+)\s*$")


class CosignTrustError(Exception):
    """Raised when signing or verification cannot establish the NDF trust contract."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _strict_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CosignTrustError(f"{label} is missing or unsafe: {path}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise CosignTrustError(f"{label} contains duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise CosignTrustError(f"{label} contains non-finite JSON value: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CosignTrustError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CosignTrustError(f"{label} must be a JSON object.")
    return value


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CosignTrustError(f"Refusing to replace symlink output: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise CosignTrustError(f"Unable to write verification result: {exc}") from exc


def parse_image_reference(image_ref: str) -> tuple[str, str]:
    match = IMAGE_REF_RE.fullmatch(image_ref)
    if match is None:
        raise CosignTrustError(
            "Image reference must be a fully qualified repository@sha256 digest; tags are forbidden."
        )
    return match.group("repository"), match.group("digest")


def _load_product_identity(
    policy_path: Path = POLICY_PATH,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        policy = artifact_trust.load_identity_policy(policy_path)
    except Exception as exc:
        raise CosignTrustError(f"Unable to load signer identity policy: {exc}") from exc
    matches = [
        entry
        for entry in policy["identities"]
        if entry["id"] == IDENTITY_ID and "product_image" in entry["artifact_kinds"]
    ]
    if len(matches) != 1:
        raise CosignTrustError("Product-image signer identity is missing or ambiguous.")
    entry = matches[0]
    if entry["reusable_workflow_ref"] is not None:
        raise CosignTrustError(
            "Product-image signer must be a direct workflow identity."
        )
    return policy, entry


def _require_product_workflow(env: dict[str, str]) -> dict[str, Any]:
    if env.get("GITHUB_ACTIONS", "").lower() != "true":
        raise CosignTrustError(
            "Keyless signing is permitted only inside GitHub Actions."
        )
    try:
        return _workflow_context(env)
    except ImageProvenanceError as exc:
        raise CosignTrustError(f"Unapproved GitHub Actions context: {exc}") from exc


def _run(
    args: list[str],
    *,
    runner: Runner = subprocess.run,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            args,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except OSError as exc:
        raise CosignTrustError(f"Unable to execute Cosign: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise CosignTrustError(
            f"Cosign command failed ({result.returncode}): {' '.join(args[:2])}: {detail}"
        )
    return result


def _require_cosign_version(
    *, runner: Runner = subprocess.run, cosign_binary: str = "cosign"
) -> None:
    result = _run([cosign_binary, "version"], runner=runner)
    match = VERSION_RE.search(result.stdout + "\n" + result.stderr)
    if match is None or match.group(1) != COSIGN_VERSION:
        actual = match.group(1) if match else "unrecognized"
        raise CosignTrustError(f"Cosign {COSIGN_VERSION} is required; found {actual}.")


def _workflow_identity_args(
    policy: dict[str, Any], identity: dict[str, Any], source_commit: str
) -> list[str]:
    verification = policy["verification"]
    return [
        "--certificate-identity",
        identity["certificate_identity"],
        "--certificate-oidc-issuer",
        policy["issuer"],
        "--certificate-github-workflow-trigger",
        verification["required_event_name"],
        "--certificate-github-workflow-repository",
        verification["required_repository"],
        "--certificate-github-workflow-ref",
        verification["required_ref"],
        "--certificate-github-workflow-sha",
        source_commit,
    ]


def _validate_statement(
    statement: dict[str, Any], *, repository: str, digest: str
) -> dict[str, Any]:
    try:
        report = artifact_trust.validate_image_provenance_statement(statement, digest)
    except Exception as exc:
        raise CosignTrustError(f"Image provenance statement is invalid: {exc}") from exc
    if statement["predicateType"] != PREDICATE_TYPE:
        raise CosignTrustError("Provenance predicate type is not SLSA Provenance v1.")
    subject = statement["subject"]
    if len(subject) != 1 or subject[0]["name"] != repository:
        raise CosignTrustError(
            "Provenance subject repository does not match image reference."
        )
    workflow = statement["predicate"]["ndf_build"]["workflow"]
    if (
        workflow["repository"] != "NdfTechLabs/frappe_docker"
        or workflow["path"] != ".github/workflows/ndf-publish-product.yml"
        or workflow["ref"] != "refs/heads/main"
    ):
        raise CosignTrustError(
            "Provenance workflow identity is outside the product-image policy."
        )
    return report


def sign_image(
    *,
    image_ref: str,
    predicate_path: Path,
    statement_path: Path,
    env: dict[str, str] | None = None,
    policy_path: Path = POLICY_PATH,
    cosign_binary: str = "cosign",
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Sign an immutable product image and attach its validated SLSA predicate."""
    runtime_env = dict(os.environ if env is None else env)
    workflow = _require_product_workflow(runtime_env)
    repository, digest = parse_image_reference(image_ref)
    policy, identity = _load_product_identity(policy_path)
    statement = _strict_json(statement_path, "provenance Statement")
    predicate = _strict_json(predicate_path, "SLSA provenance predicate")
    _validate_statement(statement, repository=repository, digest=digest)
    if predicate != statement["predicate"]:
        raise CosignTrustError(
            "Predicate file does not exactly match the Statement predicate."
        )
    statement_workflow = statement["predicate"]["ndf_build"]["workflow"]
    if statement_workflow != workflow:
        raise CosignTrustError(
            "Provenance workflow metadata differs from runtime context."
        )
    if policy["issuer"] != "https://token.actions.githubusercontent.com":
        raise CosignTrustError("Signer policy uses an unapproved OIDC issuer.")
    if identity["workflow_ref"] != (
        "NdfTechLabs/frappe_docker/.github/workflows/ndf-publish-product.yml@refs/heads/main"
    ):
        raise CosignTrustError(
            "Product-image workflow identity policy has changed unexpectedly."
        )

    _require_cosign_version(runner=runner, cosign_binary=cosign_binary)
    _run([cosign_binary, "sign", "--yes", image_ref], runner=runner, env=runtime_env)
    _run(
        [
            cosign_binary,
            "attest",
            "--yes",
            "--type",
            PREDICATE_ALIAS,
            "--predicate",
            str(predicate_path),
            image_ref,
        ],
        runner=runner,
        env=runtime_env,
    )
    return {
        "status": "signed",
        "image_repository": repository,
        "image_digest": digest,
        "predicate_type": PREDICATE_TYPE,
        "predicate_sha256": hashlib.sha256(_canonical_json(predicate)).hexdigest(),
        "identity_id": identity["id"],
        "policy_status": policy["status"],
    }


def _collect_json_values(text: str) -> list[Any]:
    decoder = json.JSONDecoder()
    values: list[Any] = []
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, (dict, list)):
            values.append(value)
    return values


def _statement_candidates(value: Any) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            candidates.extend(_statement_candidates(item))
        return candidates
    if not isinstance(value, dict):
        return candidates
    if (
        value.get("_type") == "https://in-toto.io/Statement/v1"
        and isinstance(value.get("subject"), list)
        and isinstance(value.get("predicate"), dict)
    ):
        return [value]
    if value.get("payloadType") == "application/vnd.in-toto+json":
        payload = value.get("payload")
        if not isinstance(payload, str):
            return candidates
        try:
            decoded = base64.b64decode(payload, validate=True)
            statement = json.loads(decoded.decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError):
            return candidates
        return _statement_candidates(statement)
    for item in value.values():
        if isinstance(item, (dict, list)):
            candidates.extend(_statement_candidates(item))
    return candidates


def extract_verified_statement(stdout: str) -> dict[str, Any]:
    """Extract exactly one complete in-toto Statement from Cosign's verified output."""
    candidates: list[dict[str, Any]] = []
    for value in _collect_json_values(stdout):
        candidates.extend(_statement_candidates(value))
    if len(candidates) != 1:
        raise CosignTrustError(
            f"Expected exactly one verified in-toto Statement; found {len(candidates)}."
        )
    return candidates[0]


def _parse_signature_output(stdout: str) -> None:
    values = _collect_json_values(stdout)
    signature_lists = [value for value in values if isinstance(value, list)]
    if not signature_lists or not any(signature_lists):
        raise CosignTrustError(
            "Cosign signature verification returned no verified signatures."
        )


def verify_image(
    *,
    image_ref: str,
    result_output: Path,
    policy_path: Path = POLICY_PATH,
    cosign_binary: str = "cosign",
    runner: Runner = subprocess.run,
    verified_at: datetime | None = None,
    attestation_output: Path | None = None,
) -> dict[str, Any]:
    """Verify image signature, Rekor-backed attestation and NDF provenance semantics."""
    repository, digest = parse_image_reference(image_ref)
    policy, identity = _load_product_identity(policy_path)
    _require_cosign_version(runner=runner, cosign_binary=cosign_binary)
    # The source SHA is obtained from the verified Statement, not from the verifier's
    # own checkout or caller-supplied arguments. First verify the statement's signature
    # and then repeat the signature/attestation checks with its exact SHA claim.
    initial_args = _workflow_identity_args(policy, identity, "0" * 40)
    # The source SHA is not known before reading the attestation. Verify the signer
    # identity, issuer, trigger, repository and ref first; then enforce the SHA below
    # against the actual certificate claims exposed by the verified certificate.
    initial_args = initial_args[:-2]
    signature_result = _run(
        [cosign_binary, "verify", "--output", "json", *initial_args, image_ref],
        runner=runner,
    )
    _parse_signature_output(signature_result.stdout)

    attestation_args = _workflow_identity_args(policy, identity, "0" * 40)[:-2]
    attestation_result = _run(
        [
            cosign_binary,
            "verify-attestation",
            "--type",
            PREDICATE_ALIAS,
            *attestation_args,
            image_ref,
        ],
        runner=runner,
    )
    if attestation_output is not None:
        _atomic_write(attestation_output, attestation_result.stdout.encode("utf-8"))
    statement = extract_verified_statement(attestation_result.stdout)
    _validate_statement(statement, repository=repository, digest=digest)
    workflow = statement["predicate"]["ndf_build"]["workflow"]
    source_commit = workflow["source_commit"]

    # Re-run both verifications with the source SHA obtained from the already
    # cryptographically verified attestation. This binds the signature certificate
    # itself to the same source revision.
    exact_args = _workflow_identity_args(policy, identity, source_commit)
    signature_result = _run(
        [cosign_binary, "verify", "--output", "json", *exact_args, image_ref],
        runner=runner,
    )
    _parse_signature_output(signature_result.stdout)
    attestation_result = _run(
        [
            cosign_binary,
            "verify-attestation",
            "--type",
            PREDICATE_ALIAS,
            *exact_args,
            image_ref,
        ],
        runner=runner,
    )
    verified_statement = extract_verified_statement(attestation_result.stdout)
    if verified_statement != statement:
        raise CosignTrustError("Attestation changed between verification passes.")
    _validate_statement(verified_statement, repository=repository, digest=digest)

    now = verified_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise CosignTrustError("Verification timestamp must be timezone-aware.")
    predicate_hash = hashlib.sha256(
        _canonical_json(verified_statement["predicate"])
    ).hexdigest()
    trusted = policy["status"] == "confirmed"
    result = {
        "schema_version": "1.0.0",
        "verification_id": str(uuid.uuid4()),
        "artifact": {
            "kind": "product_image",
            "repository": repository,
            "digest": digest,
            "immutable_reference": image_ref,
        },
        "signature": {
            "verified": True,
            "verification_method": "cosign-keyless",
        },
        "signer": {
            "verified": True,
            "oidc_issuer": policy["issuer"],
            "certificate_identity": identity["certificate_identity"],
            "workflow_ref": identity["workflow_ref"],
        },
        "transparency": {
            "verified": True,
            "log_entry_verified": True,
        },
        "attestations": [
            {
                "predicate_type": PREDICATE_TYPE,
                "verified": True,
                "subject_digest": digest,
                "predicate_sha256": predicate_hash,
            }
        ],
        "decision": {
            "status": "trusted" if trusted else "rejected",
            "reason_codes": [] if trusted else ["IDENTITY_POLICY_PROVISIONAL"],
        },
        "verified_at": now.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    try:
        artifact_trust.validate_trust_verification_result(result)
    except Exception as exc:
        raise CosignTrustError(
            f"Normalized trust result failed schema validation: {exc}"
        ) from exc
    _atomic_write(
        result_output,
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    if not trusted:
        raise CosignTrustError(
            "Cryptographic verification passed, but signer identity policy is provisional; "
            "result is rejected and cannot authorize promotion."
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("--image-ref", required=True)
    sign_parser.add_argument("--predicate", type=Path, required=True)
    sign_parser.add_argument("--statement", type=Path, required=True)
    sign_parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    sign_parser.add_argument("--cosign-binary", default="cosign")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--image-ref", required=True)
    verify_parser.add_argument("--result-output", type=Path, required=True)
    verify_parser.add_argument("--attestation-output", type=Path)
    verify_parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    verify_parser.add_argument("--cosign-binary", default="cosign")
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            result = sign_image(
                image_ref=args.image_ref,
                predicate_path=args.predicate,
                statement_path=args.statement,
                policy_path=args.policy,
                cosign_binary=args.cosign_binary,
            )
        else:
            result = verify_image(
                image_ref=args.image_ref,
                result_output=args.result_output,
                attestation_output=args.attestation_output,
                policy_path=args.policy,
                cosign_binary=args.cosign_binary,
            )
    except (CosignTrustError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
