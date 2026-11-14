#!/usr/bin/env python3
"""Retrieve and independently validate a digest-pinned DT Master candidate OCI artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

NDF_DIR = Path(__file__).resolve().parents[1]
SCHEMA_PATH = NDF_DIR / "schemas" / "deployment-candidate-v1.schema.json"

CANDIDATE_REPOSITORY = "ghcr.io/ndftechlabs/dt-master-deployment-candidates"
ARTIFACT_TYPE = "application/vnd.ndf.deployment-candidate.v1"
CANDIDATE_MEDIA_TYPE = "application/vnd.ndf.deployment-candidate.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
EMPTY_CONFIG_BYTES = b"{}"
EMPTY_CONFIG_DIGEST = "sha256:" + hashlib.sha256(EMPTY_CONFIG_BYTES).hexdigest()
LAYER_TITLE = "deployment-candidate.json"
ANNOTATION_CANDIDATE_ID = "io.ndf.candidate.id"
ANNOTATION_SCHEMA_VERSION = "io.ndf.candidate.schema-version"
ANNOTATION_PAYLOAD_SHA256 = "io.ndf.candidate.payload-sha256"
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
REFERENCE_RE = re.compile(
    r"^ghcr\.io/ndftechlabs/dt-master-deployment-candidates@"
    r"(sha256:[a-f0-9]{64})$"
)


class CandidateIntakeError(Exception):
    """Raised when a candidate artifact cannot be safely accepted."""


def parse_candidate_reference(reference: str) -> str:
    """Return the manifest digest from the one permitted immutable reference."""
    if not isinstance(reference, str) or not REFERENCE_RE.fullmatch(reference):
        raise CandidateIntakeError(
            "Candidate reference must be the exact allowlisted GHCR repository "
            "with a lowercase sha256 digest; tags and alternate references are forbidden."
        )
    return reference.rsplit("@", 1)[1]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateIntakeError(f"Candidate JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                CandidateIntakeError(f"{label} contains invalid numeric constant {value}.")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateIntakeError(f"{label} is not valid UTF-8 JSON.") from exc


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_manifest_response(
    response: dict[str, Any],
    *,
    reference: str,
    candidate_id: str,
    payload_sha256: str,
) -> dict[str, Any]:
    """Validate the ORAS manifest-fetch JSON wrapper and return its OCI content."""
    requested_digest = parse_candidate_reference(reference)
    if response.get("digest") != requested_digest:
        raise CandidateIntakeError("Registry manifest digest differs from requested digest.")

    manifest = response.get("content")
    if not isinstance(manifest, dict):
        raise CandidateIntakeError("ORAS manifest response has no OCI manifest content.")
    if manifest.get("schemaVersion") != 2:
        raise CandidateIntakeError("Candidate OCI manifest must use schemaVersion 2.")
    if manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
        raise CandidateIntakeError("Candidate OCI manifest mediaType is not supported.")
    if manifest.get("artifactType") != ARTIFACT_TYPE:
        raise CandidateIntakeError("Candidate OCI artifactType is not supported.")

    config = manifest.get("config")
    if not isinstance(config, dict) or any(
        config.get(key) != value
        for key, value in {
            "mediaType": EMPTY_CONFIG_MEDIA_TYPE,
            "digest": EMPTY_CONFIG_DIGEST,
            "size": len(EMPTY_CONFIG_BYTES),
        }.items()
    ):
        raise CandidateIntakeError("Candidate OCI manifest has an unexpected empty config.")

    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise CandidateIntakeError("Candidate artifact must contain exactly one layer.")
    layer = layers[0]
    if not isinstance(layer, dict):
        raise CandidateIntakeError("Candidate layer descriptor must be an object.")
    if layer.get("mediaType") != CANDIDATE_MEDIA_TYPE:
        raise CandidateIntakeError("Candidate layer media type is not supported.")
    if not SHA256_RE.fullmatch(str(layer.get("digest", ""))):
        raise CandidateIntakeError("Candidate layer has no valid sha256 digest.")
    if not isinstance(layer.get("size"), int) or layer["size"] <= 0:
        raise CandidateIntakeError("Candidate layer has an invalid byte size.")
    annotations = layer.get("annotations")
    if not isinstance(annotations, dict) or annotations.get("org.opencontainers.image.title") != LAYER_TITLE:
        raise CandidateIntakeError("Candidate layer title must be deployment-candidate.json.")

    manifest_annotations = manifest.get("annotations")
    if not isinstance(manifest_annotations, dict):
        raise CandidateIntakeError("Candidate OCI manifest annotations are required.")
    expected = {
        ANNOTATION_CANDIDATE_ID: candidate_id,
        ANNOTATION_SCHEMA_VERSION: "1.0.0",
        ANNOTATION_PAYLOAD_SHA256: payload_sha256,
    }
    if any(manifest_annotations.get(key) != value for key, value in expected.items()):
        raise CandidateIntakeError("Candidate manifest annotations disagree with the dispatch envelope.")
    return layer




def _validate_supported_product(candidate: dict[str, Any]) -> None:
    """Bind product/framework identity to the NDF image-definition inventory."""
    definitions_path = NDF_DIR / "image-definitions" / "images-v1.json"
    try:
        definitions = json.loads(definitions_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateIntakeError(f"Unable to load supported NDF image definitions: {exc}") from exc

    product_id = candidate["product"]["id"]
    matches = [
        image for image in definitions.get("images", [])
        if isinstance(image, dict) and image.get("product") == product_id
    ]
    if not matches:
        raise CandidateIntakeError(f"Candidate product is not present in the NDF image inventory: {product_id}")
    if len(matches) != 1:
        raise CandidateIntakeError(f"Candidate product maps to multiple NDF image definitions: {product_id}")

    manifest_path = NDF_DIR / "manifests" / matches[0]["manifest"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateIntakeError(f"Unable to load authoritative product manifest: {exc}") from exc
    supported_framework = manifest.get("framework", {}).get("version")
    if candidate["framework_version"] != supported_framework:
        raise CandidateIntakeError(
            f"Candidate framework version {candidate['framework_version']!r} "
            f"does not match product manifest version {supported_framework!r}."
        )
    runtime_profile = candidate["runtime_profile"]
    runtime_framework = runtime_profile.get("framework")
    if runtime_framework is not None and runtime_framework != supported_framework:
        raise CandidateIntakeError("Candidate runtime profile framework differs from the product manifest.")

    python_version = runtime_profile.get("python")
    if python_version is not None and not re.fullmatch(r"3\.14(?:\.\d+)?, python_version):
        raise CandidateIntakeError("Candidate Python runtime is outside the supported CPython 3.14 family.")
    node_version = runtime_profile.get("node")
    if node_version is not None and not re.fullmatch(r"24(?:\.\d+){0,2}, node_version):
        raise CandidateIntakeError("Candidate Node.js runtime is outside the supported 24.x family.")

def validate_candidate_payload(
    raw: bytes,
    *,
    expected_candidate_id: str,
    expected_payload_sha256: str,
) -> dict[str, Any]:
    """Verify exact payload bytes, parse strictly, validate schema and semantics."""
    if not isinstance(expected_payload_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_payload_sha256):
        raise CandidateIntakeError("Dispatch payload_sha256 must be 64 lowercase hexadecimal characters.")
    observed_hash = hashlib.sha256(raw).hexdigest()
    if observed_hash != expected_payload_sha256:
        raise CandidateIntakeError("Candidate payload SHA-256 differs from the authenticated dispatch envelope.")

    candidate = _strict_json(raw, "Candidate payload")
    if not isinstance(candidate, dict):
        raise CandidateIntakeError("Candidate payload must be a JSON object.")
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(candidate),
            key=lambda error: list(map(str, error.absolute_path)),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise CandidateIntakeError(f"Unable to validate candidate schema: {exc}") from exc
    if errors:
        detail = "; ".join(
            f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors[:10]
        )
        raise CandidateIntakeError(f"Candidate does not conform to schema: {detail}")

    if candidate["candidate_id"] != expected_candidate_id:
        raise CandidateIntakeError("Candidate ID differs from the authenticated dispatch envelope.")

    _validate_supported_product(candidate)

    applications = candidate["applications"]
    app_ids = [app["app_id"] for app in applications]
    if len(app_ids) != len(set(app_ids)):
        raise CandidateIntakeError("Candidate contains duplicate application IDs.")

    for app in applications:
        descriptor_digest = app["descriptor_digest"]
        descriptor_ref = app["descriptor_ref"]
        if not SHA256_RE.fullmatch("sha256:" + descriptor_digest):
            raise CandidateIntakeError(f"Application {app['app_id']} has an invalid descriptor digest.")
        if not descriptor_ref.endswith("@sha256:" + descriptor_digest):
            raise CandidateIntakeError(
                f"Application {app['app_id']} descriptor reference and digest disagree."
            )
        if not re.fullmatch(r"[a-f0-9]{40,64}", app["immutable_commit"]):
            raise CandidateIntakeError(
                f"Application {app['app_id']} does not identify an immutable Git commit."
            )

    return candidate


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(command, check=False, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise CandidateIntakeError(f"Command timed out: {command[0]}") from exc
    except OSError as exc:
        raise CandidateIntakeError(f"Unable to execute {command[0]}: {exc}") from exc


def _command_json(result: subprocess.CompletedProcess[bytes], label: str) -> dict[str, Any]:
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CandidateIntakeError(f"{label} failed: {detail or result.returncode}")
    value = _strict_json(result.stdout, label)
    if not isinstance(value, dict):
        raise CandidateIntakeError(f"{label} must return a JSON object.")
    return value


def intake_candidate(
    *,
    candidate_id: str,
    artifact_reference: str,
    payload_sha256: str,
    output_path: Path,
    oras_bin: str = "oras",
) -> dict[str, Any]:
    """Fetch a candidate by digest, verify all OCI/payload identities, and write validated JSON."""
    digest = parse_candidate_reference(artifact_reference)
    if not re.fullmatch(r"[a-f0-9]{64}", payload_sha256 or ""):
        raise CandidateIntakeError("Dispatch payload_sha256 is invalid.")

    manifest_response = _command_json(
        _run([oras_bin, "manifest", "fetch", "--format", "json", artifact_reference], timeout=120),
        "ORAS candidate manifest fetch",
    )
    layer = validate_manifest_response(
        manifest_response,
        reference=artifact_reference,
        candidate_id=candidate_id,
        payload_sha256=payload_sha256,
    )

    with tempfile.TemporaryDirectory(prefix="ndf-candidate-intake-") as temp:
        pulled = Path(temp)
        pull_response = _command_json(
            _run(
                [oras_bin, "pull", "--format", "json", "--output", str(pulled), artifact_reference],
                timeout=300,
            ),
            "ORAS candidate pull",
        )
        if pull_response.get("reference") != artifact_reference:
            raise CandidateIntakeError("ORAS pull returned a different artifact reference.")
        files: list[Path] = []
        for path in pulled.rglob("*"):
            if path.is_symlink():
                raise CandidateIntakeError("Candidate artifact contains a symlink.")
            if path.is_file():
                files.append(path)
        if len(files) != 1 or files[0].relative_to(pulled).as_posix() != LAYER_TITLE:
            raise CandidateIntakeError("Pulled candidate artifact must contain only deployment-candidate.json.")
        payload = files[0].read_bytes()
        if len(payload) != layer["size"]:
            raise CandidateIntakeError("Candidate layer byte size differs from its OCI descriptor.")
        if _sha256(payload) != layer["digest"]:
            raise CandidateIntakeError("Candidate layer bytes differ from the OCI layer digest.")

    candidate = validate_candidate_payload(
        payload,
        expected_candidate_id=candidate_id,
        expected_payload_sha256=payload_sha256,
    )
    if output_path.exists() or output_path.is_symlink():
        raise CandidateIntakeError("Candidate output path must not already exist.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_output = output_path.with_name(output_path.name + ".tmp")
    temp_output.write_bytes(payload)
    temp_output.replace(output_path)
    return {
        "status": "validated",
        "candidate_id": candidate["candidate_id"],
        "artifact_reference": artifact_reference,
        "artifact_digest": digest,
        "payload_sha256": payload_sha256,
        "application_count": len(candidate["applications"]),
        "output_path": str(output_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--artifact-reference", required=True)
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--oras-bin", default="oras")
    args = parser.parse_args()
    try:
        report = intake_candidate(
            candidate_id=args.candidate_id,
            artifact_reference=args.artifact_reference,
            payload_sha256=args.payload_sha256,
            output_path=args.output,
            oras_bin=args.oras_bin,
        )
    except CandidateIntakeError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
