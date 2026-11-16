#!/usr/bin/env python3
"""Correlate Cosign-verified DSSE envelopes with raw Sigstore bundles and inspect Fulcio certificates.

This is an observation utility, not a signature verifier. It requires the raw
bundle's complete DSSE envelope to match the separately verified Cosign output.
Cosign remains responsible for signature, certificate-chain and Rekor checks.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
FULCIO_OID_PREFIX = "1.3.6.1.4.1.57264.1."
LEGACY_CLAIMS = {
    "1": "iss",
    "2": "event_name",
    "3": "source_sha",
    "4": "workflow",
    "5": "repository",
    "6": "ref",
}
GENERIC_CLAIMS = {
    "8": "issuer",
    "9": "build_signer_uri",
    "10": "build_signer_digest",
    "11": "runner_environment",
    "12": "source_repository_uri",
    "13": "source_repository_digest",
    "14": "source_repository_ref",
    "15": "source_repository_identifier",
    "16": "source_repository_owner_uri",
    "17": "source_repository_owner_identifier",
    "18": "build_config_uri",
    "19": "build_config_digest",
    "20": "build_trigger",
    "21": "run_invocation_uri",
    "22": "source_repository_visibility_at_signing",
    "23": "deployment_environment",
    "24": "token_subject",
}


class CertificateObservationError(Exception):
    """Raised when bundle/envelope correlation or certificate parsing fails."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CertificateObservationError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                CertificateObservationError(f"Invalid JSON constant in {label}: {token}")
            ),
        )
    except CertificateObservationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificateObservationError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CertificateObservationError(f"{label} root must be an object.")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise CertificateObservationError(f"Unable to read bundle file: {exc}") from exc
    entries = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line, object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, CertificateObservationError) as exc:
            raise CertificateObservationError(f"Invalid bundle JSON on line {number}: {exc}") from exc
        if not isinstance(value, dict):
            raise CertificateObservationError(f"Bundle line {number} must be an object.")
        entries.append(value)
    if not entries:
        raise CertificateObservationError("Bundle file contains no bundle objects.")
    return entries


def _decode_der_utf8_string(raw: bytes, oid: str) -> str:
    """Decode one complete DER UTF8String, rejecting malformed/trailing bytes."""
    if len(raw) < 2 or raw[0] != 0x0C:
        raise CertificateObservationError(f"Fulcio extension {oid} is not a DER UTF8String.")
    first = raw[1]
    if first < 0x80:
        length = first
        offset = 2
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or len(raw) < 2 + count:
            raise CertificateObservationError(f"Fulcio extension {oid} has invalid DER length.")
        if raw[2] == 0:
            raise CertificateObservationError(f"Fulcio extension {oid} has non-minimal DER length.")
        length = int.from_bytes(raw[2 : 2 + count], "big")
        if length < 0x80:
            raise CertificateObservationError(f"Fulcio extension {oid} has non-minimal DER length.")
        offset = 2 + count
    if offset + length != len(raw):
        raise CertificateObservationError(f"Fulcio extension {oid} has truncated or trailing DER data.")
    try:
        return raw[offset:].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CertificateObservationError(f"Fulcio extension {oid} is not valid UTF-8.") from exc


def _certificate_from_bundle(bundle: dict[str, Any]) -> bytes:
    material = bundle.get("verificationMaterial")
    if not isinstance(material, dict):
        raise CertificateObservationError("Bundle has no verificationMaterial object.")
    certificate = material.get("certificate")
    if isinstance(certificate, dict) and isinstance(certificate.get("rawBytes"), str):
        encoded = certificate["rawBytes"]
    else:
        chain = material.get("x509CertificateChain")
        certificates = chain.get("certificates") if isinstance(chain, dict) else None
        if not isinstance(certificates, list) or not certificates:
            raise CertificateObservationError("Bundle contains no supported leaf certificate.")
        leaf = certificates[0]
        encoded = leaf.get("rawBytes") if isinstance(leaf, dict) else None
    if not isinstance(encoded, str) or not encoded:
        raise CertificateObservationError("Bundle leaf certificate rawBytes is missing.")
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CertificateObservationError("Bundle leaf certificate is not valid base64.") from exc


def _statement_from_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    payload = envelope.get("payload")
    if not isinstance(payload, str) or not payload:
        raise CertificateObservationError("DSSE envelope payload is missing.")
    try:
        raw = base64.b64decode(payload, validate=True)
        statement = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, CertificateObservationError) as exc:
        raise CertificateObservationError(f"DSSE payload is not valid base64-encoded JSON: {exc}") from exc
    if not isinstance(statement, dict):
        raise CertificateObservationError("DSSE statement must be a JSON object.")
    return statement


def _claim_value(extensions: dict[str, bytes], suffix: str, *, der: bool) -> str | None:
    raw = extensions.get(FULCIO_OID_PREFIX + suffix)
    if raw is None:
        return None
    if der:
        return _decode_der_utf8_string(raw, FULCIO_OID_PREFIX + suffix)
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CertificateObservationError(
            f"Legacy Fulcio extension {FULCIO_OID_PREFIX + suffix} is not UTF-8."
        ) from exc


def observe_certificate(
    bundles_path: Path,
    verified_envelope_path: Path,
    *,
    artifact_reference: str,
    predicate_type: str,
) -> dict[str, Any]:
    match = re.fullmatch(
        r"(?P<repository>[^@\s]+)@sha256:(?P<digest>[a-f0-9]{64})",
        artifact_reference,
    )
    if match is None:
        raise CertificateObservationError("Artifact reference must be immutable repository@sha256.")
    repository = match.group("repository")
    digest = match.group("digest")

    verified_envelope = _read_json(verified_envelope_path, "verified DSSE envelope")
    required_envelope_keys = {"payload", "payloadType", "signatures"}
    if set(verified_envelope) != required_envelope_keys:
        raise CertificateObservationError("Verified DSSE envelope has an unexpected shape.")
    if not isinstance(verified_envelope["signatures"], list) or not verified_envelope["signatures"]:
        raise CertificateObservationError("Verified DSSE envelope contains no signatures.")

    bundles = _read_jsonl(bundles_path)
    matching = [
        bundle
        for bundle in bundles
        if bundle.get("dsseEnvelope") == verified_envelope
    ]
    if len(matching) != 1:
        raise CertificateObservationError(
            f"Expected exactly one bundle matching the verified DSSE envelope; found {len(matching)}."
        )
    bundle = matching[0]
    if bundle.get("mediaType") != BUNDLE_MEDIA_TYPE:
        raise CertificateObservationError(
            f"Unsupported Sigstore bundle mediaType: {bundle.get('mediaType')!r}."
        )

    statement = _statement_from_envelope(verified_envelope)
    if statement.get("predicateType") != predicate_type:
        raise CertificateObservationError("Verified statement predicate type does not match the requested type.")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise CertificateObservationError("Verified statement must contain exactly one subject.")
    subject = subjects[0]
    if subject.get("name") != repository:
        raise CertificateObservationError("Verified statement subject repository mismatch.")
    if subject.get("digest") != {"sha256": digest}:
        raise CertificateObservationError("Verified statement subject digest mismatch.")

    certificate_der = _certificate_from_bundle(bundle)
    try:
        cert = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise CertificateObservationError(f"Bundle leaf certificate DER is invalid: {exc}") from exc

    raw_extensions: dict[str, bytes] = {}
    extension_inventory = []
    for extension in cert.extensions:
        oid = extension.oid.dotted_string
        if oid in raw_extensions:
            raise CertificateObservationError(f"Certificate contains duplicate extension OID {oid}.")
        raw_value = getattr(extension.value, "value", None)
        if raw_value is None:
            # Parsed standard extensions expose their DER value through
            # public_bytes(); retain it rather than dropping the extension.
            raw_value = extension.value.public_bytes()
        raw_extensions[oid] = raw_value
        extension_inventory.append(
            {
                "oid": oid,
                "critical": extension.critical,
                "raw_value_hex": raw_value.hex(),
            }
        )

    fulcio_claims: dict[str, Any] = {}
    for suffix, name in LEGACY_CLAIMS.items():
        value = _claim_value(raw_extensions, suffix, der=False)
        if value is not None:
            fulcio_claims[name] = value
    for suffix, name in GENERIC_CLAIMS.items():
        value = _claim_value(raw_extensions, suffix, der=True)
        if value is not None:
            fulcio_claims[name] = value

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san_uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        san_uris = []
    if len(san_uris) != 1:
        raise CertificateObservationError(
            f"Expected exactly one URI SAN identity; found {len(san_uris)}."
        )

    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        eku_oids = [oid.dotted_string for oid in eku]
    except x509.ExtensionNotFound:
        eku_oids = []

    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        digital_signature = key_usage.digital_signature
    except x509.ExtensionNotFound:
        digital_signature = False

    if not digital_signature or ExtendedKeyUsageOID.CODE_SIGNING.dotted_string not in eku_oids:
        raise CertificateObservationError("Fulcio certificate lacks code-signing key usage.")

    legacy_generic_pairs = {
        "iss": "issuer",
        "event_name": "build_trigger",
        "source_sha": "source_repository_digest",
        "repository": "source_repository_uri",
        "ref": "source_repository_ref",
    }
    for legacy, generic in legacy_generic_pairs.items():
        if legacy in fulcio_claims and generic in fulcio_claims:
            if fulcio_claims[legacy] != fulcio_claims[generic]:
                raise CertificateObservationError(
                    f"Legacy and generic Fulcio claims disagree: {legacy} vs {generic}."
                )

    cert_der_sha256 = hashlib.sha256(certificate_der).hexdigest()
    return {
        "schema_version": "1.0.0",
        "observation": {
            "status": "passed",
            "bundle_media_type": bundle["mediaType"],
            "bundle_count": len(bundles),
            "matching_bundle_count": 1,
            "verified_envelope_match": True,
            "verified_envelope_payload_type": verified_envelope["payloadType"],
            "verified_envelope_signature_count": len(verified_envelope["signatures"]),
            "predicate_type": predicate_type,
            "statement_type": statement.get("_type"),
            "subject_repository": repository,
            "subject_digest": f"sha256:{digest}",
        },
        "certificate": {
            "sha256": cert_der_sha256,
            "der_base64": base64.b64encode(certificate_der).decode("ascii"),
            "serial_number": str(cert.serial_number),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "subject_alt_name_uris": san_uris,
            "key_usage_digital_signature": digital_signature,
            "extended_key_usage_oids": eku_oids,
            "fulcio_claims": fulcio_claims,
            "extensions": sorted(extension_inventory, key=lambda item: item["oid"]),
        },
        "interpretation": {
            "signature_verification": "delegated_to_cosign_verified_envelope",
            "certificate_chain_verification": "delegated_to_cosign",
            "transparency_verification": "delegated_to_cosign",
            "trust_policy_decision": "not_evaluated",
            "deployment_authorization": "not_granted",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundles", required=True, type=Path)
    parser.add_argument("--verified-envelope", required=True, type=Path)
    parser.add_argument("--artifact-reference", required=True)
    parser.add_argument("--predicate-type", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = observe_certificate(
            args.bundles,
            args.verified_envelope,
            artifact_reference=args.artifact_reference,
            predicate_type=args.predicate_type,
        )
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (CertificateObservationError, OSError) as exc:
        print(f"Fulcio certificate observation failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Fulcio certificate observation passed: "
        f"{result['certificate']['sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
