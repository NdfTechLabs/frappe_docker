import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

TESTS_DIR = str(Path(__file__).resolve().parent)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from scripts import observe_fulcio_certificate as observer  # noqa: E402

PDD_PREDICATE = "https://ndftechlabs.com/attestations/pdd-image-binding/v1"
IMAGE_PREDICATE = "https://slsa.dev/provenance/v1"
REPOSITORY = "ghcr.io/ndftechlabs/dalali"
DIGEST = "a" * 64
ARTIFACT_REFERENCE = f"{REPOSITORY}@sha256:{DIGEST}"


def _der_utf8(value):
    encoded = value.encode("utf-8")
    if len(encoded) < 128:
        return b"\x0c" + bytes([len(encoded)]) + encoded
    length = len(encoded).to_bytes((len(encoded).bit_length() + 7) // 8, "big")
    return b"\x0c" + bytes([0x80 | len(length)]) + length + encoded


def _certificate_der(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-fulcio")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        "https://github.com/NdfTechLabs/frappe_docker/.github/workflows/ndf-publish-product.yml@refs/heads/main"
                    )
                ]
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
    )
    claims = {
        "1": b"https://token.actions.githubusercontent.com",
        "2": b"workflow_dispatch",
        "3": b"a042e49b27dc13cfc45023d29acc52a80204588f",
        "4": b"NDF / Publish Product Images",
        "5": b"NdfTechLabs/frappe_docker",
        "6": b"refs/heads/main",
    }
    for suffix, value in claims.items():
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier(f"{observer.FULCIO_OID_PREFIX}{suffix}"), value
            ),
            critical=False,
        )
    generic = {
        "8": "https://token.actions.githubusercontent.com",
        "9": "https://github.com/NdfTechLabs/frappe_docker/.github/workflows/ndf-publish-product.yml@refs/heads/main",
        "10": "a042e49b27dc13cfc45023d29acc52a80204588f",
        "11": "github-hosted",
        "12": "https://github.com/NdfTechLabs/frappe_docker",
        "13": "a042e49b27dc13cfc45023d29acc52a80204588f",
        "14": "refs/heads/main",
        "20": "workflow_dispatch",
        "21": "https://github.com/NdfTechLabs/frappe_docker/actions/runs/123456789/attempts/1",
    }
    for suffix, value in generic.items():
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier(f"{observer.FULCIO_OID_PREFIX}{suffix}"),
                _der_utf8(value),
            ),
            critical=False,
        )
    # Unknown Fulcio extension must survive parsing without being discarded.
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            ObjectIdentifier("1.3.6.1.4.1.57264.99.1"), b"opaque-extension"
        ),
        critical=False,
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _fixture(
    tmp_path,
    *,
    envelope_mutation=None,
    bundle_count=1,
    include_certificate=True,
    certificate_key_mismatch=False,
):
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": REPOSITORY, "digest": {"sha256": DIGEST}}],
        "predicateType": PDD_PREDICATE,
        "predicate": {"descriptor": {"id": "dalali-v16"}},
    }
    payload_type = "application/vnd.in-toto+json"
    payload = json.dumps(statement, separators=(",", ":")).encode()
    payload_type_bytes = payload_type.encode()
    pae = (
        b"DSSEv1 "
        + str(len(payload_type_bytes)).encode()
        + b" "
        + payload_type_bytes
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )
    signing_key = ec.generate_private_key(ec.SECP256R1())
    envelope = {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "sig": base64.b64encode(
                    signing_key.sign(pae, ec.ECDSA(hashes.SHA256()))
                ).decode(),
                "keyid": "",
            }
        ],
    }
    bundle_envelope = json.loads(json.dumps(envelope))
    if envelope_mutation:
        envelope_mutation(bundle_envelope)
    bundle = {
        "mediaType": observer.BUNDLE_MEDIA_TYPE,
        "verificationMaterial": {
            "certificate": (
                {
                    "rawBytes": base64.b64encode(
                        _certificate_der(
                            ec.generate_private_key(ec.SECP256R1())
                            if certificate_key_mismatch
                            else signing_key
                        )
                    ).decode()
                }
                if include_certificate
                else {}
            ),
            "tlogEntries": [{"logIndex": "123"}],
        },
        "dsseEnvelope": bundle_envelope,
    }
    bundles = [bundle for _ in range(bundle_count)]
    bundle_path = tmp_path / "bundles.jsonl"
    bundle_path.write_text(
        "".join(json.dumps(item) + "\n" for item in bundles), encoding="utf-8"
    )
    envelope_path = tmp_path / "verified-envelope.json"
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
    return bundle_path, envelope_path


def test_extracts_legacy_and_generic_fulcio_claims_and_preserves_extensions(tmp_path):
    bundles, verified = _fixture(tmp_path)
    result = observer.observe_certificate(
        bundles,
        verified,
        artifact_reference=ARTIFACT_REFERENCE,
        predicate_type=PDD_PREDICATE,
        identity_id="product-image-publication",
    )

    assert result["observation"]["verified_envelope_match"] is True
    assert result["observation"]["matching_bundle_count"] == 1
    claims = result["certificate"]["fulcio_claims"]
    assert claims["iss"] == "https://token.actions.githubusercontent.com"
    assert claims["issuer"] == claims["iss"]
    assert claims["repository"] == "NdfTechLabs/frappe_docker"
    assert claims["source_repository_uri"] == (
        "https://github.com/NdfTechLabs/frappe_docker"
    )
    assert claims["event_name"] == claims["build_trigger"] == "workflow_dispatch"
    assert claims["ref"] == claims["source_repository_ref"] == "refs/heads/main"
    assert claims["source_sha"] == claims["source_repository_digest"]
    assert claims["workflow_ref"] == (
        "NdfTechLabs/frappe_docker/.github/workflows/"
        "ndf-publish-product.yml@refs/heads/main"
    )
    assert claims["run_id"] == "123456789"
    assert claims["run_attempt"] == 1
    assert result["policy_observation"]["identity_claims_validated"] is True
    assert result["observation"]["certificate_signature_verified"] is True
    assert any(
        item["oid"] == "1.3.6.1.4.1.57264.99.1"
        for item in result["certificate"]["extensions"]
    )
    assert result["interpretation"]["deployment_authorization"] == "not_granted"


def test_rejects_bundle_without_exact_verified_envelope_match(tmp_path):
    bundles, verified = _fixture(
        tmp_path,
        envelope_mutation=lambda value: value.update(
            payloadType="application/attacker"
        ),
    )
    with pytest.raises(
        observer.CertificateObservationError, match="exactly one bundle"
    ):
        observer.observe_certificate(
            bundles,
            verified,
            artifact_reference=ARTIFACT_REFERENCE,
            predicate_type=PDD_PREDICATE,
            identity_id="product-image-publication",
        )


def test_rejects_ambiguous_duplicate_matching_bundles(tmp_path):
    bundles, verified = _fixture(tmp_path, bundle_count=2)
    with pytest.raises(observer.CertificateObservationError, match="found 2"):
        observer.observe_certificate(
            bundles,
            verified,
            artifact_reference=ARTIFACT_REFERENCE,
            predicate_type=PDD_PREDICATE,
            identity_id="product-image-publication",
        )


def test_rejects_bundle_without_leaf_certificate(tmp_path):
    bundles, verified = _fixture(tmp_path, include_certificate=False)
    with pytest.raises(observer.CertificateObservationError, match="no supported leaf"):
        observer.observe_certificate(
            bundles,
            verified,
            artifact_reference=ARTIFACT_REFERENCE,
            predicate_type=PDD_PREDICATE,
            identity_id="product-image-publication",
        )


def test_rejects_wrong_predicate_type(tmp_path):
    bundles, verified = _fixture(tmp_path)
    with pytest.raises(observer.CertificateObservationError, match="predicate type"):
        observer.observe_certificate(
            bundles,
            verified,
            artifact_reference=ARTIFACT_REFERENCE,
            predicate_type=IMAGE_PREDICATE,
            identity_id="product-image-publication",
        )


def test_rejects_wrong_subject_digest(tmp_path):
    bundles, verified = _fixture(tmp_path)
    with pytest.raises(observer.CertificateObservationError, match="subject digest"):
        observer.observe_certificate(
            bundles,
            verified,
            artifact_reference=f"{REPOSITORY}@sha256:{'b' * 64}",
            predicate_type=PDD_PREDICATE,
            identity_id="product-image-publication",
        )


def test_rejects_malformed_der_utf8_length():
    with pytest.raises(observer.CertificateObservationError, match="DER length"):
        observer._decode_der_utf8_string(bytes([0x0C, 0x82, 0x00]), "1.2.3")


def test_rejects_non_utf8_legacy_claim():
    with pytest.raises(observer.CertificateObservationError, match="not UTF-8"):
        observer._claim_value(
            {observer.FULCIO_OID_PREFIX + "1": b"\xff"}, "1", der=False
        )


def test_rejects_duplicate_json_keys_in_bundle(tmp_path):
    path = tmp_path / "bundles.jsonl"
    path.write_text('{"mediaType":"one","mediaType":"two"}' + chr(10), encoding="utf-8")
    with pytest.raises(
        observer.CertificateObservationError, match="Duplicate JSON key"
    ):
        observer._read_jsonl(path)


def test_rejects_certificate_that_does_not_verify_the_verified_envelope_signature(
    tmp_path,
):
    bundles, verified = _fixture(tmp_path, certificate_key_mismatch=True)
    with pytest.raises(
        observer.CertificateObservationError,
        match="does not verify the exact DSSE envelope signature",
    ):
        observer.observe_certificate(
            bundles,
            verified,
            artifact_reference=ARTIFACT_REFERENCE,
            predicate_type=PDD_PREDICATE,
            identity_id="product-image-publication",
        )
