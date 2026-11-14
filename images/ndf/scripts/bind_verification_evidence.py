#!/usr/bin/env python3
"""Create a digest-bound manifest for the exact bytes of image verification evidence."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "image-verification-evidence-v1.schema.json"
REQUIRED_EVIDENCE = {"lock_v2","apps_json","build_metadata","buildx_metadata","build_inventory","build_evidence","source_provenance","source_provenance_verification","source_tree_post_cleanup","source_tree_runtime","image_composition_verification"}

class VerificationEvidenceError(Exception):
    """Raised when evidence cannot be safely bound to an image digest."""

def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def create_verification_evidence(*, image_reference: str, image_repository: str, image_id: str, image_digest: str, lock_bytes: bytes, artifacts: dict[str, tuple[str, bytes]], statuses: dict[str, str]) -> dict[str, Any]:
    """Hash exact evidence bytes and bind the inventory to one immutable image digest."""
    if not image_reference or not image_repository or not image_id:
        raise VerificationEvidenceError("Image reference, repository and image ID are required.")
    if not isinstance(image_digest, str) or not image_digest.startswith("sha256:"):
        raise VerificationEvidenceError("A sha256 OCI image digest is required.")
    digest_hex = image_digest.removeprefix("sha256:")
    if len(digest_hex) != 64 or any(c not in "0123456789abcdef" for c in digest_hex):
        raise VerificationEvidenceError("OCI image digest must contain 64 lowercase hexadecimal characters.")
    if not isinstance(lock_bytes, bytes) or not lock_bytes:
        raise VerificationEvidenceError("Exact generated lock-v2 bytes are required.")
    missing, unexpected = REQUIRED_EVIDENCE-set(artifacts), set(artifacts)-REQUIRED_EVIDENCE
    if missing or unexpected:
        raise VerificationEvidenceError(f"Evidence inventory mismatch: missing={sorted(missing)}, unexpected={sorted(unexpected)}.")
    required_passes = {"source_provenance_verification","source_tree_post_cleanup","source_tree_runtime","image_composition_verification"}
    if any(statuses.get(name) != "passed" for name in required_passes):
        raise VerificationEvidenceError("One or more independent verification reports did not pass.")
    records=[]
    for name in sorted(REQUIRED_EVIDENCE):
        path, raw=artifacts[name]
        if not isinstance(path,str) or not path or not isinstance(raw,bytes) or not raw:
            raise VerificationEvidenceError(f"Evidence bytes are missing or invalid for {name}.")
        records.append({"name":name,"path":path,"sha256":_sha256(raw),"size_bytes":len(raw)})
    report={"schema_version":"1.0","algorithm":"ndf-image-verification-evidence-v1",
      "image":{"reference":image_reference,"repository":image_repository,"id":image_id,"digest":image_digest},
      "lock":{"version":2,"sha256":_sha256(lock_bytes)},"evidence":records,"status":"bound"}
    try:
        schema=json.loads(SCHEMA_PATH.read_text(encoding="utf-8")); Draft202012Validator(schema).validate(report)
    except (OSError,json.JSONDecodeError) as exc:
        raise VerificationEvidenceError(f"Unable to load evidence schema: {exc}") from exc
    except ValidationError as exc:
        location=".".join(str(p) for p in exc.absolute_path) or "<root>"
        raise VerificationEvidenceError(f"Verification evidence schema failed at {location}: {exc.message}") from exc
    return report

def verify_verification_evidence(report: dict[str,Any], *, expected_image_digest: str, expected_lock_sha256: str, artifacts: dict[str,tuple[str,bytes]]) -> None:
    """Recompute evidence hashes and reject image/lock swaps or altered report bytes."""
    if report.get("image",{}).get("digest") != expected_image_digest:
        raise VerificationEvidenceError("Verification evidence is bound to a different image digest.")
    if report.get("lock",{}).get("sha256") != expected_lock_sha256:
        raise VerificationEvidenceError("Verification evidence is bound to a different lock-v2.")
    entries=report.get("evidence",[]); observed={item.get("name"):item for item in entries}
    if len(observed)!=len(entries) or set(observed)!=set(artifacts):
        raise VerificationEvidenceError("Verification evidence entries are missing, duplicated or unexpected.")
    for name,(path,raw) in artifacts.items():
        rec=observed[name]
        if rec.get("path")!=path or rec.get("sha256")!=_sha256(raw) or rec.get("size_bytes")!=len(raw):
            raise VerificationEvidenceError(f"Verification evidence hash/identity mismatch for {name}.")
    if observed["lock_v2"]["sha256"] != expected_lock_sha256:
        raise VerificationEvidenceError("Lock-v2 evidence entry does not match the report lock identity.")

def write_report(report:dict[str,Any],path:Path)->bytes:
    """Write deterministic UTF-8 JSON and return the exact bytes written."""
    raw=(json.dumps(report,indent=2,sort_keys=True)+"\n").encode("utf-8")
    path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw); return raw
