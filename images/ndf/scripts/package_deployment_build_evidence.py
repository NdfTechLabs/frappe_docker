#!/usr/bin/env python3
"""Pack and verify an attempt-scoped NDF deployment-build evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

RESULT_FILENAME = "deployment-build-result.json"
REPORT_FILENAME = "deployment-build-trust-evidence.json"
MANIFEST_FILENAME = "deployment-build-evidence-bundle-v1.json"
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class EvidenceBundleError(Exception):
    """Raised when bundle inputs, contents or bindings are invalid."""


def _strict_json(raw: bytes, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise EvidenceBundleError(
                    f"{label} contains duplicate JSON key {key!r}."
                )
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                EvidenceBundleError(f"{label} contains invalid constant {token}.")
            ),
        )
    except EvidenceBundleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceBundleError(f"{label} is not valid UTF-8 JSON.") from exc


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        raise EvidenceBundleError(f"{label} must not be a symlink.")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvidenceBundleError(f"Unable to read {label}: {exc}") from exc
    value = _strict_json(raw, label)
    if not isinstance(value, dict):
        raise EvidenceBundleError(f"{label} root must be an object.")
    return value, raw


def _validate_schema(value: dict[str, Any], path: Path, label: str) -> None:
    try:
        schema = _strict_json(path.read_bytes(), f"{label} schema")
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
                value
            ),
            key=lambda error: (tuple(map(str, error.absolute_path)), error.message),
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceBundleError(f"Unable to load {label} schema: {exc}") from exc
    if errors:
        first = errors[0]
        location = ".".join(map(str, first.absolute_path)) or "<root>"
        raise EvidenceBundleError(
            f"{label} violates schema at {location}: {first.message}"
        )


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise EvidenceBundleError(f"{label} must be a non-empty POSIX relative path.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EvidenceBundleError(f"{label} is not a safe relative path: {value!r}.")
    if path.as_posix() != value:
        raise EvidenceBundleError(f"{label} is not canonical: {value!r}.")
    return path


def _safe_source_file(root: Path, reference: str) -> Path:
    relative = _safe_relative(reference, "Evidence reference")
    if root.is_symlink():
        raise EvidenceBundleError("Evidence source directory must not be a symlink.")
    try:
        root_resolved = root.resolve(strict=True)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise EvidenceBundleError(
                    f"Evidence source contains a symlink: {reference}."
                )
        resolved = current.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except EvidenceBundleError:
        raise
    except (OSError, ValueError) as exc:
        raise EvidenceBundleError(
            f"Evidence source is missing or escapes its root: {reference}."
        ) from exc
    if not resolved.is_file():
        raise EvidenceBundleError(
            f"Evidence source is not a regular file: {reference}."
        )
    return resolved


def _report_evidence_references(report: dict[str, Any]) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    candidate_origin = report.get("candidate_origin")
    if isinstance(candidate_origin, dict):
        refs = candidate_origin.get("evidence_references", [])
        if not isinstance(refs, list):
            raise EvidenceBundleError(
                "Candidate-origin evidence references must be an array."
            )
        references.extend(refs)

    artifacts = report.get("ndf_artifacts", {})
    if artifacts is not None and not isinstance(artifacts, dict):
        raise EvidenceBundleError("NDF artifact evidence must be an object.")
    if isinstance(artifacts, dict):
        for artifact_name in ("image", "descriptor"):
            artifact = artifacts.get(artifact_name)
            if artifact is None:
                continue
            if not isinstance(artifact, dict):
                raise EvidenceBundleError(
                    f"NDF {artifact_name} evidence must be an object."
                )
            refs = artifact.get("evidence_references", [])
            if not isinstance(refs, list):
                raise EvidenceBundleError(
                    f"NDF {artifact_name} evidence references must be an array."
                )
            references.extend(refs)

    seen: set[str] = set()
    normalized: list[dict[str, str]] = []
    for item in references:
        if not isinstance(item, dict):
            raise EvidenceBundleError("Evidence reference must be an object.")
        reference = item.get("reference")
        digest = item.get("sha256")
        if not isinstance(reference, str) or not isinstance(digest, str):
            raise EvidenceBundleError(
                "Evidence reference requires reference and sha256."
            )
        _safe_relative(reference, "Evidence reference")
        if reference in seen:
            raise EvidenceBundleError(f"Duplicate evidence reference: {reference}.")
        seen.add(reference)
        if not HASH_PATTERN.fullmatch(digest):
            raise EvidenceBundleError(f"Invalid evidence SHA-256 for {reference}.")
        normalized.append({"reference": reference, "sha256": digest})
    return normalized


def _validate_pair(
    result: dict[str, Any],
    result_bytes: bytes,
    report: dict[str, Any],
    schema_dir: Path,
) -> dict[str, Any]:
    _validate_schema(
        result,
        schema_dir / "deployment-build-result-v1.schema.json",
        "Deployment Build result",
    )
    _validate_schema(
        report,
        schema_dir / "deployment-build-trust-evidence-v1.schema.json",
        "Deployment Build trust-evidence report",
    )

    workflow = result.get("workflow")
    if not isinstance(workflow, dict):
        raise EvidenceBundleError("Deployment Build result workflow is missing.")
    run_id = workflow.get("run_id")
    attempt = workflow.get("run_attempt")
    source_commit = workflow.get("source_commit")
    candidate_id = result.get("candidate_id")
    correlation_id = result.get("correlation_id")
    if (
        not isinstance(run_id, str)
        or not run_id.isdigit()
        or not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
        or not isinstance(source_commit, str)
        or not re.fullmatch(r"[a-f0-9]{40,64}", source_commit)
    ):
        raise EvidenceBundleError(
            "Deployment Build result workflow identity is invalid."
        )
    if not isinstance(candidate_id, str) or not candidate_id:
        raise EvidenceBundleError("Deployment Build result candidate ID is missing.")
    if not isinstance(correlation_id, str) or not UUID_PATTERN.fullmatch(
        correlation_id
    ):
        raise EvidenceBundleError(
            "Deployment Build result correlation UUID is invalid."
        )

    result_id = f"ndf-{run_id}-{attempt}"
    if result.get("result_id") != result_id:
        raise EvidenceBundleError(
            "Deployment Build result ID does not match run/attempt."
        )
    if report.get("report_id") != f"{result_id}-trust":
        raise EvidenceBundleError("Trust report ID does not match result run/attempt.")
    if report.get("candidate_id") != candidate_id:
        raise EvidenceBundleError("Trust report candidate ID differs from result.")
    if report.get("correlation_id") != correlation_id:
        raise EvidenceBundleError("Trust report correlation ID differs from result.")

    report_workflow = report.get("workflow")
    expected_workflow = {
        "repository": "NdfTechLabs/frappe_docker",
        "run_id": run_id,
        "run_attempt": attempt,
        "source_commit": source_commit,
    }
    if report_workflow != expected_workflow:
        raise EvidenceBundleError("Trust report workflow identity differs from result.")

    candidate_origin = report.get("candidate_origin")
    if not isinstance(candidate_origin, dict):
        raise EvidenceBundleError("Trust report candidate-origin decision is missing.")
    if result.get("status") == "succeeded" and candidate_origin.get("decision") != "verified":
        raise EvidenceBundleError(
            "A successful deployment build result requires verified candidate origin."
        )

    binding = report.get("result_binding")
    expected_hash = hashlib.sha256(result_bytes).hexdigest()
    if not isinstance(binding, dict):
        raise EvidenceBundleError("Trust report result binding is missing.")
    if (
        binding.get("result_id") != result_id
        or binding.get("result_file") != RESULT_FILENAME
        or binding.get("result_sha256") != expected_hash
    ):
        raise EvidenceBundleError(
            "Trust report does not bind the exact terminal result bytes."
        )

    return {
        "candidate_id": candidate_id,
        "correlation_id": correlation_id,
        "workflow": expected_workflow,
        "result_id": result_id,
        "result_sha256": expected_hash,
    }


def _manifest_file(role: str, path: str, raw: bytes) -> dict[str, Any]:
    return {
        "role": role,
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def pack_bundle(
    *,
    result_path: Path,
    report_path: Path,
    evidence_root: Path,
    schema_dir: Path,
    output_dir: Path,
) -> dict[str, Any]:
    result, result_bytes = _read_json(result_path, "Deployment Build result")
    report, report_bytes = _read_json(
        report_path, "Deployment Build trust-evidence report"
    )
    identity = _validate_pair(result, result_bytes, report, schema_dir)
    references = _report_evidence_references(report)

    if evidence_root.is_symlink():
        raise EvidenceBundleError("Evidence source directory must not be a symlink.")
    files: list[dict[str, Any]] = [
        _manifest_file("result", RESULT_FILENAME, result_bytes),
        _manifest_file("trust_evidence", REPORT_FILENAME, report_bytes),
    ]
    evidence_payloads: list[tuple[str, bytes]] = []
    for item in references:
        source = _safe_source_file(evidence_root, item["reference"])
        raw = source.read_bytes()
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != item["sha256"]:
            raise EvidenceBundleError(
                f"Evidence SHA-256 differs from trust report: {item['reference']}."
            )
        bundle_path = f"evidence/{item['reference']}"
        evidence_payloads.append((bundle_path, raw))
        files.append(_manifest_file("evidence", bundle_path, raw))

    paths = [item["path"] for item in files]
    if len(paths) != len(set(paths)):
        raise EvidenceBundleError("Bundle contains duplicate file paths.")

    manifest = {
        "schema_version": "1.0.0",
        "bundle_id": f"ndf-{identity['workflow']['run_id']}-{identity['workflow']['run_attempt']}-evidence",
        "candidate_id": identity["candidate_id"],
        "correlation_id": identity["correlation_id"],
        "workflow": identity["workflow"],
        "files": files,
    }
    _validate_schema(
        manifest,
        schema_dir / "deployment-build-evidence-bundle-v1.schema.json",
        "Deployment Build evidence bundle manifest",
    )

    if output_dir.exists() or output_dir.is_symlink():
        raise EvidenceBundleError(
            "Refusing to overwrite an existing evidence bundle directory."
        )
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent)
    )
    try:
        (temporary / RESULT_FILENAME).write_bytes(result_bytes)
        (temporary / REPORT_FILENAME).write_bytes(report_bytes)
        for relative, raw in evidence_payloads:
            destination = temporary.joinpath(*PurePosixPath(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        manifest_bytes = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode()
        (temporary / MANIFEST_FILENAME).write_bytes(manifest_bytes)
        os.replace(temporary, output_dir)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def _walk_regular_files(root: Path) -> tuple[set[str], set[str]]:
    found_files: set[str] = set()
    found_dirs: set[str] = set()
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in list(dirs):
            path = current_path / name
            if path.is_symlink():
                raise EvidenceBundleError(
                    f"Bundle contains a symlink directory: {path}."
                )
            found_dirs.add(path.relative_to(root).as_posix())
        for name in files:
            path = current_path / name
            if path.is_symlink():
                raise EvidenceBundleError(f"Bundle contains a symlink file: {path}.")
            if not path.is_file():
                raise EvidenceBundleError(
                    f"Bundle contains a non-regular file: {path}."
                )
            found_files.add(path.relative_to(root).as_posix())
    return found_files, found_dirs


def verify_bundle(*, bundle_dir: Path, schema_dir: Path) -> dict[str, Any]:
    if bundle_dir.is_symlink() or not bundle_dir.is_dir():
        raise EvidenceBundleError(
            "Bundle root must be a real directory, not a symlink."
        )
    manifest_path = bundle_dir / MANIFEST_FILENAME
    manifest, _ = _read_json(manifest_path, "Evidence bundle manifest")
    _validate_schema(
        manifest,
        schema_dir / "deployment-build-evidence-bundle-v1.schema.json",
        "Deployment Build evidence bundle manifest",
    )

    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise EvidenceBundleError("Bundle manifest files must be an array.")
    by_path: dict[str, dict[str, Any]] = {}
    role_counts: dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise EvidenceBundleError("Bundle file entry must be an object.")
        relative = _safe_relative(entry.get("path"), "Bundle file path").as_posix()
        if relative in by_path:
            raise EvidenceBundleError(f"Duplicate bundle path: {relative}.")
        by_path[relative] = entry
        role_counts[entry.get("role")] = role_counts.get(entry.get("role"), 0) + 1
    if role_counts.get("result") != 1 or role_counts.get("trust_evidence") != 1:
        raise EvidenceBundleError(
            "Bundle must contain exactly one result and one trust report."
        )
    if by_path.get(RESULT_FILENAME, {}).get("role") != "result":
        raise EvidenceBundleError("Bundle result must use the canonical filename.")
    if by_path.get(REPORT_FILENAME, {}).get("role") != "trust_evidence":
        raise EvidenceBundleError(
            "Bundle trust report must use the canonical filename."
        )
    for path, entry in by_path.items():
        if entry.get("role") == "evidence":
            if not path.startswith("evidence/"):
                raise EvidenceBundleError(
                    "Evidence files must be stored under evidence/."
                )
            if path == MANIFEST_FILENAME:
                raise EvidenceBundleError("Manifest cannot also be listed as evidence.")
        if entry.get("role") not in {"result", "trust_evidence", "evidence"}:
            raise EvidenceBundleError(
                f"Unsupported bundle file role: {entry.get('role')!r}."
            )

    expected_paths = set(by_path) | {MANIFEST_FILENAME}
    actual_paths, actual_dirs = _walk_regular_files(bundle_dir)
    expected_dirs: set[str] = set()
    for relative in expected_paths:
        parent = PurePosixPath(relative).parent
        while parent.as_posix() != ".":
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    if actual_paths != expected_paths or actual_dirs != expected_dirs:
        missing = sorted(expected_paths - actual_paths)
        unexpected = sorted(actual_paths - expected_paths)
        unexpected_dirs = sorted(actual_dirs - expected_dirs)
        missing_dirs = sorted(expected_dirs - actual_dirs)
        raise EvidenceBundleError(
            "Bundle file set mismatch; "
            f"missing={missing}, unexpected={unexpected}, "
            f"missing_dirs={missing_dirs}, unexpected_dirs={unexpected_dirs}."
        )

    contents: dict[str, bytes] = {}
    for relative, entry in by_path.items():
        path = bundle_dir.joinpath(*PurePosixPath(relative).parts)
        if path.is_symlink():
            raise EvidenceBundleError(f"Bundle file is a symlink: {relative}.")
        raw = path.read_bytes()
        if len(raw) != entry.get("size"):
            raise EvidenceBundleError(f"Bundle file size mismatch: {relative}.")
        if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
            raise EvidenceBundleError(f"Bundle file SHA-256 mismatch: {relative}.")
        contents[relative] = raw

    result = _strict_json(contents[RESULT_FILENAME], "Deployment Build result")
    report = _strict_json(
        contents[REPORT_FILENAME], "Deployment Build trust-evidence report"
    )
    if not isinstance(result, dict) or not isinstance(report, dict):
        raise EvidenceBundleError(
            "Bundle result and trust report must be JSON objects."
        )
    identity = _validate_pair(result, contents[RESULT_FILENAME], report, schema_dir)

    workflow = manifest.get("workflow")
    if (
        manifest.get("candidate_id") != identity["candidate_id"]
        or manifest.get("correlation_id") != identity["correlation_id"]
        or workflow != identity["workflow"]
    ):
        raise EvidenceBundleError(
            "Bundle manifest identity differs from result/report."
        )
    expected_bundle_id = f"ndf-{workflow['run_id']}-{workflow['run_attempt']}-evidence"
    if manifest.get("bundle_id") != expected_bundle_id:
        raise EvidenceBundleError("Bundle ID does not match workflow run/attempt.")

    references = _report_evidence_references(report)
    expected_evidence: dict[str, str] = {}
    for item in references:
        relative = f"evidence/{item['reference']}"
        if relative in expected_evidence:
            raise EvidenceBundleError(f"Duplicate evidence bundle path: {relative}.")
        expected_evidence[relative] = item["sha256"]
    actual_evidence = {
        path: entry["sha256"]
        for path, entry in by_path.items()
        if entry.get("role") == "evidence"
    }
    if actual_evidence != expected_evidence:
        raise EvidenceBundleError(
            "Bundle evidence files do not exactly match trust-report references."
        )
    for path, digest in expected_evidence.items():
        if by_path[path].get("sha256") != digest:
            raise EvidenceBundleError(
                f"Evidence hash differs from trust report: {path}."
            )

    return {
        "bundle_id": manifest["bundle_id"],
        "candidate_id": identity["candidate_id"],
        "correlation_id": identity["correlation_id"],
        "result_id": identity["result_id"],
        "workflow": identity["workflow"],
        "file_count": len(by_path) + 1,
        "transport_integrity": "verified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    pack = subparsers.add_parser(
        "pack", help="Create an immutable attempt-scoped bundle."
    )
    pack.add_argument("--result", required=True, type=Path)
    pack.add_argument("--trust-evidence", required=True, type=Path)
    pack.add_argument("--evidence-root", required=True, type=Path)
    pack.add_argument("--schema-dir", required=True, type=Path)
    pack.add_argument("--output-dir", required=True, type=Path)
    verify = subparsers.add_parser("verify", help="Verify an existing bundle.")
    verify.add_argument("--bundle-dir", required=True, type=Path)
    verify.add_argument("--schema-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "pack":
            manifest = pack_bundle(
                result_path=args.result,
                report_path=args.trust_evidence,
                evidence_root=args.evidence_root,
                schema_dir=args.schema_dir,
                output_dir=args.output_dir,
            )
            print(
                json.dumps(
                    {
                        "bundle_id": manifest["bundle_id"],
                        "files": len(manifest["files"]) + 1,
                    },
                    sort_keys=True,
                )
            )
        else:
            result = verify_bundle(
                bundle_dir=args.bundle_dir, schema_dir=args.schema_dir
            )
            print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, EvidenceBundleError, json.JSONDecodeError) as exc:
        print(
            f"Deployment Build evidence bundle {args.command} failed: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
