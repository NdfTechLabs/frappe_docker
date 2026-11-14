#!/usr/bin/env python3
"""Compare captured source-tree fingerprints with a later Bench filesystem stage."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from .source_tree_fingerprint import FingerprintError, fingerprint_tree
except ImportError:
    from source_tree_fingerprint import FingerprintError, fingerprint_tree


class SourceTreeVerificationError(Exception):
    """Raised when a later source tree differs from captured provenance."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceTreeVerificationError(
            f"Unable to read JSON evidence {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise SourceTreeVerificationError(f"Expected a JSON object in {path}.")
    return value


def validate_relative_path(value: str, label: str) -> PurePosixPath:
    candidate = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != value
    ):
        raise SourceTreeVerificationError(f"Unsafe {label} path: {value!r}")
    return candidate


def compare_fingerprint(
    root: Path, expected: dict[str, Any], label: str
) -> dict[str, Any]:
    if (
        not isinstance(expected, dict)
        or expected.get("algorithm") != "ndf-source-tree-sha256-v1"
    ):
        raise SourceTreeVerificationError(
            f"Missing or unsupported captured fingerprint for {label}."
        )
    try:
        observed = fingerprint_tree(root)
    except FingerprintError as exc:
        raise SourceTreeVerificationError(
            f"Unable to fingerprint {label}: {exc}"
        ) from exc
    if observed != expected:
        raise SourceTreeVerificationError(
            f"Source-tree fingerprint mismatch for {label}: "
            f"expected={expected.get('sha256')}, observed={observed.get('sha256')}"
        )
    return observed


def verify_submodules(
    parent_root: Path, records: list[dict[str, Any]], label: str
) -> list[dict[str, Any]]:
    results = []
    for record in records:
        if not isinstance(record, dict):
            raise SourceTreeVerificationError(f"Malformed submodule record in {label}.")
        relative = validate_relative_path(record.get("path", ""), f"{label} submodule")
        child = parent_root.joinpath(*relative.parts)
        materialized = record.get("materialized")
        if not isinstance(materialized, bool):
            raise SourceTreeVerificationError(
                f"Missing materialization state for {label}:{relative}."
            )
        if materialized:
            if child.is_symlink() or not child.is_dir():
                raise SourceTreeVerificationError(
                    f"Materialized submodule is missing or unsafe: {label}:{relative}"
                )
            observed = compare_fingerprint(
                child, record.get("source_tree"), f"{label}:{relative}"
            )
            nested = verify_submodules(
                child, record.get("submodules", []), f"{label}:{relative}"
            )
            results.append(
                {
                    "path": relative.as_posix(),
                    "materialized": True,
                    "expected_commit": record.get("expected_commit"),
                    "expected_source_tree": record["source_tree"],
                    "observed_source_tree": observed,
                    "matches": True,
                    "submodules": nested,
                }
            )
        else:
            if child.is_symlink() or (child.exists() and not child.is_dir()):
                raise SourceTreeVerificationError(
                    f"Uninitialized submodule path is unsafe: {label}:{relative}"
                )
            results.append(
                {
                    "path": relative.as_posix(),
                    "materialized": False,
                    "expected_commit": record.get("expected_commit"),
                    "expected_source_tree": None,
                    "observed_source_tree": None,
                    "matches": True,
                    "submodules": [],
                }
            )
    return results


def verify_source_trees(
    bench_path: Path, provenance_path: Path, stage: str, output_path: Path
) -> dict[str, Any]:
    if stage not in {"post_cleanup", "runtime_image"}:
        raise SourceTreeVerificationError(f"Unsupported verification stage: {stage}")
    bench = bench_path.resolve()
    apps_root = bench / "apps"
    if not apps_root.is_dir() or apps_root.is_symlink():
        raise SourceTreeVerificationError(
            f"Bench apps directory is missing or unsafe: {apps_root}"
        )

    provenance = load_json(provenance_path)
    if (
        provenance.get("schema_version") != "1.0"
        or provenance.get("algorithm") != "ndf-source-provenance-v1"
        or not isinstance(provenance.get("lock"), dict)
        or provenance["lock"].get("version") != 2
        or not re.fullmatch(r"[a-f0-9]{64}", provenance["lock"].get("sha256", ""))
        or not isinstance(provenance.get("repositories"), list)
        or not provenance["repositories"]
    ):
        raise SourceTreeVerificationError(
            "Source provenance evidence has an invalid contract."
        )

    records = provenance["repositories"]
    names = [item.get("name") for item in records if isinstance(item, dict)]
    if len(names) != len(records) or len(names) != len(set(names)):
        raise SourceTreeVerificationError(
            "Source provenance contains invalid or duplicate repository names."
        )

    results = []
    for record in records:
        name = record.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise SourceTreeVerificationError(
                f"Unsafe application name in source provenance: {name!r}"
            )
        app_path = apps_root / name
        if (
            app_path.is_symlink()
            or not app_path.is_dir()
            or not app_path.resolve().is_relative_to(apps_root)
        ):
            raise SourceTreeVerificationError(
                f"Application directory is missing or unsafe: {name}"
            )
        observed = compare_fingerprint(app_path, record.get("source_tree"), name)
        submodules = verify_submodules(app_path, record.get("submodules", []), name)
        results.append(
            {
                "name": name,
                "expected_source_tree": record["source_tree"],
                "observed_source_tree": observed,
                "matches": True,
                "submodules": submodules,
            }
        )

    actual_names = sorted(
        item.name
        for item in apps_root.iterdir()
        if item.is_dir() and not item.name.startswith(".")
    )
    if actual_names != sorted(names):
        raise SourceTreeVerificationError(
            "Application directories differ from source provenance: "
            f"expected={sorted(names)}, actual={actual_names}"
        )

    provenance_bytes = provenance_path.read_bytes()
    report = {
        "schema_version": "1.0",
        "algorithm": "ndf-source-tree-verification-v1",
        "stage": stage,
        "source_provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "lock": provenance["lock"],
        "repositories": results,
        "status": "passed",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output_path)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument(
        "--stage", choices=("post_cleanup", "runtime_image"), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_source_trees(
            args.bench, args.provenance, args.stage, args.output
        )
    except (SourceTreeVerificationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"Verified {len(report['repositories'])} application source trees "
        f"at {report['stage']} stage."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
