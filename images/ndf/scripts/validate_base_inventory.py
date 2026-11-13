#!/usr/bin/env python3
"""Validate repository-tracked Debian base-image package inventory evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


class InventoryError(Exception):
    """Raised when base inventory evidence is incomplete or untrusted."""


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"Unable to read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InventoryError("Inventory manifest must be a JSON object")
    return value


def _safe_inventory_path(root: Path, relative: str, stage: str) -> Path:
    expected = f"{stage}/dpkg-inventory.tsv"
    if relative != expected:
        raise InventoryError(
            f"{stage} inventory path must be exactly {expected!r}; got {relative!r}"
        )
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise InventoryError(f"Inventory path escapes evidence directory: {relative}")
    if not candidate.is_file():
        raise InventoryError(f"Inventory file does not exist: {relative}")
    return candidate


def _validate_tsv(
    path: Path, expected_count: int, expected_sha256: str
) -> list[tuple[str, str, str]]:
    raw = path.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise InventoryError(f"SHA-256 mismatch for {path.name}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InventoryError(f"{path.name} is not UTF-8") from exc

    records: list[tuple[str, str, str]] = []
    previous = None
    seen = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split("\t")
        if len(fields) != 3 or not all(fields):
            raise InventoryError(
                f"Malformed dpkg record at {path.name}:{line_number}; expected name<TAB>version<TAB>architecture"
            )
        record = (fields[0], fields[1], fields[2])
        if any("\r" in field or "\n" in field for field in record):
            raise InventoryError(
                f"Control character in dpkg record at {path.name}:{line_number}"
            )
        if record in seen:
            raise InventoryError(
                f"Duplicate dpkg record at {path.name}:{line_number}: {record}"
            )
        if previous is not None and record < previous:
            raise InventoryError(
                f"Inventory is not sorted deterministically: {path.name}"
            )
        seen.add(record)
        records.append(record)
        previous = record

    if len(records) != expected_count:
        raise InventoryError(
            f"Package count mismatch for {path.name}: manifest={expected_count}, actual={len(records)}"
        )
    if not records:
        raise InventoryError(f"Inventory is empty: {path.name}")
    return records


def validate_inventory_directory(
    evidence_dir: Path, schema_path: Path
) -> tuple[dict, dict[str, list[tuple[str, str, str]]]]:
    root = evidence_dir.resolve()
    manifest_path = root / "inventory-manifest.json"
    manifest = _load_json(manifest_path)
    schema = _load_json(schema_path)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(manifest),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        detail = "; ".join(
            f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors
        )
        raise InventoryError(f"Inventory manifest schema validation failed: {detail}")

    inventories = manifest["inventories"]
    platforms = {
        inventories[stage]["image"]["platform"] for stage in ("builder", "runtime")
    }
    if len(platforms) != 1:
        raise InventoryError("Builder and runtime inventory platforms differ")

    parsed: dict[str, list[tuple[str, str, str]]] = {}
    for stage in ("builder", "runtime"):
        item = inventories[stage]
        image = item["image"]
        digest = image["manifest_digest"]
        if image["reference"].rsplit("@", 1)[-1] != digest:
            raise InventoryError(
                f"{stage} image reference does not match manifest digest"
            )
        path = _safe_inventory_path(root, item["file"], stage)
        parsed[stage] = _validate_tsv(path, item["package_count"], item["sha256"])

    return manifest, parsed


def find_base_package(
    parsed: dict[str, list[tuple[str, str, str]]],
    *,
    scope: str,
    name: str,
    version: str,
    architecture: str,
) -> bool:
    """Check an exact OS package in the inventory corresponding to its stage scope."""
    stage_by_scope = {"build": "builder", "runtime": "runtime"}
    if scope not in stage_by_scope:
        raise InventoryError(f"Unsupported OS package scope: {scope}")
    stage = stage_by_scope[scope]
    return (name, version, architecture) in set(parsed[stage])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "schemas"
        / "base-inventory-manifest-v1.schema.json",
    )
    args = parser.parse_args()
    try:
        manifest, parsed = validate_inventory_directory(args.evidence_dir, args.schema)
    except InventoryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for stage in ("builder", "runtime"):
        image = manifest["inventories"][stage]["image"]
        print(
            f"OK: {stage} {image['manifest_digest']} "
            f"{len(parsed[stage])} dpkg records verified"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
