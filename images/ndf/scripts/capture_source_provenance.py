#!/usr/bin/env python3
"""Capture Git provenance and complete pre-cleanup source-tree evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from .capture_build_inventory import (
        InventoryCaptureError,
        capture_git_repository,
        load_lock,
    )
    from .source_tree_fingerprint import FingerprintError, fingerprint_tree
except ImportError:
    from capture_build_inventory import (
        InventoryCaptureError,
        capture_git_repository,
        load_lock,
    )
    from source_tree_fingerprint import FingerprintError, fingerprint_tree


class SourceProvenanceError(Exception):
    """Raised when source provenance cannot be captured safely."""


def git_bytes(path: Path, arguments: list[str]) -> bytes:
    command = ["git", "-C", str(path), *arguments]
    try:
        result = subprocess.run(command, check=False, capture_output=True)
    except OSError as exc:
        raise SourceProvenanceError(
            f"Unable to execute Git command {arguments[0]}: {exc}"
        ) from exc
    if result.returncode:
        raise SourceProvenanceError(
            f"Git command failed ({arguments[0]}) for {path}: "
            f"exit code {result.returncode}"
        )
    return result.stdout


def git_text(path: Path, arguments: list[str]) -> str:
    try:
        return git_bytes(path, arguments).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise SourceProvenanceError(
            f"Git returned non-UTF-8 output for {path}."
        ) from exc


def git_paths(path: Path, arguments: list[str]) -> list[str]:
    raw = git_bytes(path, arguments)
    try:
        values = [item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise SourceProvenanceError(
            f"Repository contains a non-UTF-8 path: {path}"
        ) from exc
    return sorted(values)


def reject_gitlinks(path: Path, app_name: str) -> None:
    records = git_bytes(path, ["ls-files", "--stage", "-z"]).split(b"\0")
    submodules = []
    for record in records:
        if not record:
            continue
        metadata, separator, encoded_path = record.partition(b"\t")
        if separator and metadata.split(b" ", 1)[0] == b"160000":
            try:
                submodules.append(encoded_path.decode("utf-8", errors="strict"))
            except UnicodeDecodeError as exc:
                raise SourceProvenanceError(
                    f"Submodule path is not valid UTF-8 in {app_name}."
                ) from exc
    if submodules:
        raise SourceProvenanceError(
            f"Git submodules are not yet supported for {app_name}: "
            f"{sorted(submodules)}"
        )


def capture_repository_source(
    path: Path, app: dict[str, Any]
) -> dict[str, Any]:
    """Capture commit identity, post-clone changes and the complete source tree."""
    try:
        repository = capture_git_repository(path, app)
    except InventoryCaptureError as exc:
        raise SourceProvenanceError(str(exc)) from exc

    root = path.resolve()
    git_root = Path(
        git_text(path, ["rev-parse", "--show-toplevel"])
    ).resolve()
    if git_root != root:
        raise SourceProvenanceError(
            f"Git worktree root does not match application root for {app['name']}."
        )

    reject_gitlinks(path, app["name"])
    head_tree = git_text(path, ["rev-parse", "HEAD^{tree}"])
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head_tree):
        raise SourceProvenanceError(
            f"Invalid Git HEAD tree for application {app['name']}."
        )

    modified_paths = git_paths(
        path, ["diff", "--no-renames", "--name-only", "-z", "HEAD", "--"]
    )
    diff = git_bytes(
        path, ["diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", "--"]
    )
    untracked_paths = git_paths(
        path, ["ls-files", "--others", "--exclude-standard", "--directory", "-z"]
    )
    ignored_paths = git_paths(
        path,
        [
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
        ],
    )

    try:
        source_tree = fingerprint_tree(root)
    except FingerprintError as exc:
        raise SourceProvenanceError(
            f"Unable to fingerprint application {app['name']}: {exc}"
        ) from exc

    return {
        **repository,
        "head_tree": head_tree.lower(),
        "tracked_content": {
            "matches_head": not modified_paths,
            "installation_modified_paths": modified_paths,
            "installation_diff_sha256": (
                hashlib.sha256(diff).hexdigest() if modified_paths else None
            ),
        },
        "generated_content": {
            "origin": "post_clone_bench_init",
            "untracked_paths": untracked_paths,
            "ignored_paths": ignored_paths,
        },
        "source_tree": source_tree,
    }


def capture_source_provenance(
    bench_path: Path, lock_path: Path, output_path: Path
) -> dict[str, Any]:
    """Capture every locked repository before the build removes Git metadata."""
    bench = bench_path.resolve()
    apps_root = (bench / "apps").resolve()
    if not bench.is_dir() or not apps_root.is_dir():
        raise SourceProvenanceError(f"Bench workspace is missing: {bench}")

    lock = load_lock(lock_path)
    locked_apps = lock["applications"]
    expected_names = {app["name"] for app in locked_apps}
    actual_names = {
        item.name
        for item in apps_root.iterdir()
        if item.is_dir() and not item.name.startswith(".")
    }
    if actual_names != expected_names:
        raise SourceProvenanceError(
            "Bench application directory composition differs from lock-v2: "
            f"missing={sorted(expected_names - actual_names)}, "
            f"unexpected={sorted(actual_names - expected_names)}"
        )

    if all(isinstance(app.get("installation_order"), int) for app in locked_apps):
        ordered = sorted(
            locked_apps, key=lambda app: (app["installation_order"], app["name"])
        )
    else:
        ordered = sorted(locked_apps, key=lambda app: app["name"])

    records = []
    for app in ordered:
        app_path = (apps_root / app["name"]).resolve()
        if not app_path.is_relative_to(apps_root):
            raise SourceProvenanceError(
                f"Application path escapes Bench apps directory: {app['name']}"
            )
        records.append(capture_repository_source(app_path, app))

    if not any(item["name"] == "frappe" for item in records):
        raise SourceProvenanceError(
            "Lock-v2 must include the Frappe framework application."
        )

    report = {
        "schema_version": "1.0",
        "algorithm": "ndf-source-provenance-v1",
        "lock": {
            "version": 2,
            "sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        },
        "repositories": records,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output_path)
    except OSError as exc:
        raise SourceProvenanceError(
            f"Unable to write source provenance evidence: {exc}"
        ) from exc
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = capture_source_provenance(args.bench, args.lock, args.output)
    except (SourceProvenanceError, InventoryCaptureError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    modified = sum(
        len(item["tracked_content"]["installation_modified_paths"])
        for item in report["repositories"]
    )
    generated = sum(
        len(item["generated_content"]["untracked_paths"])
        + len(item["generated_content"]["ignored_paths"])
        for item in report["repositories"]
    )
    print(
        f"Captured source provenance for {len(report['repositories'])} repositories; "
        f"{modified} tracked modifications and {generated} generated/ignored path roots."
    )
    print(f"Source provenance: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
