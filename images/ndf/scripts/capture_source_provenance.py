"""Capture Git provenance and complete pre-cleanup source-tree evidence."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from .capture_build_inventory import (
        InventoryCaptureError,
        canonical_repository,
        capture_git_repository,
        load_lock,
    )
    from .source_tree_fingerprint import FingerprintError, fingerprint_tree
except ImportError:
    from capture_build_inventory import (
        InventoryCaptureError,
        canonical_repository,
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
        values = [
            item.decode("utf-8", errors="strict")
            for item in raw.split(b"\0")
            if item
        ]
    except UnicodeDecodeError as exc:
        raise SourceProvenanceError(
            f"Repository contains a non-UTF-8 path: {path}"
        ) from exc
    return sorted(values)


def validate_submodule_path(value: str, repository: str) -> PurePosixPath:
    """Validate a .gitmodules path before resolving it inside a worktree."""
    candidate = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != value
    ):
        raise SourceProvenanceError(
            f"Unsafe submodule path declared by {repository}: {value!r}"
        )
    return candidate


def read_declared_submodules(root: Path, repository: str) -> dict[str, str]:
    """Read credential-free submodule identities from the checked-out .gitmodules."""
    config_path = root / ".gitmodules"
    if not config_path.exists():
        return {}
    if config_path.is_symlink() or not config_path.is_file():
        raise SourceProvenanceError(
            f"Unsupported .gitmodules entry in repository {repository}."
        )

    try:
        git_bytes(root, ["ls-files", "--error-unmatch", "--", ".gitmodules"])
        committed_config = git_bytes(root, ["show", "HEAD:.gitmodules"])
        working_config = config_path.read_bytes()
    except (OSError, SourceProvenanceError) as exc:
        raise SourceProvenanceError(
            f".gitmodules is not tracked by the current HEAD for {repository}."
        ) from exc
    if working_config != committed_config:
        raise SourceProvenanceError(
            f".gitmodules differs from the checked-out HEAD for {repository}."
        )

    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        with config_path.open(encoding="utf-8") as stream:
            parser.read_file(stream)
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise SourceProvenanceError(
            f"Unable to parse .gitmodules for {repository}."
        ) from exc

    declared: dict[str, str] = {}
    try:
        for section in parser.sections():
            if not section.startswith('submodule "') or not section.endswith('"'):
                raise SourceProvenanceError(
                    f"Unsupported .gitmodules section in {repository}."
                )
            if not parser.has_option(section, "path") or not parser.has_option(
                section, "url"
            ):
                raise SourceProvenanceError(
                    f"Incomplete .gitmodules entry in repository {repository}."
                )
            submodule_path = parser.get(section, "path").strip()
            validate_submodule_path(submodule_path, repository)
            identity = canonical_repository(parser.get(section, "url"))
            if submodule_path in declared:
                raise SourceProvenanceError(
                    f"Duplicate submodule path in {repository}: {submodule_path}"
                )
            declared[submodule_path] = identity
    except InventoryCaptureError as exc:
        raise SourceProvenanceError(
            f"Invalid submodule repository URL in {repository}."
        ) from exc
    return dict(sorted(declared.items()))


def read_gitlinks(root: Path, repository: str) -> dict[str, str]:
    """Return stage-zero gitlink paths and their pinned object IDs."""
    records = git_bytes(root, ["ls-files", "--stage", "-z"]).split(b"\0")
    gitlinks: dict[str, str] = {}
    for record in records:
        if not record:
            continue
        metadata, separator, encoded_path = record.partition(b"\t")
        if not separator:
            raise SourceProvenanceError(
                f"Malformed Git index record in repository {repository}."
            )
        fields = metadata.split()
        if len(fields) != 3 or fields[0] != b"160000":
            continue
        if fields[2] != b"0":
            raise SourceProvenanceError(
                f"Unmerged submodule index entry in repository {repository}."
            )
        try:
            submodule_path = encoded_path.decode("utf-8", errors="strict")
            expected_commit = fields[1].decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise SourceProvenanceError(
                f"Non-UTF-8 submodule metadata in repository {repository}."
            ) from exc
        validate_submodule_path(submodule_path, repository)
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", expected_commit):
            raise SourceProvenanceError(
                f"Invalid gitlink object ID in repository {repository}."
            )
        if submodule_path in gitlinks:
            raise SourceProvenanceError(
                f"Duplicate gitlink path in repository {repository}: {submodule_path}"
            )
        gitlinks[submodule_path] = expected_commit.lower()
    return dict(sorted(gitlinks.items()))


def repository_remotes(path: Path, expected: str, label: str) -> str:
    """Require at least one configured remote to match the declared identity."""
    remote_names = git_text(path, ["remote"]).splitlines()
    observed: set[str] = set()
    for remote_name in sorted(set(remote_names)):
        urls = git_text(path, ["remote", "get-url", "--all", remote_name]).splitlines()
        for url in urls:
            try:
                observed.add(canonical_repository(url))
            except InventoryCaptureError:
                continue
    if expected not in observed:
        raise SourceProvenanceError(
            f"Submodule repository identity mismatch for {label}: "
            f"declared={expected}, configured={sorted(observed) or 'no supported remotes'}"
        )
    return expected


def reject_nested_git_metadata(
    root: Path, repository: str, submodule_paths: set[str]
) -> None:
    """Reject embedded repositories except the declared submodule worktree roots."""
    metadata = root / ".git"
    if metadata.is_symlink() or not (metadata.is_file() or metadata.is_dir()):
        raise SourceProvenanceError(
            f"Unsupported Git metadata entry for repository {repository}."
        )

    allowed_roots = {root.joinpath(*PurePosixPath(item).parts).resolve() for item in submodule_paths}
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current).resolve()
        if current_path == root:
            directories[:] = [name for name in directories if name != ".git"]
            continue
        if current_path in allowed_roots:
            directories[:] = []
            continue
        if ".git" in directories or ".git" in files:
            raise SourceProvenanceError(
                f"Nested Git metadata is not declared as a submodule in {repository}: "
                f"{current_path.relative_to(root).as_posix()}"
            )
        directories[:] = sorted(directories)


def capture_submodule(
    parent: Path,
    relative_path: str,
    expected_repository: str,
    expected_commit: str,
    parent_repository: str,
    depth: int,
) -> dict[str, Any]:
    """Verify and capture one initialized submodule, recursively."""
    if depth > 32:
        raise SourceProvenanceError(
            f"Submodule nesting exceeds the supported depth in {parent_repository}."
        )

    child = parent
    for part in PurePosixPath(relative_path).parts:
        child = child / part
        if child.is_symlink():
            raise SourceProvenanceError(
                f"Submodule path contains a symbolic-link component: {relative_path}"
            )
    if not child.is_dir():
        raise SourceProvenanceError(
            f"Submodule is missing or not initialized: {parent_repository}:{relative_path}"
        )
    root = child.resolve()
    if not root.is_relative_to(parent.resolve()):
        raise SourceProvenanceError(
            f"Submodule path escapes its parent repository: {relative_path}"
        )
    if not (root / ".git").exists() or (root / ".git").is_symlink():
        raise SourceProvenanceError(
            f"Submodule Git metadata is missing or unsafe: {relative_path}"
        )

    git_root = Path(git_text(root, ["rev-parse", "--show-toplevel"])).resolve()
    if git_root != root:
        raise SourceProvenanceError(
            f"Submodule worktree root mismatch: {relative_path}"
        )

    actual_commit = git_text(root, ["rev-parse", "HEAD"]).lower()
    if actual_commit != expected_commit:
        raise SourceProvenanceError(
            f"Submodule commit mismatch for {parent_repository}:{relative_path}: "
            f"expected={expected_commit}, actual={actual_commit}"
        )
    head_tree = git_text(root, ["rev-parse", "HEAD^{tree}"]).lower()
    if not re.fullmatch(r"[0-9a-f]{40,64}", head_tree):
        raise SourceProvenanceError(
            f"Invalid submodule HEAD tree: {relative_path}"
        )

    repository_remotes(root, expected_repository, relative_path)
    nested = capture_repository_contents(
        root, expected_repository, relative_path, depth + 1
    )
    return {
        "path": relative_path,
        "repository": expected_repository,
        "expected_commit": expected_commit,
        **nested,
    }


def capture_repository_contents(
    root: Path, repository: str, label: str, depth: int = 0
) -> dict[str, Any]:
    """Capture tracked/generated state, tree identity and recursive submodules."""
    gitlinks = read_gitlinks(root, label)
    declared = read_declared_submodules(root, label)
    if set(gitlinks) != set(declared):
        raise SourceProvenanceError(
            f"Declared submodules and Git index gitlinks differ for {label}: "
            f"missing_declarations={sorted(set(gitlinks) - set(declared))}, "
            f"missing_gitlinks={sorted(set(declared) - set(gitlinks))}"
        )

    reject_nested_git_metadata(root, label, set(gitlinks))
    submodules = [
        capture_submodule(
            root,
            submodule_path,
            declared[submodule_path],
            gitlinks[submodule_path],
            label,
            depth,
        )
        for submodule_path in sorted(gitlinks)
    ]

    head_tree = git_text(root, ["rev-parse", "HEAD^{tree}"]).lower()
    if not re.fullmatch(r"[0-9a-f]{40,64}", head_tree):
        raise SourceProvenanceError(f"Invalid Git HEAD tree for {label}.")

    modified_paths = git_paths(
        root, ["diff", "--no-renames", "--name-only", "-z", "HEAD", "--"]
    )
    diff = git_bytes(
        root, ["diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", "--"]
    )
    untracked_paths = git_paths(
        root, ["ls-files", "--others", "--exclude-standard", "--directory", "-z"]
    )
    ignored_paths = git_paths(
        root,
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
            f"Unable to fingerprint repository {label}: {exc}"
        ) from exc

    return {
        "head_tree": head_tree,
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
        "submodules": submodules,
    }


def capture_repository_source(
    path: Path, app: dict[str, Any]
) -> dict[str, Any]:
    """Capture root application provenance and all recursively declared submodules."""
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

    contents = capture_repository_contents(root, repository["repository"], app["name"])
    return {**repository, **contents}


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
    submodules = sum(len(item["submodules"]) for item in report["repositories"])
    print(
        f"Captured source provenance for {len(report['repositories'])} repositories; "
        f"{submodules} declared submodules, {modified} tracked modifications and "
        f"{generated} generated/ignored path roots."
    )
    print(f"Source provenance: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
