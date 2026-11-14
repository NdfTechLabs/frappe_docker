#!/usr/bin/env python3
"""Independently verify pre-cleanup Git/source provenance against generated lock-v2."""

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
from urllib.parse import urlsplit

try:
    from .source_tree_fingerprint import FingerprintError, fingerprint_tree
except ImportError:
    from source_tree_fingerprint import FingerprintError, fingerprint_tree


class SourceProvenanceVerificationError(Exception):
    """Raised when captured source provenance cannot be independently verified."""


OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")
APP_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_SUBMODULE_DEPTH = 32


def git_bytes(root: Path, args: list[str]) -> bytes:
    environment = os.environ.copy()
    for key in list(environment):
        if key in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_PREFIX",
        } or key.startswith("GIT_CONFIG_"):
            environment.pop(key, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            env=environment,
        )
    except OSError as exc:
        raise SourceProvenanceVerificationError(
            f"Unable to execute Git command {args[0]}."
        ) from exc
    if result.returncode:
        raise SourceProvenanceVerificationError(
            f"Git command failed ({args[0]}) for {root}: exit code {result.returncode}."
        )
    return result.stdout


def git_text(root: Path, args: list[str]) -> str:
    try:
        return git_bytes(root, args).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise SourceProvenanceVerificationError(
            f"Git returned non-UTF-8 output for {root}."
        ) from exc


def git_paths(root: Path, args: list[str]) -> list[str]:
    raw = git_bytes(root, args)
    try:
        paths = [part.decode("utf-8", errors="strict") for part in raw.split(b"\0") if part]
    except UnicodeDecodeError as exc:
        raise SourceProvenanceVerificationError(
            f"Repository contains a non-UTF-8 path: {root}."
        ) from exc
    if len(paths) != len(set(paths)):
        raise SourceProvenanceVerificationError(f"Git returned duplicate paths in {root}.")
    return sorted(paths)


def canonical_repository(value: str) -> str:
    """Independently canonicalize HTTPS, SSH and SCP-style Git remotes."""
    if not isinstance(value, str) or not value.strip():
        raise SourceProvenanceVerificationError("Repository identity is empty or invalid.")
    raw = value.strip()
    host: str | None = None
    path: str | None = None
    if "://" in raw:
        try:
            parsed = urlsplit(raw)
            if parsed.scheme.lower() not in {"https", "http", "ssh", "git"}:
                raise ValueError("unsupported scheme")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                # Credentials are allowed in remotes but deliberately discarded.
                if parsed.query or parsed.fragment:
                    raise ValueError("query or fragment is not supported")
            host, path = parsed.hostname, parsed.path
        except ValueError as exc:
            raise SourceProvenanceVerificationError("Unsupported Git remote URL.") from exc
    elif re.fullmatch(r"[^/@:]+/.+", raw):
        host, path = raw.split("/", 1)
    elif re.fullmatch(r"(?:[^@/]+@)?[^:/]+:.+", raw):
        authority, path = raw.split(":", 1)
        host = authority.rsplit("@", 1)[-1]
    else:
        raise SourceProvenanceVerificationError("Unsupported Git remote URL form.")
    if not host or not path:
        raise SourceProvenanceVerificationError("Git remote has no host or repository path.")
    host = host.lower()
    path = path.strip("/").removesuffix(".git").lower()
    if (
        not re.fullmatch(r"[a-z0-9.-]+", host)
        or not path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(ord(char) < 32 for char in path)
    ):
        raise SourceProvenanceVerificationError("Git remote contains an invalid identity.")
    return f"{host}/{path}"


def validate_relative_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise SourceProvenanceVerificationError(f"{label} path is not a string.")
    candidate = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != value
    ):
        raise SourceProvenanceVerificationError(f"Unsafe {label} path: {value!r}.")
    return candidate


def load_json_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceProvenanceVerificationError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise SourceProvenanceVerificationError(f"{label} must be a JSON object.")
    return value, raw


def validate_lock(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if lock.get("lock_version") != 2:
        raise SourceProvenanceVerificationError("Independent verification requires lock-v2.")
    apps = lock.get("applications")
    if not isinstance(apps, list) or not apps:
        raise SourceProvenanceVerificationError("Lock-v2 applications must be a non-empty list.")
    indexed: dict[str, dict[str, Any]] = {}
    for app in apps:
        if not isinstance(app, dict):
            raise SourceProvenanceVerificationError("Lock-v2 contains a malformed application.")
        name, repository, target_ref = app.get("name"), app.get("repository"), app.get("target_ref")
        if not isinstance(name, str) or not APP_NAME.fullmatch(name):
            raise SourceProvenanceVerificationError("Lock-v2 contains an unsafe application name.")
        if name in indexed:
            raise SourceProvenanceVerificationError(f"Lock-v2 contains duplicate app {name}.")
        if not isinstance(repository, str) or not repository.strip():
            raise SourceProvenanceVerificationError(f"Lock-v2 repository is missing for {name}.")
        if not isinstance(target_ref, str) or not target_ref.strip():
            raise SourceProvenanceVerificationError(f"Lock-v2 target_ref is missing for {name}.")
        resolved = app.get("ref")
        if resolved is not None and (
            not isinstance(resolved, str) or not OBJECT_ID.fullmatch(resolved.lower())
        ):
            raise SourceProvenanceVerificationError(f"Lock-v2 resolver ref is invalid for {name}.")
        indexed[name] = app
    if "frappe" not in indexed:
        raise SourceProvenanceVerificationError("Lock-v2 must include Frappe.")
    return indexed


def validate_provenance_shape(provenance: dict[str, Any]) -> list[dict[str, Any]]:
    if (
        provenance.get("schema_version") != "1.0"
        or provenance.get("algorithm") != "ndf-source-provenance-v1"
    ):
        raise SourceProvenanceVerificationError("Unsupported source-provenance contract.")
    lock = provenance.get("lock")
    if (
        not isinstance(lock, dict)
        or lock.get("version") != 2
        or not isinstance(lock.get("sha256"), str)
        or not SHA256.fullmatch(lock["sha256"])
    ):
        raise SourceProvenanceVerificationError("Source provenance has invalid lock identity.")
    repositories = provenance.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise SourceProvenanceVerificationError("Source provenance has no repository records.")
    return repositories


def inspect_remote_identity(root: Path, expected: str, label: str) -> str:
    names = git_text(root, ["remote"]).splitlines()
    if not names:
        raise SourceProvenanceVerificationError(f"No Git remotes are configured for {label}.")
    identities: set[str] = set()
    for name in sorted(set(names)):
        urls = git_text(root, ["remote", "get-url", "--all", name]).splitlines()
        for url in urls:
            try:
                identities.add(canonical_repository(url))
            except SourceProvenanceVerificationError:
                # Match the capture contract: unsupported remotes are ignored, never logged.
                continue
    if expected not in identities:
        raise SourceProvenanceVerificationError(
            f"Repository identity mismatch for {label}: expected={expected}, "
            f"configured={sorted(identities) or 'no supported remotes'}."
        )
    return expected


def inspect_git_root(root: Path, label: str) -> tuple[str, str]:
    if root.is_symlink() or not root.is_dir():
        raise SourceProvenanceVerificationError(f"Repository root is missing or unsafe: {label}.")
    metadata = root / ".git"
    if metadata.is_symlink() or not (metadata.is_file() or metadata.is_dir()):
        raise SourceProvenanceVerificationError(f"Git metadata is missing or unsafe for {label}.")
    actual_root = Path(git_text(root, ["rev-parse", "--show-toplevel"])).resolve()
    if actual_root != root.resolve():
        raise SourceProvenanceVerificationError(f"Git root mismatch for {label}.")
    head = git_text(root, ["rev-parse", "--verify", "HEAD"]).lower()
    tree = git_text(root, ["rev-parse", "--verify", "HEAD^{tree}"]).lower()
    if not OBJECT_ID.fullmatch(head) or not OBJECT_ID.fullmatch(tree):
        raise SourceProvenanceVerificationError(f"Invalid HEAD/tree object for {label}.")
    unmerged = git_bytes(root, ["ls-files", "--unmerged", "-z"])
    if unmerged:
        raise SourceProvenanceVerificationError(f"Unmerged index entries are unsupported in {label}.")
    return head, tree


def inspect_tracked_content(root: Path, expected: dict[str, Any], label: str) -> dict[str, Any]:
    modified = git_paths(root, ["diff", "--no-renames", "--name-only", "-z", "HEAD", "--"])
    binary_diff = git_bytes(
        root, ["diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", "--"]
    )
    observed = {
        "matches_head": not modified,
        "installation_modified_paths": modified,
        "installation_diff_sha256": hashlib.sha256(binary_diff).hexdigest() if modified else None,
    }
    if not isinstance(expected, dict):
        raise SourceProvenanceVerificationError(f"Tracked-content evidence is missing for {label}.")
    if expected != observed:
        raise SourceProvenanceVerificationError(
            f"Tracked-content evidence mismatch for {label}."
        )
    return observed


def inspect_generated_content(root: Path, expected: dict[str, Any], label: str) -> dict[str, Any]:
    untracked = git_paths(
        root, ["ls-files", "--others", "--exclude-standard", "--directory", "-z"]
    )
    ignored = git_paths(
        root,
        ["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"],
    )
    observed = {
        "origin": "post_clone_bench_init",
        "untracked_paths": untracked,
        "ignored_paths": ignored,
    }
    if not isinstance(expected, dict) or expected != observed:
        raise SourceProvenanceVerificationError(
            f"Generated/untracked/ignored path evidence mismatch for {label}."
        )
    return observed


def read_submodule_declarations(root: Path, label: str) -> dict[str, str]:
    config_path = root / ".gitmodules"
    if config_path.is_symlink():
        raise SourceProvenanceVerificationError(f"Unsafe .gitmodules file in {label}.")
    if not config_path.exists():
        return {}
    if not config_path.is_file():
        raise SourceProvenanceVerificationError(f"Unsupported .gitmodules entry in {label}.")
    try:
        git_bytes(root, ["ls-files", "--error-unmatch", "--", ".gitmodules"])
        committed = git_bytes(root, ["show", "HEAD:.gitmodules"])
        current = config_path.read_bytes()
    except (OSError, SourceProvenanceVerificationError) as exc:
        raise SourceProvenanceVerificationError(
            f".gitmodules is not tracked by HEAD in {label}."
        ) from exc
    if committed != current:
        raise SourceProvenanceVerificationError(f".gitmodules differs from HEAD in {label}.")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        parser.read_string(current.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise SourceProvenanceVerificationError(f"Unable to parse .gitmodules in {label}.") from exc
    result: dict[str, str] = {}
    for section in parser.sections():
        if not section.startswith('submodule "') or not section.endswith('"'):
            raise SourceProvenanceVerificationError(f"Unsupported .gitmodules section in {label}.")
        if not parser.has_option(section, "path") or not parser.has_option(section, "url"):
            raise SourceProvenanceVerificationError(f"Incomplete .gitmodules entry in {label}.")
        path = parser.get(section, "path").strip()
        validate_relative_path(path, f"{label} submodule")
        if path in result:
            raise SourceProvenanceVerificationError(f"Duplicate submodule path in {label}: {path}.")
        result[path] = canonical_repository(parser.get(section, "url"))
    return dict(sorted(result.items()))


def read_gitlinks(root: Path, label: str) -> dict[str, str]:
    entries = git_bytes(root, ["ls-files", "--stage", "-z"]).split(b"\0")
    result: dict[str, str] = {}
    for entry in entries:
        if not entry:
            continue
        metadata, separator, encoded_path = entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise SourceProvenanceVerificationError(f"Malformed index entry in {label}.")
        if fields[0] != b"160000":
            continue
        if fields[2] != b"0":
            raise SourceProvenanceVerificationError(f"Unmerged submodule gitlink in {label}.")
        try:
            path = encoded_path.decode("utf-8", errors="strict")
            commit = fields[1].decode("ascii", errors="strict").lower()
        except UnicodeDecodeError as exc:
            raise SourceProvenanceVerificationError(f"Invalid gitlink metadata in {label}.") from exc
        validate_relative_path(path, f"{label} gitlink")
        if not OBJECT_ID.fullmatch(commit) or path in result:
            raise SourceProvenanceVerificationError(f"Invalid or duplicate gitlink in {label}.")
        result[path] = commit
    return dict(sorted(result.items()))



def reject_undeclared_nested_git_metadata(
    root: Path, submodule_paths: set[str], label: str
) -> None:
    """Reject embedded Git repositories except declared submodule roots."""
    allowed = {
        root.joinpath(*PurePosixPath(path).parts).resolve()
        for path in submodule_paths
    }
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current).resolve()
        if current_path == root.resolve():
            directories[:] = [name for name in directories if name != ".git"]
            if ".git" in files:
                raise SourceProvenanceVerificationError(
                    f"Root Git metadata is not a directory or worktree file in {label}."
                )
            continue
        if current_path in allowed:
            directories[:] = []
            continue
        if ".git" in directories or ".git" in files:
            raise SourceProvenanceVerificationError(
                f"Undeclared nested Git metadata in {label}: "
                f"{current_path.relative_to(root.resolve()).as_posix()}."
            )
        directories[:] = sorted(directories)

def verify_fingerprint(root: Path, expected: Any, label: str) -> dict[str, Any]:
    if not isinstance(expected, dict):
        raise SourceProvenanceVerificationError(f"Source-tree fingerprint is missing for {label}.")
    try:
        observed = fingerprint_tree(root)
    except FingerprintError as exc:
        raise SourceProvenanceVerificationError(f"Unable to fingerprint {label}: {exc}") from exc
    if observed != expected:
        raise SourceProvenanceVerificationError(f"Source-tree fingerprint mismatch for {label}.")
    return observed


def verify_submodules(
    root: Path, records: Any, label: str, depth: int = 0
) -> list[dict[str, Any]]:
    if depth > MAX_SUBMODULE_DEPTH:
        raise SourceProvenanceVerificationError(f"Submodule nesting exceeds limit in {label}.")
    if not isinstance(records, list):
        raise SourceProvenanceVerificationError(f"Submodule records are malformed in {label}.")
    declared = read_submodule_declarations(root, label)
    gitlinks = read_gitlinks(root, label)
    if set(declared) != set(gitlinks):
        raise SourceProvenanceVerificationError(
            f"Declared submodules and Git index gitlinks differ in {label}."
        )
    reject_undeclared_nested_git_metadata(root, set(gitlinks), label)
    by_path: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise SourceProvenanceVerificationError(f"Malformed submodule record in {label}.")
        path = record.get("path")
        validate_relative_path(path, f"{label} submodule")
        if path in by_path:
            raise SourceProvenanceVerificationError(f"Duplicate submodule record in {label}: {path}.")
        by_path[path] = record
    if set(by_path) != set(gitlinks):
        raise SourceProvenanceVerificationError(
            f"Submodule provenance composition differs from Git metadata in {label}."
        )

    outcomes = []
    for path in sorted(gitlinks):
        record = by_path[path]
        expected_repo = declared[path]
        expected_commit = gitlinks[path]
        if record.get("repository") != expected_repo or record.get("expected_commit") != expected_commit:
            raise SourceProvenanceVerificationError(f"Submodule declaration mismatch for {label}:{path}.")
        child = root.joinpath(*PurePosixPath(path).parts)
        cursor = root
        for part in PurePosixPath(path).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise SourceProvenanceVerificationError(f"Submodule path traverses symlink: {label}:{path}.")
        if not child.exists():
            materialized = False
        elif not child.is_dir():
            raise SourceProvenanceVerificationError(f"Submodule path is not a directory: {label}:{path}.")
        elif (child / ".git").is_symlink():
            raise SourceProvenanceVerificationError(f"Submodule Git metadata is unsafe: {label}:{path}.")
        elif (child / ".git").exists():
            materialized = True
        elif any(child.iterdir()):
            raise SourceProvenanceVerificationError(
                f"Uninitialized submodule contains unexpected files: {label}:{path}."
            )
        else:
            materialized = False

        if record.get("materialized") is not materialized:
            raise SourceProvenanceVerificationError(f"Submodule materialization mismatch for {label}:{path}.")
        if not materialized:
            expected_metadata = {
                "actual_commit": None,
                "head_tree": None,
                "tracked_content": None,
                "generated_content": None,
                "source_tree": None,
                "submodules": [],
            }
            if any(record.get(key) != value for key, value in expected_metadata.items()):
                raise SourceProvenanceVerificationError(
                    f"Uninitialized submodule falsely claims Git/source metadata: {label}:{path}."
                )
            outcomes.append(
                {"path": path, "materialized": False, "expected_commit": expected_commit, "status": "metadata_only"}
            )
            continue

        child_root = child.resolve()
        if not child_root.is_relative_to(root.resolve()):
            raise SourceProvenanceVerificationError(f"Submodule path escapes repository: {label}:{path}.")
        actual_head, actual_tree = inspect_git_root(child_root, f"{label}:{path}")
        if actual_head != expected_commit or record.get("actual_commit") != actual_head:
            raise SourceProvenanceVerificationError(f"Submodule commit mismatch for {label}:{path}.")
        if record.get("head_tree") != actual_tree:
            raise SourceProvenanceVerificationError(f"Submodule HEAD tree mismatch for {label}:{path}.")
        inspect_remote_identity(child_root, expected_repo, f"{label}:{path}")
        tracked = inspect_tracked_content(child_root, record.get("tracked_content"), f"{label}:{path}")
        generated = inspect_generated_content(child_root, record.get("generated_content"), f"{label}:{path}")
        fingerprint = verify_fingerprint(child_root, record.get("source_tree"), f"{label}:{path}")
        nested = verify_submodules(child_root, record.get("submodules"), f"{label}:{path}", depth + 1)
        outcomes.append(
            {
                "path": path,
                "materialized": True,
                "expected_commit": expected_commit,
                "actual_commit": actual_head,
                "head_tree": actual_tree,
                "tracked_content": tracked,
                "generated_content": generated,
                "source_tree": fingerprint,
                "submodules": nested,
                "status": "verified",
            }
        )
    return outcomes


def verify_repository(
    bench: Path, app: dict[str, Any], record: dict[str, Any]
) -> dict[str, Any]:
    name = app["name"]
    if not isinstance(record, dict) or record.get("name") != name:
        raise SourceProvenanceVerificationError(f"Invalid provenance repository record for {name}.")
    app_path = bench / "apps" / name
    if app_path.is_symlink() or not app_path.is_dir() or not app_path.resolve().is_relative_to((bench / "apps").resolve()):
        raise SourceProvenanceVerificationError(f"Application directory is missing or unsafe: {name}.")

    expected_repository = canonical_repository(app["repository"])
    provenance_repository = canonical_repository(record.get("repository", ""))
    if provenance_repository != expected_repository:
        raise SourceProvenanceVerificationError(f"Lock/provenance repository mismatch for {name}.")
    requested_ref = app["target_ref"]
    resolver_commit = str(app.get("ref") or "")
    if record.get("requested_ref") != requested_ref:
        raise SourceProvenanceVerificationError(f"Requested ref mismatch for {name}.")
    if record.get("resolver_commit") != resolver_commit:
        raise SourceProvenanceVerificationError(f"Resolver-time commit mismatch for {name}.")

    head, tree = inspect_git_root(app_path, name)
    if record.get("actual_commit") != head:
        raise SourceProvenanceVerificationError(f"Actual Git HEAD mismatch for {name}.")
    if record.get("head_tree") != tree:
        raise SourceProvenanceVerificationError(f"Actual Git HEAD tree mismatch for {name}.")
    inspect_remote_identity(app_path, expected_repository, name)
    tracked = inspect_tracked_content(app_path, record.get("tracked_content"), name)
    generated = inspect_generated_content(app_path, record.get("generated_content"), name)
    fingerprint = verify_fingerprint(app_path, record.get("source_tree"), name)
    submodules = verify_submodules(app_path, record.get("submodules"), name)
    return {
        "name": name,
        "repository": expected_repository,
        "requested_ref": requested_ref,
        "resolver_commit": resolver_commit,
        "actual_commit": head,
        "head_tree": tree,
        "tracked_content": tracked,
        "generated_content": generated,
        "source_tree": fingerprint,
        "submodules": submodules,
        "status": "verified",
    }


def verify_source_provenance(
    bench_path: Path, lock_path: Path, provenance_path: Path, output_path: Path
) -> dict[str, Any]:
    bench = bench_path.resolve()
    apps_root = bench / "apps"
    if not bench.is_dir() or apps_root.is_symlink() or not apps_root.is_dir():
        raise SourceProvenanceVerificationError(f"Bench apps directory is missing or unsafe: {apps_root}.")

    lock, lock_bytes = load_json_object(lock_path, "generated lock-v2")
    locked_apps = validate_lock(lock)
    provenance, provenance_bytes = load_json_object(provenance_path, "source provenance")
    provenance_records = validate_provenance_shape(provenance)
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    provenance_sha = hashlib.sha256(provenance_bytes).hexdigest()
    if provenance["lock"]["sha256"] != lock_sha:
        raise SourceProvenanceVerificationError("Source provenance lock SHA-256 does not match lock-v2.")
    if provenance["lock"]["version"] != 2:
        raise SourceProvenanceVerificationError("Source provenance lock version is not 2.")

    names = [item.get("name") if isinstance(item, dict) else None for item in provenance_records]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
        raise SourceProvenanceVerificationError("Source provenance has invalid or duplicate repository records.")
    if set(names) != set(locked_apps):
        raise SourceProvenanceVerificationError(
            "Source provenance repository composition differs from lock-v2: "
            f"missing={sorted(set(locked_apps) - set(names))}, "
            f"unexpected={sorted(set(names) - set(locked_apps))}."
        )
    actual_names = {
        item.name for item in apps_root.iterdir()
        if item.is_dir() and not item.name.startswith(".")
    }
    if actual_names != set(locked_apps):
        raise SourceProvenanceVerificationError(
            "Bench application directory composition differs from lock-v2: "
            f"missing={sorted(set(locked_apps) - actual_names)}, "
            f"unexpected={sorted(actual_names - set(locked_apps))}."
        )

    records_by_name = {item["name"]: item for item in provenance_records}
    results = [
        verify_repository(bench, locked_apps[name], records_by_name[name])
        for name in sorted(locked_apps)
    ]
    report = {
        "schema_version": "1.0",
        "algorithm": "ndf-source-provenance-verification-v1",
        "verifier": {"name": "verify_source_provenance.py", "version": "1.0"},
        "lock": {"version": 2, "sha256": lock_sha},
        "source_provenance_sha256": provenance_sha,
        "repositories": results,
        "status": "passed",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output_path)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_source_provenance(args.bench, args.lock, args.provenance, args.output)
    except (SourceProvenanceVerificationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Independently verified source provenance for {len(report['repositories'])} repositories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
