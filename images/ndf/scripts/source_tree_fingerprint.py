#!/usr/bin/env python3
"""Calculate a deterministic SHA-256 fingerprint of a source filesystem tree.

Algorithm: ndf-source-tree-sha256-v1

Only Git metadata entries named .git are excluded. Symbolic links are
recorded without following them. Regular-file content and executable status,
directory paths, and symlink targets contribute to the root digest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Iterator

ALGORITHM = "ndf-source-tree-sha256-v1"
_DOMAIN = b"NDF-SOURCE-TREE\x00ndf-source-tree-sha256-v1\x00"
_CHUNK_SIZE = 1024 * 1024


class FingerprintError(Exception):
    """Raised when the tree cannot be fingerprinted unambiguously."""


def _json_record(record: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (UnicodeEncodeError, TypeError, ValueError) as exc:
        raise FingerprintError(
            "A filesystem path or record is not valid canonical UTF-8 JSON."
        ) from exc


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    """Detect replacement or mutation while a regular file is being read."""
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and stat.S_IFMT(before.st_mode) == stat.S_IFMT(after.st_mode)
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _hash_regular_file(
    path: Path, relative: str, before: os.stat_result
) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FingerprintError(
            f"Cannot safely open regular file {relative!r}: {exc}"
        ) from exc

    digest = hashlib.sha256()
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_file_state(before, opened):
            raise FingerprintError(
                f"File changed before it could be fingerprinted: {relative!r}"
            )
        while True:
            chunk = os.read(fd, _CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        if not _same_file_state(opened, after):
            raise FingerprintError(
                f"File changed while it was being fingerprinted: {relative!r}"
            )
    finally:
        os.close(fd)

    return {
        "path": relative,
        "type": "file",
        "size": before.st_size,
        "executable": bool(before.st_mode & 0o111),
        "sha256": digest.hexdigest(),
    }


def _walk(root: Path) -> Iterator[dict[str, Any]]:
    def visit(directory: Path, prefix: str) -> Iterator[dict[str, Any]]:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise FingerprintError(
                f"Cannot enumerate directory {prefix or '.'!r}: {exc}"
            ) from exc

        for entry in entries:
            if entry.name == ".git":
                continue
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                relative.encode("utf-8", errors="strict")
                info = entry.stat(follow_symlinks=False)
            except (OSError, UnicodeEncodeError) as exc:
                raise FingerprintError(
                    f"Cannot safely inspect path {relative!r}: {exc}"
                ) from exc
            path = Path(entry.path)

            if stat.S_ISDIR(info.st_mode):
                yield {"path": relative, "type": "directory"}
                yield from visit(path, relative)
            elif stat.S_ISREG(info.st_mode):
                yield _hash_regular_file(path, relative, info)
            elif stat.S_ISLNK(info.st_mode):
                try:
                    target = os.readlink(path)
                    target.encode("utf-8", errors="strict")
                except (OSError, UnicodeEncodeError) as exc:
                    raise FingerprintError(
                        f"Cannot safely read symbolic link {relative!r}: {exc}"
                    ) from exc
                yield {"path": relative, "type": "symlink", "target": target}
            else:
                raise FingerprintError(
                    f"Unsupported filesystem object at {relative!r}; "
                    "only directories, regular files and symbolic links are supported."
                )

    yield from visit(root, "")


def fingerprint_tree(root: Path) -> dict[str, Any]:
    """Return a stable root digest and entry counts for root.

    The root directory itself is not an entry. Empty directories are included.
    All entries named .git are excluded at any depth. No other paths are
    ignored, including caches, virtual environments, node_modules or generated
    files. Symlinks are recorded as links and are never followed.
    """
    root = Path(root)
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise FingerprintError(
            f"Cannot inspect source-tree root {root}: {exc}"
        ) from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise FingerprintError(
            f"Source-tree root must be a real directory, not a symlink: {root}"
        )

    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    counts = {"directory": 0, "file": 0, "symlink": 0}
    records = sorted(_walk(root), key=lambda item: item["path"])
    for record in records:
        encoded = _json_record(record)
        digest.update(len(encoded).to_bytes(8, byteorder="big", signed=False))
        digest.update(encoded)
        counts[record["type"]] += 1

    return {
        "algorithm": ALGORITHM,
        "sha256": digest.hexdigest(),
        "entry_count": sum(counts.values()),
        "file_count": counts["file"],
        "directory_count": counts["directory"],
        "symlink_count": counts["symlink"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root", type=Path, help="Directory whose contents should be fingerprinted"
    )
    args = parser.parse_args()
    try:
        result = fingerprint_tree(args.root)
    except FingerprintError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
