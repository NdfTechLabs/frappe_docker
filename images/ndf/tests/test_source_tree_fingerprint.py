from __future__ import annotations

import os
from pathlib import Path

import pytest
from scripts.source_tree_fingerprint import (
    ALGORITHM,
    FingerprintError,
    fingerprint_tree,
)


def test_fingerprint_is_deterministic_and_independent_of_creation_order(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    (first / "nested").mkdir(parents=True)
    (first / "z.txt").write_text("z", encoding="utf-8")
    (first / "nested" / "a.txt").write_text("a", encoding="utf-8")

    (second / "nested").mkdir(parents=True)
    (second / "nested" / "a.txt").write_text("a", encoding="utf-8")
    (second / "z.txt").write_text("z", encoding="utf-8")

    assert fingerprint_tree(first) == fingerprint_tree(second)


def test_fingerprint_changes_when_file_content_changes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("before", encoding="utf-8")
    before = fingerprint_tree(tmp_path)
    (tmp_path / "app.py").write_text("after", encoding="utf-8")
    assert fingerprint_tree(tmp_path)["sha256"] != before["sha256"]


def test_fingerprint_includes_executable_bit(tmp_path: Path) -> None:
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o644)
    non_executable = fingerprint_tree(tmp_path)
    script.chmod(0o755)
    executable = fingerprint_tree(tmp_path)
    assert executable["sha256"] != non_executable["sha256"]


def test_fingerprint_records_symlink_without_following_it(tmp_path: Path) -> None:
    (tmp_path / "target-a").write_text("a", encoding="utf-8")
    (tmp_path / "target-b").write_text("b", encoding="utf-8")
    link = tmp_path / "current"
    link.symlink_to("target-a")
    first = fingerprint_tree(tmp_path)
    link.unlink()
    link.symlink_to("target-b")
    second = fingerprint_tree(tmp_path)
    assert second["sha256"] != first["sha256"]
    assert second["symlink_count"] == 1


def test_git_metadata_is_excluded_at_any_depth(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("source", encoding="utf-8")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    nested_git = tmp_path / "vendor" / ".git"
    nested_git.mkdir(parents=True)
    (nested_git / "config").write_text("secret", encoding="utf-8")
    baseline = fingerprint_tree(tmp_path)
    (git_dir / "HEAD").write_text("different", encoding="utf-8")
    (nested_git / "config").write_text("different", encoding="utf-8")
    assert fingerprint_tree(tmp_path) == baseline


def test_empty_directories_are_included(tmp_path: Path) -> None:
    baseline = fingerprint_tree(tmp_path)
    (tmp_path / "empty").mkdir()
    result = fingerprint_tree(tmp_path)
    assert result["sha256"] != baseline["sha256"]
    assert result["directory_count"] == 1


def test_generated_and_hidden_files_are_not_silently_excluded(tmp_path: Path) -> None:
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "module.pyc").write_bytes(b"compiled")
    (tmp_path / ".generated").write_text("generated", encoding="utf-8")
    result = fingerprint_tree(tmp_path)
    assert result["file_count"] == 2
    assert result["directory_count"] == 1


def test_unsupported_filesystem_objects_fail_closed(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable on this platform")
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(FingerprintError, match="Unsupported filesystem object"):
        fingerprint_tree(tmp_path)


def test_root_symlink_is_rejected(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(FingerprintError, match="must be a real directory"):
        fingerprint_tree(link)


def test_empty_tree_has_stable_algorithm_identity(tmp_path: Path) -> None:
    result = fingerprint_tree(tmp_path)
    assert result["algorithm"] == ALGORITHM
    assert result["entry_count"] == 0
    assert result["file_count"] == 0
    assert result["directory_count"] == 0
    assert result["symlink_count"] == 0
    assert len(result["sha256"]) == 64


def test_v1_golden_vector(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("alpha", encoding="utf-8")
    (tmp_path / "empty").mkdir()
    assert fingerprint_tree(tmp_path) == {
        "algorithm": "ndf-source-tree-sha256-v1",
        "sha256": "16b8b8d1a3300437a2eb502b8aaabf291cd2fef45570904be1aece64210aa079",
        "entry_count": 2,
        "file_count": 1,
        "directory_count": 1,
        "symlink_count": 0,
    }


def test_records_use_global_path_order_not_depth_first_order(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "child.txt").write_text("child", encoding="utf-8")
    (tmp_path / "a!").write_text("sibling", encoding="utf-8")
    result = fingerprint_tree(tmp_path)
    assert result["sha256"] == (
        "4b171d7dd9907ba3ed4b5149ad689d1c43c1854e9d77d6c96b0d087d9801b415"
    )
