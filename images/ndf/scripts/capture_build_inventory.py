#!/usr/bin/env python3
"""Capture post-Bench source and installed-state evidence without modifying the build."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class InventoryCaptureError(Exception):
    """Raised when required build evidence cannot be captured safely."""


DEPENDENCY_NAMES = {
    "package.json", "yarn.lock", "package-lock.json", "npm-shrinkwrap.json",
    "pnpm-lock.yaml", "pyproject.toml", "poetry.lock", "uv.lock",
    "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg",
}
EXCLUDED_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}


def load_lock(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryCaptureError(f"Unable to read lock-v2 file {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("lock_version") != 2:
        raise InventoryCaptureError("Build inventory requires a valid lock-v2 JSON object.")
    apps = data.get("applications")
    if not isinstance(apps, list) or not apps:
        raise InventoryCaptureError("Lock-v2 must contain a non-empty applications array.")
    seen = set()
    for app in apps:
        if not isinstance(app, dict):
            raise InventoryCaptureError("Lock-v2 contains an invalid application entry.")
        name, repo, ref = app.get("name"), app.get("repository"), app.get("target_ref")
        if not all(isinstance(x, str) and x.strip() for x in (name, repo, ref)):
            raise InventoryCaptureError("Each locked application requires name, repository and target_ref.")
        if name in seen or name in {".", ".."} or "/" in name or "\\" in name:
            raise InventoryCaptureError(f"Duplicate or unsafe application name: {name!r}")
        seen.add(name)
    return data


def canonical_repository(value: str) -> str:
    """Return a credential-free host/path identity for HTTPS, SSH or SCP remotes."""
    raw = value.strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        host, path = parsed.hostname, parsed.path
    elif re.match(r"^(?:[^@/]+@)?[^:/]+:.+$", raw):
        authority, path = raw.split(":", 1)
        host = authority.rsplit("@", 1)[-1]
    else:
        raise InventoryCaptureError("Unsupported Git repository URL form; credentials and raw remotes are not logged.")
    if not host or not path:
        raise InventoryCaptureError("Git repository URL has no host or path.")
    path = path.strip("/").removesuffix(".git").lower()
    if not path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise InventoryCaptureError("Git repository URL contains an invalid path.")
    return f"{host.lower()}/{path}"


def run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise InventoryCaptureError(f"Unable to execute {command[0]}: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise InventoryCaptureError(f"Command failed ({command[0]}): {detail or result.returncode}")
    return result.stdout.strip()


def capture_git_repository(path: Path, app: dict[str, Any]) -> dict[str, str]:
    if not path.is_dir() or not (path / ".git").exists():
        raise InventoryCaptureError(f"Application repository or Git metadata is missing: {app['name']}")
    head = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
        raise InventoryCaptureError(f"Invalid Git HEAD for application {app['name']}.")
    remote_names = run(["git", "-C", str(path), "remote"]).splitlines()
    if not remote_names:
        raise InventoryCaptureError(f"No Git remotes are configured for application {app['name']}.")

    # Bench-managed checkouts are not guaranteed to use the conventional "origin"
    # remote name. Inspect every configured remote and accept only an identity
    # that matches the repository recorded in lock-v2.
    expected = canonical_repository(app["repository"])
    matching_identities = set()
    for remote_name in sorted(set(remote_names)):
        remote_urls = run(
            ["git", "-C", str(path), "remote", "get-url", "--all", remote_name]
        ).splitlines()
        for remote_url in remote_urls:
            try:
                matching_identities.add(canonical_repository(remote_url))
            except InventoryCaptureError:
                # Do not expose unsupported/raw remote values in build evidence or logs.
                continue

    if expected not in matching_identities:
        observed = sorted(matching_identities)
        raise InventoryCaptureError(
            f"Repository identity mismatch for {app['name']}: "
            f"lock={expected}, configured={observed or 'no supported remote URLs'}"
        )
    actual = expected
    return {
        "name": app["name"], "repository": actual, "requested_ref": app["target_ref"],
        "resolver_commit": str(app.get("ref") or ""), "actual_commit": head.lower(),
    }


def capture_python_packages() -> list[dict[str, str]]:
    items = []
    for dist in importlib.metadata.distributions():
        name, version = dist.metadata.get("Name"), dist.version
        if name and version:
            items.append({"name": name, "version": version})
    return sorted(items, key=lambda x: (x["name"].lower(), x["version"]))


def capture_node_packages(bench: Path, app_names: list[str]) -> list[dict[str, str]]:
    roots = [bench / "node_modules"] + [bench / "apps" / name / "node_modules" for name in app_names]
    found = {}
    for root in roots:
        if not root.is_dir():
            continue
        for package_file in root.rglob("package.json"):
            if package_file.is_symlink() or not package_file.is_file():
                continue
            try:
                package = json.loads(package_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            name, version = package.get("name"), package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                rel = package_file.parent.relative_to(bench).as_posix()
                found[(rel, name, version)] = {"path": rel, "name": name, "version": version}
    return [found[key] for key in sorted(found)]


def capture_dpkg_packages() -> list[dict[str, str]]:
    fmt = "-f=" + chr(36) + "{binary:Package}\\t" + chr(36) + "{Version}\\t" + chr(36) + "{Architecture}\\n"
    output = run(["dpkg-query", "-W", fmt])
    items = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or not all(fields):
            raise InventoryCaptureError("dpkg-query returned a malformed package record.")
        items.append({"name": fields[0], "version": fields[1], "architecture": fields[2]})
    return sorted(items, key=lambda x: (x["name"], x["version"], x["architecture"]))


def command_version(command: list[str]) -> str | None:
    executable = shutil.which(command[0])
    if not executable:
        return None
    try:
        output = run([executable, *command[1:]])
    except InventoryCaptureError:
        return None
    return output.splitlines()[0] if output else None


def capture_runtime() -> dict[str, Any]:
    bench_version = command_version(["bench", "--version"])
    if bench_version is None:
        raise InventoryCaptureError("Bench executable/version is unavailable.")
    machine = platform.machine().lower()
    arch = "amd64" if machine in {"x86_64", "amd64"} else machine
    return {
        "python": {"executable": sys.executable, "environment": sys.prefix, "version": platform.python_version(),
                   "implementation": platform.python_implementation()},
        "node": {"version": command_version(["node", "--version"])},
        "yarn": {"version": command_version(["yarn", "--version"])},
        "bench": {"version": bench_version},
        "platform": {"system": platform.system(), "machine": platform.machine(),
                     "oci": f"linux/{arch}"},
    }


def capture_installers() -> dict[str, Any]:
    return {
        "uv": {"version": command_version(["uv", "--version"])},
        "pip": {"version": command_version([sys.executable, "-m", "pip", "--version"])},
    }


def capture_dependency_files(app_path: Path, app_name: str) -> list[dict[str, str]]:
    records = []
    for root, dirs, files in os.walk(app_path):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRS)
        for filename in sorted(files):
            if filename not in DEPENDENCY_NAMES and not (
                filename.startswith(("requirements", "constraints")) and filename.endswith(".txt")
            ):
                continue
            path = Path(root) / filename
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(app_path).as_posix()
            records.append({"application": app_name, "path": f"apps/{app_name}/{rel}",
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return records


def capture_inventory(bench_path: Path, lock_path: Path, output_path: Path,
                      stage: str = "builder") -> dict[str, Any]:
    """Capture actual post-Bench state; never installs or modifies applications."""
    bench = bench_path.resolve()
    apps_root = (bench / "apps").resolve()
    if not bench.is_dir() or not apps_root.is_dir():
        raise InventoryCaptureError(f"Bench workspace is missing: {bench}")
    if stage != "builder":
        raise InventoryCaptureError(f"Unsupported build stage: {stage}")
    expected_python_env = (bench / "env").resolve()
    actual_python_env = Path(sys.prefix).resolve()
    if actual_python_env != expected_python_env:
        raise InventoryCaptureError(
            "Capture must run with the initialized Bench virtual-environment Python: "
            f"expected={expected_python_env}, actual={actual_python_env}"
        )

    lock = load_lock(lock_path)
    locked_apps = lock["applications"]
    expected_app_names = {app["name"] for app in locked_apps}
    actual_app_names = {
        path.name for path in apps_root.iterdir()
        if path.is_dir() and not path.name.startswith(".")
    }
    if actual_app_names != expected_app_names:
        raise InventoryCaptureError(
            "Bench application directory composition differs from lock-v2: "
            f"missing={sorted(expected_app_names - actual_app_names)}, "
            f"unexpected={sorted(actual_app_names - expected_app_names)}"
        )
    if all(isinstance(app.get("installation_order"), int) for app in locked_apps):
        ordered = sorted(locked_apps, key=lambda app: (app["installation_order"], app["name"]))
    else:
        ordered = sorted(locked_apps, key=lambda app: app["name"])

    repositories, dependency_files = [], []
    for app in ordered:
        app_path = (apps_root / app["name"]).resolve()
        if not app_path.is_relative_to(apps_root):
            raise InventoryCaptureError(f"Application path escapes Bench apps directory: {app['name']}")
        repositories.append(capture_git_repository(app_path, app))
        dependency_files.extend(capture_dependency_files(app_path, app["name"]))

    framework = next((item for item in repositories if item["name"] == "frappe"), None)
    if framework is None:
        raise InventoryCaptureError("Lock-v2 must include the Frappe framework application.")

    inventory = {
        "schema_version": "1.0", "stage": stage,
        "lock": {"version": 2, "sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest()},
        "framework": framework, "applications": repositories,
        "runtime": capture_runtime(),
        "installed_packages": {
            "python": capture_python_packages(),
            "node": capture_node_packages(bench, [app["name"] for app in ordered]),
            "debian": capture_dpkg_packages(),
        },
        "dependency_files": sorted(dependency_files, key=lambda x: (x["application"], x["path"])),
        "installers": capture_installers(),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output_path)
    except OSError as exc:
        raise InventoryCaptureError(f"Unable to write inventory evidence: {exc}") from exc
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage", choices=("builder",), default="builder")
    args = parser.parse_args()
    try:
        report = capture_inventory(args.bench, args.lock, args.output, args.stage)
    except (InventoryCaptureError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    packages = report["installed_packages"]
    print(f"Captured {len(report['applications'])} applications, "
          f"{len(packages['python'])} Python packages, {len(packages['node'])} Node packages "
          f"and {len(packages['debian'])} Debian packages.")
    print(f"Build inventory: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
