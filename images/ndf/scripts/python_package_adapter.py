"""Isolated CPython package resolution using the policy-pinned uv executable.

This adapter resolves descriptor-declared requirements only. It never installs
packages into the runner, a Bench, or an image. Wheel bytes are downloaded to a
disposable workspace solely for digest verification.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from packaging.markers import Marker, default_environment
from packaging.specifiers import SpecifierSet
from packaging.tags import compatible_tags, cpython_tags
from packaging.utils import parse_wheel_filename
from packaging.version import Version

try:
    from .package_resolution import normalize_package_name, package_identity
except ImportError:
    from package_resolution import normalize_package_name, package_identity


UV_VERSION = "0.13.7"
SOURCE_PROFILE = "python-pypi-public-v1"
PYPI_INDEX = "https://pypi.org/simple"
ARTIFACT_HOSTS = frozenset({"files.pythonhosted.org"})
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_WHEEL_BYTES = 512 * 1024 * 1024
MAX_TOTAL_WHEEL_BYTES = 2 * 1024 * 1024 * 1024
MAX_DIRECT_REQUIREMENTS = 1000
MAX_RESOLVED_PACKAGES = 5000
MAX_INPUT_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 300
TARGET_MARKER_VARIABLES = frozenset(
    {
        "implementation_name", "implementation_version", "os_name",
        "platform_machine", "platform_python_implementation", "platform_system",
        "python_full_version", "python_version", "sys_platform", "extra",
    }
)


class PythonAdapterError(RuntimeError):
    """Raised when Python package resolution cannot complete safely."""


def _safe_url(value: str, allowed_hosts: frozenset[str]) -> urllib.parse.ParseResult:
    try:
        parsed = urllib.parse.urlparse(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise PythonAdapterError("Malformed package URL.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname.lower() not in allowed_hosts
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise PythonAdapterError("Package URL is outside the approved HTTPS source profile.")
    return parsed


def _target_platforms(target: dict) -> list[str]:
    os_data = target.get("os", {})
    libc = os_data.get("libc", {})
    images = target.get("images", {})
    builder = images.get("builder", {})
    runtime = images.get("runtime", {})
    if (
        target.get("python") != "3.14.10"
        or target.get("python_implementation") != "CPython"
        or target.get("python_cache_tag") != "cpython-314"
        or target.get("python_soabi") != "cpython-314-x86_64-linux-gnu"
        or target.get("python_platform") != "linux-x86_64"
        or target.get("python_executable") != "/usr/local/bin/python3"
        or "GCC 14.2.0" not in target.get("python_build", "")
        or target.get("platform") != {"os": "linux", "architecture": "amd64"}
        or os_data.get("id") != "debian"
        or os_data.get("distribution_family") != "debian"
        or os_data.get("version_id") != "13"
        or os_data.get("codename") != "trixie"
        or os_data.get("architecture") != "amd64"
        or os_data.get("package_manager") != "apt"
        or os_data.get("package_manager_version") != "3.0.4"
        or os_data.get("package_database") != "dpkg"
        or os_data.get("package_database_version") != "1.22.22"
        or libc.get("implementation") != "glibc"
        or libc.get("version") != "2.41"
        or builder.get("reference") != "frappe/build@sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b"
        or builder.get("index_digest") != "sha256:d97ec9f1f4c7330ac419658716244f725b3d03396ca4420ce697181dd6d31cbe"
        or builder.get("manifest_digest") != "sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b"
        or builder.get("platform") != "linux/amd64"
        or runtime.get("reference") != "frappe/base@sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c"
        or runtime.get("index_digest") != "sha256:7409981f6238662325583025a8dc23364b348a806146080879f1ef48372a6bc0"
        or runtime.get("manifest_digest") != "sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c"
        or runtime.get("platform") != "linux/amd64"
    ):
        raise PythonAdapterError("Unsupported Python target; only the accepted RT-01 CPython 3.14.10 AMD64 target is supported.")
    return (
        [f"manylinux_2_{minor}_x86_64" for minor in range(41, 4, -1)]
        + ["manylinux2014_x86_64", "manylinux2010_x86_64", "manylinux1_x86_64", "linux_x86_64"]
    )


def _supported_wheel_tags(target: dict) -> list:
    platforms = _target_platforms(target)
    py_version = (3, 14)
    interpreter = "cp314"
    tags = list(cpython_tags(py_version, abis=("cp314", "abi3", "none"), platforms=platforms))
    known_tags = set(tags)
    tags.extend(
        tag for tag in compatible_tags(py_version, interpreter=interpreter, platforms=platforms)
        if tag not in known_tags
    )
    return tags


def _validate_proxy(proxy: str | None) -> str:
    if not proxy:
        raise PythonAdapterError(
            "NDF_PACKAGE_EGRESS_PROXY is required; configure an egress proxy that permits "
            "only pypi.org and files.pythonhosted.org."
        )
    try:
        parsed = urllib.parse.urlparse(proxy)
        port = parsed.port
    except ValueError as exc:
        raise PythonAdapterError("Malformed package egress proxy URL.") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or port is None
    ):
        raise PythonAdapterError("Package egress proxy URL must be credential-free HTTP(S) with an explicit port.")
    return proxy


def _bounded_run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    output_limit: int,
    runner: Callable = subprocess.run,
) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory(prefix="ndf-uv-output-") as output_dir:
        stdout_path = Path(output_dir) / "stdout"
        stderr_path = Path(output_dir) / "stderr"
        try:
            with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                if runner is subprocess.run:
                    process = subprocess.Popen(
                        command,
                        cwd=cwd,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        start_new_session=True,
                    )
                    deadline = time.monotonic() + timeout
                    while process.poll() is None:
                        if stdout_path.stat().st_size + stderr_path.stat().st_size > output_limit:
                            process.kill()
                            process.wait()
                            raise PythonAdapterError("uv output exceeded the configured output limit.")
                        if time.monotonic() >= deadline:
                            process.kill()
                            process.wait()
                            raise PythonAdapterError(
                                f"uv command exceeded the {timeout}s execution timeout."
                            )
                        time.sleep(0.05)
                    return_code = process.returncode
                else:
                    result = runner(
                        command,
                        cwd=cwd,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        timeout=timeout,
                        check=False,
                    )
                    return_code = result.returncode
        except subprocess.TimeoutExpired as exc:
            raise PythonAdapterError(f"uv command exceeded the {timeout}s execution timeout.") from exc
        except OSError as exc:
            raise PythonAdapterError(f"Unable to execute the approved uv resolver: {exc}") from exc
        if stdout_path.stat().st_size + stderr_path.stat().st_size > output_limit:
            raise PythonAdapterError("uv output exceeded the configured output limit.")
        stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
        return return_code, stdout, stderr


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _safe_url(newurl, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _verify_wheel(
    wheel: dict,
    package_name: str,
    package_version: str,
    supported_tags: list,
    opener,
    workspace: Path,
    remaining_bytes: int,
    request_timeout: int,
    deadline: float,
) -> tuple[dict, int]:
    url = wheel.get("url")
    _safe_url(url, ARTIFACT_HOSTS)
    filename = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
    try:
        wheel_name, wheel_version, _build, wheel_tags = parse_wheel_filename(filename)
    except Exception as exc:
        raise PythonAdapterError(f"Invalid wheel filename for {package_name}.") from exc
    if (
        normalize_package_name("python", str(wheel_name)) != package_name
        or str(wheel_version) != package_version
        or not (wheel_tags & set(supported_tags))
    ):
        raise PythonAdapterError(f"Wheel identity or target tags do not match {package_name}=={package_version}.")
    hashes = wheel.get("hashes")
    if not isinstance(hashes, dict) or not isinstance(hashes.get("sha256"), str):
        raise PythonAdapterError(f"PyPI did not provide a SHA-256 wheel hash for {package_name}.")
    expected = hashes["sha256"].lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise PythonAdapterError(f"Invalid SHA-256 wheel hash for {package_name}.")
    destination = workspace / (hashlib.sha256(url.encode()).hexdigest() + ".whl")
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "NDF-Package-Resolver/1"}), timeout=request_timeout) as response:
            final_url = response.geturl()
            _safe_url(final_url, ARTIFACT_HOSTS)
            with destination.open("wb") as output:
                while True:
                    if time.monotonic() >= deadline:
                        raise PythonAdapterError("Python artifact verification exceeded the overall execution timeout.")
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > min(MAX_WHEEL_BYTES, remaining_bytes):
                        raise PythonAdapterError("Wheel artifact exceeded the configured download-size limit.")
                    digest.update(chunk)
                    output.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        destination.unlink(missing_ok=True)
        raise PythonAdapterError(f"Unable to retrieve approved wheel artifact for {package_name}.") from exc
    if digest.hexdigest() != expected:
        destination.unlink(missing_ok=True)
        raise PythonAdapterError(f"Wheel SHA-256 verification failed for {package_name}.")
    destination.unlink(missing_ok=True)
    return (
        {
            "algorithm": "sha256",
            "digest": expected,
            "artifact": url,
        },
        total,
    )


def _target_marker_environment() -> dict[str, str]:
    environment = default_environment()
    environment.update(
        {
            "implementation_name": "cpython",
            "implementation_version": "3.14.10",
            "os_name": "posix",
            "platform_machine": "x86_64",
            "platform_python_implementation": "CPython",
            "platform_system": "Linux",
            "python_full_version": "3.14.10",
            "python_version": "3.14",
            "sys_platform": "linux",
            "extra": "",
        }
    )
    return environment


def _dependency_applies(dependency: dict, environment: dict[str, str]) -> bool:
    marker = dependency.get("marker")
    if marker is None:
        return True
    if not isinstance(marker, str):
        raise PythonAdapterError("Malformed environment marker in uv dependency graph.")
    marker_variables = set(
        re.findall(
            r"\b(implementation_name|implementation_version|os_name|platform_machine|"
            r"platform_python_implementation|platform_system|python_full_version|"
            r"python_version|sys_platform|extra|platform_release|platform_version)\b",
            marker,
        )
    )
    unsupported = marker_variables - TARGET_MARKER_VARIABLES
    if unsupported:
        raise PythonAdapterError(
            "Python dependency marker uses target attributes not represented by the accepted runtime: "
            + ", ".join(sorted(unsupported))
        )
    try:
        return Marker(marker).evaluate(environment=environment)
    except Exception as exc:
        raise PythonAdapterError("Invalid environment marker in uv dependency graph.") from exc


def resolve_python_packages(
    applications: list[dict],
    target_runtime: dict,
    *,
    repository_root: Path,
    uv_executable: str = "uv",
    egress_proxy: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    output_limit: int = MAX_OUTPUT_BYTES,
    runner: Callable = subprocess.run,
    opener_factory: Callable | None = None,
) -> tuple[dict, dict[str, str]]:
    """Resolve all selected descriptor Python requirements.

    Returns (normalized package_resolution section, direct package versions keyed
    by (app_id, normalized_name) joined with a NUL separator.
    """
    requirements: dict[str, list[dict]] = {}
    for app in applications:
        app_id = app.get("_app_id") or app.get("app_id")
        if not isinstance(app_id, str):
            continue
        for item in app.get("package_dependencies", []):
            if item.get("ecosystem") != "python":
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                raise PythonAdapterError(f"{app_id}: Python dependency name is missing.")
            try:
                normalized = normalize_package_name("python", name)
            except Exception as exc:
                raise PythonAdapterError(f"{app_id}: invalid Python package name {name!r}.") from exc
            policy = item.get("version_policy")
            constraint = item.get("requested_constraint")
            if policy == "constraint":
                if not isinstance(constraint, str) or not constraint:
                    raise PythonAdapterError(f"{app_id}: {name} requires a PEP 440 constraint.")
                try:
                    SpecifierSet(constraint)
                except Exception as exc:
                    raise PythonAdapterError(f"{app_id}: invalid PEP 440 constraint for {name}.") from exc
            elif policy == "latest_compatible":
                if constraint is not None:
                    raise PythonAdapterError(f"{app_id}: latest_compatible {name} must not include a version constraint.")
            else:
                raise PythonAdapterError(f"{app_id}: unsupported Python version policy for {name}.")
            if item.get("disposition") != "runtime_compatible":
                raise PythonAdapterError(
                    f"{app_id}: Python dependency {name} must be runtime_compatible; "
                    "Python base inventory and environment-level changes are outside B.1."
                )
            scope = item.get("scope", "runtime")
            if scope not in {"build", "runtime"}:
                raise PythonAdapterError(f"{app_id}: unsupported Python dependency scope for {name}.")
            requirements.setdefault(normalized, []).append(
                {
                    "app_id": app_id,
                    "name": normalized,
                    "version_policy": policy,
                    "requested_constraint": constraint if policy == "constraint" else None,
                    "disposition": "runtime_compatible",
                    "scope": scope,
                }
            )
            if sum(len(items) for items in requirements.values()) > MAX_DIRECT_REQUIREMENTS:
                raise PythonAdapterError("Python direct dependency count exceeds the configured limit.")

    catalogue_path = repository_root / "images/ndf/policies/package-source-profiles-v1.json"
    try:
        catalogue = json.loads(catalogue_path.read_text(encoding="utf-8"))
        profile = catalogue["source_profiles"][SOURCE_PROFILE]
        policy_version = catalogue["catalogue_version"]
        approved_uv = catalogue["resolver_policy"]["python"]["version"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise PythonAdapterError("Unable to load the approved Python source/resolver policy.") from exc
    if (
        not profile.get("enabled")
        or profile.get("ecosystem") != "python"
        or profile.get("registry") != PYPI_INDEX
        or profile.get("source_identity") != "official-public-pypi"
        or not isinstance(profile.get("artifact_hosts"), list)
        or set(profile.get("artifact_hosts", [])) != ARTIFACT_HOSTS
        or profile.get("artifact_hosts") != sorted(profile.get("artifact_hosts", []))
        or approved_uv != UV_VERSION
        or not isinstance(policy_version, str)
        or not policy_version
    ):
        raise PythonAdapterError("Python source profile or uv version does not match the approved B.1 policy.")

    if not requirements:
        return (
            {
                "schema_version": 1,
                "source_policy_catalogue_version": policy_version,
                "source_profiles": [],
                "base_inventory": None,
                "packages": [],
                "dependency_edges": [],
            },
            {},
        )

    supported_tags = _supported_wheel_tags(target_runtime)
    proxy = _validate_proxy(egress_proxy or os.environ.get("NDF_PACKAGE_EGRESS_PROXY"))
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix="ndf-python-resolution-") as temporary:
        workspace = Path(temporary)
        input_path = workspace / "requirements.in"
        lock_path = workspace / "pylock.toml"
        input_lines = []
        for name in sorted(requirements):
            constraints = sorted(
                {
                    item["requested_constraint"]
                    for item in requirements[name]
                    if item["version_policy"] == "constraint"
                }
            )
            if constraints:
                input_lines.extend(f"{name}{constraint}" for constraint in constraints)
            else:
                input_lines.append(name)
        input_content = "\n".join(sorted(set(input_lines))) + "\n"
        if len(input_content.encode("utf-8")) > MAX_INPUT_BYTES:
            raise PythonAdapterError("Python requirements input exceeds the configured size limit.")
        input_path.write_text(input_content, encoding="utf-8")

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(workspace / "home"),
            "TMPDIR": str(workspace),
            "TEMP": str(workspace),
            "TMP": str(workspace),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "UV_NO_CONFIG": "1",
            "UV_NO_CACHE": "1",
            "UV_PYTHON_DOWNLOADS": "never",
            "UV_INDEX_URL": PYPI_INDEX,
            "UV_DEFAULT_INDEX": PYPI_INDEX,
            "HTTPS_PROXY": proxy,
            "HTTP_PROXY": proxy,
            "https_proxy": proxy,
            "http_proxy": proxy,
            "ALL_PROXY": proxy,
            "all_proxy": proxy,
            "NO_PROXY": "",
            "no_proxy": "",
        }
        Path(env["HOME"]).mkdir()
        version_command = [uv_executable, "--version"]
        code, stdout, stderr = _bounded_run(
            version_command, cwd=workspace, env=env, timeout=timeout,
            output_limit=output_limit, runner=runner,
        )
        if code != 0 or stdout.strip() != f"uv {UV_VERSION}":
            raise PythonAdapterError(
                f"Expected authoritative resolver uv {UV_VERSION}; received {stdout.strip() or stderr.strip()}."
            )

        command = [
            uv_executable, "pip", "compile", str(input_path),
            "--output-file", str(lock_path),
            "--format", "pylock.toml",
            "--index-url", PYPI_INDEX,
            "--python-version", target_runtime["python"],
            "--python-platform", "x86_64-manylinux_2_41",
            "--no-build",
            "--no-config",
            "--no-cache",
        ]
        code, stdout, stderr = _bounded_run(
            command, cwd=workspace, env=env, timeout=timeout,
            output_limit=output_limit, runner=runner,
        )
        if code != 0:
            safe_error = stderr[-4000:].replace(proxy, "[proxy]")
            raise PythonAdapterError(f"uv dependency resolution failed: {safe_error}")
        if not lock_path.is_file() or lock_path.stat().st_size > output_limit:
            raise PythonAdapterError("uv did not produce a bounded PEP 751 pylock.toml result.")
        try:
            lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PythonAdapterError("uv produced invalid pylock.toml output.") from exc

        if lock.get("lock-version") != "1.0" or not isinstance(lock.get("packages"), list):
            raise PythonAdapterError("uv pylock output has an unsupported or incomplete PEP 751 structure.")
        if len(lock["packages"]) > MAX_RESOLVED_PACKAGES:
            raise PythonAdapterError("Resolved Python package count exceeds the configured limit.")

        proxy_handler = urllib.request.ProxyHandler({"https": proxy, "http": proxy})
        redirect_handler = _AllowlistedRedirectHandler(ARTIFACT_HOSTS)
        opener = (
            opener_factory(proxy_handler, redirect_handler)
            if opener_factory
            else urllib.request.build_opener(proxy_handler, redirect_handler)
        )
        package_rows = {}
        remaining_bytes = MAX_TOTAL_WHEEL_BYTES
        marker_environment = _target_marker_environment()
        for entry in lock["packages"]:
            if not isinstance(entry, dict):
                raise PythonAdapterError("Malformed package entry in uv pylock output.")
            if not _dependency_applies({"marker": entry.get("marker")}, marker_environment):
                continue
            requires_python = entry.get("requires-python")
            if requires_python is not None:
                if not isinstance(requires_python, str):
                    raise PythonAdapterError("Malformed package requires-python metadata.")
                try:
                    from packaging.specifiers import SpecifierSet
                    if Version("3.14.10") not in SpecifierSet(requires_python):
                        raise PythonAdapterError("Resolved package is incompatible with target Python 3.14.10.")
                except PythonAdapterError:
                    raise
                except Exception as exc:
                    raise PythonAdapterError("Invalid package requires-python metadata.") from exc
            raw_name = entry.get("name")
            if not isinstance(raw_name, str) or not raw_name:
                raise PythonAdapterError("Resolved Python package has no valid name.")
            name = normalize_package_name("python", raw_name)
            version = entry.get("version")
            if not isinstance(version, str) or not version:
                raise PythonAdapterError("Resolved Python package has no exact version.")
            try:
                Version(version)
            except Exception as exc:
                raise PythonAdapterError(f"Resolved Python package {name} has an invalid PEP 440 version.") from exc
            index = entry.get("index", PYPI_INDEX)
            if not isinstance(index, str):
                raise PythonAdapterError(f"Package {name} has no valid approved index identity.")
            index_url = urllib.parse.urlparse(index)
            if (
                index_url.scheme != "https"
                or index_url.hostname != "pypi.org"
                or index_url.port not in (None, 443)
                or index_url.path.rstrip("/") != "/simple"
                or index_url.username
                or index_url.password
                or index_url.query
                or index_url.fragment
            ):
                raise PythonAdapterError(f"Package {name} resolved from an unapproved index.")
            if any(key in entry for key in ("vcs", "directory", "archive")):
                raise PythonAdapterError(f"Non-PyPI source selected for {name}; direct sources are prohibited.")
            wheels = entry.get("wheels", [])
            if not isinstance(wheels, list) or not wheels:
                raise PythonAdapterError(
                    f"No wheel is available for {name}=={version} on the accepted target; "
                    "source-distribution builds are prohibited."
                )
            compatible = []
            tag_rank = {tag: index for index, tag in enumerate(supported_tags)}
            for wheel in wheels:
                if not isinstance(wheel, dict):
                    raise PythonAdapterError(f"Malformed wheel entry for {name}.")
                filename = urllib.parse.urlparse(wheel.get("url", "")).path.rsplit("/", 1)[-1]
                try:
                    _wheel_name, _wheel_version, _build, tags = parse_wheel_filename(filename)
                except Exception:
                    continue
                ranks = [tag_rank[tag] for tag in tags if tag in tag_rank]
                if ranks:
                    compatible.append((min(ranks), wheel))
            if not compatible:
                raise PythonAdapterError(f"No target-compatible wheel is available for {name}=={version}.")
            compatible.sort(key=lambda item: (item[0], item[1].get("url", "")))
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise PythonAdapterError("Python artifact verification exceeded the overall execution timeout.")
            if name in package_rows:
                raise PythonAdapterError(f"uv returned multiple selected versions for normalized package {name}.")
            integrity, downloaded = _verify_wheel(
                compatible[0][1],
                name, version, supported_tags, opener, workspace, remaining_bytes,
                request_timeout=max(1, min(30, int(remaining_time))),
                deadline=deadline,
            )
            remaining_bytes -= downloaded
            package_rows[name] = {
                "name": name,
                "version": version,
                "integrity": [integrity],
                "dependencies": entry.get("dependencies", []),
            }

        if not set(requirements).issubset(package_rows):
            missing = sorted(set(requirements) - set(package_rows))
            raise PythonAdapterError("uv resolution omitted direct requirements: " + ", ".join(missing))

        for name, row in package_rows.items():
            if not isinstance(row["dependencies"], list):
                raise PythonAdapterError(f"Malformed dependency list for {name}.")
            active_dependencies = []
            for dependency in row["dependencies"]:
                if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
                    raise PythonAdapterError(f"Malformed dependency edge for {name}.")
                if _dependency_applies(dependency, marker_environment):
                    active_dependencies.append(dependency)
            row["dependencies"] = active_dependencies

        direct_versions = {}
        packages = []
        edges = []
        scope_by_name = {name: ("runtime" if any(item["scope"] == "runtime" for item in requests) else "build")
                         for name, requests in requirements.items()}
        # Propagate the strongest installation scope through the resolved graph.
        changed = True
        while changed:
            changed = False
            for parent_name, row in package_rows.items():
                parent_scope = scope_by_name.get(parent_name)
                for dependency in row["dependencies"]:
                    child_name = normalize_package_name("python", dependency.get("name", ""))
                    if child_name not in package_rows:
                        continue
                    if parent_scope == "runtime" and scope_by_name.get(child_name) != "runtime":
                        scope_by_name[child_name] = "runtime"
                        changed = True

        for name in sorted(package_rows):
            row = package_rows[name]
            direct_requests = requirements.get(name, [])
            direct = bool(direct_requests)
            requesters = sorted({item["app_id"] for item in direct_requests})
            scope = scope_by_name.get(name, "build")
            package = {
                "id": package_identity("python", name, row["version"]),
                "ecosystem": "python",
                "name": name,
                "version": row["version"],
                "architecture": "",
                "source_profile": SOURCE_PROFILE,
                "source": PYPI_INDEX,
                "resolver": "uv",
                "resolver_version": UV_VERSION,
                "direct": direct,
                "requested_by": requesters,
                "disposition": "runtime_compatible",
                "install": True,
                "scope": scope,
                "integrity": row["integrity"],
                "repository_metadata": {"source_identity": "official-public-pypi"},
            }
            packages.append(package)
            for item in direct_requests:
                direct_versions[item["app_id"] + "\0" + name] = row["version"]

        by_name = {name: row for name, row in package_rows.items()}
        edge_map = {}
        for name, row in package_rows.items():
            for dependency in row["dependencies"]:
                dependency_name = normalize_package_name("python", dependency["name"])
                target = by_name.get(dependency_name)
                if target is None:
                    raise PythonAdapterError(
                        f"uv dependency graph references unresolved package {dependency_name} from {name}."
                    )
                edge = {
                    "from": package_identity("python", name, row["version"]),
                    "to": package_identity("python", dependency_name, target["version"]),
                    "constraint": "==" + target["version"],
                }
                edge_map[(edge["from"], edge["to"], edge["constraint"])] = edge
        edges = list(edge_map.values())

        package_resolution = {
            "schema_version": 1,
            "source_policy_catalogue_version": policy_version,
            "source_profiles": [SOURCE_PROFILE],
            "base_inventory": None,
            "packages": sorted(packages, key=lambda item: item["id"]),
            "dependency_edges": sorted(
                edges, key=lambda item: (item["from"], item["to"], item["constraint"])
            ),
        }
        return package_resolution, direct_versions
