import base64
import hashlib
import os
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomllib

from scripts.package_resolution import validate_package_resolution
from scripts.resolve_manifest import ManifestLoader
from scripts.python_package_adapter import (
    PYPI_INDEX,
    UV_VERSION,
    PythonAdapterError,
    _dependency_applies,
    resolve_python_packages,
)

NDF_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = NDF_DIR.parents[1]
PROXY = "http://egress-proxy.example:3128"


def target_runtime():
    return {
        "frappe": "16.0.0",
        "python": "3.14.10",
        "python_implementation": "CPython",
        "python_cache_tag": "cpython-314",
        "python_soabi": "cpython-314-x86_64-linux-gnu",
        "python_platform": "linux-x86_64",
        "python_executable": "/usr/local/bin/python3",
        "python_build": "CPython 3.14.10, compiled with GCC 14.2.0",
        "node": "24.22.2",
        "npm": "11.19.1",
        "node_platform": "linux",
        "node_architecture": "x64",
        "node_abi": "137",
        "node_api": "10",
        "node_executable": "/home/frappe/.nvm/current/bin/node",
        "platform": {"os": "linux", "architecture": "amd64"},
        "images": {
            "builder": {
                "reference": "frappe/build@sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b",
                "index_digest": "sha256:d97ec9f1f4c7330ac419658716244f725b3d03396ca4420ce697181dd6d31cbe",
                "manifest_digest": "sha256:c91399e52261c38422f28ce09ab5884d12e30d4393854ac32ed74975c135805b",
                "platform": "linux/amd64",
            },
            "runtime": {
                "reference": "frappe/base@sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c",
                "index_digest": "sha256:7409981f6238662325583025a8dc23364b348a806146080879f1ef48372a6bc0",
                "manifest_digest": "sha256:f53287f145346c98c7fc4f47d25f86863c5e0be24284f2b8f3346ffe6a76a04c",
                "platform": "linux/amd64",
            },
        },
        "os": {
            "id": "debian",
            "package_manager": "apt",
            "package_manager_version": "3.0.4",
            "package_database": "dpkg",
            "package_database_version": "1.22.22",
            "distribution_family": "debian",
            "version_id": "13",
            "codename": "trixie",
            "architecture": "amd64",
            "libc": {"implementation": "glibc", "version": "2.41"},
        },
    }


def app_with_python(*dependencies):
    return {
        "_app_id": "demo_app",
        "app_id": "demo_app",
        "package_dependencies": [
            {
                "ecosystem": "python",
                "name": name,
                "version": None,
                "source": PYPI_INDEX,
                "resolver": "uv",
                "version_policy": policy,
                "requested_constraint": constraint,
                "source_profile": "python-pypi-public-v1",
                "disposition": "runtime_compatible",
                "install": True,
                "scope": scope,
            }
            for name, policy, constraint, scope in dependencies
        ],
    }


class FakeResponse:
    def __init__(self, url, body):
        self.url = url
        self.body = body
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def geturl(self):
        return self.url

    def read(self, size=-1):
        if size < 0:
            size = len(self.body) - self.offset
        chunk = self.body[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


class FakeOpener:
    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.requested = []

    def open(self, request, timeout):
        url = request.full_url
        self.requested.append((url, timeout))
        return FakeResponse(url, self.artifacts[url])


def wheel_entry(name, version, body, *, host="files.pythonhosted.org"):
    filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    url = f"https://{host}/packages/test/{filename}"
    return {
        "name": filename,
        "url": url,
        "hashes": {"sha256": hashlib.sha256(body).hexdigest()},
    }


def pylock(packages):
    chunks = ['lock-version = "1.0"', ""]
    for package in packages:
        chunks.extend(
            [
                "[[packages]]",
                f'name = "{package["name"]}"',
                f'version = "{package["version"]}"',
                f'index = "{PYPI_INDEX}/"',
                "",
            ]
        )
        for wheel in package.get("wheels", []):
            chunks.extend(
                [
                    "[[packages.wheels]]",
                    f'name = "{wheel["name"]}"',
                    f'url = "{wheel["url"]}"',
                    "[packages.wheels.hashes]",
                    f'sha256 = "{wheel["hashes"]["sha256"]}"',
                    "",
                ]
            )
        for dependency in package.get("dependencies", []):
            chunks.extend(
                [
                    "[[packages.dependencies]]",
                    f'name = "{dependency["name"]}"',
                    f'version = "{dependency["version"]}"',
                    "",
                ]
            )
    return "\n".join(chunks)


def make_runner(lock_text, *, version=UV_VERSION, compile_error=None, oversized=False):
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        if command[-1] == "--version":
            kwargs["stdout"].write(f"uv {version}\n".encode())
            return SimpleNamespace(returncode=0)
        if compile_error:
            raise compile_error
        output_path = Path(command[command.index("--output-file") + 1])
        output_path.write_text(lock_text, encoding="utf-8")
        if oversized:
            kwargs["stdout"].write(b"x" * 128)
        return SimpleNamespace(returncode=0)

    return runner, calls



def test_manifest_loader_emits_unresolved_python_requests_for_native_adapter(tmp_path):
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    loader = ManifestLoader(manifests)
    loader.repository_root = REPOSITORY_ROOT
    descriptor = {
        "app_id": "demo_app",
        "dependencies": {
            "python": [
                {
                    "name": "Requests",
                    "version": ">=2.30,<3",
                    "version_policy": "constraint",
                    "disposition": "runtime_compatible",
                    "required": True,
                }
            ]
        },
    }

    direct = loader._resolve_descriptor_packages(descriptor, target_runtime(), set())

    assert direct == [
        {
            "ecosystem": "python",
            "name": "Requests",
            "version": None,
            "source": PYPI_INDEX,
            "resolver": "uv",
            "version_policy": "constraint",
            "requested_constraint": ">=2.30,<3",
            "source_profile": "python-pypi-public-v1",
            "disposition": "runtime_compatible",
            "install": True,
            "scope": "runtime",
        }
    ]



def test_uv_0137_emits_pep751_pylock_for_local_wheel_without_network(tmp_path):
    version = subprocess.run(
        ["uv", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if version.returncode != 0 or version.stdout.strip().split()[:2] != ["uv", "0.13.7"]:
        pytest.skip("Authoritative uv 0.13.7 is installed by the CI workflow.")

    dist_info = "demo_pylock_fixture-1.0.0.dist-info"
    metadata = (
        "Metadata-Version: 2.3\\n"
        "Name: demo-pylock-fixture\\n"
        "Version: 1.0.0\\n"
    ).encode()
    wheel_metadata = (
        "Wheel-Version: 1.0\\n"
        "Generator: NDF test fixture\\n"
        "Root-Is-Purelib: true\\n"
        "Tag: py3-none-any\\n"
    ).encode()
    wheel_path = tmp_path / "demo_pylock_fixture-1.0.0-py3-none-any.whl"
    record_rows = []
    for filename, content in (
        (f"{dist_info}/METADATA", metadata),
        (f"{dist_info}/WHEEL", wheel_metadata),
    ):
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        record_rows.append(f"{filename},sha256={digest},{len(content)}")
    record_rows.append(f"{dist_info}/RECORD,,")
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(f"{dist_info}/WHEEL", wheel_metadata)
        archive.writestr(f"{dist_info}/RECORD", "\\n".join(record_rows) + "\\n")

    requirements = tmp_path / "requirements.in"
    requirements.write_text("demo-pylock-fixture==1.0.0\\n", encoding="utf-8")
    output = tmp_path / "pylock.toml"
    completed = subprocess.run(
        [
            "uv", "pip", "compile", str(requirements),
            "--output-file", str(output),
            "--format", "pylock.toml",
            "--no-index",
            "--find-links", str(tmp_path),
            "--python-version", "3.14.10",
            "--python-platform", "x86_64-manylinux_2_40",
            "--no-build",
            "--no-config",
            "--no-cache",
        ],
        cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(tmp_path),
            "TMPDIR": str(tmp_path),
            "UV_NO_CONFIG": "1",
            "UV_NO_CACHE": "1",
            "UV_PYTHON_DOWNLOADS": "never",
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    lock = tomllib.loads(output.read_text(encoding="utf-8"))
    assert lock["lock-version"] == "1.0"
    package = next(item for item in lock["packages"] if item["name"] == "demo-pylock-fixture")
    assert package["version"] == "1.0.0"
    assert package["wheels"]
    assert package["wheels"][0]["name"].endswith(".whl")
    assert package["wheels"][0]["hashes"]["sha256"]


def test_resolves_direct_and_transitive_packages_with_verified_wheel_hashes():
    root_bytes = b"fixture wheel bytes: root"
    child_bytes = b"fixture wheel bytes: child"
    root_wheel = wheel_entry("demo-root", "1.0.0", root_bytes)
    child_wheel = wheel_entry("demo-child", "2.4.0", child_bytes)
    lock_text = pylock(
        [
            {
                "name": "demo-root",
                "version": "1.0.0",
                "wheels": [root_wheel],
                "dependencies": [{"name": "demo-child", "version": "2.4.0"}],
            },
            {
                "name": "demo-child",
                "version": "2.4.0",
                "wheels": [child_wheel],
            },
        ]
    )
    runner, calls = make_runner(lock_text)
    opener = FakeOpener(
        {
            root_wheel["url"]: root_bytes,
            child_wheel["url"]: child_bytes,
        }
    )

    result, direct_versions = resolve_python_packages(
        [app_with_python(("demo-root", "constraint", ">=1,<2", "runtime"))],
        target_runtime(),
        repository_root=REPOSITORY_ROOT,
        egress_proxy=PROXY,
        runner=runner,
        opener_factory=lambda *_args: opener,
    )

    assert direct_versions == {"demo_app\0demo-root": "1.0.0"}
    assert [item["name"] for item in result["packages"]] == ["demo-child", "demo-root"]
    direct = next(item for item in result["packages"] if item["name"] == "demo-root")
    transitive = next(item for item in result["packages"] if item["name"] == "demo-child")
    assert direct["direct"] is True
    assert direct["requested_by"] == ["demo_app"]
    assert direct["resolver"] == "uv"
    assert direct["resolver_version"] == "0.13.7"
    assert direct["integrity"][0]["digest"] == hashlib.sha256(root_bytes).hexdigest()
    assert direct["repository_metadata"]["source_identity"] == "official-public-pypi"
    assert transitive["direct"] is False
    assert transitive["scope"] == "runtime"
    assert result["dependency_edges"] == [
        {
            "from": direct["id"],
            "to": transitive["id"],
            "constraint": "==2.4.0",
        }
    ]
    compile_command = calls[1][0]
    assert "--no-build" in compile_command
    assert "--no-config" in compile_command
    assert "--no-cache" in compile_command
    assert compile_command[compile_command.index("--python-version") + 1] == "3.14.10"
    assert compile_command[compile_command.index("--python-platform") + 1] == "x86_64-manylinux_2_41"
    assert compile_command[compile_command.index("--index-url") + 1] == PYPI_INDEX
    assert all("extra-index-url" not in arg for arg in compile_command)
    resolver_env = calls[1][1]["env"]
    assert resolver_env["HTTPS_PROXY"] == PROXY
    assert resolver_env["NO_PROXY"] == ""
    assert "PYTHONPATH" not in resolver_env
    assert "PIP_INDEX_URL" not in resolver_env
    assert {url for url, _timeout in opener.requested} == {
        root_wheel["url"], child_wheel["url"]
    }

    app = app_with_python(("demo-root", "constraint", ">=1,<2", "runtime"))
    app["package_dependencies"][0]["version"] = "1.0.0"
    validate_package_resolution(
        result,
        target_runtime=target_runtime(),
        applications=[app],
        repository_root=REPOSITORY_ROOT,
    )


def test_latest_compatible_direct_requirement_is_passed_without_a_range():
    wheel_bytes = b"latest wheel"
    wheel = wheel_entry("demo-latest", "3.0.0", wheel_bytes)
    runner, calls = make_runner(
        pylock([{"name": "demo-latest", "version": "3.0.0", "wheels": [wheel]}])
    )
    opener = FakeOpener({wheel["url"]: wheel_bytes})

    _, selected = resolve_python_packages(
        [app_with_python(("demo-latest", "latest_compatible", None, "build"))],
        target_runtime(),
        repository_root=REPOSITORY_ROOT,
        egress_proxy=PROXY,
        runner=runner,
        opener_factory=lambda *_args: opener,
    )

    assert selected == {"demo_app\0demo-latest": "3.0.0"}


def test_rejects_source_distribution_only_result_without_building():
    runner, _calls = make_runner(
        'lock-version = "1.0"\n\n[[packages]]\nname = "demo-root"\nversion = "1.0.0"\n'
        '[packages.sdist]\nurl = "https://files.pythonhosted.org/demo.tar.gz"\n'
        '[packages.sdist.hashes]\nsha256 = "' + "a" * 64 + '"\n'
    )

    with pytest.raises(PythonAdapterError, match="No wheel is available"):
        resolve_python_packages(
            [app_with_python(("demo-root", "constraint", ">=1", "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=runner,
            opener_factory=lambda *_args: FakeOpener({}),
        )


def test_rejects_unapproved_resolver_version():
    runner, _calls = make_runner("", version="0.13.6")

    with pytest.raises(PythonAdapterError, match="Expected authoritative resolver uv 0.13.7"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=runner,
        )


def test_rejects_unsupported_python_implementation_and_platform():
    target = target_runtime()
    target["python_implementation"] = "PyPy"

    with pytest.raises(PythonAdapterError, match="Unsupported Python target"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target,
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
        )


def test_requires_configured_allowlist_egress_proxy():
    with pytest.raises(PythonAdapterError, match="NDF_PACKAGE_EGRESS_PROXY is required"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=None,
        )


def test_rejects_wheel_from_unapproved_artifact_host():
    body = b"unapproved wheel"
    wheel = wheel_entry("demo-root", "1.0.0", body, host="attacker.example")
    runner, _calls = make_runner(
        pylock([{"name": "demo-root", "version": "1.0.0", "wheels": [wheel]}])
    )

    with pytest.raises(PythonAdapterError, match="approved HTTPS source profile"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=runner,
            opener_factory=lambda *_args: FakeOpener({}),
        )


def test_rejects_wheel_digest_mismatch():
    body = b"actual wheel bytes"
    wheel = wheel_entry("demo-root", "1.0.0", b"different published bytes")
    runner, _calls = make_runner(
        pylock([{"name": "demo-root", "version": "1.0.0", "wheels": [wheel]}])
    )

    with pytest.raises(PythonAdapterError, match="SHA-256 verification failed"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=runner,
            opener_factory=lambda *_args: FakeOpener({wheel["url"]: body}),
        )


def test_enforces_uv_execution_timeout():
    runner, _calls = make_runner(
        "",
        compile_error=subprocess.TimeoutExpired(["uv"], timeout=1),
    )

    with pytest.raises(PythonAdapterError, match="execution timeout"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=runner,
            timeout=1,
        )



def test_rejects_uv_output_exceeding_the_configured_limit():
    wheel_bytes = b"wheel"
    wheel = wheel_entry("demo-root", "1.0.0", wheel_bytes)
    runner, _calls = make_runner(
        pylock([{"name": "demo-root", "version": "1.0.0", "wheels": [wheel]}]),
        oversized=True,
    )

    with pytest.raises(PythonAdapterError, match="output exceeded"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=runner,
            output_limit=64,
            opener_factory=lambda *_args: FakeOpener({wheel["url"]: wheel_bytes}),
        )


def test_rejects_invalid_python_constraint_before_invoking_uv():
    def unexpected_runner(*_args, **_kwargs):
        raise AssertionError("uv must not run for an invalid requirement")

    with pytest.raises(PythonAdapterError, match="invalid PEP 440 constraint"):
        resolve_python_packages(
            [app_with_python(("demo-root", "constraint", "=>1.0", "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=unexpected_runner,
        )


def test_rejects_redirect_outside_the_approved_artifact_host():
    body = b"wheel bytes"
    wheel = wheel_entry("demo-root", "1.0.0", body)

    class RedirectedOpener:
        def open(self, request, timeout):
            return FakeResponse("https://attacker.example/redirected.whl", body)

    runner, _calls = make_runner(
        pylock([{"name": "demo-root", "version": "1.0.0", "wheels": [wheel]}])
    )
    with pytest.raises(PythonAdapterError, match="approved HTTPS source profile"):
        resolve_python_packages(
            [app_with_python(("demo-root", "latest_compatible", None, "runtime"))],
            target_runtime(),
            repository_root=REPOSITORY_ROOT,
            egress_proxy=PROXY,
            runner=runner,
            opener_factory=lambda *_args: RedirectedOpener(),
        )



def test_merges_multiple_direct_requesters_and_constraints_for_one_package():
    wheel_bytes = b"shared wheel"
    wheel = wheel_entry("shared-package", "1.5.0", wheel_bytes)
    runner, _calls = make_runner(
        pylock([{"name": "shared-package", "version": "1.5.0", "wheels": [wheel]}])
    )
    opener = FakeOpener({wheel["url"]: wheel_bytes})
    first = app_with_python(("shared-package", "constraint", ">=1,<2", "runtime"))
    second = app_with_python(("shared-package", "constraint", "<2.0", "build"))
    second["_app_id"] = second["app_id"] = "second_app"

    result, selected = resolve_python_packages(
        [first, second],
        target_runtime(),
        repository_root=REPOSITORY_ROOT,
        egress_proxy=PROXY,
        runner=runner,
        opener_factory=lambda *_args: opener,
    )

    assert selected == {
        "demo_app\0shared-package": "1.5.0",
        "second_app\0shared-package": "1.5.0",
    }
    package = result["packages"][0]
    assert package["direct"] is True
    assert package["requested_by"] == ["demo_app", "second_app"]
    assert package["scope"] == "runtime"


def test_dependency_markers_use_only_the_accepted_target_environment():
    environment = {
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

    assert _dependency_applies(
        {"marker": "python_full_version >= '3.14' and sys_platform == 'linux'"},
        environment,
    )
    assert not _dependency_applies(
        {"marker": "python_version < '3.14'"},
        environment,
    )
    with pytest.raises(PythonAdapterError, match="not represented by the accepted runtime"):
        _dependency_applies(
            {"marker": "platform_release == '6.8.0'"},
            environment,
        )

def test_no_python_requirements_returns_empty_lock_without_invoking_uv():
    def unexpected_runner(*_args, **_kwargs):
        raise AssertionError("uv must not run when there are no Python requirements")

    result, versions = resolve_python_packages(
        [{"_app_id": "demo_app", "package_dependencies": []}],
        None,
        repository_root=REPOSITORY_ROOT,
        runner=unexpected_runner,
    )

    assert result["packages"] == []
    assert result["dependency_edges"] == []
    assert result["source_profiles"] == []
    assert versions == {}
