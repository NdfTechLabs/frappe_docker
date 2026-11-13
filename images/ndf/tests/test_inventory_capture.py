import os
import subprocess
from pathlib import Path

NDF_DIR = Path(__file__).resolve().parents[1]
CAPTURE_SCRIPT = NDF_DIR / "scripts" / "capture_dpkg_inventory.sh"


def _mock_docker(directory: Path, *, fail: bool) -> dict[str, str]:
    executable = directory / "docker"
    executable.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'zlib1g\\t1:1.2.13.dfsg-1\\tamd64\\n'\n"
        "printf 'base-files\\t13.8+deb13u1\\tamd64\\n'\n"
        + ("exit 42\n" if fail else "exit 0\n"),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{directory}:{env['PATH']}"
    return env


def test_dpkg_inventory_capture_sorts_and_atomically_publishes_complete_output(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    output = tmp_path / "runtime" / "dpkg-inventory.tsv"
    env = _mock_docker(bin_dir, fail=False)

    result = subprocess.run(
        ["bash", str(CAPTURE_SCRIPT), "linux/amd64", "frappe/base@sha256:" + "a" * 64, str(output)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == (
        "base-files\\t13.8+deb13u1\\tamd64\\n"
        "zlib1g\\t1:1.2.13.dfsg-1\\tamd64\\n"
    )
    assert not list(output.parent.glob("dpkg-inventory.tsv.raw.*"))
    assert not list(output.parent.glob("dpkg-inventory.tsv.sorted.*"))


def test_dpkg_query_failure_does_not_publish_partial_inventory_or_replace_existing_file(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    output = tmp_path / "runtime" / "dpkg-inventory.tsv"
    output.parent.mkdir()
    output.write_text("previous\\t1\\tamd64\\n", encoding="utf-8")
    env = _mock_docker(bin_dir, fail=True)

    result = subprocess.run(
        ["bash", str(CAPTURE_SCRIPT), "linux/amd64", "frappe/base@sha256:" + "a" * 64, str(output)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "refusing to publish a partial inventory" in result.stderr
    assert output.read_text(encoding="utf-8") == "previous\\t1\\tamd64\\n"
    assert not list(output.parent.glob("dpkg-inventory.tsv.raw.*"))
    assert not list(output.parent.glob("dpkg-inventory.tsv.sorted.*"))
