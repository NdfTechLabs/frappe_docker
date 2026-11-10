#!/usr/bin/env bash
# Inspect the exact upstream Frappe v16 builder and runtime images.
#
# This is read-only with respect to the images: it pulls them, starts temporary
# containers to read runtime metadata, and writes evidence to a local directory.
# It does not install packages or modify the images.
#
# Usage:
#   bash images/ndf/scripts/inspect_target_runtime.sh
#   bash images/ndf/scripts/inspect_target_runtime.sh --platform linux/amd64
#   bash images/ndf/scripts/inspect_target_runtime.sh --output-dir /tmp/ndf-rt01

set -Eeuo pipefail

PLATFORM="linux/amd64"
OUTPUT_DIR=""

while (($#)); do
  case "$1" in
    --platform)
      [[ $# -ge 2 ]] || { echo "Missing value for --platform" >&2; exit 2; }
      PLATFORM="$2"
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for --output-dir" >&2; exit 2; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      sed -n '1,18p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "$PLATFORM" != "linux/amd64" ]]; then
  echo "RT-01 baseline currently accepts only linux/amd64; got: $PLATFORM" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || {
  echo "Docker CLI is required." >&2
  exit 1
}
docker info >/dev/null 2>&1 || {
  echo "Docker Engine is unavailable or the current user lacks permission." >&2
  exit 1
}
docker buildx version >/dev/null 2>&1 || {
  echo "Docker Buildx is required to inspect registry manifest metadata." >&2
  exit 1
}

if [[ -z "$OUTPUT_DIR" ]]; then
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  OUTPUT_DIR=".ndf-runtime-inspection/rt01-amd64-$timestamp"
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

IMAGES=(
  "frappe/build:version-16"
  "frappe/base:version-16"
)

inspect_image() {
  local image="$1"
  local name="$2"
  local dir="$OUTPUT_DIR/$name"
  mkdir -p "$dir"

  echo
  echo "==> Resolving the mutable tag to an immutable registry digest"
  docker buildx imagetools inspect "$image" > "$dir/registry-manifest.txt"
  local index_digest platform_digest
  # Buildx aligns the Digest column with variable whitespace.
  index_digest="$(awk '$1 == "Digest:" {print $2; exit}' "$dir/registry-manifest.txt")"
  if [[ ! "$index_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Unable to extract a valid registry index digest for $image." >&2
    exit 1
  fi

  # Select the immutable child manifest for the requested platform, not an
  # attestation manifest (which is reported as unknown/unknown).
  platform_digest="$(awk -v wanted_platform="$PLATFORM" '
    $1 == "Name:" {
      candidate = $2
      if (candidate !~ /@sha256:/) candidate = ""
      else sub(/^.*@/, "", candidate)
    }
    $1 == "Platform:" && $2 == wanted_platform &&
      candidate ~ /^sha256:/ {
      print candidate
      exit
    }
  ' "$dir/registry-manifest.txt")"
  if [[ ! "$platform_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Unable to extract a valid $PLATFORM manifest digest for $image." >&2
    exit 1
  fi

  local repository="${image%%:*}"
  local index_ref="${repository}@${index_digest}"
  local resolved_ref="${repository}@${platform_digest}"
  printf '%s\n' "$index_ref" > "$dir/registry-index-ref.txt"
  printf '%s\n' "$resolved_ref" > "$dir/resolved-image-ref.txt"

  echo "==> Pulling immutable platform image $resolved_ref"
  docker pull --platform "$PLATFORM" "$resolved_ref"

  echo "==> Recording local image configuration and identity"
  docker image inspect "$resolved_ref" > "$dir/docker-image-inspect.json"
  docker image inspect --format '{{.Id}}' "$resolved_ref" > "$dir/image-id.txt"
  docker image inspect --format '{{json .RepoDigests}}' "$resolved_ref" > "$dir/repo-digests.json"
  docker image inspect --format '{{.Os}}/{{.Architecture}}' "$resolved_ref" > "$dir/image-platform.txt"

  echo "==> Inspecting runtime metadata inside the selected image"
  if ! docker run --rm -i --platform "$PLATFORM" --entrypoint /bin/sh "$resolved_ref" -s \
    > "$dir/runtime-metadata.txt" 2> "$dir/runtime-metadata.stderr" <<'CONTAINER_SCRIPT'
set +e
printf '%s\\n' "NDF_RUNTIME_METADATA_BEGIN"

echo "=== OS RELEASE ==="
if [ -r /etc/os-release ]; then
  cat /etc/os-release
else
  echo "MISSING: /etc/os-release"
fi

echo
echo "=== KERNEL / CONTAINER ARCHITECTURE ==="
uname -a
uname -m
getconf LONG_BIT 2>&1

echo
echo "=== PYTHON ==="
if command -v python3 >/dev/null 2>&1; then
  python3 --version
  python3 - <<'PYTHON'
import json
import platform
import sys
import sysconfig

data = {
    "implementation": sys.implementation.name,
    "implementation_version": platform.python_version(),
    "python_version": sys.version,
    "cache_tag": sys.implementation.cache_tag,
    "soabi": sysconfig.get_config_var("SOABI"),
    "platform": sysconfig.get_platform(),
    "machine": platform.machine(),
    "libc": platform.libc_ver(),
    "executable": sys.executable,
}
print(json.dumps(data, indent=2, sort_keys=True))
PYTHON
else
  echo "MISSING: python3"
fi

echo
echo "=== NODE / NPM ==="
if command -v node >/dev/null 2>&1; then
  node --version
  node -p 'JSON.stringify({version:process.version, platform:process.platform, arch:process.arch, modules:process.versions.modules, napi:process.versions.napi}, null, 2)'
else
  echo "MISSING: node"
fi
if command -v npm >/dev/null 2>&1; then
  npm --version
else
  echo "MISSING: npm"
fi
command -v node 2>&1
command -v npm 2>&1

echo
echo "=== LIBC ==="
if command -v getconf >/dev/null 2>&1; then
  getconf GNU_LIBC_VERSION 2>&1
fi
if command -v ldd >/dev/null 2>&1; then
  ldd --version 2>&1 | head -n 2
else
  echo "MISSING: ldd"
fi

echo
echo "=== APT / DPKG ==="
if command -v apt >/dev/null 2>&1; then apt --version 2>&1; else echo "MISSING: apt"; fi
if command -v apt-get >/dev/null 2>&1; then apt-get --version 2>&1 | head -n 1; else echo "MISSING: apt-get"; fi
if command -v dpkg >/dev/null 2>&1; then
  dpkg --version 2>&1 | head -n 1
  dpkg --print-architecture 2>&1
  dpkg --print-foreign-architectures 2>&1
else
  echo "MISSING: dpkg"
fi

echo
echo "=== APT SOURCE CONFIGURATION ==="
if [ -d /etc/apt/sources.list.d ]; then
  find /etc/apt -maxdepth 2 -type f \( -name 'sources.list' -o -name '*.list' -o -name '*.sources' \) -print
  for source_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$source_file" ] || continue
    grep -E '^(deb |URIs:|Suites:|Components:|Types:)' "$source_file" 2>/dev/null || true
  done
else
  echo "MISSING: /etc/apt/sources.list.d"
fi
printf '%s\\n' "NDF_RUNTIME_METADATA_END"
CONTAINER_SCRIPT
  then
    echo "ERROR: Runtime metadata inspection failed for $image." >&2
    if [[ -s "$dir/runtime-metadata.stderr" ]]; then
      cat "$dir/runtime-metadata.stderr" >&2
    fi
    return 1
  fi

  if [[ ! -s "$dir/runtime-metadata.txt" ]] ||
    ! grep -Fxq "NDF_RUNTIME_METADATA_BEGIN" "$dir/runtime-metadata.txt" ||
    ! grep -Fxq "NDF_RUNTIME_METADATA_END" "$dir/runtime-metadata.txt"; then
    echo "ERROR: Runtime metadata output is empty or incomplete for $image." >&2
    if [[ -s "$dir/runtime-metadata.stderr" ]]; then
      cat "$dir/runtime-metadata.stderr" >&2
    fi
    return 1
  fi

  echo "==> Capturing installed dpkg inventory"
  docker run --rm --platform "$PLATFORM" --entrypoint /bin/sh "$resolved_ref" -c \
    "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n' 2>/dev/null | LC_ALL=C sort" \
    > "$dir/dpkg-inventory.tsv"

  echo "==> Capturing package inventory summary"
  {
    printf 'image=%s\n' "$image"
    printf 'requested_platform=%s\n' "$PLATFORM"
    printf 'registry_index_ref='
    cat "$dir/registry-index-ref.txt"
    printf 'resolved_platform_image_ref='
    cat "$dir/resolved-image-ref.txt"
    printf 'image_id='
    cat "$dir/image-id.txt"
    printf 'repo_digests='
    tr -d '\n' < "$dir/repo-digests.json"
    printf '\n'
    printf 'inventory_package_count='
    wc -l < "$dir/dpkg-inventory.tsv"
  } > "$dir/summary.txt"

  (
    cd "$dir"
    sha256sum registry-manifest.txt registry-index-ref.txt resolved-image-ref.txt docker-image-inspect.json image-id.txt \
      repo-digests.json image-platform.txt runtime-metadata.txt runtime-metadata.stderr \
      dpkg-inventory.tsv summary.txt > SHA256SUMS
  )

  echo "Captured $image:"
  cat "$dir/summary.txt"
}

inspect_image "${IMAGES[0]}" "builder"
inspect_image "${IMAGES[1]}" "runtime"

(
  cd "$OUTPUT_DIR"
  find builder runtime -type f ! -name SHA256SUMS -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

echo
echo "RT-01 inspection complete."
echo "Evidence directory: $OUTPUT_DIR"
echo "Review registry-manifest.txt for the selected platform manifest digest."
echo "Do not commit raw inventory files until source credentials/repository URLs have been reviewed."
