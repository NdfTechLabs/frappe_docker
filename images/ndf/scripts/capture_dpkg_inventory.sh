#!/usr/bin/env bash
# Capture a complete dpkg inventory from an immutable image reference.
#
# Usage: capture_dpkg_inventory.sh <platform> <image-reference> <output-file>
#
# The inventory is published atomically only after docker/dpkg-query and
# deterministic sorting both complete successfully.

set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <platform> <image-reference> <output-file>" >&2
  exit 2
fi

platform="$1"
image_ref="$2"
output_file="$3"

command -v docker >/dev/null 2>&1 || {
  echo "Docker CLI is required to capture the dpkg inventory." >&2
  exit 1
}

output_dir="$(dirname "$output_file")"
mkdir -p "$output_dir"
raw_file="$(mktemp "$output_file.raw.XXXXXX")"
sorted_file="$(mktemp "$output_file.sorted.XXXXXX")"
cleanup() {
  rm -f "$raw_file" "$sorted_file"
}
trap cleanup EXIT

if ! docker run --rm --platform "$platform" --entrypoint /bin/sh "$image_ref" -c \
  "dpkg-query -W -f='\${binary:Package}\\t\${Version}\\t\${Architecture}\\n' 2>/dev/null" \
  > "$raw_file"; then
  echo "ERROR: dpkg-query failed for $image_ref; refusing to publish a partial inventory." >&2
  exit 1
fi

if [[ ! -s "$raw_file" ]]; then
  echo "ERROR: dpkg-query returned an empty inventory for $image_ref." >&2
  exit 1
fi

if ! LC_ALL=C sort "$raw_file" > "$sorted_file"; then
  echo "ERROR: Unable to sort the dpkg inventory for $image_ref." >&2
  exit 1
fi

if ! awk -F '\t' 'NF != 3 || $1 == "" || $2 == "" || $3 == "" { exit 1 } END { if (NR == 0) exit 1 }' "$sorted_file"; then
  echo "ERROR: dpkg-query produced malformed inventory records for $image_ref." >&2
  exit 1
fi

mv -f "$sorted_file" "$output_file"
