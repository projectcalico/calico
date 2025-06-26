#!/bin/bash
set -euo pipefail

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use provided YQ or fallback to ../bin/yq (relative to hack/)
YQ="${YQ:-${SCRIPT_DIR}/../bin/yq}"

# Use provided CRANE or fallback to ../bin/crane (relative to hack/)
CRANE="${CRANE:-${SCRIPT_DIR}/../bin/crane}"

# Check for required dependencies
for cmd in docker crane; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "❌ Error: Required dependency '$cmd' is not installed or not in PATH." >&2
    exit 1
  fi
done
if [ ! -x "$YQ" ]; then
  echo "❌ Error: yq not found or not executable at: $YQ" >&2
  exit 1
fi

# Get default operator version from values.yaml if not passed in
defaultOperatorVersion=$("$YQ" .tigeraOperator.version < "${SCRIPT_DIR}/../charts/tigera-operator/values.yaml")
OPERATOR_VERSION="${OPERATOR_VERSION:-$defaultOperatorVersion}"

echo "Checking images for OPERATOR_VERSION=${OPERATOR_VERSION}"
IMAGE_SOURCE="quay.io/tigera/operator:${OPERATOR_VERSION}"

#########################################
# Step 1: Fetch image list from operator
#########################################
echo "Fetching image list from ${IMAGE_SOURCE}..."

# ❗ Intentionally skip FIPS variants — they may not be published and are not officially supported
operator_images=$(
  docker run --rm "${IMAGE_SOURCE}" --print-images=list 2>/dev/null \
  | grep -E '^[a-z0-9.-]+\.[a-z0-9.-]+/[a-z0-9._/-]+:[a-zA-Z0-9._-]+' \
  | grep -v -- '-fips' \
  | sort -u
)

#########################################
# Step 2: Extract images from manifests
#########################################
echo "Scanning manifests directory for image references..."
manifest_dir="${SCRIPT_DIR}/../manifests"

# ❗ Only extract literal image names with tags, skip templated values (e.g., :{{ .Values.tag }})
# ❗ Intentionally skip FIPS variants
manifest_images=$(
  grep -rhoE 'image:\s*["'\''"]?[a-z0-9.-]+\.[a-z0-9.-]+/[a-z0-9._/-]+:[a-zA-Z0-9._-]+' "$manifest_dir" \
  | sed -E 's/image:\s*["'\''"]?//' \
  | grep -v -- '-fips' \
  | sort -u
)

#########################################
# Step 3: Combine and deduplicate
#########################################
all_images=$(echo -e "${operator_images}\n${manifest_images}" | sort -u)
count=$(echo "$all_images" | wc -l)

echo "Total unique images to check (excluding -fips): ${count}"

#########################################
# Step 4: Check availability using crane
#########################################
FAILED=0

while IFS= read -r image; do
  if crane digest "$image" >/dev/null 2>&1; then
    echo "✅ Available: $image"
  else
    echo "❌ NOT FOUND: $image"
    FAILED=1
  fi
done <<< "$all_images"

#########################################
# Step 5: Final result
#########################################
if [ "$FAILED" -eq 1 ]; then
  echo "❗ Some images are missing or invalid."
  exit 1
else
  echo "All images are available!"
fi
