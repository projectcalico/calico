#!/bin/bash
set -euo pipefail

# Use provided YQ or fall back to ../../bin/yq (adjusted path)
YQ="${YQ:-../../bin/yq}"

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get default operator version from values.yaml (adjusted relative path)
defaultOperatorVersion=$("$YQ" .tigeraOperator.version < "${SCRIPT_DIR}/../charts/tigera-operator/values.yaml")
OPERATOR_VERSION="${OPERATOR_VERSION:-$defaultOperatorVersion}"

echo "🔍 Checking images for OPERATOR_VERSION=${OPERATOR_VERSION}"
IMAGE_SOURCE="quay.io/tigera/operator:${OPERATOR_VERSION}"

#########################################
# Step 1: Fetch image list from operator
#########################################
echo "🔍 Fetching image list from ${IMAGE_SOURCE}..."

# Intentionally skip FIPS variants — they may not be published and are not officially supported
operator_images=$(
  docker run --rm "${IMAGE_SOURCE}" --print-images=list 2>/dev/null \
  | grep -E '^[a-z0-9.-]+\.[a-z0-9.-]+/[a-z0-9._/-]+:[a-zA-Z0-9._-]+' \
  | grep -v -- '-fips' \
  | sort -u
)

#########################################
# Step 2: Extract images from manifests
#########################################
echo "📁 Scanning manifests directory for image references..."
manifest_dir="${SCRIPT_DIR}"  # now scanning current folder

# Intentionally skip FIPS variants — they may not be published and are not officially supported
manifest_images=$(
  grep -rhoP 'image:\s*["'\'']?\K([a-z0-9.-]+\.[a-z0-9.-]+/[^\s"'\'']+)' "$manifest_dir" \
  | grep -E '^[a-z0-9.-]+\.[a-z0-9.-]+/[a-z0-9._/-]+:[a-zA-Z0-9._-]+' \
  | grep -v -- '-fips' \
  | sort -u
)

#########################################
# Step 3: Combine and deduplicate
#########################################
all_images=$(echo -e "${operator_images}\n${manifest_images}" | sort -u)
count=$(echo "$all_images" | wc -l)

echo "🔎 Total unique images to check (excluding -fips): ${count}"

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
  echo "🎉 All images are available!"
fi
