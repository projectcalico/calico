#!/bin/bash
set -euo pipefail

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use provided YQ or fallback to ../bin/yq (relative to hack/)
YQ="${YQ:-../bin/yq}"
CRANE="${CRANE:-../bin/crane}"

# Save the original directory
ORIG_DIR="$PWD"

# Move to the root of the Git repo
cd "$(git rev-parse --show-toplevel)"

echo "🔍 Showing latest commit for .semaphore/semaphore.yml"
git --no-pager log -p -1 -- .semaphore/semaphore.yml || echo "❌ git log failed"

# Return to the original directory
cd "$ORIG_DIR"

echo "🔍 Available files in \$HOME/secrets:"
ls -l "$HOME/secrets" || echo "❌ ~/secrets not found"

find "$HOME/secrets" 2>/dev/null || echo "❌ Cannot traverse ~/secrets"

# Authenticate to gcr.io if service account key is available (Semaphore secret)
if [[ -f "$HOME/secrets/gcp-service-account-key.json" ]]; then
  echo "🔐 Found GCR service account key at ~/secrets/gcp-service-account-key.json"
  "$CRANE" auth login gcr.io -u _json_key -p "$(cat "$HOME/secrets/gcp-service-account-key.json")"
else
  echo "ℹ️  No GCR service account key found at ~/secrets/gcp-service-account-key.json"
  echo "   Skipping crane login — assuming local Docker or cached credentials"
fi

if [ ! -x "$YQ" ]; then
  echo "❌ Error: yq not found or not executable at: $YQ" >&2
  echo "🔍 Resolved path: $(realpath "$YQ" 2>/dev/null || echo '<unresolvable>')" >&2
  exit 1
fi

# Operator version from values.yaml
defaultOperatorVersion=$("$YQ" .tigeraOperator.version < "${SCRIPT_DIR}/../charts/tigera-operator/values.yaml")
OPERATOR_VERSION="${OPERATOR_VERSION:-$defaultOperatorVersion}"
IMAGE_SOURCE="quay.io/tigera/operator:${OPERATOR_VERSION}"

echo "🔍 Checking images for OPERATOR_VERSION=${OPERATOR_VERSION}"
echo "🔍 Fetching image list from ${IMAGE_SOURCE}..."

#########################################
# Step 1: Fetch image list from operator
#########################################
operator_images=$(
  docker run --rm "${IMAGE_SOURCE}" --print-images=list 2>/dev/null \
  | grep -E '^[a-z0-9.-]+\.[a-z0-9.-]+/[a-z0-9._/-]+:[a-zA-Z0-9._-]+' \
  | grep -v -- '-fips' \
  | sort -u
)

#########################################
# Step 2: Extract from manifests
#########################################
manifest_dir="${SCRIPT_DIR}/../manifests"
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

echo "📦 Total unique images to check (excluding -fips): ${count}"

#########################################
# Step 4: Check availability with retries
#########################################
FAILED=0
FAILED_IMAGES=()

while IFS= read -r image; do
  success=0
  for attempt in 1 2 3; do
    if "$CRANE" digest "$image" >/dev/null 2>&1; then
      echo "✅ Available: $image"
      success=1
      break
    else
      echo "⚠️  Attempt $attempt failed for: $image"
      if [ "$attempt" -eq 3 ]; then
        echo "🔍 Used crane at: $(realpath "$CRANE" 2>/dev/null || echo '<unresolvable>')"
      fi
      sleep 3
    fi
  done

  if [ "$success" -ne 1 ]; then
    echo "❌ NOT FOUND after 3 attempts: $image"
    FAILED=1
    FAILED_IMAGES+=("$image")
  fi
done <<< "$all_images"

#########################################
# Step 5: Final result
#########################################
if [ "$FAILED" -eq 1 ]; then
  echo ""
  echo "❗ Some images are missing or invalid:"
  for img in "${FAILED_IMAGES[@]}"; do
    echo "   ❌ $img"
  done
  exit 1
else
  echo "All images are available!"
fi
