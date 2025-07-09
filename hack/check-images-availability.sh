#!/bin/bash

# Copyright (c) 2025 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -euo pipefail

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use provided CRANE or fallback to ../bin/crane (relative to hack/)
CRANE="${CRANE:-../bin/crane}"
YQ="${YQ:-${SCRIPT_DIR}/../bin/yq}"

if [ ! -x "$CRANE" ]; then
  echo "Error: crane not found or not executable at: $CRANE" >&2
  echo "Resolved path: $(realpath "$CRANE" 2>/dev/null || echo '<unresolvable>')" >&2
  exit 1
fi

#########################################
# Get registry and version info
#########################################
defaultRegistry="$($YQ .node.registry < "$SCRIPT_DIR/../charts/calico/values.yaml" | cut -d'/' -f1)"
REGISTRY="${REGISTRY:-$defaultRegistry}"

defaultCalicoVersion="$($YQ .version < "$SCRIPT_DIR/../charts/calico/values.yaml")"
CALICO_VERSION="${PRODUCT_VERSION:-$defaultCalicoVersion}"

echo "Using REGISTRY: $REGISTRY"
echo "Using CALICO_VERSION: $CALICO_VERSION"

#########################################
# Step 1: Extract from manifests
#########################################
manifest_dir="${SCRIPT_DIR}/../manifests"

manifest_images_raw=$(
  grep -rhoE 'image:\s*["'\''"]?[a-z0-9./_-]+:[a-zA-Z0-9._-]+' "$manifest_dir" \
  | sed -E 's/image:\s*["'\''"]?//' \
  | grep -v -- '-fips'
)

# Step 1.1: Normalize and adjust image paths
manifest_images=$(
  while IFS= read -r image; do
    base="${image%%:*}"
    tag="${image##*:}"

    if [[ "$base" == *.*/* ]]; then
      # Fully qualified (has domain), e.g., quay.io/calico/node
      if [[ "$base" == *calico/* && -n "$CALICO_VERSION" ]]; then
        echo "${base}:${CALICO_VERSION}"
      else
        echo "${base}:${tag}"
      fi
    elif [[ "$base" == calico/* ]]; then
      # Implicit registry for calico/*
      if [[ -n "$CALICO_VERSION" ]]; then
        echo "${REGISTRY}/calico/${base##*/}:${CALICO_VERSION}"
      else
        echo "${REGISTRY}/calico/${base##*/}:${tag}"
      fi
    elif [[ "$base" != */* ]]; then
      # Single name like 'busybox'
      echo "docker.io/${base}:${tag}"
    else
      # Everything else
      echo "docker.io/${base}:${tag}"
    fi
  done <<< "$manifest_images_raw" | sort -u
)

count=$(echo "$manifest_images" | wc -l)
echo "Total unique images (excluding -fips): ${count}"

#########################################
# Step 2: Check availability with retries
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
      echo "Attempt $attempt failed for: $image"
      if [ "$attempt" -eq 3 ]; then
        echo "Used crane at: $(realpath "$CRANE" 2>/dev/null || echo '<unresolvable>')"
      fi
      sleep 3
    fi
  done

  if [ "$success" -ne 1 ]; then
    echo "❌ NOT FOUND after 3 attempts: $image"
    FAILED=1
    FAILED_IMAGES+=("$image")
  fi
done <<< "$manifest_images"

#########################################
# Step 3: Final result
#########################################
if [ "$FAILED" -eq 1 ]; then
  echo ""
  echo "❗ Some images are missing or invalid:"
  for img in "${FAILED_IMAGES[@]}"; do
    echo "   ❌ $img"
  done
  exit 1
else
  echo "✅ All images from manifests are available!"
fi
