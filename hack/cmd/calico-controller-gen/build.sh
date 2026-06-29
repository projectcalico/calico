#!/bin/sh
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds the Calico-patched controller-gen binary the same way the
# projectcalico/toolchain repo bakes it into the calico/go-build image
# (see images/calico-go-build/Dockerfile): download the pinned controller-tools
# tarball, apply the Calico patches, and `go build`.
#
# Usage: build.sh <output-binary-path>
#
# Must run inside the calico/go-build container (where controller-gen is on
# PATH) from the repository root.
set -eu

# Pinned controller-tools version. This is the single source of truth and is
# kept in sync with the controller-gen baked into the calico/go-build image: if
# this script detects a mismatch it rewrites the line below, then fails so the
# bump is committed deliberately (see the check further down).
VERSION="v0.18.0"

OUT="$1"

# Resolve the patches next to this script so the build works regardless of CWD.
# Every *.patch in this directory is applied, in sorted order.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SELF="$SCRIPT_DIR/build.sh"

# Primary source: the controller-gen baked into the go-build image. If it
# reports a different version than the pin above, update the pin in this script
# and fail, so the change is reviewed and committed rather than silently built.
# When controller-gen is absent (e.g. once it is dropped from the image), fall
# back to the pinned VERSION.
if command -v controller-gen >/dev/null 2>&1; then
    IMAGE_VERSION=$(controller-gen --version 2>/dev/null \
        | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [ -n "$IMAGE_VERSION" ] && [ "$IMAGE_VERSION" != "$VERSION" ]; then
        sed -i 's/^VERSION="v[0-9][0-9.]*"/VERSION="'"$IMAGE_VERSION"'"/' "$SELF"
        echo "ERROR: controller-tools version changed: pin was $VERSION, go-build image has $IMAGE_VERSION." >&2
        echo "       The pin in hack/cmd/calico-controller-gen/build.sh has been updated to $IMAGE_VERSION." >&2
        echo "       Before committing: verify the Calico patches in that directory still apply cleanly" >&2
        echo "       against $IMAGE_VERSION (adjust them if not). Then commit the change and re-run." >&2
        exit 1
    fi
fi

mkdir -p "$(dirname "$OUT")"

SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT

echo "Fetching controller-tools $VERSION ..."
curl -sfL "https://github.com/kubernetes-sigs/controller-tools/archive/refs/tags/${VERSION}.tar.gz" \
    | tar xz --strip-components 1 -C "$SRC"

for p in "$SCRIPT_DIR"/*.patch; do
    echo "Applying $(basename "$p") ..."
    (cd "$SRC" && patch -p1 < "$p")
done

echo "Building $OUT ..."
# GOFLAGS is reset so a parent -mod=vendor/-mod=mod does not leak into this
# standalone module build. The tarball ships its own go.mod/go.sum.
(cd "$SRC" && CGO_ENABLED=0 GOFLAGS= go build -o "$OUT" -v -buildvcs=false \
    -ldflags "-X sigs.k8s.io/controller-tools/pkg/version.version=${VERSION} -s -w" \
    ./cmd/controller-gen)

echo "Built calico-controller-gen ($VERSION) at $OUT"
