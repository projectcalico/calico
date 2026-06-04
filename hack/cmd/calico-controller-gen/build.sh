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
# (see images/calico-go-build/Dockerfile): download the pinned
# controller-tools tarball, apply the NumOrString patch, and `go build`.
#
# Usage: build.sh <controller-tools-version> <output-binary-path>
#
# Run from the repository root (the patch is resolved relative to this script).
set -eu

VERSION="$1"
OUT="$2"

# Resolve the patches next to this script so the build works regardless of CWD.
# Every *.patch in this directory is applied, in sorted order.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Caching is handled by the Makefile file target (build only runs when needed),
# so always (re)build when invoked.
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
