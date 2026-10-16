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

# Builds the Calico-patched controller-gen: download the pinned controller-tools
# tarball, apply the Calico patches, and `go build`. Every controller-gen run in
# this repo uses it, so CRDs and deepcopy code come from one version.
#
# Usage: build.sh <output-binary-path>
#
# Must run inside the calico/go-build container, from the repository root.
set -eu

# The one place the controller-tools version is set.
VERSION="v0.18.0"

OUT="$1"

# Resolve the patches next to this script so the build works regardless of CWD.
# Every *.patch in this directory is applied, in sorted order.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

mkdir -p "$(dirname "$OUT")"

SRC=$(mktemp -d)
TARBALL=$(mktemp)
# Created by mktemp in $OUT's own directory, which is the shared Go build
# cache: O_EXCL there is what makes the name unique between concurrent builds.
# $$ would not — each build runs in its own container, and those PID namespaces
# hand out the same few PIDs, so it collides exactly when $OUT is contended.
TMP_OUT=$(mktemp "$OUT.tmp.XXXXXXXX")
trap 'rm -rf "$SRC" "$TARBALL" "$TMP_OUT"' EXIT

echo "Fetching controller-tools $VERSION ..."
curl -fL --retry 5 --retry-all-errors --silent --show-error -o "$TARBALL" \
    "https://github.com/kubernetes-sigs/controller-tools/archive/refs/tags/${VERSION}.tar.gz"
tar xzf "$TARBALL" --strip-components 1 -C "$SRC"

for p in "$SCRIPT_DIR"/*.patch; do
    echo "Applying $(basename "$p") ..."
    (cd "$SRC" && patch -p1 < "$p")
done

echo "Building $OUT ..."
# GOFLAGS is reset so a parent -mod=vendor/-mod=mod does not leak into this
# standalone module build. The tarball ships its own go.mod/go.sum.
(cd "$SRC" && CGO_ENABLED=0 GOFLAGS= go build -o "$TMP_OUT" -v -buildvcs=false \
    -ldflags "-X sigs.k8s.io/controller-tools/pkg/version.version=${VERSION} -s -w" \
    ./cmd/controller-gen)

# mktemp created $TMP_OUT at 0600 and `go build -o` keeps an existing file's
# mode, so the bit that makes it a binary has to be put back by hand.
chmod 0755 "$TMP_OUT"

# Renamed rather than built in place: concurrent builds share $OUT, and writing
# it directly truncates a binary another container may be executing.
mv -f "$TMP_OUT" "$OUT"

echo "Built calico-controller-gen ($VERSION) at $OUT"
