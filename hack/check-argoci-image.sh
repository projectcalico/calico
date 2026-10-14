#!/bin/bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

# Fails when a calico/go-build tag pinned outside the Makefiles differs from
# metadata.mk's, which would leave that consumer on the old toolchain and still
# passing.

set -euo pipefail

: "${GO_BUILD_VER:?not set - run this as 'make check-argoci-image'}"

rc=0

argoci="$(awk '/^goBuildVersion:/ {print $2}' .argoci/config.yaml)"
if [ "$argoci" != "$GO_BUILD_VER" ]; then
    echo "ERROR: .argoci/config.yaml has goBuildVersion: ${argoci:-<none>}"
    rc=1
fi

scanner="$(sed -n 's#^FROM calico/go-build:\([^ ]*\).*#\1#p' .oss-scanner/Dockerfile)"
if [ "$scanner" != "$GO_BUILD_VER" ]; then
    echo "ERROR: .oss-scanner/Dockerfile is FROM calico/go-build:${scanner:-<none>}"
    rc=1
fi

if [ "$rc" -ne 0 ]; then
    echo ""
    echo "metadata.mk gives GO_BUILD_VER=${GO_BUILD_VER}; update these to match."
    exit 1
fi

echo "go-build image check passed (${GO_BUILD_VER})."
