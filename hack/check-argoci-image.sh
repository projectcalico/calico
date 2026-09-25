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

# The CI workflow runs its steps in the build image directly, so it names a tag
# that metadata.mk also decides. Only metadata.mk is edited by hand; without
# this check a bump there would leave CI testing against the previous toolchain,
# and passing.
#
# GO_BUILD_VER is composed from three other variables, so it arrives already
# expanded by make rather than being parsed here.
#
# Only the workflow YAML is checked. Scripts under .argoci/ can ask make for the
# value at runtime and so cannot drift.

set -euo pipefail

: "${GO_BUILD_VER:?not set - run this as 'make check-argoci-image'}"

expected="calico/go-build:${GO_BUILD_VER}"
rc=0
found=0

while IFS=: read -r file line ref; do
    found=1
    if [ "$ref" != "$expected" ]; then
        echo "ERROR: ${file}:${line} pins ${ref}"
        rc=1
    fi
done < <(grep -rEno --include='*.yaml' --include='*.yml' \
    "calico/go-build:[^\"' ]+" .argoci || true)

# A workflow naming no build image would pass this check having compared
# nothing, which is the failure it exists to catch.
if [ "$found" -eq 0 ]; then
    echo "ERROR: no calico/go-build reference found in .argoci/ workflow files"
    rc=1
fi

if [ "$rc" -ne 0 ]; then
    echo ""
    echo "metadata.mk gives GO_BUILD_VER=${GO_BUILD_VER}, so .argoci/ must use ${expected}."
    exit 1
fi

echo "ArgoCI build image check passed (${expected})."
