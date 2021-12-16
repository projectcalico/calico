#!/usr/bin/env bash

# Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

set -o errexit
set -o nounset
set -o pipefail


CALICO_REPO_PATH="$(git rev-parse --show-toplevel)"

MISSPELL_LOC="${CALICO_REPO_PATH}/hack/check/tools/bin"

# Install tools we need if it is not present
if [[ ! -f "${MISSPELL_LOC}/misspell" ]]; then
  curl -L https://git.io/misspell | bash
  mkdir -p "${MISSPELL_LOC}"
  mv ./bin/misspell "${MISSPELL_LOC}/misspell"
fi

# Spell checking
# misspell check Project - https://github.com/client9/misspell
misspellignore_files="${CALICO_REPO_PATH}/hack/check/.misspellignore"
ignore_files=$(cat "${misspellignore_files}")
git ls-files | grep -v "${ignore_files}" | xargs "${MISSPELL_LOC}/misspell" | grep "misspelling" && echo "Please fix the listed misspell errors and verify using 'make misspell'" && exit 1 || echo "misspell check passed!"
