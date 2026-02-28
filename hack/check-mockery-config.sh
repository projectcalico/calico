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

# This script checks that all .mockery.yaml config files use the v3 format.
# Deprecated v2 fields are rejected to prevent incompatibility with mockery v3.6+.

set -euo pipefail

# v2 fields that were renamed or removed in v3:
#   mockname    -> structname
#   outpkg      -> pkgname
#   with-expecter (removed, always enabled in v3)
deprecated_keys="mockname|outpkg|with-expecter"

rc=0
for config in $(find . -name '.mockery.yaml' -o -name '.mockery.yml' | sort); do
  # Match top-level keys only (lines starting with the key name, no leading whitespace).
  if grep -Pn "^(${deprecated_keys}):" "$config"; then
    echo "ERROR: $config contains deprecated mockery v2 config keys. Please migrate to v3 format."
    echo "  mockname    -> structname"
    echo "  outpkg      -> pkgname"
    echo "  with-expecter -> (remove, always enabled in v3)"
    echo ""
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo "Mockery config check failed. All .mockery.yaml files must use v3 format only."
  exit 1
fi

echo "Mockery config check passed."
