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

# This script checks that no Go files import encoding/json (v1). Only
# encoding/json/v2 (and encoding/json/jsontext) is allowed in this repo.
#
# Exemptions:
#   - api/ is published as an independent module and must remain buildable
#     against stdlib encoding/json so that external consumers do not need
#     GOEXPERIMENT=jsonv2.
#   - hack/cmd/jsonbench/ intentionally imports both v1 and v2 to benchmark
#     them side by side.

problems="$(grep -r -I --include='*.go' '"encoding/json"' \
  --exclude-dir='vendor' \
  --exclude-dir='api' \
  --exclude-dir='containernetworking-plugins' \
  . |
  grep -v '^\./hack/cmd/jsonbench/')"

if [ "$problems" ]; then
  echo "Some files import encoding/json (v1)."
  echo "Only encoding/json/v2 is allowed outside of api/."
  echo "Replace:"
  echo "    \"encoding/json\""
  echo "with:"
  echo "    \"encoding/json/v2\""
  echo "(and \"encoding/json/jsontext\" for streaming/options)."
  echo
  printf "%s" "$problems"
  echo
  echo
  exit 1
fi
