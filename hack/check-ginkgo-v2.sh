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

# This script checks that no Go files import ginkgo v1
# (github.com/onsi/ginkgo). Only ginkgo v2 (github.com/onsi/ginkgo/v2)
# is allowed.

problems="$(grep -r -I --include='*.go' '"github.com/onsi/ginkgo"' \
  --exclude-dir='vendor' \
  --exclude-dir='containernetworking-plugins' \
  . |
  grep -v 'ginkgo/v2')"

if [ "$problems" ]; then
  echo "Some files import ginkgo v1 (github.com/onsi/ginkgo)."
  echo "Only ginkgo v2 (github.com/onsi/ginkgo/v2) is allowed."
  echo
  printf "%s" "$problems"
  echo
  echo
  exit 1
fi
