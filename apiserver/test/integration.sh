#!/bin/bash

# Copyright 2017 The Kubernetes Authors.
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

set -o errexit
set -o nounset
set -o pipefail

# this script resides in the `test/` folder at the root of the project
KUBE_ROOT=$(realpath $(dirname "${BASH_SOURCE}")/..)
source "${KUBE_ROOT}/hack/lib/init.sh"

runTests() {
  if [ -z "$DATASTORE_TYPE" ]; then
    # Run etcd only if the storage type is default for the apiserver.
    kube::etcd::start
  fi
  go test -v github.com/projectcalico/calico/apiserver/test/integration/... --args -v 10 -logtostderr
}

# Run cleanup to stop etcd on interrupt or other kill signal.
if [ -z "$DATASTORE_TYPE" ]; then
  trap kube::etcd::cleanup EXIT
fi

runTests
