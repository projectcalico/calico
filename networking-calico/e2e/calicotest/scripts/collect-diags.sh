#!/bin/bash
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

# Collect diagnostics from all nodes in the cluster, unpack the
# per-node tarfiles, fix permissions, and repack into a single archive.
#
# Usage: collect-diags.sh [label]
#
# The optional label is included in the output filename.  If omitted,
# a timestamp-based label is used.
#
# This script must be run inside the openstack-e2e container, or anywhere
# else that has this source tree with its env/ virtualenv set up (as by
# scripts/prepare-test-runtime.sh).

set -e

# Get the location of this script.
scriptdir=$(dirname $(realpath $0))

# CD to the root of the source tree, two levels up from this script.
cd $(dirname $(dirname $scriptdir))

LABEL=${1:-collect-diags-$(date +%F_%H-%M-%S)}

echo "Collecting diagnostics (label: ${LABEL})..."

sudo -E -n bash -c ". env/bin/activate && python3 -c '
import sys
sys.path.insert(0, \".\")
from calicotest.openstack.basetest import TestBase
TestBase.on_failure(test_id=\"${LABEL}\")
'"

echo "Done.  Look for diags in $(pwd)/diags/"
