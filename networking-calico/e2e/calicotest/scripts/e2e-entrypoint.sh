#!/bin/bash -e
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

# Entrypoint for the openstack-e2e Docker image.
#
# Delegates to calicotest/scripts/run-test.sh — the same wrapper test authors
# use outside the container — so the TEST_REQ → pytest mapping has a single
# source of truth. run-test.sh handles cd'ing, sourcing the venv, and
# dispatching on TEST_REQ.
#
# Typical invocation (see the README for what the cluster and test node need):
#   docker run --rm --network host \
#     -v <dir>/cluster-layout.conf:/calico-test/config/cluster-layout.conf:ro \
#     -v <path>/<SSH private key>:/root/.ssh/id_rsa:ro \
#     -v <results dir>:/output \
#     -e TEST_REQ=<selector> \
#     openstack-e2e
#
# Inputs (env):
#   TEST_REQ - test selector. Defaults to "smoke". See run-test.sh for
#              the full list of accepted values.
#
# Outputs:
#   /output/results/TEST-*.xml - JUnit XML (xmlrunner writes TEST-*.xml
#                                into the CWD; collected into /output
#                                after the run).

TEST_REQ="${TEST_REQ:-smoke}"
echo "[e2e-entrypoint] TEST_REQ=${TEST_REQ}"

mkdir -p /output/results

# Run the tests, capturing the exit code (this script runs with -e) so
# the XML collection below always happens and the container still exits
# with the tests' status, which callers use as the success/failure signal.
rc=0
./calicotest/scripts/run-test.sh "${TEST_REQ}" || rc=$?

# `python3 -m xmlrunner` writes its JUnit XML as TEST-*.xml in the
# current directory (/calico-test) -- NOT ./reports/, as an earlier
# version of this script assumed -- so collect the files into the
# /output mount, where the caller can find them.
#
# A passing run that yields no XML (none produced, or the mv failed)
# must NOT exit 0: the caller would record success with an empty results
# dir, the exact false-green this collection step exists to prevent.
# A failing run keeps its own exit code -- an early abort legitimately
# produces no XML, and the test failure is the primary signal.
shopt -s nullglob
xmls=(TEST-*.xml)
shopt -u nullglob
if [ "${#xmls[@]}" -gt 0 ]; then
    if ! mv -- "${xmls[@]}" /output/results/; then
        echo "[e2e-entrypoint] ERROR: failed to move JUnit XML into /output/results" >&2
        if [ "${rc}" -eq 0 ]; then rc=1; fi
    fi
elif [ "${rc}" -eq 0 ]; then
    echo "[e2e-entrypoint] ERROR: tests reported success but produced no TEST-*.xml" >&2
    rc=1
else
    echo "[e2e-entrypoint] no TEST-*.xml files produced (tests already failed, rc=${rc})"
fi

exit "${rc}"
