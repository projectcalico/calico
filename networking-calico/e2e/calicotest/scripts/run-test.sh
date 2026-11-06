#!/bin/bash
# Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

# This script wraps the command line needed to run the test suite, or a
# particular test or set of tests.
#
# It assumes that the private key named by the layout file's keyfile setting
# is good for accessing the nodes under test.
#
# Usage: run-test.sh <test_spec>, where <test_spec> is a way of specifying the
# tests to run.
#
# Examples:
#   run-test.sh (smoke | full-fv | fail)
#   run-test.sh calicotest/openstack/test_mainline_connectivity.py

# Get the location of this script.
scriptdir=$(dirname $(realpath $0))

# CD to the root of the source tree, two levels up from this script.
cd $(dirname $(dirname $scriptdir))
pwd

TEST_REQ=$1
TEST_ARG=
TEST_FILTER="fv_test or unit_test"
case "${TEST_REQ}" in
        smoke)
            TEST_ARG="calicotest/openstack/test_mainline_connectivity.py"
            ;;
        full-fv)
            ;;
        fail)
            # This is used for testing only - e.g. to test diags collection.
            TEST_ARG="calicotest/openstack/test_test_failures.py"
            ;;
	calicotest/*)
	    TEST_ARG=${TEST_REQ}
	    ;;
        *)
            echo Error in TEST_REQ - got ${TEST_REQ}
            exit 1
esac

sudo -E -n \
     bash -c \
     ". env/bin/activate && TEST_FILTER=\"${TEST_FILTER}\" python3 -m xmlrunner -v ${TEST_ARG}"
