#!/bin/bash
# Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

# Shell script for running the Calico unit test suite.
#
# Invoke as './run-unit-test.sh'. Arguments to this script are passed directly
# to tox: e.g., to force a rebuild of tox's virtual environments, invoke this
# script as './run-unit-test.sh -r'.
set -e

if [ -n "$VIRTUAL_ENV" ]; then
  echo "run-unit-test.sh cannot be run from within a virtualenv"
  exit 1
fi

coverage erase

tox "$@"

# Make sure we run the following coverage html command with the recent
# coverage.
source .tox/py27/bin/activate
coverage html
coverage xml
diff-cover coverage.xml --compare-branch="${COMPARE_BRANCH:-origin/master}"
deactivate
