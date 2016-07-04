#!/usr/bin/env bash
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

set -x
set -e

# Rebuild the docker container with the latest code.
docker build -t calico-pyi-build -f pyi/Dockerfile .

VERSION=$(python2.7 setup.py --version 2>>/dev/null)
GIT_COMMIT=$(git rev-parse HEAD)
GIT_COMMIT_SHORT=$(git rev-parse --short HEAD)
OUTPUT_FILENAME=dist/calico-felix-${VERSION}-git-${GIT_COMMIT_SHORT}.tgz

# Output version information
echo "Calico version:" ${VERSION} > version.txt
echo "Git revision:" ${GIT_COMMIT} >> version.txt

# Run pyinstaller to generate the distribution directory.
docker run --user $UID --rm -v `pwd`:/code calico-pyi-build /code/pyi/run-pyinstaller.sh

# Package it up.
mkdir -p dist
tar -czf ${OUTPUT_FILENAME} -C dist calico-felix

set +x
echo
echo Built archive at ${OUTPUT_FILENAME}
