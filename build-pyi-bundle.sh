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

# Run pyinstaller to generate the distribution directory.
docker run --user $UID --rm -v `pwd`:/code calico-pyi-build /code/pyi/run-pyinstaller.sh

# Package it up.
mkdir -p dist
tar -czf dist/calico-felix.tgz -C dist calico-felix
