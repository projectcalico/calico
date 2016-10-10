#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

# This script is run inside the container to actually do the pyinstaller
# build.

set -x
set -e

cd /code/

rm -rf build dist
pyinstaller docker-build-images/pyi/calico-felix.spec

cd dist/calico-felix
find -type f | grep -v -E 'calico-iptables-plugin|calico-felix' | xargs chmod -x
