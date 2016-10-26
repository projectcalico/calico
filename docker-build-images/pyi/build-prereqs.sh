#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
# Copyright 2015 Cisco Systems
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

# This script is run as part of the Docker image build process.  It builds
# our dependencies from source.  It requires the PY_VERSION environment
# variable to be set to the version of Python that was downloaded in an
# earlier step.
set -x
set -e

# Build python from the already-downloaded tarfile.
tar xzf Python-${PY_VERSION}.tgz
pushd Python-${PY_VERSION} 
./configure --prefix=/usr/local --enable-shared
make && make altinstall
popd

wget "https://bootstrap.pypa.io/get-pip.py"
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
python2.7 get-pip.py
