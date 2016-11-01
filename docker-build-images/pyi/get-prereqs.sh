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

# PyInstaller .spec file for building the bundle.  This file is actually a
# Python file,  which is run with various pre-defined variables.

# This file downloads the source files for the dependencies we build. It
# requires the PY_VERSION environment variable to be set to the version of
# Python to download.

set -x
set -e

# Get Python.
wget https://www.python.org/ftp/python/${PY_VERSION}/Python-${PY_VERSION}.tgz
