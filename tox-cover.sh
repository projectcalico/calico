#!/bin/bash
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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

# This script wraps the nosetests and coverage commands to allow the
# concurrency mode to be specified when collecting coverage.
set -x
set -e

# Coverage requires a full path.
nosetests=$(which nosetests)
coverage run --append --concurrency $1 "$nosetests" $2
