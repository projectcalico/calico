#!/bin/bash
# Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

unset -f retry_command
function retry_command() {
  local RETRY=$(($1/10))
  local CMD=$2
  echo

  for i in `seq 1 $RETRY`; do
    echo Trying $CMD, attempt ${i}
    $CMD && return 0 || sleep 10
  done
  echo "Command '${CMD}' failed after $RETRY attempts"
  return 1
}

unset -f pause-for-debug
function pause-for-debug() {
  # Stop for debug
  echo "Check for pause file..."
  while [ -f /home/semaphore/pause-for-debug ];
  do
    echo "#"
    sleep 30
  done
}

