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

# Add local user
# Either use the LOCAL_USER_ID if passed in at runtime or fallback

USER_ID=${LOCAL_USER_ID:-9001}

# The repo's build tools (ginkgo, golangci-lint, protoc...) are installed
# outside the image, at the versions it pins, and mounted in.
if [ -n "${BUILD_TOOLS_PATH:-}" ]; then
  export PATH="${BUILD_TOOLS_PATH}:${PATH}"
fi

if [ "${RUN_AS_ROOT}" = "true" ]; then
  exec "$@"
fi

echo "Starting with UID: $USER_ID" 1>&2
# Don't pass "-m" to useradd if the home directory already exists,
# (which can occur if it was volume mounted in) otherwise it will fail.
if [[ ! -d "/home/user" ]]; then
  useradd -m -U -s /bin/bash -u "$USER_ID" user
else
  useradd -U -s /bin/bash -u "$USER_ID" user
fi

export HOME=/home/user

if [ -n "$EXTRA_GROUP_ID" ]; then
  echo "Adding user to additional GID: $EXTRA_GROUP_ID" 1>&2
  # Adding the group can fail if it already exists.
  if groupadd --gid "$EXTRA_GROUP_ID" group; then
    usermod -a -G group user
  else
    echo "Adding user to existing group instead" 1>&2
    usermod -a -G "$(getent group "$EXTRA_GROUP_ID" | cut -d: -f1)" user
  fi
fi

exec /usr/bin/su-exec user "$@"
